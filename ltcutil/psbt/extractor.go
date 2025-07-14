// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// The Extractor requires provision of a single PSBT
// in which all necessary signatures are encoded, and
// uses it to construct a fully valid network serialized
// transaction.

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/secp256k1"
	"lukechampine.com/blake3"
)

// Extract takes a finalized psbt.Packet and outputs a finalized transaction
// instance. Note that if the PSBT is in-complete, then an error
// ErrIncompletePSBT will be returned. As the extracted transaction has been
// fully finalized, it will be ready for network broadcast once returned.
func Extract(p *Packet) (*wire.MsgTx, error) {
	// If the packet isn't complete, then we'll return an error as it
	// doesn't have all the required witness data.
	if !p.IsComplete() {
		return nil, ErrIncompletePSBT
	}

	if p.PsbtVersion >= 2 {
		return extractV2(p)
	}

	// First, we'll make a copy of the underlying unsigned transaction (the
	// initial template) so we don't mutate it during our activates below.
	finalTx := p.UnsignedTx.Copy()

	// For each input, we'll now populate any relevant witness and
	// sigScript data.
	for i, tin := range finalTx.TxIn {
		// We'll grab the corresponding internal packet input which
		// matches this materialized transaction input and emplace that
		// final sigScript (if present).
		pInput := p.Inputs[i]
		if pInput.FinalScriptSig != nil {
			tin.SignatureScript = pInput.FinalScriptSig
		}

		// Similarly, if there's a final witness, then we'll also need
		// to extract that as well, parsing the lower-level transaction
		// encoding.
		if pInput.FinalScriptWitness != nil {
			witness, err := extractTxWitness(pInput.FinalScriptWitness)
			if err != nil {
				return nil, err
			}

			tin.Witness = witness
		}
	}

	return finalTx, nil
}

func ExtractUnsignedTx(p *Packet) (*wire.MsgTx, error) {
	if p.PsbtVersion >= 2 {
		tx := new(wire.MsgTx)
		tx.Version = p.TxVersion

		// TODO: Compute actual lock time
		if p.FallbackLocktime != nil {
			tx.LockTime = *p.FallbackLocktime
		}

		for _, pi := range p.Inputs {
			if !pi.isMWEB() {
				txin, err := extractTxIn(&pi, false)
				if err != nil {
					return nil, err
				}

				tx.AddTxIn(txin)
			}
		}

		for _, output := range p.Outputs {
			if !output.isMWEB() {
				txout := wire.TxOut{Value: int64(output.Amount), PkScript: output.PKScript}
				tx.AddTxOut(&txout)
			}
		}

		// TODO: Include MWEB

		return tx, nil
	} else {
		return p.UnsignedTx.Copy(), nil
	}
}

func extractV2(p *Packet) (*wire.MsgTx, error) {
	tx := new(wire.MsgTx)
	tx.Version = p.TxVersion

	// TODO: Compute actual lock time
	if p.FallbackLocktime != nil {
		tx.LockTime = *p.FallbackLocktime
	}

	for _, pi := range p.Inputs {
		if !pi.isMWEB() {
			txin, err := extractTxIn(&pi, true)
			if err != nil {
				return nil, err
			}

			tx.AddTxIn(txin)
		}
	}

	for _, output := range p.Outputs {
		if !output.isMWEB() {
			txout := wire.TxOut{Value: int64(output.Amount), PkScript: output.PKScript}
			tx.AddTxOut(&txout)
		}
	}

	if p.HasMwebComponents() {
		if p.MwebTxOffset == nil || p.MwebStealthOffset == nil {
			return nil, errors.New("missing MWEB offsets")
		}

		// Extract MWEB Inputs
		var inputs []*wire.MwebInput
		for _, pi := range p.Inputs {
			if pi.isMWEB() {
				input, err := extractMwebInput(&pi)
				if err != nil {
					return nil, err
				}
				inputs = append(inputs, input)
			}
		}

		// Extract MWEB Outputs
		var outputs []*wire.MwebOutput
		for _, po := range p.Outputs {
			if po.isMWEB() {
				output, err := extractMwebOutput(&po)
				if err != nil {
					return nil, err
				}
				outputs = append(outputs, output)
			}
		}

		// Extract MWEB Kernels
		var kernels []*wire.MwebKernel
		for _, pk := range p.Kernels {
			kernel, err := extractKernel(&pk)
			if err != nil {
				return nil, err
			}
			kernels = append(kernels, kernel)
		}

		// Sort components before assembling txBody
		sort.Slice(inputs, func(i, j int) bool {
			// Sort by OutputId lexicographically
			a := new(big.Int).SetBytes(inputs[i].OutputId[:])
			b := new(big.Int).SetBytes(inputs[j].OutputId[:])
			return a.Cmp(b) < 0
		})
		sort.Slice(outputs, func(i, j int) bool {
			// Sort by OutputId lexicographically
			a := new(big.Int).SetBytes(outputs[i].Hash()[:])
			b := new(big.Int).SetBytes(outputs[j].Hash()[:])
			return a.Cmp(b) < 0
		})
		sortKernels(kernels)

		txBody := wire.MwebTxBody{
			Inputs:  inputs,
			Outputs: outputs,
			Kernels: kernels,
		}
		tx.Mweb = &wire.MwebTx{
			KernelOffset:  *p.MwebTxOffset,
			StealthOffset: *p.MwebStealthOffset,
			TxBody:        &txBody,
		}
	}

	return tx, nil
}

func extractTxIn(pi *PInput, includeSignature bool) (*wire.TxIn, error) {
	if pi.PrevoutHash == nil || pi.PrevoutIndex == nil {
		return nil, errors.New("input missing previous outpoint info")
	}

	var txin wire.TxIn
	txin.PreviousOutPoint = wire.OutPoint{Hash: *pi.PrevoutHash, Index: *pi.PrevoutIndex}

	if includeSignature {
		txin.SignatureScript = pi.FinalScriptSig
		if pi.FinalScriptWitness != nil {
			witness, err := extractTxWitness(pi.FinalScriptWitness)
			if err != nil {
				return nil, err
			}

			txin.Witness = witness
		}
	}

	txin.Sequence = 0xffffffff
	if pi.Sequence != nil {
		txin.Sequence = *pi.Sequence
	}

	return &txin, nil
}

func extractTxWitness(finalScriptWitness []byte) (wire.TxWitness, error) {
	// In order to set the witness, need to re-deserialize
	// the field as encoded within the PSBT packet.  For
	// each input, the witness is encoded as a stack with
	// one or more items.
	witnessReader := bytes.NewReader(finalScriptWitness)

	// First we extract the number of witness elements
	// encoded in the above witnessReader.
	witCount, err := wire.ReadVarInt(witnessReader, 0)
	if err != nil {
		return nil, err
	}

	// Now that we know how many inputs we'll need, we'll
	// construct a packing slice, then read out each input
	// (with a varint prefix) from the witnessReader.
	witness := make(wire.TxWitness, witCount)
	for j := uint64(0); j < witCount; j++ {
		wit, err := wire.ReadVarBytes(
			witnessReader, 0,
			txscript.MaxScriptSize, "witness",
		)
		if err != nil {
			return nil, err
		}
		witness[j] = wit
	}

	return witness, nil
}

func extractMwebInput(pi *PInput) (*wire.MwebInput, error) {
	if !pi.isMWEB() {
		return nil, errors.New("input not mweb")
	}

	if !pi.isFinalized() {
		return nil, errors.New("mweb input not finalized")
	}

	var extraData []byte
	if pi.MwebExtraData != nil {
		extraData = append([]byte(nil), pi.MwebExtraData...)
	}

	mwebInput := &wire.MwebInput{
		Features:     *pi.MwebFeatures,
		OutputId:     *pi.MwebOutputId,
		Commitment:   *pi.MwebCommit,
		InputPubKey:  pi.MwebInputPubkey,
		OutputPubKey: *pi.MwebOutputPubkey,
		ExtraData:    extraData,
		Signature:    *pi.MwebInputSig,
	}
	return mwebInput, nil
}

func extractMwebOutput(po *POutput) (*wire.MwebOutput, error) {
	if !po.isMWEB() {
		return nil, errors.New("output not mweb")
	}

	if !po.isFinalized() {
		return nil, errors.New("mweb output not finalized")
	}

	var extraData []byte
	if po.MwebExtraData != nil {
		extraData = append([]byte(nil), po.MwebExtraData...)
	}

	var keyExchangePubKey mw.PublicKey
	var viewTag uint8
	var encryptedValue uint64
	var maskedNonce big.Int
	if po.MwebStandardFields != nil {
		keyExchangePubKey = po.MwebStandardFields.KeyExchangePubkey
		viewTag = po.MwebStandardFields.ViewTag
		encryptedValue = po.MwebStandardFields.EncryptedValue
		maskedNonce.SetBytes(po.MwebStandardFields.EncryptedNonce[:])
	}

	outputMessage := wire.MwebOutputMessage{
		Features:          *po.MwebFeatures,
		KeyExchangePubKey: keyExchangePubKey,
		ViewTag:           viewTag,
		MaskedValue:       encryptedValue,
		MaskedNonce:       maskedNonce,
		ExtraData:         extraData,
	}

	var rangeProof secp256k1.RangeProof
	copy(rangeProof[:], po.RangeProof[:])

	mwebOutput := &wire.MwebOutput{
		Commitment:     *po.OutputCommit,
		SenderPubKey:   *po.SenderPubkey,
		Message:        outputMessage,
		RangeProof:     &rangeProof,
		RangeProofHash: blake3.Sum256(rangeProof[:]),
		Signature:      *po.MwebSignature,
	}
	return mwebOutput, nil
}

func extractKernel(pk *PKernel) (*wire.MwebKernel, error) {
	if !pk.isFinalized() {
		return nil, errors.New("kernel not finalized")
	}

	fee := uint64(0)
	if pk.Fee != nil {
		fee = uint64(*pk.Fee)
	}
	pegin := uint64(0)
	if pk.PeginAmount != nil {
		pegin = uint64(*pk.PeginAmount)
	}
	var pegouts []*wire.TxOut
	for _, out := range pk.PegOuts {
		copied := &wire.TxOut{
			Value:    out.Value,
			PkScript: append([]byte(nil), out.PkScript...), // clone PkScript
		}
		pegouts = append(pegouts, copied)
	}
	lockHeight := int32(0)
	if pk.LockHeight != nil {
		lockHeight = *pk.LockHeight
	}
	var stealthExcess mw.PublicKey
	if pk.StealthExcess != nil {
		stealthExcess = *pk.StealthExcess
	}
	var extraData []byte
	if pk.ExtraData != nil {
		extraData = append([]byte(nil), pk.ExtraData...)
	}
	kernel := &wire.MwebKernel{
		Features:      *pk.Features,
		Fee:           fee,
		Pegin:         pegin,
		Pegouts:       pegouts,
		LockHeight:    lockHeight,
		StealthExcess: stealthExcess,
		ExtraData:     extraData,
		Excess:        *pk.ExcessCommitment,
		Signature:     *pk.Signature,
	}
	return kernel, nil
}

// sortKernels sorts MwebKernels in place by net supply increase (descending),
// breaking ties by hash (ascending).
func sortKernels(kernels []*wire.MwebKernel) {
	sort.Slice(kernels, func(i, j int) bool {
		a := kernels[i]
		b := kernels[j]

		// Net supply change: (pegin - fee - pegouts)
		aSupply := int64(a.Pegin) - int64(a.Fee)
		for _, out := range a.Pegouts {
			aSupply -= out.Value
		}

		bSupply := int64(b.Pegin) - int64(b.Fee)
		for _, out := range b.Pegouts {
			bSupply -= out.Value
		}

		if aSupply != bSupply {
			return aSupply > bSupply // higher net supply first
		}

		aHash := new(big.Int).SetBytes(a.Hash()[:])
		bHash := new(big.Int).SetBytes(b.Hash()[:])

		// Tie-break by hash
		return aHash.Cmp(bHash) < 0
	})
}
