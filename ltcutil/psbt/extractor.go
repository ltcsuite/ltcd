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
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
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

func extractV2(p *Packet) (*wire.MsgTx, error) {
	tx := new(wire.MsgTx)
	for _, pi := range p.Inputs {
		if !pi.isMWEB() {
			txin, err := extractTxIn(&pi)
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

	if p.hasMwebComponents() {
		// TODO: Extract MWEB Tx
	}

	return tx, nil
}

func extractTxIn(pi *PInput) (*wire.TxIn, error) {
	if pi.PrevoutHash == nil || pi.PrevoutIndex == nil {
		return nil, errors.New("input missing previous outpoint info")
	}

	var txin wire.TxIn
	txin.PreviousOutPoint = wire.OutPoint{Hash: *pi.PrevoutHash, Index: *pi.PrevoutIndex}
	txin.SignatureScript = pi.FinalScriptSig
	if pi.FinalScriptWitness != nil {
		witness, err := extractTxWitness(pi.FinalScriptWitness)
		if err != nil {
			return nil, err
		}

		txin.Witness = witness
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
