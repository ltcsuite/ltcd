// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

import (
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/wire"
)

// MinTxVersion is the lowest transaction version that we'll permit.
const MinTxVersion = 1

// New on provision of an input and output 'skeleton' for the transaction, a
// new partially populated PBST packet. The populated packet will include the
// unsigned transaction, and the set of known inputs and outputs contained
// within the unsigned transaction.  The values of nLockTime, nSequence (per
// input) and transaction version (must be 1 of 2) must be specified here. Note
// that the default nSequence value is wire.MaxTxInSequenceNum.  Referencing
// the PSBT BIP, this function serves the roles of teh Creator.
func New(inputs []*wire.OutPoint,
	outputs []*wire.TxOut, version int32, nLockTime uint32,
	nSequences []uint32) (*Packet, error) {

	// Create the new struct; the input and output lists will be empty, the
	// unsignedTx object must be constructed and serialized, and that
	// serialization should be entered as the only entry for the
	// globalKVPairs list.
	//
	// Ensure that the version of the transaction is greater then our
	// minimum allowed transaction version. There must be one sequence
	// number per input.
	if version < MinTxVersion || len(nSequences) != len(inputs) {
		return nil, ErrInvalidPsbtFormat
	}

	unsignedTx := wire.NewMsgTx(version)
	unsignedTx.LockTime = nLockTime

	var psbtInputs []PInput
	for i, in := range inputs {
		unsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *in,
			Sequence:         nSequences[i],
		})
		psbtInputs = append(psbtInputs, PInput{
			PrevoutHash:  &in.Hash,
			PrevoutIndex: &in.Index,
			Sequence:     &nSequences[i],
		})
	}

	var psbtOutputs []POutput
	for _, out := range outputs {
		unsignedTx.AddTxOut(out)
		amount := ltcutil.Amount(out.Value)
		psbtOutputs = append(psbtOutputs, POutput{
			Amount:   amount,
			PKScript: out.PkScript,
		})
	}

	return newWithVersion(0, unsignedTx, psbtInputs, psbtOutputs, nil, version, &nLockTime)
}

func NewV2(inputs []PInput, outputs []POutput, kernels []PKernel,
	txVersion int32, fallbackLocktime *uint32) (*Packet, error) {

	return newWithVersion(2, nil, inputs, outputs, kernels, txVersion, fallbackLocktime)
}

func newWithVersion(psbtVersion uint32, unsignedTx *wire.MsgTx, inputs []PInput, outputs []POutput, kernels []PKernel,
	txVersion int32, fallbackLocktime *uint32) (*Packet, error) {

	if txVersion < MinTxVersion {
		return nil, ErrInvalidPsbtFormat
	}

	// This new Psbt is "raw" and contains no key-value fields, so sanity
	// checking with c.Cpsbt.SanityCheck() is not required.
	return &Packet{
		PsbtVersion:      psbtVersion,
		UnsignedTx:       unsignedTx,
		TxVersion:        txVersion,
		FallbackLocktime: fallbackLocktime,
		Inputs:           inputs,
		Outputs:          outputs,
		Kernels:          kernels,
		Unknowns:         nil,
	}, nil
}
