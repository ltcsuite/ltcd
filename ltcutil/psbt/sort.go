package psbt

import (
	"bytes"
	"sort"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
)

// InPlaceSort modifies the passed packet's wire TX inputs and outputs to be
// sorted based on BIP 69. The sorting happens in a way that the packet's
// partial inputs and outputs are also modified to match the sorted TxIn and
// TxOuts of the wire transaction.
//
// WARNING: This function must NOT be called with packages that already contain
// (partial) witness data since it will mutate the transaction if it's not
// already sorted. This can cause issues if you mutate a tx in a block, for
// example, which would invalidate the block. It could also cause cached hashes,
// such as in a ltcutil.Tx to become invalidated.
//
// The function should only be used if the caller is creating the transaction or
// is otherwise 100% positive mutating will not cause adverse affects due to
// other dependencies.
func InPlaceSort(packet *Packet) error {
	// To make sure we don't run into any nil pointers or array index
	// violations during sorting, do a very basic sanity check first.
	err := VerifyInputOutputLen(packet, false, false)
	if err != nil {
		return err
	}

	// BIP-69 sorting would misorder MWEB maps and break peg-in/kernel pairing,
	// so MWEB packets keep their own ordering, applied at extraction.
	if packet.HasMwebComponents() {
		return ErrMwebSortUnsupported
	}

	sort.Sort(&sortableInputs{p: packet})
	sort.Sort(&sortableOutputs{p: packet})

	return nil
}

// sortableInputs is a simple wrapper around a packet that implements the
// sort.Interface for sorting the wire and partial inputs of a packet.
type sortableInputs struct {
	p *Packet
}

// sortableOutputs is a simple wrapper around a packet that implements the
// sort.Interface for sorting the wire and partial outputs of a packet.
type sortableOutputs struct {
	p *Packet
}

// For sortableInputs and sortableOutputs, three functions are needed to make
// them sortable with sort.Sort() -- Len, Less, and Swap.
// Len and Swap are trivial. Less is BIP 69 specific.
func (s *sortableInputs) Len() int { return len(s.p.Inputs) }
func (s sortableOutputs) Len() int { return len(s.p.Outputs) }

// Swap swaps two inputs.
func (s *sortableInputs) Swap(i, j int) {
	tx := s.p.UnsignedTx
	// PSBTv2: UnsignedTx will be nil for psbtVersion >= 2
	if tx != nil {
		tx.TxIn[i], tx.TxIn[j] = tx.TxIn[j], tx.TxIn[i]
	}
	s.p.Inputs[i], s.p.Inputs[j] = s.p.Inputs[j], s.p.Inputs[i]
}

// Swap swaps two outputs.
func (s *sortableOutputs) Swap(i, j int) {
	tx := s.p.UnsignedTx
	// PSBTv2: UnsignedTx will be nil for psbtVersion >= 2
	if tx != nil {
		tx.TxOut[i], tx.TxOut[j] = tx.TxOut[j], tx.TxOut[i]
	}
	s.p.Outputs[i], s.p.Outputs[j] = s.p.Outputs[j], s.p.Outputs[i]
}

// Less is the input comparison function. First sort based on input hash
// (reversed / rpc-style), then index. Only canonical inputs reach here since
// InPlaceSort refuses MWEB packets.
func (s *sortableInputs) Less(i, j int) bool {
	iPrevOut, _ := s.p.getPrevOut(i)
	jPrevOut, _ := s.p.getPrevOut(j)

	// A malformed input with no prevout sorts as equal-or-after rather than
	// panicking, keeping a strict weak ordering.
	if iPrevOut == nil || jPrevOut == nil {
		return iPrevOut != nil
	}

	// If hashes are the same, compare prevout indices
	ihash := iPrevOut.Hash
	jhash := jPrevOut.Hash
	if ihash == jhash {
		return iPrevOut.Index < jPrevOut.Index
	}

	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = chainhash.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}

// Less is the output comparison function. First sort based on amount (smallest
// first), then PkScript.
func (s *sortableOutputs) Less(i, j int) bool {
	if s.p.UnsignedTx == nil {
		// v2 canonical outputs; InPlaceSort refuses MWEB packets.
		oi, oj := &s.p.Outputs[i], &s.p.Outputs[j]
		if oi.Amount == oj.Amount {
			return bytes.Compare(oi.PKScript, oj.PKScript) < 0
		}
		return oi.Amount < oj.Amount
	}

	outs := s.p.UnsignedTx.TxOut

	if outs[i].Value == outs[j].Value {
		return bytes.Compare(outs[i].PkScript, outs[j].PkScript) < 0
	}
	return outs[i].Value < outs[j].Value
}
