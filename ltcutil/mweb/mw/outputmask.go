package mw

import (
	"encoding/binary"
	"math/big"
)

type OutputMask struct {
	Blind     *BlindingFactor
	valueMask uint64
	nonceMask big.Int
}

// Feeds the shared secret 't' into tagged hash functions to derive:
//
//	q - the blinding factor
//	v' - the value mask
//	n' - the nonce mask
func OutputMaskFromShared(sharedSecret *SecretKey) *OutputMask {
	mask := &OutputMask{
		Blind:     (*BlindingFactor)(Hashed(HashTagBlind, sharedSecret[:])),
		valueMask: binary.LittleEndian.Uint64(Hashed(HashTagValueMask, sharedSecret[:])[:]),
	}
	mask.nonceMask.SetBytes(Hashed(HashTagNonceMask, sharedSecret[:])[:16])
	return mask
}

func (om *OutputMask) MaskValue(value uint64) uint64 {
	return value ^ om.valueMask
}

func (om *OutputMask) MaskNonce(nonce *big.Int) *big.Int {
	return new(big.Int).Xor(nonce, &om.nonceMask)
}

func (om *OutputMask) SwitchCommit(value uint64) *Commitment {
	return SwitchCommit(om.Blind, value)
}
