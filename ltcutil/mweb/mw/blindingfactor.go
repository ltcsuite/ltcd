package mw

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type BlindingFactor [32]byte

var generatorJPubKey = [33]byte{
	0x02,
	0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3,
	0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a, 0x2f,
	0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d,
	0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15, 0x5f,
}

func BlindSwitch(blind *BlindingFactor, value uint64) *BlindingFactor {
	var blindScalar, blindSwitchScalar secp256k1.ModNScalar
	if blindScalar.SetBytes((*[32]byte)(blind)) > 0 {
		panic("overflowed")
	}
	h := sha256.New()
	h.Write(NewCommitment(blind, value)[:])
	h.Write(mulPubKey(generatorJPubKey[:], &blindScalar)[:])
	if blindSwitchScalar.SetBytes((*[32]byte)(h.Sum(nil))) > 0 {
		panic("overflowed")
	}
	blindSwitchScalar.Add(&blindScalar)
	ret := BlindingFactor(blindSwitchScalar.Bytes())
	return &ret
}
