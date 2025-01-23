package mw

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type BlindingFactor [32]byte

var generatorJ = PublicKey{
	0x02,
	0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3,
	0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a, 0x2f,
	0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d,
	0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15, 0x5f,
}

func (b *BlindingFactor) scalar() *secp256k1.ModNScalar {
	k := &secp256k1.ModNScalar{}
	if k.SetBytes((*[32]byte)(b)) > 0 {
		panic("overflowed")
	}
	return k
}

func (b *BlindingFactor) Add(blind *BlindingFactor) *BlindingFactor {
	r := BlindingFactor(b.scalar().Add(blind.scalar()).Bytes())
	return &r
}

func (b *BlindingFactor) Sub(blind *BlindingFactor) *BlindingFactor {
	r := BlindingFactor(b.scalar().Add(blind.scalar().Negate()).Bytes())
	return &r
}

func BlindSwitch(blind *BlindingFactor, value uint64) *BlindingFactor {
	h := sha256.New()
	h.Write(NewCommitment(blind, value)[:])
	h.Write(generatorJ.mul(blind.scalar())[:])
	return (*BlindingFactor)(h.Sum(nil)).Add(blind)
}
