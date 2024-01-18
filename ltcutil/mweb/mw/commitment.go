package mw

import (
	"encoding/binary"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Commitment [33]byte

var generatorH = [64]byte{
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
	0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
	0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
	0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
	0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
	0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
	0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04,
}

func NewCommitment(blind *BlindingFactor, value uint64) *Commitment {
	var H secp256k1.JacobianPoint
	H.X.SetBytes((*[32]byte)(generatorH[:32]))
	H.Y.SetBytes((*[32]byte)(generatorH[32:]))
	H.Z.SetInt(1)

	var bs, vs secp256k1.ModNScalar
	if bs.SetBytes((*[32]byte)(blind)) > 0 {
		panic("overflowed")
	}
	vs.SetByteSlice(binary.BigEndian.AppendUint64(nil, value))

	var bj, rj secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&bs, &bj)
	secp256k1.ScalarMultNonConst(&vs, &H, &rj)
	secp256k1.AddNonConst(&bj, &rj, &rj)
	rj.ToAffine()

	c := &Commitment{8}
	rj.X.PutBytesUnchecked(c[1:])
	if !rj.X.SquareRootVal(&rj.Y) {
		c[0]++
	}
	return c
}

func SwitchCommit(blind *BlindingFactor, value uint64) *Commitment {
	return NewCommitment(BlindSwitch(blind, value), value)
}
