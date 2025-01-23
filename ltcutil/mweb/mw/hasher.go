package mw

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

type HashTag byte

const (
	HashTagAddress   HashTag = 'A'
	HashTagBlind     HashTag = 'B'
	HashTagDerive    HashTag = 'D'
	HashTagNonce     HashTag = 'N'
	HashTagOutKey    HashTag = 'O'
	HashTagSendKey   HashTag = 'S'
	HashTagTag       HashTag = 'T'
	HashTagNonceMask HashTag = 'X'
	HashTagValueMask HashTag = 'Y'
)

func Hashed(tag HashTag, data []byte) *[32]byte {
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, tag)
	h.Write(data)
	return (*[32]byte)(h.Sum(nil))
}
