package mweb

import (
	"encoding/binary"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"lukechampine.com/blake3"
)

type Keychain struct {
	Scan, Spend *mw.SecretKey
}

func (k *Keychain) Address(index uint32) *mw.StealthAddress {
	Bi := k.SpendKey(index).PubKey()
	Ai := Bi.Mul(k.Scan)
	return &mw.StealthAddress{Scan: Ai, Spend: Bi}
}

func (k *Keychain) SpendKey(index uint32) *mw.SecretKey {
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, mw.HashTagAddress)
	binary.Write(h, binary.LittleEndian, index)
	h.Write(k.Scan[:])
	mi := (*mw.SecretKey)(h.Sum(nil))
	return k.Spend.Add(mi)
}
