package mweb

import (
	"encoding/binary"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"lukechampine.com/blake3"
)

type Keychain struct {
	Scan, Spend *mw.SecretKey
	SpendPubKey *mw.PublicKey
}

func (k *Keychain) mi(index uint32) *mw.SecretKey {
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, mw.HashTagAddress)
	binary.Write(h, binary.LittleEndian, index)
	h.Write(k.Scan[:])
	return (*mw.SecretKey)(h.Sum(nil))
}

func (k *Keychain) Address(index uint32) *mw.StealthAddress {
	if k.SpendPubKey == nil {
		k.SpendPubKey = k.Spend.PubKey()
	}
	Bi := k.SpendPubKey.Add(k.mi(index).PubKey())
	Ai := Bi.Mul(k.Scan)
	return &mw.StealthAddress{Scan: Ai, Spend: Bi}
}

func (k *Keychain) SpendKey(index uint32) *mw.SecretKey {
	return k.Spend.Add(k.mi(index))
}
