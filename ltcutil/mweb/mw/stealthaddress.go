package mw

import "bytes"

type StealthAddress struct {
	Scan, Spend *PublicKey
}

func (sa *StealthAddress) A() *PublicKey {
	return sa.Scan
}

func (sa *StealthAddress) B() *PublicKey {
	return sa.Spend
}

func (sa *StealthAddress) Equal(addr *StealthAddress) bool {
	return bytes.Equal(sa.Scan[:], addr.Scan[:]) &&
		bytes.Equal(sa.Spend[:], addr.Spend[:])
}
