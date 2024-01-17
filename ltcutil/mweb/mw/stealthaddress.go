package mw

type StealthAddress struct {
	Scan, Spend *PublicKey
}

func (sa *StealthAddress) A() *PublicKey {
	return sa.Scan
}

func (sa *StealthAddress) B() *PublicKey {
	return sa.Spend
}
