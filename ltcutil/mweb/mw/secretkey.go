package mw

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type SecretKey [32]byte

func (s *SecretKey) scalar() *secp256k1.ModNScalar {
	k := &secp256k1.ModNScalar{}
	if k.SetBytes((*[32]byte)(s)) > 0 {
		panic("overflowed")
	}
	return k
}

func (s *SecretKey) Add(sk *SecretKey) *SecretKey {
	r := SecretKey(s.scalar().Add(sk.scalar()).Bytes())
	return &r
}

func (s *SecretKey) Sub(sk *SecretKey) *SecretKey {
	return s.Add(sk.Neg())
}

func (s *SecretKey) Neg() *SecretKey {
	r := SecretKey(s.scalar().Negate().Bytes())
	return &r
}

func (s *SecretKey) Mul(sk *SecretKey) *SecretKey {
	k := s.scalar()
	if k.IsZero() {
		return s
	}
	r := SecretKey(k.Mul(sk.scalar()).Bytes())
	return &r
}

func (s *SecretKey) PubKey() *PublicKey {
	k := s.scalar()
	if k.IsZero() {
		k.SetInt(1)
	}
	key := secp256k1.NewPrivateKey(k).PubKey()
	return (*PublicKey)(key.SerializeCompressed())
}
