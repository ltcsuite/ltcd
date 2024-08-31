package mw

import (
	"bytes"
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Signature [64]byte

func Sign(key *SecretKey, msg []byte) (sig Signature) {
	h := sha256.New()
	h.Write(key[:])
	h.Write(msg)
	k := (*SecretKey)(h.Sum(nil))

	var r secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k.scalar(), &r)
	r.ToAffine()
	r.X.PutBytesUnchecked(sig[:])
	if !r.X.SquareRootVal(&r.Y) {
		k = k.Neg()
	}

	e := sig.challenge(key.PubKey(), msg)
	copy(sig[32:], key.Mul(e).Add(k)[:])
	return
}

func (sig *Signature) challenge(pk *PublicKey, msg []byte) *SecretKey {
	h := sha256.New()
	h.Write(sig[:32])
	h.Write(pk[:])
	h.Write(msg)
	return (*SecretKey)(h.Sum(nil))
}

func (sig *Signature) Verify(pk *PublicKey, msg []byte) bool {
	S := (*SecretKey)(sig[32:]).PubKey()
	e := sig.challenge(pk, msg)
	K := pk.Mul(e.Neg()).Add(S)
	r := K.toJacobian()
	return bytes.Equal(K[1:], sig[:32]) && r.X.SquareRootVal(&r.Y)
}
