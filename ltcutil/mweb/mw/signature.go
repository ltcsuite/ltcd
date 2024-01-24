package mw

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Signature [64]byte

func Sign(key *SecretKey, message []byte) (sig Signature) {
	h := sha256.New()
	h.Write(key[:])
	h.Write(message)
	k := (*SecretKey)(h.Sum(nil)).scalar()

	var r secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &r)
	r.ToAffine()
	if !new(secp256k1.FieldVal).SquareRootVal(&r.Y) {
		k.Negate()
	}
	r.X.PutBytesUnchecked(sig[:32])

	h = sha256.New()
	h.Write(sig[:32])
	h.Write(key.PubKey()[:])
	h.Write(message)

	e := (*SecretKey)(h.Sum(nil)).Mul(key).scalar()
	e.Add(k).PutBytesUnchecked(sig[32:])
	return
}
