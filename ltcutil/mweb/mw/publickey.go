package mw

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type PublicKey [33]byte

func mulPubKey(pk []byte, k *secp256k1.ModNScalar) *PublicKey {
	key, err := secp256k1.ParsePubKey(pk)
	if err != nil {
		panic(err)
	}
	var p secp256k1.JacobianPoint
	key.AsJacobian(&p)
	secp256k1.ScalarMultNonConst(k, &p, &p)
	p.ToAffine()
	key = secp256k1.NewPublicKey(&p.X, &p.Y)
	return (*PublicKey)(key.SerializeCompressed())
}

func (pk *PublicKey) Mul(sk *SecretKey) *PublicKey {
	return mulPubKey(pk[:], sk.scalar())
}

func (pk *PublicKey) Div(sk *SecretKey) *PublicKey {
	return mulPubKey(pk[:], sk.scalar().InverseNonConst())
}
