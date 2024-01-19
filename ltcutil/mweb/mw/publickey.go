package mw

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type PublicKey [33]byte

func pubKeyJacobian(pk []byte) (p secp256k1.JacobianPoint) {
	key, err := secp256k1.ParsePubKey(pk)
	if err != nil {
		panic(err)
	}
	key.AsJacobian(&p)
	return
}

func pubKeySerialize(p *secp256k1.JacobianPoint) *PublicKey {
	p.ToAffine()
	key := secp256k1.NewPublicKey(&p.X, &p.Y)
	return (*PublicKey)(key.SerializeCompressed())
}

func pubKeyMul(pk []byte, k *secp256k1.ModNScalar) *PublicKey {
	p := pubKeyJacobian(pk)
	secp256k1.ScalarMultNonConst(k, &p, &p)
	return pubKeySerialize(&p)
}

func (pk *PublicKey) Add(p *PublicKey) *PublicKey {
	p1 := pubKeyJacobian(pk[:])
	p2 := pubKeyJacobian(p[:])
	secp256k1.AddNonConst(&p1, &p2, &p2)
	return pubKeySerialize(&p2)
}

func (pk *PublicKey) Mul(sk *SecretKey) *PublicKey {
	return pubKeyMul(pk[:], sk.scalar())
}

func (pk *PublicKey) Div(sk *SecretKey) *PublicKey {
	return pubKeyMul(pk[:], sk.scalar().InverseNonConst())
}
