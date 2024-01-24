package mw

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type PublicKey [33]byte

func (pk *PublicKey) toJacobian() (p secp256k1.JacobianPoint) {
	key, err := secp256k1.ParsePubKey(pk[:])
	if err != nil {
		panic(err)
	}
	key.AsJacobian(&p)
	return
}

func toPubKey(p *secp256k1.JacobianPoint) *PublicKey {
	p.ToAffine()
	key := secp256k1.NewPublicKey(&p.X, &p.Y)
	return (*PublicKey)(key.SerializeCompressed())
}

func (pk *PublicKey) mul(k *secp256k1.ModNScalar) *PublicKey {
	p := pk.toJacobian()
	secp256k1.ScalarMultNonConst(k, &p, &p)
	return toPubKey(&p)
}

func (pk *PublicKey) Add(p *PublicKey) *PublicKey {
	p1 := pk.toJacobian()
	p2 := p.toJacobian()
	secp256k1.AddNonConst(&p1, &p2, &p2)
	return toPubKey(&p2)
}

func (pk *PublicKey) Mul(sk *SecretKey) *PublicKey {
	return pk.mul(sk.scalar())
}

func (pk *PublicKey) Div(sk *SecretKey) *PublicKey {
	return pk.mul(sk.scalar().InverseNonConst())
}
