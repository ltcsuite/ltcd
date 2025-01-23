package mw

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type PublicKey [33]byte

func (pk *PublicKey) toJacobian() *secp256k1.JacobianPoint {
	key, err := secp256k1.ParsePubKey(pk[:])
	if err != nil {
		panic(err)
	}
	var r secp256k1.JacobianPoint
	key.AsJacobian(&r)
	return &r
}

func toPubKey(r *secp256k1.JacobianPoint) *PublicKey {
	r.ToAffine()
	key := secp256k1.NewPublicKey(&r.X, &r.Y)
	return (*PublicKey)(key.SerializeCompressed())
}

func (pk *PublicKey) Add(p *PublicKey) *PublicKey {
	r := p.toJacobian()
	secp256k1.AddNonConst(pk.toJacobian(), r, r)
	return toPubKey(r)
}

func (pk *PublicKey) Sub(p *PublicKey) *PublicKey {
	r := p.toJacobian()
	r.Y.Negate(1)
	secp256k1.AddNonConst(pk.toJacobian(), r, r)
	return toPubKey(r)
}

func (pk *PublicKey) mul(k *secp256k1.ModNScalar) *PublicKey {
	r := pk.toJacobian()
	secp256k1.ScalarMultNonConst(k, r, r)
	return toPubKey(r)
}

func (pk *PublicKey) Mul(sk *SecretKey) *PublicKey {
	return pk.mul(sk.scalar())
}

func (pk *PublicKey) Div(sk *SecretKey) *PublicKey {
	return pk.mul(sk.scalar().InverseNonConst())
}
