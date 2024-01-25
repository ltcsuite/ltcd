package mw

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var rangeProofGenerators [256]*secp256k1.JacobianPoint

func init() {
	makeRangeProofGenerators()
}

func makeRangeProofGenerators() {
	var G secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(new(secp256k1.ModNScalar).SetInt(1), &G)
	G.ToAffine()
	for i := 0; i < len(rangeProofGenerators); i++ {
		tmp := secp256k1.NonceRFC6979(G.X.Bytes()[:], G.Y.Bytes()[:], nil, nil, uint32(i))
		rangeProofGenerators[i] = makeRangeProofGenerator(tmp)
	}
}

func makeRangeProofGenerator(key *secp256k1.ModNScalar) *secp256k1.JacobianPoint {
	var t secp256k1.FieldVal
	keyBytes := key.Bytes()
	h := sha256.New()
	h.Write([]byte("1st generation: "))
	h.Write(keyBytes[:])
	t.SetByteSlice(h.Sum(nil))
	accum := shallueVanDeWoestijne(&t)
	h = sha256.New()
	h.Write([]byte("2nd generation: "))
	h.Write(keyBytes[:])
	t.SetByteSlice(h.Sum(nil))
	add := shallueVanDeWoestijne(&t)
	secp256k1.AddNonConst(&accum, &add, &accum)
	accum.ToAffine()
	return &accum
}

func shallueVanDeWoestijne(t *secp256k1.FieldVal) (ge secp256k1.JacobianPoint) {
	var c, d, b, bPlus1, wn, wd, x1n, x2n, x3n, x3d, jInv, tmp,
		x1, x2, x3, alphaIn, betaIn, gammaIn, y1, y2, y3 secp256k1.FieldVal

	cb, _ := hex.DecodeString("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852")
	c.SetByteSlice(cb)
	db, _ := hex.DecodeString("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40")
	d.SetByteSlice(db)
	b.SetInt(7)
	bPlus1.SetInt(8)

	wn.Mul2(&c, t)       // mag 1
	wd.SquareVal(t)      // mag 1
	wd.Add(&bPlus1)      // mag 2
	tmp.Mul2(t, &wn)     // mag 1
	tmp.Negate(1)        // mag 2
	x1n.Mul2(&d, &wd)    // mag 1
	x1n.Add(&tmp)        // mag 3
	x2n = x1n            // mag 3
	x2n.Add(&wd)         // mag 5
	x2n.Negate(5)        // mag 6
	x3d.Mul2(&c, t)      // mag 1
	x3d.Square()         // mag 1
	x3n.SquareVal(&wd)   // mag 1
	x3n.Add(&x3d)        // mag 2
	jInv.Mul2(&x3d, &wd) // mag 1
	jInv.Inverse()       // mag 1
	x1.Mul2(&x1n, &x3d)  // mag 1
	x1.Mul(&jInv)        // mag 1
	x2.Mul2(&x2n, &x3d)  // mag 1
	x2.Mul(&jInv)        // mag 1
	x3.Mul2(&x3n, &wd)   // mag 1
	x3.Mul(&jInv)        // mag 1

	alphaIn.SquareVal(&x1) // mag 1
	alphaIn.Mul(&x1)       // mag 1
	alphaIn.Add(&b)        // mag 2
	betaIn.SquareVal(&x2)  // mag 1
	betaIn.Mul(&x2)        // mag 1
	betaIn.Add(&b)         // mag 2
	gammaIn.SquareVal(&x3) // mag 1
	gammaIn.Mul(&x3)       // mag 1
	gammaIn.Add(&b)        // mag 2

	alphaQuad := y1.SquareRootVal(&alphaIn)
	betaQuad := y2.SquareRootVal(&betaIn)
	y3.SquareRootVal(&gammaIn)

	if !alphaQuad {
		if betaQuad {
			x1 = x2
			y1 = y2
		} else {
			x1 = x3
			y1 = y3
		}
	}

	ge.X = x1
	ge.Y = y1
	ge.Z.SetInt(1)

	tmp.NegateVal(&ge.Y, 1)
	if t.IsOdd() {
		ge.Y = tmp
	}
	return
}
