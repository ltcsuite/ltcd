package mw

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20"
)

type RangeProof [675]byte

func updateCommitHash(hash *[32]byte, lp, rp *secp256k1.JacobianPoint) {
	var lrParity byte
	if !new(secp256k1.FieldVal).SquareRootVal(&lp.Y) {
		lrParity = 2
	}
	if !new(secp256k1.FieldVal).SquareRootVal(&rp.Y) {
		lrParity++
	}
	h := sha256.New()
	h.Write(hash[:])
	binary.Write(h, binary.LittleEndian, lrParity)
	h.Write(lp.X.Bytes()[:])
	h.Write(rp.X.Bytes()[:])
	h.Sum(hash[:0])
}

func chacha20Scalars(key *SecretKey, index uint32) (k1, k2 secp256k1.ModNScalar) {
	for nonce := uint32(0); ; nonce++ {
		nonce := binary.LittleEndian.AppendUint32(make([]byte, 8), nonce)
		c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 64)
		c.SetCounter(index)
		c.XORKeyStream(buf, buf)
		if !k1.SetByteSlice(buf[:32]) && !k2.SetByteSlice(buf[32:]) {
			break
		}
	}
	return
}

type lrGenerator struct {
	nonce          *SecretKey
	y, z, yn, z22n secp256k1.ModNScalar
	val            uint64
	count          uint32
}

func (generator *lrGenerator) generate(x *secp256k1.ModNScalar) (
	lout, rout secp256k1.ModNScalar) {

	bit := uint32(generator.val>>generator.count) & 1

	if generator.count == 0 {
		generator.z22n.SquareVal(&generator.z)
	}

	sl, sr := chacha20Scalars(generator.nonce, generator.count+2)
	sl.Mul(x)
	sr.Mul(x)

	lout.SetInt(bit)
	var negz secp256k1.ModNScalar
	negz.NegateVal(&generator.z)
	lout.Add(&negz)
	lout.Add(&sl)

	rout.SetInt(1 - bit)
	rout.Negate()
	rout.Add(&generator.z)
	rout.Add(&sr)
	rout.Mul(&generator.yn)
	rout.Add(&generator.z22n)

	generator.count++
	generator.yn.Mul(&generator.y)
	generator.z22n.Add(&generator.z22n)
	return
}

func NewRangeProof(value uint64, blind *BlindingFactor,
	message, extraData []byte) *RangeProof {

	// Commit to all input data: pedersen commit, asset generator, extra_commit
	var commitHash [32]byte
	commit := newCommitment(blind, value)
	updateCommitHash(&commitHash, commit, generatorH())
	h := sha256.New()
	h.Write(commitHash[:])
	h.Write(extraData)
	h.Sum(commitHash[:0])

	var nonce, privateNonce SecretKey
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(privateNonce[:]); err != nil {
		panic(err)
	}

	alpha, rho := chacha20Scalars(&nonce, 0)
	tau1, tau2 := chacha20Scalars(&privateNonce, 1)

	// Encrypt value into alpha, so it will be recoverable from -mu by someone
	// who knows `nonce`.  Combine value with 20 bytes of optional message.
	var vals secp256k1.ModNScalar
	vals.SetByteSlice(binary.BigEndian.AppendUint64(message[:20], value))
	alpha.Add(vals.Negate()) // Negate so it'll be positive in -mu

	// Compute A and S
	var aj, sj secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&alpha, &aj)
	secp256k1.ScalarBaseMultNonConst(&rho, &sj)
	for j := uint32(0); j < 64; j++ {
		al := value&(1<<j) > 0
		aterm := *rangeProofGenerators[j+128]
		sl, sr := chacha20Scalars(&nonce, j+2)
		aterm.Y.Negate(1)
		if al {
			aterm = *rangeProofGenerators[j]
		}
		secp256k1.AddNonConst(&aj, &aterm, &aj)

		var stermj secp256k1.JacobianPoint
		secp256k1.ScalarMultNonConst(&sl, rangeProofGenerators[j], &stermj)
		secp256k1.AddNonConst(&sj, &stermj, &sj)
		secp256k1.ScalarMultNonConst(&sr, rangeProofGenerators[j+128], &stermj)
		secp256k1.AddNonConst(&sj, &stermj, &sj)
	}
	aj.ToAffine()
	sj.ToAffine()

	// Get challenges y and z
	outPt := [4]secp256k1.JacobianPoint{aj, sj} // inner product proof variables
	updateCommitHash(&commitHash, &outPt[0], &outPt[1])
	var y, z, zsq secp256k1.ModNScalar
	if y.SetBytes(&commitHash) > 0 || y.IsZero() {
		return nil
	}
	updateCommitHash(&commitHash, &outPt[0], &outPt[1])
	if z.SetBytes(&commitHash) > 0 || z.IsZero() {
		return nil
	}
	zsq.SquareVal(&z)

	// Compute coefficients t0, t1, t2 of the <l, r> polynomial
	var t0, t1, t2, zero secp256k1.ModNScalar

	// t0 = l(0) dot r(0)
	lrGen := &lrGenerator{nonce: &nonce, y: y, z: z, val: value}
	lrGen.yn.SetInt(1)
	for i := 0; i < 64; i++ {
		l, r := lrGen.generate(&zero)
		t0.Add(l.Mul(&r))
	}

	// A = t0 + t1 + t2 = l(1) dot r(1)
	lrGen = &lrGenerator{nonce: &nonce, y: y, z: z, val: value}
	lrGen.yn.SetInt(1)
	for i := 0; i < 64; i++ {
		l, r := lrGen.generate(new(secp256k1.ModNScalar).SetInt(1))
		t1.Add(l.Mul(&r))
	}

	// B = t0 - t1 + t2 = l(-1) dot r(-1)
	lrGen = &lrGenerator{nonce: &nonce, y: y, z: z, val: value}
	lrGen.yn.SetInt(1)
	for i := 0; i < 64; i++ {
		l, r := lrGen.generate(new(secp256k1.ModNScalar).SetInt(1).Negate())
		t2.Add(l.Mul(&r))
	}

	// t1 = (A - B)/2
	var tmps secp256k1.ModNScalar
	tmps.SetInt(2).InverseNonConst()
	t1.Add(t2.Negate()).Mul(&tmps)

	// t2 = -(-B + t0) + t1
	t2.Add(&t0).Negate().Add(&t1)

	// Compute Ti = t_i*A + tau_i*G for i = 1,2
	var tmpj secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&t1, generatorH(), &outPt[2])
	secp256k1.ScalarBaseMultNonConst(&tau1, &tmpj)
	secp256k1.AddNonConst(&outPt[2], &tmpj, &outPt[2])
	outPt[2].ToAffine()

	secp256k1.ScalarMultNonConst(&t2, generatorH(), &outPt[3])
	secp256k1.ScalarBaseMultNonConst(&tau2, &tmpj)
	secp256k1.AddNonConst(&outPt[3], &tmpj, &outPt[3])
	outPt[3].ToAffine()

	var x, xsq secp256k1.ModNScalar
	updateCommitHash(&commitHash, &outPt[2], &outPt[3])
	if x.SetBytes(&commitHash) > 0 || x.IsZero() {
		return nil
	}
	xsq.SquareVal(&x)

	// Compute tau_x and mu
	var taux, mu secp256k1.ModNScalar
	taux.Mul2(&tau1, &x)
	taux.Add(tmps.Mul2(&tau2, &xsq))
	taux.Add(tmps.Mul2(&zsq, blind.scalar()))
	zsq.Mul(&z)
	mu.Mul2(&rho, &x).Add(&alpha)

	// Negate taux and mu so the verifier doesn't have to
	taux.Negate()
	mu.Negate()

	// Encode rangeproof stuff
	proof := &RangeProof{}
	taux.PutBytesUnchecked(proof[:])
	mu.PutBytesUnchecked(proof[32:])
	for i, pt := range outPt {
		pt.X.PutBytesUnchecked(proof[65+i*32:])
		if !pt.X.SquareRootVal(&pt.Y) {
			proof[64] |= 1 << i
		}
	}

	// Mix this into the hash so the input to the inner product proof is fixed
	h = sha256.New()
	h.Write(commitHash[:])
	h.Write(proof[:64])
	h.Sum(commitHash[:0])

	// Compute l and r, do inner product proof
	lrGen = &lrGenerator{nonce: &nonce, y: y, z: z, val: value}
	lrGen.yn.SetInt(1)
	y.InverseNonConst()
	var cache secp256k1.ModNScalar
	proveInnerProduct(proof[193:], commitHash[:], func(sc *secp256k1.ModNScalar, i int) {
		if i%2 == 0 {
			*sc, cache = lrGen.generate(&x)
		} else {
			*sc = cache
		}
	})

	return proof
}

func proveInnerProduct(proof, commitHash []byte, cb func(*secp256k1.ModNScalar, int)) {
	var (
		aArr, bArr [64]secp256k1.ModNScalar
		genG, genH [64]*secp256k1.JacobianPoint
		dot, term  secp256k1.ModNScalar
	)
	for i := 0; i < 64; i++ {
		cb(&aArr[i], 2*i)
		cb(&bArr[i], 2*i+1)
		genG[i] = rangeProofGenerators[i]
		genH[i] = rangeProofGenerators[i+128]
		dot.Add(term.Mul2(&aArr[i], &bArr[i]))
	}

	// Record final dot product
	dot.PutBytesUnchecked(proof)

	// Protocol 2: hash dot product to obtain G-randomizer
	h := sha256.New()
	h.Write(commitHash)
	h.Write(proof[:32])
	h.Sum(commitHash[:0])

	proof = proof[32:]

	var ux secp256k1.ModNScalar
	ux.SetByteSlice(commitHash)

	// Final a/b values
	for i := 0; i < 2; i++ {
		aArr[i].PutBytesUnchecked(proof[32*i:])
		bArr[i].PutBytesUnchecked(proof[32*(i+2):])
	}
	proof = proof[128:]
	for i, pt := range outPt {
		pt.X.PutBytesUnchecked(proof[1+i*32:])
		if !pt.X.SquareRootVal(&pt.Y) {
			proof[0] |= 1 << i
		}
	}
}
