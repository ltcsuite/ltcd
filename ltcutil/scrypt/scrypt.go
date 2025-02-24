package scrypt

import (
	"crypto/sha256"
	"math/bits"
	"sync"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
)

type scratch = [1024][32]uint32

var pool = sync.Pool{New: func() interface{} {
	return &scratch{}
}}

func Scrypt(x []byte) []byte {
	X := pbkdf2.Key(x, x, 1, 128, sha256.New)
	scrypt((*[32]uint32)(unsafe.Pointer(&X[0])))
	return pbkdf2.Key(x, X, 1, 32, sha256.New)
}

func scrypt(X *[32]uint32) {
	var (
		A = (*[16]uint32)(X[:16])
		B = (*[16]uint32)(X[16:])
		V = pool.Get().(*scratch)
	)

	for i := 0; i < len(V); i++ {
		V[i] = *X
		salsa8(A, B)
		salsa8(B, A)
	}

	for i := 0; i < len(V); i++ {
		j := X[16] % uint32(len(V))
		for k := 0; k < len(X); k++ {
			X[k] ^= V[j][k]
		}
		salsa8(A, B)
		salsa8(B, A)
	}

	pool.Put(V)
}

func salsa8(A, B *[16]uint32) {
	A[0] ^= B[0]
	A[1] ^= B[1]
	A[2] ^= B[2]
	A[3] ^= B[3]
	A[4] ^= B[4]
	A[5] ^= B[5]
	A[6] ^= B[6]
	A[7] ^= B[7]
	A[8] ^= B[8]
	A[9] ^= B[9]
	A[10] ^= B[10]
	A[11] ^= B[11]
	A[12] ^= B[12]
	A[13] ^= B[13]
	A[14] ^= B[14]
	A[15] ^= B[15]

	x00, x01, x02, x03 := A[0], A[1], A[2], A[3]
	x04, x05, x06, x07 := A[4], A[5], A[6], A[7]
	x08, x09, x10, x11 := A[8], A[9], A[10], A[11]
	x12, x13, x14, x15 := A[12], A[13], A[14], A[15]

	for i := 0; i < 4; i++ {
		// Columns
		x04 ^= bits.RotateLeft32(x00+x12, 7)
		x09 ^= bits.RotateLeft32(x05+x01, 7)
		x14 ^= bits.RotateLeft32(x10+x06, 7)
		x03 ^= bits.RotateLeft32(x15+x11, 7)

		x08 ^= bits.RotateLeft32(x04+x00, 9)
		x13 ^= bits.RotateLeft32(x09+x05, 9)
		x02 ^= bits.RotateLeft32(x14+x10, 9)
		x07 ^= bits.RotateLeft32(x03+x15, 9)

		x12 ^= bits.RotateLeft32(x08+x04, 13)
		x01 ^= bits.RotateLeft32(x13+x09, 13)
		x06 ^= bits.RotateLeft32(x02+x14, 13)
		x11 ^= bits.RotateLeft32(x07+x03, 13)

		x00 ^= bits.RotateLeft32(x12+x08, 18)
		x05 ^= bits.RotateLeft32(x01+x13, 18)
		x10 ^= bits.RotateLeft32(x06+x02, 18)
		x15 ^= bits.RotateLeft32(x11+x07, 18)

		// Rows
		x01 ^= bits.RotateLeft32(x00+x03, 7)
		x06 ^= bits.RotateLeft32(x05+x04, 7)
		x11 ^= bits.RotateLeft32(x10+x09, 7)
		x12 ^= bits.RotateLeft32(x15+x14, 7)

		x02 ^= bits.RotateLeft32(x01+x00, 9)
		x07 ^= bits.RotateLeft32(x06+x05, 9)
		x08 ^= bits.RotateLeft32(x11+x10, 9)
		x13 ^= bits.RotateLeft32(x12+x15, 9)

		x03 ^= bits.RotateLeft32(x02+x01, 13)
		x04 ^= bits.RotateLeft32(x07+x06, 13)
		x09 ^= bits.RotateLeft32(x08+x11, 13)
		x14 ^= bits.RotateLeft32(x13+x12, 13)

		x00 ^= bits.RotateLeft32(x03+x02, 18)
		x05 ^= bits.RotateLeft32(x04+x07, 18)
		x10 ^= bits.RotateLeft32(x09+x08, 18)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}

	A[0] += x00
	A[1] += x01
	A[2] += x02
	A[3] += x03
	A[4] += x04
	A[5] += x05
	A[6] += x06
	A[7] += x07
	A[8] += x08
	A[9] += x09
	A[10] += x10
	A[11] += x11
	A[12] += x12
	A[13] += x13
	A[14] += x14
	A[15] += x15
}
