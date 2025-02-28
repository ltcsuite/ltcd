package scrypt

import (
	"crypto/sha256"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

type scratch [1024][32]uint32

var pool = sync.Pool{New: func() interface{} {
	return &scratch{}
}}

func Scrypt(x []byte) []byte {
	X := pbkdf2.Key(x, x, 1, 128, sha256.New)
	V := pool.Get().(*scratch)
	scrypt(&X[0], V)
	pool.Put(V)
	return pbkdf2.Key(x, X, 1, 32, sha256.New)
}

func scrypt(X *byte, V *scratch)
