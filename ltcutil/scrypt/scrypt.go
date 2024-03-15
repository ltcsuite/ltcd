package scrypt

// void scrypt_aux(unsigned char*);
import "C"

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func Scrypt(x []byte) []byte {
	X := pbkdf2.Key(x, x, 1, 128, sha256.New)
	C.scrypt_aux((*C.uchar)(&X[0]))
	return pbkdf2.Key(x, X, 1, 32, sha256.New)
}
