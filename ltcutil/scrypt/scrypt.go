//go:build !arm64

package scrypt

import scrypt2 "golang.org/x/crypto/scrypt"

func Scrypt(x []byte) []byte {
	x, _ = scrypt2.Key(x, x, 1024, 1, 1, 32)
	return x
}
