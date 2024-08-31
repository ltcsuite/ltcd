package mw_test

import (
	"crypto/rand"
	"testing"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

func TestSignature(t *testing.T) {
	var (
		key mw.SecretKey
		msg [32]byte
	)
	for i := 0; i < 1e4; i++ {
		rand.Read(key[:])
		rand.Read(msg[:])
		sig := mw.Sign(&key, msg[:])
		if !sig.Verify(key.PubKey(), msg[:]) {
			t.Fatal("sig verify failed")
		}
	}
}
