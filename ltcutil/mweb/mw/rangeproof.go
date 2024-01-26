package mw

// #cgo CFLAGS: -I./secp256k1/include
// #cgo LDFLAGS: ${SRCDIR}/secp256k1/.libs/libsecp256k1.a
// #include <stdlib.h>
// #include <secp256k1_bulletproofs.h>
import "C"

import "crypto/rand"

type RangeProof [675]byte

var (
	bpContext = C.secp256k1_context_create(
		C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
	bpGenerators = C.secp256k1_bulletproof_generators_create(
		bpContext, &C.secp256k1_generator_const_g, 256)
)

func makeRandomBytes() (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return
}

func NewRangeProof(value uint64, blind *BlindingFactor,
	message, extraData []byte) (proof RangeProof) {

	seed := makeRandomBytes()
	nonce := makeRandomBytes()
	privateNonce := makeRandomBytes()

	ret := C.secp256k1_context_randomize(bpContext, (*C.uchar)(&seed[0]))
	if ret != 1 {
		panic("Context randomization failed")
	}

	scratch := C.secp256k1_scratch_space_create(bpContext, 1<<28)
	proofLen := C.ulong(len(proof))
	blindPtr := C.CBytes(blind[:])
	blinds := []*C.uchar{(*C.uchar)(blindPtr)}

	ret = C.secp256k1_bulletproof_rangeproof_prove(bpContext, scratch,
		bpGenerators, (*C.uchar)(&proof[0]), &proofLen, nil, nil, nil,
		(*C.ulonglong)(&value), nil, &blinds[0], nil, 1,
		&C.secp256k1_generator_const_h, 64, (*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateNonce[0]), (*C.uchar)(&extraData[0]),
		C.ulong(len(extraData)), (*C.uchar)(&message[0]))

	C.free(blindPtr)
	C.secp256k1_scratch_space_destroy(bpContext, scratch)

	if ret != 1 {
		panic("secp256k1_bulletproof_rangeproof_prove failed")
	}
	return
}
