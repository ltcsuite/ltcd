package mw

/*
#cgo CFLAGS: -Isecp256k1 -Isecp256k1/src
#define USE_BASIC_CONFIG
#define ENABLE_MODULE_GENERATOR
#define ENABLE_MODULE_BULLETPROOF
#include "basic-config.h"
#include "secp256k1.c"
#include "precomputed_ecmult.c"
#include "precomputed_ecmult_gen.c"
*/
import "C"

import "crypto/rand"

type RangeProof [675]byte

var (
	secp256k1Context    = C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN)
	secp256k1Generators = C.secp256k1_bulletproof_generators_create(
		secp256k1Context, &C.secp256k1_generator_const_g, 256)
)

func makeRandomBytes() (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return
}

func randomizeContext() {
	seed := makeRandomBytes()
	if C.secp256k1_context_randomize(secp256k1Context, (*C.uchar)(&seed[0])) != 1 {
		panic("secp256k1_context_randomize failed")
	}
}

func NewRangeProof(value uint64, blind *BlindingFactor,
	message, extraData []byte) (proof RangeProof) {

	randomizeContext()

	var (
		scratch      = C.secp256k1_scratch_space_create(secp256k1Context, 1<<28)
		proofLen     = C.ulong(len(proof))
		blindPtr     = C.CBytes(blind[:])
		blinds       = []*C.uchar{(*C.uchar)(blindPtr)}
		nonce        = makeRandomBytes()
		privateNonce = makeRandomBytes()
	)

	ret := C.secp256k1_bulletproof_rangeproof_prove(secp256k1Context,
		scratch, secp256k1Generators, (*C.uchar)(&proof[0]), &proofLen,
		nil, nil, nil, (*C.ulonglong)(&value), nil, &blinds[0], nil, 1,
		&C.secp256k1_generator_const_h, 64, (*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateNonce[0]), (*C.uchar)(&extraData[0]),
		C.ulong(len(extraData)), (*C.uchar)(&message[0]))

	C.free(blindPtr)
	C.secp256k1_scratch_space_destroy(secp256k1Context, scratch)

	if ret != 1 {
		panic("secp256k1_bulletproof_rangeproof_prove failed")
	}
	return
}
