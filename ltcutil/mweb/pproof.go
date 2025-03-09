package mweb

import (
	"errors"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

type PaymentProof struct {
	Nonce           [16]byte
	SenderPubKey    mw.PublicKey
	RangeProofHash  chainhash.Hash
	OutputSignature mw.Signature
	NonceSignature  mw.Signature
}

func NewPaymentProof(recipient *Recipient, senderKey *mw.SecretKey,
	rangeProofHash chainhash.Hash) *PaymentProof {

	var nonce [16]byte
	copy(nonce[:], mw.Hashed(mw.HashTagNonce, senderKey[:])[:])
	output, _, _ := CreateOutput(recipient, senderKey)
	output.RangeProofHash = rangeProofHash

	return &PaymentProof{
		Nonce:           nonce,
		SenderPubKey:    output.SenderPubKey,
		RangeProofHash:  rangeProofHash,
		OutputSignature: mw.Sign(senderKey, output.SigMsg()),
		NonceSignature:  mw.Sign(senderKey, nonce[:]),
	}
}

func (pp *PaymentProof) Verify(recipient *Recipient) (*chainhash.Hash, error) {
	output, _, _ := createOutputWithNonce(recipient, pp.Nonce)
	output.SenderPubKey = pp.SenderPubKey
	output.RangeProofHash = pp.RangeProofHash
	output.Signature = pp.OutputSignature

	if !output.VerifySig() {
		return nil, errors.New("output signature invalid")
	}
	if !pp.NonceSignature.Verify(&pp.SenderPubKey, pp.Nonce[:]) {
		return nil, errors.New("nonce signature invalid")
	}

	return output.Hash(), nil
}
