package mweb

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

type PaymentProof struct {
	Output    []byte
	OutputId  string
	Address   string
	Value     uint64
	Nonce     []byte
	Signature mw.Signature
}

func NewPaymentProof(address string, value uint64, senderKey *mw.SecretKey,
	rangeProofHash chainhash.Hash) (*PaymentProof, error) {

	addr, err := ltcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	output, _, _ := CreateOutput(&Recipient{
		Address: addr.(*ltcutil.AddressMweb).StealthAddress(),
		Value:   value,
	}, senderKey)
	output.RangeProofHash = rangeProofHash
	SignOutput2(output, senderKey)

	var buf bytes.Buffer
	output.SerializeCompact(&buf)
	nonce := mw.Hashed(mw.HashTagNonce, senderKey[:])[:16]

	return &PaymentProof{
		Output:    buf.Bytes(),
		OutputId:  hex.EncodeToString(output.Hash()[:]),
		Address:   address,
		Value:     value,
		Nonce:     nonce,
		Signature: mw.Sign(senderKey, nonce),
	}, nil
}

func (pp *PaymentProof) Verify() error {
	addr, err := ltcutil.DecodeAddress(pp.Address, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	var output wire.MwebOutput
	if err = output.DeserializeCompact(bytes.NewReader(pp.Output)); err != nil {
		return err
	}
	if hex.EncodeToString(output.Hash()[:]) != pp.OutputId {
		return errors.New("output id mismatch")
	}

	output2, _, _ := CreateOutput2(&Recipient{
		Address: addr.(*ltcutil.AddressMweb).StealthAddress(),
		Value:   pp.Value,
	}, new(big.Int).SetBytes(pp.Nonce))
	output2.SenderPubKey = output.SenderPubKey
	output2.RangeProofHash = output.RangeProofHash
	output2.Signature = output.Signature

	if *output2.Hash() != *output.Hash() {
		return errors.New("output id mismatch")
	}
	if !pp.Signature.Verify(&output.SenderPubKey, pp.Nonce) {
		return errors.New("sender key signature invalid")
	}

	return nil
}
