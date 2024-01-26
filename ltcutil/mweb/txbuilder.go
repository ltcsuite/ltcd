package mweb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

func CreateInputs(coins []*Coin) []*wire.MwebInput {
	var (
		inputs       []*wire.MwebInput
		totalBlind   = &mw.BlindingFactor{}
		totalKey     = &mw.SecretKey{}
		ephemeralKey = &mw.SecretKey{}
	)
	for _, coin := range coins {
		if _, err := rand.Read(ephemeralKey[:]); err != nil {
			return nil
		}
		blind := mw.BlindSwitch(coin.Blind, coin.Value)
		commitment := mw.NewCommitment(blind, coin.Value)
		inputs = append(inputs, createInput(coin, commitment, ephemeralKey))
		totalBlind = totalBlind.Add(blind)
		totalKey = totalKey.Add(ephemeralKey).Sub(coin.SpendKey)
	}

	return inputs
}

// Creates a standard input with a stealth key (feature bit = 1)
func createInput(coin *Coin, commitment *mw.Commitment,
	inputKey *mw.SecretKey) *wire.MwebInput {

	features := wire.MwebInputStealthKeyFeatureBit
	inputPubKey := inputKey.PubKey()
	outputPubKey := coin.SpendKey.PubKey()

	// Hash keys (K_i||K_o)
	h := blake3.New(32, nil)
	h.Write(inputPubKey[:])
	h.Write(outputPubKey[:])
	keyHash := (*mw.SecretKey)(h.Sum(nil))

	// Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
	sigKey := coin.SpendKey.Mul(keyHash).Add(inputKey)

	// Hash message
	h = blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, features)
	h.Write(coin.OutputId[:])
	msgHash := h.Sum(nil)

	return &wire.MwebInput{
		Features:     features,
		OutputId:     *coin.OutputId,
		Commitment:   *commitment,
		InputPubKey:  inputPubKey,
		OutputPubKey: *outputPubKey,
		Signature:    mw.Sign(sigKey, msgHash),
	}
}

type Recipient struct {
	Value   uint64
	Address *mw.StealthAddress
}

func CreateOutputs(recipients []*Recipient) ([]*wire.MwebOutput, []*Coin) {
	var (
		outputs      []*wire.MwebOutput
		coins        []*Coin
		totalBlind   = &mw.BlindingFactor{}
		totalKey     = &mw.SecretKey{}
		ephemeralKey = &mw.SecretKey{}
	)
	for _, recipient := range recipients {
		if _, err := rand.Read(ephemeralKey[:]); err != nil {
			return nil, nil
		}
		output, blind := createOutput(recipient, ephemeralKey)
		totalBlind = totalBlind.Add(mw.BlindSwitch(blind, recipient.Value))
		totalKey = totalKey.Add(ephemeralKey)
		outputs = append(outputs, output)

		coins = append(coins, &Coin{
			Blind:     blind,
			Value:     recipient.Value,
			OutputId:  output.Hash(),
			SenderKey: ephemeralKey,
			Address:   recipient.Address,
		})
	}
	return outputs, coins
}

func createOutput(recipient *Recipient, senderKey *mw.SecretKey) (
	*wire.MwebOutput, *mw.BlindingFactor) {

	// We only support standard feature fields for now
	features := wire.MwebOutputMessageStandardFieldsFeatureBit

	// Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
	n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])

	// Calculate unique sending key 's' = H(T_send, A, B, v, n)
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	h.Write(recipient.Address.A()[:])
	h.Write(recipient.Address.B()[:])
	binary.Write(h, binary.LittleEndian, recipient.Value)
	h.Write(n.FillBytes(make([]byte, 16)))
	s := (*mw.SecretKey)(h.Sum(nil))

	// Derive shared secret 't' = H(T_derive, s*A)
	sA := recipient.Address.A().Mul(s)
	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))

	// Construct one-time public key for receiver 'Ko' = H(T_outkey, t)*B
	Ko := recipient.Address.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))

	// Key exchange public key 'Ke' = s*B
	Ke := recipient.Address.B().Mul(s)

	// Calc blinding factor and mask nonce and amount
	mask := mw.OutputMaskFromShared(t)
	blind := mw.BlindSwitch(mask.Blind, recipient.Value)
	mv := mask.MaskValue(recipient.Value)
	mn := mask.MaskNonce(n)

	// Commitment 'C' = r*G + v*H
	outputCommit := mw.NewCommitment(blind, recipient.Value)

	// Calculate the ephemeral send pubkey 'Ks' = ks*G
	Ks := senderKey.PubKey()

	// Derive view tag as first byte of H(T_tag, sA)
	viewTag := mw.Hashed(mw.HashTagTag, sA[:])[0]

	message := &wire.MwebOutputMessage{
		Features:          features,
		KeyExchangePubKey: *Ke,
		ViewTag:           viewTag,
		MaskedValue:       mv,
		MaskedNonce:       *mn,
	}
	var messageBuf bytes.Buffer
	message.Serialize(&messageBuf)

	// Probably best to store sender_key so sender
	// can identify all outputs they've sent?
	rangeProof := mw.NewRangeProof(recipient.Value,
		blind, make([]byte, 20), messageBuf.Bytes())
	rangeProofHash := blake3.Sum256(rangeProof[:])

	// Sign the output
	h = blake3.New(32, nil)
	h.Write(outputCommit[:])
	h.Write(Ks[:])
	h.Write(Ko[:])
	h.Write(message.Hash()[:])
	h.Write(rangeProofHash[:])
	signature := mw.Sign(senderKey, h.Sum(nil))

	return &wire.MwebOutput{
		Commitment:     *outputCommit,
		SenderPubKey:   *Ks,
		ReceiverPubKey: *Ko,
		Message:        *message,
		RangeProof:     rangeProof,
		RangeProofHash: rangeProofHash,
		Signature:      signature,
	}, mask.Blind
}
