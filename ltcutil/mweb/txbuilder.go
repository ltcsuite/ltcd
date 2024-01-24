package mweb

import (
	"crypto/rand"
	"encoding/binary"

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
