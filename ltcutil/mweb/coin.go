package mweb

import (
	"encoding/binary"
	"errors"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

// Represents an output owned by the wallet, or one sent by the wallet.
type Coin struct {
	// The private key needed in order to spend the coin.
	// Will be nil for watch-only wallets.
	// May be nil for locked wallets. Upon unlock, SpendKey will get populated.
	SpendKey *mw.SecretKey

	// The blinding factor of the coin's output.
	// May be nil for watch-only wallets.
	Blind *mw.BlindingFactor

	// The output amount in litoshis.
	// Typically positive, but could be 0 in the future
	// when we start using decoys to improve privacy.
	Value uint64

	// The output's ID (hash).
	OutputId *chainhash.Hash

	// The ephemeral private key used by the sender to create the output.
	// This will only be populated when the coin has flag HAS_SENDER_INFO.
	SenderKey *mw.SecretKey

	// The StealthAddress the coin was sent to.
	// This will only be populated when the coin has flag HAS_SENDER_INFO.
	Address *mw.StealthAddress

	// The shared secret used to generate the output key.
	// By storing this, we are able to postpone calculation of the spend key.
	// This allows us to scan for outputs while wallet is locked, and recalculate
	// the output key once the wallet becomes unlocked.
	SharedSecret *mw.SecretKey
}

func RewindOutput(output *wire.MwebOutput,
	scanSecret *mw.SecretKey) (coin *Coin, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = errors.New("output is bad")
		}
	}()

	if output.Message.Features&wire.MwebOutputMessageStandardFieldsFeatureBit == 0 {
		return nil, errors.New("output doesn't have standard fields")
	}

	sharedSecret := output.Message.KeyExchangePubKey.Mul(scanSecret)
	viewTag := mw.Hashed(mw.HashTagTag, sharedSecret[:])[0]
	if viewTag != output.Message.ViewTag {
		return nil, errors.New("view tag mismatch")
	}

	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sharedSecret[:]))
	B_i := output.ReceiverPubKey.Div((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))

	// Check if B_i belongs to wallet
	address := &mw.StealthAddress{Scan: B_i.Mul(scanSecret), Spend: B_i}

	// Calc blinding factor and unmask nonce and amount
	mask := mw.OutputMaskFromShared(t)
	value := mask.MaskValue(output.Message.MaskedValue)
	n := mask.MaskNonce(&output.Message.MaskedNonce)

	if *mw.SwitchCommit(mask.Blind, value) != output.Commitment {
		return nil, errors.New("commitment mismatch")
	}

	// Calculate Carol's sending key 's' and check that s*B ?= Ke
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	h.Write(address.A()[:])
	h.Write(address.B()[:])
	binary.Write(h, binary.LittleEndian, value)
	h.Write(n.FillBytes(make([]byte, 16)))
	s := (*mw.SecretKey)(h.Sum(nil))

	if output.Message.KeyExchangePubKey != *address.B().Mul(s) {
		return nil, errors.New("key exchange pubkey mismatch")
	}

	return &Coin{
		Blind:        mask.Blind,
		Value:        value,
		OutputId:     output.Hash(),
		Address:      address,
		SharedSecret: t,
	}, nil
}

func (coin *Coin) CalculateOutputKey(spendKey *mw.SecretKey) {
	if coin.SpendKey != nil || coin.SharedSecret == nil {
		return
	}
	coin.SpendKey = spendKey.Mul(
		(*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, coin.SharedSecret[:])),
	)
}
