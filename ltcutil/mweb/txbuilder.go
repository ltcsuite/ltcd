package mweb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/secp256k1"
	"lukechampine.com/blake3"
)

func NewTransaction(coins []*Coin, recipients []*Recipient,
	fee, pegin uint64, pegouts []*wire.TxOut) (
	tx *wire.MwebTx, newCoins []*Coin, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = errors.New("input coins are bad")
		}
	}()

	var sumCoins, sumRecipients, sumPegouts uint64
	for _, coin := range coins {
		sumCoins += coin.Value
	}
	for _, recipient := range recipients {
		sumRecipients += recipient.Value
	}
	for _, pegout := range pegouts {
		sumPegouts += uint64(pegout.Value)
	}
	if sumCoins+pegin != sumRecipients+sumPegouts+fee {
		return nil, nil, errors.New("total amount mismatch")
	}

	inputs, inputBlind, inputKey := createInputs(coins)
	outputs, newCoins, outputBlind, outputKey := createOutputs(recipients)

	// Total kernel offset is split between raw kernel_offset
	// and the kernel's blinding factor.
	// sum(output.blind) - sum(input.blind) = kernel_offset + sum(kernel.blind)
	var kernelOffset mw.BlindingFactor
	if _, err := rand.Read(kernelOffset[:]); err != nil {
		return nil, nil, err
	}
	kernelBlind := outputBlind.Sub(&inputBlind).Sub(&kernelOffset)

	// MW: FUTURE - This is only needed for peg-ins or when no change
	var stealthBlind mw.BlindingFactor
	if _, err := rand.Read(stealthBlind[:]); err != nil {
		return nil, nil, err
	}

	kernel := createKernel(kernelBlind, &stealthBlind, &fee, &pegin, pegouts, nil)
	stealthOffset := (*mw.BlindingFactor)(outputKey.Add(&inputKey)).Sub(&stealthBlind)

	return &wire.MwebTx{
		KernelOffset:  kernelOffset,
		StealthOffset: *stealthOffset,
		TxBody: &wire.MwebTxBody{
			Inputs:  inputs,
			Outputs: outputs,
			Kernels: []*wire.MwebKernel{kernel},
		},
	}, newCoins, nil
}

func createInputs(coins []*Coin) (inputs []*wire.MwebInput,
	totalBlind mw.BlindingFactor, totalKey mw.SecretKey) {

	var ephemeralKey mw.SecretKey

	for _, coin := range coins {
		if _, err := rand.Read(ephemeralKey[:]); err != nil {
			panic(err)
		}
		blind := mw.BlindSwitch(coin.Blind, coin.Value)
		commitment := mw.NewCommitment(blind, coin.Value)
		inputs = append(inputs, createInput(coin, commitment, &ephemeralKey))
		totalBlind = *totalBlind.Add(blind)
		totalKey = *totalKey.Add(&ephemeralKey).Sub(coin.SpendKey)
	}

	sort.Slice(inputs, func(i, j int) bool {
		a := new(big.Int).SetBytes(inputs[i].OutputId[:])
		b := new(big.Int).SetBytes(inputs[j].OutputId[:])
		return a.Cmp(b) < 0
	})

	return
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

func createOutputs(recipients []*Recipient) (outputs []*wire.MwebOutput,
	coins []*Coin, totalBlind mw.BlindingFactor, totalKey mw.SecretKey) {

	var ephemeralKey mw.SecretKey

	for _, recipient := range recipients {
		if _, err := rand.Read(ephemeralKey[:]); err != nil {
			panic(err)
		}
		output, blind := createOutput(recipient, &ephemeralKey)
		totalBlind = *totalBlind.Add(mw.BlindSwitch(blind, recipient.Value))
		totalKey = *totalKey.Add(&ephemeralKey)
		outputs = append(outputs, output)

		coins = append(coins, &Coin{
			Blind:     blind,
			Value:     recipient.Value,
			OutputId:  output.Hash(),
			SenderKey: &ephemeralKey,
			Address:   recipient.Address,
		})
	}

	sort.Slice(outputs, func(i, j int) bool {
		a := new(big.Int).SetBytes(outputs[i].Hash()[:])
		b := new(big.Int).SetBytes(outputs[j].Hash()[:])
		return a.Cmp(b) < 0
	})

	return
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
	rangeProof := secp256k1.NewRangeProof(recipient.Value,
		*blind, make([]byte, 20), messageBuf.Bytes())
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
		RangeProof:     &rangeProof,
		RangeProofHash: rangeProofHash,
		Signature:      signature,
	}, mask.Blind
}

func createKernel(blind, stealthBlind *mw.BlindingFactor,
	fee, pegin *uint64, pegouts []*wire.TxOut,
	lockHeight *int32) *wire.MwebKernel {

	k := &wire.MwebKernel{Excess: *mw.NewCommitment(blind, 0)}
	sigKey := (*mw.SecretKey)(blind)

	if fee != nil {
		k.Features |= wire.MwebKernelFeeFeatureBit
		k.Fee = *fee
	}
	if pegin != nil && *pegin > 0 {
		k.Features |= wire.MwebKernelPeginFeatureBit
		k.Pegin = *pegin
	}
	if len(pegouts) > 0 {
		k.Features |= wire.MwebKernelPegoutFeatureBit
		k.Pegouts = pegouts
	}
	if lockHeight != nil {
		k.Features |= wire.MwebKernelHeightLockFeatureBit
		k.LockHeight = *lockHeight
	}
	if stealthBlind != nil {
		k.Features |= wire.MwebKernelStealthExcessFeatureBit
		k.StealthExcess = *(*mw.SecretKey)(stealthBlind).PubKey()

		h := blake3.New(32, nil)
		h.Write(k.Excess.PubKey()[:])
		h.Write(k.StealthExcess[:])

		sigKey = sigKey.Mul((*mw.SecretKey)(h.Sum(nil))).
			Add((*mw.SecretKey)(stealthBlind))
	}

	k.Signature = mw.Sign(sigKey, k.MessageHash()[:])
	return k
}

func NewPegin(value uint64, kernel *wire.MwebKernel) *wire.TxOut {
	script, _ := txscript.NewScriptBuilder().
		AddOp(txscript.MwebPeginWitnessVersion + txscript.OP_1 - 1).
		AddData(kernel.Hash()[:]).Script()
	return wire.NewTxOut(int64(value), script)
}
