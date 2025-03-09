package mweb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/secp256k1"
	"lukechampine.com/blake3"
)

type (
	CreateInputsAndKernelFunc func(*mw.SecretKey, *mw.BlindingFactor) (
		[]*wire.MwebInput, *wire.MwebKernel, *mw.BlindingFactor, error)
	RandFunc func([]byte) error
)

func NewTransaction(coins []*Coin, recipients []*Recipient,
	fee, pegin uint64, pegouts []*wire.TxOut, randFunc RandFunc,
	createInputsAndKernelFunc CreateInputsAndKernelFunc) (
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

	if randFunc == nil {
		randFunc = func(b []byte) error {
			_, err := rand.Read(b)
			return err
		}
	}

	outputs, newCoins, outputBlind, outputKey := createOutputs(recipients, randFunc)

	// Total kernel offset is split between raw kernel_offset
	// and the kernel's blinding factor.
	// sum(output.blind) - sum(input.blind) = kernel_offset + sum(kernel.blind)
	var kernelOffset mw.BlindingFactor
	if err := randFunc(kernelOffset[:]); err != nil {
		return nil, nil, err
	}
	kernelBlind := outputBlind.Sub(&kernelOffset)
	for _, coin := range coins {
		kernelBlind = kernelBlind.Sub(mw.BlindSwitch(coin.Blind, coin.Value))
	}

	if createInputsAndKernelFunc == nil {
		createInputsAndKernelFunc = func(outputKey *mw.SecretKey,
			kernelBlind *mw.BlindingFactor) ([]*wire.MwebInput,
			*wire.MwebKernel, *mw.BlindingFactor, error) {
			return createInputsAndKernel(coins, outputKey,
				kernelBlind, fee, pegin, pegouts, randFunc)
		}
	}
	inputs, kernel, stealthOffset, err :=
		createInputsAndKernelFunc(&outputKey, kernelBlind)
	if err != nil {
		return nil, nil, err
	}

	txBody := &wire.MwebTxBody{
		Inputs:  inputs,
		Outputs: outputs,
		Kernels: []*wire.MwebKernel{kernel},
	}
	txBody.Sort()
	return &wire.MwebTx{
		KernelOffset:  kernelOffset,
		StealthOffset: *stealthOffset,
		TxBody:        txBody,
	}, newCoins, nil
}

func createInputsAndKernel(coins []*Coin,
	outputKey *mw.SecretKey, kernelBlind *mw.BlindingFactor,
	fee, pegin uint64, pegouts []*wire.TxOut, randFunc RandFunc) (
	inputs []*wire.MwebInput, kernel *wire.MwebKernel,
	stealthOffset *mw.BlindingFactor, err error) {

	var inputKey, ephemeralKey mw.SecretKey
	for _, coin := range coins {
		if err := randFunc(ephemeralKey[:]); err != nil {
			panic(err)
		}
		inputs = append(inputs, CreateInput(coin, &ephemeralKey))
		inputKey = *inputKey.Add(&ephemeralKey).Sub(coin.SpendKey)
	}

	var stealthBlind mw.BlindingFactor
	if err = randFunc(stealthBlind[:]); err != nil {
		return
	}
	kernel = CreateKernel(kernelBlind, &stealthBlind, &fee, &pegin, pegouts, nil)
	stealthOffset = (*mw.BlindingFactor)(outputKey.Add(&inputKey)).Sub(&stealthBlind)
	return
}

// Creates a standard input with a stealth key (feature bit = 1)
func CreateInput(coin *Coin, inputKey *mw.SecretKey) *wire.MwebInput {
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
		Commitment:   *mw.SwitchCommit(coin.Blind, coin.Value),
		InputPubKey:  inputPubKey,
		OutputPubKey: *outputPubKey,
		Signature:    mw.Sign(sigKey, msgHash),
	}
}

type Recipient struct {
	Value   uint64
	Address *mw.StealthAddress
}

func createOutputs(recipients []*Recipient, randFunc RandFunc) (
	outputs []*wire.MwebOutput, coins []*Coin,
	totalBlind mw.BlindingFactor, totalKey mw.SecretKey) {

	for _, recipient := range recipients {
		var ephemeralKey mw.SecretKey
		if err := randFunc(ephemeralKey[:]); err != nil {
			panic(err)
		}
		output, blind, shared := CreateOutput(recipient, &ephemeralKey)
		SignOutput(output, recipient.Value, blind, &ephemeralKey)
		totalBlind = *totalBlind.Add(mw.BlindSwitch(blind, recipient.Value))
		totalKey = *totalKey.Add(&ephemeralKey)
		outputs = append(outputs, output)

		coins = append(coins, &Coin{
			Blind:        blind,
			Value:        recipient.Value,
			OutputId:     output.Hash(),
			SenderKey:    &ephemeralKey,
			Address:      recipient.Address,
			SharedSecret: shared,
		})
	}
	return
}

func CreateOutput(recipient *Recipient, senderKey *mw.SecretKey) (
	output *wire.MwebOutput, blind *mw.BlindingFactor, shared *mw.SecretKey) {

	// Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
	n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])

	output, blind, shared = CreateOutput2(recipient, n)

	// Calculate the ephemeral send pubkey 'Ks' = ks*G
	output.SenderPubKey = *senderKey.PubKey()

	return
}

func CreateOutput2(recipient *Recipient, n *big.Int) (
	*wire.MwebOutput, *mw.BlindingFactor, *mw.SecretKey) {

	// We only support standard feature fields for now
	features := wire.MwebOutputMessageStandardFieldsFeatureBit

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

	// Derive view tag as first byte of H(T_tag, sA)
	viewTag := mw.Hashed(mw.HashTagTag, sA[:])[0]

	return &wire.MwebOutput{
		Commitment:     *outputCommit,
		ReceiverPubKey: *Ko,
		Message: wire.MwebOutputMessage{
			Features:          features,
			KeyExchangePubKey: *Ke,
			ViewTag:           viewTag,
			MaskedValue:       mv,
			MaskedNonce:       *mn,
		},
	}, mask.Blind, t
}

func SignOutput(output *wire.MwebOutput, value uint64,
	blind *mw.BlindingFactor, senderKey *mw.SecretKey) {

	var messageBuf bytes.Buffer
	output.Message.Serialize(&messageBuf)

	rangeProof := secp256k1.NewRangeProof(
		value, *mw.BlindSwitch(blind, value),
		make([]byte, 20), messageBuf.Bytes())
	output.RangeProof = &rangeProof
	output.RangeProofHash = blake3.Sum256(rangeProof[:])

	SignOutput2(output, senderKey)
}

func SignOutput2(output *wire.MwebOutput, senderKey *mw.SecretKey) {
	h := blake3.New(32, nil)
	h.Write(output.Commitment[:])
	h.Write(output.SenderPubKey[:])
	h.Write(output.ReceiverPubKey[:])
	h.Write(output.Message.Hash()[:])
	h.Write(output.RangeProofHash[:])
	output.Signature = mw.Sign(senderKey, h.Sum(nil))
}

func CreateKernel(blind, stealthBlind *mw.BlindingFactor,
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
