// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// signer encapsulates the role 'Signer' as specified in BIP174; it controls
// the insertion of signatures; the Sign() function will attempt to insert
// signatures using Updater.addPartialSignature, after first ensuring the Psbt
// is in the correct state.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/secp256k1"
	"lukechampine.com/blake3"
)

// SignOutcome is a enum-like value that expresses the outcome of a call to the
// Sign method.
type SignOutcome int

const (
	// SignSuccesful indicates that the partial signature was successfully
	// attached.
	SignSuccesful = 0

	// SignFinalized  indicates that this input is already finalized, so the
	// provided signature was *not* attached
	SignFinalized = 1

	// SignInvalid indicates that the provided signature data was not valid.
	// In this case an error will also be returned.
	SignInvalid = -1
)

// Sign allows the caller to sign a PSBT at a particular input; they
// must provide a signature and a pubkey, both as byte slices; they can also
// optionally provide both witnessScript and/or redeemScript, otherwise these
// arguments must be set as nil (and in that case, they must already be present
// in the PSBT if required for signing to succeed).
//
// This serves as a wrapper around Updater.addPartialSignature; it ensures that
// the redeemScript and witnessScript are updated as needed (note that the
// Updater is allowed to add redeemScripts and witnessScripts independently,
// before signing), and ensures that the right form of utxo field
// (NonWitnessUtxo or WitnessUtxo) is included in the input so that signature
// insertion (and then finalization) can take place.
func (u *Updater) Sign(inIndex int, sig []byte, pubKey []byte,
	redeemScript []byte, witnessScript []byte) (SignOutcome, error) {

	pInput := u.Upsbt.Inputs[inIndex]
	if pInput.isFinalized() {
		return SignFinalized, nil
	}

	// Add the witnessScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if witnessScript != nil {
		err := u.AddInWitnessScript(witnessScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// Add the redeemScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if redeemScript != nil {
		err := u.AddInRedeemScript(redeemScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// At this point, the PSBT must have the requisite witnessScript or
	// redeemScript fields for signing to succeed.
	//
	// Case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	switch {
	case pInput.WitnessScript != nil:
		if pInput.WitnessUtxo == nil {
			err := nonWitnessToWitness(u.Upsbt, inIndex)
			if err != nil {
				return SignInvalid, err
			}
		}

		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 2: no witness script, only redeem script; can be legacy p2sh or
	// p2sh-wrapped p2wkh.
	case pInput.RedeemScript != nil:
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content.
		if txscript.IsWitnessProgram(redeemScript) {
			if pInput.WitnessUtxo == nil {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		// If it is not a valid witness program, we here assume that
		// the provided WitnessUtxo/NonWitnessUtxo field was correct.
		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 3: Neither provided only works for native p2wkh, or non-segwit
	// non-p2sh. To check if it's segwit, check the scriptPubKey of the
	// output.
	default:
		if pInput.WitnessUtxo == nil {
			txIn := u.Upsbt.UnsignedTx.TxIn[inIndex]
			outIndex := txIn.PreviousOutPoint.Index
			script := pInput.NonWitnessUtxo.TxOut[outIndex].PkScript

			if txscript.IsWitnessProgram(script) {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}
	}

	return SignSuccesful, nil
}

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func nonWitnessToWitness(p *Packet, inIndex int) error {
	outIndex := p.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Index
	txout := p.Inputs[inIndex].NonWitnessUtxo.TxOut[outIndex]

	// TODO(guggero): For segwit v1, we'll want to remove the NonWitnessUtxo
	// from the packet. For segwit v0 it is unsafe to only rely on the
	// witness UTXO. See https://github.com/bitcoin/bitcoin/pull/19215.
	// p.Inputs[inIndex].NonWitnessUtxo = nil

	u := Updater{
		Upsbt: p,
	}

	return u.AddInWitnessUtxo(txout, inIndex)
}

type MwebInputSignatureData struct {
	// Final input signature
	sig mw.Signature
	// The blinding factor of the input commitment
	inputBlind mw.BlindingFactor
	// Stealth offset contribution (input_secret_key - output_spend_key)
	stealthOffsetTweak mw.SecretKey
	// Ephemeral input public key (K_i), or nil if MwebInputStealthKeyFeatureBit was not set
	inputPubKey *mw.PublicKey
}

type IMwebInputSigner interface {
	SignMwebInput(
		features wire.MwebInputFeatureBit,
		spentOutputId chainhash.Hash,
		spentOutputPk mw.PublicKey,
		amount uint64,
		extraData []byte,
		keyExchangePubKey *mw.PublicKey,
		sharedSecret *mw.SecretKey,
	) (*MwebInputSignatureData, error)
}

type Signer struct {
	// The PSBT packet to sign
	psbt *Packet
	// Signs the MWEB input, and returns the signature and other key info needed for finalizing
	mwebInputSigner IMwebInputSigner
}

func NewSigner(p *Packet, mwebInputSigner IMwebInputSigner) (*Signer, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}

	return &Signer{psbt: p, mwebInputSigner: mwebInputSigner}, nil
}

func (s *Signer) SignMwebComponents() (SignOutcome, error) {
	p := s.psbt

	var kernelOffset mw.BlindingFactor
	if p.MwebTxOffset != nil {
		kernelOffset = *p.MwebTxOffset
	}
	var stealthOffset mw.BlindingFactor
	if p.MwebStealthOffset != nil {
		stealthOffset = *p.MwebStealthOffset
	}

	for i := range p.Inputs {
		input := &p.Inputs[i]
		if !input.isMWEB() || input.isFinalized() {
			continue
		}

		sigData, err := s.signMwebInput(input)
		if err != nil {
			return SignInvalid, err
		}

		kernelOffset = *kernelOffset.Sub(&sigData.inputBlind)
		p.MwebTxOffset = &kernelOffset

		stealthOffset = *stealthOffset.Add((*mw.BlindingFactor)(&sigData.stealthOffsetTweak))
		p.MwebStealthOffset = &stealthOffset
	}

	for i := range p.Outputs {
		output := &p.Outputs[i]
		if !output.isMWEB() || output.isFinalized() {
			continue
		}

		outputBlind, outputStealthKey, err := signMwebOutput(output)
		if err != nil {
			return SignInvalid, err
		}

		kernelOffset = *kernelOffset.Add(outputBlind)
		p.MwebTxOffset = &kernelOffset

		stealthOffset = *stealthOffset.Add((*mw.BlindingFactor)(outputStealthKey))
		p.MwebStealthOffset = &stealthOffset
	}

	for i := range p.Kernels {
		kernel := &p.Kernels[i]
		if kernel.isFinalized() {
			continue
		}

		kernelBlind, kernelStealthKey, err := signMwebKernel(kernel)
		if err != nil {
			return SignInvalid, err
		}

		kernelOffset = *kernelOffset.Sub(kernelBlind)
		p.MwebTxOffset = &kernelOffset

		if kernelStealthKey != nil {
			stealthOffset = *stealthOffset.Sub((*mw.BlindingFactor)(kernelStealthKey))
			p.MwebStealthOffset = &stealthOffset
		}
	}

	return SignSuccesful, nil
}

func (s *Signer) signMwebInput(input *PInput) (*MwebInputSignatureData, error) {
	if input.MwebAmount == nil {
		return nil, errors.New("input amount missing")
	} else if input.MwebOutputPubkey == nil {
		return nil, errors.New("spent output pubkey missing")
	} else if input.MwebSharedSecret == nil && input.MwebKeyExchangePubkey == nil {
		return nil, errors.New("input shared secret missing")
	}

	if input.MwebFeatures == nil {
		defaultFeatures := wire.MwebInputStealthKeyFeatureBit
		input.MwebFeatures = &defaultFeatures
	}

	sigData, err := s.mwebInputSigner.SignMwebInput(
		*input.MwebFeatures,
		*input.MwebOutputId,
		*input.MwebOutputPubkey,
		uint64(*input.MwebAmount),
		input.MwebExtraData,
		input.MwebKeyExchangePubkey,
		input.MwebSharedSecret,
	)
	if err != nil {
		return nil, err
	}

	input.MwebInputPubkey = sigData.inputPubKey
	input.MwebCommit = mw.NewCommitment(&sigData.inputBlind, uint64(*input.MwebAmount))
	input.MwebInputSig = &sigData.sig
	return sigData, nil
}

func signMwebOutput(output *POutput) (*mw.BlindingFactor, *mw.SecretKey, error) {
	if output.StealthAddress == nil {
		return nil, nil, errors.New("output address missing")
	}

	if output.MwebFeatures != nil && (*output.MwebFeatures)&wire.MwebOutputMessageStandardFieldsFeatureBit == 0 {
		return nil, nil, errors.New("only standard outputs supported")
	}

	if output.MwebFeatures == nil {
		defaultFeatures := wire.MwebOutputMessageStandardFieldsFeatureBit
		output.MwebFeatures = &defaultFeatures
	}

	amount := uint64(output.Amount)
	address := *output.StealthAddress
	senderKey, err := mw.NewSecretKey()
	if err != nil {
		return nil, nil, err
	}

	// Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
	n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])

	// Calculate unique sending key 's' = H(T_send, A, B, v, n)
	h := blake3.New(32, nil)
	_ = binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	_, _ = h.Write(address.A()[:])
	_, _ = h.Write(address.B()[:])
	_ = binary.Write(h, binary.LittleEndian, amount)
	_, _ = h.Write(n.FillBytes(make([]byte, 16)))
	s := (*mw.SecretKey)(h.Sum(nil))

	// Derive shared secret 't' = H(T_derive, s*A)
	sA := address.A().Mul(s)
	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))

	// Construct one-time public key for receiver 'Ko' = H(T_outkey, t)*B
	Ko := address.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))

	// Key exchange public key 'Ke' = s*B
	Ke := address.B().Mul(s)

	// Calc blinding factor and mask nonce and amount
	mask := mw.OutputMaskFromShared(t)
	blind := mw.BlindSwitch(mask.Blind, amount)
	mv := mask.MaskValue(amount)
	mn := mask.MaskNonce(n)

	// Commitment 'C' = r*G + v*H
	outputCommit := mw.NewCommitment(blind, amount)

	// Calculate the ephemeral send pubkey 'Ks' = ks*G
	Ks := senderKey.PubKey()

	// Derive view tag as first byte of H(T_tag, sA)
	viewTag := mw.Hashed(mw.HashTagTag, sA[:])[0]

	message := &wire.MwebOutputMessage{
		Features:          *output.MwebFeatures,
		KeyExchangePubKey: *Ke,
		ViewTag:           viewTag,
		MaskedValue:       mv,
		MaskedNonce:       *mn,
		ExtraData:         output.MwebExtraData,
	}
	var messageBuf bytes.Buffer
	if err := message.Serialize(&messageBuf); err != nil {
		return nil, nil, err
	}

	// Probably best to store sender_key so sender
	// can identify all outputs they've sent?
	rangeProof := secp256k1.NewRangeProof(amount, *blind, make([]byte, 20), messageBuf.Bytes())
	rangeProofHash := blake3.Sum256(rangeProof[:])

	// Sign the output
	h = blake3.New(32, nil)
	_, _ = h.Write(outputCommit[:])
	_, _ = h.Write(Ks[:])
	_, _ = h.Write(Ko[:])
	_, _ = h.Write(message.Hash()[:])
	_, _ = h.Write(rangeProofHash[:])
	signature := mw.Sign(senderKey, h.Sum(nil))

	var encryptedNonce [16]byte
	mn.FillBytes(encryptedNonce[:])
	output.MwebStandardFields = &standardMwebOutputFields{
		KeyExchangePubkey: *Ke,
		ViewTag:           viewTag,
		EncryptedValue:    mv,
		EncryptedNonce:    encryptedNonce,
	}
	output.OutputCommit = outputCommit
	output.SenderPubkey = Ks
	output.OutputPubkey = Ko
	output.RangeProof = &rangeProof
	output.MwebSignature = &signature

	return blind, senderKey, nil
}

func signMwebKernel(pk *PKernel) (*mw.BlindingFactor, *mw.SecretKey, error) {
	// Populate features if missing already
	if pk.Features == nil {
		features := wire.MwebKernelStealthExcessFeatureBit
		if pk.Fee != nil {
			features |= wire.MwebKernelFeeFeatureBit
		}
		if pk.PeginAmount != nil && *pk.PeginAmount > 0 {
			features |= wire.MwebKernelPeginFeatureBit
		}
		if len(pk.PegOuts) > 0 {
			features |= wire.MwebKernelPegoutFeatureBit
		}
		if pk.LockHeight != nil && *pk.LockHeight > 0 {
			features |= wire.MwebKernelHeightLockFeatureBit
		}
		pk.Features = &features
	}

	// Verify features match PKernel fields
	if (pk.Fee != nil) != (*pk.Features&wire.MwebKernelFeeFeatureBit > 0) {
		return nil, nil, errors.New("kernel fee feature flag and field mismatch")
	}
	if (pk.PeginAmount != nil) != (*pk.Features&wire.MwebKernelPeginFeatureBit > 0) {
		return nil, nil, errors.New("kernel pegin feature flag and field mismatch")
	}
	if (len(pk.PegOuts) > 0) != (*pk.Features&wire.MwebKernelPegoutFeatureBit > 0) {
		return nil, nil, errors.New("kernel pegout feature flag and field mismatch")
	}
	if (pk.LockHeight != nil) != (*pk.Features&wire.MwebKernelHeightLockFeatureBit > 0) {
		return nil, nil, errors.New("kernel height lock feature flag and field mismatch")
	}

	sigKey, err := mw.NewSecretKey()
	if err != nil {
		return nil, nil, err
	}
	fee := uint64(0)
	if pk.Fee != nil {
		fee = uint64(*pk.Fee)
	}
	pegin := uint64(0)
	if pk.PeginAmount != nil {
		pegin = uint64(*pk.PeginAmount)
	}
	lockHeight := int32(0)
	if pk.LockHeight != nil {
		lockHeight = *pk.LockHeight
	}

	blind := (*mw.BlindingFactor)(sigKey)
	kernelExcess := *mw.NewCommitment(blind, 0)
	var stealthKey *mw.SecretKey
	var stealthExcess mw.PublicKey
	if *pk.Features&wire.MwebKernelStealthExcessFeatureBit > 0 {
		if stealthKey, err = mw.NewSecretKey(); err != nil {
			return nil, nil, err
		}
		stealthExcess = *(stealthKey).PubKey()

		h := blake3.New(32, nil)
		_, _ = h.Write(kernelExcess.PubKey()[:])
		_, _ = h.Write(stealthExcess[:])
		sigKey = sigKey.Mul((*mw.SecretKey)(h.Sum(nil))).
			Add(stealthKey)
	}

	k := &wire.MwebKernel{
		Features:      *pk.Features,
		Fee:           fee,
		Pegin:         pegin,
		Pegouts:       pk.PegOuts,
		LockHeight:    lockHeight,
		StealthExcess: stealthExcess,
		Excess:        kernelExcess,
	}

	signature := mw.Sign(sigKey, k.MessageHash()[:])

	pk.ExcessCommitment = &kernelExcess
	if *pk.Features&wire.MwebKernelStealthExcessFeatureBit > 0 {
		pk.StealthExcess = &stealthExcess
	}
	pk.Signature = &signature
	return blind, stealthKey, nil
}

type OutputKeyDerivationFunc func(spentOutputPk *mw.PublicKey, keyExchangePubKey *mw.PublicKey, sharedSecret *mw.SecretKey) (preBlind *mw.BlindingFactor, outputSpendKey *mw.SecretKey, err error)

type BasicMwebInputSigner struct {
	DeriveOutputKeys OutputKeyDerivationFunc
}

func (s BasicMwebInputSigner) SignMwebInput(features wire.MwebInputFeatureBit, spentOutputId chainhash.Hash, spentOutputPk mw.PublicKey, amount uint64, extraData []byte, keyExchangePubKey *mw.PublicKey, spentOutputSharedSecret *mw.SecretKey) (*MwebInputSignatureData, error) {
	if features&wire.MwebInputStealthKeyFeatureBit == 0 {
		return nil, errors.New("stealth key feature bit is required to ensure key safety")
	}

	preBlind, outputSpendKey, err := s.DeriveOutputKeys(&spentOutputPk, keyExchangePubKey, spentOutputSharedSecret)
	if err != nil {
		return nil, err
	}

	blind := mw.BlindSwitch(preBlind, amount)

	var ephemeralKey mw.SecretKey
	if _, err = rand.Read(ephemeralKey[:]); err != nil {
		return nil, err
	}

	inputPubKey := ephemeralKey.PubKey()

	// Hash keys (K_i||K_o)
	h := blake3.New(32, nil)
	_, _ = h.Write(inputPubKey[:])
	_, _ = h.Write(spentOutputPk[:])
	keyHash := (*mw.SecretKey)(h.Sum(nil))

	// Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
	sigKey := outputSpendKey.Mul(keyHash).Add(&ephemeralKey)

	// Hash message
	h = blake3.New(32, nil)
	_ = binary.Write(h, binary.LittleEndian, features)
	_, _ = h.Write(spentOutputId[:])

	if features&wire.MwebInputExtraDataFeatureBit > 0 {
		_ = wire.WriteVarBytes(h, 0, extraData)
	}
	msgHash := h.Sum(nil)

	return &MwebInputSignatureData{
		sig:                mw.Sign(sigKey, msgHash),
		inputBlind:         *blind,
		stealthOffsetTweak: *ephemeralKey.Sub(outputSpendKey),
		inputPubKey:        inputPubKey,
	}, nil
}
