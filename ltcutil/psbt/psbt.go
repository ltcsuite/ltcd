// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package psbt is an implementation of Partially Signed Bitcoin
// Transactions (PSBT). The format is defined in BIP 174:
// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
package psbt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"io"

	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/wire"
)

// psbtMagicLength is the length of the magic bytes used to signal the start of
// a serialized PSBT packet.
const psbtMagicLength = 5

var (
	// psbtMagic is the separator.
	psbtMagic = [psbtMagicLength]byte{0x70,
		0x73, 0x62, 0x74, 0xff, // = "psbt" + 0xff sep
	}
)

// MaxPsbtValueLength is the size of the largest transaction serialization
// that could be passed in a NonWitnessUtxo field. This is definitely
// less than 4M.
const MaxPsbtValueLength = 4000000

// MaxPsbtKeyLength is the length of the largest key that we'll successfully
// deserialize from the wire. Anything more will return ErrInvalidKeyData.
const MaxPsbtKeyLength = 10000

var (

	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrInvalidPsbtFormat = errors.New("Invalid PSBT serialization format")

	// ErrDuplicateKey indicates that a passed Psbt serialization is invalid
	// due to having the same key repeated in the same key-value pair.
	ErrDuplicateKey = errors.New("Invalid Psbt due to duplicate key")

	// ErrInvalidKeyData indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeyData = errors.New("Invalid key data")

	// ErrInvalidMagicBytes indicates that a passed Psbt serialization is
	// invalid due to having incorrect magic bytes.
	ErrInvalidMagicBytes = errors.New("Invalid Psbt due to incorrect " +
		"magic bytes")

	// ErrInvalidRawTxSigned indicates that the raw serialized transaction
	// in the global section of the passed Psbt serialization is invalid
	// because it contains scriptSigs/witnesses (i.e. is fully or partially
	// signed), which is not allowed by BIP174.
	ErrInvalidRawTxSigned = errors.New("Invalid Psbt, raw transaction " +
		"must be unsigned.")

	// ErrInvalidPrevOutNonWitnessTransaction indicates that the transaction
	// hash (i.e. SHA256^2) of the fully serialized previous transaction
	// provided in the NonWitnessUtxo key-value field doesn't match the
	// prevout hash in the UnsignedTx field in the PSBT itself.
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("Prevout hash " +
		"does not match the provided non-witness utxo serialization")

	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not " +
		"correspond to this input")

	// ErrInputAlreadyFinalized indicates that the PSBT passed to a
	// Finalizer already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("Cannot finalize PSBT, " +
		"finalized scriptSig or scriptWitnes already exists")

	// ErrIncompletePSBT indicates that the Extractor object
	// was unable to successfully extract the passed Psbt struct because
	// it is not complete
	ErrIncompletePSBT = errors.New("PSBT cannot be extracted as it is " +
		"incomplete")

	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")

	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("Invalid Sighash Flags")

	// ErrUnsupportedScriptType indicates that the redeem script or
	// script witness given is not supported by this codebase, or is
	// otherwise not valid.
	ErrUnsupportedScriptType = errors.New("Unsupported script type")
)

// Unknown is a struct encapsulating a key-value pair for which the key type is
// unknown by this package; these fields are allowed in both the 'Global' and
// the 'Input' section of a PSBT.
type Unknown struct {
	Key   []byte
	Value []byte
}

// Packet is the actual psbt representation. It is a set of 1 + N + M
// key-value pair lists, 1 global, defining the unsigned transaction structure
// with N inputs and M outputs.  These key-value pairs can contain scripts,
// signatures, key derivations and other transaction-defining data.
type Packet struct {
	// The PSBT version (Currently support 0 and 2)
	PsbtVersion uint32

	// PSBTv2: The MWEB transaction offset and stealth offset.
	// Will only be populated for signed MWEB transactions.
	MwebTxOffset      *mw.BlindingFactor
	MwebStealthOffset *mw.BlindingFactor

	// UnsignedTx is the decoded unsigned transaction for this PSBT.
	UnsignedTx *wire.MsgTx // Deserialization of unsigned tx

	// Inputs contains all the information needed to properly sign this
	// target input within the above transaction.
	Inputs []PInput

	// Outputs contains all information required to spend any outputs
	// produced by this PSBT.
	Outputs []POutput

	// Kernels contains information about MWEB pegins and pegouts.
	// For signed MWEB txs, this will contain all info required to build finalized kernels.
	Kernels []PKernel

	// Unknowns are the set of custom types (global only) within this PSBT.
	Unknowns []*Unknown
}

// validateUnsignedTx returns true if the transaction is unsigned.  Note that
// more basic sanity requirements, such as the presence of inputs and outputs,
// is implicitly checked in the call to MsgTx.Deserialize().
func validateUnsignedTX(tx *wire.MsgTx) bool {
	for _, tin := range tx.TxIn {
		if len(tin.SignatureScript) != 0 || len(tin.Witness) != 0 {
			return false
		}
	}

	return true
}

// NewFromUnsignedTx creates a new Psbt struct, without any signatures (i.e.
// only the global section is non-empty) using the passed unsigned transaction.
func NewFromUnsignedTx(tx *wire.MsgTx) (*Packet, error) {
	if !validateUnsignedTX(tx) {
		return nil, ErrInvalidRawTxSigned
	}

	inSlice := make([]PInput, len(tx.TxIn))
	outSlice := make([]POutput, len(tx.TxOut))
	unknownSlice := make([]*Unknown, 0)

	return &Packet{
		UnsignedTx: tx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}, nil
}

// NewFromRawBytes returns a new instance of a Packet struct created by reading
// from a byte slice. If the format is invalid, an error is returned. If the
// argument b64 is true, the passed byte slice is decoded from base64 encoding
// before processing.
//
// NOTE: To create a Packet from one's own data, rather than reading in a
// serialization from a counterparty, one should use a psbt.New.
func NewFromRawBytes(r io.Reader, b64 bool) (*Packet, error) {
	// If the PSBT is encoded in bas64, then we'll create a new wrapper
	// reader that'll allow us to incrementally decode the contents of the
	// io.Reader.
	if b64 {
		based64EncodedReader := r
		r = base64.NewDecoder(base64.StdEncoding, based64EncodedReader)
	}

	// The Packet struct does not store the fixed magic bytes, but they
	// must be present or the serialization must be explicitly rejected.
	var magic [5]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != psbtMagic {
		return nil, ErrInvalidMagicBytes
	}

	var psbtVersion *uint32
	var msgTx *wire.MsgTx
	var txVersion *int32
	var inputCount *int
	var outputCount *int
	var kernelCount *int
	var txOffset *mw.BlindingFactor
	var stealthOffset *mw.BlindingFactor

	// Next we parse the GLOBAL section.
	// For PSBTv0, we insist UnsignedTxType must be first; unknowns are allowed, but only after.
	kvPair, err := getKVPair(r)
	if err != nil {
		return nil, err
	}
	if kvPair == nil {
		return nil, ErrInvalidPsbtFormat
	}

	if GlobalType(kvPair.keyType) == UnsignedTxType {
		if kvPair.keyData != nil {
			return nil, ErrInvalidPsbtFormat
		}

		msgTx = wire.NewMsgTx(2)

		// BIP-0174 states: "The transaction must be in the old serialization
		// format (without witnesses)."
		err = msgTx.DeserializeNoWitness(bytes.NewReader(kvPair.valueData))
		if err != nil {
			return nil, err
		}
		if !validateUnsignedTX(msgTx) {
			return nil, ErrInvalidRawTxSigned
		}

		psbtVersion = uint32Ptr(0)
		txVersion = int32Ptr(msgTx.Version)
		inputCount = intPtr(len(msgTx.TxIn))
		outputCount = intPtr(len(msgTx.TxOut))
		kernelCount = intPtr(0)
	}

	globalKeys := newKeySet()
	var unknownSlice []*Unknown

	// Next we parse the GLOBAL section. Parse all keys and break after separator
	for {
		kvPair, err := getKVPair(r)
		if err != nil {
			return nil, err
		}

		// If this is separator byte (nil kvPair), this section is done.
		if kvPair == nil {
			break
		}

		// According to BIP-0174, <key> := <keylen><keytype><keydata> must be unique per map
		if !globalKeys.addKey(kvPair.keyType, kvPair.keyData) {
			return nil, ErrDuplicateKey
		}

		switch GlobalType(kvPair.keyType) {
		case UnsignedTxType:
			// UnsignedTxType should've already been parsed above
			return nil, ErrInvalidPsbtFormat
		case XpubType:
			if len(kvPair.keyData) != BIP32_EXTKEY_WITH_VERSION_SIZE {
				return nil, ErrInvalidPsbtFormat
			}
			// TODO: Parse Extended pubkey
		case TxVersionType:
			if psbtVersion != nil && *psbtVersion == 0 {
				return nil, ErrInvalidPsbtFormat
			}
			if kvPair.keyData != nil || len(kvPair.valueData) != 4 {
				return nil, ErrInvalidPsbtFormat
			}

			txVersion = int32Ptr(int32(binary.LittleEndian.Uint32(kvPair.valueData)))
		//case FallbackLockTimeType:
		case InputCountType:
			if psbtVersion != nil && *psbtVersion == 0 {
				return nil, ErrInvalidPsbtFormat
			}
			if kvPair.keyData != nil || kvPair.valueData == nil {
				return nil, ErrInvalidPsbtFormat
			}

			value, err := wire.ReadVarInt(bytes.NewReader(kvPair.valueData), 0)
			if err != nil {
				return nil, err
			}
			inputCount = intPtr(int(value))
		case OutputCountType:
			if psbtVersion != nil && *psbtVersion == 0 {
				return nil, ErrInvalidPsbtFormat
			}
			if kvPair.keyData != nil || kvPair.valueData == nil {
				return nil, ErrInvalidPsbtFormat
			}

			value, err := wire.ReadVarInt(bytes.NewReader(kvPair.valueData), 0)
			if err != nil {
				return nil, err
			}
			outputCount = intPtr(int(value))
		//case TxModifiableType:
		case MwebTxOffsetType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 32 {
				return nil, ErrInvalidPsbtFormat
			}
			txOffset = mw.ReadBlindingFactor(kvPair.valueData)
			if txOffset == nil {
				return nil, ErrInvalidPsbtFormat
			}
		case MwebTxStealthOffsetType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 32 {
				return nil, ErrInvalidPsbtFormat
			}
			stealthOffset = mw.ReadBlindingFactor(kvPair.valueData)
			if stealthOffset == nil {
				return nil, ErrInvalidPsbtFormat
			}
		case MwebKernelCountType:
			if psbtVersion != nil && *psbtVersion == 0 {
				return nil, ErrInvalidPsbtFormat
			}
			if kvPair.keyData != nil || kvPair.valueData == nil {
				return nil, ErrInvalidPsbtFormat
			}

			value, err := wire.ReadVarInt(bytes.NewReader(kvPair.valueData), 0)
			if err != nil {
				return nil, err
			}
			kernelCount = intPtr(int(value))
		case VersionType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 4 {
				return nil, ErrInvalidPsbtFormat
			}
			psbtVersion = uint32Ptr(binary.LittleEndian.Uint32(kvPair.valueData))
		//case ProprietaryGlobalType:
		default:
			// A fall through case for any proprietary types.
			keyCodeAndData := append(
				[]byte{kvPair.keyType}, kvPair.keyData...,
			)
			newUnknown := &Unknown{
				Key:   keyCodeAndData,
				Value: kvPair.valueData,
			}

			unknownSlice = append(unknownSlice, newUnknown)
		}
	}

	if psbtVersion == nil || txVersion == nil || inputCount == nil || outputCount == nil || kernelCount == nil {
		return nil, ErrInvalidPsbtFormat
	}

	if msgTx == nil {
		// TODO: Create msgTx with txOffset, locktime, inputs, outputs, etc?
	}

	// Next we parse the INPUT section.
	inSlice := make([]PInput, *inputCount)
	for i := 0; i < *inputCount; i++ {
		input := PInput{}
		err = input.deserialize(r)
		if err != nil {
			return nil, err
		}

		inSlice[i] = input
	}

	// Next we parse the OUTPUT section.
	outSlice := make([]POutput, *outputCount)
	for i := 0; i < *outputCount; i++ {
		output := POutput{}
		err = output.deserialize(r)
		if err != nil {
			return nil, err
		}

		outSlice[i] = output
	}

	// Next we parse the KERNEL section.
	kernelSlice := make([]PKernel, *kernelCount)
	for i := 0; i < *kernelCount; i++ {
		kernel := PKernel{}
		err = kernel.deserialize(r)
		if err != nil {
			return nil, err
		}

		kernelSlice[i] = kernel
	}

	// Populate the new Packet object.
	newPsbt := Packet{
		PsbtVersion:       *psbtVersion,
		MwebTxOffset:      txOffset,
		MwebStealthOffset: stealthOffset,
		UnsignedTx:        msgTx,
		Inputs:            inSlice,
		Outputs:           outSlice,
		Kernels:           kernelSlice,
		Unknowns:          unknownSlice,
	}

	// Extended sanity checking is applied here to make sure the
	// externally-passed Packet follows all the rules.
	if err = newPsbt.SanityCheck(); err != nil {
		return nil, err
	}

	return &newPsbt, nil
}

// Serialize creates a binary serialization of the referenced Packet struct
// with lexicographical ordering (by key) of the subsections.
func (p *Packet) Serialize(w io.Writer) error {
	// First we write out the precise set of magic bytes that identify a
	// valid PSBT transaction.
	if _, err := w.Write(psbtMagic[:]); err != nil {
		return err
	}

	// Next we prep to write out the unsigned transaction by first
	// serializing it into an intermediate buffer.
	serializedTx := bytes.NewBuffer(
		make([]byte, 0, p.UnsignedTx.SerializeSize()),
	)
	if err := p.UnsignedTx.SerializeNoWitness(serializedTx); err != nil {
		return err
	}

	// Now that we have the serialized transaction, we'll write it out to
	// the proper global type.
	err := serializeKVPairWithType(
		w, uint8(UnsignedTxType), nil, serializedTx.Bytes(),
	)
	if err != nil {
		return err
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field
	for _, kv := range p.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	// With that our global section is done, so we'll write out the
	// separator.
	separator := []byte{0x00}
	if _, err := w.Write(separator); err != nil {
		return err
	}

	for _, pInput := range p.Inputs {
		err := pInput.serialize(w)
		if err != nil {
			return err
		}
	}

	for _, pOutput := range p.Outputs {
		err := pOutput.serialize(w)
		if err != nil {
			return err
		}
	}

	for _, pKernel := range p.Kernels {
		err := pKernel.serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// B64Encode returns the base64 encoding of the serialization of
// the current PSBT, or an error if the encoding fails.
func (p *Packet) B64Encode() (string, error) {
	var b bytes.Buffer
	if err := p.Serialize(&b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// IsComplete returns true only if all of the inputs are
// finalized; this is particularly important in that it decides
// whether the final extraction to a network serialized signed
// transaction will be possible.
func (p *Packet) IsComplete() bool {
	for i := 0; i < len(p.UnsignedTx.TxIn); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	for _, kernel := range p.Kernels {
		if !kernel.isFinalized() {
			return false
		}
	}
	for _, output := range p.Outputs {
		if !output.isFinalized() {
			return false
		}
	}

	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of BIP174, and returns true if so, false if not.
func (p *Packet) SanityCheck() error {
	if !validateUnsignedTX(p.UnsignedTx) {
		return ErrInvalidRawTxSigned
	}

	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return ErrInvalidPsbtFormat
		}
	}

	for _, kernel := range p.Kernels {
		if !kernel.isSane() {
			return ErrInvalidPsbtFormat
		}
	}

	for _, output := range p.Outputs {
		if !output.isSane() {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}

// GetTxFee returns the transaction fee.  An error is returned if a transaction
// input does not contain any UTXO information.
func (p *Packet) GetTxFee() (ltcutil.Amount, error) {
	sumInputs, err := SumUtxoInputValues(p)
	if err != nil {
		return 0, err
	}

	var sumOutputs int64
	for _, txOut := range p.UnsignedTx.TxOut {
		sumOutputs += txOut.Value
	}

	fee := ltcutil.Amount(sumInputs - sumOutputs)

	for _, kernel := range p.Kernels {
		if kernel.Fee != nil {
			fee += *kernel.Fee
		}
	}
	return fee, nil
}
