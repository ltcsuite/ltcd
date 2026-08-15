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
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/hdkeychain"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"

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

// maxPsbtMapCount bounds the declared input, output, and kernel map counts of
// a v2 packet before their maps are allocated and parsed.
const maxPsbtMapCount = 100000

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

	ErrUnsupportedFieldInPsbtVersion = errors.New("Unsupported field for specified psbt version")

	// ErrMwebComponentsNotSigned indicates that canonical signature data
	// cannot be produced or finalized yet because the packet's MWEB
	// components have not been signed; sign them first.
	ErrMwebComponentsNotSigned = errors.New("mweb components must be " +
		"signed before canonical inputs")

	// ErrMwebAmountsUnbalanced indicates that the packet's explicit MWEB
	// amounts do not satisfy inputs + pegins == outputs + pegouts + fees.
	ErrMwebAmountsUnbalanced = errors.New("mweb amounts do not balance")

	// ErrMwebSortUnsupported indicates that BIP-69 sorting was requested for
	// a packet carrying MWEB components. Amount ordering would break the
	// canonical-before-MWEB map order and the positional peg-in/kernel
	// pairing, so MWEB packets keep their MWEB-defined ordering instead.
	ErrMwebSortUnsupported = errors.New("cannot BIP-69 sort a packet with " +
		"mweb components")
)

type TxModifiableFlag byte

const (
	InputsModifiableFlag TxModifiableFlag = 1 << iota
	OutputsModifiableFlag
	HasSighashSingleModifiableFlag
)

type GlobalExtPubKey struct {
	ExtKey      *hdkeychain.ExtendedKey
	Fingerprint uint32
	Path        []uint32
}

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

	// UnsignedTx is the decoded unsigned transaction for this PSBT.
	// Only used for PSBTv0 (can be nil for v2)
	UnsignedTx *wire.MsgTx // Deserialization of unsigned tx

	// PSBTv2: The transaction version
	TxVersion int32

	// PSBTv2: The fallback locktime for inputs that don't specify locktime
	FallbackLocktime *uint32

	ExtPubKeys []*GlobalExtPubKey

	// Bitfield that indicates which fields can be added or removed
	TxModifiableFlag *TxModifiableFlag

	// PSBTv2: The MWEB transaction offset and stealth offset.
	// Will only be populated for signed MWEB transactions.
	MwebTxOffset      *mw.BlindingFactor
	MwebStealthOffset *mw.BlindingFactor

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

	numInputs := len(tx.TxIn)
	numOutputs := len(tx.TxOut)
	numKernels := 0
	var mwebKernelOffset *mw.BlindingFactor = nil
	var mwebStealthOffset *mw.BlindingFactor = nil
	//if tx.Mweb != nil {
	//	numInputs += len(tx.Mweb.TxBody.Inputs)
	//	numOutputs += len(tx.Mweb.TxBody.Outputs)
	//	numKernels += len(tx.Mweb.TxBody.Kernels)
	//	mwebKernelOffset = &tx.Mweb.KernelOffset
	//	mwebStealthOffset = &tx.Mweb.StealthOffset
	//}
	inSlice := make([]PInput, numInputs)
	outSlice := make([]POutput, numOutputs)
	kernSlice := make([]PKernel, numKernels)
	unknownSlice := make([]*Unknown, 0)

	return &Packet{
		PsbtVersion:       0,
		UnsignedTx:        tx,
		MwebTxOffset:      mwebKernelOffset,
		MwebStealthOffset: mwebStealthOffset,
		TxVersion:         tx.Version,
		FallbackLocktime:  &tx.LockTime,
		Inputs:            inSlice,
		Outputs:           outSlice,
		Kernels:           kernSlice,
		Unknowns:          unknownSlice,
	}, nil
}

var (
	illegalPsbtV0GlobalKeys = map[GlobalType]bool{
		TxVersionType:           true,
		FallbackLockTimeType:    true,
		InputCountType:          true,
		OutputCountType:         true,
		TxModifiableType:        true,
		MwebTxOffsetType:        true,
		MwebTxStealthOffsetType: true,
		MwebKernelCountType:     true,
	}
)

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
	var fallbackLockTime *uint32
	var inputCount *int
	var outputCount *int
	var kernelCount *int
	var extPubKeys []*GlobalExtPubKey
	var txModifiableFlag *TxModifiableFlag
	var txOffset *mw.BlindingFactor
	var stealthOffset *mw.BlindingFactor

	// Next we parse the GLOBAL section. The unsigned-tx key may appear at
	// any position; its derived values are resolved after the map ends.
	kvPair, err := getKVPair(r)
	if err != nil {
		return nil, err
	}
	if kvPair == nil {
		return nil, ErrInvalidPsbtFormat
	}

	globalKeys := newKeySet()
	var unknownSlice []*Unknown

	// Next we parse the GLOBAL section. Parse all keys and break after separator
	for kvPair != nil {
		// According to BIP-0174, <key> := <keylen><keytype><keydata> must be unique per map
		if !globalKeys.addKey(kvPair.keyType, kvPair.keyData) {
			return nil, ErrDuplicateKey
		}

		if !kvPair.isKnownType() {
			unknownSlice = append(unknownSlice, kvPair.asUnknown())
			kvPair, err = getKVPair(r)
			if err != nil {
				return nil, err
			}
			continue
		}

		globalType := GlobalType(kvPair.keyType)
		if psbtVersion != nil && *psbtVersion == 0 && illegalPsbtV0GlobalKeys[globalType] {
			return nil, ErrUnsupportedFieldInPsbtVersion
		}

		switch globalType {
		case UnsignedTxType:
			if kvPair.keyData != nil {
				return nil, ErrInvalidPsbtFormat
			}

			msgTx = wire.NewMsgTx(2)

			// BIP-0174 states: "The transaction must be in the old
			// serialization format (without witnesses)."
			err = msgTx.DeserializeNoWitness(bytes.NewReader(kvPair.valueData))
			if err != nil {
				return nil, err
			}
			if !validateUnsignedTX(msgTx) {
				return nil, ErrInvalidRawTxSigned
			}
		case XpubType:
			if len(kvPair.keyData) != BIP32_EXTKEY_WITH_VERSION_SIZE {
				return nil, ErrInvalidKeyData
			}

			extPubKey, err := readExtendedKey(kvPair.keyData)
			if err != nil {
				return nil, err
			}

			fingerprint, path, err := ReadBip32Derivation(kvPair.valueData)
			if err != nil {
				return nil, err
			}

			extPubKeys = append(extPubKeys, &GlobalExtPubKey{ExtKey: extPubKey, Fingerprint: fingerprint, Path: path})
		case TxVersionType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 4 {
				return nil, ErrInvalidPsbtFormat
			}

			parsedTxVersion := int32(binary.LittleEndian.Uint32(kvPair.valueData))
			txVersion = &parsedTxVersion
		case FallbackLockTimeType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 4 {
				return nil, ErrInvalidPsbtFormat
			}

			fallbackLockTime = uint32Ptr(binary.LittleEndian.Uint32(kvPair.valueData))
		case InputCountType:
			value, err := kvPair.mapCountValue()
			if err != nil {
				return nil, err
			}
			inputCount = intPtr(int(value))
		case OutputCountType:
			value, err := kvPair.mapCountValue()
			if err != nil {
				return nil, err
			}
			outputCount = intPtr(int(value))
		case TxModifiableType:
			if kvPair.keyData != nil {
				return nil, ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 1 {
				return nil, ErrInvalidPsbtFormat
			}

			modifiableFlag := TxModifiableFlag(kvPair.valueData[0])
			txModifiableFlag = &modifiableFlag
		case MwebTxOffsetType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 32 ||
				!scalarInRange(kvPair.valueData) {

				return nil, ErrInvalidPsbtFormat
			}
			txOffset = mw.ReadBlindingFactor(kvPair.valueData)
			if txOffset == nil {
				return nil, ErrInvalidPsbtFormat
			}
		case MwebTxStealthOffsetType:
			if kvPair.keyData != nil || len(kvPair.valueData) != 32 ||
				!scalarInRange(kvPair.valueData) {

				return nil, ErrInvalidPsbtFormat
			}
			stealthOffset = mw.ReadBlindingFactor(kvPair.valueData)
			if stealthOffset == nil {
				return nil, ErrInvalidPsbtFormat
			}
		case MwebKernelCountType:
			value, err := kvPair.mapCountValue()
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
			unknownSlice = append(unknownSlice, kvPair.asUnknown())
		}

		kvPair, err = getKVPair(r)
		if err != nil {
			return nil, err
		}
	}

	// A packet with an unsigned transaction and no version key is v0, and
	// the transaction supplies the derived values.
	if msgTx != nil && psbtVersion == nil {
		psbtVersion = uint32Ptr(0)
	}
	if msgTx != nil && *psbtVersion == 0 {
		txVersion = &msgTx.Version
		fallbackLockTime = uint32Ptr(msgTx.LockTime)
		inputCount = intPtr(len(msgTx.TxIn))
		outputCount = intPtr(len(msgTx.TxOut))
		kernelCount = intPtr(0)
	}

	if psbtVersion == nil || txVersion == nil || inputCount == nil || outputCount == nil {
		return nil, ErrInvalidPsbtFormat
	}

	// Only versions 0 and 2 exist; anything else cannot round-trip.
	if *psbtVersion != 0 && *psbtVersion != 2 {
		return nil, ErrUnsupportedFieldInPsbtVersion
	}

	// The version key may appear after other global keys, so the per-key v0
	// check can miss v2-only keys parsed before it. Re-check now that the
	// final version is known.
	if *psbtVersion == 0 {
		for globalType := range illegalPsbtV0GlobalKeys {
			if globalKeys.hasType(uint64(globalType)) {
				return nil, ErrUnsupportedFieldInPsbtVersion
			}
		}
	}

	// BIP-0370: the unsigned transaction is excluded from v2.
	if *psbtVersion >= 2 && msgTx != nil {
		return nil, ErrUnsupportedFieldInPsbtVersion
	}

	// LIP-0007: the kernel count is omitted when there are no kernel maps.
	// (A present count of zero is tolerated for compatibility with packets
	// serialized before that rule.)
	if kernelCount == nil {
		kernelCount = intPtr(0)
	}

	// Next we parse the INPUT section.
	inSlice := make([]PInput, *inputCount)
	for i := 0; i < *inputCount; i++ {
		input := PInput{}
		err = input.deserialize(r, *psbtVersion)
		if err != nil {
			return nil, err
		}

		inSlice[i] = input
	}

	// Next we parse the OUTPUT section.
	outSlice := make([]POutput, *outputCount)
	for i := 0; i < *outputCount; i++ {
		output := POutput{}
		err = output.deserialize(r, *psbtVersion)
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

	// Per BIP-0174/BIP-0370 strict parsing, the declared counts must cover
	// the whole packet: surplus maps or trailing bytes are an error, not
	// silently dropped data.
	var trailing [1]byte
	if _, err := io.ReadFull(r, trailing[:]); err != io.EOF {
		return nil, ErrInvalidPsbtFormat
	}

	// Populate the new Packet object.
	newPsbt := Packet{
		PsbtVersion:       *psbtVersion,
		UnsignedTx:        msgTx,
		TxVersion:         *txVersion,
		FallbackLocktime:  fallbackLockTime,
		ExtPubKeys:        extPubKeys,
		TxModifiableFlag:  txModifiableFlag,
		MwebTxOffset:      txOffset,
		MwebStealthOffset: stealthOffset,
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
	// MWEB components have no v0 representation.
	if p.PsbtVersion == 0 && p.HasMwebComponents() {
		return ErrInvalidPsbtFormat
	}

	if err := p.checkMwebOrdering(); err != nil {
		return err
	}

	// First we write out the precise set of magic bytes that identify a
	// valid PSBT transaction.
	if _, err := w.Write(psbtMagic[:]); err != nil {
		return err
	}

	if p.PsbtVersion == 0 {
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
	}

	for _, extPubKey := range p.ExtPubKeys {
		// Strip checksum from base58 and take raw 78 bytes
		keyData := writeExtendedKey(extPubKey.ExtKey)

		// Build valueData: 4-byte fingerprint + derivation path. The
		// fingerprint round-trips through the same little-endian read
		// ReadBip32Derivation uses, preserving the original bytes.
		valueData := make([]byte, 4+len(extPubKey.Path)*4)
		binary.LittleEndian.PutUint32(valueData[0:4], extPubKey.Fingerprint)
		for i, index := range extPubKey.Path {
			binary.LittleEndian.PutUint32(valueData[4+i*4:], index)
		}

		if err := serializeKVPairWithType(w, uint8(XpubType), keyData, valueData); err != nil {
			return err
		}
	}

	// The v2 global keys follow the BIP-0370 global map order: tx version,
	// fallback locktime, counts, modifiable, kernel count, offsets, and
	// the version key last.
	if p.PsbtVersion >= 2 {
		// Tx Version
		var txVersionBytes [4]byte
		binary.LittleEndian.PutUint32(txVersionBytes[:], uint32(p.TxVersion))
		if err := serializeKVPairWithType(w, uint8(TxVersionType), nil, txVersionBytes[:]); err != nil {
			return err
		}

		// Fallback LockTime
		if p.FallbackLocktime != nil {
			var fallbackLockTimeBytes [4]byte
			binary.LittleEndian.PutUint32(fallbackLockTimeBytes[:], *p.FallbackLocktime)
			if err := serializeKVPairWithType(w, uint8(FallbackLockTimeType), nil, fallbackLockTimeBytes[:]); err != nil {
				return err
			}
		}

		// Input Count
		var inputCountValue bytes.Buffer
		if err := wire.WriteVarInt(&inputCountValue, 0, uint64(len(p.Inputs))); err != nil {
			return err
		}
		if err := serializeKVPairWithType(w, uint8(InputCountType), nil, inputCountValue.Bytes()); err != nil {
			return err
		}

		// Output Count
		var outputCountValue bytes.Buffer
		if err := wire.WriteVarInt(&outputCountValue, 0, uint64(len(p.Outputs))); err != nil {
			return err
		}
		if err := serializeKVPairWithType(w, uint8(OutputCountType), nil, outputCountValue.Bytes()); err != nil {
			return err
		}

		// Tx Modifiable Flags
		if p.TxModifiableFlag != nil {
			if err := serializeKVPairWithType(w, uint8(TxModifiableType), nil, []byte{byte(*p.TxModifiableFlag)}); err != nil {
				return err
			}
		}

		// Kernel Count. LIP-0007: present iff kernel maps follow.
		if len(p.Kernels) > 0 {
			var kernelCountValue bytes.Buffer
			if err := wire.WriteVarInt(&kernelCountValue, 0, uint64(len(p.Kernels))); err != nil {
				return err
			}
			if err := serializeKVPairWithType(w, uint8(MwebKernelCountType), nil, kernelCountValue.Bytes()); err != nil {
				return err
			}
		}

		// MWEB Tx Offset
		if p.MwebTxOffset != nil {
			if err := serializeKVPairWithType(w, uint8(MwebTxOffsetType), nil, p.MwebTxOffset[:]); err != nil {
				return err
			}
		}

		// MWEB Stealth Offset
		if p.MwebStealthOffset != nil {
			if err := serializeKVPairWithType(w, uint8(MwebTxStealthOffsetType), nil, p.MwebStealthOffset[:]); err != nil {
				return err
			}
		}

		// Psbt Version
		var psbtVersionBytes [4]byte
		binary.LittleEndian.PutUint32(psbtVersionBytes[:], uint32(p.PsbtVersion))
		if err := serializeKVPairWithType(w, uint8(VersionType), nil, psbtVersionBytes[:]); err != nil {
			return err
		}
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
		err := pInput.serialize(w, p.PsbtVersion)
		if err != nil {
			return err
		}
	}

	for _, pOutput := range p.Outputs {
		err := pOutput.serialize(w, p.PsbtVersion)
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
	if p.HasMwebComponents() &&
		(len(p.Kernels) == 0 || !mwebComponentsFinal(p)) {

		return false
	}

	// The MWEB side is covered above; this closes over canonical inputs
	// (POutput/PKernel isFinalized are trivially true off-MWEB).
	for _, input := range p.Inputs {
		if !input.isFinalized() {
			return false
		}
	}

	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of BIP174, and returns true if so, false if not.
func (p *Packet) SanityCheck() error {
	if p.PsbtVersion == 0 {
		if p.UnsignedTx == nil || !validateUnsignedTX(p.UnsignedTx) {
			return ErrInvalidRawTxSigned
		}

		if p.HasMwebComponents() {
			return ErrInvalidPsbtFormat
		}
	}

	if err := p.checkMwebOrdering(); err != nil {
		return err
	}

	for _, tin := range p.Inputs {
		if !tin.isSane(p.PsbtVersion) {
			return ErrInvalidPsbtFormat
		}
	}

	for _, kernel := range p.Kernels {
		if !kernel.isSane() {
			return ErrInvalidPsbtFormat
		}
	}

	for _, output := range p.Outputs {
		if !output.isSane(p.PsbtVersion) {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}

// RedactSensitive removes the key material LIP-0007 marks sensitive — the
// shared secrets and address descriptors — from every input, for use before
// forwarding a packet to parties that no longer need them. Redaction is a
// host decision; serialization itself always round-trips these fields.
func (p *Packet) RedactSensitive() {
	for i := range p.Inputs {
		p.Inputs[i].MwebSharedSecret = nil
		p.Inputs[i].MwebAddrDescriptor = nil
	}
}

// checkMwebOrdering enforces LIP-0007's section ordering: MWEB input maps
// come after all canonical input maps, and likewise for outputs.
func (p *Packet) checkMwebOrdering() error {
	sawMweb := false
	for i := range p.Inputs {
		if p.Inputs[i].isMWEB() {
			sawMweb = true
		} else if sawMweb {
			return ErrInvalidPsbtFormat
		}
	}

	sawMweb = false
	for i := range p.Outputs {
		if p.Outputs[i].isMWEB() {
			sawMweb = true
		} else if sawMweb {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}

// GetTxFee returns the transaction fee via BIP-0174 fee analysis:
// (canonical UTXO values + explicit MWEB input amounts + peg-in amounts)
// minus (all output amounts + peg-out amounts). An error is returned if an
// input lacks its UTXO information or amounts fall outside the money range.
func (p *Packet) GetTxFee() (ltcutil.Amount, error) {
	sumIn, err := sumInputValues(p, true)
	if err != nil {
		return 0, err
	}
	sumInputs := uint64(sumIn)

	var sumOutputs uint64
	if p.PsbtVersion == 0 {
		for _, txOut := range p.UnsignedTx.TxOut {
			if err := addAmount(&sumOutputs, txOut.Value); err != nil {
				return 0, err
			}
		}
	} else {
		for idx := range p.Outputs {
			if err := addAmount(&sumOutputs, int64(p.Outputs[idx].Amount)); err != nil {
				return 0, err
			}
		}
	}

	_, pegins, pegouts, err := kernelTotals(p)
	if err != nil {
		return 0, err
	}

	totalIn, err := addChecked(sumInputs, pegins)
	if err != nil {
		return 0, err
	}
	totalOut, err := addChecked(sumOutputs, pegouts)
	if err != nil {
		return 0, err
	}
	if totalIn < totalOut {
		return 0, errors.New("negative transaction fee")
	}
	return ltcutil.Amount(totalIn - totalOut), nil
}

func (p *Packet) HasMwebComponents() bool {
	if p.MwebTxOffset != nil || p.MwebStealthOffset != nil || len(p.Kernels) != 0 {
		return true
	}

	for _, input := range p.Inputs {
		if input.isMWEB() {
			return true
		}
	}

	for _, output := range p.Outputs {
		if output.isMWEB() {
			return true
		}
	}

	return false
}

// prevOutpoint returns input i's previous outpoint for either PSBT version.
func (p *Packet) prevOutpoint(i int) (wire.OutPoint, error) {
	if p.PsbtVersion == 0 {
		if p.UnsignedTx == nil || i >= len(p.UnsignedTx.TxIn) {
			return wire.OutPoint{}, ErrInvalidPsbtFormat
		}
		return p.UnsignedTx.TxIn[i].PreviousOutPoint, nil
	}

	if i >= len(p.Inputs) {
		return wire.OutPoint{}, ErrInvalidPsbtFormat
	}
	pInput := p.Inputs[i]
	if pInput.PrevoutHash == nil || pInput.PrevoutIndex == nil {
		return wire.OutPoint{}, ErrInvalidPsbtFormat
	}
	return wire.OutPoint{
		Hash:  *pInput.PrevoutHash,
		Index: *pInput.PrevoutIndex,
	}, nil
}

func (p *Packet) getPrevOut(i int) (*wire.OutPoint, *chainhash.Hash) {
	if p.PsbtVersion == 0 {
		if p.UnsignedTx == nil || i >= len(p.UnsignedTx.TxIn) {
			return nil, nil
		}

		return &p.UnsignedTx.TxIn[i].PreviousOutPoint, nil
	}

	if i >= len(p.Inputs) {
		return nil, nil
	}

	pInput := p.Inputs[i]
	if pInput.PrevoutHash == nil || pInput.PrevoutIndex == nil {
		return nil, pInput.MwebOutputId
	} // TODO: Return synthetic OutPoint?

	prevout := wire.OutPoint{Hash: *pInput.PrevoutHash, Index: *pInput.PrevoutIndex}
	return &prevout, nil
}

func (p *Packet) BuildTxOuts() []*wire.TxOut {
	if p.PsbtVersion == 0 {
		return p.UnsignedTx.TxOut
	}

	txouts := make([]*wire.TxOut, len(p.Outputs))
	for idx, pOutput := range p.Outputs {
		var txout wire.TxOut
		txout.Value = int64(pOutput.Amount)
		if pOutput.StealthAddress != nil {
			pkScript := append(pOutput.StealthAddress.Scan[:], pOutput.StealthAddress.Spend[:]...)
			txout.PkScript = pkScript
		} else {
			txout.PkScript = make([]byte, len(pOutput.PKScript))
			copy(txout.PkScript, pOutput.PKScript)
		}
		txouts[idx] = &txout
	}

	return txouts
}
