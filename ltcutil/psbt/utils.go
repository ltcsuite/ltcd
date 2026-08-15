// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	ec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
)

// WriteTxWitness is a utility function due to non-exported witness
// serialization (writeTxWitness encodes the litecoin protocol encoding for a
// transaction input's witness into w).
func WriteTxWitness(w io.Writer, wit [][]byte) error {
	if err := wire.WriteVarInt(w, 0, uint64(len(wit))); err != nil {
		return err
	}

	for _, item := range wit {
		err := wire.WriteVarBytes(w, 0, item)
		if err != nil {
			return err
		}
	}
	return nil
}

// writePKHWitness writes a witness for a p2wkh spending input
func writePKHWitness(sig []byte, pub []byte) ([]byte, error) {
	return writeWitness(sig, pub)
}

// writeWitness serializes a witness stack from the given items.
func writeWitness(stackElements ...[]byte) ([]byte, error) {
	var (
		buf          bytes.Buffer
		witnessItems = append([][]byte{}, stackElements...)
	)

	if err := WriteTxWitness(&buf, witnessItems); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// checkIsMultisigScript is a utility function to check whether a given
// redeemscript fits the standard multisig template used in all P2SH based
// multisig, given a set of pubkeys for redemption.
func checkIsMultiSigScript(pubKeys [][]byte, sigs [][]byte,
	script []byte) bool {

	// First insist that the script type is multisig.
	if txscript.GetScriptClass(script) != txscript.MultiSigTy {
		return false
	}

	// Inspect the script to ensure that the number of sigs and pubkeys is
	// correct
	_, numSigs, err := txscript.CalcMultiSigStats(script)
	if err != nil {
		return false
	}

	// If the number of sigs provided, doesn't match the number of required
	// pubkeys, then we can't proceed as we're not yet final.
	if numSigs != len(pubKeys) || numSigs != len(sigs) {
		return false
	}

	return true
}

// extractKeyOrderFromScript is a utility function to extract an ordered list
// of signatures, given a serialized script (redeemscript or witness script), a
// list of pubkeys and the signatures corresponding to those pubkeys. This
// function is used to ensure that the signatures will be embedded in the final
// scriptSig or scriptWitness in the correct order.
func extractKeyOrderFromScript(script []byte, expectedPubkeys [][]byte,
	sigs [][]byte) ([][]byte, error) {

	// If this isn't a proper finalized multi-sig script, then we can't
	// proceed.
	if !checkIsMultiSigScript(expectedPubkeys, sigs, script) {
		return nil, ErrUnsupportedScriptType
	}

	// Arrange the pubkeys and sigs into a slice of format:
	//   * [[pub,sig], [pub,sig],..]
	type sigWithPub struct {
		pubKey []byte
		sig    []byte
	}
	var pubsSigs []sigWithPub
	for i, pub := range expectedPubkeys {
		pubsSigs = append(pubsSigs, sigWithPub{
			pubKey: pub,
			sig:    sigs[i],
		})
	}

	// Now that we have the set of (pubkey, sig) pairs, we'll construct a
	// position map that we can use to swap the order in the slice above to
	// match how things are laid out in the script.
	type positionEntry struct {
		index int
		value sigWithPub
	}
	var positionMap []positionEntry

	// For each pubkey in our pubsSigs slice, we'll now construct a proper
	// positionMap entry, based on _where_ in the script the pubkey first
	// appears.
	for _, p := range pubsSigs {
		pos := bytes.Index(script, p.pubKey)
		if pos < 0 {
			return nil, errors.New("script does not contain pubkeys")
		}

		positionMap = append(positionMap, positionEntry{
			index: pos,
			value: p,
		})
	}

	// Now that we have the position map full populated, we'll use the
	// index data to properly sort the entries in the map based on where
	// they appear in the script.
	sort.Slice(positionMap, func(i, j int) bool {
		return positionMap[i].index < positionMap[j].index
	})

	// Finally, we can simply iterate through the position map in order to
	// extract the proper signature ordering.
	sortedSigs := make([][]byte, 0, len(positionMap))
	for _, x := range positionMap {
		sortedSigs = append(sortedSigs, x.value.sig)
	}

	return sortedSigs, nil
}

// getMultisigScriptWitness creates a full psbt serialized Witness field for
// the transaction, given the public keys and signatures to be appended. This
// function will only accept witnessScripts of the type M of N multisig. This
// is used for both p2wsh and nested p2wsh multisig cases.
func getMultisigScriptWitness(witnessScript []byte, pubKeys [][]byte,
	sigs [][]byte) ([]byte, error) {

	// First using the script as a guide, we'll properly order the sigs
	// according to how their corresponding pubkeys appear in the
	// witnessScript.
	orderedSigs, err := extractKeyOrderFromScript(
		witnessScript, pubKeys, sigs,
	)
	if err != nil {
		return nil, err
	}

	// Now that we know the proper order, we'll append each of the
	// signatures into a new witness stack, then top it off with the
	// witness script at the end, prepending the nil as we need the extra
	// pop..
	witnessElements := make(wire.TxWitness, 0, len(sigs)+2)
	witnessElements = append(witnessElements, nil)
	for _, os := range orderedSigs {
		witnessElements = append(witnessElements, os)
	}
	witnessElements = append(witnessElements, witnessScript)

	// Now that we have the full witness stack, we'll serialize it in the
	// expected format, and return the final bytes.
	var buf bytes.Buffer
	if err = WriteTxWitness(&buf, witnessElements); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkSigHashFlags compares the sighash flag byte on a signature with the
// value expected according to any PsbtInSighashType field in this section of
// the PSBT, and returns true if they match, false otherwise.
// If no SighashType field exists, it is assumed to be SIGHASH_ALL.
//
// TODO(waxwing): sighash type not restricted to one byte in future?
func checkSigHashFlags(sig []byte, input *PInput) bool {
	expectedSighashType := txscript.SigHashAll
	if input.SighashType != 0 {
		expectedSighashType = input.SighashType
	}

	return expectedSighashType == txscript.SigHashType(sig[len(sig)-1])
}

// serializeKVpair writes out a kv pair using a varbyte prefix for each.
func serializeKVpair(w io.Writer, key []byte, value []byte) error {
	if err := wire.WriteVarBytes(w, 0, key); err != nil {
		return err
	}

	return wire.WriteVarBytes(w, 0, value)
}

// serializeKVPairWithType writes out to the passed writer a type coupled with
// a key.
func serializeKVPairWithType(w io.Writer, kt uint8, keydata []byte,
	value []byte) error {

	// If the key has no data, then we write a blank slice.
	if keydata == nil {
		keydata = []byte{}
	}

	// The final key to be written is: {type} || {keyData}
	serializedKey := append([]byte{kt}, keydata...)
	return serializeKVpair(w, serializedKey, value)
}

// getKey reads one key from the stream: its full compact-size type and any
// keydata. ok is false when the 0x00 separator ends the key-value pair list.
func getKey(r io.Reader) (keyType uint64, keyData []byte, ok bool, err error) {

	// For the key, we read the varint separately, instead of using the
	// available ReadVarBytes, because we have a specific treatment of 0x00
	// here:
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return 0, nil, false, ErrInvalidPsbtFormat
	}
	if count == 0 {
		// A separator indicates end of key-value pair list.
		return 0, nil, false, nil
	}

	// Check that we don't attempt to decode a dangerously large key.
	if count > MaxPsbtKeyLength {
		return 0, nil, false, ErrInvalidKeyData
	}

	// Next, we ready out the designated number of bytes, which may include
	// a type, key, and optional data.
	keyTypeAndData := make([]byte, count)
	if _, err := io.ReadFull(r, keyTypeAndData[:]); err != nil {
		return 0, nil, false, err
	}
	keyReader := bytes.NewReader(keyTypeAndData[:])

	// BIP-0174 specifies that the key shall begin with a varint indicating the type.
	// The remaining bytes, if any, are the key data.
	keyType, err = wire.ReadVarInt(keyReader, 0)
	if err != nil {
		return 0, nil, false, ErrInvalidPsbtFormat
	}

	// Note that the second return value will usually be empty, since most
	// keys contain no more than the key type byte.
	if keyReader.Len() == 0 {
		return keyType, nil, true, nil
	}

	// Otherwise, we return the key, along with any data that it may contain.
	keyData = make([]byte, keyReader.Len())
	if _, err := keyReader.Read(keyData); err != nil {
		return 0, nil, false, err
	}

	return keyType, keyData, true, nil
}

type keyValuePair struct {
	// keyType holds the full compact-size key type. Types above 0xff are
	// never known to this package and must be preserved as unknowns.
	keyType   uint64
	keyData   []byte
	valueData []byte
}

// isKnownType reports whether the pair's type can be one of this package's
// single-byte key types.
func (kv *keyValuePair) isKnownType() bool {
	return kv.keyType <= 0xff
}

// unknownKey rebuilds the original serialized key (compact-size type ||
// keydata) so unknown keys round-trip byte-exact.
func (kv *keyValuePair) unknownKey() []byte {
	var buf bytes.Buffer
	_ = wire.WriteVarInt(&buf, 0, kv.keyType)
	buf.Write(kv.keyData)
	return buf.Bytes()
}

// asUnknown converts the pair into an Unknown carrying the original key bytes.
func (kv *keyValuePair) asUnknown() *Unknown {
	return &Unknown{Key: kv.unknownKey(), Value: kv.valueData}
}

// fixedValue returns the pair's value after checking that no keydata is
// present and the value is exactly n bytes. The mw.Read* parsers accept
// over-length input and silently truncate, so this guard is load-bearing.
func (kv *keyValuePair) fixedValue(n int) ([]byte, error) {
	if kv.keyData != nil {
		return nil, ErrInvalidKeyData
	}
	if len(kv.valueData) != n {
		return nil, ErrInvalidPsbtFormat
	}
	return kv.valueData, nil
}

// mapCountValue parses a map-count value: exactly one bounded compact-size
// integer with no keydata and no trailing bytes.
func (kv *keyValuePair) mapCountValue() (uint64, error) {
	if kv.keyData != nil || kv.valueData == nil {
		return 0, ErrInvalidPsbtFormat
	}
	reader := bytes.NewReader(kv.valueData)
	value, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		return 0, err
	}
	if reader.Len() != 0 || value > maxPsbtMapCount {
		return 0, ErrInvalidPsbtFormat
	}
	return value, nil
}

// commitmentValue parses a 33-byte Pedersen commitment, requiring the 0x08 or
// 0x09 commitment prefix and a valid curve point (mw.ReadCommitment accepts
// any bytes, and mw.Commitment.PubKey panics on an invalid X).
func (kv *keyValuePair) commitmentValue() (*mw.Commitment, error) {
	value, err := kv.fixedValue(len(mw.Commitment{}))
	if err != nil {
		return nil, err
	}
	if value[0] != 0x08 && value[0] != 0x09 {
		return nil, ErrInvalidPsbtFormat
	}

	point := make([]byte, len(value))
	copy(point, value)
	point[0] = 0x02 | (value[0] & 1)
	if _, err := ec.ParsePubKey(point); err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	commit := mw.ReadCommitment(value)
	if commit == nil {
		return nil, ErrInvalidPsbtFormat
	}
	return commit, nil
}

// isMwebDescriptor reports whether value is a printable-ASCII mweb(...)
// output descriptor, per the LIP-0007 mweb(...) descriptor format.
func isMwebDescriptor(value []byte) bool {
	if !bytes.HasPrefix(value, []byte("mweb(")) {
		return false
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// Returns a keyValuePair, defined by BIP-0174 as <keypair>.
// A separator will be returned as a nil keyValuePair and error.
// <keypair> := <key> <value>
// <key> := <keylen> <keytype> <keydata>
// <value> := <valuelen> <valuedata>
func getKVPair(r io.Reader) (*keyValuePair, error) {
	keyType, keyData, ok, err := getKey(r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	value, err := wire.ReadVarBytes(
		r, 0, MaxPsbtValueLength, "PSBT value",
	)
	if err != nil {
		return nil, err
	}

	return &keyValuePair{
		keyType:   keyType,
		keyData:   keyData,
		valueData: value,
	}, nil
}

// readTxOut is a limited version of wire.ReadTxOut, because the latter is not
// exported.
func readTxOut(txout []byte) (*wire.TxOut, error) {
	if len(txout) < 10 {
		return nil, ErrInvalidPsbtFormat
	}

	valueSer := binary.LittleEndian.Uint64(txout[:8])

	scriptReader := bytes.NewReader(txout[8:])
	scriptPubKey, err := wire.ReadVarBytes(scriptReader, 0, MaxPsbtValueLength, "scriptPubKey")
	if err != nil {
		return nil, err
	}

	return wire.NewTxOut(int64(valueSer), scriptPubKey), nil
}

// SumUtxoInputValues tries to extract the sum of all inputs specified in the
// UTXO fields of the PSBT. An error is returned if an input is specified that
// does not contain any UTXO information.
func SumUtxoInputValues(packet *Packet) (int64, error) {
	return sumInputValues(packet, true)
}

// sumInputValues sums the input values; MWEB inputs (whose explicit amounts
// balance through their kernels rather than the canonical ledger) count only
// when includeMweb is set.
func sumInputValues(packet *Packet, includeMweb bool) (int64, error) {
	// We take the TX ins of the unsigned TX as the truth for how many
	// inputs there should be, as the fields in the extra data part of the
	// PSBT can be empty.
	if packet.PsbtVersion == 0 && len(packet.UnsignedTx.TxIn) != len(packet.Inputs) {
		return 0, fmt.Errorf("TX input length doesn't match PSBT " +
			"input length")
	}

	inputSum := uint64(0)
	for idx, in := range packet.Inputs {
		switch {
		case in.isMWEB():
			// An MWEB input without its explicit amount cannot be
			// analyzed, whether or not it is being summed.
			if in.MwebAmount == nil {
				return 0, fmt.Errorf("input %d has no "+
					"UTXO information", idx)
			}
			if includeMweb {
				if err := addAmount(&inputSum, int64(*in.MwebAmount)); err != nil {
					return 0, err
				}
			}

		case in.WitnessUtxo != nil:
			// Witness UTXOs only need to reference the TxOut.
			if err := addAmount(&inputSum, in.WitnessUtxo.Value); err != nil {
				return 0, err
			}

		case in.NonWitnessUtxo != nil:
			// Non-witness UTXOs reference to the whole transaction
			// the UTXO resides in.
			utxOuts := in.NonWitnessUtxo.TxOut
			prevOut, err := packet.prevOutpoint(idx)
			if err != nil {
				return 0, err
			}

			// Check that utxOuts actually has enough space to
			// contain the previous outpoint's index.
			if prevOut.Index >= uint32(len(utxOuts)) {
				return 0, fmt.Errorf("input %d has malformed "+
					"TxOut field", idx)
			}

			if err := addAmount(&inputSum, utxOuts[prevOut.Index].Value); err != nil {
				return 0, err
			}

		default:
			return 0, fmt.Errorf("input %d has no UTXO information",
				idx)
		}
	}
	return int64(inputSum), nil
}

// TxOutsEqual returns true if two transaction outputs are equal.
func TxOutsEqual(out1, out2 *wire.TxOut) bool {
	if out1 == nil || out2 == nil {
		return out1 == out2
	}
	return out1.Value == out2.Value &&
		bytes.Equal(out1.PkScript, out2.PkScript)
}

// VerifyOutputsEqual verifies that the two slices of transaction outputs are
// deep equal to each other. We do the length check and manual loop to provide
// better error messages to the user than just returning "not equal".
func VerifyOutputsEqual(outs1, outs2 []*wire.TxOut) error {
	if len(outs1) != len(outs2) {
		return fmt.Errorf("number of outputs are different")
	}
	for idx, out := range outs1 {
		// There is a byte slice in the output so we can't use the
		// equality operator.
		if !TxOutsEqual(out, outs2[idx]) {
			return fmt.Errorf("output %d is different", idx)
		}
	}
	return nil
}

// VerifyInputPrevOutpointsEqual verifies that the previous outpoints of the
// two slices of transaction inputs are deep equal to each other. We do the
// length check and manual loop to provide better error messages to the user
// than just returning "not equal".
func VerifyInputPrevOutpointsEqual(ins1, ins2 []*wire.TxIn) error {
	if len(ins1) != len(ins2) {
		return fmt.Errorf("number of inputs are different")
	}
	for idx, in := range ins1 {
		if in.PreviousOutPoint != ins2[idx].PreviousOutPoint {
			return fmt.Errorf("previous outpoint of input %d is "+
				"different", idx)
		}
	}
	return nil
}

// VerifyInputOutputLen makes sure a packet is non-nil, contains a non-nil wire
// transaction if PSBTv0, and that the wire input/output lengths match the partial input/
// output lengths. A caller also can specify if they expect any inputs and/or
// outputs to be contained in the packet.
func VerifyInputOutputLen(packet *Packet, needInputs, needOutputs bool) error {
	if packet == nil {
		return fmt.Errorf("PSBT packet cannot be nil")
	}

	if packet.PsbtVersion == 0 {
		if packet.UnsignedTx == nil {
			return fmt.Errorf("invalid PSBT, unsigned tx cannot be nil for PSBTv0")
		}

		if len(packet.UnsignedTx.TxIn) != len(packet.Inputs) {
			return fmt.Errorf("invalid PSBT, wire inputs don't match " +
				"partial inputs")
		}
		if len(packet.UnsignedTx.TxOut) != len(packet.Outputs) {
			return fmt.Errorf("invalid PSBT, wire outputs don't match " +
				"partial outputs")
		}
	}

	if needInputs && len(packet.Inputs) == 0 {
		return fmt.Errorf("PSBT packet must contain at least one " +
			"input")
	}
	if needOutputs && len(packet.Outputs) == 0 {
		return fmt.Errorf("PSBT packet must contain at least one " +
			"output")
	}

	return nil
}

// InputsReadyToSign makes sure that all input data have the previous output
// specified meaning that either nonwitness UTXO or the witness UTXO data is
// specified in the psbt package. This check is necessary because of 2 reasons.
// The sighash calculation is now different for witnessV0 and witnessV1 inputs
// this means we need to check the previous output pkScript for the specific
// type and the second reason is that the sighash calculation for taproot inputs
// include the previous output pkscripts.
func InputsReadyToSign(packet *Packet) error {
	err := VerifyInputOutputLen(packet, true, true)
	if err != nil {
		return err
	}

	for i, input := range packet.Inputs {
		if input.isMWEB() {
			// Already-signed MWEB inputs have presign fields
			// (amount, shared secret, etc.) stripped by the signer.
			if !input.isFinalized() {
				if input.MwebAmount == nil {
					return errors.New("input amount missing")
				} else if input.MwebOutputPubkey == nil {
					return errors.New("spent output pubkey missing")
				} else if input.MwebSharedSecret == nil && input.MwebKeyExchangePubkey == nil {
					return errors.New("input shared secret missing")
				}
			}
		} else if input.NonWitnessUtxo == nil && input.WitnessUtxo == nil {
			return fmt.Errorf("invalid PSBT, input with index %d "+
				"missing utxo information", i)
		}
	}

	// TODO(dburkett): Check MWEB outputs

	return nil
}

// findLeafScript attempts to locate the leaf script of a given target Tap Leaf
// hash in the list of leaf scripts of the given input.
func findLeafScript(pInput *PInput,
	targetLeafHash []byte) (*TaprootTapLeafScript, error) {

	for _, leaf := range pInput.TaprootLeafScript {
		leafHash := txscript.TapLeaf{
			LeafVersion: leaf.LeafVersion,
			Script:      leaf.Script,
		}.TapHash()

		if bytes.Equal(targetLeafHash, leafHash[:]) {
			return leaf, nil
		}
	}

	return nil, fmt.Errorf("leaf script for target leaf hash %x not "+
		"found in input", targetLeafHash)
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func intPtr(v int) *int {
	return &v
}

type keySet struct {
	seen  map[string]struct{}
	types map[uint64]struct{}
}

func newKeySet() *keySet {
	return &keySet{
		seen:  make(map[string]struct{}),
		types: make(map[uint64]struct{}),
	}
}

func (ks *keySet) addKey(keyType uint64, keyData []byte) bool {
	// The dedup key is the canonical compact-size type encoding plus the
	// keydata; the one-byte fast path stops at 0xfd where the encodings
	// of different types could otherwise collide.
	var keyStr string
	if keyType < 0xfd {
		keyStr = string(append([]byte{byte(keyType)}, keyData...))
	} else {
		var fullKey bytes.Buffer
		_ = wire.WriteVarInt(&fullKey, 0, keyType)
		fullKey.Write(keyData)
		keyStr = fullKey.String()
	}

	if _, exists := ks.seen[keyStr]; exists {
		return false
	}
	ks.seen[keyStr] = struct{}{}
	ks.types[keyType] = struct{}{}
	return true
}

// hasType reports whether any key of the given type was added.
func (ks *keySet) hasType(keyType uint64) bool {
	_, exists := ks.types[keyType]
	return exists
}
