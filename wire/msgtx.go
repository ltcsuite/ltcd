// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"lukechampine.com/blake3"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + chainhash.HashSize

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// MinTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	MinTxOutPayload = 9

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / MinTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// freeListMaxScriptSize is the size of each buffer in the free list
	// that	is used for deserializing scripts from the wire before they are
	// concatenated into a single contiguous buffers.  This value was chosen
	// because it is slightly more than twice the size of the vast majority
	// of all "standard" scripts.  Larger scripts are still deserialized
	// properly as the free list will simply be bypassed for them.
	freeListMaxScriptSize = 512

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deserialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	freeListMaxItems = 12500

	// maxWitnessItemsPerInput is the maximum number of witness items to
	// be read for the witness data for a single TxIn. This number is
	// derived using a possible lower bound for the encoding of a witness
	// item: 1 byte for length + 1 byte for the witness item itself, or two
	// bytes. This value is then divided by the currently allowed maximum
	// "cost" for a transaction. We use this for an upper bound for the
	// buffer and consensus makes sure that the weight of a transaction
	// cannot be more than 4000000.
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize is the maximum allowed size for an item within
	// an input's witness data. This value is bounded by the largest
	// possible block size, post segwit v1 (taproot).
	maxWitnessItemSize = 4_000_000
)

// TxFlagMarker is the first byte of the FLAG field in a bitcoin tx
// message. It allows decoders to distinguish a regular serialized
// transaction from one that would require a different parsing logic.
//
// Position of FLAG in a bitcoin tx message:
//
//	┌─────────┬────────────────────┬─────────────┬─────┐
//	│ VERSION │ FLAG               │ TX-IN-COUNT │ ... │
//	│ 4 bytes │ 2 bytes (optional) │ varint      │     │
//	└─────────┴────────────────────┴─────────────┴─────┘
//
// Zooming into the FLAG field:
//
//	┌── FLAG ─────────────┬────────┐
//	│ TxFlagMarker (0x00) │ TxFlag │
//	│ 1 byte              │ 1 byte │
//	└─────────────────────┴────────┘
const TxFlagMarker = 0x00

// TxFlag is the second byte of the FLAG field in a bitcoin tx message.
// It indicates the decoding logic to use in the transaction parser, if
// TxFlagMarker is detected in the tx message.
//
// As of writing this, only the witness flag (0x01) is supported, but may be
// extended in the future to accommodate auxiliary non-committed fields.
type TxFlag = byte

const (
	// WitnessFlag is a flag specific to witness encoding. If the TxFlagMarker
	// is encountered followed by the WitnessFlag, then it indicates a
	// transaction has witness data. This allows decoders to distinguish a
	// serialized transaction with witnesses from a legacy one.
	WitnessFlag TxFlag = 0x01
	MwebFlag    TxFlag = 0x08
)

// scriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that have a cap according to the
// freeListMaxScriptSize constant.  It is used to provide temporary buffers for
// deserializing scripts in order to greatly reduce the number of allocations
// required.
//
// The caller can obtain a buffer from the free list by calling the Borrow
// function and should return it via the Return function when done using it.
type scriptFreeList chan []byte

// Borrow returns a byte slice from the free list with a length according the
// provided size.  A new buffer is allocated if there are any items available.
//
// When the size is larger than the max size allowed for items on the free list
// a new buffer of the appropriate size is allocated and returned.  It is safe
// to attempt to return said buffer via the Return function as it will be
// ignored and allowed to go the garbage collector.
func (c scriptFreeList) Borrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}
	return buf[:size]
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the Borrow function.  Any slices that are not of the appropriate size, such
// as those whose size is greater than the largest allowed free list item size
// are simply ignored so they can go to the garbage collector.
func (c scriptFreeList) Return(buf []byte) {
	// Ignore any buffers returned that aren't the expected size for the
	// free list.
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	// Return the buffer to the free list when it's not full.  Otherwise let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for script deserialization.  As
// previously described, this free list is maintained to significantly reduce
// the number of allocations.
var scriptPool scriptFreeList = make(chan []byte, freeListMaxItems)

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          TxWitness
	Sequence         uint32
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Witness:          witness,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input's witness.
func (t TxWitness) SerializeSize() int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(t)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range t {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
	IsHogEx  bool
	Kern0    []byte
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

// TxHash generates the Hash for the transaction.
func (msg *MsgTx) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	// A pure-MW tx can only be in mempool or the EB, not the canonical block.
	if len(msg.Kern0) > 0 && len(msg.TxIn) == 0 && len(msg.TxOut) == 0 {
		// CTransaction::ComputeHash in src/primitives/transaction.cpp.
		// Fortunately also a 32 byte hash so we can use chainhash.Hash.
		return blake3.Sum256(msg.Kern0)
	}

	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeStripped()))
	_ = msg.SerializeNoWitness(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (msg *MsgTx) WitnessHash() chainhash.Hash {
	if msg.HasWitness() {
		buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
		_ = msg.Serialize(buf)
		return chainhash.DoubleHashH(buf.Bytes())
	}

	return msg.TxHash()
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Deep copy the old signature script.
		var newScript []byte
		oldScript := oldTxIn.SignatureScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureScript:  newScript,
			Sequence:         oldTxIn.Sequence,
		}

		// If the transaction is witnessy, then also copy the
		// witnesses.
		if len(oldTxIn.Witness) != 0 {
			// Deep copy the old witness data.
			newTxIn.Witness = make([][]byte, len(oldTxIn.Witness))
			for i, oldItem := range oldTxIn.Witness {
				newItem := make([]byte, len(oldItem))
				copy(newItem, oldItem)
				newTxIn.Witness[i] = newItem
			}
		}

		// Finally, append this fully copied txin.
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{
			Value:    oldTxOut.Value,
			PkScript: newScript,
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return &newTx
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// A count of zero (meaning no TxIn's to the uninitiated) means that the
	// value is a TxFlagMarker, and hence indicates the presence of a flag.
	hasMweb := false
	hasWitness := false
	if count == TxFlagMarker && enc == WitnessEncoding {
		var flag [1]TxFlag
		// The count varint was in fact the flag marker byte. Next, we need to
		// read the flag value, which is a single byte.
		if _, err = io.ReadFull(r, flag[:]); err != nil {
			return err
		}

		hasWitness = (flag[0]&WitnessFlag != 0)
		flag[0] = flag[0] &^ WitnessFlag
		hasMweb = (flag[0]&MwebFlag != 0)
		flag[0] = flag[0] &^ MwebFlag

		if flag[0] != 0 {
			str := fmt.Sprintf("Unknown flag %x, known flags:[%d, %d]", flag, WitnessFlag, MwebFlag)
			return messageError("MsgTx.BtcDecode", str)
		}

		// With the Segregated Witness specific fields decoded, we can
		// now read in the actual txin count.
		count, err = ReadVarInt(r, pver)
		if err != nil {
			return err
		}
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// returnScriptBuffers is a closure that returns any script buffers that
	// were borrowed from the pool when there are any deserialization
	// errors.  This is only valid to call before the final step which
	// replaces the scripts with the location in a contiguous buffer and
	// returns them.
	returnScriptBuffers := func() {
		for _, txIn := range msg.TxIn {
			if txIn == nil {
				continue
			}

			if txIn.SignatureScript != nil {
				scriptPool.Return(txIn.SignatureScript)
			}

			for _, witnessElem := range txIn.Witness {
				if witnessElem != nil {
					scriptPool.Return(witnessElem)
				}
			}
		}
		for _, txOut := range msg.TxOut {
			if txOut == nil || txOut.PkScript == nil {
				continue
			}
			scriptPool.Return(txOut.PkScript)
		}
	}

	// Deserialize the inputs.
	var totalScriptSize uint64
	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		ti := &txIns[i]
		msg.TxIn[i] = ti
		err = readTxIn(r, pver, msg.Version, ti)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(ti.SignatureScript))
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxOutPerMessage) {
		returnScriptBuffers()
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the outputs.
	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		to := &txOuts[i]
		msg.TxOut[i] = to
		err = readTxOut(r, pver, msg.Version, to)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(to.PkScript))
	}

	// If the transaction's flag byte isn't 0x00 at this point, then one or
	// more of its inputs has accompanying witness data.
	if hasWitness {
		for _, txin := range msg.TxIn {
			// For each input, the witness is encoded as a stack
			// with one or more items. Therefore, we first read a
			// varint which encodes the number of stack items.
			witCount, err := ReadVarInt(r, pver)
			if err != nil {
				returnScriptBuffers()
				return err
			}

			// Prevent a possible memory exhaustion attack by
			// limiting the witCount value to a sane upper bound.
			if witCount > maxWitnessItemsPerInput {
				returnScriptBuffers()
				str := fmt.Sprintf("too many witness items to fit "+
					"into max message size [count %d, max %d]",
					witCount, maxWitnessItemsPerInput)
				return messageError("MsgTx.BtcDecode", str)
			}

			// Then for witCount number of stack items, each item
			// has a varint length prefix, followed by the witness
			// item itself.
			txin.Witness = make([][]byte, witCount)
			for j := uint64(0); j < witCount; j++ {
				txin.Witness[j], err = readScript(
					r, pver, maxWitnessItemSize, "script witness item",
				)
				if err != nil {
					returnScriptBuffers()
					return err
				}
				totalScriptSize += uint64(len(txin.Witness[j]))
			}
		}
	}

	var kern0 []byte
	var isHogEx bool
	if hasMweb {
		dec := newDecoder(r)
		kern0, isHogEx, err = dec.readMWTX()
		if err != nil {
			returnScriptBuffers()
			return err
		}

		msg.IsHogEx = isHogEx
		msg.Kern0 = kern0

		if isHogEx && len(msg.TxOut) == 0 {
			return messageError("MsgTx.BtcDecode", "No outputs on HogEx transaction")
		}

		msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			returnScriptBuffers()
			return err
		}
	} else {
		msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			returnScriptBuffers()
			return err
		}
	}

	// Create a single allocation to house all of the scripts and set each
	// input signature script and output public key script to the
	// appropriate subslice of the overall contiguous buffer.  Then, return
	// each individual script buffer back to the pool so they can be reused
	// for future deserializations.  This is done because it significantly
	// reduces the number of allocations the garbage collector needs to
	// track, which in turn improves performance and drastically reduces the
	// amount of runtime overhead that would otherwise be needed to keep
	// track of millions of small allocations.
	//
	// NOTE: It is no longer valid to call the returnScriptBuffers closure
	// after these blocks of code run because it is already done and the
	// scripts in the transaction inputs and outputs no longer point to the
	// buffers.
	var offset uint64
	scripts := make([]byte, totalScriptSize)
	for i := 0; i < len(msg.TxIn); i++ {
		// Copy the signature script into the contiguous buffer at the
		// appropriate offset.
		signatureScript := msg.TxIn[i].SignatureScript
		copy(scripts[offset:], signatureScript)

		// Reset the signature script of the transaction input to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(signatureScript))
		end := offset + scriptSize
		msg.TxIn[i].SignatureScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(signatureScript)

		for j := 0; j < len(msg.TxIn[i].Witness); j++ {
			// Copy each item within the witness stack for this
			// input into the contiguous buffer at the appropriate
			// offset.
			witnessElem := msg.TxIn[i].Witness[j]
			copy(scripts[offset:], witnessElem)

			// Reset the witness item within the stack to the slice
			// of the contiguous buffer where the witness lives.
			witnessElemSize := uint64(len(witnessElem))
			end := offset + witnessElemSize
			msg.TxIn[i].Witness[j] = scripts[offset:end:end]
			offset += witnessElemSize

			// Return the temporary buffer used for the witness stack
			// item to the pool.
			scriptPool.Return(witnessElem)
		}
	}
	for i := 0; i < len(msg.TxOut); i++ {
		// Copy the public key script into the contiguous buffer at the
		// appropriate offset.
		pkScript := msg.TxOut[i].PkScript
		copy(scripts[offset:], pkScript)

		// Reset the public key script of the transaction output to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(pkScript))
		end := offset + scriptSize
		msg.TxOut[i].PkScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(pkScript)
	}

	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// DeserializeNoWitness decodes a transaction from r into the receiver, where
// the transaction encoding format within r MUST NOT utilize the new
// serialization format created to encode transaction bearing witness data
// within inputs.
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	// If the encoding version is set to WitnessEncoding, and the Flags
	// field for the MsgTx aren't 0x00, then this indicates the transaction
	// is to be encoded using the new witness inclusionary structure
	// defined in BIP0144.
	doWitness := enc == WitnessEncoding && msg.HasWitness()
	if doWitness {
		// After the transaction's Version field, we include two additional
		// bytes specific to the witness encoding. This byte sequence is known
		// as a flag. The first byte is a marker byte (TxFlagMarker) and the
		// second one is the flag value to indicate presence of witness data.
		if _, err := w.Write([]byte{TxFlagMarker, WitnessFlag}); err != nil {
			return err
		}
	}

	count := uint64(len(msg.TxIn))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = writeTxIn(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = WriteTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	// If this transaction is a witness transaction, and the witness
	// encoded is desired, then encode the witness for each of the inputs
	// within the transaction.
	if doWitness {
		for _, ti := range msg.TxIn {
			err = writeTxWitness(w, pver, msg.Version, ti.Witness)
			if err != nil {
				return err
			}
		}
	}

	return binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTx) HasWitness() bool {
	for _, txIn := range msg.TxIn {
		if len(txIn.Witness) != 0 {
			return true
		}
	}

	return false
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the bitcoin wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//
	// Passing a encoding type of WitnessEncoding to BtcEncode for MsgTx
	// indicates that the transaction's witnesses (if any) should be
	// serialized according to the new serialization structure defined in
	// BIP0144.
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes the transaction to w in an identical manner to
// Serialize, however even if the source transaction has inputs with witness
// data, the old serialization format will still be used.
func (msg *MsgTx) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTx) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTx) SerializeSize() int {
	n := msg.baseSize()

	if msg.HasWitness() {
		// The marker, and flag fields take up two additional bytes.
		n += 2

		// Additionally, factor in the serialized size of each of the
		// witnesses for each txin.
		for _, txin := range msg.TxIn {
			n += txin.Witness.SerializeSize()
		}
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the transaction, excluding any included witness data.
func (msg *MsgTx) SerializeSizeStripped() int {
	return msg.baseSize()
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw serialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTx) PkScriptLocs() []int {
	numTxOut := len(msg.TxOut)
	if numTxOut == 0 {
		return nil
	}

	// The starting offset in the serialized transaction of the first
	// transaction output is:
	//
	// Version 4 bytes + serialized varint size for the number of
	// transaction inputs and outputs + serialized size of each transaction
	// input.
	n := 4 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(numTxOut))

	// If this transaction has a witness input, the an additional two bytes
	// for the marker, and flag byte need to be taken into account.
	if len(msg.TxIn) > 0 && msg.TxIn[0].Witness != nil {
		n += 2
	}

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numTxOut)
	for i, txOut := range msg.TxOut {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + serialized varint size for the length of
		// PkScript.
		n += 8 + VarIntSerializeSize(uint64(len(txOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(txOut.PkScript)
	}

	return pkScriptLocs
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func readOutPoint(r io.Reader, pver uint32, version int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint32(r, littleEndian)
	return err
}

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, op.Index)
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhaustion attacks and forced panics through malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, messageError("readScript", str)
	}

	b := scriptPool.Borrow(count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		scriptPool.Return(b)
		return nil, err
	}
	return b, nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn) error {
	err := readOutPoint(r, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	ti.SignatureScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction input signature script")
	if err != nil {
		return err
	}

	return readElement(r, &ti.Sequence)
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxIn(w io.Writer, pver uint32, version int32, ti *TxIn) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, ti.SignatureScript)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, ti.Sequence)
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOut(r io.Reader, pver uint32, version int32, to *TxOut) error {
	err := readElement(r, &to.Value)
	if err != nil {
		return err
	}

	to.PkScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction output public key script")
	return err
}

// WriteTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
//
// NOTE: This function is exported in order to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}

// writeTxWitness encodes the bitcoin protocol encoding for a transaction
// input's witness into to w.
func writeTxWitness(w io.Writer, pver uint32, version int32, wit [][]byte) error {
	err := WriteVarInt(w, pver, uint64(len(wit)))
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = WriteVarBytes(w, pver, item)
		if err != nil {
			return err
		}
	}
	return nil
}

/// MWEB

type decoder struct {
	buf [8]byte
	rd  io.Reader
	tee *bytes.Buffer // anything read from rd is Written to tee
}

// decoders
func newDecoder(r io.Reader) *decoder {
	return &decoder{rd: r}
}

func (d *decoder) Read(b []byte) (n int, err error) {
	n, err = d.rd.Read(b)
	if err != nil {
		return 0, err
	}
	if d.tee != nil {
		d.tee.Write(b)
	}
	return n, nil
}

func (d *decoder) readByte() (byte, error) {
	b := d.buf[:1]
	if _, err := io.ReadFull(d, b); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *decoder) discardBytes(n int64) error {
	m, err := io.CopyN(io.Discard, d, n)
	if err != nil {
		return err
	}
	if m != n {
		return fmt.Errorf("only discarded %d of %d bytes", m, n)
	}
	return nil
}

func (d *decoder) discardVect() error {
	sz, err := ReadVarInt(d, 0)
	if err != nil {
		return err
	}
	return d.discardBytes(int64(sz))
}

func (d *decoder) readVLQ() (uint64, error) {
	var n uint64
	for {
		val, err := d.readByte()
		if err != nil {
			return 0, err
		}
		n = (n << 7) | uint64(val&0x7f)
		if val&0x80 != 0x80 {
			break
		}
		n++
	}

	return n, nil
}

// reader
func (d *decoder) readMWTX() ([]byte, bool, error) {
	// src/mweb/mweb_models.h - struct Tx
	// "A convenience wrapper around a possibly-null MWEB transaction."
	// Read the uint8_t is_set of OptionalPtr.
	haveMWTX, err := d.readByte()
	if err != nil {
		return nil, false, err
	}
	if haveMWTX == 0 {
		return nil, true, nil // HogEx - that's all folks
	}

	// src/libmw/include/mw/models/tx/Transaction.h - class Transaction
	// READWRITE(obj.m_kernelOffset); // class BlindingFactor
	// READWRITE(obj.m_stealthOffset); // class BlindingFactor
	// READWRITE(obj.m_body); // class TxBody

	// src/libmw/include/mw/models/crypto/BlindingFactor.h - class BlindingFactor
	// just 32 bytes:
	//  BigInt<32> m_value;
	//  READWRITE(obj.m_value);
	// x2 for both kernel_offset and stealth_offset BlindingFactor
	if err = d.discardBytes(64); err != nil {
		return nil, false, err
	}

	// TxBody
	kern0, err := d.readMWTXBody()
	if err != nil {
		return nil, false, err
	}
	return kern0, false, nil
}

func (d *decoder) readMWTXBody() ([]byte, error) {
	// src/libmw/include/mw/models/tx/TxBody.h - class TxBody
	//  READWRITE(obj.m_inputs, obj.m_outputs, obj.m_kernels);
	//  std::vector<Input> m_inputs;
	//  std::vector<Output> m_outputs;
	//  std::vector<Kernel> m_kernels;

	// inputs
	numIn, err := ReadVarInt(d, 0)
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(numIn); i++ {
		// src/libmw/include/mw/models/tx/Input.h - class Input
		// - features uint8_t
		// - outputID mw::Hash - 32 bytes BigInt<32>
		// - commit Commitment - 33 bytes BigInt<SIZE> for SIZE 33
		// - outputPubKey PublicKey - 33 bytes BigInt<33>
		// (if features includes STEALTH_KEY_FEATURE_BIT) input_pubkey PublicKey
		// (if features includes EXTRA_DATA_FEATURE_BIT) extraData vector<uint8_t>
		// - signature Signature - 64 bytes BigInt<SIZE> for SIZE 64
		//
		// enum FeatureBit {
		//     STEALTH_KEY_FEATURE_BIT = 0x01,
		//     EXTRA_DATA_FEATURE_BIT = 0x02
		// };
		feats, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if err = d.discardBytes(32 + 33 + 33); err != nil { // outputID, commitment, outputPubKey
			return nil, err
		}
		if feats&0x1 != 0 { // input pubkey
			if err = d.discardBytes(33); err != nil {
				return nil, err
			}
		}
		if feats&0x2 != 0 { // extraData
			if err = d.discardVect(); err != nil {
				return nil, err
			}
		}
		if err = d.discardBytes(64); err != nil { // sig
			return nil, err
		}
	}

	// outputs
	numOut, err := ReadVarInt(d, 0)
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(numOut); i++ {
		// src/libmw/include/mw/models/tx/Output.h - class Output
		// commit
		// sender pubkey
		// receiver pubkey
		// message OutputMessage --- fuuuuuuuu
		// proof RangeProof
		// signature
		if err = d.discardBytes(33 + 33 + 33); err != nil { // commitment, sender pk, receiver pk
			return nil, err
		}

		// OutputMessage
		feats, err := d.readByte()
		if err != nil {
			return nil, err
		}
		// enum FeatureBit {
		// 	STANDARD_FIELDS_FEATURE_BIT = 0x01,
		// 	EXTRA_DATA_FEATURE_BIT = 0x02
		// };
		if feats&0x1 != 0 { // pubkey | view_tag uint8_t | masked_value uint64_t | nonce 16-bytes
			if err = d.discardBytes(33 + 1 + 8 + 16); err != nil {
				return nil, err
			}
		}
		if feats&0x2 != 0 { // extraData
			if err = d.discardVect(); err != nil {
				return nil, err
			}
		}

		// RangeProof "The proof itself, at most 675 bytes long."
		// std::vector<uint8_t> m_bytes; -- except it's actually used like a [675]byte...
		if err = d.discardBytes(675 + 64); err != nil { // proof + sig
			return nil, err
		}
	}

	// kernels
	numKerns, err := ReadVarInt(d, 0)
	if err != nil {
		return nil, err
	}
	// Capture the first kernel since pure MW txns (no canonical inputs or
	// outputs) that live in the MWEB but are also seen in mempool have their
	// hash computed as blake3_256(kernel0).
	var kern0 []byte
	d.tee = new(bytes.Buffer)
	for i := 0; i < int(numKerns); i++ {
		// src/libmw/include/mw/models/tx/Kernel.h - class Kernel

		// enum FeatureBit {
		//     FEE_FEATURE_BIT = 0x01,
		//     PEGIN_FEATURE_BIT = 0x02,
		//     PEGOUT_FEATURE_BIT = 0x04,
		//     HEIGHT_LOCK_FEATURE_BIT = 0x08,
		//     STEALTH_EXCESS_FEATURE_BIT = 0x10,
		//     EXTRA_DATA_FEATURE_BIT = 0x20,
		//     ALL_FEATURE_BITS = FEE_FEATURE_BIT | PEGIN...
		// };
		feats, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if feats&0x1 != 0 { // fee
			_, err = d.readVLQ() // vlq for amount? in the wire protocol?!?
			if err != nil {
				return nil, err
			}
		}
		if feats&0x2 != 0 { // pegin amt
			_, err = d.readVLQ()
			if err != nil {
				return nil, err
			}
		}
		if feats&0x4 != 0 { // pegouts vector
			sz, err := ReadVarInt(d, 0)
			if err != nil {
				return nil, err
			}
			for i := uint64(0); i < sz; i++ {
				_, err = d.readVLQ() // pegout amt
				if err != nil {
					return nil, err
				}
				if err = d.discardVect(); err != nil { // pkScript
					return nil, err
				}
			}
		}
		if feats&0x8 != 0 { // lockHeight
			_, err = d.readVLQ()
			if err != nil {
				return nil, err
			}
		}
		if feats&0x10 != 0 { // stealth_excess pubkey
			if err = d.discardBytes(33); err != nil {
				return nil, err
			}
		}
		if feats&0x20 != 0 { // extraData vector
			if err = d.discardVect(); err != nil {
				return nil, err
			}
		}
		// "excess" commitment and signature
		if err = d.discardBytes(33 + 64); err != nil {
			return nil, err
		}

		if i == 0 {
			kern0 = d.tee.Bytes()
			d.tee = nil
		}
	}

	return kern0, nil
}
