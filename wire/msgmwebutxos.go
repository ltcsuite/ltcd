// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"lukechampine.com/blake3"
)

const (
	MwebOutputMessageStandardFieldsFeatureBit MwebOutputMessageFeatureBit = 0x1
	MwebOutputMessageExtraDataFeatureBit      MwebOutputMessageFeatureBit = 0x2
)

type (
	MwebCommitment [33]byte
	MwebPubKey     [33]byte
	MwebSignature  [64]byte

	MwebOutputMessageFeatureBit byte

	MwebOutputMessage struct {
		Features          MwebOutputMessageFeatureBit
		KeyExchangePubKey MwebPubKey
		ViewTag           byte
		MaskedValue       uint64
		MaskedNonce       [16]byte
		ExtraData         []byte
	}

	MwebOutput struct {
		Commitment     MwebCommitment
		SenderPubKey   MwebPubKey
		ReceiverPubKey MwebPubKey
		Message        MwebOutputMessage
		RangeProof     [675]byte
		RangeProofHash chainhash.Hash
		Signature      MwebSignature
	}

	MwebNetUtxo struct {
		LeafIndex uint64
		Output    *MwebOutput
		OutputId  chainhash.Hash
	}
)

func (om *MwebOutputMessage) Hash() (hash chainhash.Hash) {
	h := blake3.New(32, nil)
	om.write(h, 0)
	h.Sum(hash[:0])
	return
}

func (mo *MwebOutput) Hash() (hash chainhash.Hash) {
	h := blake3.New(32, nil)
	mo.write(h, 0, true, true)
	h.Sum(hash[:0])
	return
}

// Reads a litecoin mweb output message from r.  See Deserialize for
// decoding mweb output messages stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (om *MwebOutputMessage) read(r io.Reader, pver uint32) error {
	err := readElement(r, &om.Features)
	if err != nil {
		return err
	}

	if om.Features&MwebOutputMessageStandardFieldsFeatureBit > 0 {
		if _, err = io.ReadFull(r, om.KeyExchangePubKey[:]); err != nil {
			return err
		}
		if err = readElements(r, &om.ViewTag, &om.MaskedValue); err != nil {
			return err
		}
		if _, err = io.ReadFull(r, om.MaskedNonce[:]); err != nil {
			return err
		}
	}

	if om.Features&MwebOutputMessageExtraDataFeatureBit > 0 {
		om.ExtraData, err = ReadVarBytes(r, pver, MaxMessagePayload, "ExtraData")
		if err != nil {
			return err
		}
	}

	return err
}

// Writes a litecoin mweb output message to w.  See Serialize for
// encoding mweb output messages to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (om *MwebOutputMessage) write(w io.Writer, pver uint32) error {
	err := writeElement(w, om.Features)
	if err != nil {
		return err
	}

	if om.Features&MwebOutputMessageStandardFieldsFeatureBit > 0 {
		if _, err = w.Write(om.KeyExchangePubKey[:]); err != nil {
			return err
		}
		if err = writeElements(w, om.ViewTag, om.MaskedValue); err != nil {
			return err
		}
		if _, err = w.Write(om.MaskedNonce[:]); err != nil {
			return err
		}
	}

	if om.Features&MwebOutputMessageExtraDataFeatureBit > 0 {
		if err = WriteVarBytes(w, pver, om.ExtraData); err != nil {
			return err
		}
	}

	return err
}

// Reads a litecoin mweb output from r.  See Deserialize for
// decoding mweb outputs stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (mo *MwebOutput) read(r io.Reader, pver uint32, compact bool) error {
	_, err := io.ReadFull(r, mo.Commitment[:])
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, mo.SenderPubKey[:])
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, mo.ReceiverPubKey[:])
	if err != nil {
		return err
	}

	err = mo.Message.read(r, pver)
	if err != nil {
		return err
	}

	if !compact {
		if _, err = io.ReadFull(r, mo.RangeProof[:]); err != nil {
			return err
		}
		mo.RangeProofHash = blake3.Sum256(mo.RangeProof[:])
	} else if err = readElement(r, &mo.RangeProofHash); err != nil {
		return err
	}

	_, err = io.ReadFull(r, mo.Signature[:])
	return err
}

// Writes a litecoin mweb output to w.  See Serialize for
// encoding mweb outputs to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (mo *MwebOutput) write(w io.Writer, pver uint32, compact, hashing bool) error {
	_, err := w.Write(mo.Commitment[:])
	if err != nil {
		return err
	}

	_, err = w.Write(mo.SenderPubKey[:])
	if err != nil {
		return err
	}

	_, err = w.Write(mo.ReceiverPubKey[:])
	if err != nil {
		return err
	}

	if hashing {
		h := mo.Message.Hash()
		_, err = w.Write(h[:])
	} else {
		err = mo.Message.write(w, pver)
	}
	if err != nil {
		return err
	}

	if compact || hashing {
		err = writeElement(w, &mo.RangeProofHash)
	} else {
		_, err = w.Write(mo.RangeProof[:])
	}
	if err != nil {
		return err
	}

	_, err = w.Write(mo.Signature[:])
	return err
}

func (mo *MwebOutput) Serialize(w io.Writer) error {
	return mo.write(w, 0, true, false)
}

func (mo *MwebOutput) Deserialize(r io.Reader) error {
	return mo.read(r, 0, true)
}

// readMwebNetUtxo reads a litecoin mweb utxo from r.  See Deserialize for
// decoding mweb utxos stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readMwebNetUtxo(r io.Reader, pver uint32, utxo *MwebNetUtxo,
	utxoType MwebNetUtxoType) (err error) {

	utxo.LeafIndex, err = ReadVarInt(r, pver)
	if err != nil {
		return
	}

	switch utxoType {
	case MwebNetUtxoFull:
		utxo.Output = new(MwebOutput)
		err = utxo.Output.read(r, pver, false)
	case MwebNetUtxoHashOnly:
		err = readElement(r, &utxo.OutputId)
	case MwebNetUtxoCompact:
		utxo.Output = new(MwebOutput)
		err = utxo.Output.read(r, pver, true)
	}
	if err != nil {
		return
	}

	if utxo.Output != nil {
		utxo.OutputId = utxo.Output.Hash()
	}

	return
}

// writeMwebNetUtxo writes a litecoin mweb utxo to w.  See Serialize for
// encoding mweb utxos to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeMwebNetUtxo(w io.Writer, pver uint32, utxo *MwebNetUtxo,
	utxoType MwebNetUtxoType) error {

	err := WriteVarInt(w, pver, utxo.LeafIndex)
	if err != nil {
		return err
	}

	if utxo.Output != nil {
		utxo.OutputId = utxo.Output.Hash()
	}

	switch utxoType {
	case MwebNetUtxoFull:
		err = utxo.Output.write(w, pver, false, false)
	case MwebNetUtxoHashOnly:
		err = writeElement(w, &utxo.OutputId)
	case MwebNetUtxoCompact:
		err = utxo.Output.write(w, pver, true, false)
	}

	return err
}

// MsgMwebUtxos implements the Message interface and represents a litecoin
// mwebutxos message which is used to send a batch of MWEB UTXOs.
//
// This message was not added until protocol version MwebLightClientVersion.
type MsgMwebUtxos struct {
	BlockHash    chainhash.Hash
	StartIndex   uint64
	OutputFormat MwebNetUtxoType
	Utxos        []*MwebNetUtxo
	ProofHashes  []*chainhash.Hash
}

// BtcDecode decodes r using the litecoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMwebUtxos) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebutxos message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebUtxos.BtcDecode", str)
	}

	err := readElement(r, &msg.BlockHash)
	if err != nil {
		return err
	}

	msg.StartIndex, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.OutputFormat)
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.Utxos = make([]*MwebNetUtxo, count)

	for i := range msg.Utxos {
		utxo := new(MwebNetUtxo)
		if err = readMwebNetUtxo(r, pver, utxo, msg.OutputFormat); err != nil {
			return err
		}
		msg.Utxos[i] = utxo
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.ProofHashes = make([]*chainhash.Hash, count)

	for i := range msg.ProofHashes {
		hash := new(chainhash.Hash)
		if err = readElement(r, hash); err != nil {
			return err
		}
		msg.ProofHashes[i] = hash
	}

	return err
}

// BtcEncode encodes the receiver to w using the litecoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMwebUtxos) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebutxos message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebUtxos.BtcEncode", str)
	}

	err := writeElement(w, &msg.BlockHash)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, msg.StartIndex)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.OutputFormat)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Utxos)))
	if err != nil {
		return err
	}

	for _, utxo := range msg.Utxos {
		if err = writeMwebNetUtxo(w, pver, utxo, msg.OutputFormat); err != nil {
			return err
		}
	}

	err = WriteVarInt(w, pver, uint64(len(msg.ProofHashes)))
	if err != nil {
		return err
	}

	for _, hash := range msg.ProofHashes {
		if err = writeElement(w, hash); err != nil {
			return err
		}
	}

	return err
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMwebUtxos) Command() string {
	return CmdMwebUtxos
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMwebUtxos) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgMwebUtxos returns a new litecoin mwebutxos message that conforms to
// the Message interface.  See MsgMwebUtxos for details.
func NewMsgMwebUtxos(blockHash *chainhash.Hash, startIndex uint64,
	outputFormat MwebNetUtxoType) *MsgMwebUtxos {

	return &MsgMwebUtxos{
		BlockHash:    *blockHash,
		StartIndex:   startIndex,
		OutputFormat: outputFormat,
	}
}
