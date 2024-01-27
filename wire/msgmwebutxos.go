// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
)

const MaxMwebUtxosPerQuery = 4096

type MwebNetUtxo struct {
	LeafIndex uint64
	Output    *MwebOutput
	OutputId  *chainhash.Hash
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
	if count > MaxMwebUtxosPerQuery {
		return errors.New("count exceeds MaxMwebUtxosPerQuery")
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
	if count > 1e5 {
		return errors.New("too many proof hashes")
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
func NewMsgMwebUtxos(blockHash chainhash.Hash, startIndex uint64,
	outputFormat MwebNetUtxoType) *MsgMwebUtxos {

	return &MsgMwebUtxos{
		BlockHash:    blockHash,
		StartIndex:   startIndex,
		OutputFormat: outputFormat,
	}
}
