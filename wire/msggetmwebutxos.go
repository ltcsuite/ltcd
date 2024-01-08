// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
)

type MwebNetUtxoType byte

const (
	MwebNetUtxoFull MwebNetUtxoType = iota
	MwebNetUtxoHashOnly
	MwebNetUtxoCompact
)

// MsgGetMwebUtxos implements the Message interface and represents a litecoin
// getmwebutxos message which is used to request a batch of MWEB UTXOs.
//
// This message was not added until protocol version MwebLightClientVersion.
type MsgGetMwebUtxos struct {
	BlockHash    chainhash.Hash
	StartIndex   uint64
	NumRequested uint16
	OutputFormat MwebNetUtxoType
}

// BtcDecode decodes r using the litecoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetMwebUtxos) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("getmwebutxos message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgGetMwebUtxos.BtcDecode", str)
	}

	err := readElement(r, &msg.BlockHash)
	if err != nil {
		return err
	}

	msg.StartIndex, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	return readElements(r, &msg.NumRequested, &msg.OutputFormat)
}

// BtcEncode encodes the receiver to w using the litecoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetMwebUtxos) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("getmwebutxos message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgGetMwebUtxos.BtcEncode", str)
	}

	err := writeElement(w, &msg.BlockHash)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, msg.StartIndex)
	if err != nil {
		return err
	}

	return writeElements(w, msg.NumRequested, msg.OutputFormat)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetMwebUtxos) Command() string {
	return CmdGetMwebUtxos
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetMwebUtxos) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgGetMwebUtxos returns a new litecoin getmwebutxos message that conforms to
// the Message interface.  See MsgGetMwebUtxos for details.
func NewMsgGetMwebUtxos(blockHash *chainhash.Hash, startIndex uint64, numRequested uint16, outputFormat MwebNetUtxoType) *MsgGetMwebUtxos {
	return &MsgGetMwebUtxos{
		BlockHash:    *blockHash,
		StartIndex:   startIndex,
		NumRequested: numRequested,
		OutputFormat: outputFormat,
	}
}
