// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
)

// MsgMwebLeafset implements the Message interface and represents a litecoin
// mwebleafset message which is used for retrieving the leaf indices of all
// unspent MWEB UTXOs.
//
// This message was not added until protocol version MwebLightClientVersion.
type MsgMwebLeafset struct {
	BlockHash chainhash.Hash
	Leafset   []byte
}

// BtcDecode decodes r using the litecoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMwebLeafset) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebleafset message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebLeafset.BtcDecode", str)
	}

	err := readElement(r, &msg.BlockHash)
	if err != nil {
		return err
	}

	msg.Leafset, err = ReadVarBytes(r, pver, MaxMessagePayload, "Leafset")
	return err
}

// BtcEncode encodes the receiver to w using the litecoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMwebLeafset) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebleafset message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebLeafset.BtcEncode", str)
	}

	err := writeElement(w, &msg.BlockHash)
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, msg.Leafset)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMwebLeafset) Command() string {
	return CmdMwebLeafset
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMwebLeafset) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgMwebLeafset returns a new litecoin mwebleafset message that conforms to
// the Message interface.  See MsgMwebLeafset for details.
func NewMsgMwebLeafset(blockHash *chainhash.Hash, leafset []byte) *MsgMwebLeafset {
	return &MsgMwebLeafset{
		BlockHash: *blockHash,
		Leafset:   leafset,
	}
}
