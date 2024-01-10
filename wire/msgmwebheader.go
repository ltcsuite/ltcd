// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgMwebHeader implements the Message interface and represents a litecoin
// mwebheader message which is used for syncing MWEB headers.
//
// This message was not added until protocol version MwebLightClientVersion.
type MsgMwebHeader struct {
	Merkle     MsgMerkleBlock
	Hogex      MsgTx
	MwebHeader MwebHeader
}

// BtcDecode decodes r using the litecoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMwebHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebheader message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebHeader.BtcDecode", str)
	}

	err := msg.Merkle.BtcDecode(r, pver, enc)
	if err != nil {
		return err
	}

	err = msg.Hogex.BtcDecode(r, pver, enc)
	if err != nil {
		return err
	}

	return msg.MwebHeader.read(r)
}

// BtcEncode encodes the receiver to w using the litecoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMwebHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < MwebLightClientVersion {
		str := fmt.Sprintf("mwebheader message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMwebHeader.BtcEncode", str)
	}

	err := msg.Merkle.BtcEncode(w, pver, enc)
	if err != nil {
		return err
	}

	err = msg.Hogex.BtcEncode(w, pver, enc)
	if err != nil {
		return err
	}

	return msg.MwebHeader.write(w)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMwebHeader) Command() string {
	return CmdMwebHeader
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMwebHeader) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgMwebHeader returns a new litecoin mwebheader message that conforms to
// the Message interface.  See MsgMwebHeader for details.
func NewMsgMwebHeader(mb *MsgMerkleBlock, hogex *MsgTx, mh *MwebHeader) *MsgMwebHeader {
	return &MsgMwebHeader{
		Merkle:     *mb,
		Hogex:      *hogex,
		MwebHeader: *mh,
	}
}
