// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
)

type MwebHeader struct {
	Height        int32
	OutputRoot    chainhash.Hash
	KernelRoot    chainhash.Hash
	LeafsetRoot   chainhash.Hash
	KernelOffset  chainhash.Hash
	StealthOffset chainhash.Hash
	OutputMMRSize uint64
	KernelMMRSize uint64
}

// readMwebHeader reads a litecoin mweb header from r.  See Deserialize for
// decoding mweb headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readMwebHeader(r io.Reader, pver uint32, mh *MwebHeader) error {
	err := readElements(r, &mh.Height, &mh.OutputRoot, &mh.KernelRoot,
		&mh.LeafsetRoot, &mh.KernelOffset, &mh.StealthOffset)
	if err != nil {
		return err
	}

	mh.OutputMMRSize, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	mh.KernelMMRSize, err = ReadVarInt(r, pver)
	return err
}

// writeMwebHeader writes a litecoin mweb header to w.  See Serialize for
// encoding mweb headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeMwebHeader(w io.Writer, pver uint32, mh *MwebHeader) error {
	err := writeElements(w, mh.Height, &mh.OutputRoot, &mh.KernelRoot,
		&mh.LeafsetRoot, &mh.KernelOffset, &mh.StealthOffset)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, mh.OutputMMRSize)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, mh.KernelMMRSize)
	return err
}

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

	return readMwebHeader(r, pver, &msg.MwebHeader)
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

	return writeMwebHeader(w, pver, &msg.MwebHeader)
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
