// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"lukechampine.com/blake3"
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

// the Litecoin-internal VarInt encoding
func writeVarInt(w io.Writer, n uint64) error {
	var buf [10]byte
	i := 0
	for ; ; i++ {
		buf[i] = byte(n & 0x7f)
		if i > 0 {
			buf[i] |= 0x80
		}
		if n < 0x80 {
			break
		}
		n = (n >> 7) - 1
	}
	for ; i >= 0; i-- {
		if _, err := w.Write(buf[i : i+1]); err != nil {
			return err
		}
	}
	return nil
}

func (mh *MwebHeader) Hash() chainhash.Hash {
	var buf bytes.Buffer
	writeVarInt(&buf, uint64(mh.Height))
	writeElements(&buf, &mh.OutputRoot, &mh.KernelRoot,
		&mh.LeafsetRoot, &mh.KernelOffset, &mh.StealthOffset)
	writeVarInt(&buf, mh.OutputMMRSize)
	writeVarInt(&buf, mh.KernelMMRSize)
	return blake3.Sum256(buf.Bytes())
}

// Reads a litecoin mweb header from r.  See Deserialize for
// decoding mweb headers stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (mh *MwebHeader) read(r io.Reader, pver uint32) error {
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

// Writes a litecoin mweb header to w.  See Serialize for
// encoding mweb headers to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (mh *MwebHeader) write(w io.Writer, pver uint32) error {
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

	return msg.MwebHeader.read(r, pver)
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

	return msg.MwebHeader.write(w, pver)
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
