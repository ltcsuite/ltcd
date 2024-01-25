package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"lukechampine.com/blake3"
)

const (
	MwebOutputMessageStandardFieldsFeatureBit MwebOutputMessageFeatureBit = 0x1
	MwebOutputMessageExtraDataFeatureBit      MwebOutputMessageFeatureBit = 0x2
)

type (
	MwebOutputMessageFeatureBit byte

	MwebOutputMessage struct {
		Features          MwebOutputMessageFeatureBit
		KeyExchangePubKey mw.PublicKey
		ViewTag           byte
		MaskedValue       uint64
		MaskedNonce       big.Int
		ExtraData         []byte
	}

	MwebOutput struct {
		Commitment     mw.Commitment
		SenderPubKey   mw.PublicKey
		ReceiverPubKey mw.PublicKey
		Message        MwebOutputMessage
		RangeProof     mw.RangeProof
		RangeProofHash chainhash.Hash
		Signature      mw.Signature
	}
)

func (om *MwebOutputMessage) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	om.write(h, 0)
	return (*chainhash.Hash)(h.Sum(nil))
}

func (mo *MwebOutput) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	mo.write(h, 0, true, true)
	return (*chainhash.Hash)(h.Sum(nil))
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
		var maskedNonce [16]byte
		if _, err = io.ReadFull(r, maskedNonce[:]); err != nil {
			return err
		}
		om.MaskedNonce.SetBytes(maskedNonce[:])
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
		var maskedNonce [16]byte
		om.MaskedNonce.FillBytes(maskedNonce[:])
		if _, err = w.Write(maskedNonce[:]); err != nil {
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
	compact := bytes.Count(mo.RangeProof[:], []byte{0}) == len(mo.RangeProof)
	if err := binary.Write(w, binary.LittleEndian, compact); err != nil {
		return err
	}
	return mo.write(w, 0, compact, false)
}

func (mo *MwebOutput) Deserialize(r io.Reader) error {
	var compact bool
	if err := binary.Read(r, binary.LittleEndian, &compact); err != nil {
		return err
	}
	return mo.read(r, 0, compact)
}
