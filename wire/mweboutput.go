package wire

import (
	"bytes"
	"io"
	"math/big"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/secp256k1"
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
		RangeProof     *secp256k1.RangeProof
		RangeProofHash chainhash.Hash
		Signature      mw.Signature

		hash *chainhash.Hash
	}
)

func (om *MwebOutputMessage) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	om.write(h, 0)
	return (*chainhash.Hash)(h.Sum(nil))
}

func (mo *MwebOutput) Hash() *chainhash.Hash {
	if mo.hash != nil {
		return mo.hash
	}
	h := blake3.New(32, nil)
	mo.write(h, 0, true, true)
	mo.hash = (*chainhash.Hash)(h.Sum(nil))
	return mo.hash
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

func (om *MwebOutputMessage) Serialize(w io.Writer) error {
	return om.write(w, 0)
}

func (om *MwebOutputMessage) Deserialize(r io.Reader) error {
	return om.read(r, 0)
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

	err = readElement(r, &mo.RangeProofHash)
	if err != nil {
		return err
	}

	if !compact {
		if bytes.Count(mo.RangeProofHash[:], []byte{0}) == 32 {
			err = readElement(r, &mo.RangeProofHash)
		} else {
			mo.RangeProof = &secp256k1.RangeProof{}
			copy(mo.RangeProof[:], mo.RangeProofHash[:])
			_, err = io.ReadFull(r, mo.RangeProof[32:])
			mo.RangeProofHash = blake3.Sum256(mo.RangeProof[:])
		}
		if err != nil {
			return err
		}
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
	} else if mo.RangeProof != nil {
		_, err = w.Write(mo.RangeProof[:])
	} else {
		if _, err = w.Write(make([]byte, 32)); err != nil {
			return err
		}
		err = writeElement(w, &mo.RangeProofHash)
	}
	if err != nil {
		return err
	}

	_, err = w.Write(mo.Signature[:])
	return err
}

func (mo *MwebOutput) Serialize(w io.Writer) error {
	return mo.write(w, 0, false, false)
}

func (mo *MwebOutput) Deserialize(r io.Reader) error {
	return mo.read(r, 0, false)
}

func (mo *MwebOutput) SerializeCompact(w io.Writer) error {
	return mo.write(w, 0, true, false)
}

func (mo *MwebOutput) DeserializeCompact(r io.Reader) error {
	return mo.read(r, 0, true)
}

func (mo *MwebOutput) VerifySig() bool {
	h := blake3.New(32, nil)
	h.Write(mo.Commitment[:])
	h.Write(mo.SenderPubKey[:])
	h.Write(mo.ReceiverPubKey[:])
	h.Write(mo.Message.Hash()[:])
	h.Write(mo.RangeProofHash[:])
	return mo.Signature.Verify(&mo.SenderPubKey, h.Sum(nil))
}
