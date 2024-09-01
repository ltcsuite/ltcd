package wire

import (
	"io"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"lukechampine.com/blake3"
)

const (
	MwebInputStealthKeyFeatureBit MwebInputFeatureBit = 0x1
	MwebInputExtraDataFeatureBit  MwebInputFeatureBit = 0x2
)

type (
	MwebInputFeatureBit byte

	MwebInput struct {
		Features     MwebInputFeatureBit
		OutputId     chainhash.Hash
		Commitment   mw.Commitment
		InputPubKey  *mw.PublicKey
		OutputPubKey mw.PublicKey
		ExtraData    []byte
		Signature    mw.Signature
	}
)

func (mi *MwebInput) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	mi.write(h, 0)
	return (*chainhash.Hash)(h.Sum(nil))
}

// Reads a litecoin mweb input from r.  See Deserialize for
// decoding mweb inputs stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (mi *MwebInput) read(r io.Reader, pver uint32) error {
	err := readElements(r, &mi.Features, &mi.OutputId,
		mi.Commitment[:], mi.OutputPubKey[:])
	if err != nil {
		return err
	}

	if mi.Features&MwebInputStealthKeyFeatureBit > 0 {
		mi.InputPubKey = new(mw.PublicKey)
		if _, err = io.ReadFull(r, mi.InputPubKey[:]); err != nil {
			return err
		}
	}

	if mi.Features&MwebInputExtraDataFeatureBit > 0 {
		mi.ExtraData, err = ReadVarBytes(r, pver, MaxMessagePayload, "ExtraData")
		if err != nil {
			return err
		}
	}

	_, err = io.ReadFull(r, mi.Signature[:])
	return err
}

// Writes a litecoin mweb input to w.  See Serialize for
// encoding mweb inputs to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (mi *MwebInput) write(w io.Writer, pver uint32) error {
	err := writeElements(w, mi.Features, &mi.OutputId,
		mi.Commitment[:], mi.OutputPubKey[:])
	if err != nil {
		return err
	}

	if mi.Features&MwebInputStealthKeyFeatureBit > 0 {
		if _, err = w.Write(mi.InputPubKey[:]); err != nil {
			return err
		}
	}

	if mi.Features&MwebInputExtraDataFeatureBit > 0 {
		if err = WriteVarBytes(w, pver, mi.ExtraData); err != nil {
			return err
		}
	}

	_, err = w.Write(mi.Signature[:])
	return err
}

func (mi *MwebInput) VerifySig() bool {
	h := blake3.New(32, nil)
	h.Write(mi.InputPubKey[:])
	h.Write(mi.OutputPubKey[:])
	keyHash := (*mw.SecretKey)(h.Sum(nil))
	pubKey := mi.OutputPubKey.Mul(keyHash).Add(mi.InputPubKey)

	h.Reset()
	h.Write([]byte{byte(mi.Features)})
	h.Write(mi.OutputId[:])
	return mi.Signature.Verify(pubKey, h.Sum(nil))
}
