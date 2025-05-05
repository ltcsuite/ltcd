package wire

import (
	"errors"
	"io"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"lukechampine.com/blake3"
)

const (
	MwebKernelFeeFeatureBit MwebKernelFeatureBit = 1 << iota
	MwebKernelPeginFeatureBit
	MwebKernelPegoutFeatureBit
	MwebKernelHeightLockFeatureBit
	MwebKernelStealthExcessFeatureBit
	MwebKernelExtraDataFeatureBit

	MwebKernelAllFeatureBits = MwebKernelFeeFeatureBit |
		MwebKernelPeginFeatureBit | MwebKernelPegoutFeatureBit |
		MwebKernelHeightLockFeatureBit | MwebKernelStealthExcessFeatureBit |
		MwebKernelExtraDataFeatureBit
)

type (
	MwebKernelFeatureBit byte

	MwebKernel struct {
		Features      MwebKernelFeatureBit
		Fee           uint64
		Pegin         uint64
		Pegouts       []*TxOut
		LockHeight    int32
		StealthExcess mw.PublicKey
		ExtraData     []byte
		Excess        mw.Commitment
		Signature     mw.Signature
	}
)

func (mk *MwebKernel) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	mk.write(h, 0, false)
	return (*chainhash.Hash)(h.Sum(nil))
}

func (mk *MwebKernel) MessageHash() *chainhash.Hash {
	h := blake3.New(32, nil)
	mk.write(h, 0, true)
	return (*chainhash.Hash)(h.Sum(nil))
}

// Reads a litecoin mweb kernel from r.  See Deserialize for
// decoding mweb kernels stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (mk *MwebKernel) read(r io.Reader, pver uint32) error {
	err := readElement(r, &mk.Features)
	if err != nil {
		return err
	}

	if mk.Features&MwebKernelFeeFeatureBit > 0 {
		if mk.Fee, err = readVarInt(r); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelPeginFeatureBit > 0 {
		if mk.Pegin, err = readVarInt(r); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelPegoutFeatureBit > 0 {
		var count uint64
		if count, err = ReadVarInt(r, pver); err != nil {
			return err
		}
		if count > maxTxOutPerMessage {
			return errors.New("too many pegouts")
		}
		mk.Pegouts = make([]*TxOut, count)
		for i := range mk.Pegouts {
			mk.Pegouts[i] = &TxOut{}
			if value, err := readVarInt(r); err == nil {
				mk.Pegouts[i].Value = int64(value)
			} else {
				return err
			}
			mk.Pegouts[i].PkScript, err = readScript(r, pver,
				MaxMessagePayload, "public key script")
			if err != nil {
				return err
			}
		}
	}

	if mk.Features&MwebKernelHeightLockFeatureBit > 0 {
		var lockHeight uint64
		if lockHeight, err = readVarInt(r); err != nil {
			return err
		}
		mk.LockHeight = int32(lockHeight)
	}

	if mk.Features&MwebKernelStealthExcessFeatureBit > 0 {
		if _, err = io.ReadFull(r, mk.StealthExcess[:]); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelExtraDataFeatureBit > 0 {
		mk.ExtraData, err = ReadVarBytes(r, pver, MaxMessagePayload, "ExtraData")
		if err != nil {
			return err
		}
	}

	return readElements(r, mk.Excess[:], mk.Signature[:])
}

// Writes a litecoin mweb kernel to w.  See Serialize for
// encoding mweb kernels to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (mk *MwebKernel) write(w io.Writer, pver uint32, message bool) error {
	err := writeElements(w, mk.Features)
	if err != nil {
		return err
	}

	if message {
		if _, err = w.Write(mk.Excess[:]); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelFeeFeatureBit > 0 {
		if err = writeVarInt(w, mk.Fee); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelPeginFeatureBit > 0 {
		if err = writeVarInt(w, mk.Pegin); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelPegoutFeatureBit > 0 {
		if err = WriteVarInt(w, pver, uint64(len(mk.Pegouts))); err != nil {
			return err
		}
		for _, out := range mk.Pegouts {
			if err = writeVarInt(w, uint64(out.Value)); err != nil {
				return err
			}
			if err = WriteVarBytes(w, pver, out.PkScript); err != nil {
				return err
			}
		}
	}

	if mk.Features&MwebKernelHeightLockFeatureBit > 0 {
		if err = writeVarInt(w, uint64(mk.LockHeight)); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelStealthExcessFeatureBit > 0 {
		if _, err = w.Write(mk.StealthExcess[:]); err != nil {
			return err
		}
	}

	if mk.Features&MwebKernelExtraDataFeatureBit > 0 {
		if err = WriteVarBytes(w, pver, mk.ExtraData); err != nil {
			return err
		}
	}

	if message {
		return nil
	}

	return writeElements(w, mk.Excess[:], mk.Signature[:])
}
