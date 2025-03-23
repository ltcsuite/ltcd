package psbt

import (
	"bytes"
	"encoding/binary"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"io"
)

// PKernel is a struct encapsulating all the data that can be attached to any
// specific kernel of the PSBT.
type PKernel struct {
	ExcessCommitment *mw.Commitment
	StealthExcess    *mw.PublicKey
	Fee              *ltcutil.Amount
	PeginAmount      *ltcutil.Amount
	PegOuts          []*wire.TxOut
	LockHeight       *int32
	ExtraData        []byte
	Signature        *mw.Signature
	Unknowns         []*Unknown
}

func (pk *PKernel) isFinalized() bool {
	if pk.Signature == nil {
		return false
	}

	// TODO: Do we need to check that all required fields exist?

	return true
}

func (pk *PKernel) isSane() bool {
	if pk.Signature != nil {
		if pk.ExcessCommitment == nil {
			return false
		}
	}

	return true
}

// deserialize attempts to deserialize a new PKernel from the passed io.Reader.
func (pk *PKernel) deserialize(r io.Reader) error {
	kernelKeys := newKeySet()
	for {
		kvPair, err := getKVPair(r)
		if err != nil {
			return err
		}

		// If this is separator byte (nil kvPair), this section is done.
		if kvPair == nil {
			break
		}

		// According to BIP-0174, <key> := <keylen><keytype><keydata> must be unique per map
		if !kernelKeys.addKey(kvPair.keyType, kvPair.keyData) {
			return ErrDuplicateKey
		}

		switch KernelType(kvPair.keyType) {
		case MwebKernelExcessCommitType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pk.ExcessCommitment = mw.ReadCommitment(kvPair.valueData)
			if pk.ExcessCommitment == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebKernelStealthCommitType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pk.StealthExcess = mw.ReadPublicKey(kvPair.valueData)
			if pk.StealthExcess == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebKernelFeeType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 8 {
				return ErrInvalidPsbtFormat
			}

			fee := ltcutil.Amount(binary.LittleEndian.Uint64(kvPair.valueData))
			pk.Fee = &fee
		case MwebKernelPeginAmountType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 8 {
				return ErrInvalidPsbtFormat
			}

			peginAmount := ltcutil.Amount(binary.LittleEndian.Uint64(kvPair.valueData))
			pk.PeginAmount = &peginAmount
		case MwebKernelPegoutType:
			pegout := new(wire.TxOut)
			err := wire.ReadTxOut(bytes.NewReader(kvPair.valueData), 0, 0, pegout)
			if err != nil {
				return err
			}
			pk.PegOuts = append(pk.PegOuts, pegout)
		case MwebKernelLockHeightType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 4 {
				return ErrInvalidPsbtFormat
			}

			pk.LockHeight = int32Ptr(int32(binary.LittleEndian.Uint32(kvPair.valueData)))
		case MwebKernelExtraDataType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pk.ExtraData = kvPair.valueData
		case MwebKernelSignatureType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pk.Signature = mw.ReadSignature(kvPair.valueData)
			if pk.Signature == nil {
				return ErrInvalidPsbtFormat
			}
		default:
			// A fall through case for any proprietary types.
			keyCodeAndData := append(
				[]byte{kvPair.keyType}, kvPair.keyData...,
			)
			newUnknown := &Unknown{
				Key:   keyCodeAndData,
				Value: kvPair.valueData,
			}

			pk.Unknowns = append(pk.Unknowns, newUnknown)
		}
	}

	return nil
}

// serialize attempts to write out the target PKernel into the passed
// io.Writer.
func (pk *PKernel) serialize(w io.Writer) error {
	if pk.ExcessCommitment != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelExcessCommitType), nil, pk.ExcessCommitment[:],
		)
		if err != nil {
			return err
		}
	}
	if pk.StealthExcess != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelStealthCommitType), nil, pk.StealthExcess[:],
		)
		if err != nil {
			return err
		}
	}
	if pk.Fee != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelFeeType), nil, binary.LittleEndian.AppendUint64(nil, uint64(*pk.Fee)),
		)
		if err != nil {
			return err
		}
	}
	if pk.PeginAmount != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelPeginAmountType), nil, binary.LittleEndian.AppendUint64(nil, uint64(*pk.PeginAmount)),
		)
		if err != nil {
			return err
		}
	}
	for i, pegout := range pk.PegOuts {
		var keydata bytes.Buffer
		err := wire.WriteVarInt(&keydata, 0, uint64(i))
		if err != nil {
			return err
		}
		var valueData bytes.Buffer
		_, err = valueData.Write(binary.LittleEndian.AppendUint64(nil, uint64(pegout.Value)))
		if err != nil {
			return err
		}
		err = wire.WriteVarBytes(&valueData, 0, pegout.PkScript)
		if err != nil {
			return err
		}

		err = serializeKVPairWithType(
			w, uint8(MwebKernelPegoutType), keydata.Bytes(), valueData.Bytes(),
		)
		if err != nil {
			return err
		}
	}

	if pk.LockHeight != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelLockHeightType), nil, binary.LittleEndian.AppendUint32(nil, uint32(*pk.LockHeight)),
		)
		if err != nil {
			return err
		}
	}

	if pk.ExtraData != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelExtraDataType), nil, pk.ExtraData,
		)
		if err != nil {
			return err
		}
	}

	if pk.Signature != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelSignatureType), nil, pk.Signature[:],
		)
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field
	for _, kv := range pk.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	separator := []byte{0x00}
	if _, err := w.Write(separator); err != nil {
		return err
	}

	return nil
}
