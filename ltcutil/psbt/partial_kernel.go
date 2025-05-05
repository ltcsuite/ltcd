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
	Features         *wire.MwebKernelFeatureBit
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

// isFinalized returns true if the kernel has a signature.
// If the PKernel isFinalized and isSane, a completed wire.MwebKernel should be extractable.
func (pk *PKernel) isFinalized() bool {
	return pk.Signature != nil
}

// isSane performs validation based on the kernel's feature bits and returns true if all required fields are present.
func (pk *PKernel) isSane() bool {
	if pk.Signature != nil {
		if pk.Features == nil || pk.ExcessCommitment == nil {
			return false
		}

		if *pk.Features&wire.MwebKernelFeeFeatureBit > 0 && pk.Fee == nil {
			return false
		}

		if *pk.Features&wire.MwebKernelPeginFeatureBit > 0 && pk.PeginAmount == nil {
			return false
		}

		if *pk.Features&wire.MwebKernelPegoutFeatureBit > 0 && len(pk.PegOuts) == 0 {
			return false
		}

		if *pk.Features&wire.MwebKernelHeightLockFeatureBit > 0 && pk.LockHeight == nil {
			return false
		}

		if *pk.Features&wire.MwebKernelStealthExcessFeatureBit > 0 && pk.StealthExcess == nil {
			return false
		}

		if *pk.Features&wire.MwebKernelExtraDataFeatureBit > 0 && len(pk.ExtraData) == 0 {
			return false
		}
	}

	return true
}

// deserialize attempts to deserialize the PKernel from the provided reader.
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

			pk.StealthExcess, err = mw.ReadPublicKey(kvPair.valueData)
			if err != nil {
				return err
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

			lockHeight := int32(binary.LittleEndian.Uint32(kvPair.valueData))
			pk.LockHeight = &lockHeight
		case MwebKernelFeaturesType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 1 {
				return ErrInvalidPsbtFormat
			}

			features := wire.MwebKernelFeatureBit(kvPair.valueData[0])
			pk.Features = &features
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

// serialize writes the PKernel to the provided writer in PSBT key-value format.
func (pk *PKernel) serialize(w io.Writer) error {
	// Kernel Excess
	if pk.ExcessCommitment != nil {
		err := serializeKVPairWithType(w, uint8(MwebKernelExcessCommitType), nil, pk.ExcessCommitment[:])
		if err != nil {
			return err
		}
	}

	// Stealth Excess
	if pk.StealthExcess != nil {
		err := serializeKVPairWithType(w, uint8(MwebKernelStealthCommitType), nil, pk.StealthExcess[:])
		if err != nil {
			return err
		}
	}

	// Kernel Fee
	if pk.Fee != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelFeeType), nil, binary.LittleEndian.AppendUint64(nil, uint64(*pk.Fee)),
		)
		if err != nil {
			return err
		}
	}

	// Peg-ins
	if pk.PeginAmount != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelPeginAmountType), nil,
			binary.LittleEndian.AppendUint64(nil, uint64(*pk.PeginAmount)),
		)
		if err != nil {
			return err
		}
	}

	// Peg-outs
	if pk.PegOuts != nil {
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

			err = serializeKVPairWithType(w, uint8(MwebKernelPegoutType), keydata.Bytes(), valueData.Bytes())
			if err != nil {
				return err
			}
		}
	}

	// Lock Height
	if pk.LockHeight != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebKernelLockHeightType), nil, binary.LittleEndian.AppendUint32(nil, uint32(*pk.LockHeight)),
		)
		if err != nil {
			return err
		}
	}

	// Kernel Features
	if pk.Features != nil {
		err := serializeKVPairWithType(w, uint8(MwebKernelFeaturesType), nil, []byte{byte(*pk.Features)})
		if err != nil {
			return err
		}
	}

	// Extradata
	if len(pk.ExtraData) > 0 {
		err := serializeKVPairWithType(w, uint8(MwebKernelExtraDataType), nil, pk.ExtraData)
		if err != nil {
			return err
		}
	}

	// Signature
	if pk.Signature != nil {
		err := serializeKVPairWithType(w, uint8(MwebKernelSignatureType), nil, pk.Signature[:])
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and a value field
	for _, kv := range pk.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	// Write separator byte
	if _, err := w.Write([]byte{0x00}); err != nil {
		return err
	}

	return nil
}
