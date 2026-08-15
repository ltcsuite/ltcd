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

// isFinalized returns true if the kernel carries everything a completed
// wire.MwebKernel needs: excess commitment, features byte, and signature.
func (pk *PKernel) isFinalized() bool {
	return pk.Signature != nil && pk.Features != nil &&
		pk.ExcessCommitment != nil && pk.isSane()
}

// featuresFromFields derives the feature bits implied by the populated fields.
func (pk *PKernel) featuresFromFields() wire.MwebKernelFeatureBit {
	var features wire.MwebKernelFeatureBit
	if pk.Fee != nil {
		features |= wire.MwebKernelFeeFeatureBit
	}
	if pk.PeginAmount != nil {
		features |= wire.MwebKernelPeginFeatureBit
	}
	if len(pk.PegOuts) > 0 {
		features |= wire.MwebKernelPegoutFeatureBit
	}
	if pk.LockHeight != nil {
		features |= wire.MwebKernelHeightLockFeatureBit
	}
	if pk.StealthExcess != nil {
		features |= wire.MwebKernelStealthExcessFeatureBit
	}
	if len(pk.ExtraData) > 0 {
		features |= wire.MwebKernelExtraDataFeatureBit
	}
	return features
}

// isSane returns true when a present features byte agrees with the populated
// fields in both directions, as LIP-0007 requires, and when a signed kernel
// also carries its excess commitment and features byte.
func (pk *PKernel) isSane() bool {
	if pk.Signature != nil && (pk.Features == nil || pk.ExcessCommitment == nil) {
		return false
	}

	if pk.Features != nil && *pk.Features != pk.featuresFromFields() {
		return false
	}

	if pk.LockHeight != nil && *pk.LockHeight < 0 {
		return false
	}

	return true
}

// deserialize attempts to deserialize the PKernel from the provided reader.
func (pk *PKernel) deserialize(r io.Reader) error {
	kernelKeys := newKeySet()
	var pegouts map[uint64]*wire.TxOut
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

		if !kvPair.isKnownType() {
			pk.Unknowns = append(pk.Unknowns, kvPair.asUnknown())
			continue
		}

		switch KernelType(kvPair.keyType) {
		case MwebKernelExcessCommitType:
			pk.ExcessCommitment, err = kvPair.commitmentValue()
			if err != nil {
				return err
			}
		case MwebKernelStealthCommitType:
			value, err := kvPair.fixedValue(len(mw.PublicKey{}))
			if err != nil {
				return err
			}

			pk.StealthExcess, err = mw.ReadPublicKey(value)
			if err != nil {
				return err
			}
		case MwebKernelFeeType:
			value, err := kvPair.fixedValue(8)
			if err != nil {
				return err
			}

			fee := ltcutil.Amount(binary.LittleEndian.Uint64(value))
			pk.Fee = &fee
		case MwebKernelPeginAmountType:
			value, err := kvPair.fixedValue(8)
			if err != nil {
				return err
			}

			peginAmount := ltcutil.Amount(binary.LittleEndian.Uint64(value))
			pk.PeginAmount = &peginAmount
		case MwebKernelPegoutType:
			// LIP-0007: the keydata is a compact-size index; map order
			// is not authoritative for the pegout vector.
			indexReader := bytes.NewReader(kvPair.keyData)
			index, err := wire.ReadVarInt(indexReader, 0)
			if err != nil || indexReader.Len() != 0 {
				return ErrInvalidKeyData
			}

			pegout := new(wire.TxOut)
			valueReader := bytes.NewReader(kvPair.valueData)
			if err := wire.ReadTxOut(valueReader, 0, 0, pegout); err != nil {
				return err
			}
			if valueReader.Len() != 0 || len(pegout.PkScript) == 0 {
				return ErrInvalidPsbtFormat
			}
			if pegouts == nil {
				pegouts = make(map[uint64]*wire.TxOut)
			}
			pegouts[index] = pegout
		case MwebKernelLockHeightType:
			value, err := kvPair.fixedValue(4)
			if err != nil {
				return err
			}

			// The signature-preimage VARINT is defined only for
			// non-negative values; a negative height has no valid
			// encoding.
			lockHeight := int32(binary.LittleEndian.Uint32(value))
			if lockHeight < 0 {
				return ErrInvalidPsbtFormat
			}
			pk.LockHeight = &lockHeight
		case MwebKernelFeaturesType:
			value, err := kvPair.fixedValue(1)
			if err != nil {
				return err
			}

			features := wire.MwebKernelFeatureBit(value[0])
			pk.Features = &features
		case MwebKernelExtraDataType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pk.ExtraData = kvPair.valueData
		case MwebKernelSignatureType:
			value, err := kvPair.fixedValue(len(mw.Signature{}))
			if err != nil {
				return err
			}
			pk.Signature = mw.ReadSignature(value)
			if pk.Signature == nil {
				return ErrInvalidPsbtFormat
			}
		default:
			// A fall through case for any proprietary types.
			pk.Unknowns = append(pk.Unknowns, kvPair.asUnknown())
		}
	}

	// LIP-0007: pegout indexes must be contiguous starting from zero.
	if len(pegouts) > 0 {
		pk.PegOuts = make([]*wire.TxOut, len(pegouts))
		for index, pegout := range pegouts {
			if index >= uint64(len(pegouts)) {
				return ErrInvalidPsbtFormat
			}
			pk.PegOuts[index] = pegout
		}
	}

	return nil
}

// serialize writes the PKernel to the provided writer in PSBT key-value
// format, in LIP-0007 kernel key order (features byte first).
func (pk *PKernel) serialize(w io.Writer) error {
	// Kernel Features
	if pk.Features != nil {
		err := serializeKVPairWithType(w, uint8(MwebKernelFeaturesType), nil, []byte{byte(*pk.Features)})
		if err != nil {
			return err
		}
	}

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
