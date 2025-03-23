package psbt

import (
	"encoding/binary"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"io"
	"sort"
)

// POutput is a struct encapsulating all the data that can be attached
// to any specific output of the PSBT.
type POutput struct {
	RedeemScript           []byte
	WitnessScript          []byte
	Bip32Derivation        []*Bip32Derivation
	TaprootInternalKey     []byte
	TaprootTapTree         []byte
	TaprootBip32Derivation []*TaprootBip32Derivation
	StealthAddress         *mw.StealthAddress
	OutputCommit           *mw.Commitment
	MwebFeatures           *wire.MwebOutputMessageFeatureBit
	SenderPubkey           *mw.PublicKey
	OutputPubkey           *mw.PublicKey
	MwebStandardFields     *standardMwebOutputFields
	RangeProof             *mw.RangeProof
	MwebSignature          *mw.Signature
	Unknowns               []*Unknown
}

type standardMwebOutputFields struct {
	KeyExchangePubkey mw.PublicKey
	ViewTag           uint8
	EncryptedValue    uint64
	EncryptedNonce    [16]byte
}

// NewPsbtOutput creates an instance of PsbtOutput; the three parameters
// redeemScript, witnessScript and Bip32Derivation are all allowed to be
// `nil`.
func NewPsbtOutput(redeemScript []byte, witnessScript []byte,
	bip32Derivation []*Bip32Derivation) *POutput {
	return &POutput{
		RedeemScript:    redeemScript,
		WitnessScript:   witnessScript,
		Bip32Derivation: bip32Derivation,
	}
}

func (po *POutput) isMWEB() bool {
	return po.StealthAddress != nil || po.OutputCommit != nil
}

func (po *POutput) isFinalized() bool {
	return !po.isMWEB() || po.MwebSignature != nil
}

func (po *POutput) isSane() bool {
	if po.isMWEB() {
		if po.StealthAddress == nil && po.OutputCommit == nil {
			return false
		}

		if po.MwebFeatures != nil && (*po.MwebFeatures&wire.MwebOutputMessageExtraDataFeatureBit) > 0 {
			// We don't yet support MWEB extra data fields
			return false
		}

		if po.MwebSignature != nil {
			if po.OutputCommit == nil ||
				po.MwebFeatures == nil ||
				po.SenderPubkey == nil ||
				po.OutputPubkey == nil ||
				po.RangeProof == nil {
				return false
			}

			if (*po.MwebFeatures&wire.MwebOutputMessageStandardFieldsFeatureBit) > 0 && po.MwebStandardFields == nil {
				return false
			}
		}

		return true
	}

	// No MWEB fields should be set on non-MWEB outputs
	if po.MwebFeatures != nil ||
		po.SenderPubkey != nil ||
		po.OutputPubkey != nil ||
		po.MwebStandardFields != nil ||
		po.RangeProof != nil ||
		po.MwebSignature != nil {
		return false
	}

	return true
}

// deserialize attempts to recode a new POutput from the passed io.Reader.
func (po *POutput) deserialize(r io.Reader) error {
	outputKeys := newKeySet()
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
		if !outputKeys.addKey(kvPair.keyType, kvPair.keyData) {
			return ErrDuplicateKey
		}

		switch OutputType(kvPair.keyType) {

		case RedeemScriptOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.RedeemScript = kvPair.valueData

		case WitnessScriptOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.WitnessScript = kvPair.valueData

		case Bip32DerivationOutputType:
			if !validatePubkey(kvPair.keyData) {
				return ErrInvalidKeyData
			}
			master, derivationPath, err := ReadBip32Derivation(
				kvPair.valueData,
			)
			if err != nil {
				return err
			}

			po.Bip32Derivation = append(po.Bip32Derivation,
				&Bip32Derivation{
					PubKey:               kvPair.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)

		case TaprootInternalKeyOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			if !validateXOnlyPubkey(kvPair.valueData) {
				return ErrInvalidKeyData
			}

			po.TaprootInternalKey = kvPair.valueData

		case TaprootTapTreeType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			po.TaprootTapTree = kvPair.valueData

		case TaprootBip32DerivationOutputType:
			if !validateXOnlyPubkey(kvPair.keyData) {
				return ErrInvalidKeyData
			}

			taprootDerivation, err := ReadTaprootBip32Derivation(
				kvPair.keyData, kvPair.valueData,
			)
			if err != nil {
				return err
			}

			po.TaprootBip32Derivation = append(
				po.TaprootBip32Derivation, taprootDerivation,
			)

		case MwebStealthAddressOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 66 {
				return ErrInvalidPsbtFormat
			}

			po.StealthAddress = new(mw.StealthAddress)
			po.StealthAddress.Scan = mw.ReadPublicKey(kvPair.valueData[0:33])
			po.StealthAddress.Spend = mw.ReadPublicKey(kvPair.valueData[33:])
			if po.StealthAddress.Scan == nil || po.StealthAddress.Spend == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebCommitOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.OutputCommit = mw.ReadCommitment(kvPair.valueData)
			if po.OutputCommit == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebFeaturesOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 1 {
				return ErrInvalidPsbtFormat
			}

			features := wire.MwebOutputMessageFeatureBit(kvPair.valueData[0])
			po.MwebFeatures = &features
		case MwebSenderPubKeyOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.SenderPubkey = mw.ReadPublicKey(kvPair.valueData)
			if po.SenderPubkey == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebOutputPubKeyOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.OutputPubkey = mw.ReadPublicKey(kvPair.valueData)
			if po.OutputPubkey == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebStandardFieldsOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 33+1+8+16 {
				return ErrInvalidPsbtFormat
			}
			keyExchangePubkey := mw.ReadPublicKey(kvPair.valueData[0:33])
			if keyExchangePubkey == nil {
				return ErrInvalidPsbtFormat
			}
			po.MwebStandardFields = new(standardMwebOutputFields)
			po.MwebStandardFields.KeyExchangePubkey = *keyExchangePubkey
			po.MwebStandardFields.ViewTag = kvPair.valueData[33]
			po.MwebStandardFields.EncryptedValue = binary.LittleEndian.Uint64(kvPair.valueData[34:42])
			copy(po.MwebStandardFields.EncryptedNonce[:], kvPair.valueData[42:58])
		case MwebRangeProofOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.RangeProof = mw.ReadRangeProof(kvPair.valueData)
			if po.RangeProof == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebSignatureOutputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			po.MwebSignature = mw.ReadSignature(kvPair.valueData)
			if po.MwebSignature == nil {
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

			po.Unknowns = append(po.Unknowns, newUnknown)
		}
	}

	return nil
}

// serialize attempts to write out the target POutput into the passed
// io.Writer.
func (po *POutput) serialize(w io.Writer) error {
	if po.RedeemScript != nil {
		err := serializeKVPairWithType(
			w, uint8(RedeemScriptOutputType), nil, po.RedeemScript,
		)
		if err != nil {
			return err
		}
	}
	if po.WitnessScript != nil {
		err := serializeKVPairWithType(
			w, uint8(WitnessScriptOutputType), nil, po.WitnessScript,
		)
		if err != nil {
			return err
		}
	}

	sort.Sort(Bip32Sorter(po.Bip32Derivation))
	for _, kd := range po.Bip32Derivation {
		err := serializeKVPairWithType(w,
			uint8(Bip32DerivationOutputType),
			kd.PubKey,
			SerializeBIP32Derivation(
				kd.MasterKeyFingerprint,
				kd.Bip32Path,
			),
		)
		if err != nil {
			return err
		}
	}

	if po.TaprootInternalKey != nil {
		err := serializeKVPairWithType(
			w, uint8(TaprootInternalKeyOutputType), nil,
			po.TaprootInternalKey,
		)
		if err != nil {
			return err
		}
	}

	if po.TaprootTapTree != nil {
		err := serializeKVPairWithType(
			w, uint8(TaprootTapTreeType), nil,
			po.TaprootTapTree,
		)
		if err != nil {
			return err
		}
	}

	sort.Slice(po.TaprootBip32Derivation, func(i, j int) bool {
		return po.TaprootBip32Derivation[i].SortBefore(
			po.TaprootBip32Derivation[j],
		)
	})
	for _, derivation := range po.TaprootBip32Derivation {
		value, err := SerializeTaprootBip32Derivation(
			derivation,
		)
		if err != nil {
			return err
		}
		err = serializeKVPairWithType(
			w, uint8(TaprootBip32DerivationOutputType),
			derivation.XOnlyPubKey, value,
		)
		if err != nil {
			return err
		}
	}

	if po.StealthAddress != nil {
		err := serializeKVPairWithType(w, uint8(MwebStealthAddressOutputType), nil,
			append(po.StealthAddress.Scan[:], po.StealthAddress.Spend[:]...),
		)
		if err != nil {
			return err
		}
	}

	if po.OutputCommit != nil {
		err := serializeKVPairWithType(w, uint8(MwebCommitOutputType), nil, po.OutputCommit[:])
		if err != nil {
			return err
		}
	}

	if po.MwebFeatures != nil {
		err := serializeKVPairWithType(w, uint8(MwebFeaturesOutputType), nil, []byte{uint8(*po.MwebFeatures)})
		if err != nil {
			return err
		}
	}

	if po.SenderPubkey != nil {
		err := serializeKVPairWithType(w, uint8(MwebSenderPubKeyOutputType), nil, po.SenderPubkey[:])
		if err != nil {
			return err
		}
	}

	if po.OutputPubkey != nil {
		err := serializeKVPairWithType(w, uint8(MwebOutputPubKeyOutputType), nil, po.OutputPubkey[:])
		if err != nil {
			return err
		}
	}

	if po.MwebStandardFields != nil {
		valueData := po.MwebStandardFields.KeyExchangePubkey[:]
		valueData = append(valueData, po.MwebStandardFields.ViewTag)
		valueData = binary.LittleEndian.AppendUint64(valueData, po.MwebStandardFields.EncryptedValue)
		valueData = append(valueData, po.MwebStandardFields.EncryptedNonce[:]...)
		err := serializeKVPairWithType(w, uint8(MwebStandardFieldsOutputType), nil, valueData)
		if err != nil {
			return err
		}
	}

	if po.RangeProof != nil {
		err := serializeKVPairWithType(w, uint8(MwebRangeProofOutputType), nil, po.RangeProof[:])
		if err != nil {
			return err
		}
	}

	if po.MwebSignature != nil {
		err := serializeKVPairWithType(w, uint8(MwebSignatureOutputType), nil, po.MwebSignature[:])
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field
	for _, kv := range po.Unknowns {
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
