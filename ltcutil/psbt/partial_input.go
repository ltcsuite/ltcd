package psbt

import (
	"bytes"
	"encoding/binary"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"io"
	"sort"

	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
)

// PInput is a struct encapsulating all the data that can be attached to any
// specific input of the PSBT.
type PInput struct {
	NonWitnessUtxo         *wire.MsgTx
	WitnessUtxo            *wire.TxOut
	PartialSigs            []*PartialSig
	SighashType            txscript.SigHashType
	RedeemScript           []byte
	WitnessScript          []byte
	Bip32Derivation        []*Bip32Derivation
	FinalScriptSig         []byte
	FinalScriptWitness     []byte
	TaprootKeySpendSig     []byte
	TaprootScriptSpendSig  []*TaprootScriptSpendSig
	TaprootLeafScript      []*TaprootTapLeafScript
	TaprootBip32Derivation []*TaprootBip32Derivation
	TaprootInternalKey     []byte
	TaprootMerkleRoot      []byte
	MwebOutputId           *chainhash.Hash
	MwebAddressIndex       *uint32
	MwebAmount             *ltcutil.Amount
	MwebSharedSecret       *mw.SecretKey
	MwebRawBlindingFactor  *mw.BlindingFactor
	MwebCommit             *mw.Commitment
	MwebOutputPubkey       *mw.PublicKey
	MwebInputPubkey        *mw.PublicKey
	MwebFeatures           *wire.MwebInputFeatureBit
	MwebInputSig           *mw.Signature
	Unknowns               []*Unknown
}

// NewPsbtInput creates an instance of PsbtInput given either a nonWitnessUtxo
// or a witnessUtxo.
//
// NOTE: Only one of the two arguments should be specified, with the other
// being `nil`; otherwise the created PsbtInput object will fail IsSane()
// checks and will not be usable.
func NewPsbtInput(nonWitnessUtxo *wire.MsgTx, witnessUtxo *wire.TxOut) *PInput {
	return &PInput{
		NonWitnessUtxo:        nonWitnessUtxo,
		WitnessUtxo:           witnessUtxo,
		PartialSigs:           []*PartialSig{},
		SighashType:           0,
		RedeemScript:          nil,
		WitnessScript:         nil,
		Bip32Derivation:       []*Bip32Derivation{},
		FinalScriptSig:        nil,
		FinalScriptWitness:    nil,
		MwebOutputId:          nil,
		MwebAddressIndex:      nil,
		MwebAmount:            nil,
		MwebSharedSecret:      nil,
		MwebRawBlindingFactor: nil,
		MwebCommit:            nil,
		MwebOutputPubkey:      nil,
		MwebInputPubkey:       nil,
		MwebFeatures:          nil,
		MwebInputSig:          nil,
		Unknowns:              nil,
	}
}

// IsSane returns true only if there are no conflicting values in the Psbt
// PInput. For segwit v0 no checks are currently implemented.
func (pi *PInput) IsSane() bool {
	// TODO(guggero): Implement sanity checks for segwit v1. For segwit v0
	// it is unsafe to only rely on the witness UTXO so we don't check that
	// only one is set anymore.
	// See https://github.com/bitcoin/bitcoin/pull/19215.

	if pi.isMWEB() {
		if pi.MwebInputSig != nil {
			if pi.MwebFeatures == nil || pi.MwebCommit == nil || pi.MwebOutputPubkey == nil {
				return false
			}

		}
		return true
	}

	// No MWEB fields should be set on non-MWEB inputs
	if pi.MwebAddressIndex != nil ||
		pi.MwebAmount != nil ||
		pi.MwebSharedSecret != nil ||
		pi.MwebRawBlindingFactor != nil ||
		pi.MwebCommit != nil ||
		pi.MwebOutputPubkey != nil ||
		pi.MwebInputPubkey != nil ||
		pi.MwebFeatures != nil ||
		pi.MwebInputSig != nil {
		return false
	}

	return true
}

func (pi *PInput) isMWEB() bool {
	return pi.MwebOutputId != nil
}

// deserialize attempts to deserialize a new PInput from the passed io.Reader.
func (pi *PInput) deserialize(r io.Reader) error {
	inputKeys := newKeySet()
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
		if !inputKeys.addKey(kvPair.keyType, kvPair.keyData) {
			return ErrDuplicateKey
		}

		switch InputType(kvPair.keyType) {

		case NonWitnessUtxoType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			tx := wire.NewMsgTx(2)

			err := tx.Deserialize(bytes.NewReader(kvPair.valueData))
			if err != nil {
				return err
			}
			pi.NonWitnessUtxo = tx

		case WitnessUtxoType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			txout, err := readTxOut(kvPair.valueData)
			if err != nil {
				return err
			}
			pi.WitnessUtxo = txout

		case PartialSigType:
			newPartialSig := PartialSig{
				PubKey:    kvPair.keyData,
				Signature: kvPair.valueData,
			}

			if !newPartialSig.checkValid() {
				return ErrInvalidPsbtFormat
			}

			pi.PartialSigs = append(pi.PartialSigs, &newPartialSig)

		case SighashType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			// Bounds check on value here since the sighash type
			// must be a 32-bit unsigned integer.
			if len(kvPair.valueData) != 4 {
				return ErrInvalidKeyData
			}

			sighashType := txscript.SigHashType(
				binary.LittleEndian.Uint32(kvPair.valueData),
			)
			pi.SighashType = sighashType

		case RedeemScriptInputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pi.RedeemScript = kvPair.valueData

		case WitnessScriptInputType:
			if pi.WitnessScript != nil {
				return ErrDuplicateKey
			}
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pi.WitnessScript = kvPair.valueData

		case Bip32DerivationInputType:
			if !validatePubkey(kvPair.keyData) {
				return ErrInvalidPsbtFormat
			}
			master, derivationPath, err := ReadBip32Derivation(
				kvPair.valueData,
			)
			if err != nil {
				return err
			}

			pi.Bip32Derivation = append(
				pi.Bip32Derivation,
				&Bip32Derivation{
					PubKey:               kvPair.keyData,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				},
			)

		case FinalScriptSigType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.FinalScriptSig = kvPair.valueData

		case FinalScriptWitnessType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.FinalScriptWitness = kvPair.valueData

		case TaprootKeySpendSignatureType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			// The signature can either be 64 or 65 bytes.
			switch {
			case len(kvPair.valueData) == schnorrSigMinLength:
				if !validateSchnorrSignature(kvPair.valueData) {
					return ErrInvalidKeyData
				}

			case len(kvPair.valueData) == schnorrSigMaxLength:
				if !validateSchnorrSignature(
					kvPair.valueData[0:schnorrSigMinLength],
				) {
					return ErrInvalidKeyData
				}

			default:
				return ErrInvalidKeyData
			}

			pi.TaprootKeySpendSig = kvPair.valueData

		case TaprootScriptSpendSignatureType:
			// The key data for the script spend signature is:
			//   <xonlypubkey> <leafhash>
			if len(kvPair.keyData) != 32*2 {
				return ErrInvalidKeyData
			}

			newPartialSig := TaprootScriptSpendSig{
				XOnlyPubKey: kvPair.keyData[:32],
				LeafHash:    kvPair.keyData[32:],
			}

			// The signature can either be 64 or 65 bytes.
			switch {
			case len(kvPair.valueData) == schnorrSigMinLength:
				newPartialSig.Signature = kvPair.valueData
				newPartialSig.SigHash = txscript.SigHashDefault

			case len(kvPair.valueData) == schnorrSigMaxLength:
				newPartialSig.Signature = kvPair.valueData[0:schnorrSigMinLength]
				newPartialSig.SigHash = txscript.SigHashType(
					kvPair.valueData[schnorrSigMinLength],
				)

			default:
				return ErrInvalidKeyData
			}

			if !newPartialSig.checkValid() {
				return ErrInvalidKeyData
			}

			pi.TaprootScriptSpendSig = append(
				pi.TaprootScriptSpendSig, &newPartialSig,
			)

		case TaprootLeafScriptType:
			if len(kvPair.valueData) < 1 {
				return ErrInvalidKeyData
			}

			newLeafScript := TaprootTapLeafScript{
				ControlBlock: kvPair.keyData,
				Script:       kvPair.valueData[:len(kvPair.valueData)-1],
				LeafVersion: txscript.TapscriptLeafVersion(
					kvPair.valueData[len(kvPair.valueData)-1],
				),
			}

			if !newLeafScript.checkValid() {
				return ErrInvalidKeyData
			}

			pi.TaprootLeafScript = append(
				pi.TaprootLeafScript, &newLeafScript,
			)

		case TaprootBip32DerivationInputType:
			if !validateXOnlyPubkey(kvPair.keyData) {
				return ErrInvalidKeyData
			}

			taprootDerivation, err := ReadTaprootBip32Derivation(
				kvPair.keyData, kvPair.valueData,
			)
			if err != nil {
				return err
			}

			pi.TaprootBip32Derivation = append(
				pi.TaprootBip32Derivation, taprootDerivation,
			)

		case TaprootInternalKeyInputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			if !validateXOnlyPubkey(kvPair.valueData) {
				return ErrInvalidKeyData
			}

			pi.TaprootInternalKey = kvPair.valueData

		case TaprootMerkleRootType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.TaprootMerkleRoot = kvPair.valueData

		case MwebSpentOutputIdType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebOutputId = new(chainhash.Hash)
			err = pi.MwebOutputId.SetBytes(kvPair.valueData)
			if err != nil {
				return err
			}
		case MwebSpentOutputCommitType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebCommit = mw.ReadCommitment(kvPair.valueData)
			if pi.MwebCommit == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebSpentOutputPubKeyType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebOutputPubkey = mw.ReadPublicKey(kvPair.valueData)
			if pi.MwebOutputPubkey == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebInputPubKeyType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebInputPubkey = mw.ReadPublicKey(kvPair.valueData)
			if pi.MwebInputPubkey == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebInputFeaturesType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 1 {
				return ErrInvalidPsbtFormat
			}

			features := wire.MwebInputFeatureBit(kvPair.valueData[0])
			pi.MwebFeatures = &features
		case MwebInputSignatureType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebInputSig = mw.ReadSignature(kvPair.valueData)
			if pi.MwebInputSig == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebAddressIndexType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 4 {
				return ErrInvalidPsbtFormat
			}

			pi.MwebAddressIndex = uint32Ptr(binary.LittleEndian.Uint32(kvPair.valueData))
		case MwebInputAmountType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 8 {
				return ErrInvalidPsbtFormat
			}

			mwebAmount := ltcutil.Amount(binary.LittleEndian.Uint64(kvPair.valueData))
			pi.MwebAmount = &mwebAmount
		case MwebSharedSecretType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			if len(kvPair.valueData) != 32 {
				return ErrInvalidPsbtFormat
			}

			pi.MwebSharedSecret = (*mw.SecretKey)(kvPair.valueData)
		case MwebSpentOutputBlindType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			pi.MwebRawBlindingFactor = mw.ReadBlindingFactor(kvPair.valueData)
		// case MwebInputExtraDataType: // TODO: Not yet supported
		default:
			// A fall through case for any proprietary types.
			keyCodeAndData := append(
				[]byte{kvPair.keyType}, kvPair.keyData...,
			)
			newUnknown := &Unknown{
				Key:   keyCodeAndData,
				Value: kvPair.valueData,
			}

			pi.Unknowns = append(pi.Unknowns, newUnknown)
		}
	}

	return nil
}

// serialize attempts to serialize the target PInput into the passed io.Writer.
func (pi *PInput) serialize(w io.Writer) error {
	if !pi.IsSane() {
		return ErrInvalidPsbtFormat
	}

	if pi.NonWitnessUtxo != nil {
		var buf bytes.Buffer
		err := pi.NonWitnessUtxo.Serialize(&buf)
		if err != nil {
			return err
		}

		err = serializeKVPairWithType(
			w, uint8(NonWitnessUtxoType), nil, buf.Bytes(),
		)
		if err != nil {
			return err
		}
	}
	if pi.WitnessUtxo != nil {
		var buf bytes.Buffer
		err := wire.WriteTxOut(&buf, 0, 0, pi.WitnessUtxo)
		if err != nil {
			return err
		}

		err = serializeKVPairWithType(
			w, uint8(WitnessUtxoType), nil, buf.Bytes(),
		)
		if err != nil {
			return err
		}
	}

	if pi.FinalScriptSig == nil && pi.FinalScriptWitness == nil {
		sort.Sort(PartialSigSorter(pi.PartialSigs))
		for _, ps := range pi.PartialSigs {
			err := serializeKVPairWithType(
				w, uint8(PartialSigType), ps.PubKey,
				ps.Signature,
			)
			if err != nil {
				return err
			}
		}

		if pi.SighashType != 0 {
			var shtBytes [4]byte
			binary.LittleEndian.PutUint32(
				shtBytes[:], uint32(pi.SighashType),
			)

			err := serializeKVPairWithType(
				w, uint8(SighashType), nil, shtBytes[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.RedeemScript != nil {
			err := serializeKVPairWithType(
				w, uint8(RedeemScriptInputType), nil,
				pi.RedeemScript,
			)
			if err != nil {
				return err
			}
		}

		if pi.WitnessScript != nil {
			err := serializeKVPairWithType(
				w, uint8(WitnessScriptInputType), nil,
				pi.WitnessScript,
			)
			if err != nil {
				return err
			}
		}

		sort.Sort(Bip32Sorter(pi.Bip32Derivation))
		for _, kd := range pi.Bip32Derivation {
			err := serializeKVPairWithType(
				w,
				uint8(Bip32DerivationInputType), kd.PubKey,
				SerializeBIP32Derivation(
					kd.MasterKeyFingerprint, kd.Bip32Path,
				),
			)
			if err != nil {
				return err
			}
		}

		if pi.TaprootKeySpendSig != nil {
			err := serializeKVPairWithType(
				w, uint8(TaprootKeySpendSignatureType), nil,
				pi.TaprootKeySpendSig,
			)
			if err != nil {
				return err
			}
		}

		sort.Slice(pi.TaprootScriptSpendSig, func(i, j int) bool {
			return pi.TaprootScriptSpendSig[i].SortBefore(
				pi.TaprootScriptSpendSig[j],
			)
		})
		for _, scriptSpend := range pi.TaprootScriptSpendSig {
			keyData := append([]byte{}, scriptSpend.XOnlyPubKey...)
			keyData = append(keyData, scriptSpend.LeafHash...)
			value := append([]byte{}, scriptSpend.Signature...)
			if scriptSpend.SigHash != txscript.SigHashDefault {
				value = append(value, byte(scriptSpend.SigHash))
			}
			err := serializeKVPairWithType(
				w, uint8(TaprootScriptSpendSignatureType),
				keyData, value,
			)
			if err != nil {
				return err
			}
		}

		sort.Slice(pi.TaprootLeafScript, func(i, j int) bool {
			return pi.TaprootLeafScript[i].SortBefore(
				pi.TaprootLeafScript[j],
			)
		})
		for _, leafScript := range pi.TaprootLeafScript {
			value := append([]byte{}, leafScript.Script...)
			value = append(value, byte(leafScript.LeafVersion))
			err := serializeKVPairWithType(
				w, uint8(TaprootLeafScriptType),
				leafScript.ControlBlock, value,
			)
			if err != nil {
				return err
			}
		}

		sort.Slice(pi.TaprootBip32Derivation, func(i, j int) bool {
			return pi.TaprootBip32Derivation[i].SortBefore(
				pi.TaprootBip32Derivation[j],
			)
		})
		for _, derivation := range pi.TaprootBip32Derivation {
			value, err := SerializeTaprootBip32Derivation(
				derivation,
			)
			if err != nil {
				return err
			}
			err = serializeKVPairWithType(
				w, uint8(TaprootBip32DerivationInputType),
				derivation.XOnlyPubKey, value,
			)
			if err != nil {
				return err
			}
		}

		if pi.TaprootInternalKey != nil {
			err := serializeKVPairWithType(
				w, uint8(TaprootInternalKeyInputType), nil,
				pi.TaprootInternalKey,
			)
			if err != nil {
				return err
			}
		}

		if pi.TaprootMerkleRoot != nil {
			err := serializeKVPairWithType(
				w, uint8(TaprootMerkleRootType), nil,
				pi.TaprootMerkleRoot,
			)
			if err != nil {
				return err
			}
		}
	}

	if pi.FinalScriptSig != nil {
		err := serializeKVPairWithType(
			w, uint8(FinalScriptSigType), nil, pi.FinalScriptSig,
		)
		if err != nil {
			return err
		}
	}

	if pi.FinalScriptWitness != nil {
		err := serializeKVPairWithType(
			w, uint8(FinalScriptWitnessType), nil, pi.FinalScriptWitness,
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebOutputId != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebSpentOutputIdType), nil,
			pi.MwebOutputId[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebCommit != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebSpentOutputCommitType), nil,
			pi.MwebCommit[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebOutputPubkey != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebSpentOutputPubKeyType), nil,
			pi.MwebOutputPubkey[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebInputPubkey != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebInputPubKeyType), nil,
			pi.MwebInputPubkey[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebFeatures != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebInputFeaturesType), nil,
			[]byte{byte(*pi.MwebFeatures)},
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebInputSig != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebInputSignatureType), nil,
			pi.MwebInputSig[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebAddressIndex != nil {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], *pi.MwebAddressIndex)
		err := serializeKVPairWithType(
			w, uint8(MwebAddressIndexType), nil,
			buf[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebAmount != nil {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(*pi.MwebAmount))
		err := serializeKVPairWithType(
			w, uint8(MwebInputAmountType), nil,
			buf[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebSharedSecret != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebSharedSecretType), nil,
			pi.MwebSharedSecret[:],
		)
		if err != nil {
			return err
		}
	}

	if pi.MwebRawBlindingFactor != nil {
		err := serializeKVPairWithType(
			w, uint8(MwebSpentOutputBlindType), nil,
			pi.MwebRawBlindingFactor[:],
		)
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field.
	for _, kv := range pi.Unknowns {
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
