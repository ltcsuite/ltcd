package psbt

import (
	"bytes"
	"encoding/binary"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"io"
	"sort"
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
	PrevoutHash            *chainhash.Hash
	PrevoutIndex           *uint32
	Sequence               *uint32
	RequiredTimeLockTime   *uint32
	RequiredHeightLockTime *uint32
	TaprootKeySpendSig     []byte
	TaprootScriptSpendSig  []*TaprootScriptSpendSig
	TaprootLeafScript      []*TaprootTapLeafScript
	TaprootBip32Derivation []*TaprootBip32Derivation
	TaprootInternalKey     []byte
	TaprootMerkleRoot      []byte
	MwebOutputId           *chainhash.Hash
	MwebAddrDescriptor     []byte

	// sighashZero records that the packet carried an explicit sighash key
	// with value 0 (SIGHASH_DEFAULT), which must round-trip even though
	// the zero value otherwise means "absent".
	sighashZero           bool
	MwebAmount            *ltcutil.Amount
	MwebSharedSecret      *mw.SecretKey
	MwebKeyExchangePubkey *mw.PublicKey
	MwebCommit            *mw.Commitment
	MwebOutputPubkey      *mw.PublicKey
	MwebInputPubkey       *mw.PublicKey
	MwebFeatures          *wire.MwebInputFeatureBit
	MwebInputSig          *mw.Signature
	MwebExtraData         []byte
	Unknowns              []*Unknown
}

// NewPsbtInput creates an instance of PsbtInput given either a nonWitnessUtxo
// or a witnessUtxo.
//
// NOTE: Only one of the two arguments should be specified, with the other
// being `nil`; otherwise the created PsbtInput object will fail IsSane()
// checks and will not be usable.
func NewPsbtInput(nonWitnessUtxo *wire.MsgTx, witnessUtxo *wire.TxOut) *PInput {
	return &PInput{
		NonWitnessUtxo:         nonWitnessUtxo,
		WitnessUtxo:            witnessUtxo,
		PartialSigs:            []*PartialSig{},
		SighashType:            0,
		RedeemScript:           nil,
		WitnessScript:          nil,
		Bip32Derivation:        []*Bip32Derivation{},
		FinalScriptSig:         nil,
		FinalScriptWitness:     nil,
		PrevoutHash:            nil,
		PrevoutIndex:           nil,
		Sequence:               nil,
		RequiredTimeLockTime:   nil,
		RequiredHeightLockTime: nil,
		MwebOutputId:           nil,
		MwebAddrDescriptor:     nil,
		MwebAmount:             nil,
		MwebSharedSecret:       nil,
		MwebKeyExchangePubkey:  nil,
		MwebCommit:             nil,
		MwebOutputPubkey:       nil,
		MwebInputPubkey:        nil,
		MwebFeatures:           nil,
		MwebInputSig:           nil,
		MwebExtraData:          nil,
		Unknowns:               nil,
	}
}

// isSane returns true only if there are no conflicting values in the Psbt
// PInput. For segwit v0 no checks are currently implemented.
func (pi *PInput) isSane(psbtVersion uint32) bool {
	// TODO(guggero): Implement sanity checks for segwit v1. For segwit v0
	// it is unsafe to only rely on the witness UTXO so we don't check that
	// only one is set anymore.
	// See https://github.com/bitcoin/bitcoin/pull/19215.

	// No MWEB fields should be set on PSBTv0 inputs or non-MWEB inputs
	if psbtVersion < 2 || !pi.isMWEB() {
		if pi.MwebOutputId != nil ||
			pi.MwebAddrDescriptor != nil ||
			pi.MwebAmount != nil ||
			pi.MwebSharedSecret != nil ||
			pi.MwebKeyExchangePubkey != nil ||
			pi.MwebCommit != nil ||
			pi.MwebOutputPubkey != nil ||
			pi.MwebInputPubkey != nil ||
			pi.MwebFeatures != nil ||
			pi.MwebInputSig != nil ||
			pi.MwebExtraData != nil {
			return false
		}
	}

	if pi.isMWEB() {
		if pi.MwebInputSig != nil && !pi.isFinalized() {
			return false
		}

		// TODO(dburkett): Should probably verify that no non-MWEB fields are set
		return true
	}

	if psbtVersion >= 2 {
		// Per BIP-0370 PSBT_IN_PREVIOUS_TXID handling, an explicit zero
		// hash is treated as missing.
		if pi.PrevoutHash == nil || *pi.PrevoutHash == (chainhash.Hash{}) ||
			pi.PrevoutIndex == nil {

			return false
		}
	}

	return true
}

// isFinalized considers this input finalized if it's got all required MWEB fields populated,
// or contains at least one of the FinalScriptSig or FinalScriptWitness (which only occurs in a
// successful call to Finalize*).
func (pi *PInput) isFinalized() bool {
	if pi.isMWEB() {
		if pi.MwebInputSig == nil || pi.MwebFeatures == nil || pi.MwebCommit == nil || pi.MwebOutputPubkey == nil {
			return false
		}

		// The stealth-key bit and the input pubkey must agree: the pubkey is
		// serialized (and enters the stealth sum) only when the bit is set,
		// so a bit-clear pubkey has no on-chain representation.
		if (pi.MwebInputPubkey != nil) !=
			(*pi.MwebFeatures&wire.MwebInputStealthKeyFeatureBit > 0) {

			return false
		}

		// The extra-data bit and field must agree: the signature commits
		// to extra data only when the bit is set.
		if (len(pi.MwebExtraData) > 0) !=
			(*pi.MwebFeatures&wire.MwebInputExtraDataFeatureBit > 0) {

			return false
		}

		return true
	}

	return pi.FinalScriptSig != nil || pi.FinalScriptWitness != nil
}

func (pi *PInput) isMWEB() bool {
	return pi.MwebOutputId != nil
}

var (
	illegalPsbtV0InputKeys = map[InputType]bool{
		PrevoutHashInputType:            true,
		PrevoutIndexInputType:           true,
		SequenceInputType:               true,
		RequiredTimeLocktimeInputType:   true,
		RequiredHeightLocktimeInputType: true,
		MwebSpentOutputIdType:           true,
		MwebSpentOutputCommitType:       true,
		MwebSpentOutputPubKeyType:       true,
		MwebInputPubKeyType:             true,
		MwebInputFeaturesType:           true,
		MwebInputSignatureType:          true,
		MwebAddrDescriptorType:          true,
		MwebInputAmountType:             true,
		MwebSharedSecretType:            true,
		MwebKeyExchangePubKeyType:       true,
		MwebInputExtraDataType:          true,
	}
	illegalPsbtV2InputKeys = map[InputType]bool{}
)

func (pi *PInput) isAllowed(psbtVersion uint32, inputType InputType) bool {
	if psbtVersion == 0 {
		return !illegalPsbtV0InputKeys[inputType]
	} else if psbtVersion == 2 {
		return !illegalPsbtV2InputKeys[inputType]
	}

	return true
}

// deserialize attempts to deserialize a new PInput from the passed io.Reader.
func (pi *PInput) deserialize(r io.Reader, psbtVersion uint32) error {
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

		if !kvPair.isKnownType() {
			pi.Unknowns = append(pi.Unknowns, kvPair.asUnknown())
			continue
		}

		// Check if kvPair.keyType is allowed for psbtVersion
		inputType := InputType(kvPair.keyType)
		if !pi.isAllowed(psbtVersion, inputType) {
			return ErrUnsupportedFieldInPsbtVersion
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
			pi.sighashZero = sighashType == 0

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

		case PrevoutHashInputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			var prevoutHash chainhash.Hash
			if err = prevoutHash.SetBytes(kvPair.valueData[:]); err != nil {
				return err
			}

			pi.PrevoutHash = &prevoutHash

		case PrevoutIndexInputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			if len(kvPair.valueData) != 4 {
				return ErrInvalidKeyData
			}

			prevoutIndex := binary.LittleEndian.Uint32(kvPair.valueData)
			pi.PrevoutIndex = &prevoutIndex

		case SequenceInputType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}

			if len(kvPair.valueData) != 4 {
				return ErrInvalidKeyData
			}

			sequence := binary.LittleEndian.Uint32(kvPair.valueData)
			pi.Sequence = &sequence

		case RequiredTimeLocktimeInputType:
			value, err := kvPair.fixedValue(4)
			if err != nil {
				return err
			}

			// BIP-0370: time locks live at or above the threshold
			// consensus uses to tell timestamps from heights.
			requiredTimeLockTime := binary.LittleEndian.Uint32(value)
			if requiredTimeLockTime < txscript.LockTimeThreshold {
				return ErrInvalidPsbtFormat
			}
			pi.RequiredTimeLockTime = &requiredTimeLockTime

		case RequiredHeightLocktimeInputType:
			value, err := kvPair.fixedValue(4)
			if err != nil {
				return err
			}

			// Zero is accepted and treated as no lock (LIP-0007 kernel
			// required-height-locktime field).
			requiredHeightLockTime := binary.LittleEndian.Uint32(value)
			if requiredHeightLockTime >= txscript.LockTimeThreshold {
				return ErrInvalidPsbtFormat
			}
			pi.RequiredHeightLockTime = &requiredHeightLockTime

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
			pi.MwebCommit, err = kvPair.commitmentValue()
			if err != nil {
				return err
			}
		case MwebSpentOutputPubKeyType:
			value, err := kvPair.fixedValue(len(mw.PublicKey{}))
			if err != nil {
				return err
			}

			pi.MwebOutputPubkey, err = mw.ReadPublicKey(value)
			if err != nil {
				return err
			}
		case MwebInputPubKeyType:
			value, err := kvPair.fixedValue(len(mw.PublicKey{}))
			if err != nil {
				return err
			}

			pi.MwebInputPubkey, err = mw.ReadPublicKey(value)
			if err != nil {
				return err
			}
		case MwebInputFeaturesType:
			value, err := kvPair.fixedValue(1)
			if err != nil {
				return err
			}

			features := wire.MwebInputFeatureBit(value[0])
			pi.MwebFeatures = &features
		case MwebInputSignatureType:
			value, err := kvPair.fixedValue(len(mw.Signature{}))
			if err != nil {
				return err
			}

			pi.MwebInputSig = mw.ReadSignature(value)
			if pi.MwebInputSig == nil {
				return ErrInvalidPsbtFormat
			}
		case MwebAddrDescriptorType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			// LIP-0007: an exactly-4-byte value is the legacy address-index
			// encoding and is silently ignored.
			if len(kvPair.valueData) == 4 {
				break
			}
			if !isMwebDescriptor(kvPair.valueData) {
				return ErrInvalidPsbtFormat
			}

			pi.MwebAddrDescriptor = kvPair.valueData
		case MwebInputAmountType:
			value, err := kvPair.fixedValue(8)
			if err != nil {
				return err
			}

			mwebAmount := ltcutil.Amount(binary.LittleEndian.Uint64(value))
			pi.MwebAmount = &mwebAmount
		case MwebSharedSecretType:
			value, err := kvPair.fixedValue(len(mw.SecretKey{}))
			if err != nil {
				return err
			}

			pi.MwebSharedSecret = (*mw.SecretKey)(value)
		case MwebKeyExchangePubKeyType:
			value, err := kvPair.fixedValue(len(mw.PublicKey{}))
			if err != nil {
				return err
			}

			pi.MwebKeyExchangePubkey, err = mw.ReadPublicKey(value)
			if err != nil {
				return err
			}
		case MwebInputExtraDataType:
			if kvPair.keyData != nil {
				return ErrInvalidKeyData
			}
			pi.MwebExtraData = kvPair.valueData
		default:
			// A fall through case for any proprietary types.
			pi.Unknowns = append(pi.Unknowns, kvPair.asUnknown())
		}
	}

	return nil
}

// serialize attempts to serialize the target PInput into the passed io.Writer.
func (pi *PInput) serialize(w io.Writer, psbtVersion uint32) error {
	if !pi.isSane(psbtVersion) {
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

		if pi.SighashType != 0 || pi.sighashZero {
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

	if psbtVersion >= 2 {
		if pi.PrevoutHash != nil {
			err := serializeKVPairWithType(
				w, uint8(PrevoutHashInputType), nil,
				pi.PrevoutHash[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.PrevoutIndex != nil {
			var valueData [4]byte
			binary.LittleEndian.PutUint32(valueData[:], *pi.PrevoutIndex)
			err := serializeKVPairWithType(
				w, uint8(PrevoutIndexInputType), nil,
				valueData[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.Sequence != nil {
			var valueData [4]byte
			binary.LittleEndian.PutUint32(valueData[:], *pi.Sequence)
			err := serializeKVPairWithType(
				w, uint8(SequenceInputType), nil,
				valueData[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.RequiredTimeLockTime != nil {
			var valueData [4]byte
			binary.LittleEndian.PutUint32(valueData[:], *pi.RequiredTimeLockTime)
			err := serializeKVPairWithType(
				w, uint8(RequiredTimeLocktimeInputType), nil,
				valueData[:],
			)
			if err != nil {
				return err
			}
		}

		if pi.RequiredHeightLockTime != nil {
			var valueData [4]byte
			binary.LittleEndian.PutUint32(valueData[:], *pi.RequiredHeightLockTime)
			err := serializeKVPairWithType(
				w, uint8(RequiredHeightLocktimeInputType), nil,
				valueData[:],
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

		if len(pi.MwebExtraData) > 0 {
			err := serializeKVPairWithType(w, uint8(MwebInputExtraDataType), nil, pi.MwebExtraData)
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

		// Every field round-trips; redacting the shared secret is a host
		// decision, not a serializer rule.
		if pi.MwebAddrDescriptor != nil {
			err := serializeKVPairWithType(
				w, uint8(MwebAddrDescriptorType), nil,
				pi.MwebAddrDescriptor,
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

		if pi.MwebKeyExchangePubkey != nil {
			err := serializeKVPairWithType(
				w, uint8(MwebKeyExchangePubKeyType), nil,
				pi.MwebKeyExchangePubkey[:],
			)
			if err != nil {
				return err
			}
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
