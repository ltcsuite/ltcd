// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// signer encapsulates the role 'Signer' as specified in BIP174; it controls
// the insertion of signatures; the Sign() function will attempt to insert
// signatures using Updater.addPartialSignature, after first ensuring the Psbt
// is in the correct state.

import (
	"errors"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
)

// SignOutcome is a enum-like value that expresses the outcome of a call to the
// Sign method.
type SignOutcome int

const (
	// SignSuccesful indicates that the partial signature was successfully
	// attached.
	SignSuccesful = 0

	// SignFinalized  indicates that this input is already finalized, so the
	// provided signature was *not* attached
	SignFinalized = 1

	// SignInvalid indicates that the provided signature data was not valid.
	// In this case an error will also be returned.
	SignInvalid = -1
)

// Sign allows the caller to sign a PSBT at a particular input; they
// must provide a signature and a pubkey, both as byte slices; they can also
// optionally provide both witnessScript and/or redeemScript, otherwise these
// arguments must be set as nil (and in that case, they must already be present
// in the PSBT if required for signing to succeed).
//
// This serves as a wrapper around Updater.addPartialSignature; it ensures that
// the redeemScript and witnessScript are updated as needed (note that the
// Updater is allowed to add redeemScripts and witnessScripts independently,
// before signing), and ensures that the right form of utxo field
// (NonWitnessUtxo or WitnessUtxo) is included in the input so that signature
// insertion (and then finalization) can take place.
func (u *Updater) Sign(inIndex int, sig []byte, pubKey []byte,
	redeemScript []byte, witnessScript []byte) (SignOutcome, error) {

	pInput := u.Upsbt.Inputs[inIndex]
	if pInput.isFinalized() {
		return SignFinalized, nil
	}

	// Add the witnessScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if witnessScript != nil {
		err := u.AddInWitnessScript(witnessScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// Add the redeemScript to the PSBT in preparation.  If it already
	// exists, it will be overwritten.
	if redeemScript != nil {
		err := u.AddInRedeemScript(redeemScript, inIndex)
		if err != nil {
			return SignInvalid, err
		}
	}

	// At this point, the PSBT must have the requisite witnessScript or
	// redeemScript fields for signing to succeed.
	//
	// Case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	switch {
	case pInput.WitnessScript != nil:
		if pInput.WitnessUtxo == nil {
			err := nonWitnessToWitness(u.Upsbt, inIndex)
			if err != nil {
				return SignInvalid, err
			}
		}

		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 2: no witness script, only redeem script; can be legacy p2sh or
	// p2sh-wrapped p2wkh.
	case pInput.RedeemScript != nil:
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content.
		if txscript.IsWitnessProgram(redeemScript) {
			if pInput.WitnessUtxo == nil {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		// If it is not a valid witness program, we here assume that
		// the provided WitnessUtxo/NonWitnessUtxo field was correct.
		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}

	// Case 3: Neither provided only works for native p2wkh, or non-segwit
	// non-p2sh. To check if it's segwit, check the scriptPubKey of the
	// output.
	default:
		if pInput.WitnessUtxo == nil {
			txIn := u.Upsbt.UnsignedTx.TxIn[inIndex]
			outIndex := txIn.PreviousOutPoint.Index
			script := pInput.NonWitnessUtxo.TxOut[outIndex].PkScript

			if txscript.IsWitnessProgram(script) {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return SignInvalid, err
				}
			}
		}

		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return SignInvalid, err
		}
	}

	return SignSuccesful, nil
}

func buildCoinForMwebInput(input *PInput, keychain *mweb.Keychain) (*mweb.Coin, error) {
	if input.MwebAmount == nil {
		return nil, errors.New("input amount missing")
	} else if input.MwebOutputPubkey == nil {
		return nil, errors.New("spent output pubkey missing")
	} else if input.MwebSharedSecret == nil && input.MwebKeyExchangePubkey == nil {
		return nil, errors.New("input shared secret missing")
	}

	sharedSecret := input.MwebSharedSecret
	if sharedSecret == nil {
		sharedSecretPk := input.MwebOutputPubkey.Mul(keychain.Scan)
		sharedSecret = (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sharedSecretPk[:]))
	}

	addrB := input.MwebOutputPubkey.Div((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, sharedSecret[:])))
	addrA := addrB.Mul(keychain.Scan)
	address := mw.StealthAddress{Scan: addrA, Spend: addrB}

	var addrIdx *uint32
	// TODO: Do an actual lookup from a walletdb
	for i := uint32(0); i < uint32(1000); i++ {
		iAddr := keychain.Address(i)
		if (*iAddr) == address {
			addrIdx = &i
			break
		}
	}
	if addrIdx == nil {
		return nil, errors.New("address not found")
	}

	addrSpendKey := keychain.SpendKey(*addrIdx)
	outputSpendKey := addrSpendKey.Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, sharedSecret[:])))

	blind := (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, sharedSecret[:]))

	senderKey, err := mw.NewSecretKey()
	if err != nil {
		return nil, err
	}

	coin := &mweb.Coin{
		SpendKey:     outputSpendKey,
		Blind:        blind,
		Value:        uint64(*input.MwebAmount),
		OutputId:     input.MwebOutputId,
		SenderKey:    senderKey,
		Address:      &address,
		SharedSecret: sharedSecret,
	}
	return coin, nil
}

func addMwebSignatures(p *Packet) (SignOutcome, error) {
	// TODO: Check if already signed

	//var txOffset mw.BlindingFactor
	//var stealthOffset mw.BlindingFactor
	//var outputSigs [](int, mw.Signature)

	var recipients []*mweb.Recipient
	for _, output := range p.Outputs {
		if output.isMWEB() {
			recipients = append(recipients, &mweb.Recipient{Value: uint64(output.Amount), Address: output.StealthAddress})
		}
	}

	var coins []*mweb.Coin

	// To sign, all MWEB inputs need:
	// 1. Spent Output ID
	// 2. Amount
	// 3. Spent Output Pubkey (Ko)
	// 4. Master scan and master spend key info
	// 5. Shared secret OR key exchange pubkey (Ke)
	for _, input := range p.Inputs {
		if input.isMWEB() {
			if input.MwebMasterScanKey == nil || input.MwebMasterSpendKey == nil {
				return SignInvalid, errors.New("input master key derivation missing")
			}

			// TODO: Use actual master keys
			masterScanSecret, err := mw.NewSecretKey()
			if err != nil {
				return SignInvalid, err
			}
			masterSpendSecret, err := mw.NewSecretKey()
			if err != nil {
				return SignInvalid, err
			}
			keychain := mweb.Keychain{Scan: masterScanSecret, Spend: masterSpendSecret}

			coin, err := buildCoinForMwebInput(&input, &keychain)
			if err != nil {
				return SignInvalid, err
			}
			coins = append(coins, coin)
		}
	}

	fees := uint64(0)
	pegins := uint64(0)
	var pegouts []*wire.TxOut
	for _, kernel := range p.Kernels {
		if kernel.Fee != nil {
			fees += uint64(*kernel.Fee)
		}

		if kernel.PeginAmount != nil {
			pegins += uint64(*kernel.PeginAmount)
		}

		for _, pegout := range kernel.PegOuts {
			pegouts = append(pegouts, pegout)
		}
	}

	mwebTx, _, err := mweb.NewTransaction(coins, recipients, fees, pegins, pegouts)
	if err != nil {
		return SignInvalid, err
	}

	p.MwebTxOffset = &mwebTx.KernelOffset
	p.MwebStealthOffset = &mwebTx.StealthOffset
	// TODO: Finish updating components from values in mwebTx

	return SignSuccesful, nil
}

//func signMwebOutput(po *POutput, senderKey *mw.SecretKey)

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func nonWitnessToWitness(p *Packet, inIndex int) error {
	outIndex := p.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Index
	txout := p.Inputs[inIndex].NonWitnessUtxo.TxOut[outIndex]

	// TODO(guggero): For segwit v1, we'll want to remove the NonWitnessUtxo
	// from the packet. For segwit v0 it is unsafe to only rely on the
	// witness UTXO. See https://github.com/bitcoin/bitcoin/pull/19215.
	// p.Inputs[inIndex].NonWitnessUtxo = nil

	u := Updater{
		Upsbt: p,
	}

	return u.AddInWitnessUtxo(txout, inIndex)
}
