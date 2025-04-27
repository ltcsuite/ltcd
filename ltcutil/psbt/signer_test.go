package psbt

import (
    "encoding/binary"
    "github.com/ltcsuite/ltcd/chaincfg/chainhash"
    "github.com/ltcsuite/ltcd/ltcutil"
    "github.com/ltcsuite/ltcd/ltcutil/mweb"
    "github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
    "github.com/ltcsuite/ltcd/wire"
    "lukechampine.com/blake3"
    "math/big"
    "testing"
)

func generateUnsignedPInput(features wire.MwebInputFeatureBit, stealthAddress mw.StealthAddress) *PInput {
    amount := ltcutil.Amount(123456)
    senderKey, _ := mw.NewSecretKey()

    // Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
    n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])

    // Calculate unique sending key 's' = H(T_send, A, B, v, n)
    h := blake3.New(32, nil)
    _ = binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
    _, _ = h.Write(stealthAddress.A()[:])
    _, _ = h.Write(stealthAddress.B()[:])
    _ = binary.Write(h, binary.LittleEndian, uint64(amount))
    _, _ = h.Write(n.FillBytes(make([]byte, 16)))
    s := (*mw.SecretKey)(h.Sum(nil))

    // Derive shared secret 't' = H(T_derive, s*A)
    sA := stealthAddress.A().Mul(s)
    t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))

    // Construct one-time public key for receiver 'Ko' = H(T_outkey, t)*B
    Ko := stealthAddress.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))

    // Key exchange public key 'Ke' = s*B
    Ke := stealthAddress.B().Mul(s)

    // Calc blinding factor and mask nonce and amount
    mask := mw.OutputMaskFromShared(t)
    blind := mw.BlindSwitch(mask.Blind, uint64(amount))

    // Commitment 'C' = r*G + v*H
    outputCommit := mw.NewCommitment(blind, uint64(amount))

    var extradata []byte
    if features&wire.MwebInputExtraDataFeatureBit > 0 {
        extradata = []byte{0xaa, 0xbb, 0xcc}
    }

    var outputId chainhash.Hash
    tmp, _ := mw.NewSecretKey()
    copy(outputId[:], tmp[:])

    pi := PInput{
        MwebOutputId:          &outputId,
        MwebFeatures:          &features,
        MwebAmount:            &amount,
        MwebCommit:            outputCommit,
        MwebOutputPubkey:      Ko,
        MwebSharedSecret:      nil,
        MwebKeyExchangePubkey: Ke,
        MwebExtraData:         extradata,
    }
    return &pi
}

func generateUnsignedPOutput(features wire.MwebOutputMessageFeatureBit) *POutput {
    var extradata []byte
    if features&wire.MwebOutputMessageExtraDataFeatureBit > 0 {
        extradata = []byte{0xaa, 0xbb, 0xcc}
    }

    amount := ltcutil.Amount(345678)

    scanKey, _ := mw.NewSecretKey()
    spendKey, _ := mw.NewSecretKey()
    stealthAddress := mw.StealthAddress{Scan: scanKey.PubKey(), Spend: spendKey.PubKey()}

    po := POutput{
        Amount:             amount,
        StealthAddress:     &stealthAddress,
        OutputCommit:       nil,
        MwebFeatures:       &features,
        SenderPubkey:       nil,
        OutputPubkey:       nil,
        MwebStandardFields: nil,
        RangeProof:         nil,
        MwebSignature:      nil,
        MwebExtraData:      extradata,
    }
    return &po
}

func generateUnsignedPKernel(features wire.MwebKernelFeatureBit) *PKernel {
    var fee *ltcutil.Amount
    if features&wire.MwebKernelFeeFeatureBit > 0 {
        fee_amount := ltcutil.Amount(10000)
        fee = &fee_amount
    }
    var peginAmount *ltcutil.Amount
    if features&wire.MwebKernelPeginFeatureBit > 0 {
        pegin := ltcutil.Amount(20000)
        peginAmount = &pegin
    }
    var lockHeight *int32
    if features&wire.MwebKernelHeightLockFeatureBit > 0 {
        height := int32(40000)
        lockHeight = &height
    }
    var extradata []byte
    if features&wire.MwebKernelExtraDataFeatureBit > 0 {
        extradata = []byte{0xab, 0xcd, 0xef}
    }
    var pegouts []*wire.TxOut
    if features&wire.MwebKernelPegoutFeatureBit > 0 {
        pegouts = []*wire.TxOut{
            {
                Value:    100000,
                PkScript: []byte{0x76, 0xa9, 0x14, 0x20, 0x88, 0xac}, // basic P2PKH
            },
            {
                Value:    2000000,
                PkScript: []byte{0x76, 0xa9, 0x14, 0x20, 0x88, 0xac}, // basic P2PKH
            },
        }
    }

    pk := PKernel{
        Features:         &features,
        ExcessCommitment: nil,
        StealthExcess:    nil,
        Fee:              fee,
        PeginAmount:      peginAmount,
        LockHeight:       lockHeight,
        ExtraData:        extradata,
        Signature:        nil,
        PegOuts:          pegouts,
        Unknowns:         nil,
    }
    return &pk
}

func TestSignMwebComponents(t *testing.T) {
    scanKey, _ := mw.NewSecretKey()
    spendKey, _ := mw.NewSecretKey()
    mwebKeychain := mweb.Keychain{Scan: scanKey, Spend: spendKey}

    inputFeatures := wire.MwebInputStealthKeyFeatureBit
    pi := generateUnsignedPInput(inputFeatures, *mwebKeychain.Address(uint32(10)))

    outputFeatures := wire.MwebOutputMessageStandardFieldsFeatureBit
    po := generateUnsignedPOutput(outputFeatures)

    kernelFeatures := wire.MwebKernelStealthExcessFeatureBit | wire.MwebKernelFeeFeatureBit
    pk := generateUnsignedPKernel(kernelFeatures)

    packet := &Packet{
        PsbtVersion:       2,
        MwebTxOffset:      nil,
        MwebStealthOffset: nil,
        Inputs:            []PInput{*pi},
        Outputs:           []POutput{*po},
        Kernels:           []PKernel{*pk},
    }

    mwebInputSigner := BasicMwebInputSigner{
        Keychain:           &mwebKeychain,
        LookupAddressIndex: NaiveAddressLookup,
    }
    signer, err := NewSigner(packet, mwebInputSigner)
    if err != nil {
        t.Fatalf("NewSigner failed: %v", err)
    }

    outcome, err := signer.SignMwebComponents()
    if outcome != SignSuccesful || err != nil {
        t.Fatalf("SignMwebComponents failed: %v", err)
    }

    tx, err := Extract(packet)
    if tx == nil || err != nil {
        t.Fatalf("Extract failed: %v", err)
    }

    // TODO(dburkett) Verify all signatures.
}
