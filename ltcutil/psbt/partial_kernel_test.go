package psbt

import (
	"bytes"
	"encoding/hex"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/wire"
	"testing"
)

func TestAllKernelFieldsPopulated(t *testing.T) {
	allFieldsPopulated := "010021093d957d9c2a301532ffc9c11344e87ad252eccbac597bac6567ba38a2365bea14010121022a969b0465d5e8a24fc0659710925b534e82e81f7677a3012bb8d550dcff9f1c0102081027000000000000010308204e0000000000000204000fa0860100000000000676a9142088ac0204010f80841e00000000000676a9142088ac010504960000000106013f01070a65787472612064617461010840e12804f0a96165fbabeda93782cc0b79e92faab448d72e728dfba7fa82771f0f8195c80e5b8754f01cdf53fca8fe9820b15074d4ae5cfb01b5307c64c51f62cf03fc00010b70726f707269657461727900"
	kernelBytes, _ := hex.DecodeString(allFieldsPopulated)

	var pk PKernel
	if err := pk.deserialize(bytes.NewReader(kernelBytes)); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	expectedExcess, _ := hex.DecodeString("093d957d9c2a301532ffc9c11344e87ad252eccbac597bac6567ba38a2365bea14")
	if pk.ExcessCommitment == nil || !bytes.Equal(pk.ExcessCommitment[:], expectedExcess) {
		t.Fatalf("Excess commitment does not match expected")
	}

	expectedStealthExcess, _ := hex.DecodeString("022a969b0465d5e8a24fc0659710925b534e82e81f7677a3012bb8d550dcff9f1c")
	if pk.StealthExcess == nil || !bytes.Equal(pk.StealthExcess[:], expectedStealthExcess) {
		t.Fatalf("Stealth excess does not match expected")
	}

	expectedFee := ltcutil.Amount(10000)
	if pk.Fee == nil || *pk.Fee != expectedFee {
		t.Fatalf("Fee does not match expected")
	}

	expectedPegin := ltcutil.Amount(20000)
	if pk.PeginAmount == nil || *pk.PeginAmount != expectedPegin {
		t.Fatalf("Pegin amount does not match expected")
	}

	if len(pk.PegOuts) != 2 {
		t.Fatalf("Pegout count does not match expected")
	}

	pegout0Value := int64(100_000)
	pkScript0, _ := hex.DecodeString("76a9142088ac")
	if pk.PegOuts[0].Value != pegout0Value || !bytes.Equal(pk.PegOuts[0].PkScript, pkScript0) {
		t.Fatalf("Pegout[0] does not match expected")
	}

	pegout1Value := int64(2_000_000)
	pkScript1, _ := hex.DecodeString("76a9142088ac")
	if pk.PegOuts[1].Value != pegout1Value || !bytes.Equal(pk.PegOuts[1].PkScript, pkScript1) {
		t.Fatalf("Pegout[1] does not match expected")
	}

	expectedLockHeight := int32(150)
	if pk.LockHeight == nil || *pk.LockHeight != expectedLockHeight {
		t.Fatalf("LockHeight does not match expected")
	}

	expectedFeatures := wire.MwebKernelAllFeatureBits
	if pk.Features == nil || *pk.Features != expectedFeatures {
		t.Fatalf("Features does not match expected")
	}

	expectedExtraData, _ := hex.DecodeString("65787472612064617461")
	if pk.ExtraData == nil || !bytes.Equal(pk.ExtraData, expectedExtraData) {
		t.Fatalf("ExtraData does not match expected")
	}

	expectedSignature, _ := hex.DecodeString("e12804f0a96165fbabeda93782cc0b79e92faab448d72e728dfba7fa82771f0f8195c80e5b8754f01cdf53fca8fe9820b15074d4ae5cfb01b5307c64c51f62cf")
	if pk.Signature == nil || !bytes.Equal(pk.Signature[:], expectedSignature) {
		t.Fatalf("Signature does not match expected")
	}

	unknown0Key, _ := hex.DecodeString("fc0001")
	unknown0Value, _ := hex.DecodeString("70726f7072696574617279")
	if len(pk.Unknowns) != 1 || !bytes.Equal(pk.Unknowns[0].Key, unknown0Key) || !bytes.Equal(pk.Unknowns[0].Value, unknown0Value) {
		t.Fatalf("Unknowns does not match expected")
	}

	var buf bytes.Buffer
	if err := pk.serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	if hex.EncodeToString(buf.Bytes()) != allFieldsPopulated {
		t.Fatalf("serialize failed, expected %s, got %s", allFieldsPopulated, hex.EncodeToString(buf.Bytes()))
	}
}
