package psbt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAllKernelFieldsPopulated(t *testing.T) {
	allFieldsPopulated := "01002108d0d2ced8b1fa04024f8f6e7ac54ac0e3d27932dfda9d91b571b7c4d3e7545e100101210391fda19029cb53b2a1b756a9237eaf8ffd2e0ccfb9e20e27f7d8ba54cb4ef61c0102081027000000000000010308204e0000000000000204000fa0860100000000000676a9142088ac0105049600000001060a657874726120646174610107403b65f41ae862b2b0fd55353f09bd7f6193c059d13c747fd39830ae8bb2d7d9372214e16b6d8aac4bcd05b3e157a75d8829cc23a2655944942937a1095df921be03fc00010b70726f707269657461727900"
	kernelBytes, _ := hex.DecodeString(allFieldsPopulated)

	var parsed PKernel
	if err := parsed.deserialize(bytes.NewReader(kernelBytes)); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	// TODO: Assert fields

	var buf bytes.Buffer
	if err := parsed.serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	if hex.EncodeToString(buf.Bytes()) != allFieldsPopulated {
		t.Fatalf("serialize failed, expected %s, got %s", allFieldsPopulated, hex.EncodeToString(buf.Bytes()))
	}
}

func TestKernelWithMultiplePegouts(t *testing.T) {
	multiplePegouts := "0204000fa0860100000000000676a9142088ac0204010f80841e00000000000676a9142088ac01074035b4ea690bc628a7539e4654a4f0904120596148bc28b08ac50f83a6b19a840a714dfb02e7e57979874c13328756d8bbc1f726e958121d6874b36b553f4682a103fc00010b70726f707269657461727900"
	kernelBytes, _ := hex.DecodeString(multiplePegouts)

	var parsed PKernel
	if err := parsed.deserialize(bytes.NewReader(kernelBytes)); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	// TODO: Assert fields

	var buf bytes.Buffer
	if err := parsed.serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	if hex.EncodeToString(buf.Bytes()) != multiplePegouts {
		t.Fatalf("serialize failed, expected %s, got %s", multiplePegouts, hex.EncodeToString(buf.Bytes()))
	}
}
