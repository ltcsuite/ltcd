package psbt

import (
	"bytes"
	"testing"

	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/secp256k1"
)

// buildFinalizedMwebOutput returns a POutput that is finalized (MwebSignature
// non-nil) and carries a StealthAddress plus every MWEB field required by
// isSane() for a signed output. Used to exercise the post-sign serialisation
// path.
func buildFinalizedMwebOutput(t *testing.T) *POutput {
	t.Helper()

	scanKey, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (scan) failed: %v", err)
	}
	spendKey, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (spend) failed: %v", err)
	}
	addr := &mw.StealthAddress{Scan: scanKey.PubKey(), Spend: spendKey.PubKey()}

	blind, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (blind) failed: %v", err)
	}
	commit := mw.NewCommitment((*mw.BlindingFactor)(blind), 12345)

	senderKey, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (sender) failed: %v", err)
	}
	outputPubKey, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (output pub) failed: %v", err)
	}
	keyExchangePubKey, err := mw.NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey (key exchange pub) failed: %v", err)
	}

	sig := mw.Sign(senderKey, []byte("regression-fixture"))

	features := wire.MwebOutputMessageStandardFieldsFeatureBit

	return &POutput{
		Amount:         ltcutil.Amount(12345),
		StealthAddress: addr,
		OutputCommit:   commit,
		MwebFeatures:   &features,
		SenderPubkey:   senderKey.PubKey(),
		OutputPubkey:   outputPubKey.PubKey(),
		MwebStandardFields: &standardMwebOutputFields{
			KeyExchangePubkey: *keyExchangePubKey.PubKey(),
			ViewTag:           0x12,
			EncryptedValue:    0xdeadbeef,
			EncryptedNonce:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
		RangeProof:    &secp256k1.RangeProof{},
		MwebSignature: &sig,
	}
}

// TestFinalizedMwebOutputStealthAddressSurvives is the §10.6a regression
// guard: a signed/finalized MWEB output MUST round-trip through serialize +
// deserialize with its StealthAddress intact. Without the patch, the
// serializer drops 0x90 once MwebSignature is populated and a consumer that
// rederives output pubkeys from (A, B) has nothing to compare against.
func TestFinalizedMwebOutputStealthAddressSurvives(t *testing.T) {
	po := buildFinalizedMwebOutput(t)
	origScan := po.StealthAddress.Scan
	origSpend := po.StealthAddress.Spend

	var buf bytes.Buffer
	if err := po.serialize(&buf, 2); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded POutput
	if err := decoded.deserialize(bytes.NewReader(buf.Bytes()), 2); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if decoded.MwebSignature == nil {
		t.Fatalf("MwebSignature missing after round-trip")
	}
	if decoded.StealthAddress == nil {
		t.Fatalf("StealthAddress dropped on serialization of finalized output")
	}
	if !bytes.Equal(decoded.StealthAddress.Scan[:], origScan[:]) {
		t.Fatalf("StealthAddress.Scan mismatch after round-trip")
	}
	if !bytes.Equal(decoded.StealthAddress.Spend[:], origSpend[:]) {
		t.Fatalf("StealthAddress.Spend mismatch after round-trip")
	}
}

// TestUnsignedMwebOutputStealthAddressSurvives exercises the pre-sign path
// to confirm the patch did not regress the previously-working case.
func TestUnsignedMwebOutputStealthAddressSurvives(t *testing.T) {
	po := buildFinalizedMwebOutput(t)
	// Drop all post-sign fields so isSane() treats this as an unsigned MWEB
	// output (StealthAddress only is sufficient).
	po.OutputCommit = nil
	po.MwebFeatures = nil
	po.SenderPubkey = nil
	po.OutputPubkey = nil
	po.MwebStandardFields = nil
	po.RangeProof = nil
	po.MwebSignature = nil
	origScan := po.StealthAddress.Scan
	origSpend := po.StealthAddress.Spend

	var buf bytes.Buffer
	if err := po.serialize(&buf, 2); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded POutput
	if err := decoded.deserialize(bytes.NewReader(buf.Bytes()), 2); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if decoded.StealthAddress == nil {
		t.Fatalf("StealthAddress dropped on serialization of unsigned output")
	}
	if !bytes.Equal(decoded.StealthAddress.Scan[:], origScan[:]) {
		t.Fatalf("StealthAddress.Scan mismatch after round-trip")
	}
	if !bytes.Equal(decoded.StealthAddress.Spend[:], origSpend[:]) {
		t.Fatalf("StealthAddress.Spend mismatch after round-trip")
	}
}
