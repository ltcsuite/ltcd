package psbt

// BIP-0174 Combiner tests over the golden vectors: idempotent merges
// reproduce the pinned bytes, conflicts fail and leave the destination
// byte-identical, disjoint halves union in both orders, and the peg-in
// placeholder rules hold.

import (
	"bytes"
	"testing"

	"github.com/ltcsuite/ltcd/txscript"
	"github.com/stretchr/testify/require"
)

// Merging a packet with itself is a no-op reproducing the pinned bytes.
func TestCombineIdempotent(t *testing.T) {
	for _, name := range []string{
		"vector-mweb-signed.b64", "vector-pegin-signed.b64",
		"vector-pegout-signed.b64", "vector-mixed-signed.b64",
	} {
		t.Run(name, func(t *testing.T) {
			dst := parseVector(t, name)
			src := parseVector(t, name)
			require.NoError(t, dst.Combine(src))
			require.Equal(t, readVector(t, name), serializeBytes(t, dst))
		})
	}
}

// Two independently signed packets over the same structure conflict, and the
// failed combine leaves the destination byte-identical.
func TestCombineConflictUntouched(t *testing.T) {
	dst := parseVector(t, "vector-mweb-signed.b64")
	src := parseVector(t, "vector-mweb-signed-alt.b64")

	require.ErrorIs(t, dst.Combine(src), ErrCombineMismatch)
	require.Equal(t, readVector(t, "vector-mweb-signed.b64"), serializeBytes(t, dst))
}

// A conflict detected late (global offsets) must also leave the destination
// untouched: everything before the offsets merges cleanly.
func TestCombineLateConflictAtomic(t *testing.T) {
	dst := parseVector(t, "vector-mweb-signed.b64")
	src := parseVector(t, "vector-mweb-signed.b64")
	src.MwebTxOffset[0] ^= 0x01

	require.ErrorIs(t, dst.Combine(src), ErrCombineMismatch)
	require.Equal(t, readVector(t, "vector-mweb-signed.b64"), serializeBytes(t, dst))
}

// Disjoint halves of a signed packet union back to the pinned bytes in both
// merge orders.
func TestCombineDisjointHalves(t *testing.T) {
	makeHalves := func() (*Packet, *Packet) {
		a := parseVector(t, "vector-mweb-signed.b64")
		// Half A lacks the kernel signature and the global offsets.
		a.Kernels[0].Signature = nil
		a.MwebTxOffset = nil
		a.MwebStealthOffset = nil

		b := parseVector(t, "vector-mweb-signed.b64")
		// Half B lacks the input signature and its key material.
		b.Inputs[0].MwebInputSig = nil
		b.Inputs[0].MwebSharedSecret = nil
		return a, b
	}

	expected := readVector(t, "vector-mweb-signed.b64")

	a, b := makeHalves()
	require.NoError(t, a.Combine(b))
	require.Equal(t, expected, serializeBytes(t, a))

	a, b = makeHalves()
	require.NoError(t, b.Combine(a))
	require.Equal(t, expected, serializeBytes(t, b))
}

// A placeholder peg-in script is replaced by the finalized one in either
// merge order.
func TestCombinePeginPlaceholderReplaced(t *testing.T) {
	makePlaceholder := func() *Packet {
		p := parseVector(t, "vector-pegin-signed.b64")
		p.Outputs[0].PKScript = PeginPlaceholderScript()
		p.Kernels[0].Signature = nil
		p.MwebTxOffset = nil
		p.MwebStealthOffset = nil
		return p
	}
	final := readVector(t, "vector-pegin-signed.b64")

	dst := makePlaceholder()
	require.NoError(t, dst.Combine(parseVector(t, "vector-pegin-signed.b64")))
	require.Equal(t, final, serializeBytes(t, dst))

	dst = parseVector(t, "vector-pegin-signed.b64")
	require.NoError(t, dst.Combine(makePlaceholder()))
	require.Equal(t, final, serializeBytes(t, dst))
}

// The replacement is refused when the placeholder's side carries canonical
// signature data: those signatures committed to the placeholder script.
func TestCombinePeginPlaceholderWithBaseSigsFails(t *testing.T) {
	placeholder := parseVector(t, "vector-mixed-signed.b64")
	for i := range placeholder.Outputs {
		if isPeginScript(placeholder.Outputs[i].PKScript) {
			placeholder.Outputs[i].PKScript = PeginPlaceholderScript()
		}
	}
	// The canonical input keeps its final witness: base signature data on
	// the placeholder side.
	require.True(t, hasBaseSignatureData(placeholder))

	before := serializeBytes(t, placeholder)
	err := placeholder.Combine(parseVector(t, "vector-mixed-signed.b64"))
	require.ErrorIs(t, err, ErrCombineMismatch)
	require.Equal(t, before, serializeBytes(t, placeholder))
}

// After a merge involving MWEB signatures, the modifiable flags are cleared.
func TestCombineClearsModifiable(t *testing.T) {
	dst := parseVector(t, "vector-mweb-signed.b64")
	src := parseVector(t, "vector-mweb-signed.b64")
	modifiable := InputsModifiableFlag | OutputsModifiableFlag
	dst.TxModifiableFlag = &modifiable

	require.NoError(t, dst.Combine(src))
	require.NotNil(t, dst.TxModifiableFlag)
	require.EqualValues(t, 0, *dst.TxModifiableFlag)
}

// Structurally different packets never merge.
func TestCombineStructuralMismatch(t *testing.T) {
	dst := parseVector(t, "vector-mweb-signed.b64")
	src := parseVector(t, "vector-pegin-signed.b64")
	require.ErrorIs(t, dst.Combine(src), ErrCombineMismatch)
}

// The three taproot collections must dedup on their serialized keydata,
// keeping the first occurrence, per BIP-0174 Combiner keydata dedup.
func TestUnionTaprootDedup(t *testing.T) {
	a := &TaprootBip32Derivation{XOnlyPubKey: []byte{1}, MasterKeyFingerprint: 1}
	aDup := &TaprootBip32Derivation{XOnlyPubKey: []byte{1}, MasterKeyFingerprint: 99}
	b := &TaprootBip32Derivation{XOnlyPubKey: []byte{2}}
	merged := unionTaprootBip32(
		[]*TaprootBip32Derivation{a},
		[]*TaprootBip32Derivation{aDup, b},
	)
	require.Len(t, merged, 2)
	require.EqualValues(t, 1, merged[0].MasterKeyFingerprint) // keep-first

	s1 := &TaprootScriptSpendSig{XOnlyPubKey: []byte{1}, LeafHash: []byte{9}}
	s1Dup := &TaprootScriptSpendSig{XOnlyPubKey: []byte{1}, LeafHash: []byte{9}}
	s2 := &TaprootScriptSpendSig{XOnlyPubKey: []byte{1}, LeafHash: []byte{8}}
	sigs := unionTaprootScriptSpendSigs(
		[]*TaprootScriptSpendSig{s1},
		[]*TaprootScriptSpendSig{s1Dup, s2},
	)
	require.Len(t, sigs, 2) // same x-only but distinct leaf hash is a new key

	l1 := &TaprootTapLeafScript{ControlBlock: []byte{1}}
	l1Dup := &TaprootTapLeafScript{ControlBlock: []byte{1}}
	l2 := &TaprootTapLeafScript{ControlBlock: []byte{2}}
	leaves := unionTaprootLeafScripts(
		[]*TaprootTapLeafScript{l1},
		[]*TaprootTapLeafScript{l1Dup, l2},
	)
	require.Len(t, leaves, 2)
}

// Combining packets that share a taproot entry must dedup it, so the result
// still serializes to a reparseable PSBT.
func TestCombineDedupsTaproot(t *testing.T) {
	xonly := mustHex(t, validXOnly)
	inject := func(p *Packet) {
		tap := &TaprootBip32Derivation{
			XOnlyPubKey:          xonly,
			MasterKeyFingerprint: 0x01020304,
			Bip32Path:            []uint32{0x80000000, 1},
		}
		p.Inputs[0].TaprootBip32Derivation = []*TaprootBip32Derivation{tap}
		p.Outputs[0].TaprootBip32Derivation = []*TaprootBip32Derivation{tap}
	}

	parse := func() *Packet {
		raw := readVector(t, "vector-allfields.b64")
		p, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.NoError(t, err)
		require.False(t, p.Inputs[0].isMWEB())  // canonical input
		require.False(t, p.Outputs[0].isMWEB()) // canonical output
		inject(p)
		return p
	}

	dst, src := parse(), parse()
	require.NoError(t, dst.Combine(src))

	require.Len(t, dst.Inputs[0].TaprootBip32Derivation, 1)
	require.Len(t, dst.Outputs[0].TaprootBip32Derivation, 1)

	var buf bytes.Buffer
	require.NoError(t, dst.Serialize(&buf))
	_, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err) // reparse must not hit a duplicate key
}

// Two xpub entries that share the extended key but differ in origin must merge
// to one (the serialized key is the xpub), so the result still reparses.
func TestCombineDedupsXpubs(t *testing.T) {
	extKey, err := readExtendedKey(validXpubPayload(t))
	require.NoError(t, err)

	makePacket := func(fp uint32) *Packet {
		p := canonicalV2Packet()
		p.ExtPubKeys = []*GlobalExtPubKey{{
			ExtKey:      extKey,
			Fingerprint: fp,
			Path:        []uint32{fp},
		}}
		return p
	}

	dst := makePacket(1)
	require.NoError(t, dst.Combine(makePacket(2)))
	require.Len(t, dst.ExtPubKeys, 1)
	require.EqualValues(t, 1, dst.ExtPubKeys[0].Fingerprint) // keep-first

	var buf bytes.Buffer
	require.NoError(t, dst.Serialize(&buf))
	_, err = NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err) // no duplicate xpub key
}

// A one-sided sighash instruction must survive a combine (destination wins).
func TestCombineFillsSighash(t *testing.T) {
	dst := canonicalV2Packet()
	src := canonicalV2Packet()
	src.Inputs[0].SighashType = txscript.SigHashAll

	require.NoError(t, dst.Combine(src))
	require.Equal(t, txscript.SigHashAll, dst.Inputs[0].SighashType)
}
