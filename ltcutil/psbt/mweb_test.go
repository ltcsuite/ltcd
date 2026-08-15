package psbt

// MWEB PSBT tests spanning parse, serialize, sign, combine, and extract:
// golden-vector round-trips, LIP-0007 field and ordering rules, the peg-in
// lifecycle, verification gates, and end-to-end signing workflows. The shared
// test helpers used across the MWEB test files live here.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/stretchr/testify/require"
)

// validXOnly is the secp256k1 generator's x-coordinate, a valid x-only pubkey
// accepted by validateXOnlyPubkey at parse time.
const validXOnly = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func validXpubPayload(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, BIP32_EXTKEY_WITH_VERSION_SIZE)
	copy(payload[0:4], []byte{0x04, 0x88, 0xB2, 0x1E})
	payload[4] = 3
	copy(payload[5:9], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint32(payload[9:13], 7)
	copy(payload[13:45], bytes.Repeat([]byte{0xAB}, 32))
	payload[45] = 0x02
	copy(payload[46:78], mustHex(t, validXOnly))
	return payload
}

// The golden vectors are the pinned serializations produced by the LIP-0007
// reference implementation's psbt_vectors.h. They carry real signatures and
// proofs and must never be regenerated; the tests assert byte-exact
// round-trips and cryptographic verification.
//
// Coverage: allfields = every LIP key-type, unsigned (deterministic builder);
// mweb-signed / mweb-signed-alt = fully signed MWEB-to-MWEB (alt is the
// merge-conflict twin); pegin-signed = zero-input peg-in with the finalized
// OP_9 script; pegout-signed = indexed peg-out kernel; mixed-signed = final
// canonical wpkh input whose witness commits to the rewritten peg-in script.

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	b64, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	require.NoError(t, err)
	return raw
}

func parseVector(t *testing.T, name string) *Packet {
	t.Helper()
	raw := readVector(t, name)
	p, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	return p
}

func serializeBytes(t *testing.T, p *Packet) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	return buf.Bytes()
}

// roundTrip serializes p and parses it back.
func roundTrip(t *testing.T, p *Packet) *Packet {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	parsed, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err)
	return parsed
}

// canonicalV2Packet returns a minimal MWEB-less v2 packet.
func canonicalV2Packet() *Packet {
	prevHash := chainhash.Hash{1}
	prevIndex := uint32(0)
	return &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs: []PInput{{
			PrevoutHash:  &prevHash,
			PrevoutIndex: &prevIndex,
		}},
		Outputs: []POutput{{
			Amount:   1000,
			PKScript: []byte{0x00, 0x14, 0x99},
		}},
	}
}

func mwebInput(amount ltcutil.Amount) PInput {
	outputId := chainhash.Hash{7}
	return PInput{
		MwebOutputId: &outputId,
		MwebAmount:   &amount,
	}
}

func mwebOutput(amount ltcutil.Amount) POutput {
	scanKey, _ := mw.NewSecretKey()
	spendKey, _ := mw.NewSecretKey()
	return POutput{
		Amount: amount,
		StealthAddress: &mw.StealthAddress{
			Scan: scanKey.PubKey(), Spend: spendKey.PubKey(),
		},
	}
}

func feeKernel(fee ltcutil.Amount) PKernel {
	return PKernel{Fee: &fee}
}

func peginKernel(fee, pegin ltcutil.Amount) PKernel {
	return PKernel{Fee: &fee, PeginAmount: &pegin}
}

// serializeWithInputKey re-serializes p with the last input's descriptor
// replaced by an arbitrary key-value pair injected into that input's map.
func serializeWithInputKey(t *testing.T, p *Packet, keyType uint8,
	value []byte) []byte {

	t.Helper()
	saved := p.Inputs[len(p.Inputs)-1].MwebAddrDescriptor
	p.Inputs[len(p.Inputs)-1].MwebAddrDescriptor = nil
	p.Inputs[len(p.Inputs)-1].Unknowns = []*Unknown{{
		Key: []byte{keyType}, Value: value,
	}}
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	p.Inputs[len(p.Inputs)-1].MwebAddrDescriptor = saved
	p.Inputs[len(p.Inputs)-1].Unknowns = nil
	return buf.Bytes()
}

// keychainDeriver returns a DeriveOutputKeys closure over a test keychain.
func keychainDeriver(keychain *mweb.Keychain, addrIdx uint32) OutputKeyDerivationFunc {
	return func(spentOutputPk *mw.PublicKey, keyExchangePubKey *mw.PublicKey,
		sharedSecret *mw.SecretKey) (*mw.BlindingFactor, *mw.SecretKey, error) {

		secret := sharedSecret
		if secret == nil {
			sharedSecretPk := keyExchangePubKey.Mul(keychain.Scan)
			secret = (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sharedSecretPk[:]))
		}
		preBlind := (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, secret[:]))
		spendKey := keychain.SpendKey(addrIdx).
			Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, secret[:])))
		return preBlind, spendKey, nil
	}
}

func TestGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signed bool
	}{
		{"vector-allfields.b64", false},
		{"vector-mweb-signed.b64", true},
		{"vector-mweb-signed-alt.b64", true},
		{"vector-pegin-signed.b64", true},
		{"vector-pegout-signed.b64", true},
		{"vector-mixed-signed.b64", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readVector(t, tc.name)

			p, err := NewFromRawBytes(bytes.NewReader(raw), false)
			require.NoError(t, err)

			// Re-serialization must reproduce the pinned vector bytes.
			var buf bytes.Buffer
			require.NoError(t, p.Serialize(&buf))
			require.Equal(t, raw, buf.Bytes())

			if !tc.signed {
				return
			}

			// The signed vectors are complete and carry signatures and
			// proofs that must verify.
			require.True(t, p.IsComplete())
			_, err = verifyMwebComponents(p)
			require.NoError(t, err)

			// And they extract to a broadcastable transaction.
			tx, err := Extract(p)
			require.NoError(t, err)
			require.NotNil(t, tx.Mweb)
		})
	}
}

func TestInvalidVectors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reason  string
		wantErr error
	}{
		{"invalid-1.b64", "MWEB tx offset in a v0 packet", ErrUnsupportedFieldInPsbtVersion},
		{"invalid-2.b64", "MWEB stealth offset in a v0 packet", ErrUnsupportedFieldInPsbtVersion},
		{"invalid-3.b64", "kernel pegout key without its index", ErrInvalidKeyData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readVector(t, tc.name)
			_, err := NewFromRawBytes(bytes.NewReader(raw), false)
			require.ErrorIs(t, err, tc.wantErr, tc.reason)
		})
	}
}

// sortKernels must order by net supply (pegin - fee - pegouts) descending.
func TestSortKernelsSupplyOrder(t *testing.T) {
	mk := func(pegin, fee uint64, pegout int64, tag byte) *wire.MwebKernel {
		k := &wire.MwebKernel{Fee: fee, Pegin: pegin}
		k.Excess[1] = tag
		if pegout > 0 {
			k.Pegouts = []*wire.TxOut{{Value: pegout, PkScript: []byte{0x51}}}
		}
		return k
	}
	a := mk(1000, 10, 0, 0x01) // supply 990
	c := mk(700, 0, 200, 0x02) // supply 500 (exercises the pegout subtraction)
	b := mk(100, 10, 0, 0x03)  // supply 90

	kernels := []*wire.MwebKernel{b, c, a}
	sortKernels(kernels)

	require.Same(t, a, kernels[0])
	require.Same(t, c, kernels[1])
	require.Same(t, b, kernels[2])
}

// InPlaceSort must refuse MWEB packets: BIP-69 amount ordering would break the
// canonical-before-MWEB map order and the positional peg-in/kernel pairing.
func TestInPlaceSortRefusesMweb(t *testing.T) {
	raw := readVector(t, "vector-mweb-signed.b64")
	p, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.ErrorIs(t, InPlaceSort(p), ErrMwebSortUnsupported)
}

// Finalize (a public entry point) must refuse a packet whose MWEB components
// are not yet signed, so it cannot commit canonical signatures to a still
// placeholder peg-in script.
func TestFinalizeRefusesUnsignedMweb(t *testing.T) {
	of := wire.MwebOutputMessageFeatureBit(0)
	p := &Packet{
		PsbtVersion: 2,
		Inputs:      []PInput{{}},
		Outputs: []POutput{{
			MwebFeatures: &of,
			OutputCommit: &mw.Commitment{}, // isMWEB, but not finalized
		}},
	}
	require.ErrorIs(t, Finalize(p, 0), ErrMwebComponentsNotSigned)
}

// isFinalized must require the input pubkey exactly when the stealth-key bit is
// set: a bit-clear pubkey has no wire representation and would unbalance the
// extracted transaction against the LIP-0007 stealth-sum check.
func TestIsFinalizedStealthKeyBitAgreement(t *testing.T) {
	build := func(features wire.MwebInputFeatureBit, withPubkey bool) *PInput {
		f := features
		pi := &PInput{
			MwebOutputId:     &chainhash.Hash{},
			MwebInputSig:     &mw.Signature{},
			MwebFeatures:     &f,
			MwebCommit:       &mw.Commitment{},
			MwebOutputPubkey: &mw.PublicKey{},
		}
		if withPubkey {
			pi.MwebInputPubkey = &mw.PublicKey{}
		}
		return pi
	}

	require.True(t, build(0, false).isFinalized())
	require.True(t, build(wire.MwebInputStealthKeyFeatureBit, true).isFinalized())
	require.False(t, build(0, true).isFinalized())
	require.False(t, build(wire.MwebInputStealthKeyFeatureBit, false).isFinalized())
}

// The explicit input amount is optional (omitted from the completeness rules),
// so a complete signed packet with its amounts cleared must still extract; the
// commitment balance is authoritative. The strict check stays only for signing.
func TestExtractToleratesMissingInputAmount(t *testing.T) {
	raw := readVector(t, "vector-mweb-signed.b64")

	base, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	_, err = Extract(base)
	require.NoError(t, err) // baseline: extracts with amounts present

	p, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	cleared := false
	for i := range p.Inputs {
		if p.Inputs[i].isMWEB() && p.Inputs[i].MwebAmount != nil {
			p.Inputs[i].MwebAmount = nil
			cleared = true
		}
	}
	require.True(t, cleared, "vector must carry an explicit input amount to clear")

	require.True(t, p.IsComplete()) // amount is not part of completeness
	_, err = Extract(p)
	require.NoError(t, err)
}

// The kernel-count global is omitted for kernel-less packets and required
// reading is driven by it when kernels are present.
func TestKernelCountPresence(t *testing.T) {
	// Kernel-less: the 0x92 key must not appear on the wire.
	p := canonicalV2Packet()
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	serialized := buf.Bytes()
	require.NotContains(t, string(serialized), string([]byte{0x01, 0x92}))

	// And a conforming packet without the key parses.
	parsed, err := NewFromRawBytes(bytes.NewReader(serialized), false)
	require.NoError(t, err)
	require.Len(t, parsed.Kernels, 0)

	// With kernels the key round-trips and the maps are read back.
	p = canonicalV2Packet()
	p.Inputs = []PInput{mwebInput(1000)}
	p.Outputs = nil
	p.Kernels = []PKernel{feeKernel(1000)}
	parsed = roundTrip(t, p)
	require.Len(t, parsed.Kernels, 1)
	require.Equal(t, ltcutil.Amount(1000), *parsed.Kernels[0].Fee)
}

// MWEB maps must come after all canonical maps in their section.
func TestMwebOrderingEnforced(t *testing.T) {
	p := canonicalV2Packet()
	p.Inputs = []PInput{mwebInput(1000), p.Inputs[0]} // MWEB before canonical
	var buf bytes.Buffer
	require.Error(t, p.Serialize(&buf))
	require.Error(t, p.SanityCheck())

	p = canonicalV2Packet()
	p.Outputs = []POutput{mwebOutput(500), p.Outputs[0]}
	require.Error(t, p.SanityCheck())
}

// A packet holding MWEB components cannot be represented as v0.
func TestSerializeRefusesV0Mweb(t *testing.T) {
	p := &Packet{
		PsbtVersion: 0,
		UnsignedTx:  wire.NewMsgTx(2),
		Kernels:     []PKernel{feeKernel(1)},
	}
	var buf bytes.Buffer
	require.Error(t, p.Serialize(&buf))
}

// The 0x96 value is an ASCII mweb(...) descriptor; a 4-byte legacy address
// index is silently ignored; anything else is rejected.
func TestAddrDescriptor(t *testing.T) {
	descriptor := []byte("mweb(xpub.../0/1)")
	p := canonicalV2Packet()
	p.Inputs = append(p.Inputs, mwebInput(1000))
	p.Inputs[1].MwebAddrDescriptor = descriptor
	p.Outputs = nil
	p.Kernels = []PKernel{feeKernel(1000)}

	parsed := roundTrip(t, p)
	require.Equal(t, descriptor, parsed.Inputs[1].MwebAddrDescriptor)

	// Legacy 4-byte address index: ignored, not an error.
	serialized := serializeWithInputKey(t, p, uint8(MwebAddrDescriptorType),
		[]byte{1, 0, 0, 0})
	parsed, err := NewFromRawBytes(bytes.NewReader(serialized), false)
	require.NoError(t, err)
	require.Nil(t, parsed.Inputs[1].MwebAddrDescriptor)

	// Neither 4 bytes nor a descriptor: rejected.
	serialized = serializeWithInputKey(t, p, uint8(MwebAddrDescriptorType),
		[]byte("not-a-descriptor"))
	_, err = NewFromRawBytes(bytes.NewReader(serialized), false)
	require.Error(t, err)
}

// Reserved input keys 0x9A/0x9B and multi-byte key types survive as unknowns.
func TestReservedAndWideKeysPreserved(t *testing.T) {
	p := canonicalV2Packet()
	p.Inputs = append(p.Inputs, mwebInput(1000))
	p.Outputs = nil
	p.Kernels = []PKernel{feeKernel(1000)}

	// 0x9A with empty keydata, and a two-byte key type 0x0190.
	var wideKey bytes.Buffer
	_ = wire.WriteVarInt(&wideKey, 0, 0x0190)
	p.Inputs[1].Unknowns = []*Unknown{
		{Key: []byte{0x9A}, Value: []byte{0x01}},
		{Key: wideKey.Bytes(), Value: []byte{0x02}},
	}

	parsed := roundTrip(t, p)
	require.Len(t, parsed.Inputs[1].Unknowns, 2)
	require.Equal(t, p.Inputs[1].Unknowns[0], parsed.Inputs[1].Unknowns[0])
	require.Equal(t, p.Inputs[1].Unknowns[1], parsed.Inputs[1].Unknowns[1])

	// A second round-trip must be byte-identical.
	var first, second bytes.Buffer
	require.NoError(t, parsed.Serialize(&first))
	reparsed, err := NewFromRawBytes(bytes.NewReader(first.Bytes()), false)
	require.NoError(t, err)
	require.NoError(t, reparsed.Serialize(&second))
	require.Equal(t, first.Bytes(), second.Bytes())
}

// Peg-out records are keyed by compact-size index: order in the map is not
// authoritative, gaps and empty scripts are invalid.
func TestPegoutIndexes(t *testing.T) {
	script := []byte{0x00, 0x14, 0x55}
	makePacket := func(indexes []uint64) []byte {
		var buf bytes.Buffer
		buf.Write(psbtMagic[:])
		_ = serializeKVPairWithType(&buf, uint8(VersionType), nil, []byte{2, 0, 0, 0})
		_ = serializeKVPairWithType(&buf, uint8(TxVersionType), nil, []byte{2, 0, 0, 0})
		_ = serializeKVPairWithType(&buf, uint8(InputCountType), nil, []byte{1})
		_ = serializeKVPairWithType(&buf, uint8(OutputCountType), nil, []byte{0})
		_ = serializeKVPairWithType(&buf, uint8(MwebKernelCountType), nil, []byte{1})
		buf.WriteByte(0x00)

		// One MWEB input map.
		outputId := chainhash.Hash{7}
		_ = serializeKVPairWithType(&buf, uint8(MwebSpentOutputIdType), nil, outputId[:])
		buf.WriteByte(0x00)

		// The hand-built kernel map.
		_ = serializeKVPairWithType(&buf, uint8(MwebKernelFeeType), nil,
			binary.LittleEndian.AppendUint64(nil, 1000))
		for _, index := range indexes {
			var keyData, value bytes.Buffer
			_ = wire.WriteVarInt(&keyData, 0, index)
			value.Write(binary.LittleEndian.AppendUint64(nil, 5000+index))
			_ = wire.WriteVarBytes(&value, 0, script)
			_ = serializeKVPairWithType(&buf, uint8(MwebKernelPegoutType),
				keyData.Bytes(), value.Bytes())
		}
		buf.WriteByte(0x00)
		return buf.Bytes()
	}

	// Out-of-order indexes are reassembled by index, not stream order.
	parsed, err := NewFromRawBytes(bytes.NewReader(makePacket([]uint64{1, 0})), false)
	require.NoError(t, err)
	require.Len(t, parsed.Kernels[0].PegOuts, 2)
	require.Equal(t, int64(5000), parsed.Kernels[0].PegOuts[0].Value)
	require.Equal(t, int64(5001), parsed.Kernels[0].PegOuts[1].Value)

	// A gap is rejected.
	_, err = NewFromRawBytes(bytes.NewReader(makePacket([]uint64{0, 2})), false)
	require.Error(t, err)
}

// A features byte inconsistent with the populated fields is rejected.
func TestKernelFeatureConsistency(t *testing.T) {
	fee := ltcutil.Amount(1000)
	features := wire.MwebKernelPeginFeatureBit // pegin bit, but only fee set
	p := canonicalV2Packet()
	p.Inputs = []PInput{mwebInput(1000)}
	p.Outputs = nil
	p.Kernels = []PKernel{{Fee: &fee, Features: &features}}
	require.Error(t, p.SanityCheck())

	correct := wire.MwebKernelFeeFeatureBit
	p.Kernels[0].Features = &correct
	require.NoError(t, p.SanityCheck())
}

// Only the offsets that are set are serialized, each under its own key.
func TestOffsetSerialization(t *testing.T) {
	txOffset := mw.BlindingFactor{1}
	stealthOffset := mw.BlindingFactor{2}

	for _, tc := range []struct {
		name          string
		txOffset      *mw.BlindingFactor
		stealthOffset *mw.BlindingFactor
	}{
		{"both", &txOffset, &stealthOffset},
		{"tx only", &txOffset, nil},
		{"stealth only", nil, &stealthOffset},
		{"neither", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := canonicalV2Packet()
			p.MwebTxOffset = tc.txOffset
			p.MwebStealthOffset = tc.stealthOffset
			parsed := roundTrip(t, p)
			require.Equal(t, tc.txOffset, parsed.MwebTxOffset)
			require.Equal(t, tc.stealthOffset, parsed.MwebStealthOffset)
		})
	}
}

// GetTxFee covers v0-style canonical, pure-MWEB, peg-in, and peg-out shapes.
func TestGetTxFeeV2(t *testing.T) {
	canonicalIn := func(value int64) PInput {
		prevHash := chainhash.Hash{3}
		prevIndex := uint32(0)
		return PInput{
			PrevoutHash:  &prevHash,
			PrevoutIndex: &prevIndex,
			WitnessUtxo:  &wire.TxOut{Value: value},
		}
	}

	// Canonical-only: inputs - outputs.
	p := canonicalV2Packet()
	p.Inputs = []PInput{canonicalIn(5000)}
	p.Outputs[0].Amount = 4600
	fee, err := p.GetTxFee()
	require.NoError(t, err)
	require.Equal(t, ltcutil.Amount(400), fee)

	// Pure MWEB: the kernel fee alone.
	p = canonicalV2Packet()
	p.Inputs = []PInput{mwebInput(100000)}
	p.Outputs = []POutput{mwebOutput(99000)}
	p.Kernels = []PKernel{feeKernel(1000)}
	fee, err = p.GetTxFee()
	require.NoError(t, err)
	require.Equal(t, ltcutil.Amount(1000), fee)

	// Peg-in: canonical surplus funds the peg-in output; kernel fee on top.
	// The MWEB side balances: pegin 9000 = output 8500 + fee 500.
	p = canonicalV2Packet()
	p.Inputs = []PInput{canonicalIn(10000)}
	p.Outputs = []POutput{
		{Amount: 9000, PKScript: PeginPlaceholderScript()},
		mwebOutput(8500),
	}
	p.Kernels = []PKernel{peginKernel(500, 9000)}
	fee, err = p.GetTxFee()
	require.NoError(t, err)
	require.Equal(t, ltcutil.Amount(1500), fee)

	// Peg-out: MWEB inputs leave via the kernel; fee is the kernel fee.
	p = canonicalV2Packet()
	p.Inputs = []PInput{mwebInput(50000)}
	p.Outputs = nil
	pegoutKernel := feeKernel(700)
	pegoutKernel.PegOuts = []*wire.TxOut{{Value: 49300, PkScript: []byte{0x51}}}
	p.Kernels = []PKernel{pegoutKernel}
	fee, err = p.GetTxFee()
	require.NoError(t, err)
	require.Equal(t, ltcutil.Amount(700), fee)
}

// The full peg-in lifecycle: placeholder written by the creator, rewritten to
// the kernel ID by the MWEB signer, extracted exactly once.
func TestPeginPlaceholderLifecycle(t *testing.T) {
	pegin := ltcutil.Amount(50000)
	fee := ltcutil.Amount(1000)
	po := generateUnsignedPOutput(wire.MwebOutputMessageStandardFieldsFeatureBit)
	po.Amount = pegin - fee

	prevHash := chainhash.Hash{9}
	prevIndex := uint32(1)
	packet := &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs: []PInput{{
			PrevoutHash:  &prevHash,
			PrevoutIndex: &prevIndex,
			WitnessUtxo:  &wire.TxOut{Value: int64(pegin) + 200},
		}},
		Outputs: []POutput{
			{Amount: pegin, PKScript: PeginPlaceholderScript()},
			*po,
		},
		Kernels: []PKernel{peginKernel(fee, pegin)},
	}
	modifiable := InputsModifiableFlag | OutputsModifiableFlag
	packet.TxModifiableFlag = &modifiable

	signer, err := NewSigner(packet, BasicMwebInputSigner{})
	require.NoError(t, err)

	outcome, err := signer.SignMwebComponents()
	require.NoError(t, err)
	require.EqualValues(t, SignSuccesful, outcome)

	// The placeholder is rewritten to the finalized kernel's ID.
	script := packet.Outputs[0].PKScript
	require.True(t, isPeginScript(script))
	require.False(t, isPeginPlaceholder(script))
	kernel, err := extractKernel(&packet.Kernels[0])
	require.NoError(t, err)
	require.Equal(t, kernel.Hash()[:], script[2:])

	// The modifiable flags are cleared.
	require.NotNil(t, packet.TxModifiableFlag)
	require.Equal(t, TxModifiableFlag(0), *packet.TxModifiableFlag)

	// The unsigned tx carries the same output set: nothing appended.
	unsigned, err := ExtractUnsignedTx(packet)
	require.NoError(t, err)
	require.Len(t, unsigned.TxOut, 1)
	require.Equal(t, script, unsigned.TxOut[0].PkScript)
	require.Equal(t, int64(pegin), unsigned.TxOut[0].Value)
}

// A peg-in kernel without its canonical output (or with the wrong amount)
// does not sign.
func TestPeginAssociationErrors(t *testing.T) {
	pegin := ltcutil.Amount(50000)
	fee := ltcutil.Amount(1000)
	newPacket := func() *Packet {
		po := generateUnsignedPOutput(wire.MwebOutputMessageStandardFieldsFeatureBit)
		po.Amount = pegin - fee
		return &Packet{
			PsbtVersion: 2,
			TxVersion:   2,
			Outputs: []POutput{
				{Amount: pegin, PKScript: PeginPlaceholderScript()},
				*po,
			},
			Kernels: []PKernel{peginKernel(fee, pegin)},
		}
	}
	newSigner := func(p *Packet) *Signer {
		s, err := NewSigner(p, BasicMwebInputSigner{})
		require.NoError(t, err)
		return s
	}

	// Missing placeholder output.
	p := newPacket()
	p.Outputs = p.Outputs[1:]
	_, err := newSigner(p).SignMwebComponents()
	require.Error(t, err)

	// Amount mismatch.
	p = newPacket()
	p.Outputs[0].Amount--
	p.Outputs[1].Amount++
	_, err = newSigner(p).SignMwebComponents()
	require.Error(t, err)

	// Unbalanced MWEB amounts.
	p = newPacket()
	p.Outputs[1].Amount--
	_, err = newSigner(p).SignMwebComponents()
	require.Error(t, err)
}

// Canonical signatures cannot be added while MWEB components are unsigned,
// and MWEB signing refuses to run over existing canonical signatures.
func TestMwebBeforeCanonicalOrdering(t *testing.T) {
	prevHash := chainhash.Hash{4}
	prevIndex := uint32(0)
	p := &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs: []PInput{{
			PrevoutHash:  &prevHash,
			PrevoutIndex: &prevIndex,
			WitnessUtxo:  &wire.TxOut{Value: 2000, PkScript: []byte{0x00, 0x14, 0x99}},
		}, mwebInput(1000)},
		Kernels: []PKernel{feeKernel(1000)},
	}

	u, err := NewUpdater(p)
	require.NoError(t, err)
	outcome, err := u.Sign(0, []byte{0x30, 0x01}, []byte{0x02}, nil, nil)
	require.EqualValues(t, SignInvalid, outcome)
	require.ErrorIs(t, err, ErrMwebComponentsNotSigned)

	// And the reverse: a canonical partial signature blocks MWEB signing.
	p.Inputs[0].PartialSigs = []*PartialSig{{}}
	signer, err := NewSigner(p, BasicMwebInputSigner{})
	require.NoError(t, err)
	_, err = signer.SignMwebComponents()
	require.Error(t, err)
}

// A tampered component signature fails extraction.
func TestExtractRejectsTamperedSignature(t *testing.T) {
	masterScanKey, _ := mw.NewSecretKey()
	masterSpendKey, _ := mw.NewSecretKey()
	keychain := mweb.Keychain{Scan: masterScanKey, Spend: masterSpendKey}

	fee := ltcutil.Amount(1000)
	amount := ltcutil.Amount(50000)
	addrIdx := uint32(2)
	pi := generateUnsignedPInput(wire.MwebInputStealthKeyFeatureBit,
		*keychain.Address(addrIdx))
	*pi.MwebAmount = amount
	pi.MwebCommit = nil // fixture commit was built for its original amount
	po := generateUnsignedPOutput(wire.MwebOutputMessageStandardFieldsFeatureBit)
	po.Amount = amount - fee

	packet := &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs:      []PInput{*pi},
		Outputs:     []POutput{*po},
		Kernels:     []PKernel{{Fee: &fee}},
	}

	deriveOutputKeys := func(spentOutputPk *mw.PublicKey,
		keyExchangePubKey *mw.PublicKey, sharedSecret *mw.SecretKey) (
		*mw.BlindingFactor, *mw.SecretKey, error) {

		sharedSecretPk := keyExchangePubKey.Mul(keychain.Scan)
		secret := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sharedSecretPk[:]))
		preBlind := (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, secret[:]))
		spendKey := keychain.SpendKey(addrIdx).
			Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, secret[:])))
		return preBlind, spendKey, nil
	}

	signer, err := NewSigner(packet, BasicMwebInputSigner{DeriveOutputKeys: deriveOutputKeys})
	require.NoError(t, err)
	_, err = signer.SignMwebComponents()
	require.NoError(t, err)

	// Untampered: extracts.
	_, err = Extract(packet)
	require.NoError(t, err)

	// Tampered input signature: refused.
	packet.Inputs[0].MwebInputSig[0] ^= 0x01
	_, err = Extract(packet)
	require.Error(t, err)
	packet.Inputs[0].MwebInputSig[0] ^= 0x01

	// Tampered kernel fee breaks the balance equation.
	*packet.Kernels[0].Fee++
	_, err = Extract(packet)
	require.Error(t, err)
	*packet.Kernels[0].Fee--

	// A substituted stealth offset breaks the stealth sums equation even
	// though every signature and proof still verifies.
	savedOffset := *packet.MwebStealthOffset
	packet.MwebStealthOffset[0] ^= 0x01
	_, err = Extract(packet)
	require.Error(t, err)
	*packet.MwebStealthOffset = savedOffset

	_, err = Extract(packet)
	require.NoError(t, err)
}

// A crafted global packet — the version key after MWEB keys, with no unsigned
// tx — must error, not panic.
func TestVersionAfterMwebKeysNoPanic(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(psbtMagic[:])
	writeKV := func(keyType uint8, value []byte) {
		_ = serializeKVPairWithType(&buf, keyType, nil, value)
	}
	writeKV(uint8(TxVersionType), []byte{2, 0, 0, 0})
	writeKV(uint8(InputCountType), []byte{0})
	writeKV(uint8(OutputCountType), []byte{0})
	writeKV(uint8(MwebKernelCountType), []byte{0})
	writeKV(uint8(VersionType), []byte{0, 0, 0, 0}) // v0 after v2-only keys
	buf.WriteByte(0x00)

	_, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.Error(t, err)
}

// A v2 packet embedding an unsigned transaction is invalid.
func TestUnsignedTxRejectedInV2(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{})
	var txBuf bytes.Buffer
	require.NoError(t, tx.SerializeNoWitness(&txBuf))

	var buf bytes.Buffer
	buf.Write(psbtMagic[:])
	_ = serializeKVPairWithType(&buf, uint8(UnsignedTxType), nil, txBuf.Bytes())
	_ = serializeKVPairWithType(&buf, uint8(VersionType), nil, []byte{2, 0, 0, 0})
	buf.WriteByte(0x00)
	buf.WriteByte(0x00) // input map
	buf.WriteByte(0x00) // output map

	_, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.Error(t, err)
}

// Spot-checks of decoded allfields vector field values.
func TestGoldenAllfieldsValues(t *testing.T) {
	p := parseVector(t, "vector-allfields.b64")

	require.Len(t, p.Inputs, 2)
	require.Len(t, p.Outputs, 2)
	require.Len(t, p.Kernels, 1)

	in := p.Inputs[1]
	require.NotNil(t, in.MwebOutputId)
	require.Equal(t, []byte("mweb(test)"), in.MwebAddrDescriptor)
	require.NotNil(t, in.MwebSharedSecret)

	out := p.Outputs[1]
	require.NotNil(t, out.StealthAddress)
	require.NotNil(t, out.RangeProof)

	kernel := p.Kernels[0]
	require.Len(t, kernel.PegOuts, 2)
	require.Equal(t, int64(600), kernel.PegOuts[0].Value)
	require.Equal(t, int64(700), kernel.PegOuts[1].Value)

	require.NotNil(t, p.MwebTxOffset)
	require.NotNil(t, p.MwebStealthOffset)
	require.True(t, p.HasMwebComponents())
}

// Clearing each optional MWEB field must still round-trip, pinning the
// absence encodings.
func TestGoldenFieldSubsetRoundtrip(t *testing.T) {
	clearers := map[string]func(*Packet){
		"input-commit":       func(p *Packet) { p.Inputs[1].MwebCommit = nil },
		"input-output-pk":    func(p *Packet) { p.Inputs[1].MwebOutputPubkey = nil },
		"input-input-pk":     func(p *Packet) { p.Inputs[1].MwebInputPubkey = nil },
		"input-features":     func(p *Packet) { p.Inputs[1].MwebFeatures = nil },
		"input-sig":          func(p *Packet) { p.Inputs[1].MwebInputSig = nil },
		"input-descriptor":   func(p *Packet) { p.Inputs[1].MwebAddrDescriptor = nil },
		"input-amount":       func(p *Packet) { p.Inputs[1].MwebAmount = nil },
		"input-secret":       func(p *Packet) { p.Inputs[1].MwebSharedSecret = nil },
		"input-ke-pk":        func(p *Packet) { p.Inputs[1].MwebKeyExchangePubkey = nil },
		"input-extra":        func(p *Packet) { p.Inputs[1].MwebExtraData = nil },
		"output-commit":      func(p *Packet) { p.Outputs[1].OutputCommit = nil },
		"output-features":    func(p *Packet) { p.Outputs[1].MwebFeatures = nil },
		"output-sender-pk":   func(p *Packet) { p.Outputs[1].SenderPubkey = nil },
		"output-output-pk":   func(p *Packet) { p.Outputs[1].OutputPubkey = nil },
		"output-std-fields":  func(p *Packet) { p.Outputs[1].MwebStandardFields = nil },
		"output-rangeproof":  func(p *Packet) { p.Outputs[1].RangeProof = nil },
		"output-sig":         func(p *Packet) { p.Outputs[1].MwebSignature = nil },
		"output-extra":       func(p *Packet) { p.Outputs[1].MwebExtraData = nil },
		"kernel-stealth":     func(p *Packet) { p.Kernels[0].StealthExcess = nil },
		"kernel-fee":         func(p *Packet) { p.Kernels[0].Fee = nil },
		"kernel-pegin":       func(p *Packet) { p.Kernels[0].PeginAmount = nil },
		"kernel-pegouts":     func(p *Packet) { p.Kernels[0].PegOuts = nil },
		"kernel-lock-height": func(p *Packet) { p.Kernels[0].LockHeight = nil },
		"kernel-extra":       func(p *Packet) { p.Kernels[0].ExtraData = nil },
		"tx-offset":          func(p *Packet) { p.MwebTxOffset = nil },
		"stealth-offset":     func(p *Packet) { p.MwebStealthOffset = nil },
	}

	for name, clear := range clearers {
		t.Run(name, func(t *testing.T) {
			p := parseVector(t, "vector-allfields.b64")
			clear(p)
			// Keep the features byte and signature presence coherent
			// with the cleared field so the packet stays sane.
			if p.Kernels[0].Features != nil {
				features := p.Kernels[0].featuresFromFields()
				p.Kernels[0].Features = &features
			}
			if p.Inputs[1].MwebFeatures == nil ||
				p.Inputs[1].MwebCommit == nil ||
				p.Inputs[1].MwebOutputPubkey == nil ||
				p.Inputs[1].MwebInputPubkey == nil ||
				len(p.Inputs[1].MwebExtraData) == 0 {

				p.Inputs[1].MwebInputSig = nil
			}
			if p.Outputs[1].OutputCommit == nil ||
				p.Outputs[1].MwebFeatures == nil ||
				p.Outputs[1].SenderPubkey == nil ||
				p.Outputs[1].OutputPubkey == nil ||
				p.Outputs[1].RangeProof == nil ||
				p.Outputs[1].MwebStandardFields == nil ||
				len(p.Outputs[1].MwebExtraData) == 0 {

				p.Outputs[1].MwebSignature = nil
			}
			serialized := serializeBytes(t, p)
			reparsed, err := NewFromRawBytes(bytes.NewReader(serialized), false)
			require.NoError(t, err)
			require.Equal(t, serialized, serializeBytes(t, reparsed))
		})
	}
}

// Every MWEB keytype is individually rejected in a v0 packet.
func TestV0RejectsEachMwebKeytype(t *testing.T) {
	// A minimal valid v0 packet: one-input one-output unsigned tx.
	baseTx := wire.NewMsgTx(2)
	baseTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}}})
	baseTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	var txBuf bytes.Buffer
	require.NoError(t, baseTx.SerializeNoWitness(&txBuf))

	buildPacket := func(section int, keyType uint8, value []byte) []byte {
		var buf bytes.Buffer
		buf.Write(psbtMagic[:])
		_ = serializeKVPairWithType(&buf, uint8(UnsignedTxType), nil, txBuf.Bytes())
		if section == 0 {
			_ = serializeKVPairWithType(&buf, keyType, nil, value)
		}
		buf.WriteByte(0x00)
		if section == 1 {
			_ = serializeKVPairWithType(&buf, keyType, nil, value)
		}
		buf.WriteByte(0x00)
		if section == 2 {
			_ = serializeKVPairWithType(&buf, keyType, nil, value)
		}
		buf.WriteByte(0x00)
		return buf.Bytes()
	}

	value32 := make([]byte, 32)
	inputKeys := []uint8{0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9C}
	outputKeys := []uint8{0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98}

	// The MWEB field keys are rejected specifically as unsupported-for-version.
	// The kernel-count global (0x92) is a structural field rejected while
	// parsing its count value, so it only needs to be rejected.
	for _, keyType := range []uint8{0x90, 0x91} {
		_, err := NewFromRawBytes(bytes.NewReader(buildPacket(0, keyType, value32)), false)
		require.ErrorIs(t, err, ErrUnsupportedFieldInPsbtVersion, "global 0x%02x", keyType)
	}
	_, err := NewFromRawBytes(bytes.NewReader(buildPacket(0, 0x92, value32)), false)
	require.Error(t, err, "global 0x92")

	for _, keyType := range inputKeys {
		_, err := NewFromRawBytes(bytes.NewReader(buildPacket(1, keyType, value32)), false)
		require.ErrorIs(t, err, ErrUnsupportedFieldInPsbtVersion, "input 0x%02x", keyType)
	}
	for _, keyType := range outputKeys {
		_, err := NewFromRawBytes(bytes.NewReader(buildPacket(2, keyType, value32)), false)
		require.ErrorIs(t, err, ErrUnsupportedFieldInPsbtVersion, "output 0x%02x", keyType)
	}
}

// Removing each required piece of a complete packet flips IsComplete.
func TestIsCompleteBreakerMatrix(t *testing.T) {
	breakers := map[string]func(*Packet){
		"input-sig":         func(p *Packet) { p.Inputs[0].MwebInputSig = nil },
		"input-commit":      func(p *Packet) { p.Inputs[0].MwebCommit = nil },
		"input-output-pk":   func(p *Packet) { p.Inputs[0].MwebOutputPubkey = nil },
		"input-features":    func(p *Packet) { p.Inputs[0].MwebFeatures = nil },
		"input-input-pk":    func(p *Packet) { p.Inputs[0].MwebInputPubkey = nil },
		"output-sig":        func(p *Packet) { p.Outputs[0].MwebSignature = nil },
		"output-commit":     func(p *Packet) { p.Outputs[0].OutputCommit = nil },
		"output-features":   func(p *Packet) { p.Outputs[0].MwebFeatures = nil },
		"output-sender-pk":  func(p *Packet) { p.Outputs[0].SenderPubkey = nil },
		"output-output-pk":  func(p *Packet) { p.Outputs[0].OutputPubkey = nil },
		"output-rangeproof": func(p *Packet) { p.Outputs[0].RangeProof = nil },
		"output-std-fields": func(p *Packet) { p.Outputs[0].MwebStandardFields = nil },
		"kernel-sig":        func(p *Packet) { p.Kernels[0].Signature = nil },
		"kernel-excess":     func(p *Packet) { p.Kernels[0].ExcessCommitment = nil },
		"kernel-features":   func(p *Packet) { p.Kernels[0].Features = nil },
		"tx-offset":         func(p *Packet) { p.MwebTxOffset = nil },
		"stealth-offset":    func(p *Packet) { p.MwebStealthOffset = nil },
	}

	for name, breaker := range breakers {
		t.Run(name, func(t *testing.T) {
			p := parseVector(t, "vector-mweb-signed.b64")
			require.True(t, p.IsComplete())
			breaker(p)
			require.False(t, p.IsComplete())
		})
	}
}

// RedactSensitive strips the shared secrets and descriptors; the packet
// still verifies and extracts.
func TestRedactSensitive(t *testing.T) {
	p := parseVector(t, "vector-mweb-signed.b64")
	require.NotNil(t, p.Inputs[0].MwebSharedSecret)

	p.RedactSensitive()
	require.Nil(t, p.Inputs[0].MwebSharedSecret)
	require.Nil(t, p.Inputs[0].MwebAddrDescriptor)

	_, err := Extract(p)
	require.NoError(t, err)
}

// A fabricated NonWitnessUtxo whose hash does not match the input's outpoint
// must not extract.
func TestExtractRejectsMismatchedNonWitnessUtxo(t *testing.T) {
	p := parseVector(t, "vector-mixed-signed.b64")

	fake := wire.NewMsgTx(2)
	fake.AddTxOut(&wire.TxOut{Value: 110000, PkScript: p.Inputs[0].WitnessUtxo.PkScript})
	p.Inputs[0].NonWitnessUtxo = fake

	_, err := Extract(p)
	require.ErrorIs(t, err, ErrInvalidPrevOutNonWitnessTransaction)
}

// Mutating explicit amount metadata after signing invalidates extraction.
func TestExtractRejectsTamperedExplicitAmounts(t *testing.T) {
	p := parseVector(t, "vector-mweb-signed.b64")
	*p.Inputs[0].MwebAmount++
	_, err := Extract(p)
	require.ErrorIs(t, err, ErrMwebAmountsUnbalanced)

	p = parseVector(t, "vector-mweb-signed.b64")
	p.Outputs[0].Amount--
	_, err = Extract(p)
	require.ErrorIs(t, err, ErrMwebAmountsUnbalanced)
}

// A present-but-zero kernel count is tolerated on parse for compatibility.
func TestZeroKernelCountTolerated(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(psbtMagic[:])
	_ = serializeKVPairWithType(&buf, uint8(TxVersionType), nil, []byte{2, 0, 0, 0})
	_ = serializeKVPairWithType(&buf, uint8(InputCountType), nil, []byte{0})
	_ = serializeKVPairWithType(&buf, uint8(OutputCountType), nil, []byte{0})
	_ = serializeKVPairWithType(&buf, uint8(MwebKernelCountType), nil, []byte{0})
	_ = serializeKVPairWithType(&buf, uint8(VersionType), nil, []byte{2, 0, 0, 0})
	buf.WriteByte(0x00)

	p, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err)
	require.Len(t, p.Kernels, 0)
	// And it re-serializes without the key, per the LIP omission rule.
	require.NotContains(t, string(serializeBytes(t, p)), string([]byte{0x01, 0x92}))
}

// An empty peg-out script is rejected.
func TestEmptyPegoutScriptRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(psbtMagic[:])
	_ = serializeKVPairWithType(&buf, uint8(VersionType), nil, []byte{2, 0, 0, 0})
	_ = serializeKVPairWithType(&buf, uint8(TxVersionType), nil, []byte{2, 0, 0, 0})
	_ = serializeKVPairWithType(&buf, uint8(InputCountType), nil, []byte{0})
	_ = serializeKVPairWithType(&buf, uint8(OutputCountType), nil, []byte{0})
	_ = serializeKVPairWithType(&buf, uint8(MwebKernelCountType), nil, []byte{1})
	buf.WriteByte(0x00)

	var keyData, value bytes.Buffer
	_ = wire.WriteVarInt(&keyData, 0, 0)
	value.Write(binary.LittleEndian.AppendUint64(nil, 5000))
	_ = wire.WriteVarBytes(&value, 0, nil) // empty script
	_ = serializeKVPairWithType(&buf, uint8(MwebKernelPegoutType), keyData.Bytes(), value.Bytes())
	buf.WriteByte(0x00)

	_, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.Error(t, err)
}

// An explicit SIGHASH_DEFAULT (0) round-trips.
func TestSighashDefaultRoundtrip(t *testing.T) {
	p := canonicalV2Packet()
	p.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2000, PkScript: []byte{0x00, 0x14, 0x99}}

	// Inject an explicit zero sighash key by smuggling it through an
	// unknown, then parse: the key must be recognized and preserved on
	// every subsequent round-trip.
	p.Inputs[0].Unknowns = []*Unknown{{Key: []byte{uint8(SighashType)}, Value: []byte{0, 0, 0, 0}}}
	parsed, err := NewFromRawBytes(bytes.NewReader(serializeBytes(t, p)), false)
	require.NoError(t, err)
	require.True(t, parsed.Inputs[0].sighashZero)

	canonical := serializeBytes(t, parsed)
	require.Contains(t, string(canonical), string([]byte{0x01, 0x03, 0x04, 0, 0, 0, 0}))

	reparsed, err := NewFromRawBytes(bytes.NewReader(canonical), false)
	require.NoError(t, err)
	require.Equal(t, canonical, serializeBytes(t, reparsed))
}

// A negative kernel lock height has no valid preimage encoding and is
// rejected.
func TestNegativeLockHeightRejected(t *testing.T) {
	p := parseVector(t, "vector-mweb-signed.b64")
	lockHeight := int32(-1)
	p.Kernels[0].LockHeight = &lockHeight
	require.Error(t, p.SanityCheck())
}

// Empty and misaligned BIP32 derivation values are clean parse errors.
func TestBip32DerivationBounds(t *testing.T) {
	_, _, err := ReadBip32Derivation(nil)
	require.Error(t, err)
	_, _, err = ReadBip32Derivation([]byte{1, 2, 3})
	require.Error(t, err)
	master, path, err := ReadBip32Derivation([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	require.Empty(t, path)
	require.Equal(t, binary.LittleEndian.Uint32([]byte{1, 2, 3, 4}), master)
}

// A global xpub round-trips its fingerprint bytes verbatim.
func TestGlobalXpubFingerprintRoundtrip(t *testing.T) {
	p := canonicalV2Packet()

	extKey, err := readExtendedKey(validXpubPayload(t))
	require.NoError(t, err)
	p.ExtPubKeys = []*GlobalExtPubKey{{
		ExtKey:      extKey,
		Fingerprint: binary.LittleEndian.Uint32([]byte{1, 2, 3, 4}),
		Path:        []uint32{5},
	}}
	serialized := serializeBytes(t, p)
	parsed, err := NewFromRawBytes(bytes.NewReader(serialized), false)
	require.NoError(t, err)
	require.Equal(t, p.ExtPubKeys[0].Fingerprint, parsed.ExtPubKeys[0].Fingerprint)
	require.Equal(t, serialized, serializeBytes(t, parsed))
}

// End-to-end signing with extra data on the input, output, and kernel: the
// signer derives the feature bits and the result verifies and extracts.
func TestSignWorkflowExtraData(t *testing.T) {
	masterScanKey, _ := mw.NewSecretKey()
	masterSpendKey, _ := mw.NewSecretKey()
	keychain := mweb.Keychain{Scan: masterScanKey, Spend: masterSpendKey}

	fee := ltcutil.Amount(1000)
	amount := ltcutil.Amount(50000)
	addrIdx := uint32(3)
	pi := generateUnsignedPInput(
		wire.MwebInputStealthKeyFeatureBit|wire.MwebInputExtraDataFeatureBit,
		*keychain.Address(addrIdx))
	*pi.MwebAmount = amount
	pi.MwebCommit = nil
	pi.MwebFeatures = nil // signer derives stealth + extra bits

	po := generateUnsignedPOutput(wire.MwebOutputMessageStandardFieldsFeatureBit)
	po.Amount = amount - fee
	po.MwebFeatures = nil
	po.MwebExtraData = []byte{0xde, 0xad}

	kernel := feeKernel(fee)
	kernel.ExtraData = []byte{0xbe, 0xef}

	packet := &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs:      []PInput{*pi},
		Outputs:     []POutput{*po},
		Kernels:     []PKernel{kernel},
	}

	signer, err := NewSigner(packet, BasicMwebInputSigner{
		DeriveOutputKeys: keychainDeriver(&keychain, addrIdx),
	})
	require.NoError(t, err)
	_, err = signer.SignMwebComponents()
	require.NoError(t, err)

	require.True(t,
		*packet.Inputs[0].MwebFeatures&wire.MwebInputExtraDataFeatureBit > 0)
	require.True(t,
		*packet.Outputs[0].MwebFeatures&wire.MwebOutputMessageExtraDataFeatureBit > 0)
	require.True(t,
		*packet.Kernels[0].Features&wire.MwebKernelExtraDataFeatureBit > 0)

	tx, err := Extract(packet)
	require.NoError(t, err)
	require.Equal(t, []byte{0xbe, 0xef}, tx.Mweb.TxBody.Kernels[0].ExtraData)
}

// End-to-end signing of a peg-out kernel.
func TestSignWorkflowPegout(t *testing.T) {
	masterScanKey, _ := mw.NewSecretKey()
	masterSpendKey, _ := mw.NewSecretKey()
	keychain := mweb.Keychain{Scan: masterScanKey, Spend: masterSpendKey}

	fee := ltcutil.Amount(1000)
	pegout := int64(30000)
	amount := ltcutil.Amount(50000)
	addrIdx := uint32(4)
	pi := generateUnsignedPInput(wire.MwebInputStealthKeyFeatureBit,
		*keychain.Address(addrIdx))
	*pi.MwebAmount = amount
	pi.MwebCommit = nil

	po := generateUnsignedPOutput(wire.MwebOutputMessageStandardFieldsFeatureBit)
	po.Amount = amount - fee - ltcutil.Amount(pegout)

	kernel := feeKernel(fee)
	kernel.PegOuts = []*wire.TxOut{{Value: pegout, PkScript: []byte{0x00, 0x14, 0x42}}}

	packet := &Packet{
		PsbtVersion: 2,
		TxVersion:   2,
		Inputs:      []PInput{*pi},
		Outputs:     []POutput{*po},
		Kernels:     []PKernel{kernel},
	}

	signer, err := NewSigner(packet, BasicMwebInputSigner{
		DeriveOutputKeys: keychainDeriver(&keychain, addrIdx),
	})
	require.NoError(t, err)
	_, err = signer.SignMwebComponents()
	require.NoError(t, err)

	tx, err := Extract(packet)
	require.NoError(t, err)
	require.Len(t, tx.Mweb.TxBody.Kernels[0].Pegouts, 1)
	require.Equal(t, pegout, tx.Mweb.TxBody.Kernels[0].Pegouts[0].Value)
}
