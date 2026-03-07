package mweb

import (
	"encoding/hex"
	"testing"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
)

// Cross-implementation test vectors from Litecoin Core.
// Scan/spend secrets derived from test seed
// 2a64df085eefedd8bfdbb33176b5ba2e62e8be8b56c8837795598bb6c440c064
// at the standard MWEB path m/0'/100'.
var (
	testScanSecret  = mustHex("b3c91b7291c2e1e06d4a93f3dc32404aef9927db8e794c01a7b4de18a397c338")
	testSpendSecret = mustHex("2fe1982b98c0b68c0839421c8a0a0a67ef3198c746ab8e6d09101eb7396a44d8")

	keychainVectors = []struct {
		index    uint32
		scanA    string // A_i compressed pubkey hex
		spendB   string // B_i compressed pubkey hex
		spendKey string // spend_key_i scalar hex
	}{
		{
			index:    0,
			scanA:    "03acdfb78943f3330437760e37731828f9abd626a72df16fc7cd968df13b7465ab",
			spendB:   "039ed000ed69ca7d593f09ad4a373200bc9711261aab56efc05b92a5eab434f864",
			spendKey: "4076801c591afd06d2823c79858e4c93a6a69ad31ddca673e457437229c74b18",
		},
		{
			index:    1,
			scanA:    "02516a92f3bc6025bce2911e67140dded34ac1f938df0148c9b478e577b5054e42",
			spendB:   "035dad4451e4f2bfd56bb0266a12d92af4749d43a452471e52a437b9d7bbb157c1",
			spendKey: "edf509d17a9ebe744dfb77650a4cc39fa90dc6a758c9d33107b2c4a501fa98ab",
		},
		{
			index:    10,
			scanA:    "03f864dcaa67a74542ff9b5adc27ad2f9002626baa91372e9aee7737ecfec18cca",
			spendB:   "027223f04b94617ec15d7d5c135c42242af64b2129f17080e6b10756bb6ec10073",
			spendKey: "bb33118206a8f8ec35874f78ae5676365bc4e9480d4600947ebb5e049ca4d3e4",
		},
	}
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func testKeychain() *Keychain {
	return &Keychain{
		Scan:  (*mw.SecretKey)(testScanSecret),
		Spend: (*mw.SecretKey)(testSpendSecret),
	}
}

// TestKeychainSubaddressMatchesCore verifies that the BLAKE3-based
// subaddress formula produces stealth addresses and spend keys matching
// Litecoin Core's Keychain.cpp implementation.
func TestKeychainSubaddressMatchesCore(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	for _, tc := range keychainVectors {
		addr := kc.Address(tc.index)
		gotA := hex.EncodeToString(addr.Scan[:])
		gotB := hex.EncodeToString(addr.Spend[:])

		if gotA != tc.scanA {
			t.Errorf("index %d: A_i mismatch:\n  got:  %s\n  want: %s",
				tc.index, gotA, tc.scanA)
		}
		if gotB != tc.spendB {
			t.Errorf("index %d: B_i mismatch:\n  got:  %s\n  want: %s",
				tc.index, gotB, tc.spendB)
		}

		sk := kc.SpendKey(tc.index)
		gotSK := hex.EncodeToString(sk[:])
		if gotSK != tc.spendKey {
			t.Errorf("index %d: spend_key mismatch:\n  got:  %s\n  want: %s",
				tc.index, gotSK, tc.spendKey)
		}
	}
}

// TestKeychainSpendKeyConsistency verifies that SpendKey(i).PubKey()
// equals Address(i).B() for all test indices.
func TestKeychainSpendKeyConsistency(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	for _, tc := range keychainVectors {
		addr := kc.Address(tc.index)
		pk := kc.SpendKey(tc.index).PubKey()

		if *pk != *addr.Spend {
			t.Errorf("index %d: SpendKey(i).PubKey() != Address(i).B()\n  secret-derived: %x\n  address:        %x",
				tc.index, pk[:], addr.Spend[:])
		}
	}
}

// TestKeychainMiModifier verifies the BLAKE3 subaddress modifier by
// checking that Spend + mi(i) == SpendKey(i) for all test indices.
func TestKeychainMiModifier(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	for _, tc := range keychainVectors {
		modifier := kc.mi(tc.index)
		reconstructed := kc.Spend.Add(modifier)

		expected := (*mw.SecretKey)(mustHex(tc.spendKey))
		if *reconstructed != *expected {
			t.Errorf("index %d: Spend + mi(i) != SpendKey(i)\n  got:  %x\n  want: %x",
				tc.index, reconstructed[:], expected[:])
		}
	}
}

// TestOutputRoundTrip creates an MWEB output to a standard-scope stealth
// address, rewinds it using the scan secret, and verifies the recovered
// coin matches. This mirrors Litecoin Core's Test_Keychain.cpp flow:
// create output -> verify rewinding -> verify spend key recovery.
func TestOutputRoundTrip(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	senderKey := (*mw.SecretKey)(mustHex(
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	))

	addr := kc.Address(0)
	amount := uint64(1_234_567)

	output, _ := createOutput(&Recipient{
		Value:   amount,
		Address: addr,
	}, senderKey)

	// Rewind the output using the scan secret
	coin, err := RewindOutput(output, kc.Scan)
	if err != nil {
		t.Fatalf("RewindOutput failed: %v", err)
	}

	if coin.Value != amount {
		t.Errorf("value mismatch: got %d, want %d", coin.Value, amount)
	}
	if !coin.Address.Equal(addr) {
		t.Errorf("address mismatch:\n  got:  A=%x B=%x\n  want: A=%x B=%x",
			coin.Address.Scan[:], coin.Address.Spend[:],
			addr.Scan[:], addr.Spend[:])
	}

	// Verify spend key recovery: b_i * H('O', t) produces the output key
	spendKey := kc.SpendKey(0)
	coin.CalculateOutputKey(spendKey)
	if coin.SpendKey == nil {
		t.Fatal("CalculateOutputKey did not set SpendKey")
	}

	// The output's ReceiverPubKey must equal the recovered spend key's pubkey
	got := coin.SpendKey.PubKey()
	want := &output.ReceiverPubKey
	if *got != *want {
		t.Errorf("receiver pubkey mismatch:\n  got:  %x\n  want: %x",
			got[:], want[:])
	}
}

// TestOutputRoundTripMultipleIndices verifies output creation and
// rewinding for stealth addresses at multiple subaddress indices.
func TestOutputRoundTripMultipleIndices(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	for i, tc := range keychainVectors {
		var senderKeyBytes [32]byte
		senderKeyBytes[0] = byte(i + 1)
		// Fill remaining bytes to avoid a zero key
		for j := 1; j < 32; j++ {
			senderKeyBytes[j] = byte(0xaa + i)
		}
		senderKey := (*mw.SecretKey)(&senderKeyBytes)

		addr := kc.Address(tc.index)
		amount := uint64(100_000 * (uint64(i) + 1))

		output, _ := createOutput(&Recipient{
			Value:   amount,
			Address: addr,
		}, senderKey)

		coin, err := RewindOutput(output, kc.Scan)
		if err != nil {
			t.Fatalf("index %d: RewindOutput failed: %v", tc.index, err)
		}
		if coin.Value != amount {
			t.Errorf("index %d: value mismatch: got %d, want %d",
				tc.index, coin.Value, amount)
		}
		if !coin.Address.Equal(addr) {
			t.Errorf("index %d: address mismatch", tc.index)
		}

		// Verify spend key recovery
		spendKey := kc.SpendKey(tc.index)
		coin.CalculateOutputKey(spendKey)
		if coin.SpendKey == nil {
			t.Fatalf("index %d: CalculateOutputKey did not set SpendKey", tc.index)
		}
		got := coin.SpendKey.PubKey()
		want := &output.ReceiverPubKey
		if *got != *want {
			t.Errorf("index %d: receiver pubkey mismatch:\n  got:  %x\n  want: %x",
				tc.index, got[:], want[:])
		}
	}
}

// TestRewindWrongScanKey verifies that rewinding an output with the
// wrong scan secret fails (view tag mismatch).
func TestRewindWrongScanKey(t *testing.T) {
	t.Parallel()
	kc := testKeychain()

	senderKey := (*mw.SecretKey)(mustHex(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	))

	output, _ := createOutput(&Recipient{
		Value:   500_000,
		Address: kc.Address(0),
	}, senderKey)

	// Use a different scan secret
	wrongScan := (*mw.SecretKey)(mustHex(
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	))
	_, err := RewindOutput(output, wrongScan)
	if err == nil {
		t.Fatal("expected RewindOutput to fail with wrong scan key")
	}
}
