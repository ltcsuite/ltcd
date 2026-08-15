package psbt

// Allocation-bound hardening for pre-existing upstream (btcd) parsers: a
// declared length larger than the input must be rejected before make().

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// A declared leaf-hash count that overflows the size check must be rejected,
// not drive an oversized allocation.
func TestReadTaprootBip32DerivationRejectsOversizedCount(t *testing.T) {
	// secp256k1 generator x-coordinate: a valid x-only pubkey.
	xonly, err := hex.DecodeString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	require.NoError(t, err)

	var value bytes.Buffer
	value.WriteByte(0xff)
	require.NoError(t, binary.Write(&value, binary.LittleEndian, uint64(1)<<58))

	_, err = ReadTaprootBip32Derivation(xonly, value.Bytes())
	require.Error(t, err)
}

// A declared witness-element count larger than the remaining bytes must be
// rejected before allocating.
func TestExtractTxWitnessRejectsOversizedCount(t *testing.T) {
	fsw := append([]byte{0xff}, bytes.Repeat([]byte{0xff}, 8)...)
	_, err := extractTxWitness(fsw)
	require.Error(t, err)
}
