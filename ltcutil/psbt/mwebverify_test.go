package psbt

// Unit tests for mwebverify.go: consensus body-weight and input limits, the
// money-range balance and amount checks, hash-to-scalar, and lock-time
// resolution.

import (
	"testing"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/stretchr/testify/require"
	"lukechampine.com/blake3"
)

// checkMwebBodyLimits pins the consensus body bounds and the strict-greater
// comparison so a wrong constant cannot ship silently.
func TestCheckMwebBodyLimits(t *testing.T) {
	require.NoError(t, checkMwebBodyLimits(maxMwebInputs, maxMwebBlockWeight))
	require.Error(t, checkMwebBodyLimits(maxMwebInputs+1, 0))
	require.Error(t, checkMwebBodyLimits(0, maxMwebBlockWeight+1))
	require.NoError(t, checkMwebBodyLimits(0, 0))
}

// checkMwebBalance must reject a combined total outside the money range even
// when the two sides are individually balanced (each category is <= MaxSatoshi
// but inputs+pegins exceeds it).
func TestCheckMwebBalanceRejectsCombinedOverflow(t *testing.T) {
	max := ltcutil.Amount(ltcutil.MaxSatoshi)
	p := &Packet{
		PsbtVersion: 2,
		Inputs:      []PInput{{MwebOutputId: &chainhash.Hash{}, MwebAmount: &max}},
		Outputs:     []POutput{{OutputCommit: &mw.Commitment{}, Amount: max}},
		Kernels: []PKernel{{
			PeginAmount: &max,
			PegOuts:     []*wire.TxOut{{Value: int64(max), PkScript: []byte{0x51}}},
		}},
	}
	// lhs = inputs(max) + pegins(max) = 2*MaxSatoshi, equal to rhs, so the
	// bare equation balances; the money-range cap must still reject it.
	require.Error(t, checkMwebBalance(p, true))
}

// Individually valid amounts whose total exceeds the money range are
// rejected.
func TestAmountTotalMoneyRange(t *testing.T) {
	var sum uint64
	require.NoError(t, addAmount(&sum, ltcutil.MaxSatoshi))
	require.Error(t, addAmount(&sum, 1))
}

// hashToScalar: a valid digest passes through; an over-order digest maps via
// the "MWEB hash-to-scalar" retry rule.
func TestHashToScalar(t *testing.T) {
	digest := [32]byte{5}
	require.Equal(t, mw.SecretKey(digest), *hashToScalar(digest[:]))

	var overflow [32]byte
	for i := range overflow {
		overflow[i] = 0xff
	}
	h := blake3.New(32, nil)
	h.Write([]byte("MWEB hash-to-scalar"))
	h.Write(overflow[:])
	h.Write([]byte{0, 0, 0, 0})
	expected := h.Sum(nil)
	require.True(t, validScalar(expected)) // counter 0 suffices here
	require.Equal(t, *(*mw.SecretKey)(expected), *hashToScalar(overflow[:]))
}

// effectiveLockTime follows BIP-0370's per-input required lock times.
func TestEffectiveLockTime(t *testing.T) {
	height1, height2 := uint32(100), uint32(200)
	time1 := uint32(1700000000)
	fallback := uint32(77)

	p := &Packet{PsbtVersion: 2, FallbackLocktime: &fallback}
	lockTime, err := effectiveLockTime(p)
	require.NoError(t, err)
	require.Equal(t, fallback, lockTime)

	p.Inputs = []PInput{
		{RequiredHeightLockTime: &height1},
		{RequiredHeightLockTime: &height2},
	}
	lockTime, err = effectiveLockTime(p)
	require.NoError(t, err)
	require.Equal(t, height2, lockTime)

	// Height-only and time-only inputs cannot be reconciled.
	p.Inputs = []PInput{
		{RequiredHeightLockTime: &height1},
		{RequiredTimeLockTime: &time1},
	}
	_, err = effectiveLockTime(p)
	require.Error(t, err)
}

// Height and time lock resolution per BIP-0370, including the zero-height
// veto case.
func TestEffectiveLockTimeVetoCases(t *testing.T) {
	height0, height100 := uint32(0), uint32(100)
	time1 := uint32(1700000000)

	// A zero height lock still vetoes time locks: irreconcilable.
	p := &Packet{PsbtVersion: 2, Inputs: []PInput{
		{RequiredHeightLockTime: &height0},
		{RequiredTimeLockTime: &time1},
	}}
	_, err := effectiveLockTime(p)
	require.Error(t, err)

	// Height preferred when an input allows both.
	p = &Packet{PsbtVersion: 2, Inputs: []PInput{
		{RequiredHeightLockTime: &height100, RequiredTimeLockTime: &time1},
	}}
	lockTime, err := effectiveLockTime(p)
	require.NoError(t, err)
	require.Equal(t, height100, lockTime)

	// A lone zero height lock falls back.
	fallback := uint32(77)
	p = &Packet{PsbtVersion: 2, FallbackLocktime: &fallback, Inputs: []PInput{
		{RequiredHeightLockTime: &height0},
	}}
	lockTime, err = effectiveLockTime(p)
	require.NoError(t, err)
	require.Equal(t, fallback, lockTime)
}
