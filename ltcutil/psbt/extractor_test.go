package psbt

import (
	"testing"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/secp256k1"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/stretchr/testify/require"
)

func TestExtract_NonFinalized(t *testing.T) {
	p := &Packet{
		PsbtVersion: 2,
		Inputs:      []PInput{{}}, // not finalized
	}

	_, err := Extract(p)
	require.ErrorIs(t, err, ErrIncompletePSBT)
}

// A structurally complete packet whose signatures and proofs are garbage must
// not extract: LIP-0007 requires cryptographic verification before extraction.
// (The valid-extraction path is covered by TestSignMwebComponents.)
func TestExtract_InvalidMwebComponents(t *testing.T) {
	inputFeatures := wire.MwebInputFeatureBit(0)
	outputFeatures := wire.MwebOutputMessageFeatureBit(0)
	kernelFeatures := wire.MwebKernelFeatureBit(0)
	p := &Packet{
		PsbtVersion:       2,
		MwebTxOffset:      &mw.BlindingFactor{},
		MwebStealthOffset: &mw.BlindingFactor{},
		Inputs: []PInput{{
			// Stealth-key bit clear, so no input pubkey (isFinalized
			// enforces that agreement); the crypto itself is garbage.
			MwebFeatures:     &inputFeatures,
			MwebCommit:       &mw.Commitment{},
			MwebOutputId:     &chainhash.Hash{},
			MwebOutputPubkey: &mw.PublicKey{},
			MwebInputSig:     &mw.Signature{},
		}},
		Outputs: []POutput{{
			MwebFeatures:  &outputFeatures,
			OutputCommit:  &mw.Commitment{},
			OutputPubkey:  &mw.PublicKey{},
			SenderPubkey:  &mw.PublicKey{},
			RangeProof:    &secp256k1.RangeProof{},
			MwebSignature: &mw.Signature{},
		}},
		Kernels: []PKernel{{
			Features:         &kernelFeatures,
			ExcessCommitment: &mw.Commitment{},
			Signature:        &mw.Signature{},
		}},
	}

	require.True(t, p.Inputs[0].isFinalized())
	require.True(t, p.Outputs[0].isFinalized())
	require.True(t, p.Kernels[0].isFinalized())

	_, err := Extract(p)
	require.Error(t, err)
}
