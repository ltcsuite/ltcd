package psbt

import (
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"testing"

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

func TestExtract_ValidMWEB(t *testing.T) {
	// Build a fully valid, minimal Packet
	inputFeatures := wire.MwebInputFeatureBit(0)
	outputFeatures := wire.MwebOutputMessageFeatureBit(0)
	kernelFeatures := wire.MwebKernelFeatureBit(0)
	p := &Packet{
		PsbtVersion:       2,
		MwebTxOffset:      &mw.BlindingFactor{},
		MwebStealthOffset: &mw.BlindingFactor{},
		Inputs: []PInput{{
			MwebFeatures:     &inputFeatures,
			MwebCommit:       &mw.Commitment{},
			MwebOutputId:     &chainhash.Hash{},
			MwebInputPubkey:  &mw.PublicKey{},
			MwebOutputPubkey: &mw.PublicKey{},
			MwebInputSig:     &mw.Signature{},
		}},
		Outputs: []POutput{{
			MwebFeatures:  &outputFeatures,
			OutputCommit:  &mw.Commitment{},
			SenderPubkey:  &mw.PublicKey{},
			RangeProof:    &mw.RangeProof{},
			MwebSignature: &mw.Signature{},
		}},
		Kernels: []PKernel{{
			Features:         &kernelFeatures,
			ExcessCommitment: &mw.Commitment{},
			Signature:        &mw.Signature{},
		}},
	}

	// Set required finalization fields
	p.Inputs[0].MwebInputSig = &mw.Signature{}
	p.Outputs[0].MwebSignature = &mw.Signature{}
	p.Kernels[0].Signature = &mw.Signature{}

	// Mark finalized
	require.True(t, p.Inputs[0].isFinalized())
	require.True(t, p.Outputs[0].isFinalized())
	require.True(t, p.Kernels[0].isFinalized())

	tx, err := Extract(p)
	require.NoError(t, err)
	require.NotNil(t, tx)
	require.NotNil(t, tx.Mweb)
	require.Equal(t, 1, len(tx.Mweb.TxBody.Inputs))
	require.Equal(t, 1, len(tx.Mweb.TxBody.Outputs))
	require.Equal(t, 1, len(tx.Mweb.TxBody.Kernels))
}
