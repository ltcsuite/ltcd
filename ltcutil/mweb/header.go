package mweb

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil/bloom"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

func VerifyHeader(mwebHeader *wire.MsgMwebHeader) error {
	extractResult := bloom.VerifyMerkleBlock(&mwebHeader.Merkle)
	if !extractResult.Root.IsEqual(&mwebHeader.Merkle.Header.MerkleRoot) {
		return errors.New("mwebheader merkle block is bad")
	}

	if !mwebHeader.Hogex.IsHogEx {
		return errors.New("mwebheader hogex is not hogex")
	}

	// Validate that the hash of the HogEx transaction in the tx message
	// matches the hash in the merkleblock message, and that it's the
	// last transaction committed to by the merkle root of the block.

	finalTx := extractResult.Match[len(extractResult.Match)-1]
	if mwebHeader.Hogex.TxHash() != *finalTx {
		return fmt.Errorf("tx hash mismatch, hogex=%v, last merkle tx=%v",
			mwebHeader.Hogex.TxHash(), *finalTx)
	}

	finalTxPos := extractResult.Index[len(extractResult.Index)-1]
	if finalTxPos != mwebHeader.Merkle.Transactions-1 {
		return fmt.Errorf("tx index mismatch, got=%v, expected=%v",
			finalTxPos, mwebHeader.Merkle.Transactions-1)
	}

	// Validate that the pubkey script of the first output contains
	// the HogAddr, which shall consist of <OP_8><0x20> followed by
	// the 32-byte hash of the MWEB header.

	script, _ := txscript.NewScriptBuilder().
		AddOp(txscript.MwebHogAddrWitnessVersion + txscript.OP_1 - 1).
		AddData(mwebHeader.MwebHeader.Hash()[:]).Script()
	if !bytes.Equal(mwebHeader.Hogex.TxOut[0].PkScript, script) {
		return fmt.Errorf("HogAddr mismatch, hogex=%v, expected=%v",
			mwebHeader.Hogex.TxOut[0].PkScript, script)
	}

	return nil
}

func VerifyLeafset(mwebHeader *wire.MsgMwebHeader,
	mwebLeafset *wire.MsgMwebLeafset) error {

	// Verify that the hash of the leafset bitmap matches the
	// leafset_root value in the MWEB header.

	leafsetRoot := chainhash.Hash(blake3.Sum256(mwebLeafset.Leafset))
	if leafsetRoot != mwebHeader.MwebHeader.LeafsetRoot {
		return fmt.Errorf("leafset root mismatch, leafset=%v, header=%v",
			leafsetRoot, mwebHeader.MwebHeader.LeafsetRoot)
	}

	return nil
}
