// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom

import (
	"github.com/ltcsuite/ltcd/blockchain"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/wire"
)

// merkleBlock is used to house intermediate information needed to generate a
// wire.MsgMerkleBlock according to a filter.
type merkleBlock struct {
	numTx       uint32
	allHashes   []*chainhash.Hash
	finalHashes []*chainhash.Hash
	matchedBits []byte
	bits        []byte
}

type merkleExtractResult struct {
	root     *chainhash.Hash
	match    []*chainhash.Hash
	index    []uint32
	bitsUsed int
	hashUsed int
	bad      bool
}

// calcTreeWidth calculates and returns the number of nodes (width) or a
// merkle tree at the given depth-first height.
func (m *merkleBlock) calcTreeWidth(height uint32) uint32 {
	return (m.numTx + (1 << height) - 1) >> height
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (m *merkleBlock) calcHash(height, pos uint32) *chainhash.Hash {
	if height == 0 {
		return m.allHashes[pos]
	}

	var right *chainhash.Hash
	left := m.calcHash(height-1, pos*2)
	if pos*2+1 < m.calcTreeWidth(height-1) {
		right = m.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	res := blockchain.HashMerkleBranches(left, right)
	return &res
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.  As it calculates the hashes, it also saves whether or not each
// node is a parent node and a list of final hashes to be included in the
// merkle block.
func (m *merkleBlock) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < m.numTx; i++ {
		isParent |= m.matchedBits[i]
	}
	m.bits = append(m.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		m.finalHashes = append(m.finalHashes, m.calcHash(height, pos))
		return
	}

	// At this point, the node is an internal node and it is the parent of
	// of an included leaf node.

	// Descend into the left child and process its sub-tree.
	m.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < m.calcTreeWidth(height-1) {
		m.traverseAndBuild(height-1, pos*2+1)
	}
}

func (m *merkleBlock) traverseAndExtract(height, pos uint32,
	res *merkleExtractResult) *chainhash.Hash {

	if res.bitsUsed >= len(m.bits) {
		// Overflowed the bits array - failure
		res.bad = true
		return &chainhash.Hash{}
	}
	parentOfMatch := m.bits[res.bitsUsed] > 0
	res.bitsUsed++

	if height == 0 || !parentOfMatch {
		// If at height 0, or nothing interesting below,
		// use stored hash and do not descend

		if res.hashUsed >= len(m.finalHashes) {
			// Overflowed the hash array - failure
			res.bad = true
			return &chainhash.Hash{}
		}
		hash := m.finalHashes[res.hashUsed]
		res.hashUsed++

		if height == 0 && parentOfMatch {
			// In case of height 0, we have a matched txid
			res.match = append(res.match, hash)
			res.index = append(res.index, pos)
		}
		return hash

	} else {
		// Otherwise, descend into the subtrees to extract
		// matched txids and hashes
		left := m.traverseAndExtract(height-1, pos*2, res)
		right := left

		if pos*2+1 < m.calcTreeWidth(height-1) {
			right = m.traverseAndExtract(height-1, pos*2+1, res)

			if left.IsEqual(right) {
				// The left and right branches should never be
				// identical, as the transaction hashes covered
				// by them must each be unique.
				res.bad = true
			}
		}

		// Combine them before returning
		return blockchain.HashMerkleBranches(left, right)
	}
}

func (m *merkleBlock) extractMatches() (res *merkleExtractResult) {
	res = &merkleExtractResult{}

	// An empty set will not work
	if m.numTx == 0 {
		return
	}

	// Check for excessively high numbers of transactions
	if m.numTx > blockchain.MaxOutputsPerBlock {
		return
	}

	// There can never be more hashes provided than one for every txid
	if uint32(len(m.finalHashes)) > m.numTx {
		return
	}

	// There must be at least one bit per node in the partial tree,
	// and at least one node per hash
	if len(m.bits) < len(m.finalHashes) {
		return
	}

	// Calculate height of tree
	var height uint32
	for m.calcTreeWidth(height) > 1 {
		height++
	}

	// Traverse the partial tree
	hashMerkleRoot := m.traverseAndExtract(height, 0, res)

	// Verify that no problems occurred during the tree traversal
	if res.bad {
		return
	}

	// Verify that all bits were consumed (except for the padding
	// caused by serializing it as a byte sequence)
	if (res.bitsUsed+7)/8 != (len(m.bits)+7)/8 {
		return
	}

	// Verify that all hashes were consumed
	if res.hashUsed != len(m.finalHashes) {
		return
	}

	res.root = hashMerkleRoot
	return
}

// NewMerkleBlock returns a new *wire.MsgMerkleBlock and an array of the matched
// transaction index numbers based on the passed block and filter.
func NewMerkleBlock(block *ltcutil.Block, filter *Filter) (*wire.MsgMerkleBlock, []uint32) {
	numTx := uint32(len(block.Transactions()))
	mBlock := merkleBlock{
		numTx:       numTx,
		allHashes:   make([]*chainhash.Hash, 0, numTx),
		matchedBits: make([]byte, 0, numTx),
	}

	// Find and keep track of any transactions that match the filter.
	var matchedIndices []uint32
	for txIndex, tx := range block.Transactions() {
		if filter.MatchTxAndUpdate(tx) {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x01)
			matchedIndices = append(matchedIndices, uint32(txIndex))
		} else {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x00)
		}
		mBlock.allHashes = append(mBlock.allHashes, tx.Hash())
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for mBlock.calcTreeWidth(height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	mBlock.traverseAndBuild(height, 0)

	// Create and return the merkle block.
	msgMerkleBlock := wire.MsgMerkleBlock{
		Header:       block.MsgBlock().Header,
		Transactions: mBlock.numTx,
		Hashes:       make([]*chainhash.Hash, 0, len(mBlock.finalHashes)),
		Flags:        make([]byte, (len(mBlock.bits)+7)/8),
	}
	for _, hash := range mBlock.finalHashes {
		_ = msgMerkleBlock.AddTxHash(hash)
	}
	for i := uint32(0); i < uint32(len(mBlock.bits)); i++ {
		msgMerkleBlock.Flags[i/8] |= mBlock.bits[i] << (i % 8)
	}
	return &msgMerkleBlock, matchedIndices
}

// VerifyMerkleBlock verifies the integrity of a merkle block.
func VerifyMerkleBlock(msgMerkleBlock *wire.MsgMerkleBlock) bool {
	mBlock := &merkleBlock{
		numTx:       msgMerkleBlock.Transactions,
		finalHashes: msgMerkleBlock.Hashes,
		bits:        make([]byte, len(msgMerkleBlock.Flags)*8),
	}
	for i := range mBlock.bits {
		mBlock.bits[i] = msgMerkleBlock.Flags[i/8] & (1 << (i % 8))
	}
	return mBlock.extractMatches().root.IsEqual(&msgMerkleBlock.Header.MerkleRoot)
}
