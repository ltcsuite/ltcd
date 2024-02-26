package mweb

import (
	"encoding/binary"
	"math/bits"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

type (
	leafIdx uint64
	nodeIdx uint64
)

func (l *Leafset) contains(i leafIdx) bool {
	return l.Contains(uint64(i))
}

func (l *Leafset) nextUnspent(i leafIdx) leafIdx {
	for {
		i++
		if l.contains(i) || uint64(i) >= l.Size {
			return i
		}
	}
}

func (i leafIdx) nodeIdx() nodeIdx {
	return nodeIdx(2*i) - nodeIdx(bits.OnesCount64(uint64(i)))
}

func (i nodeIdx) height() uint64 {
	height := uint64(i)
	h := 64 - bits.LeadingZeros64(uint64(i))
	for peakSize := uint64(1<<h - 1); peakSize > 0; peakSize >>= 1 {
		if height >= peakSize {
			height -= peakSize
		}
	}
	return height
}

func (i nodeIdx) leafIdx() leafIdx {
	leafIndex := uint64(0)
	numLeft := uint64(i)
	h := 64 - bits.LeadingZeros64(uint64(i))
	for peakSize := uint64(1<<h - 1); peakSize > 0; peakSize >>= 1 {
		if numLeft >= peakSize {
			leafIndex += (peakSize + 1) / 2
			numLeft -= peakSize
		}
	}
	return leafIdx(leafIndex)
}

func (i nodeIdx) left(height uint64) nodeIdx {
	return i - (1 << height)
}

func (i nodeIdx) right() nodeIdx {
	return i - 1
}

func (i nodeIdx) hash(data []byte) *chainhash.Hash {
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, uint64(i))
	wire.WriteVarBytes(h, 0, data)
	return (*chainhash.Hash)(h.Sum(nil))
}

func (i nodeIdx) parentHash(left, right []byte) *chainhash.Hash {
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, uint64(i))
	h.Write(left)
	h.Write(right)
	return (*chainhash.Hash)(h.Sum(nil))
}

func calcPeaks(nodes uint64) (peaks []nodeIdx) {
	sumPrevPeaks := uint64(0)
	h := 64 - bits.LeadingZeros64(nodes)
	for peakSize := uint64(1<<h - 1); peakSize > 0; peakSize >>= 1 {
		if nodes >= peakSize {
			peaks = append(peaks, nodeIdx(sumPrevPeaks+peakSize-1))
			sumPrevPeaks += peakSize
			nodes -= peakSize
		}
	}
	return
}

type verifyMwebUtxosVars struct {
	mwebUtxos                 *wire.MsgMwebUtxos
	leafset                   *Leafset
	firstLeafIdx, lastLeafIdx leafIdx
	leavesUsed, hashesUsed    int
	isProofHash               map[nodeIdx]bool
}

func (v *verifyMwebUtxosVars) nextLeaf() (leafIndex leafIdx, hash *chainhash.Hash) {
	if v.leavesUsed == len(v.mwebUtxos.Utxos) {
		return
	}
	utxo := v.mwebUtxos.Utxos[v.leavesUsed]
	leafIndex = leafIdx(utxo.LeafIndex)
	hash = utxo.OutputId
	v.leavesUsed++
	return
}

func (v *verifyMwebUtxosVars) nextHash(nodeIdx nodeIdx) (hash *chainhash.Hash) {
	if v.hashesUsed == len(v.mwebUtxos.ProofHashes) {
		return
	}
	hash = v.mwebUtxos.ProofHashes[v.hashesUsed]
	v.hashesUsed++
	v.isProofHash[nodeIdx] = true
	return
}

func (v *verifyMwebUtxosVars) calcNodeHash(nodeIdx nodeIdx, height uint64) *chainhash.Hash {
	if nodeIdx < v.firstLeafIdx.nodeIdx() || v.isProofHash[nodeIdx] {
		return v.nextHash(nodeIdx)
	}
	if height == 0 {
		leafIdx := nodeIdx.leafIdx()
		if !v.leafset.contains(leafIdx) {
			return nil
		}
		leafIdx2, outputId := v.nextLeaf()
		if leafIdx != leafIdx2 || outputId == nil {
			return nil
		}
		return nodeIdx.hash(outputId[:])
	}
	left := v.calcNodeHash(nodeIdx.left(height), height-1)
	var right *chainhash.Hash
	if v.lastLeafIdx.nodeIdx() <= nodeIdx.left(height) {
		right = v.nextHash(nodeIdx.right())
	} else {
		right = v.calcNodeHash(nodeIdx.right(), height-1)
	}
	switch {
	case left == nil && right == nil:
		return nil
	case left == nil:
		if left = v.nextHash(nodeIdx.left(height)); left == nil {
			return nil
		}
	case right == nil:
		if right = v.nextHash(nodeIdx.right()); right == nil {
			return nil
		}
	}
	return nodeIdx.parentHash(left[:], right[:])
}

func VerifyUtxos(mwebHeader *wire.MwebHeader,
	mwebLeafset *Leafset, mwebUtxos *wire.MsgMwebUtxos) bool {

	if mwebUtxos.StartIndex == 0 &&
		len(mwebUtxos.Utxos) == 0 &&
		len(mwebUtxos.ProofHashes) == 0 &&
		mwebHeader.OutputRoot.IsEqual(&chainhash.Hash{}) &&
		mwebHeader.OutputMMRSize == 0 {
		return true
	} else if len(mwebUtxos.Utxos) == 0 ||
		mwebHeader.OutputMMRSize == 0 {
		return false
	}

	v := &verifyMwebUtxosVars{
		mwebUtxos:    mwebUtxos,
		leafset:      mwebLeafset,
		firstLeafIdx: leafIdx(mwebUtxos.StartIndex),
		lastLeafIdx:  leafIdx(mwebUtxos.StartIndex),
		isProofHash:  make(map[nodeIdx]bool),
	}

	for i := 0; ; i++ {
		if !v.leafset.contains(v.lastLeafIdx) {
			return false
		}
		if leafIdx(mwebUtxos.Utxos[i].LeafIndex) != v.lastLeafIdx {
			return false
		}
		if i == len(mwebUtxos.Utxos)-1 {
			break
		}
		v.lastLeafIdx = v.leafset.nextUnspent(v.lastLeafIdx)
	}

	var (
		nextNodeIdx = leafIdx(mwebHeader.OutputMMRSize).nodeIdx()
		peaks       = calcPeaks(uint64(nextNodeIdx))
		peakHashes  []*chainhash.Hash
	)
	for i := 0; i < 2; i++ {
		peakHashes = nil
		v.leavesUsed = 0
		v.hashesUsed = 0

		for _, peakNodeIdx := range peaks {
			peakHash := v.calcNodeHash(peakNodeIdx, peakNodeIdx.height())
			if peakHash == nil {
				peakHash = v.nextHash(peakNodeIdx)
				if peakHash == nil {
					return false
				}
			}
			peakHashes = append(peakHashes, peakHash)
			if v.lastLeafIdx.nodeIdx() <= peakNodeIdx {
				if peakNodeIdx != peaks[len(peaks)-1] {
					baggedPeak := v.nextHash(nextNodeIdx)
					if baggedPeak == nil {
						return false
					}
					peakHashes = append(peakHashes, baggedPeak)
				}
				break
			}
		}
		if v.leavesUsed != len(v.mwebUtxos.Utxos) ||
			v.hashesUsed != len(v.mwebUtxos.ProofHashes) {
			return false
		}
	}

	baggedPeak := peakHashes[len(peakHashes)-1]
	for i := len(peakHashes) - 2; i >= 0; i-- {
		baggedPeak = nextNodeIdx.parentHash(peakHashes[i][:], baggedPeak[:])
	}
	return baggedPeak.IsEqual(&mwebHeader.OutputRoot)
}
