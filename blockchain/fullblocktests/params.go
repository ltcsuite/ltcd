// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fullblocktests

import (
	"encoding/hex"
	"math/big"
	"time"

	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/wire"
)

// newHashFromStr converts the passed big-endian hex string into a
// wire.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return hash
}

// fromHex converts the passed hex string into a byte slice and will panic if
// there is an error.  This is only provided for the hard-coded constants so
// errors in the source code can be detected. It will only (and must only) be
// called for initialization purposes.
func fromHex(s string) []byte {
	r, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return r
}

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// regressionPowLimit is the highest proof of work value a Litecoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// regTestGenesisBlock defines the genesis block of the block chain which serves
	// as the public transaction ledger for the regression test network.
	regTestGenesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  *newHashFromStr("0000000000000000000000000000000000000000000000000000000000000000"),
			MerkleRoot: *newHashFromStr("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"),
			Timestamp:  time.Unix(1296688602, 0), // 2011-02-02 23:16:42 +0000 UTC
			Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
			Nonce:      2,
		},
		Transactions: []*wire.MsgTx{{
			Version: 1,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
				},
				SignatureScript: fromHex("04ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536"),
				Sequence:        0xffffffff,
			}},
			TxOut: []*wire.TxOut{{
				Value:    0,
				PkScript: fromHex("41418471fa689ad502369c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaff47216fe1b5185b4acf21b179c45070ac7b3a9ac"),
			}},
			LockTime: 0,
		}},
	}
)

// regressionNetParams defines the network parameters for the regression test
// network.
//
// NOTE: The test generator intentionally does not use the existing definitions
// in the chaincfg package since the intent is to be able to generate known
// good tests which exercise that code.  Using the chaincfg parameters would
// allow them to change out from under the tests potentially invalidating them.
var regressionNetParams = &chaincfg.Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "19444",

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              newHashFromStr("530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"),
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	BIP0034Height:            100000000, // Not active - Permit ver 1 blocks
	BIP0065Height:            1351,      // Used by regression tests
	BIP0066Height:            1251,      // Used by regression tests
	SubsidyReductionInterval: 150,
	TargetTimespan:           (time.Hour * 24 * 3) + (time.Hour * 12), // 3.5 days
	TargetTimePerBlock:       (time.Minute * 2) + (time.Second * 30),  // 2.5 minutes
	RetargetAdjustmentFactor: 4,                                       // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}
