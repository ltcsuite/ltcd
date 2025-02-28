// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	_ "embed"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
)

var (
	// Testnet4 block 1821752 is pre-MWEB activation, 3 txns.
	// But version 20000000.
	//go:embed testdata/testnet4Block1821752.dat
	block1821752 []byte

	// Block 2215584 is the first with MW txns, a peg-in with witness version 9
	// script, an integ tx with witness version 8 script, block version 20000000
	// (with a MWEB), and 5 txns.
	// 7e35fabe7b3c694ebeb0368a1a1c31e83962f3c5b4cc8dcede3ae94ed3deb306
	//go:embed testdata/testnet4Block2215584.dat
	block2215584 []byte

	// Block 2321749 is version 20000000 with a MWEB, 4 txns, the last one being
	// an integration / hogex txn that fails to decode.
	// 57929846db4a92d937eb596354d10949e33c815ee45df0c9b3bbdfb283e15bcd
	//go:embed testdata/testnet4Block2321749.dat
	block2321749 []byte

	// Block 2319633 is version 20000000 with a MWEB, 2 txns, one coinbase and
	// one integration.
	// e9fe2c6496aedefa8bf6529bdc5c1f9fd4af565ca4c98cab73e3a1f616fb3502
	//go:embed testdata/testnet4Block2319633.dat
	block2319633 []byte

	//go:embed testdata/testnet4Block2215586.dat
	block2215586 []byte
)

// TestBlock tests the MsgBlock API.
func TestBlock(t *testing.T) {
	pver := ProtocolVersion

	// Block 1 header.
	prevHash := &blockOne.Header.PrevBlock
	merkleHash := &blockOne.Header.MerkleRoot
	bits := blockOne.Header.Bits
	nonce := blockOne.Header.Nonce
	bh := NewBlockHeader(1, prevHash, merkleHash, bits, nonce)

	// Ensure the command is expected value.
	wantCmd := "block"
	msg := NewMsgBlock(bh)
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgBlock: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	// Num addresses (varInt) + max allowed addresses.
	wantPayload := uint32(4000000)
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure we get the same block header data back out.
	if !reflect.DeepEqual(&msg.Header, bh) {
		t.Errorf("NewMsgBlock: wrong block header - got %v, want %v",
			spew.Sdump(&msg.Header), spew.Sdump(bh))
	}

	// Ensure transactions are added properly.
	tx := blockOne.Transactions[0].Copy()
	msg.AddTransaction(tx)
	if !reflect.DeepEqual(msg.Transactions, blockOne.Transactions) {
		t.Errorf("AddTransaction: wrong transactions - got %v, want %v",
			spew.Sdump(msg.Transactions),
			spew.Sdump(blockOne.Transactions))
	}

	// Ensure transactions are properly cleared.
	msg.ClearTransactions()
	if len(msg.Transactions) != 0 {
		t.Errorf("ClearTransactions: wrong transactions - got %v, want %v",
			len(msg.Transactions), 0)
	}
}

// TestBlockTxHashes tests the ability to generate a slice of all transaction
// hashes from a block accurately.
func TestBlockTxHashes(t *testing.T) {
	// Block 1, transaction 1 hash.
	hashStr := "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
	wantHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
		return
	}

	wantHashes := []chainhash.Hash{*wantHash}
	hashes, err := blockOne.TxHashes()
	if err != nil {
		t.Errorf("TxHashes: %v", err)
	}
	if !reflect.DeepEqual(hashes, wantHashes) {
		t.Errorf("TxHashes: wrong transaction hashes - got %v, want %v",
			spew.Sdump(hashes), spew.Sdump(wantHashes))
	}
}

// TestBlockHash tests the ability to generate the hash of a block accurately.
func TestBlockHash(t *testing.T) {
	// Block 1 hash.
	hashStr := "839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
	wantHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Ensure the hash produced is expected.
	blockHash := blockOne.BlockHash()
	if !blockHash.IsEqual(wantHash) {
		t.Errorf("BlockHash: wrong hash - got %v, want %v",
			spew.Sprint(blockHash), spew.Sprint(wantHash))
	}
}

// TestBlockWire tests the MsgBlock wire encode and decode for various numbers
// of transaction inputs and outputs and protocol versions.
func TestBlockWire(t *testing.T) {
	tests := []struct {
		in     *MsgBlock       // Message to encode
		out    *MsgBlock       // Expected decoded message
		buf    []byte          // Wire encoding
		txLocs []TxLoc         // Expected transaction locations
		pver   uint32          // Protocol version for wire encoding
		enc    MessageEncoding // Message encoding format
	}{
		// Latest protocol version.
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0035Version.
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version.
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion.
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion.
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
			MultipleAddressVersion,
			BaseEncoding,
		},
		// TODO(roasbeef): add case for witnessy block
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgBlock
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(&msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestBlockWireErrors performs negative tests against wire encode and decode
// of MsgBlock to confirm error paths work correctly.
func TestBlockWireErrors(t *testing.T) {
	// Use protocol version 60002 specifically here instead of the latest
	// because the test data is using bytes encoded with that protocol
	// version.
	pver := uint32(60002)

	tests := []struct {
		in       *MsgBlock       // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error in version.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in prev block hash.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 4, io.ErrShortWrite, io.EOF},
		// Force error in merkle root.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 36, io.ErrShortWrite, io.EOF},
		// Force error in timestamp.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 68, io.ErrShortWrite, io.EOF},
		// Force error in difficulty bits.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 72, io.ErrShortWrite, io.EOF},
		// Force error in header nonce.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 76, io.ErrShortWrite, io.EOF},
		// Force error in transaction count.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 80, io.ErrShortWrite, io.EOF},
		// Force error in transactions.
		{&blockOne, blockOneBytes, pver, BaseEncoding, 81, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BtcEncode(w, test.pver, test.enc)
		if err != test.writeErr {
			t.Errorf("BtcEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire format.
		var msg MsgBlock
		r := newFixedReader(test.max, test.buf)
		err = msg.BtcDecode(r, test.pver, test.enc)
		if err != test.readErr {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestBlockSerialize tests MsgBlock serialize and deserialize.
func TestBlockSerialize(t *testing.T) {
	tests := []struct {
		in     *MsgBlock // Message to encode
		out    *MsgBlock // Expected decoded message
		buf    []byte    // Serialized data
		txLocs []TxLoc   // Expected transaction locations
	}{
		{
			&blockOne,
			&blockOne,
			blockOneBytes,
			blockOneTxLocs,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the block.
		var buf bytes.Buffer
		err := test.in.Serialize(&buf)
		if err != nil {
			t.Errorf("Serialize #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("Serialize #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Deserialize the block.
		var block MsgBlock
		rbuf := bytes.NewReader(test.buf)
		err = block.Deserialize(rbuf)
		if err != nil {
			t.Errorf("Deserialize #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&block, test.out) {
			t.Errorf("Deserialize #%d\n got: %s want: %s", i,
				spew.Sdump(&block), spew.Sdump(test.out))
			continue
		}

		// Deserialize the block while gathering transaction location
		// information.
		var txLocBlock MsgBlock
		br := bytes.NewBuffer(test.buf)
		txLocs, err := txLocBlock.DeserializeTxLoc(br)
		if err != nil {
			t.Errorf("DeserializeTxLoc #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&txLocBlock, test.out) {
			t.Errorf("DeserializeTxLoc #%d\n got: %s want: %s", i,
				spew.Sdump(&txLocBlock), spew.Sdump(test.out))
			continue
		}
		if !reflect.DeepEqual(txLocs, test.txLocs) {
			t.Errorf("DeserializeTxLoc #%d\n got: %s want: %s", i,
				spew.Sdump(txLocs), spew.Sdump(test.txLocs))
			continue
		}
	}
}

// TestBlockSerializeErrors performs negative tests against wire encode and
// decode of MsgBlock to confirm error paths work correctly.
func TestBlockSerializeErrors(t *testing.T) {
	tests := []struct {
		in       *MsgBlock // Value to encode
		buf      []byte    // Serialized data
		max      int       // Max size of fixed buffer to induce errors
		writeErr error     // Expected write error
		readErr  error     // Expected read error
	}{
		// Force error in version.
		{&blockOne, blockOneBytes, 0, io.ErrShortWrite, io.EOF},
		// Force error in prev block hash.
		{&blockOne, blockOneBytes, 4, io.ErrShortWrite, io.EOF},
		// Force error in merkle root.
		{&blockOne, blockOneBytes, 36, io.ErrShortWrite, io.EOF},
		// Force error in timestamp.
		{&blockOne, blockOneBytes, 68, io.ErrShortWrite, io.EOF},
		// Force error in difficulty bits.
		{&blockOne, blockOneBytes, 72, io.ErrShortWrite, io.EOF},
		// Force error in header nonce.
		{&blockOne, blockOneBytes, 76, io.ErrShortWrite, io.EOF},
		// Force error in transaction count.
		{&blockOne, blockOneBytes, 80, io.ErrShortWrite, io.EOF},
		// Force error in transactions.
		{&blockOne, blockOneBytes, 81, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the block.
		w := newFixedWriter(test.max)
		err := test.in.Serialize(w)
		if err != test.writeErr {
			t.Errorf("Serialize #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Deserialize the block.
		var block MsgBlock
		r := newFixedReader(test.max, test.buf)
		err = block.Deserialize(r)
		if err != test.readErr {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		var txLocBlock MsgBlock
		br := bytes.NewBuffer(test.buf[0:test.max])
		_, err = txLocBlock.DeserializeTxLoc(br)
		if err != test.readErr {
			t.Errorf("DeserializeTxLoc #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestBlockOverflowErrors  performs tests to ensure deserializing blocks which
// are intentionally crafted to use large values for the number of transactions
// are handled properly.  This could otherwise potentially be used as an attack
// vector.
func TestBlockOverflowErrors(t *testing.T) {
	// Use protocol version 70001 specifically here instead of the latest
	// protocol version because the test data is using bytes encoded with
	// that version.
	pver := uint32(70001)

	tests := []struct {
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
		err  error           // Expected error
	}{
		// Block that claims to have ~uint64(0) transactions.
		{
			[]byte{
				0x01, 0x00, 0x00, 0x00, // Version 1
				0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
				0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
				0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
				0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, // PrevBlock
				0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
				0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
				0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
				0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e, // MerkleRoot
				0x61, 0xbc, 0x66, 0x49, // Timestamp
				0xff, 0xff, 0x00, 0x1d, // Bits
				0x01, 0xe3, 0x62, 0x99, // Nonce
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // TxnCount
			}, pver, BaseEncoding, &MessageError{},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode from wire format.
		var msg MsgBlock
		r := bytes.NewReader(test.buf)
		err := msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}

		// Deserialize from wire format.
		r = bytes.NewReader(test.buf)
		err = msg.Deserialize(r)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}

		// Deserialize with transaction location info from wire format.
		br := bytes.NewBuffer(test.buf)
		_, err = msg.DeserializeTxLoc(br)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("DeserializeTxLoc #%d wrong error got: %v, "+
				"want: %v", i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// TestBlockSerializeSize performs tests to ensure the serialize size for
// various blocks is accurate.
func TestBlockSerializeSize(t *testing.T) {
	// Block with no transactions.
	noTxBlock := NewMsgBlock(&blockOne.Header)

	tests := []struct {
		in   *MsgBlock // Block to encode
		size int       // Expected serialized size
	}{
		// Block with no transactions.
		{noTxBlock, 81},

		// First block in the mainnet block chain.
		{&blockOne, len(blockOneBytes)},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		serializedSize := test.in.SerializeSize()
		if serializedSize != test.size {
			t.Errorf("MsgBlock.SerializeSize: #%d got: %d, want: "+
				"%d", i, serializedSize, test.size)
			continue
		}
	}
}

func TestDeserializeBlockBytes(t *testing.T) {
	tests := []struct {
		name       string
		blk        []byte
		wantHash   string
		wantNumTx  int
		wantLastTx string
	}{
		{
			"block 1821752 pre-MWEB activation",
			block1821752,
			"ece484c02e84e4b1c551fbbdde3045e9096c970fbd3e31f2586b68d50dad6b24",
			3,
			"cb4d9d2d7ab7211ddf030a667d320fe499c849623e9d4a130e1901391e9d4947",
		},
		{
			"block 2215584 MWEB",
			block2215584,
			"7e35fabe7b3c694ebeb0368a1a1c31e83962f3c5b4cc8dcede3ae94ed3deb306",
			5,
			"4c86658e64861c2f2b7fbbf26bbf7a6640ae3824d24293a009ad5ea1e8ab4418",
		},
		{
			"block 2215586 MWEB",
			block2215586,
			"3000cc2076a568a8eb5f56a06112a57264446e2c7d2cca28cdc85d91820dfa17",
			37,
			"3a7299f5e6ee9975bdcc2d754ff5de3312d92db177b55c68753a1cdf9ce63a7c",
		},
		{
			"block 2321749 MWEB",
			block2321749,
			"57929846db4a92d937eb596354d10949e33c815ee45df0c9b3bbdfb283e15bcd",
			4,
			"1bad5e78b145947d32eeeb1d24295891ba03359508d5f09921bada3be66bbe17",
		},
		{
			"block 2319633 MWEB",
			block2319633,
			"e9fe2c6496aedefa8bf6529bdc5c1f9fd4af565ca4c98cab73e3a1f616fb3502",
			2,
			"3cd43df64e9382040eff0bf54ba1c2389d5111eb5ab0968ab7af67e3c30cac04",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg MsgBlock
			r := bytes.NewReader(tt.blk)
			err := msg.Deserialize(r)
			if err != nil {
				t.Fatal(err)
			}

			blkHash := msg.BlockHash()
			if blkHash.String() != tt.wantHash {
				t.Errorf("Wanted block hash %v, got %v", tt.wantHash, blkHash)
			}

			if len(msg.Transactions) != tt.wantNumTx {
				t.Errorf("Wanted %d txns, found %d", tt.wantNumTx, len(msg.Transactions))
			}

			lastTxHash := msg.Transactions[len(msg.Transactions)-1].TxHash()
			if lastTxHash.String() != tt.wantLastTx {
				t.Errorf("Wanted last tx hash %v, got %v", tt.wantLastTx, lastTxHash)
			}
		})
	}
}

// blockOne is the first block in the mainnet block chain.
var blockOne = MsgBlock{
	Header: BlockHeader{
		Version: 1,
		PrevBlock: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
			0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
			0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
			0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
		}),
		MerkleRoot: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
			0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
			0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
			0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e,
		}),

		Timestamp: time.Unix(0x4966bc61, 0), // 2009-01-08 20:54:25 -0600 CST
		Bits:      0x1d00ffff,               // 486604799
		Nonce:     0x9962e301,               // 2573394689
	},
	Transactions: []*MsgTx{
		{
			Version: 1,
			TxIn: []*TxIn{
				{
					PreviousOutPoint: OutPoint{
						Hash:  chainhash.Hash{},
						Index: 0xffffffff,
					},
					SignatureScript: []byte{
						0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04,
					},
					Sequence: 0xffffffff,
				},
			},
			TxOut: []*TxOut{
				{
					Value: 0x12a05f200,
					PkScript: []byte{
						0x41, // OP_DATA_65
						0x04, 0x96, 0xb5, 0x38, 0xe8, 0x53, 0x51, 0x9c,
						0x72, 0x6a, 0x2c, 0x91, 0xe6, 0x1e, 0xc1, 0x16,
						0x00, 0xae, 0x13, 0x90, 0x81, 0x3a, 0x62, 0x7c,
						0x66, 0xfb, 0x8b, 0xe7, 0x94, 0x7b, 0xe6, 0x3c,
						0x52, 0xda, 0x75, 0x89, 0x37, 0x95, 0x15, 0xd4,
						0xe0, 0xa6, 0x04, 0xf8, 0x14, 0x17, 0x81, 0xe6,
						0x22, 0x94, 0x72, 0x11, 0x66, 0xbf, 0x62, 0x1e,
						0x73, 0xa8, 0x2c, 0xbf, 0x23, 0x42, 0xc8, 0x58,
						0xee, // 65-byte signature
						0xac, // OP_CHECKSIG
					},
				},
			},
			LockTime: 0,
		},
	},
}

// Block one serialized bytes.
var blockOneBytes = []byte{
	0x01, 0x00, 0x00, 0x00, // Version 1
	0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
	0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
	0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
	0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, // PrevBlock
	0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
	0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
	0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
	0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e, // MerkleRoot
	0x61, 0xbc, 0x66, 0x49, // Timestamp
	0xff, 0xff, 0x00, 0x1d, // Bits
	0x01, 0xe3, 0x62, 0x99, // Nonce
	0x01,                   // TxnCount
	0x01, 0x00, 0x00, 0x00, // Version
	0x01, // Varint for number of transaction inputs
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
	0xff, 0xff, 0xff, 0xff, // Prevous output index
	0x07,                                     // Varint for length of signature script
	0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, // Signature script (coinbase)
	0xff, 0xff, 0xff, 0xff, // Sequence
	0x01,                                           // Varint for number of transaction outputs
	0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // Transaction amount
	0x43, // Varint for length of pk script
	0x41, // OP_DATA_65
	0x04, 0x96, 0xb5, 0x38, 0xe8, 0x53, 0x51, 0x9c,
	0x72, 0x6a, 0x2c, 0x91, 0xe6, 0x1e, 0xc1, 0x16,
	0x00, 0xae, 0x13, 0x90, 0x81, 0x3a, 0x62, 0x7c,
	0x66, 0xfb, 0x8b, 0xe7, 0x94, 0x7b, 0xe6, 0x3c,
	0x52, 0xda, 0x75, 0x89, 0x37, 0x95, 0x15, 0xd4,
	0xe0, 0xa6, 0x04, 0xf8, 0x14, 0x17, 0x81, 0xe6,
	0x22, 0x94, 0x72, 0x11, 0x66, 0xbf, 0x62, 0x1e,
	0x73, 0xa8, 0x2c, 0xbf, 0x23, 0x42, 0xc8, 0x58,
	0xee,                   // 65-byte uncompressed public key
	0xac,                   // OP_CHECKSIG
	0x00, 0x00, 0x00, 0x00, // Lock time
}

// Transaction location information for block one transactions.
var blockOneTxLocs = []TxLoc{
	{TxStart: 81, TxLen: 134},
}
