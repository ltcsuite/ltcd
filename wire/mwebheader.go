// Copyright (c) 2024 The ltcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"errors"
	"io"
	"math"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"lukechampine.com/blake3"
)

// The MWEB header struct
type MwebHeader struct {
	Height        int32
	OutputRoot    chainhash.Hash
	KernelRoot    chainhash.Hash
	LeafsetRoot   chainhash.Hash
	KernelOffset  chainhash.Hash
	StealthOffset chainhash.Hash
	OutputMMRSize uint64
	KernelMMRSize uint64
}

// Read the Litecoin-internal VarInt encoding
func readVarInt(r io.Reader) (n uint64, err error) {
	var buf [1]byte
	for {
		if _, err = r.Read(buf[:]); err != nil {
			return
		}
		if n > math.MaxUint64>>7 {
			return n, errors.New("size too large")
		}
		n = n<<7 | uint64(buf[0]&0x7f)
		if buf[0]&0x80 == 0 {
			return
		}
		if n == math.MaxUint64 {
			return n, errors.New("size too large")
		}
		n++
	}
}

// Write the Litecoin-internal VarInt encoding
func writeVarInt(w io.Writer, n uint64) error {
	var buf [10]byte
	i := 0
	for ; ; i++ {
		buf[i] = byte(n & 0x7f)
		if i > 0 {
			buf[i] |= 0x80
		}
		if n < 0x80 {
			break
		}
		n = (n >> 7) - 1
	}
	for ; i >= 0; i-- {
		if _, err := w.Write(buf[i : i+1]); err != nil {
			return err
		}
	}
	return nil
}

// Reads a litecoin mweb header from r.  See Deserialize for
// decoding mweb headers stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (mh *MwebHeader) read(r io.Reader) error {
	n, err := readVarInt(r)
	if err != nil {
		return err
	}
	mh.Height = int32(n)

	err = readElements(r, &mh.OutputRoot, &mh.KernelRoot,
		&mh.LeafsetRoot, &mh.KernelOffset, &mh.StealthOffset)
	if err != nil {
		return err
	}

	mh.OutputMMRSize, err = readVarInt(r)
	if err != nil {
		return err
	}

	mh.KernelMMRSize, err = readVarInt(r)
	return err
}

// Writes a litecoin mweb header to w.  See Serialize for
// encoding mweb headers to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (mh *MwebHeader) write(w io.Writer) error {
	err := writeVarInt(w, uint64(mh.Height))
	if err != nil {
		return err
	}

	err = writeElements(w, &mh.OutputRoot, &mh.KernelRoot,
		&mh.LeafsetRoot, &mh.KernelOffset, &mh.StealthOffset)
	if err != nil {
		return err
	}

	err = writeVarInt(w, mh.OutputMMRSize)
	if err != nil {
		return err
	}

	err = writeVarInt(w, mh.KernelMMRSize)
	return err
}

// Hash of the mweb header
func (mh *MwebHeader) Hash() *chainhash.Hash {
	h := blake3.New(32, nil)
	mh.write(h)
	return (*chainhash.Hash)(h.Sum(nil))
}
