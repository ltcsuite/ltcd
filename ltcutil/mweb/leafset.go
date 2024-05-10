package mweb

import (
	"encoding/binary"
	"io"

	"github.com/ltcmweb/ltcd/wire"
)

type Leafset struct {
	Bits   []byte
	Size   uint64
	Height uint32
	Block  *wire.BlockHeader
}

func (l *Leafset) Contains(i uint64) bool {
	if i >= l.Size {
		return false
	}
	return l.Bits[i/8]&(0x80>>(i%8)) > 0
}

func (l *Leafset) Serialize(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, l.Size)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.LittleEndian, l.Height)
	if err != nil {
		return err
	}

	err = l.Block.Serialize(w)
	if err != nil {
		return err
	}

	_, err = w.Write(l.Bits)
	return err
}

func (l *Leafset) Deserialize(r io.Reader) error {
	err := binary.Read(r, binary.LittleEndian, &l.Size)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.LittleEndian, &l.Height)
	if err != nil {
		return err
	}

	l.Block = &wire.BlockHeader{}
	err = l.Block.Deserialize(r)
	if err != nil {
		return err
	}

	l.Bits = make([]byte, (l.Size+7)/8)
	_, err = r.Read(l.Bits)
	return err
}
