package wire

import (
	"errors"
	"io"
	"math/big"
	"sort"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

type (
	MwebTxBody struct {
		Inputs  []*MwebInput
		Outputs []*MwebOutput
		Kernels []*MwebKernel
	}

	MwebTx struct {
		KernelOffset  mw.BlindingFactor
		StealthOffset mw.BlindingFactor
		TxBody        *MwebTxBody
	}
)

func (tb *MwebTxBody) Sort() {
	sort.Slice(tb.Inputs, func(i, j int) bool {
		a := new(big.Int).SetBytes(tb.Inputs[i].OutputId[:])
		b := new(big.Int).SetBytes(tb.Inputs[j].OutputId[:])
		return a.Cmp(b) < 0
	})
	sort.Slice(tb.Outputs, func(i, j int) bool {
		a := new(big.Int).SetBytes(tb.Outputs[i].Hash()[:])
		b := new(big.Int).SetBytes(tb.Outputs[j].Hash()[:])
		return a.Cmp(b) < 0
	})
	sort.Slice(tb.Kernels, func(i, j int) bool {
		da := tb.Kernels[i].SupplyChange()
		db := tb.Kernels[j].SupplyChange()
		a := new(big.Int).SetBytes(tb.Kernels[i].Hash()[:])
		b := new(big.Int).SetBytes(tb.Kernels[j].Hash()[:])
		return da > db || da == db && a.Cmp(b) < 0
	})
}

// Reads a litecoin mweb txbody from r.  See Deserialize for
// decoding mweb txbodys stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (tb *MwebTxBody) read(r io.Reader, pver uint32) (err error) {
	var count uint64

	if count, err = ReadVarInt(r, pver); err != nil {
		return
	}
	if count > maxTxInPerMessage {
		return errors.New("too many inputs")
	}
	tb.Inputs = make([]*MwebInput, count)
	for i := range tb.Inputs {
		tb.Inputs[i] = &MwebInput{}
		if err = tb.Inputs[i].read(r, pver); err != nil {
			return
		}
	}

	if count, err = ReadVarInt(r, pver); err != nil {
		return
	}
	if count > maxTxOutPerMessage {
		return errors.New("too many outputs")
	}
	tb.Outputs = make([]*MwebOutput, count)
	for i := range tb.Outputs {
		tb.Outputs[i] = &MwebOutput{}
		if err = tb.Outputs[i].read(r, pver, false); err != nil {
			return
		}
	}

	if count, err = ReadVarInt(r, pver); err != nil {
		return
	}
	if count > maxTxPerBlock {
		return errors.New("too many kernels")
	}
	tb.Kernels = make([]*MwebKernel, count)
	for i := range tb.Kernels {
		tb.Kernels[i] = &MwebKernel{}
		if err = tb.Kernels[i].read(r, pver); err != nil {
			return
		}
	}

	return
}

// Writes a litecoin mweb txbody to w.  See Serialize for
// encoding mweb txbodys to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (tb *MwebTxBody) write(w io.Writer, pver uint32) (err error) {
	if err = WriteVarInt(w, pver, uint64(len(tb.Inputs))); err != nil {
		return
	}
	for i := range tb.Inputs {
		if err = tb.Inputs[i].write(w, pver); err != nil {
			return
		}
	}

	if err = WriteVarInt(w, pver, uint64(len(tb.Outputs))); err != nil {
		return
	}
	for i := range tb.Outputs {
		if err = tb.Outputs[i].write(w, pver, false, false); err != nil {
			return
		}
	}

	if err = WriteVarInt(w, pver, uint64(len(tb.Kernels))); err != nil {
		return
	}
	for i := range tb.Kernels {
		if err = tb.Kernels[i].write(w, pver, false); err != nil {
			return
		}
	}

	return
}

// Reads a litecoin mweb tx from r.  See Deserialize for
// decoding mweb txns stored to disk, such as in a database,
// as opposed to decoding from the wire.
func (tx *MwebTx) read(r io.Reader, pver uint32) error {
	err := readElements(r, tx.KernelOffset[:], tx.StealthOffset[:])
	if err != nil {
		return err
	}
	tx.TxBody = &MwebTxBody{}
	if err = tx.TxBody.read(r, pver); err != nil {
		return err
	}
	if len(tx.TxBody.Kernels) < 1 {
		return errors.New("transaction requires at least one kernel")
	}
	return nil
}

// Writes a litecoin mweb tx to w.  See Serialize for
// encoding mweb txns to be stored to disk, such as in
// a database, as opposed to encoding for the wire.
func (tx *MwebTx) write(w io.Writer, pver uint32) error {
	err := writeElements(w, tx.KernelOffset[:], tx.StealthOffset[:])
	if err != nil {
		return err
	}
	return tx.TxBody.write(w, pver)
}
