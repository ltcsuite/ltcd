package mweb

import (
	"reflect"

	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
)

func NewPegin(value uint64, kernel *wire.MwebKernel) *wire.TxOut {
	script, _ := txscript.NewScriptBuilder().
		AddOp(txscript.OP_9).AddData(kernel.Hash()[:]).Script()
	return wire.NewTxOut(int64(value), script)
}

func Pegins(tx *wire.MsgTx) (pegins []*wire.TxOut) {
	for _, txOut := range tx.TxOut {
		version, program, _ :=
			txscript.ExtractWitnessProgramInfo(txOut.PkScript)
		if version == 9 && len(program) == 32 {
			pegins = append(pegins, txOut)
		}
	}
	return
}

func PeginsMatch(pegins []*wire.TxOut, kernels []*wire.MwebKernel) bool {
	var kPegins []*wire.TxOut
	for _, kernel := range kernels {
		if kernel.Pegin > 0 {
			kPegins = append(kPegins, NewPegin(kernel.Pegin, kernel))
		}
	}
	return reflect.DeepEqual(pegins, kPegins)
}
