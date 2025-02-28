package mweb

import (
	"math"

	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/txscript"
	"github.com/ltcmweb/ltcd/wire"
)

const (
	BaseMwebFee = 100

	BaseKernelWeight        = 2
	StealthExcessWeight     = 1
	KernelWithStealthWeight = BaseKernelWeight + StealthExcessWeight

	BaseOutputWeight           = 17
	StandardOutputFieldsWeight = 1
	StandardOutputWeight       = BaseOutputWeight + StandardOutputFieldsWeight

	// For any extra data added to inputs, outputs or kernels
	BytesPerWeight = 42
)

func EstimateFee(outputs []*wire.TxOut,
	feeRatePerKb ltcutil.Amount, includeChange bool) uint64 {

	var weight uint64 = KernelWithStealthWeight
	var txOutSize int

	for _, txOut := range outputs {
		if txscript.IsMweb(txOut.PkScript) {
			weight += StandardOutputWeight
		} else {
			weight += (uint64(len(txOut.PkScript)) +
				BytesPerWeight - 1) / BytesPerWeight
			txOutSize += txOut.SerializeSize()
		}
	}

	if includeChange {
		weight += StandardOutputWeight
	}

	fee := math.Ceil(float64(feeRatePerKb) * float64(txOutSize) / 1000)
	return uint64(fee) + weight*BaseMwebFee
}
