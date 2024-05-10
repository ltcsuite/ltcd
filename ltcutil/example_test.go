package ltcutil_test

import (
	"fmt"
	"math"

	"github.com/ltcmweb/ltcd/ltcutil"
)

func ExampleAmount() {

	a := ltcutil.Amount(0)
	fmt.Println("Zero Satoshi:", a)

	a = ltcutil.Amount(1e8)
	fmt.Println("100,000,000 Satoshis:", a)

	a = ltcutil.Amount(1e5)
	fmt.Println("100,000 Satoshis:", a)
	// Output:
	// Zero Satoshi: 0 LTC
	// 100,000,000 Satoshis: 1 LTC
	// 100,000 Satoshis: 0.00100000 LTC
}

func ExampleNewAmount() {
	amountOne, err := ltcutil.NewAmount(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountOne) //Output 1

	amountFraction, err := ltcutil.NewAmount(0.01234567)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountFraction) //Output 2

	amountZero, err := ltcutil.NewAmount(0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountZero) //Output 3

	amountNaN, err := ltcutil.NewAmount(math.NaN())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountNaN) //Output 4

	// Output: 1 LTC
	// 0.01234567 LTC
	// 0 LTC
	// invalid litecoin amount
}

func ExampleAmount_unitConversions() {
	amount := ltcutil.Amount(44433322211100)

	fmt.Println("Satoshi to kLTC:", amount.Format(ltcutil.AmountKiloBTC))
	fmt.Println("Satoshi to LTC:", amount)
	fmt.Println("Satoshi to MilliLTC:", amount.Format(ltcutil.AmountMilliBTC))
	fmt.Println("Satoshi to MicroLTC:", amount.Format(ltcutil.AmountMicroBTC))
	fmt.Println("Satoshi to Litoshi:", amount.Format(ltcutil.AmountSatoshi))

	// Output:
	// Satoshi to kLTC: 444.333222111 kLTC
	// Satoshi to LTC: 444333.22211100 LTC
	// Satoshi to MilliLTC: 444333222.111 mLTC
	// Satoshi to MicroLTC: 444333222111 μLTC
	// Satoshi to Litoshi: 44433322211100 Litoshi
}
