package mweb

import (
	"errors"

	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

type Recipient struct {
	Address *mw.StealthAddress
	Value   uint64
}

func NewRecipient(address string, value uint64) (*Recipient, error) {
	addr, err := ltcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	mwebAddr, ok := addr.(*ltcutil.AddressMweb)
	if !ok {
		return nil, errors.New("invalid mweb address")
	}
	return &Recipient{
		Address: mwebAddr.StealthAddress(),
		Value:   value,
	}, nil
}
