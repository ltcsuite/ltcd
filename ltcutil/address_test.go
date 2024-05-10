// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ltcutil_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/ltcutil"
	"golang.org/x/crypto/ripemd160"
)

func TestAddresses(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		encoded string
		valid   bool
		result  ltcutil.Address
		f       func() (ltcutil.Address, error)
		net     *chaincfg.Params
	}{
		// Positive P2PKH tests.
		{
			name:    "litecoin mainnet p2pkh",
			addr:    "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",
			encoded: "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",
			valid:   true,
			result: ltcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x13, 0xc6, 0x0d, 0x8e, 0x68, 0xd7, 0x34, 0x9f, 0x5b, 0x4c,
					0xa3, 0x62, 0xc3, 0x95, 0x4b, 0x15, 0x04, 0x50, 0x61, 0xb1},
				chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0x13, 0xc6, 0x0d, 0x8e, 0x68, 0xd7, 0x34, 0x9f, 0x5b, 0x4c,
					0xa3, 0x62, 0xc3, 0x95, 0x4b, 0x15, 0x04, 0x50, 0x61, 0xb1}
				return ltcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "litecoin mainnet p2pkh with ltc1 prefix and no other '1' chars",
			addr:    "LTC1f9gtb7bU6B4VjHXvPGDi8ACNZhkKPo",
			encoded: "LTC1f9gtb7bU6B4VjHXvPGDi8ACNZhkKPo",
			valid:   true,
			result: ltcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x57, 0x63, 0x02, 0x3d, 0x3f, 0x02, 0x50, 0x96, 0x44, 0xda,
					0xcb, 0xfc, 0x45, 0xf2, 0xc9, 0x10, 0x21, 0x29, 0x74, 0x97},
				chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0x57, 0x63, 0x02, 0x3d, 0x3f, 0x02, 0x50, 0x96, 0x44, 0xda,
					0xcb, 0xfc, 0x45, 0xf2, 0xc9, 0x10, 0x21, 0x29, 0x74, 0x97}
				return ltcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "testnet p2pkh",
			addr:    "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			encoded: "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			valid:   true,
			result: ltcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f},
				chaincfg.TestNet4Params.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f}
				return ltcutil.NewAddressPubKeyHash(pkHash, &chaincfg.TestNet4Params)
			},
			net: &chaincfg.TestNet4Params,
		},

		// Negative P2PKH tests.
		{
			name:  "p2pkh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0x00, 0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b,
					0xf4, 0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad,
					0xaa}
				return ltcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:  "p2pkh bad checksum",
			addr:  "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gY",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},

		// Positive P2SH tests.
		{
			name:    "litecoin mainnet P2SH ",
			addr:    "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9",
			encoded: "MVcg9uEvtWuP5N6V48EHfEtbz48qR8TKZ9",
			valid:   true,
			result: ltcutil.TstAddressScriptHash(
				[ripemd160.Size]byte{
					0xee, 0x34, 0xac, 0x67, 0x6b, 0xda, 0xf6, 0xe3, 0x70, 0xc8,
					0xc8, 0x20, 0xb9, 0x48, 0xed, 0xfa, 0xd3, 0xa8, 0x73, 0xd8},
				chaincfg.MainNetParams.ScriptHashAddrID),
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0xEE, 0x34, 0xAC, 0x67, 0x6B, 0xDA, 0xF6, 0xE3, 0x70, 0xC8,
					0xC8, 0x20, 0xB9, 0x48, 0xED, 0xFA, 0xD3, 0xA8, 0x73, 0xD8}
				return ltcutil.NewAddressScriptHashFromHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			// Taken from litecoind base58_keys_valid.
			name:    "testnet p2sh",
			addr:    "Qec8RUd8PgAMi6dKDKdHQ7zu71kyQNeU5m",
			encoded: "Qec8RUd8PgAMi6dKDKdHQ7zu71kyQNeU5m",
			valid:   true,
			result: ltcutil.TstAddressScriptHash(
				[ripemd160.Size]byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a},
				chaincfg.TestNet4Params.ScriptHashAddrID),
			f: func() (ltcutil.Address, error) {
				hash := []byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a}
				return ltcutil.NewAddressScriptHashFromHash(hash, &chaincfg.TestNet4Params)
			},
			net: &chaincfg.TestNet4Params,
		},

		// Negative P2SH tests.
		{
			name:  "p2sh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (ltcutil.Address, error) {
				hash := []byte{
					0x00, 0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9,
					0xf2, 0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55,
					0x10}
				return ltcutil.NewAddressScriptHashFromHash(hash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},

		// Positive P2PK tests.
		{
			name:    "mainnet p2pk compressed (0x02)",
			addr:    "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
			encoded: "LMRDMebt3wib3ru1CZXMjJQ6X4jY2L2dvx",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4},
				ltcutil.PKFCompressed, chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "mainnet p2pk compressed (0x03)",
			addr:    "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
			encoded: "LQ6ERagJG6wA32WHhtCh3RgGJzQWNxwEcb",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65},
				ltcutil.PKFCompressed, chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name: "mainnet p2pk uncompressed (0x04)",
			addr: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2" +
				"e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
			encoded: "LLqYfYm5SBfqhoT3Rtu6Y4i41a1XzQ5YsL",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3},
				ltcutil.PKFUncompressed, chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "testnet p2pk compressed (0x02)",
			addr:    "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
			encoded: "mhiDPVP2nJunaAgTjzWSHCYfAqxxrxzjmo",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4},
				ltcutil.PKFCompressed, chaincfg.TestNet4Params.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet4Params)
			},
			net: &chaincfg.TestNet4Params,
		},
		{
			name:    "testnet p2pk compressed (0x03)",
			addr:    "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
			encoded: "mkPETRTSzU8MZLHkFKBmbKppxmdw9qT42t",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65},
				ltcutil.PKFCompressed, chaincfg.TestNet4Params.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet4Params)
			},
			net: &chaincfg.TestNet4Params,
		},
		{
			name: "testnet p2pk uncompressed (0x04)",
			addr: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5" +
				"cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
			encoded: "mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF",
			valid:   true,
			result: ltcutil.TstAddressPubKey(
				[]byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3},
				ltcutil.PKFUncompressed, chaincfg.TestNet4Params.PubKeyHashAddrID),
			f: func() (ltcutil.Address, error) {
				serializedPubKey := []byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3}
				return ltcutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet4Params)
			},
			net: &chaincfg.TestNet4Params,
		},
		// Segwit address tests.
		{
			name:    "segwit litecoin mainnet p2wpkh v0",
			addr:    "LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9",
			encoded: "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
			valid:   true,
			result: ltcutil.TstAddressWitnessPubKeyHash(
				0,
				[20]byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6},
				chaincfg.MainNetParams.Bech32HRPSegwit,
			),
			f: func() (ltcutil.Address, error) {
				pkHash := []byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6}
				return ltcutil.NewAddressWitnessPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		// P2TR address tests.
		{
			name:    "segwit v1 mainnet p2tr",
			addr:    "ltc1paardr2nczq0rx5rqpfwnvpzm497zvux64y0f7wjgcs7xuuuh2nnqd8yawa",
			encoded: "ltc1paardr2nczq0rx5rqpfwnvpzm497zvux64y0f7wjgcs7xuuuh2nnqd8yawa",
			valid:   true,
			result: ltcutil.TstAddressTaproot(
				1, [32]byte{
					0xef, 0x46, 0xd1, 0xaa, 0x78, 0x10, 0x1e, 0x33,
					0x50, 0x60, 0x0a, 0x5d, 0x36, 0x04, 0x5b, 0xa9,
					0x7c, 0x26, 0x70, 0xda, 0xa9, 0x1e, 0x9f, 0x3a,
					0x48, 0xc4, 0x3c, 0x6e, 0x73, 0x97, 0x54, 0xe6,
				}, chaincfg.MainNetParams.Bech32HRPSegwit,
			),
			f: func() (ltcutil.Address, error) {
				scriptHash := []byte{
					0xef, 0x46, 0xd1, 0xaa, 0x78, 0x10, 0x1e, 0x33,
					0x50, 0x60, 0x0a, 0x5d, 0x36, 0x04, 0x5b, 0xa9,
					0x7c, 0x26, 0x70, 0xda, 0xa9, 0x1e, 0x9f, 0x3a,
					0x48, 0xc4, 0x3c, 0x6e, 0x73, 0x97, 0x54, 0xe6,
				}
				return ltcutil.NewAddressTaproot(
					scriptHash, &chaincfg.MainNetParams,
				)
			},
			net: &chaincfg.MainNetParams,
		},

		// Invalid bech32m tests. Source:
		// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
		{
			name:  "segwit v1 invalid human-readable part",
			addr:  "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 mainnet bech32 instead of bech32m",
			addr:  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 testnet bech32 instead of bech32m",
			addr:  "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit v1 mainnet bech32 instead of bech32m upper case",
			addr:  "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v0 mainnet bech32m instead of bech32",
			addr:  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 testnet bech32 instead of bech32m second test",
			addr:  "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit v1 mainnet bech32m invalid character in checksum",
			addr:  "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mainnet witness v17",
			addr:  "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 mainnet bech32m invalid program length (1 byte)",
			addr:  "bc1pw5dgrnzv",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 mainnet bech32m invalid program length (41 bytes)",
			addr:  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 testnet bech32m mixed case",
			addr:  "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit v1 mainnet bech32m zero padding of more than 4 bits",
			addr:  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit v1 mainnet bech32m non-zero padding in 8-to-5-conversion",
			addr:  "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit v1 mainnet bech32m empty data section",
			addr:  "bc1gmk9yu",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},

		// Unsupported witness versions (version 0 and 1 only supported at this point)
		{
			name:  "segwit mainnet witness v16",
			addr:  "BC1SW50QA3JX3S",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mainnet witness v2",
			addr:  "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		// Invalid segwit addresses
		{
			name:  "segwit invalid hrp",
			addr:  "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit invalid checksum",
			addr:  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid witness version",
			addr:  "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length",
			addr:  "bc1rw5uspcuh",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length",
			addr:  "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length for witness version 0 (per BIP141)",
			addr:  "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mixed case",
			addr:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit zero padding of more than 4 bits",
			addr:  "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
		{
			name:  "segwit non-zero padding in 8-to-5 conversion",
			addr:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
			valid: false,
			net:   &chaincfg.TestNet4Params,
		},
	}

	for _, test := range tests {
		// Decode addr and compare error against valid.
		decoded, err := ltcutil.DecodeAddress(test.addr, test.net)
		if (err == nil) != test.valid {
			t.Errorf("%v: decoding test failed: %v", test.name, err)
			return
		}

		if err == nil {
			// Ensure the stringer returns the same address as the
			// original.
			if decodedStringer, ok := decoded.(fmt.Stringer); ok {
				addr := test.addr

				// For Segwit addresses the string representation
				// will always be lower case, so in that case we
				// convert the original to lower case first.
				if strings.Contains(test.name, "segwit") {
					addr = strings.ToLower(addr)
				}

				if addr != decodedStringer.String() {
					t.Errorf("%v: String on decoded value does not match expected value: %v != %v",
						test.name, test.addr, decodedStringer.String())
					return
				}
			}

			// Encode again and compare against the original.
			encoded := decoded.EncodeAddress()
			if test.encoded != encoded {
				t.Errorf("%v: decoding and encoding produced different addresses: %v != %v",
					test.name, test.encoded, encoded)
				return
			}

			// Perform type-specific calculations.
			var saddr []byte
			switch d := decoded.(type) {
			case *ltcutil.AddressPubKeyHash:
				saddr = ltcutil.TstAddressSAddr(encoded)

			case *ltcutil.AddressScriptHash:
				saddr = ltcutil.TstAddressSAddr(encoded)

			case *ltcutil.AddressPubKey:
				// Ignore the error here since the script
				// address is checked below.
				saddr, _ = hex.DecodeString(d.String())
			case *ltcutil.AddressWitnessPubKeyHash:
				saddr = ltcutil.TstAddressSegwitSAddr(encoded)
			case *ltcutil.AddressWitnessScriptHash:
				saddr = ltcutil.TstAddressSegwitSAddr(encoded)
			case *ltcutil.AddressTaproot:
				saddr = ltcutil.TstAddressTaprootSAddr(encoded)
			}

			// Check script address, as well as the Hash160 method for P2PKH and
			// P2SH addresses.
			if !bytes.Equal(saddr, decoded.ScriptAddress()) {
				t.Errorf("%v: script addresses do not match:\n%x != \n%x",
					test.name, saddr, decoded.ScriptAddress())
				return
			}
			switch a := decoded.(type) {
			case *ltcutil.AddressPubKeyHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *ltcutil.AddressScriptHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *ltcutil.AddressWitnessPubKeyHash:
				if hrp := a.Hrp(); test.net.Bech32HRPSegwit != hrp {
					t.Errorf("%v: hrps do not match:\n%x != \n%x",
						test.name, test.net.Bech32HRPSegwit, hrp)
					return
				}

				expVer := test.result.(*ltcutil.AddressWitnessPubKeyHash).WitnessVersion()
				if v := a.WitnessVersion(); v != expVer {
					t.Errorf("%v: witness versions do not match:\n%x != \n%x",
						test.name, expVer, v)
					return
				}

				if p := a.WitnessProgram(); !bytes.Equal(saddr, p) {
					t.Errorf("%v: witness programs do not match:\n%x != \n%x",
						test.name, saddr, p)
					return
				}

			case *ltcutil.AddressWitnessScriptHash:
				if hrp := a.Hrp(); test.net.Bech32HRPSegwit != hrp {
					t.Errorf("%v: hrps do not match:\n%x != \n%x",
						test.name, test.net.Bech32HRPSegwit, hrp)
					return
				}

				expVer := test.result.(*ltcutil.AddressWitnessScriptHash).WitnessVersion()
				if v := a.WitnessVersion(); v != expVer {
					t.Errorf("%v: witness versions do not match:\n%x != \n%x",
						test.name, expVer, v)
					return
				}

				if p := a.WitnessProgram(); !bytes.Equal(saddr, p) {
					t.Errorf("%v: witness programs do not match:\n%x != \n%x",
						test.name, saddr, p)
					return
				}
			}

			// Ensure the address is for the expected network.
			if !decoded.IsForNet(test.net) {
				t.Errorf("%v: calculated network does not match expected",
					test.name)
				return
			}
		} else {
			// If there is an error, make sure we can print it
			// correctly.
			errStr := err.Error()
			if errStr == "" {
				t.Errorf("%v: error was non-nil but message is"+
					"empty: %v", test.name, err)
			}
		}

		if !test.valid {
			// If address is invalid, but a creation function exists,
			// verify that it returns a nil addr and non-nil error.
			if test.f != nil {
				_, err := test.f()
				if err == nil {
					t.Errorf("%v: address is invalid but creating new address succeeded",
						test.name)
					return
				}
			}
			continue
		}

		// Valid test, compare address created with f against expected result.
		addr, err := test.f()
		if err != nil {
			t.Errorf("%v: address is valid but creating new address failed with error %v",
				test.name, err)
			return
		}

		if !reflect.DeepEqual(addr, test.result) {
			t.Errorf("%v: created address does not match expected result",
				test.name)
			return
		}
	}
}
