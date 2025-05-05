package mweb_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

var (
	outputRawBytes = "" +
		"087c3e31a61d3d46bdb13729d3c4ac39da15fb13f3e1b1e0e1abdbbc52ca03f0" +
		"2d031a4777fdfcbb3594ac4f7b57a1ad4343d27601e8542cac591733098d41e4" +
		"9c5002e44d6d8cbdb20d58b39a3294ea6e94031ae09e4a489e4f484ceea0df6c" +
		"467a76010334bab2ce38ea861e61d92386b4bdbb916ce3b481ce996ad5e62c2f" +
		"6801fa8e4e51f84fd893a8c658fcca5b70966568af374bfb0e75f24830ca0000" +
		"000000000000000000000000000000000000000000000000000000000000c090" +
		"05a93313d9d9ea3805655f5474e3f39db5ae4d0bc29c6ab3f3aded78e46da942" +
		"a4ec525fbf41cbb3e9bf878bbe0c26dba6f44250cc55c82a7fd1eb90a51ceda0" +
		"89ee46105283bb99cf465eb1bc901c62e289e3e710ec8df7daeaab187b9e"

	scanKeyBytes   = "164c6001b2623ed37be1c776567d12fe28c82664bd7497e63b0efcddb5b3ec48"
	spendKeyBytes  = "ef66d0e0f7d2c59b3d7f5837ac4831ed0805f8f48f8bfd574a7fafc065b5747f"
	senderKeyBytes = "46ea6b248ba712462007aad44d06d8cb2f05c2ab737a8fc3e0ff328676fa40e7"
)

func TestSignature(t *testing.T) {
	outputRawBytes, _ := hex.DecodeString(outputRawBytes)
	output := &wire.MwebOutput{}
	output.Deserialize(bytes.NewReader(outputRawBytes))
	senderKey, _ := hex.DecodeString(senderKeyBytes)

	h := blake3.New(32, nil)
	h.Write(output.Commitment[:])
	h.Write(output.SenderPubKey[:])
	h.Write(output.ReceiverPubKey[:])
	h.Write(output.Message.Hash()[:])
	h.Write(output.RangeProofHash[:])

	if mw.Sign((*mw.SecretKey)(senderKey), h.Sum(nil)) != output.Signature {
		t.Error("unexpected signature")
	}
}

func TestRewindOutput(t *testing.T) {
	outputRawBytes, _ := hex.DecodeString(outputRawBytes)
	output := &wire.MwebOutput{}
	output.Deserialize(bytes.NewReader(outputRawBytes))
	scan, _ := hex.DecodeString(scanKeyBytes)
	spend, _ := hex.DecodeString(spendKeyBytes)
	keys := &mweb.Keychain{Scan: (*mw.SecretKey)(scan), Spend: (*mw.SecretKey)(spend)}
	coin, err := mweb.RewindOutput(output, keys.Scan)
	if err != nil {
		t.Fatalf("RewindOutput failed: %s", err.Error())
	}
	if coin.Value != 0.1*ltcutil.SatoshiPerBitcoin {
		t.Error("unexpected value")
	}
	if !coin.Address.Equal(keys.Address(0)) {
		t.Error("unexpected address")
	}
	addr := ltcutil.NewAddressMweb(coin.Address, &chaincfg.TestNet4Params)
	if addr.String() != "tmweb1qqv0mlyyk7sl09jkcrgy059m5yplw567ypuj6lxpwkcw4tl8m59p7wq6jc"+
		"6prtph5kf45kdlql8fjppr32nmwng34fs6ess9fq72ck7lfyvmr6s0c" {
		t.Error("unexpected address")
	}
}
