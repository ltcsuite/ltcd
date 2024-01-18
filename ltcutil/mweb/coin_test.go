package mweb_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
)

func TestRewindOutput(t *testing.T) {
	outputRawBytes, _ := hex.DecodeString(
		"01087c3e31a61d3d46bdb13729d3c4ac39da15fb13f3e1b1e0e1abdbbc52ca03" +
			"f02d031a4777fdfcbb3594ac4f7b57a1ad4343d27601e8542cac591733098d41" +
			"e49c5002e44d6d8cbdb20d58b39a3294ea6e94031ae09e4a489e4f484ceea0df" +
			"6c467a76010334bab2ce38ea861e61d92386b4bdbb916ce3b481ce996ad5e62c" +
			"2f6801fa8e4e51f84fd893a8c658fcca5b70966568af374bfb0e75f24830cac0" +
			"9005a93313d9d9ea3805655f5474e3f39db5ae4d0bc29c6ab3f3aded78e46da9" +
			"42a4ec525fbf41cbb3e9bf878bbe0c26dba6f44250cc55c82a7fd1eb90a51ced" +
			"a089ee46105283bb99cf465eb1bc901c62e289e3e710ec8df7daeaab187b9e",
	)
	output := &wire.MwebOutput{}
	output.Deserialize(bytes.NewReader(outputRawBytes))
	scan, _ := hex.DecodeString("164c6001b2623ed37be1c776567d12fe28c82664bd7497e63b0efcddb5b3ec48")
	spend, _ := hex.DecodeString("ef66d0e0f7d2c59b3d7f5837ac4831ed0805f8f48f8bfd574a7fafc065b5747f")
	keys := &mweb.Keychain{Scan: (*mw.SecretKey)(scan), Spend: (*mw.SecretKey)(spend)}
	coin, err := mweb.RewindOutput(output, keys.Scan)
	if err != nil {
		t.Fatalf("RewindOutput failed: %s", err.Error())
	}
	coin.CalculateOutputKey(keys.SpendKey(0))
	if coin.SpendKey == nil {
		t.Fatalf("CalculateOutputKey failed: %s", err.Error())
	}
}
