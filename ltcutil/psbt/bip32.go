package psbt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ltcsuite/ltcd/btcec/v2"
	"github.com/ltcsuite/ltcd/ltcutil/base58"
	"github.com/ltcsuite/ltcd/ltcutil/hdkeychain"
	"math/big"
)

const BIP32_EXTKEY_SIZE = 74
const BIP32_EXTKEY_WITH_VERSION_SIZE = 78

// Bip32Derivation encapsulates the data for the input and output
// Bip32Derivation key-value fields.
//
// TODO(roasbeef): use hdkeychain here instead?
type Bip32Derivation struct {
	// PubKey is the raw pubkey serialized in compressed format.
	PubKey []byte

	// MasterKeyFingerprint is the fingerprint of the master pubkey.
	MasterKeyFingerprint uint32

	// Bip32Path is the BIP 32 path with child index as a distinct integer.
	Bip32Path []uint32
}

// checkValid ensures that the PubKey in the Bip32Derivation struct is valid.
func (pb *Bip32Derivation) checkValid() bool {
	return validatePubkey(pb.PubKey)
}

// Bip32Sorter implements sort.Interface for the Bip32Derivation struct.
type Bip32Sorter []*Bip32Derivation

func (s Bip32Sorter) Len() int { return len(s) }

func (s Bip32Sorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s Bip32Sorter) Less(i, j int) bool {
	return bytes.Compare(s[i].PubKey, s[j].PubKey) < 0
}

// ReadBip32Derivation deserializes a byte slice containing chunks of 4 byte
// little endian encodings of uint32 values, the first of which is the
// masterkeyfingerprint and the remainder of which are the derivation path.
func ReadBip32Derivation(path []byte) (uint32, []uint32, error) {
	// BIP-0174 defines the derivation path being encoded as
	//   "<32-bit uint> <32-bit uint>*"
	// with the asterisk meaning 0 to n times. Which in turn means that an
	// empty path is valid, only the key fingerprint is mandatory.
	if len(path)%4 != 0 {
		return 0, nil, ErrInvalidPsbtFormat
	}

	masterKeyInt := binary.LittleEndian.Uint32(path[:4])

	var paths []uint32
	for i := 4; i < len(path); i += 4 {
		paths = append(paths, binary.LittleEndian.Uint32(path[i:i+4]))
	}

	return masterKeyInt, paths, nil
}

// SerializeBIP32Derivation takes a master key fingerprint as defined in BIP32,
// along with a path specified as a list of uint32 values, and returns a
// bytestring specifying the derivation in the format required by BIP174: //
// master key fingerprint (4) || child index (4) || child index (4) || ....
func SerializeBIP32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32) []byte {

	var masterKeyBytes [4]byte
	binary.LittleEndian.PutUint32(masterKeyBytes[:], masterKeyFingerprint)

	derivationPath := make([]byte, 0, 4+4*len(bip32Path))
	derivationPath = append(derivationPath, masterKeyBytes[:]...)
	for _, path := range bip32Path {
		var pathbytes [4]byte
		binary.LittleEndian.PutUint32(pathbytes[:], path)
		derivationPath = append(derivationPath, pathbytes[:]...)
	}

	return derivationPath
}

// Parses 78 byte BIP32 Extended key with version bytes.
// Similar to hdkeychain.NewKeyFromString, except without the checksum, and using raw bytes instead of base58.
func readExtendedKey(payload []byte) (*hdkeychain.ExtendedKey, error) {
	if len(payload) != 78 {
		return nil, fmt.Errorf("invalid xpub length: %d", len(payload))
	}

	// Deserialize each of the payload fields.
	version := payload[:4]
	depth := payload[4:5][0]
	parentFP := payload[5:9]
	childNum := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:78]

	// The key data is a private key if it starts with 0x00.  Serialized
	// compressed pubkeys either start with 0x02 or 0x03.
	isPrivate := keyData[0] == 0x00
	if isPrivate {
		// Ensure the private key is valid.  It must be within the range
		// of the order of the secp256k1 curve and not be 0.
		keyData = keyData[1:]
		keyNum := new(big.Int).SetBytes(keyData)
		if keyNum.Cmp(btcec.S256().N) >= 0 || keyNum.Sign() == 0 {
			return nil, hdkeychain.ErrUnusableSeed
		}
	} else {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		_, err := btcec.ParsePubKey(keyData)
		if err != nil {
			return nil, err
		}
	}

	return hdkeychain.NewExtendedKey(version, keyData, chainCode, parentFP, depth, childNum, isPrivate), nil
}

// Writes the 78 byte BIP32 Extended key with version bytes. No checksum is included.
func writeExtendedKey(extKey *hdkeychain.ExtendedKey) []byte {
	return base58.Decode(extKey.String())[0:78]
}
