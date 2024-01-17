module github.com/ltcsuite/ltcd/ltcutil

go 1.17

require (
	github.com/aead/siphash v1.0.1
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/kkdai/bstream v1.0.0
	github.com/ltcsuite/ltcd v0.23.5
	github.com/ltcsuite/ltcd/btcec/v2 v2.3.2
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	lukechampine.com/blake3 v1.2.1
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace github.com/ltcsuite/ltcd => ../

replace github.com/ltcsuite/ltcd/btcec/v2 => ../btcec

replace github.com/ltcsuite/ltcd/chaincfg/chainhash => ../chaincfg/chainhash
