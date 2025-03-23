module github.com/ltcsuite/ltcd/ltcutil/psbt

go 1.17

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/ltcsuite/ltcd v0.23.5
	github.com/ltcsuite/ltcd/btcec/v2 v2.3.2
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2
	github.com/ltcsuite/ltcd/ltcutil v1.1.4-0.20240325211356-491681cb5556
	github.com/stretchr/testify v1.8.3
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)

replace github.com/ltcsuite/ltcd => ../..

replace github.com/ltcsuite/ltcd/ltcutil => ../
