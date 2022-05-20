module github.com/ltcsuite/ltcd

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/btcsuite/goleveldb v1.0.0
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/btcsuite/winsvc v1.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/lru v1.0.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/ltcsuite/ltcd/btcec/v2 v2.1.0
	github.com/ltcsuite/ltcd/ltcutil v1.1.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/snappy-go v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.15.0 // indirect
	github.com/onsi/gomega v1.10.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20210521195947-fe42d452be8f // indirect
	golang.org/x/sys v0.0.0-20210521203332-0cec03c779c1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/ltcsuite/ltcd/ltcutil => ./ltcutil

replace github.com/ltcsuite/ltcd/btcec/v2 => ./btcec

go 1.17
