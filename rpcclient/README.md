rpcclient
=========

[![Build Status](https://github.com/ltcsuite/ltcd/workflows/Build%20and%20Test/badge.svg)](https://github.com/ltcsuite/ltcd/actions)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/ltcsuite/ltcd/rpcclient)

rpcclient implements a Websocket-enabled Litecoin JSON-RPC client package written
in [Go](http://golang.org/).  It provides a robust and easy to use client for
interfacing with a Litecoin RPC server that uses a ltcd/litecoin core compatible
Litecoin JSON-RPC API.

## Status

This package is currently under active development.  It is already stable and
the infrastructure is complete.  However, there are still several RPCs left to
implement and the API is not stable yet.

## Documentation

* [API Reference](https://pkg.go.dev/github.com/ltcsuite/ltcd/rpcclient)
* [ltcd Websockets Example](https://github.com/ltcsuite/ltcd/tree/master/rpcclient/examples/btcdwebsockets)
  Connects to a ltcd RPC server using TLS-secured websockets, registers for
  block connected and block disconnected notifications, and gets the current
  block count
* [ltcwallet Websockets Example](https://github.com/ltcsuite/ltcd/tree/master/rpcclient/examples/btcwalletwebsockets)
  Connects to a ltcwallet RPC server using TLS-secured websockets, registers for
  notifications about changes to account balances, and gets a list of unspent
  transaction outputs (utxos) the wallet can sign
* [Litecoin Core HTTP POST Example](https://github.com/ltcsuite/ltcd/tree/master/rpcclient/examples/bitcoincorehttp)
  Connects to a litecoin core RPC server using HTTP POST mode with TLS disabled
  and gets the current block count

## Major Features

* Supports Websockets (ltcd/ltcwallet) and HTTP POST mode (litecoin core)
* Provides callback and registration functions for ltcd/ltcwallet notifications
* Supports ltcd extensions
* Translates to and from higher-level and easier to use Go types
* Offers a synchronous (blocking) and asynchronous API
* When running in Websockets mode (the default):
  * Automatic reconnect handling (can be disabled)
  * Outstanding commands are automatically reissued
  * Registered notifications are automatically reregistered
  * Back-off support on reconnect attempts

## Installation

```bash
$ go get -u github.com/ltcmweb/ltcd/rpcclient
```

## License

Package rpcclient is licensed under the [copyfree](http://copyfree.org) ISC
License.
