dcrvanity
====

dcrvanity is an address and keypair generator for [decred](https://decred.org/).

It takes one or two regex patterns that are matched against the address.

## Requirements

[Go](http://golang.org) 1.6 or newer.

## Installation

```bash
go get -u github.com/chappjc/dcrvanity
```

## Usage

```
Usage: dcrvanity [-testnet] [-simnet] [-pattern1] [-pattern2] [-h]
Generate a Decred private and public key matching pattern(s).

  -h            Print this message
  -testnet      Generate a testnet key instead of mainnet
  -simnet       Generate a simnet key instead of mainnet
  -regtest      Generate a regtest key instead of mainnet
  -pattern1     Primary pattern. dcrvanity will exit if this matches an address.
  -pattern2     Secondary pattern. dcrvanity will NOT exit, just report, an address match.
```
