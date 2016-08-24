dcrvanity
====

dcrvanity is an address and keypair generator for [decred](https://decred.org/).

It takes one or two regex patterns that are matched against the address.  The
patterns may be unrelated, but in the case where one pattern implies a match on
the other, a switch can be given to speed up the search.

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
  -pat1implies2 A match on pattern1 implies a match on pattern2.
  -N            Number of goroutines to launch (essentially the number of cores to use).
```

The pattern should not include any of `0OIl`.

## Important First Character Restrictions

Many character may not appear in the first digit following "Ds" in an encoded
Decred address. Notably, this includes the potentially confusing characters
`0OIl`, which are present nowhere in an address. Most capital letters should
also not be used as the first letter in the input pattern. However, the
following characters should be possible in the first position after the Ds
prefix: `[a-npQ-Z]` (lowercase a to p, excluding o, and uppercae Q to Z).

Before beginning a potentially long search, test the leading character alone.
Please read more about [base58 address
encoding](https://en.bitcoin.it/wiki/Base58Check_encoding) for more information
about what characters are acceptable.

## Examples

Use 1 core, by default, to search for an address starting with "Dsdcr":

    $ dcrvanity.exe -pattern1 dcr
    Primary pattern:  ^Dsdcr
    30325
    Woohoo!
    Addr: Dsdcr4zcCVvataLzb5w5m6WdnbrM543EV3N
    Private key (WIF-encoded):  PmQeeekBXGjiPg4SBvHiZsym2zrM8NeTSUgDFjneFaGknaS5NjkER

Use 2 cores (`-N 2`) to search for an address with "goDCR" following the "Ds"
prefix:

    $ dcrvanity.exe -pattern1 goDCR -N 2

Ultimately search for "fred". Report any case-insensitive match of "fred", but
don't stop searching. Specify that matching the primary pattern implies a match
on secondary (`-pat1implies2`).

    $ dcrvanity.exe -pattern1 "fred" -pattern2 "f(?i)red" -pat1implies2
    Primary pattern:  ^Dsfred
    Secondary pattern:  ^Ds(?i)fred
    808101
    Addr: DsfrEdQDGFf6uYbjmkT2D1cDYoW6m9BD7ga
    Pubkey compressed: 0375b0b472bddb49265131b72094e287ec2694d502310df5af1589ca7eef3b715f
    Private key (WIF-encoded): PmQejCoacLSiLes4aj6vnNgRhtwjkKTDtBMkix3qDKrS8CEFhLcyD
    1898882
    Woohoo!
    Addr: Dsfrediud1mTy9MuRHE5XNH4HJg9xhJ5Rts
    Private key (WIF-encoded): PmQeHrMcmcRQBPqzBiSAnxzmQkj6sP3MdbCQZzeba8gyrwEmM3W4s
    WIF struct: PmQeHrMcmcRQBPqzBiSAnxzmQkj6sP3MdbCQZzeba8gyrwEmM3W4s

First it found an address with "frEd" after Ds, then it found "fred" and
stopped searching.

Use 3 cores. Ultimately search for "decred", "d3cred", "DECRED", or "D3CRED".
Secondary pattern (report, but don't stop), implied by pattern1, is a
case-insensitive version of the primary pattern.  Both patterns may be found
anywhere in the address because of the leading `.*`.

    $ dcrvanity.exe -pattern1 ".*(d[e3]cred|D[E3]CRED)" -pattern2 ".*(?i)d[e3]cred" -N 3
    Primary pattern:  ^Ds.*(d[e3]cred|D[E3]CRED)
    Secondary pattern:  ^Ds.*(?i)d[e3]cred
    4382354
    Addr: Dsg6y9PwYkNj8VUQbLWVcy6qpBtZBDecred
    Private key (WIF-encoded): Pm---------------------------------------------------

After 4382354 iterations, it found the address
Dsg6y9PwYkNj8VUQbLWVcy6qpBtZB**Decred**. The corresponding private key is
shown WIF-encoded, as this is the format required by `importprivkey`. I have
redacted the private key for this address since I rather like it.
