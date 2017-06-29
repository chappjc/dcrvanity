dcrvanity
====

dcrvanity is a multi-core vanity address and public-private keypair generator
for [Decred](https://decred.org/) written in Go.

It takes one or two regexp patterns that are matched against addresses in a
brute force search.  The patterns may be unrelated, although in the case where
one pattern implies a match on the other, a switch can be given to speed up the
search.

## Important

Understand the security and privacy implications of [address reuse][1].  [See
also][2].

## Requirements

[Go](http://golang.org) 1.7 or newer.

## Installation

```bash
git clone https://github.com/chappjc/dcrvanity $GOPATH/src/chappjc/dcrvanity
cd $GOPATH/src/chappjc/dcrvanity
go get -u github.com/Masterminds/glide
$GOPATH/bin/glide install
go build
```

## Usage

```none
$ dcrvanity -h
dcrvanity version 0.1.3-beta
Usage: dcrvanity [-pattern1] [-pattern2] [-N] [-pat1implies2] [-h]
Generate a Decred private and public key, with an address matching pattern(s).
  -h            Print this message
  -pattern1=    (string) Primary regexp pattern. Exit on match.
  -pattern2=    (string) Secondary regexp pattern. Print and continue on match.
  -pat1implies2 (bool) A match on pattern1 implies a match on pattern2.
                Matching on pattern1 skipped unless pattern2 matches.
  -N=           (int) Number of goroutines to launch (~number of cores to use).
  -testnet      (bool) Generate a testnet key instead of mainnet.
  -simnet       (bool) Generate a simnet key instead of mainnet.
```

When a match is found, dcrvanity outputs the matching address, which is a
compressed representation of the public key, along with the corresponding
private key. The private key is also compressed; it uses a Wallet Import Format
(WIF) encoding, the format required by dcrwallet's `importprivkey` RPC. See the
section [Importing the Address into Your Wallet](#importing-the-address-into-your-wallet) for details.

**But wait!**  Before you start searching, be aware that there are some
[restrictions on the characters](#first-character-restrictions) that may appear
in the address.

## First Character Restrictions

Many character may not appear in the first digit following "Ds" in a Decred
address. Notably, this includes the potentially confusing characters `0OIl`,
which are present nowhere in an address. The following characters should be
possible in the first position after the Ds prefix: `[a-npQ-Z]` (lowercase a to
p, excluding o and l, and uppercae Q to Z). Please read more about [base58
address encoding][4], ripemd160, and [this post by davecgh][5] for more
information.

Before beginning a potentially long search, test the leading character alone if
in doubt of its validity.  These checks may be built into the generator in the
future.

## Importing the Address into Your Wallet

The Wallet Import Format (WIF) represents the private key in the format
required by `importprivkey`, dcrwallet's RPC used to import the address into
your wallet.  The private portion of the public-private keypair returned by
dcrvanity is already in this format. To import the address:

 1. Unlock your wallet with `walletpassphrase`
 1. Use dcrctl to issue `importprivkey <WIF_key>`

 This is described in more detail on [dcrdocs][3].

## Examples

Use 1 core (the default) to search for an address starting with "Dsdcr":

    $ dcrvanity -pattern1 dcr
    Primary pattern:  ^Dsdcr
    30325
    Woohoo!
    Addr: Dsdcr4zcCVvataLzb5w5m6WdnbrM543EV3N
    Private key (WIF-encoded):  PmQeeekBXGjiPg4SBvHiZsym2zrM8NeTSUgDFjneFaGknaS5NjkER

Use 2 cores (`-N 2`) to ultimately search for "fred" immediately following "Ds".
Report any case-insensitive match of "fred", but don't stop searching. Specify
that matching the primary pattern implies a match on secondary
(`-pat1implies2`).

    $ dcrvanity -pattern1 "fred" -pattern2 "f(?i)red" -pat1implies2 -N 2
    Primary pattern:  ^Dsfred
    Secondary pattern:  ^Ds(?i)fred
    808101
    Addr: DsfrEdQDGFf6uYbjmkT2D1cDYoW6m9BD7ga
    Private key (WIF-encoded): PmQejCoacLSiLes4aj6vnNgRhtwjkKTDtBMkix3qDKrS8CEFhLcyD
    1898882
    Woohoo!
    Addr: Dsfrediud1mTy9MuRHE5XNH4HJg9xhJ5Rts
    Private key (WIF-encoded): PmQeHrMcmcRQBPqzBiSAnxzmQkj6sP3MdbCQZzeba8gyrwEmM3W4s
    WIF struct: PmQeHrMcmcRQBPqzBiSAnxzmQkj6sP3MdbCQZzeba8gyrwEmM3W4s

First it found an address with "frEd" after Ds, then it found "fred" and
stopped searching.

Ultimately search for "decred" or "d3cred". Secondary pattern (report, but don't
stop), implied by pattern1, is a case-insensitive version of the primary
pattern.  Both patterns may be found anywhere in the address because of the
leading `.*`.

    $ dcrvanity -pattern1 ".*d[e3]cred" -pattern2 ".*(?i)d[e3]cred" -N 3
    Primary pattern:  ^Ds.*d[e3]cred
    Secondary pattern:  ^Ds.*(?i)d[e3]cred
    4382354
    Addr: Dsg6y9PwYkNj8VUQbLWVcy6qpBtZBDecred
    Private key (WIF-encoded): Pm---------------------------------------------------

After 4382354 iterations, it found the address
Dsg6y9PwYkNj8VUQbLWVcy6qpBtZB**Decred**. The corresponding private key is
shown WIF-encoded, as this is the format required by `importprivkey`. I have
redacted the private key for this address since I rather like it.

Now say we want an address with no capital letters.  That would be cool.  and
perhaps you'd also be interested in addresses with capital "J" and "C".

    $ dcrvanity -pattern1 "[a-z1-9]*$" -pattern2 "[a-z1-9JC]*$" -pat1implies2 -N 3
    dcrvanity version 0.1.0-beta
    Primary pattern:  ^Ds[a-z1-9]*$
    Secondary pattern:  ^Ds[a-z1-9JC]*$
    12755537
    Addr: Dsjsrm5zi557982394xqza3JbpmcCd9utni
    Private key (WIF-encoded): PmQdy9wA1QmLiLGM9yVGr8S1qXVD2oModaHfB9W1sLDLCfFVgoLTi
    <snip, lots more secondary matches>
    Woohoo!
    Addr: Dsjn9te4bhf7uoaujotjghp3v9u82tomzbi
    Private key (WIF-encoded):  PmQemTyD7D7f1uTs1au5AZeMeN2qjZ9EUyBjAGp1LobCJ5wtT1zdX

Make any regexp patterns, but keep in mind the computational burden of complex
patterns, as well as the character restrictions mentioned in [First Character
Restrictions](#first-character-restrictions).

 [1]: https://en.bitcoin.it/wiki/Address_reuse
 [2]: http://bitcoin.stackexchange.com/questions/20621/is-it-safe-to-reuse-a-bitcoin-address/42380#42380
 [3]: https://docs.decred.org/faq/wallets-and-seeds/#7-how-do-i-import-a-key-that-is-in-wallet-import-format-wif
 [4]: https://en.bitcoin.it/wiki/Base58Check_encoding
 [5]: https://forum.decred.org/threads/personalize-your-address-with-vanitygen.253/#post-3077
