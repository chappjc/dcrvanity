// Copyright (c) 2015 The Decred Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	//"bufio"
	//"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	//"strings"

	//"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrutil"
	//"github.com/decred/dcrutil/hdkeychain"
	//"github.com/decred/dcrwallet/pgpwordlist"
)

var curve = secp256k1.S256()

var params = chaincfg.MainNetParams

// Flag arguments.
var getHelp = flag.Bool("h", false, "Print help message")
var testnet = flag.Bool("testnet", false, "")
var simnet = flag.Bool("simnet", false, "")
var pattern1 = flag.String("pattern1", "", "Primary pattern. dcrvanity will exit if this matches.")
var pattern2 = flag.String("pattern2", "", "Secondary pattern. dcrvanity will NOT exit if this matches.")

func setupFlags(msg func(), f *flag.FlagSet) {
	f.Usage = msg
}

var newLine = "\n"

// writeNewFile writes data to a file named by filename.
// Error is returned if the file does exist. Otherwise writeNewFile creates the file with permissions perm;
// Based on ioutil.WriteFile, but produces an err if the file exists.
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		// There was no error, but not all the data was written, so report an error.
		err = io.ErrShortWrite
	}
	if err == nil {
		// There was an error, so close file (ignoreing any further errors) and return the error.
		f.Close()
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

// searchKeyPair generates a secp256k1 keypair
func searchKeyPair(primaryPattern, secondaryPattern string, inclusive bool) (*secp256k1.PrivateKey, *dcrutil.AddressPubKeyHash, error) {
	var regexPrimary, regexSecondary *regexp.Regexp
	var err error

	// pat1 := "chap(?i)p"
	if len(secondaryPattern) > 0 {
		regexSecondary, err = regexp.Compile("^Ds" + secondaryPattern)
		if err != nil {
			return nil, nil, err // there was a problem with the regular expression.
		}
	} else if inclusive {
		fmt.Println("nil secondary pattern and inclusive is true. No addresses will be checked.")
		return nil, nil, err
	}
	fmt.Println("Secondary pattern: ", regexSecondary.String())

	// pat2 := "chapp(?i)jc"
	if len(primaryPattern) > 0 {
		regexPrimary, err = regexp.Compile("^Ds" + primaryPattern)
		if err != nil {
			return nil, nil, err // there was a problem with the regular expression.
		}
	} else {
		fmt.Println("nil primary pattern. The program will never quit.")
	}
	fmt.Println("Primary pattern: ", regexPrimary.String())

	var key *ecdsa.PrivateKey
	var addr *dcrutil.AddressPubKeyHash

	for i := 0; ; i++ {
		key0, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub := secp256k1.PublicKey{
			Curve: curve,
			X:     key0.PublicKey.X,
			Y:     key0.PublicKey.Y,
		}

		addr0, err := dcrutil.NewAddressPubKeyHash(Hash160(pub.SerializeCompressed()),
			&params, chainec.ECTypeSecp256k1)
		if err != nil {
			return nil, nil, err
		}

		if i%10000 == 0 {
			fmt.Printf("\r%d", i)
		}

		// If the secondary pattern is matched by the primary, this is faster
		// because if the secondary does't match, then neither will primary.
		if inclusive {
			if regexSecondary != nil && regexSecondary.MatchString(addr0.EncodeAddress()) {
				fmt.Printf("\r%d\nAddr: %s\n", i, addr0.EncodeAddress())
				fmt.Printf("Pubkey compressed: %x\n", pub.SerializeCompressed())

				privX := secp256k1.PrivateKey{
					PublicKey: key0.PublicKey,
					D:         key0.D,
				}
				privWifX := NewWIF(privX)
				fmt.Printf("Private key (WIF-encoded): %s\n", privWifX.String())
				fmt.Println("Private key (secp256k1): ", privX)

				if regexPrimary != nil && regexPrimary.MatchString(addr0.EncodeAddress()) {
					key = key0
					addr = addr0
					fmt.Printf("Woohoo!\n")
					break
				}
			}
		} else {
			// primary match does not imply secondary, so check both separately
			if regexSecondary != nil && regexSecondary.MatchString(addr0.EncodeAddress()) {
				fmt.Printf("\r%d\n%s\n", i, addr0.EncodeAddress())
				fmt.Printf("%x\n", pub.SerializeCompressed())

				privX := secp256k1.PrivateKey{
					PublicKey: key0.PublicKey,
					D:         key0.D,
				}
				privWifX := NewWIF(privX)
				fmt.Printf("%s\n", privWifX.String())
			}

			if regexPrimary != nil && regexPrimary.MatchString(addr0.EncodeAddress()) {
				fmt.Printf("Woohoo!\n")
				fmt.Printf("\r%d\n%s\n", i, addr0.EncodeAddress())
				fmt.Printf("%x\n", pub.SerializeCompressed())
				key = key0
				addr = addr0

				privX := secp256k1.PrivateKey{
					PublicKey: key0.PublicKey,
					D:         key0.D,
				}
				privWifX := NewWIF(privX)
				fmt.Printf("%s\n", privWifX.String())

				break
			}
		}
	}

	priv := &secp256k1.PrivateKey{
		PublicKey: key.PublicKey,
		D:         key.D,
	}

	return priv, addr, nil

	//privWif := NewWIF(priv)

	// var buf bytes.Buffer
	// buf.WriteString("Address: ")
	// buf.WriteString(addr.EncodeAddress())
	// buf.WriteString(" | ")
	// buf.WriteString("Private key: ")
	// buf.WriteString(privWif.String())
	//buf.WriteString(newLine)

	// outs := buf.String()
	// fmt.Println(outs)

	// err = writeNewFile(filename, buf.Bytes(), 0600)
	// if err != nil {
	// return err
	// }
	//return nil
}

func main() {
	if runtime.GOOS == "windows" {
		newLine = "\r\n"
	}
	helpMessage := func() {
		fmt.Println("Usage: dcraddrgen [-testnet] [-simnet] [-h]")
		fmt.Println("Generate a Decred private and public key, with address matching pattern(s).")
		//"These are output to the file 'filename'.\n")
		fmt.Println("  -h \t\tPrint this message")
		fmt.Println("  -testnet \tGenerate a testnet key instead of mainnet")
		fmt.Println("  -simnet \tGenerate a simnet key instead of mainnet")
		fmt.Println("  -pattern1 \tPrimary pattern. dcrvanity will exit if this matches.")
		fmt.Println("  -pattern2 \tSecondary pattern. dcrvanity will NOT exit if this matches.")
	}

	setupFlags(helpMessage, flag.CommandLine)
	flag.Parse()

	if *getHelp {
		helpMessage()
		return
	}

	// var fileName string
	// if flag.Arg(0) != "" {
	// 	fileName = flag.Arg(0)
	// } else {
	// 	fileName = "keys.txt"
	// }

	// Alter the globals to specified network.
	if *testnet {
		if *simnet {
			fmt.Println("Error: Only specify one network.")
			return
		}
		params = chaincfg.TestNetParams
	}
	if *simnet {
		params = chaincfg.SimNetParams
	}

	// Single keypair generation/search
	priv, addr, err := searchKeyPair(*pattern1, *pattern2, true)
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err.Error())
		return
	}

	//fmt.Println("spew of private key (secp256k1) and address:")
	//spew.Dump(priv, addr)
	fmt.Printf("Addr: %s\n", addr.EncodeAddress())
	fmt.Println("Private key (secp256k1): ", priv)
	privWif := NewWIF(*priv)
	fmt.Printf("Private key (WIF-encoded): %s\nWIF struct: %v\n", privWif.String(), privWif)

	// fmt.Printf("Successfully generated keypair and stored it in %v.\n",
	// fn)
	// fmt.Printf("Your private key is used to spend your funds. Do not " +
	// "reveal it to anyone.\n")
	return

}
