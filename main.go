// Copyright (c) 2016 Jonathan Chappelow
// Copyright (c) 2015 The Decred Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	//"log"
	"math"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	//"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrutil"
)

// TODO: Use a logger, if even golang's logger
// var (
// 	Trace   *log.Logger
// 	Info    *log.Logger
// 	Warning *log.Logger
// 	Error   *log.Logger
// )

var curve = secp256k1.S256()

var params = chaincfg.MainNetParams

// Flag arguments.
var getHelp = flag.Bool("h", false, "Print help message")
var testnet = flag.Bool("testnet", false, "")
var simnet = flag.Bool("simnet", false, "")
var pattern1 = flag.String("pattern1", "", "Primary pattern. dcrvanity will exit if this matches.")
var pattern2 = flag.String("pattern2", "", "A match on pattern1 implies a match on pattern2.")
var pat1implies2 = flag.Bool("pat1implies2", false, "")
var nCores = flag.Uint("N", 1, "Number of goroutines to launch (essentially the number of cores to use).")

func setupFlags(msg func(), f *flag.FlagSet) {
	f.Usage = msg
}

var newLine = "\n"

var wg sync.WaitGroup
var searchIterator = int64(0)
var quit = make(chan struct{})

type keySearchResult struct {
	priv *secp256k1.PrivateKey
	addr *dcrutil.AddressPubKeyHash
	err  error
}

func keySearcher(regexPrimary, regexSecondary *regexp.Regexp, inclusive bool,
	searchResult chan<- keySearchResult) {
	priv, addr, err := searchKeyPair(regexPrimary, regexSecondary,
		inclusive)
	select {
	case searchResult <- keySearchResult{priv, addr, err}:
	case <-quit:
	}
}

// searchKeyPair generates a secp256k1 keypair
func searchKeyPair(regexPrimary, regexSecondary *regexp.Regexp,
	inclusive bool) (*secp256k1.PrivateKey, *dcrutil.AddressPubKeyHash, error) {
	defer wg.Done()

	var key *ecdsa.PrivateKey
	var addr *dcrutil.AddressPubKeyHash

	ticker := time.NewTicker(time.Millisecond * 200 * time.Duration(1+math.Ceil((float64(*nCores)-1)/1.5)))

searchloop:
	for i := int64(0); ; i++ {
		select {
		case <-ticker.C:
			fmt.Printf("\r%d", atomic.AddInt64(&searchIterator, i))
			i = 0
		case <-quit:
			return nil, nil, nil
		default:
		}

		// Generate public-private key pair
		key0, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		// ecdsa.PublicKey with serialization functions
		pub := secp256k1.PublicKey{
			Curve: curve,
			X:     key0.PublicKey.X,
			Y:     key0.PublicKey.Y,
		}

		// PubKeyHashAddrID (Ds) followed by ripemd160 hash of secp256k1 pubkey
		addr0, err := dcrutil.NewAddressPubKeyHash(Hash160(pub.SerializeCompressed()),
			&params, chainec.ECTypeSecp256k1)
		if err != nil {
			return nil, nil, err
		}

		// If the secondary pattern is matched by the primary, this is faster
		// because if the secondary does't match, then neither will primary.
		if inclusive {
			if regexSecondary != nil && regexSecondary.MatchString(addr0.EncodeAddress()) {

				if regexPrimary != nil && regexPrimary.MatchString(addr0.EncodeAddress()) {
					key = key0
					addr = addr0
					fmt.Printf("Woohoo!\n")
					atomic.AddInt64(&searchIterator, i)
					break searchloop
				}

				ii := atomic.LoadInt64(&searchIterator) + i
				fmt.Printf("\r%d\nAddr: %s\n", ii, addr0.EncodeAddress())
				fmt.Printf("Pubkey compressed: %x\n", pub.SerializeCompressed())

				privX := secp256k1.PrivateKey{
					PublicKey: key0.PublicKey,
					D:         key0.D,
				}
				privWifX := NewWIF(privX)
				fmt.Printf("Private key (WIF-encoded): %s\n", privWifX.String())
				fmt.Println("Private key (secp256k1): ", privX)
			}
		} else {
			// primary match does not imply secondary, so check both separately
			if regexSecondary != nil && regexSecondary.MatchString(addr0.EncodeAddress()) {
				ii := atomic.LoadInt64(&searchIterator) + i
				fmt.Printf("\r%d\nAddr: %s\n", ii, addr0.EncodeAddress())
				fmt.Printf("Pubkey compressed: %x\n", pub.SerializeCompressed())

				privX := secp256k1.PrivateKey{
					PublicKey: key0.PublicKey,
					D:         key0.D,
				}
				privWifX := NewWIF(privX)
				fmt.Printf("Private key (WIF-encoded): %s\n", privWifX.String())
				fmt.Println("Private key (secp256k1): ", privX)
			}

			// Primary does not require printing here since it will be displayed
			// in main().  Get the keys and break.
			if regexPrimary != nil && regexPrimary.MatchString(addr0.EncodeAddress()) {
				atomic.AddInt64(&searchIterator, i)
				fmt.Printf("\nWoohoo!\n")
				key = key0
				addr = addr0

				// privX := secp256k1.PrivateKey{
				// 	PublicKey: key0.PublicKey,
				// 	D:         key0.D,
				// }
				//privWifX := NewWIF(privX)
				//fmt.Printf("%s\n", privWifX.String())

				break searchloop
			}
		}
	}

	priv := &secp256k1.PrivateKey{
		PublicKey: key.PublicKey,
		D:         key.D,
	}

	return priv, addr, nil

	//privWif := NewWIF(priv)
}

// func InitLog(
// 	traceHandle io.Writer,
// 	infoHandle io.Writer,
// 	warningHandle io.Writer,
// 	errorHandle io.Writer) {

// 	Trace = log.New(traceHandle,
// 		"TRACE: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	Info = log.New(infoHandle,
// 		"INFO: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	Warning = log.New(warningHandle,
// 		"WARNING: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	Error = log.New(errorHandle,
// 		"ERROR: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)
// }

func main() {
	if runtime.GOOS == "windows" {
		newLine = "\r\n"
	}
	helpMessage := func() {
		fmt.Println("Usage: dcrvanity [-pattern1] [-pattern2] [-N] [-pat1implies2] [-h]")
		fmt.Println("Generate a Decred public/private key pair, with address matching pattern(s).")
		fmt.Println("  -h \t\tPrint this message")
		fmt.Println("  -pattern1=    (string) Primary regexp pattern. Exit on match.")
		fmt.Println("  -pattern2=    (string) Secondary regexp pattern. Print and continue on match.")
		fmt.Println("  -pat1implies2 (bool) A match on pattern1 implies a match on pattern2. \n" +
		            "                Matching on pattern1 skipped unless pattern2 matches.")
		fmt.Println("  -N=           (int) Number of goroutines to launch (~number of cores to use).")
		fmt.Println("  -testnet      (bool) Generate a testnet key instead of mainnet.")
		fmt.Println("  -simnet       (bool) Generate a simnet key instead of mainnet.")
	}

	setupFlags(helpMessage, flag.CommandLine)
	flag.Parse()

	//InitLog(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	fmt.Printf(appName+" version %s\n", ver.String())

	var err error

	if *getHelp {
		helpMessage()
		return
	}

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

	// Primary (exit) pattern
	var regexPrimary *regexp.Regexp
	primaryPattern := *pattern1
	if len(primaryPattern) > 0 {
		pat := "^Ds" + primaryPattern
		regexPrimary, err = regexp.Compile(pat)
		if err != nil {
			fmt.Printf("Failed to compile regexp %v: %v", pat, err)
			return
		}
		fmt.Println("Primary pattern: ", regexPrimary.String())
	} else {
		fmt.Println("nil primary pattern. The program will never quit.")
	}

	// Secondary (report, but no exit) pattern
	var regexSecondary *regexp.Regexp
	secondaryPattern := *pattern2
	inclusive := *pat1implies2
	if len(secondaryPattern) > 0 {
		pat := "^Ds" + secondaryPattern
		regexSecondary, err = regexp.Compile(pat)
		if err != nil {
			fmt.Printf("Failed to compile regexp %v: %v", pat, err)
			return
		}
		fmt.Println("Secondary pattern: ", regexSecondary.String())
	} else if inclusive {
		fmt.Println("nil secondary pattern and inclusive is true. No addresses will be checked.")
		return
	}

	// Launch goroutines
	N := int(*nCores)

	// Wait for key search results or the quit signal
	searchResultChan := make(chan keySearchResult)
	searchResult := keySearchResult{}
	go func() {
		select {
		case searchResult = <-searchResultChan:
			close(quit)
		case <-quit:
		}
	}()

goroutineloop:
	for i := 0; i < N; i++ {
		// Stagger the launches so the display is not quite so jumpy
		time.Sleep(time.Duration(100*(N-1)) * time.Millisecond)
		select {
		case <-quit:
			fmt.Println("quit signaled. Not launching more goroutines.")
			break goroutineloop
		default:
		}
		wg.Add(1)
		go keySearcher(regexPrimary, regexSecondary, inclusive, searchResultChan)
	}

	// Only accept a single CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Start waiting for the interrupt signal
	go func() {
		<-c
		signal.Stop(c)
		// Close the channel so multiple goroutines can get the message
		fmt.Print("CTRL+C hit.  Terminating searchers.")
		close(quit)
		return
	}()

	// Allow each goroutine to receive the quit signal and finish up
	wg.Wait()

	if searchResult.priv != nil {
		fmt.Printf("Addr: %s\n", searchResult.addr.EncodeAddress())
		fmt.Println("Private key (secp256k1): ", searchResult.priv)
		privWif := NewWIF(*searchResult.priv)
		fmt.Println("Private key (WIF-encoded): ", privWif)
		fmt.Println("You many now import this into your wallet via importprivkey.")
	}

	return
}
