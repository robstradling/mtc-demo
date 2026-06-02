// Command mtc-demo is a CLI tool for demonstrating the Merkle Tree
// Certificates lifecycle as specified in draft-ietf-plants-merkle-tree-certs.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "demo":
		err = cmdDemo()
	case "hash":
		err = cmdHash(os.Args[2:])
	case "tree":
		err = cmdTree(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "cosigner":
		err = cmdCosigner(os.Args[2:])
	case "mirror":
		err = cmdMirror(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "landmark":
		err = cmdLandmark(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: mtc-demo <command> [arguments]

CA operations:
  ca init <ca-id> <log-number>         Initialize a new CA and issuance log
  ca info                              Show CA and log state
  ca add <common-name>                 Add a TBS certificate entry to the log
  ca checkpoint                        Display current checkpoint hash
  ca issue <index>                     Issue a certificate for a log entry
  ca prune <min-index>                 Prune entries below min-index

Cosigner operations:
  cosigner keygen <id> <algorithm>     Generate a cosigner key pair (ed25519, p256, p384)
  cosigner list                        List configured cosigner keys
  cosigner sign <id> <start> <end>     Cosign a subtree

Mirror operations:
  mirror inclusion <index>             Generate and verify an inclusion proof
  mirror consistency <old-size> <hex>  Verify consistency with a previous checkpoint

Certificate verification:
  verify cert <cert.pem>               Verify a Merkle Tree Certificate

Landmark operations:
  landmark init <max-active>           Initialize landmark sequence
  landmark allocate                    Allocate a landmark at current tree size
  landmark info                        Show landmark sequence info
  landmark find <index>                Find which landmark covers an entry

Utilities:
  demo                                 Run a full end-to-end lifecycle demo
  hash leaf [data]                     Compute a Merkle leaf hash
  hash node <left-hex> <right-hex>     Compute an interior node hash
  tree [entries...]                    Build a Merkle tree and show info
  help                                 Show this help message

State is stored in ./mtc-state.json (override with MTC_STATE env var).
`)
}

// statePath returns the path to the state file.
func statePath() string {
	if p := os.Getenv("MTC_STATE"); p != "" {
		return p
	}
	return "mtc-state.json"
}
