package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"mtc"
)

// cmdHash computes Merkle tree hashes.
func cmdHash(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo hash <subcommand>

Subcommands:
  leaf [data]              Compute leaf hash (reads stdin if no data argument)
  node <left> <right>      Compute interior node hash from two hex-encoded hashes
`)
		return nil
	}

	switch args[0] {
	case "leaf":
		var data []byte
		var err error
		if len(args) >= 2 {
			data = []byte(strings.Join(args[1:], " "))
		} else {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		}
		h := mtc.HashLeaf(data)
		fmt.Println(hex.EncodeToString(h[:]))

	case "node":
		if len(args) != 3 {
			return fmt.Errorf("usage: mtc-demo hash node <left-hex> <right-hex>")
		}
		left, err := parseHashValue(args[1])
		if err != nil {
			return fmt.Errorf("left hash: %w", err)
		}
		right, err := parseHashValue(args[2])
		if err != nil {
			return fmt.Errorf("right hash: %w", err)
		}
		h := mtc.HashNode(&left, &right)
		fmt.Println(hex.EncodeToString(h[:]))

	default:
		return fmt.Errorf("unknown hash subcommand: %s", args[0])
	}

	return nil
}

// cmdTree builds a Merkle tree from input entries and displays tree info.
func cmdTree(args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo tree [entries...]

Build a Merkle tree from the given entries (as strings) and display info.
If no entries are given, reads lines from stdin.
`)
		return nil
	}

	var entries [][]byte
	if len(args) > 0 {
		for _, a := range args {
			entries = append(entries, []byte(a))
		}
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				entries = append(entries, []byte(line))
			}
		}
	}

	if len(entries) == 0 {
		return fmt.Errorf("no entries provided")
	}

	tree := mtc.NewMerkleTree(entries)
	root, err := tree.RootHash()
	if err != nil {
		return fmt.Errorf("computing root hash: %w", err)
	}

	fmt.Printf("Entries:   %d\n", tree.Size())
	fmt.Printf("Root hash: %s\n", hex.EncodeToString(root[:]))

	fmt.Println("\nLeaf hashes:")
	for i, e := range entries {
		h := mtc.HashLeaf(e)
		label := string(e)
		if len(label) > 40 {
			label = label[:40] + "..."
		}
		fmt.Printf("  [%d] %s  %q\n", i, hex.EncodeToString(h[:]), label)
	}

	if tree.Size() > 1 {
		subtrees, err := findSubtreeSlice(0, tree.Size())
		if err != nil {
			return fmt.Errorf("finding subtrees: %w", err)
		}
		fmt.Println("\nSubtrees:")
		for _, st := range subtrees {
			h, err := tree.SubtreeHash(st.Start, st.End)
			if err != nil {
				continue
			}
			fmt.Printf("  [%d, %d): %s\n", st.Start, st.End, hex.EncodeToString(h[:]))
		}
	}

	fmt.Println("\nInclusion proofs:")
	for i, e := range entries {
		h := mtc.HashLeaf(e)
		proof, err := tree.InclusionProof(i)
		if err != nil {
			fmt.Printf("  [%d] error: %v\n", i, err)
			continue
		}
		err = mtc.VerifyInclusionProof(proof, i, tree.Size(), h, root)
		status := "OK"
		if err != nil {
			status = fmt.Sprintf("FAIL: %v", err)
		}
		fmt.Printf("  [%d] %s (%d path elements)\n", i, status, len(proof)/mtc.HashSize)
	}

	return nil
}

// ── Shared helpers ──────────────────────────────────────────────────

func findSubtreeSlice(start, end int) ([]mtc.Interval, error) {
	left, right, single, err := mtc.FindSubtrees(start, end)
	if err != nil {
		return nil, err
	}
	if single {
		return []mtc.Interval{left}, nil
	}
	return []mtc.Interval{left, right}, nil
}

func section(title string) {
	fmt.Printf("\n── %s ──\n", title)
}

func parseHashValue(s string) (mtc.HashValue, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return mtc.HashValue{}, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != mtc.HashSize {
		return mtc.HashValue{}, fmt.Errorf("expected %d bytes, got %d", mtc.HashSize, len(b))
	}
	var h mtc.HashValue
	copy(h[:], b)
	return h, nil
}

func buildDemoTBSCert(caID mtc.TrustAnchorID, cn string, spki []byte, notBefore, notAfter time.Time) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
			v.AddASN1Int64(2)
		})
		tbs.AddASN1Int64(0)
		tbs.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(mtc.OIDMTCProofExperimental)
		})
		addIssuerDN(tbs, caID)
		addValidity(tbs, notBefore, notAfter)
		addSubjectDN(tbs, cn)
		tbs.AddBytes(spki)
	})
	data, err := b.Bytes()
	if err != nil {
		panic(fmt.Sprintf("building demo TBS cert: %v", err))
	}
	return data
}

func marshalSPKI(pub *ecdsa.PublicKey) ([]byte, error) {
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(spki *cryptobyte.Builder) {
		spki.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier([]int{1, 2, 840, 10045, 2, 1})
			alg.AddASN1ObjectIdentifier([]int{1, 2, 840, 10045, 3, 1, 7})
		})
		spki.AddASN1BitString(point)
	})
	return b.Bytes()
}

func addValidity(b *cryptobyte.Builder, notBefore, notAfter time.Time) {
	b.AddASN1(cbasn1.SEQUENCE, func(v *cryptobyte.Builder) {
		addUTCTime(v, notBefore)
		addUTCTime(v, notAfter)
	})
}

func addUTCTime(b *cryptobyte.Builder, t time.Time) {
	b.AddASN1(cbasn1.Tag(23), func(utc *cryptobyte.Builder) {
		utc.AddBytes([]byte(t.UTC().Format("060102150405Z")))
	})
}

func addSubjectDN(b *cryptobyte.Builder, cn string) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier([]int{2, 5, 4, 3})
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(cn))
				})
			})
		})
	})
}

func addIssuerDN(b *cryptobyte.Builder, issuer mtc.TrustAnchorID) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(mtc.OIDRDNATrustAnchorIDExperimental)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(issuer.String()))
				})
			})
		})
	})
}
