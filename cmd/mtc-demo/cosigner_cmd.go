package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"mtc"
)

func cmdCosigner(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo cosigner <subcommand>

Subcommands:
  keygen <id> <algorithm>   Generate a cosigner key pair (ed25519, p256, p384)
  list                      List configured cosigner keys
  sign <id> <start> <end>   Cosign a subtree
`)
		return nil
	}

	switch args[0] {
	case "keygen":
		return cmdCosignerKeygen(args[1:])
	case "list":
		return cmdCosignerList()
	case "sign":
		return cmdCosignerSign(args[1:])
	default:
		return fmt.Errorf("unknown cosigner subcommand: %s", args[0])
	}
}

func cmdCosignerKeygen(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: mtc-demo cosigner keygen <cosigner-id> <algorithm>\nalgorithms: ed25519, p256, p384")
	}

	s, err := requireState()
	if err != nil {
		return err
	}

	cosignerID := args[0]
	algName := args[1]

	// Validate the trust anchor ID.
	if _, err := mtc.ParseTrustAnchorID(cosignerID); err != nil {
		return fmt.Errorf("invalid cosigner ID: %w", err)
	}

	// Check for duplicate.
	for _, c := range s.Cosigners {
		if c.ID == cosignerID {
			return fmt.Errorf("cosigner %s already exists", cosignerID)
		}
	}

	// Validate algorithm.
	if _, err := parseAlgorithm(algName); err != nil {
		return err
	}

	// Generate key.
	signer, err := generateCosignerKey(algName)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	s.Cosigners = append(s.Cosigners, CosignerKeyConfig{
		ID:         cosignerID,
		Algorithm:  algName,
		PrivateKey: hex.EncodeToString(pkcs8),
	})
	if err := saveState(s); err != nil {
		return err
	}

	fmt.Printf("Cosigner key generated:\n")
	fmt.Printf("  ID:        %s\n", cosignerID)
	fmt.Printf("  Algorithm: %s\n", algName)
	return nil
}

func cmdCosignerList() error {
	s, err := requireState()
	if err != nil {
		return err
	}

	if len(s.Cosigners) == 0 {
		fmt.Println("No cosigner keys configured.")
		return nil
	}

	fmt.Printf("%-20s  %s\n", "COSIGNER ID", "ALGORITHM")
	for _, c := range s.Cosigners {
		fmt.Printf("%-20s  %s\n", c.ID, c.Algorithm)
	}
	return nil
}

func cmdCosignerSign(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: mtc-demo cosigner sign <cosigner-id> <start> <end>")
	}

	cosignerID := args[0]
	start, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid start: %w", err)
	}
	end, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid end: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}

	// Find the cosigner key.
	var keyCfg *CosignerKeyConfig
	for i := range s.Cosigners {
		if s.Cosigners[i].ID == cosignerID {
			keyCfg = &s.Cosigners[i]
			break
		}
	}
	if keyCfg == nil {
		return fmt.Errorf("cosigner %s not found", cosignerID)
	}

	cosignerKey, err := rebuildCosignerKey(*keyCfg)
	if err != nil {
		return err
	}

	h, err := log.SubtreeHash(int(start), int(end))
	if err != nil {
		return fmt.Errorf("computing subtree hash: %w", err)
	}

	sig, err := mtc.Cosign(cosignerKey, log.LogID(), start, end, &h)
	if err != nil {
		return fmt.Errorf("cosigning: %w", err)
	}

	fmt.Printf("Cosignature:\n")
	fmt.Printf("  Cosigner:      %s\n", cosignerID)
	fmt.Printf("  Subtree:       [%d, %d)\n", start, end)
	fmt.Printf("  Subtree hash:  %s\n", hex.EncodeToString(h[:]))
	fmt.Printf("  Signature:     %s\n", hex.EncodeToString(sig))

	// Verify the signature we just produced.
	tc, _ := rebuildTrustedCosigners(s)
	for _, t := range tc {
		if t.CosignerID.Equal(cosignerKey.CosignerID) {
			err := mtc.VerifyCosignature(t.CosignerID, t.PublicKey, t.SignatureAlgorithm,
				log.LogID(), start, end, &h, sig)
			if err != nil {
				fmt.Printf("  Verify:        FAIL (%v)\n", err)
			} else {
				fmt.Printf("  Verify:        OK\n")
			}
			break
		}
	}

	return nil
}
