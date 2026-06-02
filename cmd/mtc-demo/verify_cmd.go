package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"mtc"
)

func cmdVerify(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo verify <subcommand>

Subcommands:
  cert <cert.pem>   Verify a Merkle Tree Certificate
`)
		return nil
	}

	switch args[0] {
	case "cert":
		return cmdVerifyCert(args[1:])
	default:
		return fmt.Errorf("unknown verify subcommand: %s", args[0])
	}
}

func cmdVerifyCert(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo verify cert <cert.pem>")
	}

	s, err := requireState()
	if err != nil {
		return err
	}

	// Read certificate PEM.
	certPEM, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found in %s", args[0])
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected CERTIFICATE PEM block, got %s", block.Type)
	}

	caID, err := mtc.ParseTrustAnchorID(s.CAID)
	if err != nil {
		return err
	}

	// Build trusted cosigner list from state.
	trustedCosigners, err := rebuildTrustedCosigners(s)
	if err != nil {
		return err
	}
	if len(trustedCosigners) == 0 {
		return fmt.Errorf("no cosigner keys configured for verification")
	}

	var trustedIDs []mtc.TrustAnchorID
	for _, tc := range trustedCosigners {
		trustedIDs = append(trustedIDs, tc.CosignerID)
	}

	cfg := &mtc.VerifierConfig{
		CAID:      caID,
		Cosigners: trustedCosigners,
		Policy: &mtc.AnyNCosignerPolicy{
			N:       1,
			Trusted: trustedIDs,
		},
	}

	err = mtc.VerifyCertificateSignature(block.Bytes, cfg)
	if err != nil {
		fmt.Printf("Verification: FAIL\n")
		fmt.Printf("  Error: %v\n", err)
		return err
	}

	fmt.Printf("Verification: PASSED\n")
	fmt.Printf("  File:    %s\n", args[0])
	fmt.Printf("  CA ID:   %s\n", s.CAID)
	fmt.Printf("  Size:    %d bytes\n", len(block.Bytes))
	return nil
}
