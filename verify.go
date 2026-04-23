package mtc

import (
	"crypto"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// TrustedCosigner holds cosigner identity and public key for verification.
type TrustedCosigner struct {
	CosignerID         TrustAnchorID
	SignatureAlgorithm SignatureAlgorithm
	PublicKey          crypto.PublicKey
}

// TrustedSubtree represents a predistributed trusted subtree hash
// for landmark-relative certificate verification (Section 7.4).
type TrustedSubtree struct {
	Start uint64
	End   uint64
	Hash  HashValue
}

// CosignerPolicy defines the relying party's requirements for which
// cosigners must sign a subtree (Section 7.3).
type CosignerPolicy interface {
	// IsSatisfied returns true if the given set of cosigner IDs
	// satisfies this policy.
	IsSatisfied(cosignerIDs []TrustAnchorID) bool
}

// AnyNCosignerPolicy requires at least N cosigners from the trusted set.
type AnyNCosignerPolicy struct {
	N       int
	Trusted []TrustAnchorID
}

func (p *AnyNCosignerPolicy) IsSatisfied(cosignerIDs []TrustAnchorID) bool {
	count := 0
	for _, id := range cosignerIDs {
		for _, trusted := range p.Trusted {
			if id.Equal(trusted) {
				count++
				break
			}
		}
	}
	return count >= p.N
}

// RevokedRanges holds ranges of revoked indices (Section 7.5).
type RevokedRanges []Interval

// IsRevoked checks whether the given index falls within a revoked range.
func (rr RevokedRanges) IsRevoked(index int) bool {
	for _, r := range rr {
		if index >= r.Start && index < r.End {
			return true
		}
	}
	return false
}

// VerifierConfig holds the relying party's configuration for
// verifying Merkle Tree Certificates (Section 7.1).
type VerifierConfig struct {
	LogID           TrustAnchorID
	Cosigners       []TrustedCosigner
	Policy          CosignerPolicy
	TrustedSubtrees []TrustedSubtree
	RevokedRanges   RevokedRanges
}

// VerifyCertificateSignature implements the certificate signature
// verification procedure from Section 7.2.
//
// This replaces the standard X.509 signature verification for
// certificates whose issuer is a Merkle Tree CA.
//
// Parameters:
//   - certDER: the full DER-encoded X.509 Certificate
//   - cfg: the relying party's verifier configuration
//
// It returns nil on success, or an error describing the verification failure.
func VerifyCertificateSignature(certDER []byte, cfg *VerifierConfig) error {
	// Parse the outer Certificate SEQUENCE.
	input := cryptobyte.String(certDER)
	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) {
		return errors.New("invalid certificate: not a SEQUENCE")
	}

	// Read TBSCertificate element (keep raw bytes for entry hash).
	var tbsElement cryptobyte.String
	if !cert.ReadASN1Element(&tbsElement, cbasn1.SEQUENCE) {
		return errors.New("invalid certificate: could not read TBSCertificate")
	}
	tbsBytes := []byte(tbsElement)

	// Read signatureAlgorithm.
	var sigAlg cryptobyte.String
	if !cert.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return errors.New("invalid certificate: could not read signatureAlgorithm")
	}
	// Verify it is id-alg-mtcProof with no parameters.

	// Read signatureValue.
	var sigValue cryptobyte.String
	if !cert.ReadASN1(&sigValue, cbasn1.BIT_STRING) {
		return errors.New("invalid certificate: could not read signatureValue")
	}
	// Skip the unused bits byte.
	if len(sigValue) < 1 {
		return errors.New("invalid signatureValue")
	}
	proofData := []byte(sigValue[1:])

	// Parse TBSCertificate to extract fields.
	tbs := cryptobyte.String(tbsBytes)
	var tbsSeq cryptobyte.String
	if !tbs.ReadASN1(&tbsSeq, cbasn1.SEQUENCE) {
		return errors.New("invalid TBSCertificate")
	}

	// version [0]
	var version cryptobyte.String
	if !tbsSeq.ReadOptionalASN1(&version, nil, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return errors.New("could not read version")
	}

	// serialNumber = index
	var serialNumber int
	if !tbsSeq.ReadASN1Integer(&serialNumber) {
		return errors.New("could not read serialNumber")
	}
	index := serialNumber

	// Step 3: Check revocation.
	if cfg.RevokedRanges.IsRevoked(index) {
		return fmt.Errorf("index %d is revoked", index)
	}

	// Parse MTCProof from signatureValue.
	mtcProof, err := UnmarshalMTCProof(proofData)
	if err != nil {
		return fmt.Errorf("parsing MTCProof: %w", err)
	}

	// Step 5: Compute entry hash using single-pass approach.
	// We construct the MerkleTreeCertEntry from the TBSCertificate.
	entryContents, err := BuildTBSCertificateLogEntry(tbsBytes)
	if err != nil {
		return fmt.Errorf("building TBSCertificateLogEntry: %w", err)
	}
	entry := MarshalTBSCertEntry(entryContents)
	entryHash := HashEntry(entry)

	// Step 6: Evaluate inclusion proof.
	expectedSubtreeHash, err := EvaluateSubtreeInclusionProof(
		mtcProof.InclusionProof, index, entryHash,
		int(mtcProof.Start), int(mtcProof.End),
	)
	if err != nil {
		return fmt.Errorf("evaluating inclusion proof: %w", err)
	}

	// Step 7: Check trusted subtrees (for landmark-relative certificates).
	for _, ts := range cfg.TrustedSubtrees {
		if ts.Start == mtcProof.Start && ts.End == mtcProof.End {
			if expectedSubtreeHash == ts.Hash {
				return nil
			}
			return fmt.Errorf("subtree hash mismatch with trusted subtree")
		}
	}

	// Step 8: Check cosignatures.
	var validCosignerIDs []TrustAnchorID
	for _, sig := range mtcProof.Signatures {
		for _, tc := range cfg.Cosigners {
			if !sig.CosignerID.Equal(tc.CosignerID) {
				continue
			}
			err := VerifyCosignature(
				tc.CosignerID, tc.PublicKey, tc.SignatureAlgorithm,
				cfg.LogID,
				mtcProof.Start, mtcProof.End,
				&expectedSubtreeHash,
				sig.Signature,
			)
			if err == nil {
				validCosignerIDs = append(validCosignerIDs, sig.CosignerID)
			}
			break
		}
	}

	if cfg.Policy != nil && !cfg.Policy.IsSatisfied(validCosignerIDs) {
		return errors.New("cosigner policy not satisfied")
	}

	return nil
}
