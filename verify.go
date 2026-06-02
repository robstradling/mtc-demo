package mtc

import (
	"crypto"
	"errors"
	"fmt"
	"math/big"

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
	LogNumber uint16
	Start     uint64
	End       uint64
	Hash      HashValue
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

// RevokedRanges holds ranges of revoked serial numbers (Section 7.5).
// Serial numbers encode both log number and index: (log_number << 48) | index.
type RevokedRanges []SerialRange

// SerialRange represents a half-open range of serial numbers [Start, End).
type SerialRange struct {
	Start, End uint64
}

// IsRevoked checks whether the given serial number falls within a revoked range.
func (rr RevokedRanges) IsRevoked(serial uint64) bool {
	for _, r := range rr {
		if serial >= r.Start && serial < r.End {
			return true
		}
	}
	return false
}

// VerifierConfig holds the relying party's configuration for
// verifying Merkle Tree Certificates (Section 7.1).
type VerifierConfig struct {
	CAID            TrustAnchorID
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

	// Read signatureValue.
	var sigValue cryptobyte.String
	if !cert.ReadASN1(&sigValue, cbasn1.BIT_STRING) {
		return errors.New("invalid certificate: could not read signatureValue")
	}
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

	// Step 3: Read serial number.
	// Use big.Int to handle serials up to 2^64-1 (the spec allows
	// values that overflow int64 when logNumber >= 32768).
	var serialBig big.Int
	if !tbsSeq.ReadASN1Integer(&serialBig) {
		return errors.New("could not read serialNumber")
	}
	if serialBig.Sign() < 0 {
		return errors.New("negative serial number")
	}
	if !serialBig.IsUint64() {
		return errors.New("serial number exceeds 2^64-1")
	}
	serial := serialBig.Uint64()

	// Step 4: Check revocation.
	if cfg.RevokedRanges.IsRevoked(serial) {
		return fmt.Errorf("serial %d is revoked", serial)
	}

	// Step 5: Extract index and log_number from serial.
	index := int(serial & 0xFFFFFFFFFFFF)
	logNumber := uint16(serial >> 48)
	if logNumber == 0 {
		return errors.New("log_number is zero")
	}

	// Step 6: Construct log_id from CA ID and log_number.
	logID := cfg.CAID.LogID(logNumber)

	// Parse MTCProof from signatureValue (Step 2).
	mtcProof, err := UnmarshalMTCProof(proofData)
	if err != nil {
		return fmt.Errorf("parsing MTCProof: %w", err)
	}

	// Step 8: Construct MerkleTreeCertEntry with extensions from MTCProof.
	entryContents, err := BuildTBSCertificateLogEntry(tbsBytes)
	if err != nil {
		return fmt.Errorf("building TBSCertificateLogEntry: %w", err)
	}
	// Build entry: extensions + type + tbs_cert_entry_data
	var entry []byte
	if mtcProof.Extensions != nil {
		entry = append(entry, mtcProof.Extensions...)
	} else {
		entry = append(entry, 0, 0) // empty extensions
	}
	entry = append(entry, byte(EntryTypeTBSCert>>8), byte(EntryTypeTBSCert))
	entry = append(entry, entryContents...)

	// Step 9: Compute entry hash.
	entryHash := HashEntry(entry)

	// Step 10: Evaluate inclusion proof.
	expectedSubtreeHash, err := EvaluateSubtreeInclusionProof(
		mtcProof.InclusionProof, index, entryHash,
		int(mtcProof.Start), int(mtcProof.End),
	)
	if err != nil {
		return fmt.Errorf("evaluating inclusion proof: %w", err)
	}

	// Step 11: Check trusted subtrees (for landmark-relative certificates).
	for _, ts := range cfg.TrustedSubtrees {
		if ts.LogNumber == logNumber && ts.Start == mtcProof.Start && ts.End == mtcProof.End {
			if expectedSubtreeHash == ts.Hash {
				return nil
			}
			return fmt.Errorf("subtree hash mismatch with trusted subtree")
		}
	}

	// Step 12: Check cosignatures.
	var validCosignerIDs []TrustAnchorID
	for _, sig := range mtcProof.Signatures {
		for _, tc := range cfg.Cosigners {
			if !sig.CosignerID.Equal(tc.CosignerID) {
				continue
			}
			err := VerifyCosignature(
				tc.CosignerID, tc.PublicKey, tc.SignatureAlgorithm,
				logID,
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
