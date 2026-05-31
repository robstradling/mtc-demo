package mtc

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MerkleTreeCertEntryType identifies the type of a log entry.
type MerkleTreeCertEntryType uint16

const (
	// EntryTypeNull is a null entry that carries no information.
	EntryTypeNull MerkleTreeCertEntryType = 0
	// EntryTypeTBSCert is a TBSCertificateLogEntry.
	EntryTypeTBSCert MerkleTreeCertEntryType = 1
)

var (
	// OIDMTCProofExperimental is the experimental OID for id-alg-mtcProof.
	OIDMTCProofExperimental = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	// OIDRDNATrustAnchorIDExperimental is the experimental OID for id-rdna-trustAnchorID.
	OIDRDNATrustAnchorIDExperimental = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	// OIDMTCCertificationAuthorityExperimental is the experimental OID for id-pe-mtcCertificationAuthority.
	OIDMTCCertificationAuthorityExperimental = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
)

// MerkleTreeCertEntryExtension represents a tag-length-value extension
// associated with a log entry (Section 5.2.1).
type MerkleTreeCertEntryExtension struct {
	ExtensionType uint16
	ExtensionData []byte
}

// MarshalExtensions serializes a list of extensions using the TLS
// presentation language as extensions<0..2^16-1>.
func MarshalExtensions(exts []MerkleTreeCertEntryExtension) []byte {
	var inner []byte
	for _, ext := range exts {
		inner = append(inner, byte(ext.ExtensionType>>8), byte(ext.ExtensionType))
		inner = append(inner, byte(len(ext.ExtensionData)>>8), byte(len(ext.ExtensionData)))
		inner = append(inner, ext.ExtensionData...)
	}
	// Prefix with 2-byte length.
	result := make([]byte, 2, 2+len(inner))
	result[0] = byte(len(inner) >> 8)
	result[1] = byte(len(inner))
	result = append(result, inner...)
	return result
}

// MarshalNullEntry returns the serialized form of a null_entry with
// empty extensions.
func MarshalNullEntry() []byte {
	return MarshalNullEntryWithExtensions(nil)
}

// MarshalNullEntryWithExtensions returns the serialized form of a
// null_entry with the given extensions.
func MarshalNullEntryWithExtensions(exts []MerkleTreeCertEntryExtension) []byte {
	b := MarshalExtensions(exts)
	b = append(b, byte(EntryTypeNull>>8), byte(EntryTypeNull))
	return b
}

// MarshalTBSCertEntry marshals a tbs_cert_entry from the DER-encoded
// contents of a TBSCertificateLogEntry. The contents parameter should
// be the concatenation of the DER encodings of each field (i.e., the
// contents octets of the SEQUENCE, excluding the SEQUENCE tag and length).
func MarshalTBSCertEntry(tbsCertLogEntryContents []byte) []byte {
	return MarshalTBSCertEntryWithExtensions(nil, tbsCertLogEntryContents)
}

// MarshalTBSCertEntryWithExtensions marshals a tbs_cert_entry with the
// given extensions.
func MarshalTBSCertEntryWithExtensions(exts []MerkleTreeCertEntryExtension, tbsCertLogEntryContents []byte) []byte {
	b := MarshalExtensions(exts)
	b = append(b, byte(EntryTypeTBSCert>>8), byte(EntryTypeTBSCert))
	b = append(b, tbsCertLogEntryContents...)
	return b
}

// BuildTBSCertificateLogEntry builds the contents octets of a
// TBSCertificateLogEntry from a TBSCertificate (as found in an X.509
// certificate). The issuer must be the log's trust anchor ID.
//
// The TBSCertificateLogEntry fields are:
//
//	version, issuer, validity, subject, subjectPublicKeyAlgorithm,
//	subjectPublicKeyInfoHash, issuerUniqueID, subjectUniqueID, extensions
//
// This function constructs the entry from the TBSCertificate by:
//   - Copying version, issuer, validity, subject
//   - Extracting the algorithm from subjectPublicKeyInfo
//   - Hashing the full subjectPublicKeyInfo
//   - Copying issuerUniqueID, subjectUniqueID, extensions if present
func BuildTBSCertificateLogEntry(tbsCert []byte) ([]byte, error) {
	input := cryptobyte.String(tbsCert)

	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: not a SEQUENCE")
	}

	b := cryptobyte.NewBuilder(nil)

	// version [0] EXPLICIT
	var version cryptobyte.String
	if !tbs.ReadOptionalASN1(&version, nil, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("invalid TBSCertificate: could not read version")
	}

	// Always write v3 version
	b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
		v.AddASN1Int64(2) // v3
	})

	// serialNumber - skip (not in log entry)
	var serial cryptobyte.String
	if !tbs.ReadASN1(&serial, cbasn1.INTEGER) {
		return nil, errors.New("invalid TBSCertificate: could not read serialNumber")
	}

	// signature (algorithm in TBSCert) - skip
	var sigAlg cryptobyte.String
	if !tbs.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: could not read signature algorithm")
	}

	// issuer
	var issuerBytes cryptobyte.String
	if !tbs.ReadASN1Element(&issuerBytes, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: could not read issuer")
	}
	b.AddBytes(issuerBytes)

	// validity
	var validityBytes cryptobyte.String
	if !tbs.ReadASN1Element(&validityBytes, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: could not read validity")
	}
	b.AddBytes(validityBytes)

	// subject
	var subjectBytes cryptobyte.String
	if !tbs.ReadASN1Element(&subjectBytes, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: could not read subject")
	}
	b.AddBytes(subjectBytes)

	// subjectPublicKeyInfo
	var spkiElement cryptobyte.String
	if !tbs.ReadASN1Element(&spkiElement, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid TBSCertificate: could not read subjectPublicKeyInfo")
	}
	spkiBytes := []byte(spkiElement)

	// Extract algorithm from SPKI
	spki := cryptobyte.String(spkiBytes)
	var spkiSeq cryptobyte.String
	if !spki.ReadASN1(&spkiSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid subjectPublicKeyInfo")
	}
	var algBytes cryptobyte.String
	if !spkiSeq.ReadASN1Element(&algBytes, cbasn1.SEQUENCE) {
		return nil, errors.New("invalid subjectPublicKeyInfo: could not read algorithm")
	}
	// subjectPublicKeyAlgorithm
	b.AddBytes(algBytes)

	// subjectPublicKeyInfoHash
	spkiHash := sha256.Sum256(spkiBytes)
	b.AddASN1OctetString(spkiHash[:])

	// Optional fields: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
	// These are context-specific tagged.
	var issuerUID cryptobyte.String
	var hasIssuerUID bool
	if !tbs.ReadOptionalASN1(&issuerUID, &hasIssuerUID, cbasn1.Tag(1).ContextSpecific()) {
		return nil, errors.New("invalid TBSCertificate: could not read issuerUniqueID")
	}
	if hasIssuerUID {
		b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(child *cryptobyte.Builder) {
			child.AddBytes(issuerUID)
		})
	}

	var subjectUID cryptobyte.String
	var hasSubjectUID bool
	if !tbs.ReadOptionalASN1(&subjectUID, &hasSubjectUID, cbasn1.Tag(2).ContextSpecific()) {
		return nil, errors.New("invalid TBSCertificate: could not read subjectUniqueID")
	}
	if hasSubjectUID {
		b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(child *cryptobyte.Builder) {
			child.AddBytes(subjectUID)
		})
	}

	var extensions cryptobyte.String
	var hasExtensions bool
	if !tbs.ReadOptionalASN1(&extensions, &hasExtensions, cbasn1.Tag(3).Constructed().ContextSpecific()) {
		return nil, errors.New("invalid TBSCertificate: could not read extensions")
	}
	if hasExtensions {
		b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(child *cryptobyte.Builder) {
			child.AddBytes(extensions)
		})
	}

	return b.Bytes()
}

// HashEntry computes the Merkle leaf hash of a serialized MerkleTreeCertEntry.
func HashEntry(entry []byte) HashValue {
	return HashLeaf(entry)
}
