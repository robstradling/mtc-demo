package mtc

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MTCProof is the proof structure embedded in the signatureValue of a
// Merkle Tree Certificate, as defined in Section 6.1.
type MTCProof struct {
	Start          uint64
	End            uint64
	InclusionProof []byte
	Signatures     []MTCSignature
}

// Marshal serializes an MTCProof using the TLS presentation language.
func (p *MTCProof) Marshal() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint64(p.Start)
	b.AddUint64(p.End)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(p.InclusionProof)
	})
	b.AddUint16LengthPrefixed(func(sigs *cryptobyte.Builder) {
		for _, sig := range p.Signatures {
			sigs.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes(sig.CosignerID)
			})
			sigs.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes(sig.Signature)
			})
		}
	})
	return b.Bytes()
}

// UnmarshalMTCProof parses an MTCProof from its TLS serialization.
func UnmarshalMTCProof(data []byte) (*MTCProof, error) {
	if len(data) < 16 {
		return nil, errors.New("MTCProof too short")
	}
	p := &MTCProof{
		Start: binary.BigEndian.Uint64(data[0:8]),
		End:   binary.BigEndian.Uint64(data[8:16]),
	}
	s := cryptobyte.String(data[16:])

	var inclusionProof cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&inclusionProof) {
		return nil, errors.New("could not read inclusion_proof")
	}
	p.InclusionProof = []byte(inclusionProof)

	var signatures cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&signatures) {
		return nil, errors.New("could not read signatures")
	}
	for !signatures.Empty() {
		var sig MTCSignature
		var cosignerID cryptobyte.String
		if !signatures.ReadUint8LengthPrefixed(&cosignerID) {
			return nil, errors.New("could not read cosigner_id")
		}
		sig.CosignerID = TrustAnchorID(cosignerID)
		var sigBytes cryptobyte.String
		if !signatures.ReadUint16LengthPrefixed(&sigBytes) {
			return nil, errors.New("could not read signature")
		}
		sig.Signature = []byte(sigBytes)
		p.Signatures = append(p.Signatures, sig)
	}
	return p, nil
}

// CreateCertificate constructs an X.509 certificate containing an MTCProof
// in the signatureValue field, as defined in Section 6.1.
//
// Parameters:
//   - mt: the issuance log Merkle tree
//   - issuer: the log's trust anchor ID
//   - index: the entry's index in the log (used as serialNumber)
//   - tbsCertFields: the DER-encoded TBSCertificate body (version through extensions),
//     constructed to match the TBSCertificateLogEntry
//   - spki: the DER-encoded SubjectPublicKeyInfo
//   - start, end: the subtree for the proof
//   - cosigners: cosigner keys to produce cosignatures
func CreateCertificate(mt *MerkleTree, issuer TrustAnchorID, index int, tbsCertFields func(b *cryptobyte.Builder), spki []byte, start, end int, cosignerKeys []*CosignerKey) ([]byte, error) {
	// Build inclusion proof
	proof, err := mt.SubtreeInclusionProof(index, start, end)
	if err != nil {
		return nil, fmt.Errorf("creating inclusion proof: %w", err)
	}

	// Get subtree hash for cosigning
	subtreeHash, err := mt.SubtreeHash(start, end)
	if err != nil {
		return nil, fmt.Errorf("computing subtree hash: %w", err)
	}

	// Generate cosignatures
	var sigs []MTCSignature
	for _, ck := range cosignerKeys {
		sig, err := Cosign(ck, issuer, uint64(start), uint64(end), &subtreeHash)
		if err != nil {
			return nil, fmt.Errorf("cosigning: %w", err)
		}
		sigs = append(sigs, MTCSignature{
			CosignerID: ck.CosignerID,
			Signature:  sig,
		})
	}

	// Build MTCProof
	mtcProof := &MTCProof{
		Start:          uint64(start),
		End:            uint64(end),
		InclusionProof: proof,
		Signatures:     sigs,
	}
	proofBytes, err := mtcProof.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling proof: %w", err)
	}

	// Build the X.509 Certificate DER
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		// TBSCertificate
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			// version [0] EXPLICIT v3
			tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
				v.AddASN1Int64(2)
			})
			// serialNumber = index
			tbs.AddASN1Int64(int64(index))
			// signature = id-alg-mtcProof
			addMTCProofAlg(tbs)
			// issuer
			addIssuerDN(tbs, issuer)
			// The remaining fields are provided by the caller
			tbsCertFields(tbs)
			// subjectPublicKeyInfo
			tbs.AddBytes(spki)
		})

		// signatureAlgorithm = id-alg-mtcProof
		addMTCProofAlg(cert)

		// signatureValue
		cert.AddASN1BitString(proofBytes)
	})
	return b.Bytes()
}

// addMTCProofAlg adds the id-alg-mtcProof AlgorithmIdentifier (no parameters).
func addMTCProofAlg(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
		alg.AddASN1ObjectIdentifier(OIDMTCProofExperimental)
	})
}

// addIssuerDN adds the issuer distinguished name containing the trust anchor ID.
func addIssuerDN(b *cryptobyte.Builder, issuer TrustAnchorID) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(OIDRDNATrustAnchorIDExperimental)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(issuer.String()))
				})
			})
		})
	})
}
