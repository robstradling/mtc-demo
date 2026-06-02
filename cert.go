package mtc

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MTCProof is the proof structure embedded in the signatureValue of a
// Merkle Tree Certificate, as defined in Section 6.1.
type MTCProof struct {
	Extensions     []byte // raw serialized extensions<0..2^16-1>
	Start          uint64
	End            uint64
	InclusionProof []byte
	Signatures     []MTCSignature
}

// addUint48 appends a big-endian 48-bit integer to the builder.
func addUint48(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{
		byte(v >> 40), byte(v >> 32), byte(v >> 24),
		byte(v >> 16), byte(v >> 8), byte(v),
	})
}

// readUint48 reads a big-endian 48-bit integer from a byte slice.
func readUint48(data []byte) uint64 {
	return uint64(data[0])<<40 | uint64(data[1])<<32 | uint64(data[2])<<24 |
		uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
}

// Marshal serializes an MTCProof using the TLS presentation language.
// Cosigner IDs must be unique and ordered (shorter before longer,
// then lexicographic).
func (p *MTCProof) Marshal() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	// extensions<0..2^16-1>
	if p.Extensions != nil {
		b.AddBytes(p.Extensions)
	} else {
		b.AddUint16(0) // empty extensions
	}
	// uint48 start, uint48 end
	addUint48(b, p.Start)
	addUint48(b, p.End)
	// inclusion_proof<0..2^16-1>
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(p.InclusionProof)
	})
	// signatures<0..2^16-1>
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
	s := cryptobyte.String(data)
	p := &MTCProof{}

	// Read extensions<0..2^16-1>
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("could not read extensions")
	}
	if len(extensions) > 0 {
		// Store with the length prefix for round-tripping.
		p.Extensions = make([]byte, 2+len(extensions))
		p.Extensions[0] = byte(len(extensions) >> 8)
		p.Extensions[1] = byte(len(extensions))
		copy(p.Extensions[2:], extensions)
	} else {
		p.Extensions = []byte{0, 0}
	}

	// Read uint48 start, uint48 end
	if len(s) < 12 {
		return nil, errors.New("MTCProof too short for start/end")
	}
	p.Start = readUint48([]byte(s[:6]))
	s = s[6:]
	p.End = readUint48([]byte(s[:6]))
	s = s[6:]

	// inclusion_proof<0..2^16-1>
	var inclusionProof cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&inclusionProof) {
		return nil, errors.New("could not read inclusion_proof")
	}
	p.InclusionProof = []byte(inclusionProof)

	// signatures<0..2^16-1>
	var signatures cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&signatures) {
		return nil, errors.New("could not read signatures")
	}
	var prevID TrustAnchorID
	for !signatures.Empty() {
		var sig MTCSignature
		var cosignerID cryptobyte.String
		if !signatures.ReadUint8LengthPrefixed(&cosignerID) {
			return nil, errors.New("could not read cosigner_id")
		}
		sig.CosignerID = TrustAnchorID(cosignerID)
		// Enforce ordering: shorter before longer, then lexicographic.
		if prevID != nil {
			if compareCosignerIDs(prevID, sig.CosignerID) >= 0 {
				return nil, errors.New("cosigner_id values not in canonical order")
			}
		}
		prevID = sig.CosignerID
		var sigBytes cryptobyte.String
		if !signatures.ReadUint16LengthPrefixed(&sigBytes) {
			return nil, errors.New("could not read signature")
		}
		sig.Signature = []byte(sigBytes)
		p.Signatures = append(p.Signatures, sig)
	}
	return p, nil
}

// compareCosignerIDs compares two cosigner IDs for canonical ordering:
// shorter before longer, then lexicographic.
func compareCosignerIDs(a, b TrustAnchorID) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return bytes.Compare(a, b)
}

// sortSignatures sorts MTCSignature slices by cosigner_id in canonical order.
func sortSignatures(sigs []MTCSignature) {
	sort.Slice(sigs, func(i, j int) bool {
		return compareCosignerIDs(sigs[i].CosignerID, sigs[j].CosignerID) < 0
	})
}

// CreateCertificate constructs an X.509 certificate containing an MTCProof
// in the signatureValue field, as defined in Section 6.1.
//
// Parameters:
//   - mt: the issuance log Merkle tree
//   - issuer: the CA's trust anchor ID (used in the issuer DN)
//   - logID: the issuance log's trust anchor ID (used for cosigning)
//   - logNumber: the log number (1-65535)
//   - index: the entry's zero-based index in the log
//   - tbsCertFields: callback to write validity, subject, extensions into the TBSCertificate
//   - spki: the DER-encoded SubjectPublicKeyInfo
//   - start, end: the subtree for the proof
//   - extensions: serialized MerkleTreeCertEntryExtension extensions (or nil)
//   - cosignerKeys: cosigner keys to produce cosignatures
func CreateCertificate(mt *MerkleTree, issuer TrustAnchorID, logID TrustAnchorID, logNumber uint16, index int, tbsCertFields func(b *cryptobyte.Builder), spki []byte, start, end int, extensions []byte, cosignerKeys []*CosignerKey) ([]byte, error) {
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
		sig, err := Cosign(ck, logID, uint64(start), uint64(end), &subtreeHash)
		if err != nil {
			return nil, fmt.Errorf("cosigning: %w", err)
		}
		sigs = append(sigs, MTCSignature{
			CosignerID: ck.CosignerID,
			Signature:  sig,
		})
	}

	// Sort signatures by cosigner_id in canonical order.
	sortSignatures(sigs)

	// Compute serial number: (log_number << 48) | index
	serial := (uint64(logNumber) << 48) | uint64(index)

	// Build MTCProof
	mtcProof := &MTCProof{
		Extensions:     extensions,
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
			// serialNumber = (log_number << 48) | index
			tbs.AddASN1BigInt(new(big.Int).SetUint64(serial))
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
