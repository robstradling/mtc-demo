package mtc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// OIDAlgUnsigned is id-alg-unsigned (1.3.6.1.5.5.7.6.36), RFC 9925.
	OIDAlgUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}
	// OIDRDNAUnsigned is id-rdna-unsigned (1.3.6.1.5.5.7.25.1), RFC 9925.
	OIDRDNAUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 1}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

const (
	// MTCMinSerial is mtcMinSerial (2^48), the minimum serial number
	// in this protocol (Section 5.5).
	MTCMinSerial uint64 = 1 << 48
	// MTCMaxSerial is mtcMaxSerial (2^64-1), the maximum serial number
	// in this protocol (Section 5.5).
	MTCMaxSerial uint64 = 1<<64 - 1
)

// signatureAlgorithmOID returns the AlgorithmIdentifier OID for a cosigner
// signature algorithm, as used in the MTCCertificationAuthority sigAlg field.
func signatureAlgorithmOID(alg SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch alg {
	case SignatureP256SHA256:
		return oidECDSAWithSHA256, nil
	case SignatureP384SHA384:
		return oidECDSAWithSHA384, nil
	case SignatureEd25519:
		return oidEd25519, nil
	case SignatureMLDSA44:
		return oidMLDSA44, nil
	case SignatureMLDSA65:
		return oidMLDSA65, nil
	case SignatureMLDSA87:
		return oidMLDSA87, nil
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %d", alg)
	}
}

// marshalCosignerSPKI returns the DER SubjectPublicKeyInfo for a cosigner
// public key, checking that the key matches the signature algorithm.
func marshalCosignerSPKI(pub crypto.PublicKey, alg SignatureAlgorithm) ([]byte, error) {
	switch alg {
	case SignatureP256SHA256, SignatureP384SHA384:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA public key")
		}
		want := elliptic.P256()
		if alg == SignatureP384SHA384 {
			want = elliptic.P384()
		}
		if k.Curve != want {
			return nil, fmt.Errorf("ECDSA key is not on %s", want.Params().Name)
		}
		return x509.MarshalPKIXPublicKey(k)
	case SignatureEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("not an Ed25519 public key")
		}
		return x509.MarshalPKIXPublicKey(k)
	case SignatureMLDSA44, SignatureMLDSA65, SignatureMLDSA87:
		params := mldsaParameters(alg)
		k, ok := pub.(*mldsa.PublicKey)
		if !ok || k.Parameters() != params {
			return nil, fmt.Errorf("not an %s public key", params)
		}
		oid, _ := signatureAlgorithmOID(alg)
		// RFC 9881 §4: parameters absent, raw public key in the BIT STRING.
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(spki *cryptobyte.Builder) {
			spki.AddASN1(cbasn1.SEQUENCE, func(a *cryptobyte.Builder) {
				a.AddASN1ObjectIdentifier(oid)
			})
			spki.AddASN1BitString(k.Bytes())
		})
		return b.Bytes()
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %d", alg)
	}
}

// ParseCosignerPublicKey parses a DER SubjectPublicKeyInfo holding a
// cosigner public key and returns the key and its signature algorithm.
// Supported keys are ECDSA P-256 and P-384, Ed25519, and ML-DSA-44, -65
// and -87; each key type implies a single signature algorithm.
func ParseCosignerPublicKey(spki []byte) (crypto.PublicKey, SignatureAlgorithm, error) {
	input := cryptobyte.String(spki)
	var seq, algSeq cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !input.Empty() ||
		!seq.ReadASN1(&algSeq, cbasn1.SEQUENCE) ||
		!algSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, 0, errors.New("malformed SubjectPublicKeyInfo")
	}

	for _, alg := range []SignatureAlgorithm{SignatureMLDSA44, SignatureMLDSA65, SignatureMLDSA87} {
		if algOID, _ := signatureAlgorithmOID(alg); !oid.Equal(algOID) {
			continue
		}
		var bits asn1.BitString
		if !algSeq.Empty() || !seq.ReadASN1BitString(&bits) || !seq.Empty() || bits.BitLength%8 != 0 {
			return nil, 0, errors.New("malformed ML-DSA SubjectPublicKeyInfo")
		}
		pk, err := mldsa.NewPublicKey(mldsaParameters(alg), bits.Bytes)
		if err != nil {
			return nil, 0, err
		}
		return pk, alg, nil
	}

	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, 0, err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return k, SignatureP256SHA256, nil
		case elliptic.P384():
			return k, SignatureP384SHA384, nil
		}
		return nil, 0, fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return k, SignatureEd25519, nil
	}
	return nil, 0, fmt.Errorf("unsupported public key algorithm %v", oid)
}

// addCertTime adds a UTCTime for years 1950-2049 and a GeneralizedTime
// otherwise (RFC 5280 Section 4.1.2.5).
func addCertTime(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC()
	if y := t.Year(); y >= 1950 && y < 2050 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}

// addExtension adds an X.509 Extension whose extnValue is built by f.
func addExtension(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, critical bool, f cryptobyte.BuilderContinuation) {
	b.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
		ext.AddASN1ObjectIdentifier(oid)
		if critical {
			ext.AddASN1Boolean(true)
		}
		ext.AddASN1(cbasn1.OCTET_STRING, f)
	})
}

// CreateCACertificate constructs the X.509 certificate representation of
// a Merkle Tree CA, as defined in Section 5.5. The certificate's subject is
// the CA ID, its subjectPublicKeyInfo is the CA cosigner's public key (pub,
// for algorithm alg), and it carries a critical
// id-pe-mtcCertificationAuthority-SHA256 extension with the given serial
// number bounds.
//
// Per Section 5.5, the certificate is not self-signed. It is an unsigned
// certificate (RFC 9925) with the id-rdna-unsigned placeholder issuer.
func CreateCACertificate(caID TrustAnchorID, pub crypto.PublicKey, alg SignatureAlgorithm, minSerial, maxSerial uint64, notBefore, notAfter time.Time) ([]byte, error) {
	if _, err := caID.OIDName(); err != nil || len(caID) == 0 {
		return nil, fmt.Errorf("invalid CA ID %q", caID.String())
	}
	if minSerial < MTCMinSerial || maxSerial < MTCMinSerial {
		return nil, fmt.Errorf("serial bounds must be at least %d", MTCMinSerial)
	}
	if minSerial > maxSerial {
		return nil, fmt.Errorf("minSerial %d exceeds maxSerial %d", minSerial, maxSerial)
	}
	if notAfter.Before(notBefore) {
		return nil, errors.New("notAfter is before notBefore")
	}
	sigAlgOID, err := signatureAlgorithmOID(alg)
	if err != nil {
		return nil, err
	}
	spki, err := marshalCosignerSPKI(pub, alg)
	if err != nil {
		return nil, err
	}

	// RFC 5280 serial: positive, at most 20 octets.
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, err
	}
	serialBytes[0] = serialBytes[0]&0x7f | 0x40
	serial := new(big.Int).SetBytes(serialBytes)

	unsignedAlg := func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(a *cryptobyte.Builder) {
			a.AddASN1ObjectIdentifier(OIDAlgUnsigned)
		})
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
				v.AddASN1Int64(2)
			})
			tbs.AddASN1BigInt(serial)
			unsignedAlg(tbs)
			// issuer: RFC 9925 placeholder, 1.3.6.1.5.5.7.25.1=#0C00
			tbs.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
				dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
					rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
						attr.AddASN1ObjectIdentifier(OIDRDNAUnsigned)
						attr.AddASN1(cbasn1.UTF8String, func(*cryptobyte.Builder) {})
					})
				})
			})
			tbs.AddASN1(cbasn1.SEQUENCE, func(v *cryptobyte.Builder) {
				addCertTime(v, notBefore)
				addCertTime(v, notAfter)
			})
			addIssuerDN(tbs, caID) // subject
			tbs.AddBytes(spki)
			tbs.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(e *cryptobyte.Builder) {
				e.AddASN1(cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
					addExtension(exts, oidExtBasicConstraints, true, func(v *cryptobyte.Builder) {
						v.AddASN1(cbasn1.SEQUENCE, func(bc *cryptobyte.Builder) {
							bc.AddASN1Boolean(true)
						})
					})
					addExtension(exts, oidExtKeyUsage, true, func(v *cryptobyte.Builder) {
						// keyCertSign (bit 5): 2 unused bits, 0b00000100.
						v.AddASN1(cbasn1.BIT_STRING, func(bs *cryptobyte.Builder) {
							bs.AddBytes([]byte{0x02, 0x04})
						})
					})
					addExtension(exts, oidExtSubjectKeyID, false, func(v *cryptobyte.Builder) {
						v.AddASN1OctetString(caID)
					})
					addExtension(exts, OIDMTCCertificationAuthoritySHA256, true, func(v *cryptobyte.Builder) {
						v.AddASN1(cbasn1.SEQUENCE, func(ca *cryptobyte.Builder) {
							ca.AddASN1(cbasn1.SEQUENCE, func(a *cryptobyte.Builder) {
								a.AddASN1ObjectIdentifier(sigAlgOID)
							})
							ca.AddASN1Uint64(minSerial)
							ca.AddASN1Uint64(maxSerial)
						})
					})
				})
			})
		})
		unsignedAlg(cert)
		cert.AddASN1BitString(nil)
	})
	return b.Bytes()
}
