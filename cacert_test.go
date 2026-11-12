package mtc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"filippo.io/mldsa"
)

func TestCreateCACertificate(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		pub  crypto.PublicKey
		alg  SignatureAlgorithm
		oid  asn1.ObjectIdentifier
	}{
		{"p256", &p256.PublicKey, SignatureP256SHA256, oidECDSAWithSHA256},
		{"p384", &p384.PublicKey, SignatureP384SHA384, oidECDSAWithSHA384},
		{"ed25519", edPub, SignatureEd25519, oidEd25519},
		{"mldsa44", mlKey.PublicKey(), SignatureMLDSA44, oidMLDSA44},
	}

	notBefore := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2056, 11, 1, 0, 0, 0, 0, time.UTC)
	minSerial := MTCMinSerial | 5
	maxSerial := 2<<48 - 1

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der, err := CreateCACertificate(caID, tc.pub, tc.alg, minSerial, uint64(maxSerial), notBefore, notAfter)
			if err != nil {
				t.Fatal(err)
			}
			// crypto/x509 cannot parse the RELATIVE-OID subject, so
			// decode the structure directly.
			var cert struct {
				TBS struct {
					Version  int `asn1:"optional,explicit,default:0,tag:0"`
					Serial   *big.Int
					SigAlg   asn1.RawValue
					Issuer   asn1.RawValue
					Validity struct {
						NotBefore, NotAfter time.Time
					}
					Subject    asn1.RawValue
					SPKI       asn1.RawValue
					Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
				}
				SigAlg asn1.RawValue
				Sig    asn1.BitString
			}
			if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 {
				t.Fatalf("parsing certificate: %v", err)
			}
			tbs := &cert.TBS

			// RFC 9925 unsigned certificate.
			wantAlg, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: OIDAlgUnsigned})
			if !bytes.Equal(cert.SigAlg.FullBytes, wantAlg) || !bytes.Equal(tbs.SigAlg.FullBytes, wantAlg) || cert.Sig.BitLength != 0 {
				t.Errorf("not an unsigned certificate: alg %x, sig bits %d", cert.SigAlg.FullBytes, cert.Sig.BitLength)
			}
			wantIssuer, _ := hex.DecodeString("3010310e300c06082b060105050719010c00")
			if !bytes.Equal(tbs.Issuer.FullBytes, wantIssuer) {
				t.Errorf("issuer = %x, want %x", tbs.Issuer.FullBytes, wantIssuer)
			}

			if tbs.Version != 2 {
				t.Errorf("version = %d, want 2 (v3)", tbs.Version)
			}
			wantSubject, _ := hex.DecodeString("30143112301006082b06010505071903" + "0d0481fd5901")
			if !bytes.Equal(tbs.Subject.FullBytes, wantSubject) {
				t.Errorf("subject = %x, want %x", tbs.Subject.FullBytes, wantSubject)
			}
			if !tbs.Validity.NotBefore.Equal(notBefore) || !tbs.Validity.NotAfter.Equal(notAfter) {
				t.Errorf("validity = %v..%v", tbs.Validity.NotBefore, tbs.Validity.NotAfter)
			}
			if tbs.Serial.Sign() <= 0 {
				t.Errorf("serial %v is not positive", tbs.Serial)
			}

			wantSPKI, err := marshalCosignerSPKI(tc.pub, tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tbs.SPKI.FullBytes, wantSPKI) {
				t.Error("SPKI mismatch")
			}

			skid := append([]byte{0x04, byte(len(caID))}, caID...)
			wantExts := []struct {
				oid      asn1.ObjectIdentifier
				critical bool
				value    []byte // nil: checked separately
			}{
				{oidExtBasicConstraints, true, []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
				{oidExtKeyUsage, true, []byte{0x03, 0x02, 0x02, 0x04}},
				{oidExtSubjectKeyID, false, skid},
				{OIDMTCCertificationAuthoritySHA256, true, nil},
			}
			if len(tbs.Extensions) != len(wantExts) {
				t.Fatalf("got %d extensions, want %d", len(tbs.Extensions), len(wantExts))
			}
			for i, w := range wantExts {
				ext := tbs.Extensions[i]
				if !ext.Id.Equal(w.oid) || ext.Critical != w.critical {
					t.Errorf("extension %d = %v (critical %v), want %v (critical %v)", i, ext.Id, ext.Critical, w.oid, w.critical)
				}
				if w.value != nil && !bytes.Equal(ext.Value, w.value) {
					t.Errorf("extension %v value = %x, want %x", w.oid, ext.Value, w.value)
				}
			}

			for _, ext := range tbs.Extensions {
				if !ext.Id.Equal(OIDMTCCertificationAuthoritySHA256) {
					continue
				}
				var ca struct {
					SigAlg    pkix.AlgorithmIdentifier
					MinSerial *big.Int
					MaxSerial *big.Int
				}
				if rest, err := asn1.Unmarshal(ext.Value, &ca); err != nil || len(rest) != 0 {
					t.Fatalf("parsing MTC CA extension: %v", err)
				}
				if !ca.SigAlg.Algorithm.Equal(tc.oid) || len(ca.SigAlg.Parameters.FullBytes) != 0 {
					t.Errorf("sigAlg = %v, want %v with no parameters", ca.SigAlg.Algorithm, tc.oid)
				}
				if ca.MinSerial.Uint64() != minSerial || ca.MaxSerial.Uint64() != uint64(maxSerial) {
					t.Errorf("serials = [%v, %v]", ca.MinSerial, ca.MaxSerial)
				}
			}
		})
	}
}

func TestCreateCACertificateMaxSerial(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	der, err := CreateCACertificate(caID, &key.PublicKey, SignatureP256SHA256, MTCMinSerial, MTCMaxSerial, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// INTEGER 2^64-1 needs a leading zero octet.
	if !bytes.Contains(der, []byte{0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("maxSerial 2^64-1 not encoded as a positive 9-octet INTEGER")
	}
}

func TestCreateCACertificateRejects(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	later := now.Add(time.Hour)

	cases := []struct {
		name     string
		pub      crypto.PublicKey
		alg      SignatureAlgorithm
		min, max uint64
		nb, na   time.Time
	}{
		{"minSerial too small", &p256.PublicKey, SignatureP256SHA256, MTCMinSerial - 1, MTCMinSerial, now, later},
		{"min > max", &p256.PublicKey, SignatureP256SHA256, MTCMinSerial + 1, MTCMinSerial, now, later},
		{"wrong curve", &p256.PublicKey, SignatureP384SHA384, MTCMinSerial, MTCMaxSerial, now, later},
		{"wrong key type", edPub, SignatureP256SHA256, MTCMinSerial, MTCMaxSerial, now, later},
		{"bad validity", &p256.PublicKey, SignatureP256SHA256, MTCMinSerial, MTCMaxSerial, later, now},
	}
	for _, tc := range cases {
		if _, err := CreateCACertificate(caID, tc.pub, tc.alg, tc.min, tc.max, tc.nb, tc.na); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
