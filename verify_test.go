package mtc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// TestIssuerDNEncoding checks the Section 5.1 example: CA ID 32473.1 is
// 1.3.6.1.5.5.7.25.3=#0d0481fd5901.
func TestIssuerDNEncoding(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	b := cryptobyte.NewBuilder(nil)
	addIssuerDN(b, caID)
	got, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("30143112301006082b06010505071903" + "0d0481fd5901")
	if !bytes.Equal(got, want) {
		t.Fatalf("issuer DN = %x, want %x", got, want)
	}
}

func TestCosignRejectsOutOfRangeOIDComponent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 32473 followed by a component equal to 2^64, which exceeds 64 bits.
	bad := TrustAnchorID{0x81, 0xfd, 0x59, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}
	good, _ := ParseTrustAnchorID("32473.1.0.1")
	var h HashValue

	ck := &CosignerKey{CosignerID: bad, SignatureAlgorithm: SignatureP256SHA256, PrivateKey: key}
	if _, err := Cosign(ck, good, 0, 1, &h); err == nil {
		t.Fatal("expected Cosign to fail for out-of-range cosigner ID component")
	}
	ck.CosignerID, _ = ParseTrustAnchorID("32473.1")
	if _, err := Cosign(ck, bad, 0, 1, &h); err == nil {
		t.Fatal("expected Cosign to fail for out-of-range log ID component")
	}
	if err := VerifyCosignature(bad, &key.PublicKey, SignatureP256SHA256, good, 0, 1, &h, []byte{0}); err == nil {
		t.Fatal("expected VerifyCosignature to fail for out-of-range cosigner ID component")
	}
}

// TestVerifyIgnoresGREASECosignature checks that a GREASE cosignature
// (Section 6.2) is parsed and ignored by the relying party.
func TestVerifyIgnoresGREASECosignature(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	greaseID, _ := ParseTrustAnchorID("32473.99999")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&subjectKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	notBefore := time.Now().Truncate(time.Second)
	fields := func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(v *cryptobyte.Builder) {
			v.AddASN1UTCTime(notBefore)
			v.AddASN1UTCTime(notBefore.Add(24 * time.Hour))
		})
		b.AddASN1(cbasn1.SEQUENCE, func(*cryptobyte.Builder) {}) // empty subject
	}

	tb := cryptobyte.NewBuilder(nil)
	tb.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(v *cryptobyte.Builder) {
			v.AddASN1Int64(2)
		})
		tbs.AddASN1BigInt(big.NewInt(0))
		addMTCProofAlg(tbs)
		addIssuerDN(tbs, caID)
		fields(tbs)
		tbs.AddBytes(spki)
	})
	tbsDER, err := tb.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := BuildTBSCertificateLogEntry(tbsDER)
	if err != nil {
		t.Fatal(err)
	}

	log := NewIssuanceLog(caID, 1)
	idx := log.AddTBSCertEntry(contents)
	caCosigner := &CosignerKey{CosignerID: caID, SignatureAlgorithm: SignatureP256SHA256, PrivateKey: caKey}
	certDER, err := CreateCertificate(log.Tree(), caID, log.LogID(), 1, idx, fields, spki, 0, log.Size(), nil, []*CosignerKey{caCosigner})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &VerifierConfig{
		CAID:      caID,
		Cosigners: []TrustedCosigner{{CosignerID: caID, SignatureAlgorithm: SignatureP256SHA256, PublicKey: &caKey.PublicKey}},
		Policy:    &AnyNCosignerPolicy{N: 1, Trusted: []TrustAnchorID{caID}},
	}
	if err := VerifyCertificateSignature(certDER, cfg); err != nil {
		t.Fatalf("baseline verification failed: %v", err)
	}

	withGREASE := replaceCosignatures(t, certDER, func(sigs []Cosignature) []Cosignature {
		return append(sigs, Cosignature{CosignerID: greaseID, Signature: []byte("grease")})
	})
	if err := VerifyCertificateSignature(withGREASE, cfg); err != nil {
		t.Fatalf("verification with GREASE cosignature failed: %v", err)
	}

	onlyGREASE := replaceCosignatures(t, certDER, func([]Cosignature) []Cosignature {
		return []Cosignature{{CosignerID: greaseID, Signature: []byte("grease")}}
	})
	if err := VerifyCertificateSignature(onlyGREASE, cfg); err == nil {
		t.Fatal("expected verification to fail with only a GREASE cosignature")
	}
}

// replaceCosignatures rewrites the MTCProof signatures in a certificate.
func replaceCosignatures(t *testing.T, certDER []byte, f func([]Cosignature) []Cosignature) []byte {
	t.Helper()
	input := cryptobyte.String(certDER)
	var cert, tbs, alg cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		t.Fatal("malformed certificate")
	}
	var bs cryptobyte.String
	if !cert.ReadASN1(&bs, cbasn1.BIT_STRING) || len(bs) < 1 {
		t.Fatal("malformed signatureValue")
	}
	proof, err := UnmarshalMTCProof(bs[1:])
	if err != nil {
		t.Fatal(err)
	}
	proof.Signatures = f(proof.Signatures)
	sortSignatures(proof.Signatures)
	proofBytes, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddBytes(tbs)
		c.AddBytes(alg)
		c.AddASN1BitString(proofBytes)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
