package mtc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"filippo.io/mldsa"
)

func TestCosignAndVerify(t *testing.T) {
	// Generate a P-256 key for cosigning.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cosignerID, _ := ParseTrustAnchorID("32473.1")
	logID, _ := ParseTrustAnchorID("32473.1.0.1")

	ck := &CosignerKey{
		CosignerID:         cosignerID,
		SignatureAlgorithm: SignatureP256SHA256,
		PrivateKey:         privKey,
	}

	mt, _ := makeTestTree(8)
	hash, _ := mt.SubtreeHash(0, 8)

	sig, err := Cosign(ck, logID, 0, 8, &hash)
	if err != nil {
		t.Fatalf("Cosign failed: %v", err)
	}

	err = VerifyCosignature(cosignerID, &privKey.PublicKey, SignatureP256SHA256, logID, 0, 8, &hash, sig)
	if err != nil {
		t.Fatalf("VerifyCosignature failed: %v", err)
	}

	// Wrong hash should fail.
	wrongHash := HashValue{}
	err = VerifyCosignature(cosignerID, &privKey.PublicKey, SignatureP256SHA256, logID, 0, 8, &wrongHash, sig)
	if err == nil {
		t.Fatal("expected error for wrong hash")
	}
}

func TestCosignEd25519(t *testing.T) {
	// Use crypto/ed25519 directly for testing.
	// Ed25519 requires crypto.SignMessage which is available in Go >= 1.21.
	// Skipping if not supported.
	t.Skip("Ed25519 cosigning requires crypto.SignMessage (Go 1.21+)")
}

func TestCosignMLDSA44(t *testing.T) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}

	cosignerID, _ := ParseTrustAnchorID("32473.1")
	logID, _ := ParseTrustAnchorID("32473.1.0.1")

	ck := &CosignerKey{
		CosignerID:         cosignerID,
		SignatureAlgorithm: SignatureMLDSA44,
		PrivateKey:         privKey,
	}

	mt, _ := makeTestTree(8)
	hash, _ := mt.SubtreeHash(0, 8)

	sig, err := Cosign(ck, logID, 0, 8, &hash)
	if err != nil {
		t.Fatalf("Cosign failed: %v", err)
	}

	err = VerifyCosignature(cosignerID, privKey.PublicKey(), SignatureMLDSA44, logID, 0, 8, &hash, sig)
	if err != nil {
		t.Fatalf("VerifyCosignature failed: %v", err)
	}

	// Wrong hash should fail.
	wrongHash := HashValue{}
	err = VerifyCosignature(cosignerID, privKey.PublicKey(), SignatureMLDSA44, logID, 0, 8, &wrongHash, sig)
	if err == nil {
		t.Fatal("expected error for wrong hash")
	}
}
