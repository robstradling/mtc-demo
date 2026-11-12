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

func TestCosignMLDSA(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{SignatureMLDSA44, SignatureMLDSA65, SignatureMLDSA87} {
		params := mldsaParameters(alg)
		t.Run(params.String(), func(t *testing.T) {
			privKey, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatal(err)
			}

			cosignerID, _ := ParseTrustAnchorID("32473.1")
			logID, _ := ParseTrustAnchorID("32473.1.0.1")

			ck := &CosignerKey{
				CosignerID:         cosignerID,
				SignatureAlgorithm: alg,
				PrivateKey:         privKey,
			}

			mt, _ := makeTestTree(8)
			hash, _ := mt.SubtreeHash(0, 8)

			sig, err := Cosign(ck, logID, 0, 8, &hash)
			if err != nil {
				t.Fatalf("Cosign failed: %v", err)
			}
			if len(sig) != params.SignatureSize() {
				t.Fatalf("signature size = %d, want %d", len(sig), params.SignatureSize())
			}

			err = VerifyCosignature(cosignerID, privKey.PublicKey(), alg, logID, 0, 8, &hash, sig)
			if err != nil {
				t.Fatalf("VerifyCosignature failed: %v", err)
			}

			// Wrong hash should fail.
			wrongHash := HashValue{}
			err = VerifyCosignature(cosignerID, privKey.PublicKey(), alg, logID, 0, 8, &wrongHash, sig)
			if err == nil {
				t.Fatal("expected error for wrong hash")
			}

			// Mismatched parameter set should fail.
			other := SignatureMLDSA44
			if alg == SignatureMLDSA44 {
				other = SignatureMLDSA65
			}
			if err := VerifyCosignature(cosignerID, privKey.PublicKey(), other, logID, 0, 8, &hash, sig); err == nil {
				t.Fatal("expected error for mismatched ML-DSA parameter set")
			}
		})
	}
}
