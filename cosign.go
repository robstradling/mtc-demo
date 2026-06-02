package mtc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"
)

// SignatureAlgorithm identifies a cosigner signature algorithm.
type SignatureAlgorithm int

const (
	SignatureP256SHA256 SignatureAlgorithm = iota
	SignatureP384SHA384
	SignatureEd25519
	SignatureMLDSA44
)

// MTCSignature represents a cosignature with cosigner identity.
type MTCSignature struct {
	CosignerID TrustAnchorID
	Signature  []byte
}

// CosignerKey holds cosigner identity and key material for signing.
type CosignerKey struct {
	CosignerID         TrustAnchorID
	SignatureAlgorithm SignatureAlgorithm
	PrivateKey         crypto.Signer
}

// marshalCosignedMessage marshals a CosignedMessage as defined in
// Section 5.3.1. The timestamp field is set to zero for certificate use.
func marshalCosignedMessage(cosignerID TrustAnchorID, logID TrustAnchorID, start, end uint64, subtreeHash *HashValue) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	// label: "subtree/v1\n\0" (12 bytes)
	b.AddBytes([]byte("subtree/v1\n\x00"))
	// cosigner_name<1..2^8-1>
	cosignerName := []byte(cosignerID.OIDName())
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(cosignerName)
	})
	// timestamp: uint64 (zero for certificate use)
	b.AddUint64(0)
	// log_origin<1..2^8-1>
	logOrigin := []byte(logID.OIDName())
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(logOrigin)
	})
	b.AddUint64(start)
	b.AddUint64(end)
	b.AddBytes(subtreeHash[:])
	return b.Bytes()
}

// Cosign generates a cosignature over a subtree.
func Cosign(key *CosignerKey, logID TrustAnchorID, start, end uint64, hash *HashValue) ([]byte, error) {
	if !IsValidSubtree(int(start), int(end)) {
		return nil, fmt.Errorf("invalid subtree [%d, %d)", start, end)
	}
	input, err := marshalCosignedMessage(key.CosignerID, logID, start, end, hash)
	if err != nil {
		return nil, err
	}
	var opts crypto.SignerOpts
	var signInput []byte
	switch key.SignatureAlgorithm {
	case SignatureP256SHA256:
		h := crypto.SHA256.New()
		h.Write(input)
		signInput = h.Sum(nil)
		opts = crypto.SHA256
	case SignatureP384SHA384:
		h := crypto.SHA384.New()
		h.Write(input)
		signInput = h.Sum(nil)
		opts = crypto.SHA384
	case SignatureEd25519:
		signInput = input
		opts = crypto.Hash(0)
	case SignatureMLDSA44:
		// ML-DSA signs the raw message with empty context (§5.3.3, RFC 9881 §3).
		signInput = input
		opts = &mldsa.Options{}
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %d", key.SignatureAlgorithm)
	}
	return key.PrivateKey.Sign(rand.Reader, signInput, opts)
}

// VerifyCosignature verifies a cosignature over a subtree.
func VerifyCosignature(cosignerID TrustAnchorID, publicKey crypto.PublicKey, sigAlg SignatureAlgorithm, logID TrustAnchorID, start, end uint64, hash *HashValue, signature []byte) error {
	input, err := marshalCosignedMessage(cosignerID, logID, start, end, hash)
	if err != nil {
		return err
	}

	switch sigAlg {
	case SignatureP256SHA256:
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("not an ECDSA public key")
		}
		if ecKey.Curve != elliptic.P256() {
			return errors.New("not a P-256 key")
		}
		h := crypto.SHA256.New()
		h.Write(input)
		digest := h.Sum(nil)
		if !ecdsa.VerifyASN1(ecKey, digest, signature) {
			return errors.New("ECDSA P-256 signature verification failed")
		}
	case SignatureP384SHA384:
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("not an ECDSA public key")
		}
		if ecKey.Curve != elliptic.P384() {
			return errors.New("not a P-384 key")
		}
		h := crypto.SHA384.New()
		h.Write(input)
		digest := h.Sum(nil)
		if !ecdsa.VerifyASN1(ecKey, digest, signature) {
			return errors.New("ECDSA P-384 signature verification failed")
		}
	case SignatureEd25519:
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("not an Ed25519 public key")
		}
		if !ed25519.Verify(edKey, input, signature) {
			return errors.New("Ed25519 signature verification failed")
		}
	case SignatureMLDSA44:
		pk, ok := publicKey.(*mldsa.PublicKey)
		if !ok {
			return errors.New("not an ML-DSA public key")
		}
		if pk.Parameters() != mldsa.MLDSA44() {
			return errors.New("not an ML-DSA-44 key")
		}
		if err := mldsa.Verify(pk, input, signature, &mldsa.Options{}); err != nil {
			return fmt.Errorf("ML-DSA-44 signature verification failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signature algorithm: %d", sigAlg)
	}
	return nil
}
