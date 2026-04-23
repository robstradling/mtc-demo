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

	"golang.org/x/crypto/cryptobyte"
)

// SignatureAlgorithm identifies a cosigner signature algorithm.
type SignatureAlgorithm int

const (
	SignatureP256SHA256 SignatureAlgorithm = iota
	SignatureP384SHA384
	SignatureEd25519
)

// MTCSubtree represents a subtree descriptor used in cosignatures.
type MTCSubtree struct {
	LogID TrustAnchorID
	Start uint64
	End   uint64
	Hash  HashValue
}

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

// marshalSubtreeSignatureInput marshals an MTCSubtreeSignatureInput
// as defined in Section 5.4.1.
func marshalSubtreeSignatureInput(cosignerID TrustAnchorID, subtree MTCSubtree) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	// label: "mtc-subtree/v1\n\0" (16 bytes)
	b.AddBytes([]byte("mtc-subtree/v1\n\x00"))
	// cosigner_id: TrustAnchorID<1..2^8-1>
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(cosignerID)
	})
	// log_id
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(subtree.LogID)
	})
	b.AddUint64(subtree.Start)
	b.AddUint64(subtree.End)
	b.AddBytes(subtree.Hash[:])
	return b.Bytes()
}

// Cosign generates a cosignature over a subtree.
func Cosign(key *CosignerKey, logID TrustAnchorID, start, end uint64, hash *HashValue) ([]byte, error) {
	if !IsValidSubtree(int(start), int(end)) {
		return nil, fmt.Errorf("invalid subtree [%d, %d)", start, end)
	}
	subtree := MTCSubtree{
		LogID: logID,
		Start: start,
		End:   end,
		Hash:  *hash,
	}
	input, err := marshalSubtreeSignatureInput(key.CosignerID, subtree)
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
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %d", key.SignatureAlgorithm)
	}
	return key.PrivateKey.Sign(rand.Reader, signInput, opts)
}

// VerifyCosignature verifies a cosignature over a subtree.
func VerifyCosignature(cosignerID TrustAnchorID, publicKey crypto.PublicKey, sigAlg SignatureAlgorithm, logID TrustAnchorID, start, end uint64, hash *HashValue, signature []byte) error {
	subtree := MTCSubtree{
		LogID: logID,
		Start: start,
		End:   end,
		Hash:  *hash,
	}
	input, err := marshalSubtreeSignatureInput(cosignerID, subtree)
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
	default:
		return fmt.Errorf("unsupported signature algorithm: %d", sigAlg)
	}
	return nil
}
