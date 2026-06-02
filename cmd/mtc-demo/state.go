package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"mtc"
)

// DemoState is the persistent state for the CLI tool.
type DemoState struct {
	CAID      string `json:"ca_id"`
	LogNumber uint16 `json:"log_number"`

	// Hex-encoded serialized MerkleTreeCertEntry values.
	Entries  []string `json:"entries"`
	MinIndex int      `json:"min_index"`

	// Per-entry metadata for certificate issuance.
	EntryMeta []EntryMeta `json:"entry_meta,omitempty"`

	Cosigners []CosignerKeyConfig `json:"cosigners"`

	Landmarks *LandmarkConfig `json:"landmarks,omitempty"`
}

// EntryMeta stores per-entry metadata needed to reconstruct TBSCertificates.
type EntryMeta struct {
	CN        string `json:"cn"`
	SPKI      string `json:"spki"`       // hex-encoded DER SubjectPublicKeyInfo
	NotBefore string `json:"not_before"` // RFC3339
	NotAfter  string `json:"not_after"`  // RFC3339
}

// CosignerKeyConfig stores a cosigner's key material.
type CosignerKeyConfig struct {
	ID         string `json:"id"`          // dotted-decimal trust anchor ID
	Algorithm  string `json:"algorithm"`   // "ed25519", "p256", "p384"
	PrivateKey string `json:"private_key"` // hex-encoded PKCS8 DER
}

// LandmarkConfig stores landmark sequence state.
type LandmarkConfig struct {
	MaxActive int      `json:"max_active"`
	TreeSizes []uint64 `json:"tree_sizes"`
}

// loadState reads state from the state file. Returns nil if file doesn't exist.
func loadState() (*DemoState, error) {
	data, err := os.ReadFile(statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s DemoState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing state: %w", err)
	}
	return &s, nil
}

// saveState writes state to the state file.
func saveState(s *DemoState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), data, 0600)
}

// requireState loads state and returns an error if not initialized.
func requireState() (*DemoState, error) {
	s, err := loadState()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("not initialized; run 'mtc-demo ca init' first")
	}
	return s, nil
}

// rebuildLog reconstructs an IssuanceLog from persisted state.
func rebuildLog(s *DemoState) (*mtc.IssuanceLog, error) {
	caID, err := mtc.ParseTrustAnchorID(s.CAID)
	if err != nil {
		return nil, fmt.Errorf("parsing CA ID: %w", err)
	}
	log := mtc.NewIssuanceLog(caID, s.LogNumber)
	// Entry 0 (null entry) was created by NewIssuanceLog.
	// Add remaining entries starting from index 1.
	for i := 1; i < len(s.Entries); i++ {
		entry, err := hex.DecodeString(s.Entries[i])
		if err != nil {
			return nil, fmt.Errorf("decoding entry %d: %w", i, err)
		}
		log.AddEntry(entry)
	}
	if s.MinIndex > 0 {
		if err := log.Prune(s.MinIndex); err != nil {
			return nil, err
		}
	}
	return log, nil
}

// syncEntries updates state entries from the log.
func syncEntries(s *DemoState, log *mtc.IssuanceLog) {
	s.Entries = make([]string, log.Size())
	for i := 0; i < log.Size(); i++ {
		entry, err := log.Entry(i)
		if err != nil {
			s.Entries[i] = "" // pruned
			continue
		}
		s.Entries[i] = hex.EncodeToString(entry)
	}
	s.MinIndex = log.MinIndex()
}

// rebuildLandmarks reconstructs a LandmarkSequence from persisted state.
func rebuildLandmarks(s *DemoState) (*mtc.LandmarkSequence, error) {
	if s.Landmarks == nil {
		return nil, fmt.Errorf("landmarks not initialized; run 'mtc-demo landmark init' first")
	}
	caID, err := mtc.ParseTrustAnchorID(s.CAID)
	if err != nil {
		return nil, err
	}
	ls := mtc.NewLandmarkSequence(caID, s.LogNumber, s.Landmarks.MaxActive)
	for i := 1; i < len(s.Landmarks.TreeSizes); i++ {
		if err := ls.AllocateLandmark(s.Landmarks.TreeSizes[i]); err != nil {
			return nil, fmt.Errorf("allocating landmark %d: %w", i, err)
		}
	}
	return ls, nil
}

// rebuildCosignerKey reconstructs a CosignerKey from config.
func rebuildCosignerKey(cfg CosignerKeyConfig) (*mtc.CosignerKey, error) {
	id, err := mtc.ParseTrustAnchorID(cfg.ID)
	if err != nil {
		return nil, err
	}
	pkcs8, err := hex.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	alg, err := parseAlgorithm(cfg.Algorithm)
	if err != nil {
		return nil, err
	}
	return &mtc.CosignerKey{
		CosignerID:         id,
		SignatureAlgorithm: alg,
		PrivateKey:         signer,
	}, nil
}

// rebuildAllCosignerKeys reconstructs all cosigner keys from state.
func rebuildAllCosignerKeys(s *DemoState) ([]*mtc.CosignerKey, error) {
	var keys []*mtc.CosignerKey
	for _, cfg := range s.Cosigners {
		k, err := rebuildCosignerKey(cfg)
		if err != nil {
			return nil, fmt.Errorf("cosigner %s: %w", cfg.ID, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// rebuildTrustedCosigners builds TrustedCosigner entries for verification.
func rebuildTrustedCosigners(s *DemoState) ([]mtc.TrustedCosigner, error) {
	var cosigners []mtc.TrustedCosigner
	for _, cfg := range s.Cosigners {
		id, err := mtc.ParseTrustAnchorID(cfg.ID)
		if err != nil {
			return nil, err
		}
		pkcs8, err := hex.DecodeString(cfg.PrivateKey)
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParsePKCS8PrivateKey(pkcs8)
		if err != nil {
			return nil, err
		}
		alg, err := parseAlgorithm(cfg.Algorithm)
		if err != nil {
			return nil, err
		}
		var pub crypto.PublicKey
		switch k := priv.(type) {
		case ed25519.PrivateKey:
			pub = k.Public()
		case *ecdsa.PrivateKey:
			pub = &k.PublicKey
		default:
			return nil, fmt.Errorf("unsupported key type for cosigner %s", cfg.ID)
		}
		cosigners = append(cosigners, mtc.TrustedCosigner{
			CosignerID:         id,
			SignatureAlgorithm: alg,
			PublicKey:          pub,
		})
	}
	return cosigners, nil
}

// parseAlgorithm converts a string algorithm name to SignatureAlgorithm.
func parseAlgorithm(name string) (mtc.SignatureAlgorithm, error) {
	switch name {
	case "ed25519":
		return mtc.SignatureEd25519, nil
	case "p256":
		return mtc.SignatureP256SHA256, nil
	case "p384":
		return mtc.SignatureP384SHA384, nil
	default:
		return 0, fmt.Errorf("unknown algorithm %q (use ed25519, p256, or p384)", name)
	}
}

// algorithmName converts a SignatureAlgorithm to a display name.
func algorithmName(alg mtc.SignatureAlgorithm) string {
	switch alg {
	case mtc.SignatureEd25519:
		return "ed25519"
	case mtc.SignatureP256SHA256:
		return "p256"
	case mtc.SignatureP384SHA384:
		return "p384"
	case mtc.SignatureMLDSA44:
		return "mldsa44"
	default:
		return fmt.Sprintf("unknown(%d)", alg)
	}
}

// generateCosignerKey generates a new key pair for the given algorithm.
func generateCosignerKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unknown algorithm %q", alg)
	}
}
