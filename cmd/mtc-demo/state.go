package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"mtc"
)

// DemoState is the persistent state for the CLI tool.
type DemoState struct {
	CAID      string `json:"ca_id"`
	LogNumber uint16 `json:"log_number"`

	// Hex-encoded serialized MTCLogEntry values.
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
	Algorithm  string `json:"algorithm"`   // "ed25519", "p256", "p384", "mldsa44", "mldsa65", "mldsa87"
	PrivateKey string `json:"private_key"` // hex-encoded PKCS8 DER
}

// LandmarkConfig stores landmark sequence state.
type LandmarkConfig struct {
	MaxActive int      `json:"max_active"`
	TreeSizes []uint64 `json:"tree_sizes"`
	Expiries  []uint64 `json:"expiries"` // seconds since the Epoch, parallel to TreeSizes
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
		var expiry uint64
		if i < len(s.Landmarks.Expiries) {
			expiry = s.Landmarks.Expiries[i]
		}
		if err := ls.AllocateLandmark(s.Landmarks.TreeSizes[i], expiry); err != nil {
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
	signer, err := parsePrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
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
		k, err := rebuildCosignerKey(cfg)
		if err != nil {
			return nil, fmt.Errorf("cosigner %s: %w", cfg.ID, err)
		}
		cosigners = append(cosigners, mtc.TrustedCosigner{
			CosignerID:         k.CosignerID,
			SignatureAlgorithm: k.SignatureAlgorithm,
			PublicKey:          k.PrivateKey.Public(),
		})
	}
	return cosigners, nil
}

// mldsaAlgorithms maps CLI names to ML-DSA parameter sets and their
// RFC 9881 OIDs; crypto/x509 cannot encode these keys.
var mldsaAlgorithms = []struct {
	name   string
	params *mldsa.Parameters
	oid    asn1.ObjectIdentifier
}{
	{"mldsa44", mldsa.MLDSA44(), asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}},
	{"mldsa65", mldsa.MLDSA65(), asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}},
	{"mldsa87", mldsa.MLDSA87(), asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}},
}

// marshalPrivateKey encodes a private key as PKCS #8. ML-DSA keys use the
// seed-only form from RFC 9881 §6.
func marshalPrivateKey(key crypto.Signer) ([]byte, error) {
	k, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return x509.MarshalPKCS8PrivateKey(key)
	}
	for _, m := range mldsaAlgorithms {
		if k.PublicKey().Parameters() != m.params {
			continue
		}
		b := cryptobyte.NewBuilder(nil)
		b.AddASN1(cbasn1.SEQUENCE, func(pki *cryptobyte.Builder) {
			pki.AddASN1Int64(0)
			pki.AddASN1(cbasn1.SEQUENCE, func(a *cryptobyte.Builder) {
				a.AddASN1ObjectIdentifier(m.oid)
			})
			pki.AddASN1(cbasn1.OCTET_STRING, func(pk *cryptobyte.Builder) {
				pk.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(seed *cryptobyte.Builder) {
					seed.AddBytes(k.Bytes())
				})
			})
		})
		return b.Bytes()
	}
	return nil, errors.New("unknown ML-DSA parameter set")
}

// parsePrivateKey decodes a PKCS #8 private key written by marshalPrivateKey.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	in := cryptobyte.String(der)
	var pki, algSeq cryptobyte.String
	var version int64
	var oid asn1.ObjectIdentifier
	if in.ReadASN1(&pki, cbasn1.SEQUENCE) && pki.ReadASN1Integer(&version) &&
		pki.ReadASN1(&algSeq, cbasn1.SEQUENCE) && algSeq.ReadASN1ObjectIdentifier(&oid) {
		for _, m := range mldsaAlgorithms {
			if !oid.Equal(m.oid) {
				continue
			}
			var privKey, seed cryptobyte.String
			if !pki.ReadASN1(&privKey, cbasn1.OCTET_STRING) ||
				!privKey.ReadASN1(&seed, cbasn1.Tag(0).ContextSpecific()) || !privKey.Empty() {
				return nil, errors.New("unsupported ML-DSA private key encoding (want seed form)")
			}
			return mldsa.NewPrivateKey(m.params, seed)
		}
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not implement crypto.Signer")
	}
	return signer, nil
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
	case "mldsa44":
		return mtc.SignatureMLDSA44, nil
	case "mldsa65":
		return mtc.SignatureMLDSA65, nil
	case "mldsa87":
		return mtc.SignatureMLDSA87, nil
	default:
		return 0, fmt.Errorf("unknown algorithm %q (use %s)", name, algorithmList)
	}
}

const algorithmList = "ed25519, p256, p384, mldsa44, mldsa65, mldsa87"

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
	case mtc.SignatureMLDSA65:
		return "mldsa65"
	case mtc.SignatureMLDSA87:
		return "mldsa87"
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
		for _, m := range mldsaAlgorithms {
			if m.name == alg {
				return mldsa.GenerateKey(m.params)
			}
		}
		return nil, fmt.Errorf("unknown algorithm %q", alg)
	}
}
