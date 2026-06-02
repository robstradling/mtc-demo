package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"mtc"
)

// cmdDemo runs a full end-to-end MTC lifecycle demonstration.
func cmdDemo() error {
	section("Setting up CA")
	caID, err := mtc.ParseTrustAnchorID("32473.1")
	if err != nil {
		return fmt.Errorf("parsing CA ID: %w", err)
	}
	fmt.Printf("  CA Trust Anchor ID: %s\n", caID)

	const logNumber uint16 = 1
	log := mtc.NewIssuanceLog(caID, logNumber)
	fmt.Printf("  Log ID:            %s\n", log.LogID())
	fmt.Printf("  Log number:        %d\n", log.LogNumber())
	fmt.Printf("  Initial log size:  %d (null entry at index 0)\n", log.Size())

	// ── Generate cosigner keys ──────────────────────────────────────
	section("Generating cosigner keys")

	cosigner1ID, _ := mtc.ParseTrustAnchorID("32473.100")
	cosigner2ID, _ := mtc.ParseTrustAnchorID("32473.200")

	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating Ed25519 key: %w", err)
	}
	cosigner1 := &mtc.CosignerKey{
		CosignerID:         cosigner1ID,
		SignatureAlgorithm: mtc.SignatureEd25519,
		PrivateKey:         ed25519Priv,
	}
	fmt.Printf("  Cosigner 1: %s (Ed25519)\n", cosigner1ID)

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating P-256 key: %w", err)
	}
	cosigner2 := &mtc.CosignerKey{
		CosignerID:         cosigner2ID,
		SignatureAlgorithm: mtc.SignatureP256SHA256,
		PrivateKey:         p256Key,
	}
	fmt.Printf("  Cosigner 2: %s (P-256/SHA-256)\n", cosigner2ID)

	// ── Generate subject keys ───────────────────────────────────────
	section("Generating subject keys")
	subjects := []string{"example.com", "test.example.com", "mail.example.com", "www.example.com"}
	type subjectInfo struct {
		CN   string
		Key  *ecdsa.PrivateKey
		SPKI []byte
	}
	subjectInfos := make([]subjectInfo, len(subjects))
	for i, cn := range subjects {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating key for %s: %w", cn, err)
		}
		spki, err := marshalSPKI(&key.PublicKey)
		if err != nil {
			return fmt.Errorf("marshaling SPKI for %s: %w", cn, err)
		}
		subjectInfos[i] = subjectInfo{CN: cn, Key: key, SPKI: spki}
		fmt.Printf("  %s: P-256 key generated\n", cn)
	}

	// ── Add entries to the log ──────────────────────────────────────
	section("Adding entries to the issuance log")

	notBefore := time.Now()
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	indices := make([]int, len(subjects))
	for i, si := range subjectInfos {
		tbsDER := buildDemoTBSCert(caID, si.CN, si.SPKI, notBefore, notAfter)
		contents, err := mtc.BuildTBSCertificateLogEntry(tbsDER)
		if err != nil {
			return fmt.Errorf("building log entry for %s: %w", si.CN, err)
		}
		idx := log.AddTBSCertEntry(contents)
		indices[i] = idx
		fmt.Printf("  Entry %d: %s (index %d)\n", i+1, si.CN, idx)
	}
	fmt.Printf("  Log size: %d\n", log.Size())

	// ── Checkpoint ──────────────────────────────────────────────────
	section("Computing checkpoint")
	checkpoint, err := log.CheckpointHash()
	if err != nil {
		return fmt.Errorf("computing checkpoint: %w", err)
	}
	fmt.Printf("  Root hash: %s\n", hex.EncodeToString(checkpoint[:]))
	fmt.Printf("  Tree size: %d\n", log.Size())

	// ── Subtree operations ──────────────────────────────────────────
	section("Subtree operations")
	subtrees, err := findSubtreeSlice(0, log.Size())
	if err != nil {
		return fmt.Errorf("finding subtrees: %w", err)
	}
	for _, st := range subtrees {
		h, err := log.SubtreeHash(st.Start, st.End)
		if err != nil {
			return fmt.Errorf("subtree hash: %w", err)
		}
		fmt.Printf("  Subtree [%d, %d): %s\n", st.Start, st.End, hex.EncodeToString(h[:]))
	}

	// ── Cosigning ───────────────────────────────────────────────────
	section("Cosigning subtrees")
	for _, st := range subtrees {
		h, _ := log.SubtreeHash(st.Start, st.End)
		sig1, err := mtc.Cosign(cosigner1, log.LogID(), uint64(st.Start), uint64(st.End), &h)
		if err != nil {
			return fmt.Errorf("cosigning: %w", err)
		}
		fmt.Printf("  Cosigner 1 signed [%d, %d): %s...\n", st.Start, st.End, hex.EncodeToString(sig1[:16]))

		sig2, err := mtc.Cosign(cosigner2, log.LogID(), uint64(st.Start), uint64(st.End), &h)
		if err != nil {
			return fmt.Errorf("cosigning: %w", err)
		}
		fmt.Printf("  Cosigner 2 signed [%d, %d): %s...\n", st.Start, st.End, hex.EncodeToString(sig2[:16]))
	}

	// ── Inclusion proofs ────────────────────────────────────────────
	section("Verifying inclusion proofs")
	for i, idx := range indices {
		entry, err := log.Entry(idx)
		if err != nil {
			return fmt.Errorf("getting entry: %w", err)
		}
		entryHash := mtc.HashEntry(entry)

		proof, err := log.Tree().InclusionProof(idx)
		if err != nil {
			return fmt.Errorf("creating inclusion proof: %w", err)
		}
		err = mtc.VerifyInclusionProof(proof, idx, log.Size(), entryHash, checkpoint)
		if err != nil {
			return fmt.Errorf("verifying inclusion proof: %w", err)
		}
		fmt.Printf("  Entry %d (%s): inclusion proof OK (%d hash path elements)\n",
			i+1, subjects[i], len(proof)/mtc.HashSize)
	}

	// ── Certificate creation ────────────────────────────────────────
	section("Creating Merkle Tree Certificate")

	certEntryIdx := indices[0]
	certSubject := subjectInfos[0]
	st := subtrees[0]

	certDER, err := mtc.CreateCertificate(
		log.Tree(),
		caID,
		log.LogID(),
		logNumber,
		certEntryIdx,
		func(b *cryptobyte.Builder) {
			addValidity(b, notBefore, notAfter)
			addSubjectDN(b, certSubject.CN)
		},
		certSubject.SPKI,
		st.Start, st.End,
		nil,
		[]*mtc.CosignerKey{cosigner1, cosigner2},
	)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}
	fmt.Printf("  Certificate size: %d bytes\n", len(certDER))
	fmt.Printf("  Subject:          %s\n", certSubject.CN)
	fmt.Printf("  Serial:           0x%x\n", (uint64(logNumber)<<48)|uint64(certEntryIdx))

	// ── Certificate verification ────────────────────────────────────
	section("Verifying Merkle Tree Certificate")

	verifierCfg := &mtc.VerifierConfig{
		CAID: caID,
		Cosigners: []mtc.TrustedCosigner{
			{
				CosignerID:         cosigner1ID,
				SignatureAlgorithm: mtc.SignatureEd25519,
				PublicKey:          ed25519Priv.Public(),
			},
			{
				CosignerID:         cosigner2ID,
				SignatureAlgorithm: mtc.SignatureP256SHA256,
				PublicKey:          &p256Key.PublicKey,
			},
		},
		Policy: &mtc.AnyNCosignerPolicy{
			N:       1,
			Trusted: []mtc.TrustAnchorID{cosigner1ID, cosigner2ID},
		},
	}

	err = mtc.VerifyCertificateSignature(certDER, verifierCfg)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}
	fmt.Println("  Certificate verification: PASSED")

	// ── Output certificate PEM ──────────────────────────────────────
	section("Certificate (PEM)")
	pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// ── Consistency proof ───────────────────────────────────────────
	section("Consistency proof")
	oldSize := log.Size()
	oldRoot := checkpoint

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newSPKI, _ := marshalSPKI(&newKey.PublicKey)
	newTBS := buildDemoTBSCert(caID, "new.example.com", newSPKI, notBefore, notAfter)
	newContents, _ := mtc.BuildTBSCertificateLogEntry(newTBS)
	log.AddTBSCertEntry(newContents)
	newRoot, err := log.CheckpointHash()
	if err != nil {
		return fmt.Errorf("computing new checkpoint: %w", err)
	}
	fmt.Printf("  Old tree size: %d, root: %s\n", oldSize, hex.EncodeToString(oldRoot[:]))
	fmt.Printf("  New tree size: %d, root: %s\n", log.Size(), hex.EncodeToString(newRoot[:]))

	consistencyProof, err := log.Tree().ConsistencyProof(oldSize)
	if err != nil {
		return fmt.Errorf("creating consistency proof: %w", err)
	}
	err = mtc.VerifyConsistencyProof(consistencyProof, oldSize, log.Size(), oldRoot, newRoot)
	if err != nil {
		return fmt.Errorf("verifying consistency proof: %w", err)
	}
	fmt.Printf("  Consistency proof: OK (%d hash path elements)\n", len(consistencyProof)/mtc.HashSize)

	section("Demo complete")
	return nil
}
