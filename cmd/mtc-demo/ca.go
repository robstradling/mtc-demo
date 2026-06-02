package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"mtc"
)

func cmdCA(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo ca <subcommand>

Subcommands:
  init <ca-id> <log-number>   Initialize a new CA and issuance log
  info                        Show CA and log state
  add <common-name>           Add a TBS certificate entry to the log
  checkpoint                  Display current checkpoint hash
  issue <index>               Issue a certificate for a log entry
  prune <min-index>           Prune entries below min-index
`)
		return nil
	}

	switch args[0] {
	case "init":
		return cmdCAInit(args[1:])
	case "info":
		return cmdCAInfo()
	case "add":
		return cmdCAAdd(args[1:])
	case "checkpoint":
		return cmdCACheckpoint()
	case "issue":
		return cmdCAIssue(args[1:])
	case "prune":
		return cmdCAPrune(args[1:])
	default:
		return fmt.Errorf("unknown ca subcommand: %s", args[0])
	}
}

func cmdCAInit(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: mtc-demo ca init <ca-id> <log-number>")
	}

	existing, _ := loadState()
	if existing != nil {
		return fmt.Errorf("state already exists at %s; delete it first to reinitialize", statePath())
	}

	caID, err := mtc.ParseTrustAnchorID(args[0])
	if err != nil {
		return fmt.Errorf("invalid CA ID: %w", err)
	}
	logNum, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil || logNum == 0 {
		return fmt.Errorf("log number must be a positive integer (1-65535)")
	}

	log := mtc.NewIssuanceLog(caID, uint16(logNum))

	// Get the null entry at index 0.
	nullEntry, _ := log.Entry(0)

	s := &DemoState{
		CAID:      caID.String(),
		LogNumber: uint16(logNum),
		Entries:   []string{hex.EncodeToString(nullEntry)},
	}
	if err := saveState(s); err != nil {
		return err
	}

	fmt.Printf("CA initialized:\n")
	fmt.Printf("  CA ID:      %s\n", caID)
	fmt.Printf("  Log ID:     %s\n", log.LogID())
	fmt.Printf("  Log number: %d\n", logNum)
	fmt.Printf("  State file: %s\n", statePath())
	return nil
}

func cmdCAInfo() error {
	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}

	checkpoint, err := log.CheckpointHash()
	if err != nil {
		return err
	}

	fmt.Printf("CA ID:        %s\n", s.CAID)
	fmt.Printf("Log ID:       %s\n", log.LogID())
	fmt.Printf("Log number:   %d\n", s.LogNumber)
	fmt.Printf("Log size:     %d\n", log.Size())
	fmt.Printf("Min index:    %d\n", log.MinIndex())
	fmt.Printf("Checkpoint:   %s\n", hex.EncodeToString(checkpoint[:]))
	fmt.Printf("Cosigners:    %d\n", len(s.Cosigners))

	if s.Landmarks != nil {
		fmt.Printf("Landmarks:    %d (max active: %d)\n", len(s.Landmarks.TreeSizes), s.Landmarks.MaxActive)
	}

	return nil
}

func cmdCAAdd(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo ca add <common-name>")
	}
	cn := args[0]

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}
	caID, _ := mtc.ParseTrustAnchorID(s.CAID)

	// Generate a P-256 subject key.
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating subject key: %w", err)
	}
	spki, err := marshalSPKI(&subjectKey.PublicKey)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	tbsDER := buildDemoTBSCert(caID, cn, spki, notBefore, notAfter)
	contents, err := mtc.BuildTBSCertificateLogEntry(tbsDER)
	if err != nil {
		return fmt.Errorf("building log entry: %w", err)
	}

	idx := log.AddTBSCertEntry(contents)
	syncEntries(s, log)

	// Store per-entry metadata for certificate issuance.
	for len(s.EntryMeta) < log.Size() {
		s.EntryMeta = append(s.EntryMeta, EntryMeta{})
	}
	s.EntryMeta[idx] = EntryMeta{
		CN:        cn,
		SPKI:      hex.EncodeToString(spki),
		NotBefore: notBefore.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}

	if err := saveState(s); err != nil {
		return err
	}

	fmt.Printf("Added entry:\n")
	fmt.Printf("  Index:   %d\n", idx)
	fmt.Printf("  Subject: %s\n", cn)
	fmt.Printf("  SPKI:    %s...\n", hex.EncodeToString(spki[:16]))

	// Save the private key PEM for potential later use.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(subjectKey)
	if err == nil {
		keyFile := fmt.Sprintf("subject-%d.key.pem", idx)
		f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
			f.Close()
			fmt.Printf("  Key:     %s\n", keyFile)
		}
	}

	return nil
}

func cmdCACheckpoint() error {
	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}
	checkpoint, err := log.CheckpointHash()
	if err != nil {
		return err
	}

	fmt.Printf("Tree size:  %d\n", log.Size())
	fmt.Printf("Checkpoint: %s\n", hex.EncodeToString(checkpoint[:]))

	subtrees, err := findSubtreeSlice(0, log.Size())
	if err != nil {
		return err
	}
	fmt.Println("Subtrees:")
	for _, st := range subtrees {
		h, err := log.SubtreeHash(st.Start, st.End)
		if err != nil {
			continue
		}
		fmt.Printf("  [%d, %d): %s\n", st.Start, st.End, hex.EncodeToString(h[:]))
	}
	return nil
}

func cmdCAIssue(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo ca issue <index>")
	}
	index, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid index: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}
	caID, _ := mtc.ParseTrustAnchorID(s.CAID)

	if index < 1 || index >= log.Size() {
		return fmt.Errorf("index %d out of range (1..%d)", index, log.Size()-1)
	}

	// Retrieve stored entry metadata.
	if index >= len(s.EntryMeta) || s.EntryMeta[index].CN == "" {
		return fmt.Errorf("no metadata for entry %d; was it added with 'ca add'?", index)
	}
	meta := s.EntryMeta[index]

	spki, err := hex.DecodeString(meta.SPKI)
	if err != nil {
		return fmt.Errorf("decoding SPKI: %w", err)
	}
	notBefore, err := time.Parse(time.RFC3339, meta.NotBefore)
	if err != nil {
		return fmt.Errorf("parsing notBefore: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, meta.NotAfter)
	if err != nil {
		return fmt.Errorf("parsing notAfter: %w", err)
	}

	// Reconstruct cosigner keys.
	cosignerKeys, err := rebuildAllCosignerKeys(s)
	if err != nil {
		return err
	}
	if len(cosignerKeys) == 0 {
		return fmt.Errorf("no cosigner keys configured; run 'mtc-demo cosigner keygen' first")
	}

	// Find covering subtree for this entry.
	subtrees, err := findSubtreeSlice(0, log.Size())
	if err != nil {
		return err
	}
	var coveringST mtc.Interval
	found := false
	for _, st := range subtrees {
		if index >= st.Start && index < st.End {
			coveringST = st
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no covering subtree found for index %d", index)
	}

	certDER, err := mtc.CreateCertificate(
		log.Tree(),
		caID,
		log.LogID(),
		s.LogNumber,
		index,
		func(b *cryptobyte.Builder) {
			addValidity(b, notBefore, notAfter)
			addSubjectDN(b, meta.CN)
		},
		spki,
		coveringST.Start, coveringST.End,
		nil,
		cosignerKeys,
	)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	serial := (uint64(s.LogNumber) << 48) | uint64(index)
	certFile := fmt.Sprintf("cert-%d.pem", index)
	f, err := os.Create(certFile)
	if err != nil {
		return err
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	fmt.Printf("Certificate issued:\n")
	fmt.Printf("  Index:    %d\n", index)
	fmt.Printf("  Serial:   0x%x\n", serial)
	fmt.Printf("  Subtree:  [%d, %d)\n", coveringST.Start, coveringST.End)
	fmt.Printf("  Size:     %d bytes\n", len(certDER))
	fmt.Printf("  File:     %s\n", certFile)
	return nil
}

func cmdCAPrune(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo ca prune <min-index>")
	}
	minIdx, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid min-index: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}

	if err := log.Prune(minIdx); err != nil {
		return err
	}
	syncEntries(s, log)
	if err := saveState(s); err != nil {
		return err
	}

	fmt.Printf("Pruned to min index %d\n", minIdx)
	fmt.Printf("Log size: %d\n", log.Size())
	return nil
}
