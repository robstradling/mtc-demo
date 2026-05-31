package mtc

import (
	"testing"
)

func TestIssuanceLog(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	log := NewIssuanceLog(caID, 1)

	// Should start with 1 entry (null entry at index 0).
	if log.Size() != 1 {
		t.Fatalf("initial size = %d, want 1", log.Size())
	}

	// Entry 0 should be a null entry.
	entry, err := log.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	expected := MarshalNullEntry()
	if len(entry) != len(expected) || entry[0] != expected[0] || entry[1] != expected[1] {
		t.Fatal("entry 0 is not a null entry")
	}

	// Add some entries.
	idx1 := log.AddEntry(MarshalTBSCertEntry([]byte("cert1")))
	idx2 := log.AddEntry(MarshalTBSCertEntry([]byte("cert2")))
	if idx1 != 1 || idx2 != 2 {
		t.Fatalf("indices = %d, %d; want 1, 2", idx1, idx2)
	}
	if log.Size() != 3 {
		t.Fatalf("size after 2 adds = %d, want 3", log.Size())
	}

	// Checkpoint hash should work.
	_, err = log.CheckpointHash()
	if err != nil {
		t.Fatal(err)
	}
}

func TestIssuanceLogProofs(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	log := NewIssuanceLog(caID, 1)
	for i := 0; i < 12; i++ {
		log.AddEntry(MarshalTBSCertEntry([]byte{byte(i)}))
	}
	// 13 entries total (1 null + 12 added).

	// Inclusion proof for entry 5 in full tree.
	proof, err := log.SubtreeInclusionProof(5, 0, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := log.Entry(5)
	entryHash := HashEntry(entry)
	rootHash, _ := log.CheckpointHash()
	err = VerifySubtreeInclusionProof(proof, 5, entryHash, rootHash, 0, log.Size())
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestIssuanceLogPruning(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	log := NewIssuanceLog(caID, 1)
	for i := 0; i < 10; i++ {
		log.AddEntry(MarshalTBSCertEntry([]byte{byte(i)}))
	}

	err := log.Prune(5)
	if err != nil {
		t.Fatal(err)
	}
	if log.MinIndex() != 5 {
		t.Fatalf("MinIndex = %d, want 5", log.MinIndex())
	}

	// Entry below min should be unavailable.
	_, err = log.Entry(4)
	if err == nil {
		t.Fatal("expected error for pruned entry")
	}

	// Entry at min should work.
	_, err = log.Entry(5)
	if err != nil {
		t.Fatal(err)
	}

	// Cannot decrease min.
	err = log.Prune(3)
	if err == nil {
		t.Fatal("expected error for decreasing minimum index")
	}
}

func TestIssuanceLogCoveringSubtrees(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	log := NewIssuanceLog(caID, 1)
	for i := 0; i < 12; i++ {
		log.AddEntry(MarshalTBSCertEntry([]byte{byte(i)}))
	}
	// 13 entries. Covering subtrees for entries added after checkpoint at 8.
	left, right, single, err := log.CoveringSubtrees(8)
	if err != nil {
		t.Fatal(err)
	}
	if single {
		t.Fatal("expected two subtrees")
	}
	if left.End != right.Start {
		t.Fatalf("subtrees not contiguous: left.End=%d, right.Start=%d", left.End, right.Start)
	}
	// The subtrees should cover [8, 13).
	if right.End != 13 {
		t.Fatalf("right.End = %d, want 13", right.End)
	}
}
