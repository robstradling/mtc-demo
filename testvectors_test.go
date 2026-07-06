package mtc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// buildTestTree builds a tree of size n where d[i] = byte(i).
func buildTestTree(n int) *MerkleTree {
	entries := make([][]byte, n)
	for i := 0; i < n; i++ {
		entries[i] = []byte{byte(i)}
	}
	return NewMerkleTree(entries)
}

// TestAppendixC1SubtreeHashes verifies the accumulated test vector from
// Appendix C.1 of draft-ietf-plants-merkle-tree-certs-05.
func TestAppendixC1SubtreeHashes(t *testing.T) {
	const maxSize = 130
	mt := buildTestTree(maxSize)
	h := sha256.New()

	for end := 1; end <= maxSize; end++ {
		for start := 0; start < end; start++ {
			if !IsValidSubtree(start, end) {
				continue
			}
			subtreeHash, err := mt.SubtreeHash(start, end)
			if err != nil {
				t.Fatalf("SubtreeHash(%d, %d): %v", start, end, err)
			}
			line := fmt.Sprintf("[%d, %d) %s\n", start, end, hex.EncodeToString(subtreeHash[:]))
			h.Write([]byte(line))
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	if got != want {
		t.Fatalf("Appendix C.1 subtree hashes: got %s, want %s", got, want)
	}
}

// TestAppendixC2SubtreeInclusionProofs verifies the accumulated test vector
// from Appendix C.2 of draft-ietf-plants-merkle-tree-certs-05.
func TestAppendixC2SubtreeInclusionProofs(t *testing.T) {
	const maxSize = 130
	mt := buildTestTree(maxSize)
	h := sha256.New()

	for end := 1; end <= maxSize; end++ {
		for start := 0; start < end; start++ {
			if !IsValidSubtree(start, end) {
				continue
			}
			for index := start; index < end; index++ {
				proof, err := mt.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				line := fmt.Sprintf("%d [%d, %d)", index, start, end)
				for i := 0; i < len(proof); i += HashSize {
					line += fmt.Sprintf(" %s", hex.EncodeToString(proof[i:i+HashSize]))
				}
				line += "\n"
				h.Write([]byte(line))
			}
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
	if got != want {
		t.Fatalf("Appendix C.2 subtree inclusion proofs: got %s, want %s", got, want)
	}
}

// TestAppendixC3SubtreeConsistencyProofs verifies the accumulated test vector
// from Appendix C.3 of draft-ietf-plants-merkle-tree-certs-05.
func TestAppendixC3SubtreeConsistencyProofs(t *testing.T) {
	const maxSize = 130
	h := sha256.New()

	// We need trees of different sizes for the consistency proofs.
	trees := make([]*MerkleTree, maxSize+1)
	for n := 0; n <= maxSize; n++ {
		entries := make([][]byte, n)
		for i := 0; i < n; i++ {
			entries[i] = []byte{byte(i)}
		}
		trees[n] = NewMerkleTree(entries)
	}

	for n := 0; n <= maxSize; n++ {
		for end := 1; end <= n; end++ {
			for start := 0; start < end; start++ {
				if !IsValidSubtree(start, end) {
					continue
				}
				proof, err := trees[n].SubtreeConsistencyProof(start, end)
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof([%d, %d), %d): %v", start, end, n, err)
				}
				line := fmt.Sprintf("[%d, %d) %d", start, end, n)
				for i := 0; i < len(proof); i += HashSize {
					line += fmt.Sprintf(" %s", hex.EncodeToString(proof[i:i+HashSize]))
				}
				line += "\n"
				h.Write([]byte(line))
			}
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	if got != want {
		t.Fatalf("Appendix C.3 subtree consistency proofs: got %s, want %s", got, want)
	}
}

// TestAppendixC4EfficientCoveringSubtrees verifies the accumulated test vector
// from Appendix C.4 of draft-ietf-plants-merkle-tree-certs-05.
func TestAppendixC4EfficientCoveringSubtrees(t *testing.T) {
	const maxSize = 130
	h := sha256.New()

	for end := 1; end <= maxSize; end++ {
		for start := 0; start < end; start++ {
			if IsValidSubtree(start, end) {
				line := fmt.Sprintf("[%d, %d)\n", start, end)
				h.Write([]byte(line))
			} else {
				left, right, single, err := FindSubtrees(start, end)
				if err != nil {
					t.Fatalf("FindSubtrees(%d, %d): %v", start, end, err)
				}
				if single {
					line := fmt.Sprintf("[%d, %d)\n", left.Start, left.End)
					h.Write([]byte(line))
				} else {
					line := fmt.Sprintf("[%d, %d) [%d, %d)\n", left.Start, left.End, right.Start, right.End)
					h.Write([]byte(line))
				}
			}
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := "e0aecb912a10c57d753b6ecc64db73217f9bc4ed10fcb4e9062be3b6fbe1ebfd"
	if got != want {
		t.Fatalf("Appendix C.4 efficient covering subtrees: got %s, want %s", got, want)
	}
}
