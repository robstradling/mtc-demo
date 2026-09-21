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
// Appendix C.1.1 of draft-ietf-plants-merkle-tree-certs-06.
func TestAppendixC1SubtreeHashes(t *testing.T) {
	const maxSize = 130
	mt := buildTestTree(maxSize)
	h := sha256.New()

	for end := 0; end <= maxSize; end++ {
		for start := 0; start <= end; start++ {
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
	want := "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
	if got != want {
		t.Fatalf("Appendix C.1.1 subtree hashes: got %s, want %s", got, want)
	}
}

// TestAppendixC2SubtreeInclusionProofs verifies the accumulated test vector
// from Appendix C.1.2 of draft-ietf-plants-merkle-tree-certs-06.
func TestAppendixC2SubtreeInclusionProofs(t *testing.T) {
	const maxSize = 130
	mt := buildTestTree(maxSize)
	h := sha256.New()

	for end := 0; end <= maxSize; end++ {
		for start := 0; start <= end; start++ {
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
		t.Fatalf("Appendix C.1.2 subtree inclusion proofs: got %s, want %s", got, want)
	}
}

// TestAppendixC3SubtreeConsistencyProofs verifies the accumulated test vector
// from Appendix C.1.3 of draft-ietf-plants-merkle-tree-certs-06.
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
		for end := 0; end <= n; end++ {
			for start := 0; start <= end; start++ {
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
	want := "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
	if got != want {
		t.Fatalf("Appendix C.1.3 subtree consistency proofs: got %s, want %s", got, want)
	}
}

// TestAppendixC4EfficientCoveringSubtrees verifies the accumulated test vector
// from Appendix C.1.4 of draft-ietf-plants-merkle-tree-certs-06.
func TestAppendixC4EfficientCoveringSubtrees(t *testing.T) {
	const maxSize = 130
	h := sha256.New()

	for end := 0; end <= maxSize; end++ {
		for start := 0; start <= end; start++ {
			left, right, err := FindSubtrees(start, end)
			if err != nil {
				t.Fatalf("FindSubtrees(%d, %d): %v", start, end, err)
			}
			line := fmt.Sprintf("[%d, %d) [%d, %d)\n", left.Start, left.End, right.Start, right.End)
			h.Write([]byte(line))
		}
	}

	got := hex.EncodeToString(h.Sum(nil))
	want := "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
	if got != want {
		t.Fatalf("Appendix C.1.4 efficient covering subtrees: got %s, want %s", got, want)
	}
}

// TestAppendixC2LargeSubtreeValidity verifies the large-tree subtree
// validity vectors from Appendix C.2.1 of draft-ietf-plants-merkle-tree-certs-06.
func TestAppendixC2LargeSubtreeValidity(t *testing.T) {
	valid := []struct{ start, end uint64 }{
		{0, (1 << 47) + 1},
		{0, (1 << 48) - 1},
		{0, (1 << 62) + 1},
		{0, (1 << 63) - 1},
		{0, (1 << 63) + 1},
		{0, ^uint64(0)}, // 2^64 - 1
	}
	invalid := []struct{ start, end uint64 }{
		{1 << 46, (1 << 47) + 1},
		{1 << 46, (1 << 48) - 1},
		{1 << 61, (1 << 62) + 1},
		{1 << 61, (1 << 63) - 1},
		{1 << 62, (1 << 63) + 1},
		{1 << 62, ^uint64(0)},
	}
	for _, tc := range valid {
		if !isValidSubtreeU64(tc.start, tc.end) {
			t.Errorf("isValidSubtreeU64(%#x, %#x) = false, want true", tc.start, tc.end)
		}
	}
	for _, tc := range invalid {
		if isValidSubtreeU64(tc.start, tc.end) {
			t.Errorf("isValidSubtreeU64(%#x, %#x) = true, want false", tc.start, tc.end)
		}
	}
}
