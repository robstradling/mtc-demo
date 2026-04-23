package mtc

import (
	"testing"
)

func makeTestTree(n int) (*MerkleTree, [][]byte) {
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	return NewMerkleTree(entries), entries
}

func TestMerkleTreeSize(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 16, 100} {
		mt, _ := makeTestTree(n)
		if mt.Size() != n {
			t.Fatalf("Size() = %d, want %d", mt.Size(), n)
		}
	}
}

func TestMerkleTreeRootHash(t *testing.T) {
	mt1, _ := makeTestTree(8)
	mt2, _ := makeTestTree(8)
	h1, err := mt1.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := mt2.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("same trees should have same root hash")
	}

	mt3, _ := makeTestTree(7)
	h3, err := mt3.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("different trees should have different root hashes")
	}
}

func TestSubtreeHash(t *testing.T) {
	mt, _ := makeTestTree(13)

	// [0, 13) should equal the root hash.
	root, _ := mt.RootHash()
	h, err := mt.SubtreeHash(0, 13)
	if err != nil {
		t.Fatal(err)
	}
	if h != root {
		t.Fatal("[0, 13) hash should equal root hash")
	}

	// [4, 8) should be a valid full subtree.
	_, err = mt.SubtreeHash(4, 8)
	if err != nil {
		t.Fatal(err)
	}

	// [8, 13) should be a valid partial subtree.
	_, err = mt.SubtreeHash(8, 13)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid subtree should error.
	_, err = mt.SubtreeHash(3, 7)
	if err == nil {
		t.Fatal("expected error for invalid subtree [3, 7)")
	}
}

func TestSubtreeInclusionProof(t *testing.T) {
	mt, _ := makeTestTree(13)

	// Test inclusion proof for entry 10 in subtree [8, 13).
	proof, err := mt.SubtreeInclusionProof(10, 8, 13)
	if err != nil {
		t.Fatal(err)
	}

	entryHash := HashLeaf([]byte{10})
	subtreeHash, _ := mt.SubtreeHash(8, 13)

	err = VerifySubtreeInclusionProof(proof, 10, entryHash, subtreeHash, 8, 13)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Test that a wrong entry hash fails.
	wrongHash := HashLeaf([]byte{99})
	err = VerifySubtreeInclusionProof(proof, 10, wrongHash, subtreeHash, 8, 13)
	if err == nil {
		t.Fatal("expected error for wrong entry hash")
	}
}

func TestSubtreeInclusionProofAllEntries(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 16, 32, 33} {
		mt, entries := makeTestTree(n)
		rootHash, _ := mt.RootHash()
		for i := 0; i < n; i++ {
			proof, err := mt.InclusionProof(i)
			if err != nil {
				t.Fatalf("n=%d, i=%d: InclusionProof failed: %v", n, i, err)
			}
			entryHash := HashLeaf(entries[i])
			err = VerifyInclusionProof(proof, i, n, entryHash, rootHash)
			if err != nil {
				t.Fatalf("n=%d, i=%d: verification failed: %v", n, i, err)
			}
		}
	}
}

func TestSubtreeConsistencyProof(t *testing.T) {
	mt, _ := makeTestTree(14)
	rootHash, _ := mt.RootHash()

	// Test consistency for [4, 8) within tree of 14.
	subtreeHash, _ := mt.SubtreeHash(4, 8)
	proof, err := mt.SubtreeConsistencyProof(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySubtreeConsistencyProof(proof, 4, 8, 14, subtreeHash, rootHash)
	if err != nil {
		t.Fatalf("consistency proof verification failed: %v", err)
	}

	// Test consistency for [8, 13) within tree of 14.
	subtreeHash2, _ := mt.SubtreeHash(8, 13)
	proof2, err := mt.SubtreeConsistencyProof(8, 13)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySubtreeConsistencyProof(proof2, 8, 13, 14, subtreeHash2, rootHash)
	if err != nil {
		t.Fatalf("consistency proof verification for [8,13) failed: %v", err)
	}
}

func TestConsistencyProof(t *testing.T) {
	// Standard Merkle consistency proof: [0, oldSize) in tree of newSize.
	for _, tc := range []struct{ old, new int }{
		{1, 2}, {1, 8}, {3, 8}, {4, 8}, {6, 8},
		{1, 13}, {5, 13}, {8, 13}, {12, 13},
		{1, 16}, {8, 16}, {15, 16},
	} {
		mt, _ := makeTestTree(tc.new)
		mtOld, _ := makeTestTree(tc.old)
		oldRoot, _ := mtOld.RootHash()
		newRoot, _ := mt.RootHash()

		proof, err := mt.ConsistencyProof(tc.old)
		if err != nil {
			t.Fatalf("old=%d, new=%d: ConsistencyProof failed: %v", tc.old, tc.new, err)
		}

		err = VerifyConsistencyProof(proof, tc.old, tc.new, oldRoot, newRoot)
		if err != nil {
			t.Fatalf("old=%d, new=%d: verification failed: %v", tc.old, tc.new, err)
		}
	}
}
