package mtc

import (
	"fmt"
	"math/bits"
)

// MerkleTree is an in-memory Merkle Tree over a sequence of entries.
// It precomputes all interior nodes for efficient proof generation.
type MerkleTree struct {
	// levels[i][j] is the hash at level i, index j.
	// levels[0] contains leaf hashes.
	levels [][]HashValue
}

// NewMerkleTree constructs a MerkleTree from serialized entries.
func NewMerkleTree(entries [][]byte) *MerkleTree {
	mt := &MerkleTree{}
	level := make([]HashValue, len(entries))
	for i, entry := range entries {
		level[i] = HashLeaf(entry)
	}
	mt.levels = append(mt.levels, level)
	for {
		last := mt.levels[len(mt.levels)-1]
		if len(last) < 2 {
			break
		}
		next := make([]HashValue, len(last)/2)
		for i := range next {
			next[i] = HashNode(&last[2*i], &last[2*i+1])
		}
		mt.levels = append(mt.levels, next)
	}
	return mt
}

// Size returns the number of leaves in the tree.
func (mt *MerkleTree) Size() int {
	return len(mt.levels[0])
}

// RootHash returns the Merkle Tree Hash MTH(D_n).
func (mt *MerkleTree) RootHash() (HashValue, error) {
	return mt.SubtreeHash(0, mt.Size())
}

// SubtreeHash computes the hash of the subtree [start, end).
// The subtree must be valid as defined in Section 4.1.
func (mt *MerkleTree) SubtreeHash(start, end int) (HashValue, error) {
	if !IsValidSubtree(start, end) {
		return HashValue{}, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	if end > mt.Size() {
		return HashValue{}, fmt.Errorf("subtree [%d, %d) exceeds tree of size %d", start, end, mt.Size())
	}
	// Start at the largest complete subtree on the right edge.
	last := end - 1
	level := bits.TrailingZeros(^uint(last - start))
	s := start >> level
	l := last >> level
	ret := mt.levels[level][l]
	// Iterate up until we get the desired subtree.
	for s < l {
		if l&1 == 1 {
			ret = HashNode(&mt.levels[level][l-1], &ret)
		}
		level++
		s >>= 1
		l >>= 1
	}
	return ret, nil
}

// SubtreeInclusionProof generates a subtree inclusion proof (Section 4.3)
// for entry at index within subtree [start, end).
func (mt *MerkleTree) SubtreeInclusionProof(index, start, end int) ([]byte, error) {
	if !IsValidSubtree(start, end) {
		return nil, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	if end > mt.Size() {
		return nil, fmt.Errorf("subtree [%d, %d) exceeds tree of size %d", start, end, mt.Size())
	}
	if start > index || index >= end {
		return nil, fmt.Errorf("index %d not in subtree [%d, %d)", index, start, end)
	}
	var proof []byte
	var level int
	last := end - 1
	for start < last {
		neighbor := index ^ 1
		if neighbor < last {
			proof = append(proof, mt.levels[level][neighbor][:]...)
		} else if neighbor == last {
			h, err := mt.SubtreeHash(last<<level, end)
			if err != nil {
				return nil, err
			}
			proof = append(proof, h[:]...)
		}
		level++
		start >>= 1
		index >>= 1
		last >>= 1
	}
	return proof, nil
}

// SubtreeConsistencyProof generates a subtree consistency proof (Section 4.4)
// proving subtree [start, end) is consistent with tree of size n.
func (mt *MerkleTree) SubtreeConsistencyProof(start, end int) ([]byte, error) {
	if !IsValidSubtree(start, end) {
		return nil, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	n := mt.Size()
	if end > n {
		return nil, fmt.Errorf("subtree [%d, %d) exceeds tree of size %d", start, end, n)
	}
	var proof []byte
	mt.subtreeSubproof(start, end, 0, n, true, &proof)
	return proof, nil
}

func (mt *MerkleTree) subtreeSubproof(start, end, treeStart, treeEnd int, knownHash bool, proof *[]byte) {
	n := treeEnd - treeStart
	subStart := start - treeStart
	subEnd := end - treeStart

	if subStart == 0 && subEnd == n {
		if !knownHash {
			h, _ := mt.SubtreeHash(treeStart, treeEnd)
			*proof = append(*proof, h[:]...)
		}
		return
	}

	k := 1 << (bits.Len(uint(n-1)) - 1) // largest power of 2 < n
	if subEnd <= k {
		// Subtree is on the left.
		mt.subtreeSubproof(start, end, treeStart, treeStart+k, knownHash, proof)
		h, _ := mt.SubtreeHash(treeStart+k, treeEnd)
		*proof = append(*proof, h[:]...)
	} else if subStart >= k {
		// Subtree is on the right.
		mt.subtreeSubproof(start, end, treeStart+k, treeEnd, knownHash, proof)
		h, _ := mt.SubtreeHash(treeStart, treeStart+k)
		*proof = append(*proof, h[:]...)
	} else {
		// start < k < end, implies start == treeStart (i.e. subStart == 0)
		mt.subtreeSubproof(treeStart+k, end, treeStart+k, treeEnd, false, proof)
		h, _ := mt.SubtreeHash(treeStart, treeStart+k)
		*proof = append(*proof, h[:]...)
	}
}

// InclusionProof generates a Merkle inclusion proof for entry at index
// into the full tree, as in Section 2.1.3 of RFC 9162.
func (mt *MerkleTree) InclusionProof(index int) ([]byte, error) {
	return mt.SubtreeInclusionProof(index, 0, mt.Size())
}

// ConsistencyProof generates a Merkle consistency proof between
// a tree of size oldSize and this tree, as in Section 2.1.4 of RFC 9162.
func (mt *MerkleTree) ConsistencyProof(oldSize int) ([]byte, error) {
	return mt.SubtreeConsistencyProof(0, oldSize)
}
