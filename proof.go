package mtc

import (
	"errors"
	"fmt"
)

// ErrInvalidProof is returned when a proof fails verification.
var ErrInvalidProof = errors.New("invalid proof")

// EvaluateSubtreeInclusionProof evaluates a subtree inclusion proof
// (Section 4.3.2) and returns the expected subtree hash.
//
// Parameters:
//   - inclusionProof: the proof bytes (sequence of HashSize hashes)
//   - index: the entry index in the full tree
//   - entryHash: the hash of the entry
//   - start, end: the subtree interval [start, end)
func EvaluateSubtreeInclusionProof(inclusionProof []byte, index int, entryHash HashValue, start, end int) (HashValue, error) {
	if !IsValidSubtree(start, end) {
		return HashValue{}, fmt.Errorf("%w: invalid subtree [%d, %d)", ErrInvalidProof, start, end)
	}
	if index < start || index >= end {
		return HashValue{}, fmt.Errorf("%w: index %d not in [%d, %d)", ErrInvalidProof, index, start, end)
	}
	if len(inclusionProof)%HashSize != 0 {
		return HashValue{}, fmt.Errorf("%w: proof length %d not a multiple of %d", ErrInvalidProof, len(inclusionProof), HashSize)
	}

	fn := index - start
	sn := end - start - 1
	r := entryHash

	for len(inclusionProof) > 0 {
		if sn == 0 {
			return HashValue{}, fmt.Errorf("%w: proof has too many elements", ErrInvalidProof)
		}
		var p HashValue
		copy(p[:], inclusionProof[:HashSize])
		inclusionProof = inclusionProof[HashSize:]

		if fn&1 == 1 || fn == sn {
			r = HashNode(&p, &r)
			// "Until LSB(fn) is set, right-shift fn and sn equally."
			// This means: while LSB(fn) is NOT set, right-shift.
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashNode(&r, &p)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return HashValue{}, fmt.Errorf("%w: proof has too few elements", ErrInvalidProof)
	}
	return r, nil
}

// VerifySubtreeInclusionProof verifies a subtree inclusion proof
// (Section 4.3.3).
func VerifySubtreeInclusionProof(inclusionProof []byte, index int, entryHash, subtreeHash HashValue, start, end int) error {
	expected, err := EvaluateSubtreeInclusionProof(inclusionProof, index, entryHash, start, end)
	if err != nil {
		return err
	}
	if expected != subtreeHash {
		return fmt.Errorf("%w: computed subtree hash does not match", ErrInvalidProof)
	}
	return nil
}

// VerifySubtreeConsistencyProof verifies a subtree consistency proof
// (Section 4.4.3).
//
// Parameters:
//   - proof: the proof bytes (sequence of HashSize hashes)
//   - start, end: the subtree interval [start, end)
//   - n: the full tree size
//   - nodeHash: the expected subtree hash
//   - rootHash: the expected full tree root hash
func VerifySubtreeConsistencyProof(proof []byte, start, end, n int, nodeHash, rootHash HashValue) error {
	if !IsValidSubtree(start, end) {
		return fmt.Errorf("%w: invalid subtree [%d, %d)", ErrInvalidProof, start, end)
	}
	if end > n {
		return fmt.Errorf("%w: subtree end %d > tree size %d", ErrInvalidProof, end, n)
	}
	if len(proof)%HashSize != 0 {
		return fmt.Errorf("%w: proof length %d not a multiple of %d", ErrInvalidProof, len(proof), HashSize)
	}

	fn := start
	sn := end - 1
	tn := n - 1

	// Step 3 & 4: Skip to starting node.
	if sn == tn {
		// Step 3: "Until fn is sn, right-shift fn, sn, and tn equally."
		for fn != sn {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	} else {
		// Step 4: "Until fn is sn or LSB(sn) is not set, right-shift..."
		for fn != sn && sn&1 == 1 {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	}

	// Step 5 & 6: Initialize fr and sr.
	var fr, sr HashValue
	if fn == sn {
		fr = nodeHash
		sr = nodeHash
	} else {
		if len(proof) == 0 {
			return fmt.Errorf("%w: empty proof for non-root subtree", ErrInvalidProof)
		}
		copy(fr[:], proof[:HashSize])
		copy(sr[:], proof[:HashSize])
		proof = proof[HashSize:]
	}

	// Step 7: Process remaining proof elements.
	for len(proof) > 0 {
		if tn == 0 {
			return fmt.Errorf("%w: proof has too many elements", ErrInvalidProof)
		}
		var c HashValue
		copy(c[:], proof[:HashSize])
		proof = proof[HashSize:]

		if sn&1 == 1 || sn == tn {
			if fn < sn {
				fr = HashNode(&c, &fr)
			}
			sr = HashNode(&c, &sr)
			// "Until LSB(sn) is set, right-shift fn, sn, and tn equally."
			for sn&1 == 0 && sn != 0 {
				fn >>= 1
				sn >>= 1
				tn >>= 1
			}
		} else {
			sr = HashNode(&sr, &c)
		}
		fn >>= 1
		sn >>= 1
		tn >>= 1
	}

	// Step 8: Final checks.
	if tn != 0 {
		return fmt.Errorf("%w: proof has too few elements", ErrInvalidProof)
	}
	if fr != nodeHash {
		return fmt.Errorf("%w: reconstructed subtree hash does not match", ErrInvalidProof)
	}
	if sr != rootHash {
		return fmt.Errorf("%w: reconstructed root hash does not match", ErrInvalidProof)
	}
	return nil
}

// VerifyInclusionProof verifies a standard Merkle inclusion proof
// for entry at index in a tree of size treeSize with root rootHash.
func VerifyInclusionProof(proof []byte, index, treeSize int, entryHash, rootHash HashValue) error {
	return VerifySubtreeInclusionProof(proof, index, entryHash, rootHash, 0, treeSize)
}

// VerifyConsistencyProof verifies a standard Merkle consistency proof
// between a tree of size oldSize and a tree of size newSize.
func VerifyConsistencyProof(proof []byte, oldSize, newSize int, oldRoot, newRoot HashValue) error {
	return VerifySubtreeConsistencyProof(proof, 0, oldSize, newSize, oldRoot, newRoot)
}
