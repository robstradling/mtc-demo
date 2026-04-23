package mtc

import (
	"fmt"
)

// IssuanceLog represents a CA's issuance log (Section 5).
// It wraps a MerkleTree and manages entries.
type IssuanceLog struct {
	logID    TrustAnchorID
	entries  [][]byte // serialized MerkleTreeCertEntry values
	tree     *MerkleTree
	minIndex int // minimum available index (for pruning)
}

// NewIssuanceLog creates a new issuance log with the given log ID.
// It initializes the log with a null_entry at index 0 as required
// by Section 5.3.
func NewIssuanceLog(logID TrustAnchorID) *IssuanceLog {
	nullEntry := MarshalNullEntry()
	return &IssuanceLog{
		logID:   logID,
		entries: [][]byte{nullEntry},
		tree:    NewMerkleTree([][]byte{nullEntry}),
	}
}

// LogID returns the log's trust anchor ID.
func (l *IssuanceLog) LogID() TrustAnchorID {
	return l.logID
}

// Size returns the current number of entries in the log.
func (l *IssuanceLog) Size() int {
	return len(l.entries)
}

// MinIndex returns the minimum available index.
func (l *IssuanceLog) MinIndex() int {
	return l.minIndex
}

// AddEntry appends a serialized MerkleTreeCertEntry to the log
// and returns its index. The Merkle tree is rebuilt after each addition.
func (l *IssuanceLog) AddEntry(entry []byte) int {
	l.entries = append(l.entries, entry)
	l.tree = NewMerkleTree(l.entries)
	return len(l.entries) - 1
}

// AddTBSCertEntry adds a tbs_cert_entry to the log, given the
// DER-encoded contents of the TBSCertificateLogEntry.
func (l *IssuanceLog) AddTBSCertEntry(tbsCertLogEntryContents []byte) int {
	entry := MarshalTBSCertEntry(tbsCertLogEntryContents)
	return l.AddEntry(entry)
}

// Entry returns the serialized entry at the given index.
func (l *IssuanceLog) Entry(index int) ([]byte, error) {
	if index < l.minIndex || index >= len(l.entries) {
		return nil, fmt.Errorf("index %d not available (min=%d, size=%d)", index, l.minIndex, len(l.entries))
	}
	return l.entries[index], nil
}

// Tree returns the underlying Merkle tree.
func (l *IssuanceLog) Tree() *MerkleTree {
	return l.tree
}

// CheckpointHash returns the hash of the checkpoint at the current tree size.
func (l *IssuanceLog) CheckpointHash() (HashValue, error) {
	return l.tree.RootHash()
}

// Prune updates the minimum index. Entries before minIndex are
// no longer available, but their hashes are retained in the tree.
func (l *IssuanceLog) Prune(newMinIndex int) error {
	if newMinIndex < l.minIndex {
		return fmt.Errorf("cannot decrease minimum index from %d to %d", l.minIndex, newMinIndex)
	}
	if newMinIndex > len(l.entries) {
		return fmt.Errorf("minimum index %d exceeds log size %d", newMinIndex, len(l.entries))
	}
	l.minIndex = newMinIndex
	return nil
}

// SubtreeInclusionProof returns a subtree inclusion proof for
// entry at index within subtree [start, end).
func (l *IssuanceLog) SubtreeInclusionProof(index, start, end int) ([]byte, error) {
	return l.tree.SubtreeInclusionProof(index, start, end)
}

// SubtreeHash returns the hash of subtree [start, end).
func (l *IssuanceLog) SubtreeHash(start, end int) (HashValue, error) {
	return l.tree.SubtreeHash(start, end)
}

// SubtreeConsistencyProof returns a subtree consistency proof for
// subtree [start, end) against the full tree.
func (l *IssuanceLog) SubtreeConsistencyProof(start, end int) ([]byte, error) {
	return l.tree.SubtreeConsistencyProof(start, end)
}

// CoveringSubtrees returns the one or two subtrees that cover entries
// added between prevCheckpoint and the current tree size.
func (l *IssuanceLog) CoveringSubtrees(prevCheckpoint int) (left, right Interval, single bool, err error) {
	return FindSubtrees(prevCheckpoint, l.Size())
}
