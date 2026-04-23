package mtc

import (
	"testing"
)

func TestHashLeaf(t *testing.T) {
	data := []byte("test data")
	h := HashLeaf(data)
	if h == (HashValue{}) {
		t.Fatal("HashLeaf returned zero hash")
	}
	// Should be deterministic.
	h2 := HashLeaf(data)
	if h != h2 {
		t.Fatal("HashLeaf not deterministic")
	}
	// Different data should give different hashes.
	h3 := HashLeaf([]byte("other data"))
	if h == h3 {
		t.Fatal("different data gave same hash")
	}
}

func TestHashNode(t *testing.T) {
	left := HashLeaf([]byte("left"))
	right := HashLeaf([]byte("right"))
	h := HashNode(&left, &right)
	if h == (HashValue{}) {
		t.Fatal("HashNode returned zero hash")
	}
	// Order matters.
	h2 := HashNode(&right, &left)
	if h == h2 {
		t.Fatal("HashNode is commutative (should not be)")
	}
}
