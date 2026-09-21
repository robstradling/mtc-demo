package mtc

import (
	"testing"
)

// farFuture is an expiration time well beyond any test's notion of "now".
const farFuture = uint64(1 << 40)

func TestLandmarkSequence(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(caID, 1, 5)

	// Landmark 0 always has tree size 0.
	ts, err := ls.TreeSize(0)
	if err != nil {
		t.Fatal(err)
	}
	if ts != 0 {
		t.Fatalf("landmark 0 tree size = %d, want 0", ts)
	}

	// Allocate some landmarks.
	if err := ls.AllocateLandmark(100, farFuture); err != nil {
		t.Fatal(err)
	}
	if err := ls.AllocateLandmark(200, farFuture); err != nil {
		t.Fatal(err)
	}
	if err := ls.AllocateLandmark(300, farFuture); err != nil {
		t.Fatal(err)
	}

	if ls.Count() != 4 {
		t.Fatalf("Count = %d, want 4", ls.Count())
	}
	if ls.LastLandmark() != 3 {
		t.Fatalf("LastLandmark = %d, want 3", ls.LastLandmark())
	}

	// Cannot go backwards in tree size.
	if err := ls.AllocateLandmark(150, farFuture); err == nil {
		t.Fatal("expected error for non-increasing tree size")
	}

	// Expiry must be monotonically non-decreasing.
	if err := ls.AllocateLandmark(400, farFuture-1); err == nil {
		t.Fatal("expected error for decreasing expiry")
	}
}

func TestLandmarkSubtrees(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(caID, 1, 5)
	ls.AllocateLandmark(100, farFuture)
	ls.AllocateLandmark(200, farFuture)

	// Landmark 1 subtrees cover [0, 100).
	_, right, err := ls.LandmarkSubtrees(1)
	if err != nil {
		t.Fatal(err)
	}
	if right.End != 100 {
		t.Fatalf("expected right.End=100, got %d", right.End)
	}

	// Landmark 2 subtrees cover [100, 200).
	left2, right2, err := ls.LandmarkSubtrees(2)
	if err != nil {
		t.Fatal(err)
	}
	if left2.Start > 100 {
		t.Fatalf("left.Start %d > 100", left2.Start)
	}
	if right2.End != 200 {
		t.Fatalf("right.End = %d, want 200", right2.End)
	}
}

func TestLandmarkActiveLandmarks(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(caID, 1, 3)
	// Landmarks 1-3 expire at 100, 4-5 expire far in the future.
	ls.AllocateLandmark(100, 100)
	ls.AllocateLandmark(200, 100)
	ls.AllocateLandmark(300, 100)
	ls.AllocateLandmark(400, farFuture)
	ls.AllocateLandmark(500, farFuture)

	// At time 150, landmarks 1-3 are expired; 4 and 5 are active.
	active := ls.ActiveLandmarks(150)
	if len(active) != 2 {
		t.Fatalf("active landmarks count = %d, want 2", len(active))
	}
	if active[0] != 4 || active[1] != 5 {
		t.Fatalf("active = %v, want [4, 5]", active)
	}

	// At time 50, all landmarks are active.
	if got := ls.ActiveLandmarks(50); len(got) != 5 {
		t.Fatalf("active landmarks at t=50 = %d, want 5", len(got))
	}
}

func TestLandmarkTrustAnchorID(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(caID, 1, 5)
	ls.AllocateLandmark(100, farFuture)

	// Landmark ID = {caID landmarks(1) N L} = 32473.1.1.1.42
	id := ls.LandmarkTrustAnchorID(42)
	expected := id.String()
	if expected != "32473.1.1.1.42" {
		t.Fatalf("trust anchor ID = %q, want \"32473.1.1.1.42\"", expected)
	}
}

func TestLandmarkFindContaining(t *testing.T) {
	caID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(caID, 1, 10)
	ls.AllocateLandmark(100, farFuture)
	ls.AllocateLandmark(200, farFuture)
	ls.AllocateLandmark(300, farFuture)

	num, subtree, err := ls.FindContainingLandmark(150)
	if err != nil {
		t.Fatal(err)
	}
	if num != 2 {
		t.Fatalf("landmark = %d, want 2", num)
	}
	if 150 < subtree.Start || 150 >= subtree.End {
		t.Fatalf("entry 150 not in subtree [%d, %d)", subtree.Start, subtree.End)
	}
}

func TestRecommendedMaxActiveLandmarks(t *testing.T) {
	// 7 days * 24h = 168h lifetime, 1h between landmarks.
	// ceil(168/1) + 1 = 169.
	result := RecommendedMaxActiveLandmarks(168, 1)
	if result != 169 {
		t.Fatalf("recommended = %d, want 169", result)
	}
}
