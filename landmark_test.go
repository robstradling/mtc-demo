package mtc

import (
	"testing"
)

func TestLandmarkSequence(t *testing.T) {
	baseID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(baseID, 5)

	// Landmark 0 always has tree size 0.
	ts, err := ls.TreeSize(0)
	if err != nil {
		t.Fatal(err)
	}
	if ts != 0 {
		t.Fatalf("landmark 0 tree size = %d, want 0", ts)
	}

	// Allocate some landmarks.
	if err := ls.AllocateLandmark(100); err != nil {
		t.Fatal(err)
	}
	if err := ls.AllocateLandmark(200); err != nil {
		t.Fatal(err)
	}
	if err := ls.AllocateLandmark(300); err != nil {
		t.Fatal(err)
	}

	if ls.Count() != 4 {
		t.Fatalf("Count = %d, want 4", ls.Count())
	}
	if ls.LastLandmark() != 3 {
		t.Fatalf("LastLandmark = %d, want 3", ls.LastLandmark())
	}

	// Cannot go backwards.
	if err := ls.AllocateLandmark(150); err == nil {
		t.Fatal("expected error for non-increasing tree size")
	}
}

func TestLandmarkSubtrees(t *testing.T) {
	baseID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(baseID, 5)
	ls.AllocateLandmark(100)
	ls.AllocateLandmark(200)

	// Landmark 1 subtrees cover [0, 100).
	left, right, single, err := ls.LandmarkSubtrees(1)
	if err != nil {
		t.Fatal(err)
	}
	if single {
		if left.End != 100 {
			t.Fatalf("expected end=100, got %d", left.End)
		}
	} else {
		if right.End != 100 {
			t.Fatalf("expected right.End=100, got %d", right.End)
		}
	}

	// Landmark 2 subtrees cover [100, 200).
	left2, right2, single2, err := ls.LandmarkSubtrees(2)
	if err != nil {
		t.Fatal(err)
	}
	if single2 {
		if left2.Start > 100 || left2.End != 200 {
			t.Fatalf("unexpected subtree [%d, %d)", left2.Start, left2.End)
		}
	} else {
		if left2.Start > 100 {
			t.Fatalf("left.Start %d > 100", left2.Start)
		}
		if right2.End != 200 {
			t.Fatalf("right.End = %d, want 200", right2.End)
		}
	}
}

func TestLandmarkActiveLandmarks(t *testing.T) {
	baseID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(baseID, 3)
	for i := 1; i <= 5; i++ {
		ls.AllocateLandmark(uint64(i * 100))
	}
	// 6 landmarks total (0-5). MaxActive=3, so active = [3, 4, 5].
	active := ls.ActiveLandmarks()
	if len(active) != 3 {
		t.Fatalf("active landmarks count = %d, want 3", len(active))
	}
	if active[0] != 3 || active[1] != 4 || active[2] != 5 {
		t.Fatalf("active = %v, want [3, 4, 5]", active)
	}
}

func TestLandmarkTrustAnchorID(t *testing.T) {
	baseID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(baseID, 5)
	ls.AllocateLandmark(100)

	id := ls.LandmarkTrustAnchorID(42)
	expected := id.String()
	if expected != "32473.1.42" {
		t.Fatalf("trust anchor ID = %q, want \"32473.1.42\"", expected)
	}
}

func TestLandmarkFindContaining(t *testing.T) {
	baseID, _ := ParseTrustAnchorID("32473.1")
	ls := NewLandmarkSequence(baseID, 10)
	ls.AllocateLandmark(100)
	ls.AllocateLandmark(200)
	ls.AllocateLandmark(300)

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
