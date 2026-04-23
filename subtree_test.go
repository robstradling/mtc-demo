package mtc

import (
	"testing"
)

func TestIsValidSubtree(t *testing.T) {
	tests := []struct {
		start, end int
		valid      bool
	}{
		{0, 1, true},
		{0, 8, true},
		{4, 8, true},
		{8, 13, true},
		{8, 12, true},
		{0, 13, true},
		// Invalid: start not a multiple of BIT_CEIL(size).
		{3, 7, false},
		{5, 8, false},
		{1, 3, false},
		// Invalid: start >= end.
		{5, 5, false},
		{5, 3, false},
		// Invalid: negative.
		{-1, 5, false},
	}
	for _, tc := range tests {
		got := IsValidSubtree(tc.start, tc.end)
		if got != tc.valid {
			t.Errorf("IsValidSubtree(%d, %d) = %v, want %v", tc.start, tc.end, got, tc.valid)
		}
	}
}

func TestFindSubtrees(t *testing.T) {
	tests := []struct {
		start, end int
		// Expected coverage.
		leftStart, leftEnd, rightStart, rightEnd int
		single                                   bool
	}{
		// Single entry.
		{5, 6, 5, 6, 0, 0, true},
		// [5, 13) should give [4, 8) and [8, 13).
		{5, 13, 4, 8, 8, 13, false},
		// [7, 9) should give [7, 8) and [8, 9).
		{7, 9, 7, 8, 8, 9, false},
		// [0, 8) returns two subtrees per the spec.
		{0, 8, 0, 4, 4, 8, false},
	}
	for _, tc := range tests {
		left, right, single, err := FindSubtrees(tc.start, tc.end)
		if err != nil {
			t.Fatalf("FindSubtrees(%d, %d) error: %v", tc.start, tc.end, err)
		}
		if single != tc.single {
			t.Fatalf("FindSubtrees(%d, %d) single=%v, want %v", tc.start, tc.end, single, tc.single)
		}
		if left.Start != tc.leftStart || left.End != tc.leftEnd {
			t.Fatalf("FindSubtrees(%d, %d) left=[%d, %d), want [%d, %d)",
				tc.start, tc.end, left.Start, left.End, tc.leftStart, tc.leftEnd)
		}
		if !single {
			if right.Start != tc.rightStart || right.End != tc.rightEnd {
				t.Fatalf("FindSubtrees(%d, %d) right=[%d, %d), want [%d, %d)",
					tc.start, tc.end, right.Start, right.End, tc.rightStart, tc.rightEnd)
			}
			// Verify properties from the spec.
			if left.End != right.Start {
				t.Fatalf("left.End (%d) != right.Start (%d)", left.End, right.Start)
			}
			if left.Start > tc.start {
				t.Fatalf("left.Start (%d) > start (%d)", left.Start, tc.start)
			}
			if right.End != tc.end {
				t.Fatalf("right.End (%d) != end (%d)", right.End, tc.end)
			}
		}
		// All results should be valid subtrees.
		if !left.IsValid() {
			t.Fatalf("left subtree [%d, %d) is not valid", left.Start, left.End)
		}
		if !single && !right.IsValid() {
			t.Fatalf("right subtree [%d, %d) is not valid", right.Start, right.End)
		}
	}
}

func TestFindSubtreesInvalid(t *testing.T) {
	_, _, _, err := FindSubtrees(5, 5)
	if err == nil {
		t.Fatal("expected error for start == end")
	}
	_, _, _, err = FindSubtrees(5, 3)
	if err == nil {
		t.Fatal("expected error for start > end")
	}
}
