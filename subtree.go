package mtc

import (
	"fmt"
	"math/bits"
)

// IsValidSubtree checks whether [start, end) defines a valid subtree
// as specified in Section 4.1:
//   - 0 <= start < end
//   - start is a multiple of BIT_CEIL(end - start)
func IsValidSubtree(start, end int) bool {
	if start < 0 || start >= end {
		return false
	}
	size := end - start
	ceil := bitCeil(uint(size))
	return uint(start)&(ceil-1) == 0
}

// bitCeil returns the smallest power of two >= n.
func bitCeil(n uint) uint {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(n-1)
}

// FindSubtrees returns one or two subtrees that efficiently cover
// the interval [start, end), as described in Section 4.5.
//
// Returns (left, right, singleSubtree):
//   - If singleSubtree is true, left covers the entire interval and right is zero-valued.
//   - Otherwise, both left and right cover the interval, with left.End == right.Start.
func FindSubtrees(start, end int) (left, right Interval, single bool, err error) {
	if start < 0 || start >= end {
		err = fmt.Errorf("invalid interval [%d, %d)", start, end)
		return
	}
	if end-start == 1 {
		left = Interval{Start: start, End: end}
		single = true
		return
	}
	last := end - 1
	split := bits.Len(uint(start^last)) - 1
	mask := (1 << split) - 1
	mid := last & ^mask
	leftSplit := bits.Len(uint(^start & mask))
	leftStart := start & ^((1 << leftSplit) - 1)
	left = Interval{Start: leftStart, End: mid}
	right = Interval{Start: mid, End: end}
	return
}

// Interval represents a half-open interval [Start, End).
type Interval struct {
	Start, End int
}

// Size returns the number of elements in the interval.
func (i Interval) Size() int {
	return i.End - i.Start
}

// IsValid reports whether the interval defines a valid subtree.
func (i Interval) IsValid() bool {
	return IsValidSubtree(i.Start, i.End)
}
