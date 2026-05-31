package mtc

import (
	"fmt"
	"math"
)

// LandmarkSequence manages a sequence of landmarks as defined
// in Section 6.3.1. Landmarks are agreed-upon tree sizes for
// optimizing certificates.
type LandmarkSequence struct {
	// CAID is the CA's trust anchor ID.
	CAID TrustAnchorID
	// LogNumber is the log number for this landmark sequence.
	LogNumber uint16
	// MaxActiveLandmarks is the maximum number of landmarks that may
	// contain unexpired certificates at any time.
	MaxActiveLandmarks int
	// landmarks[i] is the tree size for landmark i.
	// landmarks[0] is always 0.
	landmarks []uint64
}

// NewLandmarkSequence creates a new landmark sequence with the given
// CA ID, log number, and maximum number of active landmarks. Landmark
// zero is automatically created with tree size 0.
func NewLandmarkSequence(caID TrustAnchorID, logNumber uint16, maxActive int) *LandmarkSequence {
	return &LandmarkSequence{
		CAID:               caID,
		LogNumber:          logNumber,
		MaxActiveLandmarks: maxActive,
		landmarks:          []uint64{0},
	}
}

// AllocateLandmark appends a new landmark with the given tree size.
// The tree size must be strictly greater than the previous landmark.
func (ls *LandmarkSequence) AllocateLandmark(treeSize uint64) error {
	if len(ls.landmarks) > 0 && treeSize <= ls.landmarks[len(ls.landmarks)-1] {
		return fmt.Errorf("tree size %d not greater than previous landmark %d", treeSize, ls.landmarks[len(ls.landmarks)-1])
	}
	ls.landmarks = append(ls.landmarks, treeSize)
	return nil
}

// Count returns the total number of landmarks allocated (including landmark 0).
func (ls *LandmarkSequence) Count() int {
	return len(ls.landmarks)
}

// TreeSize returns the tree size for the given landmark number.
func (ls *LandmarkSequence) TreeSize(landmarkNum int) (uint64, error) {
	if landmarkNum < 0 || landmarkNum >= len(ls.landmarks) {
		return 0, fmt.Errorf("landmark %d out of range [0, %d)", landmarkNum, len(ls.landmarks))
	}
	return ls.landmarks[landmarkNum], nil
}

// LastLandmark returns the number of the most recently allocated landmark.
func (ls *LandmarkSequence) LastLandmark() int {
	return len(ls.landmarks) - 1
}

// ActiveLandmarks returns the indices of the currently active landmarks.
// Active landmarks are the most recent MaxActiveLandmarks landmarks.
func (ls *LandmarkSequence) ActiveLandmarks() []int {
	last := ls.LastLandmark()
	numActive := ls.MaxActiveLandmarks
	if numActive > last {
		numActive = last
	}
	result := make([]int, numActive)
	for i := range result {
		result[i] = last - numActive + 1 + i
	}
	return result
}

// LandmarkSubtrees returns the subtrees determined by the given landmark
// number. Landmark 0 has no subtrees. For other landmarks, the subtrees
// cover the interval [prevTreeSize, treeSize).
func (ls *LandmarkSequence) LandmarkSubtrees(landmarkNum int) (left, right Interval, single bool, err error) {
	if landmarkNum <= 0 || landmarkNum >= len(ls.landmarks) {
		err = fmt.Errorf("landmark %d has no subtrees", landmarkNum)
		return
	}
	prevSize := ls.landmarks[landmarkNum-1]
	curSize := ls.landmarks[landmarkNum]
	return FindSubtrees(int(prevSize), int(curSize))
}

// LandmarkTrustAnchorID returns the trust anchor ID for the given
// landmark number: {caID landmarks(1) N L} where N is the log number
// and L is the landmark number (Section 5.1).
func (ls *LandmarkSequence) LandmarkTrustAnchorID(landmarkNum int) TrustAnchorID {
	return ls.CAID.LandmarkID(ls.LogNumber, uint32(landmarkNum))
}

// FindContainingLandmark finds the first landmark whose subtrees
// contain the given entry index. Returns the landmark number and
// the specific subtree interval.
func (ls *LandmarkSequence) FindContainingLandmark(entryIndex int) (landmarkNum int, subtree Interval, err error) {
	for i := 1; i < len(ls.landmarks); i++ {
		prevSize := ls.landmarks[i-1]
		curSize := ls.landmarks[i]
		if uint64(entryIndex) < prevSize || uint64(entryIndex) >= curSize {
			continue
		}
		left, right, single, err2 := FindSubtrees(int(prevSize), int(curSize))
		if err2 != nil {
			err = err2
			return
		}
		if single {
			if entryIndex >= left.Start && entryIndex < left.End {
				return i, left, nil
			}
		} else {
			if entryIndex >= left.Start && entryIndex < left.End {
				return i, left, nil
			}
			if entryIndex >= right.Start && entryIndex < right.End {
				return i, right, nil
			}
		}
	}
	err = fmt.Errorf("no landmark contains entry index %d", entryIndex)
	return
}

// RecommendedMaxActiveLandmarks computes the recommended
// max_active_landmarks value given a maximum certificate lifetime
// and time between landmarks, as described in Section 6.3.2.
func RecommendedMaxActiveLandmarks(maxCertLifetimeHours, timeBetweenLandmarksHours float64) int {
	return int(math.Ceil(maxCertLifetimeHours/timeBetweenLandmarksHours)) + 1
}
