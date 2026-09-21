package mtc

import (
	"fmt"
	"math"
)

// LandmarkSequence manages a sequence of landmarks as defined
// in Section 6.4.1. Landmarks are agreed-upon tree sizes for
// optimizing certificates. Each landmark consists of a landmark
// number, a tree size, and an expiration time.
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
	// expiries[i] is the expiration time (seconds since the Epoch) for
	// landmark i. expiries[0] is always 0.
	expiries []uint64
}

// NewLandmarkSequence creates a new landmark sequence with the given
// CA ID, log number, and maximum number of active landmarks. Landmark
// zero is automatically created with tree size 0 and expiry 0.
func NewLandmarkSequence(caID TrustAnchorID, logNumber uint16, maxActive int) *LandmarkSequence {
	return &LandmarkSequence{
		CAID:               caID,
		LogNumber:          logNumber,
		MaxActiveLandmarks: maxActive,
		landmarks:          []uint64{0},
		expiries:           []uint64{0},
	}
}

// AllocateLandmark appends a new landmark with the given tree size and
// expiration time (seconds since the Epoch). The tree size must be
// strictly greater than the previous landmark, and the expiry must be
// greater or equal to that of the previous landmark (Section 6.4.1).
func (ls *LandmarkSequence) AllocateLandmark(treeSize, expiry uint64) error {
	last := len(ls.landmarks) - 1
	if treeSize <= ls.landmarks[last] {
		return fmt.Errorf("tree size %d not greater than previous landmark %d", treeSize, ls.landmarks[last])
	}
	if expiry < ls.expiries[last] {
		return fmt.Errorf("expiry %d less than previous landmark expiry %d", expiry, ls.expiries[last])
	}
	ls.landmarks = append(ls.landmarks, treeSize)
	ls.expiries = append(ls.expiries, expiry)
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

// Expiry returns the expiration time (seconds since the Epoch) for the
// given landmark number.
func (ls *LandmarkSequence) Expiry(landmarkNum int) (uint64, error) {
	if landmarkNum < 0 || landmarkNum >= len(ls.expiries) {
		return 0, fmt.Errorf("landmark %d out of range [0, %d)", landmarkNum, len(ls.expiries))
	}
	return ls.expiries[landmarkNum], nil
}

// LastLandmark returns the number of the most recently allocated landmark.
func (ls *LandmarkSequence) LastLandmark() int {
	return len(ls.landmarks) - 1
}

// ActiveLandmarks returns the numbers of the currently active landmarks,
// given the current time (seconds since the Epoch). A landmark is active
// if it is not yet expired; landmark zero is never active (Section 6.4.1).
func (ls *LandmarkSequence) ActiveLandmarks(now uint64) []int {
	var result []int
	for i := 1; i < len(ls.landmarks); i++ {
		if ls.expiries[i] > now {
			result = append(result, i)
		}
	}
	return result
}

// LandmarkSubtrees returns the two subtrees determined by the given
// landmark number. Landmark 0 has empty subtrees. For other landmarks,
// the subtrees cover the interval [prevTreeSize, treeSize) (Section 6.4.1).
func (ls *LandmarkSequence) LandmarkSubtrees(landmarkNum int) (left, right Interval, err error) {
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

// FindContainingLandmark finds the lowest-numbered landmark whose tree
// size is strictly greater than the given entry index, and returns the
// landmark number and the unique subtree interval that contains the
// index (Section 6.4.4).
func (ls *LandmarkSequence) FindContainingLandmark(entryIndex int) (landmarkNum int, subtree Interval, err error) {
	for i := 1; i < len(ls.landmarks); i++ {
		if uint64(entryIndex) >= ls.landmarks[i] {
			continue
		}
		// Lowest landmark whose tree size is strictly greater than idx.
		left, right, err2 := ls.LandmarkSubtrees(i)
		if err2 != nil {
			err = err2
			return
		}
		if entryIndex >= left.Start && entryIndex < left.End {
			return i, left, nil
		}
		if entryIndex >= right.Start && entryIndex < right.End {
			return i, right, nil
		}
		return 0, Interval{}, fmt.Errorf("entry index %d not in landmark %d subtrees", entryIndex, i)
	}
	err = fmt.Errorf("no landmark contains entry index %d", entryIndex)
	return
}

// RecommendedMaxActiveLandmarks computes the recommended
// max_active_landmarks value given a maximum certificate lifetime
// and time between landmarks, as described in Section 6.4.2.
func RecommendedMaxActiveLandmarks(maxCertLifetimeHours, timeBetweenLandmarksHours float64) int {
	return int(math.Ceil(maxCertLifetimeHours/timeBetweenLandmarksHours)) + 1
}
