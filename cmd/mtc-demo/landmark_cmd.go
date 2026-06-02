package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"mtc"
)

func cmdLandmark(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo landmark <subcommand>

Subcommands:
  init <max-active>    Initialize landmark sequence
  allocate             Allocate a new landmark at current tree size
  info                 Show landmark sequence info
  find <index>         Find which landmark covers an entry index
`)
		return nil
	}

	switch args[0] {
	case "init":
		return cmdLandmarkInit(args[1:])
	case "allocate":
		return cmdLandmarkAllocate()
	case "info":
		return cmdLandmarkInfo()
	case "find":
		return cmdLandmarkFind(args[1:])
	default:
		return fmt.Errorf("unknown landmark subcommand: %s", args[0])
	}
}

func cmdLandmarkInit(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo landmark init <max-active>")
	}
	maxActive, err := strconv.Atoi(args[0])
	if err != nil || maxActive < 1 {
		return fmt.Errorf("max-active must be a positive integer")
	}

	s, err := requireState()
	if err != nil {
		return err
	}

	if s.Landmarks != nil {
		return fmt.Errorf("landmarks already initialized")
	}

	s.Landmarks = &LandmarkConfig{
		MaxActive: maxActive,
		TreeSizes: []uint64{0}, // landmark 0
	}
	if err := saveState(s); err != nil {
		return err
	}

	fmt.Printf("Landmark sequence initialized:\n")
	fmt.Printf("  Max active: %d\n", maxActive)
	fmt.Printf("  Recommended for 7-day certs with 1-hour intervals: %d\n",
		mtc.RecommendedMaxActiveLandmarks(168, 1))
	return nil
}

func cmdLandmarkAllocate() error {
	s, err := requireState()
	if err != nil {
		return err
	}

	log, err := rebuildLog(s)
	if err != nil {
		return err
	}
	ls, err := rebuildLandmarks(s)
	if err != nil {
		return err
	}

	treeSize := uint64(log.Size())
	if err := ls.AllocateLandmark(treeSize); err != nil {
		return err
	}

	s.Landmarks.TreeSizes = append(s.Landmarks.TreeSizes, treeSize)
	if err := saveState(s); err != nil {
		return err
	}

	landmarkNum := ls.LastLandmark()
	fmt.Printf("Landmark allocated:\n")
	fmt.Printf("  Landmark #:    %d\n", landmarkNum)
	fmt.Printf("  Tree size:     %d\n", treeSize)
	fmt.Printf("  Trust anchor:  %s\n", ls.LandmarkTrustAnchorID(landmarkNum))

	// Show subtrees for this landmark.
	left, right, single, err := ls.LandmarkSubtrees(landmarkNum)
	if err != nil {
		return err
	}
	fmt.Printf("  Subtrees:\n")
	printSubtreeHash(log, left)
	if !single {
		printSubtreeHash(log, right)
	}

	return nil
}

func printSubtreeHash(log *mtc.IssuanceLog, st mtc.Interval) {
	h, err := log.SubtreeHash(st.Start, st.End)
	if err != nil {
		fmt.Printf("    [%d, %d): error: %v\n", st.Start, st.End, err)
		return
	}
	fmt.Printf("    [%d, %d): %s\n", st.Start, st.End, hex.EncodeToString(h[:]))
}

func cmdLandmarkInfo() error {
	s, err := requireState()
	if err != nil {
		return err
	}
	ls, err := rebuildLandmarks(s)
	if err != nil {
		return err
	}

	fmt.Printf("Landmark sequence:\n")
	fmt.Printf("  Total landmarks: %d\n", ls.Count())
	fmt.Printf("  Last landmark:   %d\n", ls.LastLandmark())
	fmt.Printf("  Max active:      %d\n", s.Landmarks.MaxActive)

	active := ls.ActiveLandmarks()
	if len(active) > 0 {
		fmt.Printf("  Active landmarks: %v\n", active)
	}

	fmt.Printf("\n  %-8s  %-12s  %s\n", "LANDMARK", "TREE SIZE", "TRUST ANCHOR ID")
	for i := 0; i < ls.Count(); i++ {
		ts, _ := ls.TreeSize(i)
		activeStr := ""
		for _, a := range active {
			if a == i {
				activeStr = " (active)"
				break
			}
		}
		fmt.Printf("  %-8d  %-12d  %s%s\n", i, ts, ls.LandmarkTrustAnchorID(i), activeStr)
	}

	return nil
}

func cmdLandmarkFind(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo landmark find <entry-index>")
	}
	index, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid index: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	ls, err := rebuildLandmarks(s)
	if err != nil {
		return err
	}

	landmarkNum, subtree, err := ls.FindContainingLandmark(index)
	if err != nil {
		return fmt.Errorf("no landmark covers index %d: %w", index, err)
	}

	ts, _ := ls.TreeSize(landmarkNum)
	fmt.Printf("Entry %d is covered by:\n", index)
	fmt.Printf("  Landmark #:     %d\n", landmarkNum)
	fmt.Printf("  Tree size:      %d\n", ts)
	fmt.Printf("  Trust anchor:   %s\n", ls.LandmarkTrustAnchorID(landmarkNum))
	fmt.Printf("  Subtree:        [%d, %d)\n", subtree.Start, subtree.End)

	return nil
}
