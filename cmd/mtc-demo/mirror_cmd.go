package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"mtc"
)

func cmdMirror(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: mtc-demo mirror <subcommand>

Subcommands:
  inclusion <index>                  Generate and verify an inclusion proof
  consistency <old-size> <old-root>  Verify consistency with a previous checkpoint
`)
		return nil
	}

	switch args[0] {
	case "inclusion":
		return cmdMirrorInclusion(args[1:])
	case "consistency":
		return cmdMirrorConsistency(args[1:])
	default:
		return fmt.Errorf("unknown mirror subcommand: %s", args[0])
	}
}

func cmdMirrorInclusion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mtc-demo mirror inclusion <index>")
	}
	index, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid index: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}

	if index < 0 || index >= log.Size() {
		return fmt.Errorf("index %d out of range (0..%d)", index, log.Size()-1)
	}

	entry, err := log.Entry(index)
	if err != nil {
		return err
	}
	entryHash := mtc.HashEntry(entry)

	checkpoint, err := log.CheckpointHash()
	if err != nil {
		return err
	}

	proof, err := log.Tree().InclusionProof(index)
	if err != nil {
		return fmt.Errorf("generating inclusion proof: %w", err)
	}

	err = mtc.VerifyInclusionProof(proof, index, log.Size(), entryHash, checkpoint)

	fmt.Printf("Inclusion proof for index %d:\n", index)
	fmt.Printf("  Tree size:    %d\n", log.Size())
	fmt.Printf("  Entry hash:   %s\n", hex.EncodeToString(entryHash[:]))
	fmt.Printf("  Root hash:    %s\n", hex.EncodeToString(checkpoint[:]))
	fmt.Printf("  Path length:  %d\n", len(proof)/mtc.HashSize)
	for i := 0; i < len(proof)/mtc.HashSize; i++ {
		var h mtc.HashValue
		copy(h[:], proof[i*mtc.HashSize:(i+1)*mtc.HashSize])
		fmt.Printf("    [%d] %s\n", i, hex.EncodeToString(h[:]))
	}
	if err != nil {
		fmt.Printf("  Verification: FAIL (%v)\n", err)
		return err
	}
	fmt.Printf("  Verification: OK\n")
	return nil
}

func cmdMirrorConsistency(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: mtc-demo mirror consistency <old-size> <old-root-hex>")
	}
	oldSize, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid old-size: %w", err)
	}
	oldRoot, err := parseHashValue(args[1])
	if err != nil {
		return fmt.Errorf("invalid old-root: %w", err)
	}

	s, err := requireState()
	if err != nil {
		return err
	}
	log, err := rebuildLog(s)
	if err != nil {
		return err
	}

	if oldSize < 1 || oldSize > log.Size() {
		return fmt.Errorf("old-size %d out of range (1..%d)", oldSize, log.Size())
	}

	newRoot, err := log.CheckpointHash()
	if err != nil {
		return err
	}

	proof, err := log.Tree().ConsistencyProof(oldSize)
	if err != nil {
		return fmt.Errorf("generating consistency proof: %w", err)
	}

	err = mtc.VerifyConsistencyProof(proof, oldSize, log.Size(), oldRoot, newRoot)

	fmt.Printf("Consistency proof:\n")
	fmt.Printf("  Old size: %d\n", oldSize)
	fmt.Printf("  Old root: %s\n", hex.EncodeToString(oldRoot[:]))
	fmt.Printf("  New size: %d\n", log.Size())
	fmt.Printf("  New root: %s\n", hex.EncodeToString(newRoot[:]))
	fmt.Printf("  Path:     %d hash elements\n", len(proof)/mtc.HashSize)
	if err != nil {
		fmt.Printf("  Verify:   FAIL (%v)\n", err)
		return err
	}
	fmt.Printf("  Verify:   OK\n")
	return nil
}
