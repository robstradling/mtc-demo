package mtc

import (
	"crypto/sha256"
)

// HashSize is the size of the hash output in bytes (SHA-256).
const HashSize = sha256.Size

// HashValue is a fixed-size hash output.
type HashValue = [HashSize]byte

// HashLeaf computes MTH({d}) = HASH(0x00 || d) as defined in
// Section 2.1.1 of RFC 9162.
func HashLeaf(data []byte) HashValue {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var ret HashValue
	h.Sum(ret[:0])
	return ret
}

// HashNode computes HASH(0x01 || left || right) as defined in
// Section 2.1.1 of RFC 9162.
func HashNode(left, right *HashValue) HashValue {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var ret HashValue
	h.Sum(ret[:0])
	return ret
}
