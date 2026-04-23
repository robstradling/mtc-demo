// Package mtc implements Merkle Tree Certificates as specified in
// draft-ietf-plants-merkle-tree-certs-03.
package mtc

import (
	"fmt"
	"strconv"
	"strings"
)

// TrustAnchorID is a trust anchor identifier as defined in
// draft-ietf-tls-trust-anchor-ids. It is encoded as a sequence of
// base-128 OID components.
type TrustAnchorID []byte

// ParseTrustAnchorID parses a dotted-decimal string like "32473.1"
// into a TrustAnchorID.
func ParseTrustAnchorID(s string) (TrustAnchorID, error) {
	var t TrustAnchorID
	for _, part := range strings.Split(s, ".") {
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid trust anchor ID component %q: %w", part, err)
		}
		t = appendBase128(t, uint32(v))
	}
	if len(t) == 0 {
		return nil, fmt.Errorf("empty trust anchor ID")
	}
	return t, nil
}

// String returns the dotted-decimal representation.
func (t TrustAnchorID) String() string {
	if len(t) == 0 {
		return fmt.Sprintf("<invalid: %x>", []byte(t))
	}
	var s strings.Builder
	rest := []byte(t)
	for len(rest) != 0 {
		v, r, ok := parseBase128(rest)
		if !ok {
			return fmt.Sprintf("<invalid: %x>", []byte(t))
		}
		if s.Len() != 0 {
			s.WriteByte('.')
		}
		fmt.Fprintf(&s, "%d", v)
		rest = r
	}
	return s.String()
}

// Equal reports whether t and other are the same trust anchor ID.
func (t TrustAnchorID) Equal(other TrustAnchorID) bool {
	if len(t) != len(other) {
		return false
	}
	for i := range t {
		if t[i] != other[i] {
			return false
		}
	}
	return true
}

func appendBase128(dst []byte, v uint32) []byte {
	var l int
	for n := v; n != 0; n >>= 7 {
		l++
	}
	if v == 0 {
		l = 1
	}
	for ; l > 0; l-- {
		b := byte(v>>uint(7*(l-1))) & 0x7f
		if l > 1 {
			b |= 0x80
		}
		dst = append(dst, b)
	}
	return dst
}

func parseBase128(in []byte) (ret uint32, rest []byte, ok bool) {
	rest = in
	if len(rest) == 0 {
		return
	}
	if rest[0] == 0x80 {
		return // Not minimally-encoded.
	}
	for {
		if len(rest) == 0 || (ret<<7)>>7 != ret {
			return
		}
		b := rest[0]
		ret <<= 7
		ret |= uint32(b & 0x7f)
		rest = rest[1:]
		if b&0x80 == 0 {
			ok = true
			return
		}
	}
}
