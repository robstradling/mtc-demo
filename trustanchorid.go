// Package mtc implements Merkle Tree Certificates as specified in
// draft-ietf-plants-merkle-tree-certs-05.
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
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid trust anchor ID component %q: %w", part, err)
		}
		t = appendBase128(t, v)
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

func appendBase128(dst []byte, v uint64) []byte {
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

func parseBase128(in []byte) (ret uint64, rest []byte, ok bool) {
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
		ret |= uint64(b & 0x7f)
		rest = rest[1:]
		if b&0x80 == 0 {
			ok = true
			return
		}
	}
}

// OIDName returns the cosigner_name/log_origin format used in
// CosignedMessage (Section 5.3.1): "oid/1.3.6.1.4.1." + ASCII representation.
func (t TrustAnchorID) OIDName() string {
	return "oid/1.3.6.1.4.1." + t.String()
}

// LogID constructs the log ID for a given CA ID and log number.
// Log ID = {caID logs(0) N} where N is the log number (Section 5.2).
func (t TrustAnchorID) LogID(logNumber uint16) TrustAnchorID {
	id := make(TrustAnchorID, len(t))
	copy(id, t)
	id = appendBase128(id, 0)
	id = appendBase128(id, uint64(logNumber))
	return id
}

// LandmarkID constructs the landmark trust anchor ID for a given
// CA ID, log number, and landmark number.
// Landmark ID = {caID landmarks(1) N L} (Section 5.1).
func (t TrustAnchorID) LandmarkID(logNumber uint16, landmarkNum uint32) TrustAnchorID {
	id := make(TrustAnchorID, len(t))
	copy(id, t)
	id = appendBase128(id, 1)
	id = appendBase128(id, uint64(logNumber))
	id = appendBase128(id, uint64(landmarkNum))
	return id
}
