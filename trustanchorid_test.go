package mtc

import (
	"testing"
)

func TestTrustAnchorIDRoundtrip(t *testing.T) {
	tests := []string{
		"32473.1",
		"1.2.3.4.5",
		"0",
		"32473.1.42",
	}
	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			id, err := ParseTrustAnchorID(s)
			if err != nil {
				t.Fatalf("ParseTrustAnchorID(%q) failed: %v", s, err)
			}
			got := id.String()
			if got != s {
				t.Fatalf("roundtrip: got %q, want %q", got, s)
			}
		})
	}
}

func TestTrustAnchorIDEqual(t *testing.T) {
	a, _ := ParseTrustAnchorID("32473.1")
	b, _ := ParseTrustAnchorID("32473.1")
	c, _ := ParseTrustAnchorID("32473.2")

	if !a.Equal(b) {
		t.Fatal("equal IDs should be equal")
	}
	if a.Equal(c) {
		t.Fatal("different IDs should not be equal")
	}
}

func TestTrustAnchorIDInvalid(t *testing.T) {
	_, err := ParseTrustAnchorID("abc")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
	_, err = ParseTrustAnchorID("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
