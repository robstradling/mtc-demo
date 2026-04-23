package mtc

import (
	"testing"
)

func TestMTCProofRoundtrip(t *testing.T) {
	cosignerID, _ := ParseTrustAnchorID("32473.1.1")
	p := &MTCProof{
		Start: 4,
		End:   8,
		InclusionProof: []byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		},
		Signatures: []MTCSignature{
			{
				CosignerID: cosignerID,
				Signature:  []byte{0xaa, 0xbb, 0xcc},
			},
		},
	}

	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	p2, err := UnmarshalMTCProof(data)
	if err != nil {
		t.Fatal(err)
	}

	if p2.Start != p.Start || p2.End != p.End {
		t.Fatalf("start/end mismatch: got %d/%d, want %d/%d", p2.Start, p2.End, p.Start, p.End)
	}
	if len(p2.InclusionProof) != len(p.InclusionProof) {
		t.Fatal("inclusion proof length mismatch")
	}
	if len(p2.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(p2.Signatures))
	}
	if !p2.Signatures[0].CosignerID.Equal(cosignerID) {
		t.Fatal("cosigner ID mismatch")
	}
}
