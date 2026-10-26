package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// TestExplanationLength checks that a long explanation is cut to a length
// that fits an SMTP reply line.
//
// checklist: SPF-MOD-08
func TestExplanationLength(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 -all exp=explain.example",
		"explain.example TXT "+strings.Repeat("%{s} ", 100),
	)
	got := mailFrom(z, "192.0.2.1", "someone@example.com")
	if len(got.Explanation) != maxExplanation {
		t.Errorf("len(Explanation) = %d, want %d", len(got.Explanation), maxExplanation)
	}
}

// TestResponseTextIsPrintable checks that Reason, which may quote names from
// the sender or from DNS, is printable US-ASCII, so it is safe in a header
// field.
//
// checklist: SPF-HDR-04
func TestResponseTextIsPrintable(t *testing.T) {
	z := zone()
	got := CheckHost(context.Background(), netip.MustParseAddr("192.0.2.1"), "bad\r\nX-Evil: 1", "a@bad", "", opts(z))
	for i := 0; i < len(got.Reason); i++ {
		if got.Reason[i] < 0x20 || got.Reason[i] > 0x7e {
			t.Fatalf("Reason %q holds byte %#x", got.Reason, got.Reason[i])
		}
	}
	if printable("ok") != "ok" || printable("a\x00\xffb") != "a??b" {
		t.Error("printable")
	}
}
