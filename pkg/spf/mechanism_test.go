package spf

import (
	"fmt"
	"testing"
)

// TestPTRNameLimit checks that only the first 10 PTR names are considered:
// a matching 11th name is ignored, by ptr and by %{p}.
//
// checklist: SPF-LIMIT-05
func TestPTRNameLimit(t *testing.T) {
	lines := []string{
		"example.com TXT v=spf1 ptr -all",
	}
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf("192.0.2.1 PTR h%d.other.example", i), fmt.Sprintf("h%d.other.example A 192.0.2.1", i))
	}
	lines = append(lines, "192.0.2.1 PTR mail.example.com", "mail.example.com A 192.0.2.1")
	z := zone(lines...)
	want(t, "11th name ignored", mailFrom(z, "192.0.2.1", "a@example.com"), ResultFail)
	if z.Count("A", "mail.example.com") != 0 {
		t.Error("the 11th PTR name was looked up")
	}
	if got := expandFor(t, z, "%{p}", "192.0.2.1", "a@example.com", "example.com", false); got != "h0.other.example" {
		t.Errorf("%%{p} = %q, want the first validated name", got)
	}
}
