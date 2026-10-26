package idna

import (
	"testing"
)

// TestToALabels checks the punycode conversion against RFC 3492 §7.1 and
// IDNA examples.
//
// checklist: SPF-EAI-01
func TestToALabels(t *testing.T) {
	for in, out := range map[string]string{
		"bücher.example":        "xn--bcher-kva.example",
		"BÜCHER.Example":        "xn--bcher-kva.Example",
		"münchen.de":            "xn--mnchen-3ya.de",
		"例え.テスト":                "xn--r8jz45g.xn--zckzah",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"example.com":           "example.com",
		"b\xffcher.example":     "b\xffcher.example",
		// Refused U-labels leave the name as it is (TestRFC8616InvalidULabels).
		"a\u200db.example": "a\u200db.example",
		"-bücher.example":  "-bücher.example",
	} {
		if got := ToALabels(in); got != out {
			t.Errorf("ToALabels(%q) = %q, want %q", in, got, out)
		}
	}
}
