package spf

import (
	"testing"
)

// TestRFC8616LocalPart checks the RFC 8616 §4 note on %{s} and %{l}: a UTF-8
// local-part is left as it is, so the expanded name is not a valid domain,
// is not queried, and the term does not match.
//
// checklist: SPF-EAI-03
func TestRFC8616LocalPart(t *testing.T) {
	for _, spec := range []string{"%{l}.l.example", "%{s}.s.example"} {
		z := zone("xn--bcher-kva.example TXT v=spf1 exists:" + spec + " -all")
		want(t, spec, mailFrom(z, "192.0.2.1", "ñandú@bücher.example"), ResultFail)
		if len(z.Queries) != 1 {
			t.Errorf("%s: queries = %v, want only the record lookup", spec, z.Queries)
		}
	}
	z := zone()
	if got := expandFor(t, z, "%{l}", "192.0.2.1", "ñandú@xn--bcher-kva.example", "xn--bcher-kva.example", false); got != "ñandú" {
		t.Errorf("%%{l} = %q, want the local-part unchanged", got)
	}
}
