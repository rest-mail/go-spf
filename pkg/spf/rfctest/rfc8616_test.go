package rfctest

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
)

// TestRFC8616ULabels checks RFC 8616 §4: U-labels in the MAIL FROM domain
// become A-labels before the record lookup, in any letter case, and an
// existing A-label is used as it is.
//
// checklist: SPF-EAI-01
func TestRFC8616ULabels(t *testing.T) {
	for _, sender := range []string{
		"a@bücher.example",
		"<a@bücher.example>",
		"a@BÜCHER.example",
		"a@bücher.example.",
		"a@xn--bcher-kva.example",
		"ñandú@bücher.example",
	} {
		z := zone("xn--bcher-kva.example TXT v=spf1 ip4:192.0.2.1 -all")
		want(t, sender, mailFrom(z, "192.0.2.1", sender), spf.ResultPass)
		want(t, sender+" other client", mailFrom(z, "192.0.2.9", sender), spf.ResultFail)
		if !slices.Contains(z.Queries, "TXT xn--bcher-kva.example") {
			t.Errorf("%s: queries = %v, want the A-label record lookup", sender, z.Queries)
		}
	}

	// A HELO name is converted the same way (the client MUST send A-labels,
	// but a U-label is still not checked as itself).
	z := zone("mail.xn--bcher-kva.example TXT v=spf1 +all")
	got := spf.CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), "mail.bücher.example", opts(z))
	want(t, "U-label HELO", got, spf.ResultPass)

	// A name that is not UTF-8 cannot be converted and stays malformed.
	z = zone()
	want(t, "invalid UTF-8", mailFrom(z, "192.0.2.1", "a@b\xffcher.example"), spf.ResultNone)
	if len(z.Queries) != 0 {
		t.Errorf("invalid UTF-8: queries = %v, want none", z.Queries)
	}
}

// TestRFC8616MacroALabels checks RFC 8616 §4: the domain names that macros
// expand (%{d}, %{o}, the domain of %{s}, %{h}) carry A-labels, so a
// domain-spec built from them names the A-label host.
//
// checklist: SPF-EAI-02
func TestRFC8616MacroALabels(t *testing.T) {
	z := zone(
		"xn--bcher-kva.example TXT v=spf1 exists:%{d}.%{o}.%{h}.d.example -all",
		"xn--bcher-kva.example.xn--bcher-kva.example.mail.xn--bcher-kva.example.d.example A 127.0.0.2",
	)
	got := spf.CheckMailFrom(context.Background(), netip.MustParseAddr("192.0.2.1"), "a@bücher.example", "mail.bücher.example", opts(z))
	want(t, "%{d}.%{o}.%{h}", got, spf.ResultPass)

	z = zone(
		"xn--bcher-kva.example TXT v=spf1 exists:%{s}.s.example -all",
		"a@xn--bcher-kva.example.s.example A 127.0.0.2",
	)
	want(t, "%{s}", mailFrom(z, "192.0.2.1", "a@bücher.example"), spf.ResultPass)
}

// TestRFC8616InvalidULabels checks that a U-label IDNA2008 cannot allow is not
// converted: the name stays malformed, the result is none, and nothing is
// looked up, for the MAIL FROM domain and the HELO name alike.
//
// checklist: SPF-EAI-01
func TestRFC8616InvalidULabels(t *testing.T) {
	for _, name := range []string{
		"a\u200db.example",     // ZERO WIDTH JOINER, no virama before it
		"a\u200cb.example",     // ZERO WIDTH NON-JOINER
		"\u0301bcher.example",  // the label begins with a combining mark
		"bü\u202echer.example", // RIGHT-TO-LEFT OVERRIDE, a format character
		"bü cher.example",      // a space
		"bü\u3000cher.example", // IDEOGRAPHIC SPACE
		"-bücher.example",      // leading hyphen
		"bücher-.example",      // trailing hyphen
		"bü--cher.example",     // "--" in the third and fourth positions
		"bücher..example",      // an empty label
	} {
		z := zone()
		want(t, name+" MAIL FROM", mailFrom(z, "192.0.2.1", "a@"+name), spf.ResultNone)
		got := spf.CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), name, opts(z))
		want(t, name+" HELO", got, spf.ResultNone)
		if len(z.Queries) != 0 {
			t.Errorf("%q: queries = %v, want none", name, z.Queries)
		}
	}
	// A valid U-label beside them is still converted and checked.
	z := zone("xn--bcher-kva.example TXT v=spf1 ip4:192.0.2.1 -all")
	want(t, "valid U-label", mailFrom(z, "192.0.2.1", "a@bücher.example"), spf.ResultPass)
}
