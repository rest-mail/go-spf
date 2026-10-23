package spf

import (
	"context"
	"net/netip"
	"slices"
	"testing"
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
		want(t, sender, mailFrom(z, "192.0.2.1", sender), ResultPass)
		want(t, sender+" other client", mailFrom(z, "192.0.2.9", sender), ResultFail)
		if !slices.Contains(z.queries, "TXT xn--bcher-kva.example") {
			t.Errorf("%s: queries = %v, want the A-label record lookup", sender, z.queries)
		}
	}

	// A HELO name is converted the same way (the client MUST send A-labels,
	// but a U-label is still not checked as itself).
	z := zone("mail.xn--bcher-kva.example TXT v=spf1 +all")
	got := CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), "mail.bücher.example", opts(z))
	want(t, "U-label HELO", got, ResultPass)

	// A name that is not UTF-8 cannot be converted and stays malformed.
	z = zone()
	want(t, "invalid UTF-8", mailFrom(z, "192.0.2.1", "a@b\xffcher.example"), ResultNone)
	if len(z.queries) != 0 {
		t.Errorf("invalid UTF-8: queries = %v, want none", z.queries)
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
	got := CheckMailFrom(context.Background(), netip.MustParseAddr("192.0.2.1"), "a@bücher.example", "mail.bücher.example", opts(z))
	want(t, "%{d}.%{o}.%{h}", got, ResultPass)

	z = zone(
		"xn--bcher-kva.example TXT v=spf1 exists:%{s}.s.example -all",
		"a@xn--bcher-kva.example.s.example A 127.0.0.2",
	)
	want(t, "%{s}", mailFrom(z, "192.0.2.1", "a@bücher.example"), ResultPass)
}

// TestRFC8616LocalPart checks the RFC 8616 §4 note on %{s} and %{l}: a UTF-8
// local-part is left as it is, so the expanded name is not a valid domain,
// is not queried, and the term does not match.
//
// checklist: SPF-EAI-03
func TestRFC8616LocalPart(t *testing.T) {
	for _, spec := range []string{"%{l}.l.example", "%{s}.s.example"} {
		z := zone("xn--bcher-kva.example TXT v=spf1 exists:" + spec + " -all")
		want(t, spec, mailFrom(z, "192.0.2.1", "ñandú@bücher.example"), ResultFail)
		if len(z.queries) != 1 {
			t.Errorf("%s: queries = %v, want only the record lookup", spec, z.queries)
		}
	}
	z := zone()
	if got := expandFor(t, z, "%{l}", "192.0.2.1", "ñandú@xn--bcher-kva.example", "xn--bcher-kva.example", false); got != "ñandú" {
		t.Errorf("%%{l} = %q, want the local-part unchanged", got)
	}
}

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
		if got := toALabels(in); got != out {
			t.Errorf("toALabels(%q) = %q, want %q", in, got, out)
		}
	}
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
		want(t, name+" MAIL FROM", mailFrom(z, "192.0.2.1", "a@"+name), ResultNone)
		got := CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), name, opts(z))
		want(t, name+" HELO", got, ResultNone)
		if len(z.queries) != 0 {
			t.Errorf("%q: queries = %v, want none", name, z.queries)
		}
	}
	// A valid U-label beside them is still converted and checked.
	z := zone("xn--bcher-kva.example TXT v=spf1 ip4:192.0.2.1 -all")
	want(t, "valid U-label", mailFrom(z, "192.0.2.1", "a@bücher.example"), ResultPass)
}
