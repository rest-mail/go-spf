package spf

import (
	"strings"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf/internal/dnstest"
	"github.com/rest-mail/go-spf/pkg/spf/internal/syntax"
)

// Macros (RFC 7208 §7).

// TestMacroEscapes checks the escapes: "%%" is "%", "%_" a space and "%-" a
// URL-encoded space.
//
// checklist: SPF-MACRO-01
func TestMacroEscapes(t *testing.T) {
	got := expandFor(t, zone(), "a%%b%_c%-d", "192.0.2.1", "a@example.com", "example.com", true)
	if got != "a%b c%20d" {
		t.Errorf("got %q", got)
	}
}

// TestMacroSyntaxErrors checks that a malformed macro is a syntax error, and
// so a permerror: "%" not followed by "{", "%", "_" or "-", an unterminated or
// empty macro, an unknown letter, a bad transformer or delimiter, and a zero
// digit transformer.
//
// checklist: SPF-MACRO-02 SPF-MACRO-06
func TestMacroSyntaxErrors(t *testing.T) {
	for _, spec := range []string{
		"%(ir).sbl.example.org",
		"%",
		"foo%",
		"%x.example.org",
		"%{d.example.org",
		"%{}.example.org",
		"%{x}.example.org",
		"%{d0}.example.org",
		"%{d00}.example.org",
		"%{d2x}.example.org",
		"%{dr2}.example.org",
		"%{d2r!}.example.org",
		"%{ d}.example.org",
	} {
		if _, err := syntax.CheckDomainSpec(spec); err == nil {
			t.Errorf("syntax.CheckDomainSpec(%q) = nil, want an error", spec)
		}
		z := zone("example.com TXT v=spf1 -exists:" + spec + " +all")
		want(t, spec, mailFrom(z, "192.0.2.1", "a@example.com"), ResultPermError)
	}
	if _, err := syntax.ParseMacroString("a b", false); err == nil {
		t.Error("a space is not a macro-literal outside explanations")
	}
	if _, err := syntax.ParseMacroString("%{d01}.%{d127}.%{d99999999999999999999}", false); err != nil {
		t.Errorf("leading zero and long digit transformers: %v", err)
	}
}

// TestMacroLetters checks the macro letters of a domain-spec: s, l, o, d, i,
// p, v and h.
//
// checklist: SPF-MACRO-03 SPF-MACRO-12
func TestMacroLetters(t *testing.T) {
	z := zone(
		"192.0.2.3 PTR mx.example.org",
		"mx.example.org A 192.0.2.3",
	)
	for spec, wantOut := range map[string]string{
		"%{s}": "strong-bad@email.example.com",
		"%{l}": "strong-bad",
		"%{o}": "email.example.com",
		"%{d}": "example.net",
		"%{i}": "192.0.2.3",
		"%{p}": "mx.example.org",
		"%{v}": "in-addr",
		"%{h}": "mail.example.net",
	} {
		if got := expandFor(t, z, spec, "192.0.2.3", "strong-bad@email.example.com", "example.net", false); got != wantOut {
			t.Errorf("%s = %q, want %q", spec, got, wantOut)
		}
	}
	if got := expandFor(t, z, "%{o}", "192.0.2.3", "a@example.com.", "example.com", false); got != "example.com" {
		t.Errorf("%%{o} of a sender with a trailing dot = %q", got)
	}
	if got := expandFor(t, z, "%{v}", "2001:db8::cb01", "a@example.com", "example.com", false); got != "ip6" {
		t.Errorf("IPv6 %%{v} = %q", got)
	}
	e := newEvaluator(t.Context(), mustAddr("192.0.2.3"), "example.com", "a@example.com", "", opts(z))
	toks, _ := syntax.ParseMacroString("%{h}", false)
	if got, _ := e.expand(toks, "example.com", true); got != "unknown" {
		t.Errorf("%%{h} without a HELO = %q, want unknown", got)
	}
}

// TestExpOnlyMacros checks that c, r and t are allowed only in explanation
// text: in a domain-spec they are a syntax error.
//
// checklist: SPF-MACRO-03
func TestExpOnlyMacros(t *testing.T) {
	for _, l := range []string{"c", "r", "t", "C", "R", "T"} {
		spec := "%{" + l + "}.example.org"
		if _, err := syntax.CheckDomainSpec(spec); err == nil {
			t.Errorf("%s accepted in a domain-spec", spec)
		}
		if _, err := syntax.ParseMacroString(spec, true); err != nil {
			t.Errorf("%s refused in an explanation: %v", spec, err)
		}
	}
}

// TestMacroTransformers checks the transformers: the value is split on the
// delimiters (dots by default), optionally reversed, cut to the right-hand
// parts, and joined with dots; empty parts are kept; and a digit count above
// the number of parts, 127 or more included, keeps them all.
//
// checklist: SPF-MACRO-04 SPF-MACRO-07
func TestMacroTransformers(t *testing.T) {
	sender := "first.last-name+tag@a.b.c.example.com"
	cases := map[string]string{
		"%{o}":       "a.b.c.example.com",
		"%{o2}":      "example.com",
		"%{or}":      "com.example.c.b.a",
		"%{o2r}":     "b.a",
		"%{l-}":      "first.last.name+tag",
		"%{l+}":      "first.last-name.tag",
		"%{l-+}":     "first.last.name.tag",
		"%{l1-+}":    "tag",
		"%{lr-+}":    "tag.name.first.last",
		"%{lR.}":     "last-name+tag.first",
		"%{o127}":    "a.b.c.example.com",
		"%{o9999}":   "a.b.c.example.com",
		"%{l,/_=}":   "first.last-name+tag",
		"%{d}":       "x..y.",
		"%{dr}":      ".y..x",
		"%{d2}":      "y.",
		"%{s=}":      "first.last-name+tag@a.b.c.example.com",
		"%{l1r}":     "first",
		"%{o1}.%{o}": "com.a.b.c.example.com",
	}
	for spec, wantOut := range cases {
		if got := expandFor(t, zone(), spec, "192.0.2.1", sender, "x..y.", false); got != wantOut {
			t.Errorf("%s = %q, want %q", spec, got, wantOut)
		}
	}
	labels := strings.Repeat("a.", 199) + "com"
	if got := expandFor(t, zone(), "%{d127}", "192.0.2.1", sender, labels, false); got != strings.Repeat("a.", 126)+"com" {
		t.Errorf("%%{d127} kept %d parts", strings.Count(got, ".")+1)
	}
}

// TestTrailingDots checks that a trailing dot is accepted: in a published
// domain-spec, in the domain being checked, and in names from DNS.
//
// checklist: SPF-MACRO-05
func TestTrailingDots(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a:host.example.org. mx:example.org. include:inc.example. -all",
		"host.example.org A 192.0.2.1",
		"example.org MX mail.example.org.",
		"mail.example.org A 192.0.2.2",
		"inc.example TXT v=spf1 ip4:192.0.2.3 -all",
	)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		want(t, ip, mailFrom(z, ip, "a@example.com."), ResultPass)
	}
}

// TestSenderMacrosAcrossRecursion checks that s, l and o keep the original
// sender inside include and redirect, while d follows the current domain.
//
// checklist: SPF-MACRO-08
func TestSenderMacrosAcrossRecursion(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 include:inc.example redirect=red.example",
		"inc.example TXT v=spf1 exists:%{l}.%{o}.%{d}.inc.check.test -all",
		"red.example TXT v=spf1 exists:%{s}.%{d}.red.check.test -all",
		"alice.example.com.inc.example.inc.check.test A 127.0.0.2",
		"bob@example.com.red.example.red.check.test A 127.0.0.2",
	)
	want(t, "include", mailFrom(z, "192.0.2.1", "alice@example.com"), ResultPass)
	want(t, "redirect", mailFrom(z, "192.0.2.1", "bob@example.com"), ResultPass)
	want(t, "neither", mailFrom(z, "192.0.2.1", "carol@example.com"), ResultFail)
}

// TestMacroIPForms checks the forms of the client address: %{i} is the
// dotted quad for IPv4 and the dotted nibbles for IPv6, and %{c} the
// conventional text form.
//
// checklist: SPF-MACRO-09
func TestMacroIPForms(t *testing.T) {
	cases := []struct{ ip, spec, want string }{
		{"192.0.2.3", "%{i}", "192.0.2.3"},
		{"192.0.2.3", "%{ir}", "3.2.0.192"},
		{"::ffff:192.0.2.3", "%{i}", "192.0.2.3"},
		{"2001:db8::cb01", "%{i}", "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"},
		{"2001:db8::cb01", "%{c}", "2001:db8::cb01"},
		{"192.0.2.3", "%{c}", "192.0.2.3"},
	}
	for _, c := range cases {
		if got := expandFor(t, zone(), c.spec, c.ip, "a@example.com", "example.com", true); got != c.want {
			t.Errorf("%s for %s = %q, want %q", c.spec, c.ip, got, c.want)
		}
	}
}

// TestMacroP checks %{p}: of the client's validated names it prefers the
// domain itself, then a subdomain of it, then any; with none, or on a DNS
// error, it is "unknown". The PTR lookup is made once per evaluation.
//
// checklist: SPF-MACRO-10
func TestMacroP(t *testing.T) {
	z := zone(
		"192.0.2.1 PTR other.example",
		"192.0.2.1 PTR mail.example.com",
		"192.0.2.1 PTR example.com",
		"192.0.2.1 PTR fake.example.com",
		"other.example A 192.0.2.1",
		"mail.example.com A 192.0.2.1",
		"example.com A 192.0.2.1",
		"fake.example.com A 198.51.100.1",
		"192.0.2.2 SERVFAIL PTR",
	)
	for domain, wantOut := range map[string]string{
		"example.com":      "example.com",
		"mail.example.com": "mail.example.com",
		"com":              "mail.example.com",
		"elsewhere.test":   "other.example",
	} {
		if got := expandFor(t, z, "%{p}", "192.0.2.1", "a@example.com", domain, false); got != wantOut {
			t.Errorf("%%{p} for %s = %q, want %q", domain, got, wantOut)
		}
	}
	if got := expandFor(t, z, "%{p}", "192.0.2.2", "a@example.com", "example.com", false); got != "unknown" {
		t.Errorf("%%{p} on a DNS error = %q", got)
	}
	if got := expandFor(t, z, "%{p}", "192.0.2.3", "a@example.com", "example.com", false); got != "unknown" {
		t.Errorf("%%{p} with no PTR = %q", got)
	}
	z.Queries = nil
	e := newEvaluator(t.Context(), mustAddr("192.0.2.1"), "example.com", "a@example.com", "", opts(z))
	toks, _ := syntax.ParseMacroString("%{p}.%{p}", false)
	if got, _ := e.expand(toks, "example.com", true); got != "example.com.example.com" || z.Count("PTR", "") != 1 || e.lookups != 1 {
		t.Errorf("%%{p}.%%{p} = %q with %d PTR queries and %d counted lookups", got, z.Count("PTR", ""), e.lookups)
	}

	// In a record, %{p} is charged against the DNS-query limit.
	var b strings.Builder
	for i := 0; i < 9; i++ {
		b.WriteString(" a:example.com")
	}
	z.TXT["p.example"] = []string{"v=spf1" + b.String() + " exists:%{p}.check.test -all"}
	want(t, "%{p} over the limit", mailFrom(z, "198.51.100.1", "a@p.example"), ResultPermError)
	z.TXT["p.example"] = []string{"v=spf1" + b.String() + " redirect=%{p}.example"}
	want(t, "%{p} in redirect over the limit", mailFrom(z, "198.51.100.1", "a@p.example"), ResultPermError)
	z.TXT["p.example"] = []string{"v=spf1 -all exp=e.example"}
	z.TXT["e.example"] = []string{"%{p}"}
	if got := mailFrom(z, "192.0.2.1", "a@p.example"); got.Explanation != "other.example" {
		t.Errorf("%%{p} in an explanation = %q", got.Explanation)
	}
}

// TestTargetTruncation checks that an expanded name longer than 253
// characters loses labels from the left until it fits, and that an expansion
// with no label boundary to cut at, or past the expansion bound, is
// malformed.
//
// checklist: SPF-MACRO-13
func TestTargetTruncation(t *testing.T) {
	long := strings.Repeat("abcdefghi.", 30) // 300 characters
	z := zone("example.com TXT v=spf1 exists:%{l}.check.test -all")
	tail := strings.Repeat("abcdefghi.", 24) + "check.test"
	z.Addr[dnstest.Canon(tail)] = append(z.Addr[dnstest.Canon(tail)], mustAddr("127.0.0.2"))
	want(t, "truncated", mailFrom(z, "192.0.2.1", strings.TrimSuffix(long, ".")+"@example.com"), ResultPass)
	if len(tail) > 253 || z.Count("A", dnstest.Canon(tail)) != 1 {
		t.Errorf("queries = %v, want one for %q (%d)", z.Queries, tail, len(tail))
	}

	e := newEvaluator(t.Context(), mustAddr("192.0.2.1"), "example.com", strings.Repeat("x", 300)+"@example.com", "", opts(z))
	toks, _ := syntax.ParseMacroString("%{l}", false)
	if _, ok, _ := e.target(toks, "example.com", true); ok {
		t.Error("a 300-character label was accepted")
	}
	toks, _ = syntax.ParseMacroString(strings.Repeat("%{s}", 100)+".example", false)
	if _, ok, _ := e.target(toks, "example.com", true); ok {
		t.Error("an expansion past maxExpansion was accepted")
	}
}

// TestMacroURLEscape checks that an uppercase macro is URL-escaped: every
// character outside the RFC 3986 unreserved set is percent-encoded.
//
// checklist: SPF-MACRO-14
func TestMacroURLEscape(t *testing.T) {
	sender := "a b+c/d~e_f-g.h%i@example.com"
	got := expandFor(t, zone(), "%{L}|%{S}|%{O}|%{Lr+}", "192.0.2.1", sender, "example.com", true)
	const out = "a%20b%2Bc%2Fd~e_f-g.h%25i|a%20b%2Bc%2Fd~e_f-g.h%25i%40example.com|example.com|c%2Fd~e_f-g.h%25i.a%20b"
	if got != out {
		t.Errorf("got\n%q\nwant\n%q", got, out)
	}
}

// TestHostileMacroInput checks that hostile sender and HELO values only ever
// reach DNS as bounded, visible-ASCII names, and that their expansion stays
// bounded.
//
// checklist: SPF-SEC-01
func TestHostileMacroInput(t *testing.T) {
	z := zone("example.com TXT v=spf1 exists:%{l}.%{h}.x.example a:%{l}.%{h}.y.example -all")
	for _, local := range []string{"a\x00b", "a b", "\xff\xfe", "a\r\nb", strings.Repeat("%", 300), "..", "-"} {
		got := CheckMailFrom(t.Context(), mustAddr("192.0.2.1"), local+"@example.com", local, opts(z))
		want(t, local, got, ResultFail)
	}
	for _, q := range z.Queries {
		name := strings.SplitN(q, " ", 2)[1]
		if !validDomain(name) {
			t.Errorf("queried %q", name)
		}
	}
}

// TestMacroExamples reproduces the expansion examples of RFC 7208 §7.4.
//
// checklist: SPF-MACRO-15
func TestMacroExamples(t *testing.T) {
	const sender = "strong-bad@email.example.com"
	z := zone(
		"192.0.2.3 PTR mx.example.org",
		"mx.example.org A 192.0.2.3",
	)
	v4 := map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}":   "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}":  "3.2.0.192.in-addr.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
	}
	for spec, out := range v4 {
		if got := expandFor(t, z, spec, "192.0.2.3", sender, "email.example.com", false); got != out {
			t.Errorf("%s = %q, want %q", spec, got, out)
		}
	}
	got := expandFor(t, z, "%{ir}.%{v}._spf.%{d2}", "2001:db8::cb01", sender, "email.example.com", false)
	const v6 = "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
	if got != v6 {
		t.Errorf("IPv6 example = %q, want %q", got, v6)
	}
}
