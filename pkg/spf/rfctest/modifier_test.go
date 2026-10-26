package rfctest

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
)

// Modifiers (RFC 7208 §6): redirect and exp.

// TestDuplicateModifiers checks that a record with redirect or exp more than
// once gives permerror, whatever their case.
//
// checklist: SPF-MOD-01
func TestDuplicateModifiers(t *testing.T) {
	for _, rec := range []string{
		"v=spf1 redirect=a.example redirect=b.example",
		"v=spf1 exp=a.example -all exp=b.example",
		"v=spf1 exp=a.example -all EXP=a.example",
		"v=spf1 Redirect=a.example redirect=a.example",
	} {
		z := zone("example.com TXT " + rec)
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPermError)
	}
}

// TestUnknownModifiers checks that modifiers this package does not know are
// ignored wherever and however often they appear, while their syntax is
// still checked.
//
// checklist: SPF-MOD-02
func TestUnknownModifiers(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 foo=bar ip4:192.0.2.1 foo=baz moo.cow-far_out=man:dog/cat -all default=pass",
		"bad.example TXT v=spf1 foo=%x -all",
	)
	want(t, "ignored", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPass)
	want(t, "ignored, no match", mailFrom(z, "192.0.2.2", "a@example.com"), spf.ResultFail)
	want(t, "bad macro", mailFrom(z, "192.0.2.1", "a@bad.example"), spf.ResultPermError)
}

// TestRedirect checks redirect: when no mechanism matches, the target's result
// becomes the result, with the same sender; a target without a record, or a
// malformed target, gives permerror.
//
// checklist: SPF-MOD-03
func TestRedirect(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 ip4:198.51.100.1 redirect=_spf.example.com",
		"_spf.example.com TXT v=spf1 exists:%{l}.%{d}.check.test ~all",
		"alice._spf.example.com.check.test A 127.0.0.2",
		"chain.example TXT v=spf1 redirect=example.com",
		"none.example TXT v=spf1 redirect=norecord.example",
		"norecord.example A 192.0.2.1",
		"nx.example TXT v=spf1 redirect=nowhere.example",
		"bad.example TXT v=spf1 redirect=%{l}.example",
		"before.example TXT v=spf1 redirect=example.com ip4:192.0.2.9",
	)
	want(t, "mechanism matched first", mailFrom(z, "198.51.100.1", "bob@example.com"), spf.ResultPass)
	want(t, "redirect pass", mailFrom(z, "192.0.2.1", "alice@example.com"), spf.ResultPass)
	want(t, "redirect softfail", mailFrom(z, "192.0.2.1", "bob@example.com"), spf.ResultSoftfail)
	want(t, "chained", mailFrom(z, "192.0.2.1", "bob@chain.example"), spf.ResultSoftfail)
	want(t, "no record", mailFrom(z, "192.0.2.1", "a@none.example"), spf.ResultPermError)
	want(t, "NXDOMAIN", mailFrom(z, "192.0.2.1", "a@nx.example"), spf.ResultPermError)
	want(t, "malformed target", mailFrom(z, "192.0.2.1", "a.@bad.example"), spf.ResultPermError)
	want(t, "redirect written first", mailFrom(z, "192.0.2.9", "a@before.example"), spf.ResultPass)
}

// TestExplanationAbsent checks that a fail without an exp= modifier returns
// an empty explanation, and that other results never carry one.
//
// checklist: SPF-MOD-04
func TestExplanationAbsent(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 -all",
		"soft.example TXT v=spf1 ~all exp=explain.example",
		"explain.example TXT go away",
	)
	if got := mailFrom(z, "192.0.2.1", "a@example.com"); got.Result != spf.ResultFail || got.Explanation != "" {
		t.Errorf("no exp: %+v", got)
	}
	if got := mailFrom(z, "192.0.2.1", "a@soft.example"); got.Explanation != "" {
		t.Errorf("softfail carries an explanation: %+v", got)
	}
}

// TestExplanation checks exp: for a fail from a matching mechanism, the TXT
// record at the expanded target is the explanation.
//
// checklist: SPF-MOD-05
func TestExplanation(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 -ip4:192.0.2.1 ?all exp=explain._spf.%{d}",
		"explain._spf.example.com TXT Mail from example.com should only be sent by its own servers.",
	)
	got := mailFrom(z, "192.0.2.1", "a@example.com")
	if got.Result != spf.ResultFail || got.Explanation != "Mail from example.com should only be sent by its own servers." {
		t.Errorf("got %+v", got)
	}
	if got := mailFrom(z, "192.0.2.2", "a@example.com"); got.Explanation != "" {
		t.Errorf("neutral result carries an explanation: %+v", got)
	}
}

// TestExplanationProblems checks that any problem with the explanation (a DNS
// error, no record, several records, a syntax error, or a malformed target)
// leaves the result as it is with an empty explanation.
//
// checklist: SPF-MOD-05
func TestExplanationProblems(t *testing.T) {
	for target, lines := range map[string][]string{
		"servfail.example": {"servfail.example SERVFAIL TXT"},
		"nowhere.example":  nil,
		"empty.example":    {"empty.example A 192.0.2.1"},
		"two.example":      {"two.example TXT one", "two.example TXT two"},
		"syntax.example":   {"syntax.example TXT bad %x macro"},
		"exponly.example":  {"exponly.example TXT tab\there"},
		"%{l}.example":     nil,
	} {
		z := zone(append(lines, "example.com TXT v=spf1 -all exp="+target)...)
		got := mailFrom(z, "192.0.2.1", strings.Repeat("x", 70)+"@example.com")
		if got.Result != spf.ResultFail || got.Explanation != "" {
			t.Errorf("%s: got %+v, want fail with no explanation", target, got)
		}
	}
}

// TestExplanationMacros checks that the explanation is an explain-string: its
// macros are expanded, spaces are kept, and the explanation-only macros c, r
// and t work there.
//
// checklist: SPF-MOD-06 SPF-MACRO-11 SPF-MACRO-12
func TestExplanationMacros(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 -all exp=explain.example",
		"explain.example TXT %{i} (%{c}) is not one of %{d}'s servers; %{s} via %{h}, checked by %{r} at %{t}. See http://%{d}/why.html?s=%{S}&i=%{I}",
	)
	got := mailFrom(z, "192.0.2.1", "a+b@example.com")
	const exp = "192.0.2.1 (192.0.2.1) is not one of example.com's servers; a+b@example.com via mail.example.net, checked by mx.receiver.example at 1700000000. See http://example.com/why.html?s=a%2Bb%40example.com&i=192.0.2.1"
	if got.Explanation != exp {
		t.Errorf("Explanation =\n%q\nwant\n%q", got.Explanation, exp)
	}
	z.TXT["explain.example"] = []string{"%{c} %{r}"}
	o := opts(z)
	o.Receiver = ""
	got = spf.CheckMailFrom(context.Background(), netip.MustParseAddr("2001:db8::cb01"), "a@example.com", testHELO, o)
	if got.Explanation != "2001:db8::cb01 unknown" {
		t.Errorf("IPv6 %%{c} and default %%{r}: %q", got.Explanation)
	}
}

// TestExplanationASCII checks that the explanation is limited to printable
// US-ASCII, even when a macro inserts other bytes from the sender.
//
// checklist: SPF-MOD-07
func TestExplanationASCII(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 -all exp=explain.example",
		"explain.example TXT denied for %{l}",
		"utf8.example TXT v=spf1 -all exp=utf8explain.example",
		"utf8explain.example TXT dénied",
	)
	got := mailFrom(z, "192.0.2.1", "jürgen\r\nX-Evil: 1@example.com")
	if got.Explanation != "denied for j??rgen??X-Evil: 1" {
		t.Errorf("Explanation = %q", got.Explanation)
	}
	if got := mailFrom(z, "192.0.2.1", "a@utf8.example"); got.Explanation != "" {
		t.Errorf("non-ASCII explanation record: %q, want it ignored", got.Explanation)
	}
}

// TestExplanationScope checks whose exp= applies: an included record's exp=
// is never used, and after a redirect the redirected record's exp= replaces
// the original's.
//
// checklist: SPF-MOD-10 SPF-MOD-11
func TestExplanationScope(t *testing.T) {
	z := zone(
		"inc.example TXT v=spf1 include:inner.example -all exp=outer-exp.example",
		"inner.example TXT v=spf1 -all exp=inner-exp.example",
		"redir.example TXT v=spf1 redirect=target.example exp=outer-exp.example",
		"target.example TXT v=spf1 -all exp=target-exp.example",
		"redirnoexp.example TXT v=spf1 redirect=noexp.example exp=outer-exp.example",
		"noexp.example TXT v=spf1 -all",
		"outer-exp.example TXT outer",
		"inner-exp.example TXT inner",
		"target-exp.example TXT target %{d}",
	)
	for sender, exp := range map[string]string{
		"a@inc.example":        "outer",
		"a@redir.example":      "target target.example",
		"a@redirnoexp.example": "",
	} {
		got := mailFrom(z, "192.0.2.1", sender)
		if got.Result != spf.ResultFail || got.Explanation != exp {
			t.Errorf("%s: got %+v, want fail with %q", sender, got, exp)
		}
	}
}
