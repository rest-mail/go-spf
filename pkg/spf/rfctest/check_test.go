package rfctest

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
)

// Identities (RFC 7208 §2), record lookup and selection (§3, §4.4, §4.5) and
// the general evaluation rules of §4.

// TestCheckMailFromArguments checks that the MAIL FROM check runs
// check_host() with the client IP, the domain of the reverse-path and the
// reverse-path as sender.
//
// checklist: SPF-ID-01
func TestCheckMailFromArguments(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 exists:%{l}.%{o}.%{i}.%{d}.check.test -all",
		"alice.example.com.192.0.2.1.example.com.check.test A 127.0.0.2",
	)
	want(t, "matching arguments", mailFrom(z, "192.0.2.1", "alice@example.com"), spf.ResultPass)
	want(t, "other client", mailFrom(z, "192.0.2.2", "alice@example.com"), spf.ResultFail)
	want(t, "other sender", mailFrom(z, "192.0.2.1", "bob@example.com"), spf.ResultFail)
}

// TestCheckMailFromExtractsDomain checks that the domain is taken from the
// address itself: angle brackets and a source route are dropped, and with a
// %-hack the domain is the one after the last "@".
//
// checklist: SPF-ID-03
func TestCheckMailFromExtractsDomain(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 ip4:192.0.2.1 -all",
		"relay.example TXT v=spf1 -all",
	)
	for _, from := range []string{
		"<alice@example.com>",
		"@relay.example,@other.example:alice@example.com",
		"<@relay.example:alice@example.com>",
		"alice%relay.example@example.com",
	} {
		want(t, from, mailFrom(z, "192.0.2.1", from), spf.ResultPass)
	}
	want(t, "bang path has no domain", mailFrom(z, "192.0.2.1", "relay.example!alice"), spf.ResultNone)
}

// TestCheckHELO checks the HELO identity: check_host() runs with the HELO name
// as domain and as sender, so %{s} is postmaster@<helo>.
//
// checklist: SPF-ID-04
func TestCheckHELO(t *testing.T) {
	z := zone(
		"mail.example.net TXT v=spf1 exists:%{l}.%{s}.check.test -all",
		"postmaster.postmaster@mail.example.net.check.test A 127.0.0.2",
	)
	ctx := context.Background()
	got := spf.CheckHELO(ctx, netip.MustParseAddr("192.0.2.1"), "mail.example.net", opts(z))
	want(t, "HELO identity", got, spf.ResultPass)
}

// TestCheckHELOInvalid checks that a HELO that is not a multi-label domain
// name, such as an address literal, gives none without any DNS query.
//
// checklist: SPF-ID-05 SPF-EVAL-02
func TestCheckHELOInvalid(t *testing.T) {
	z := zone()
	for _, helo := range []string{"[192.0.2.1]", "192.0.2.1", "localhost", "", "mail..example.net", "-"} {
		got := spf.CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), helo, opts(z))
		want(t, helo, got, spf.ResultNone)
	}
	if len(z.Queries) != 0 {
		t.Errorf("queries = %v, want none", z.Queries)
	}
}

// TestCheckMailFromNullSender checks that the null reverse-path checks the
// mailbox postmaster@<HELO>.
//
// checklist: SPF-ID-08
func TestCheckMailFromNullSender(t *testing.T) {
	z := zone(
		"mail.example.net TXT v=spf1 exists:%{s}.check.test -all",
		"postmaster@mail.example.net.check.test A 127.0.0.2",
	)
	for _, from := range []string{"", "<>"} {
		want(t, "null sender "+from, mailFrom(z, "192.0.2.1", from), spf.ResultPass)
	}
}

// TestSenderWithoutLocalPart checks that a sender with no local-part is
// checked as postmaster at its domain.
//
// checklist: SPF-EVAL-04
func TestSenderWithoutLocalPart(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 exists:%{l}.%{o}.check.test -all",
		"postmaster.example.com.check.test A 127.0.0.2",
	)
	ip := netip.MustParseAddr("192.0.2.1")
	for _, sender := range []string{"example.com", "@example.com"} {
		got := spf.CheckHost(context.Background(), ip, "example.com", sender, testHELO, opts(z))
		want(t, sender, got, spf.ResultPass)
	}
	got := spf.CheckHost(context.Background(), ip, "example.com", "", testHELO, opts(z))
	want(t, "empty sender", got, spf.ResultPass)
}

// TestRecordLookupTXTOnly checks that the record is fetched with a TXT query
// and nothing else (the SPF RR type is no longer used).
//
// checklist: SPF-REC-01
func TestRecordLookupTXTOnly(t *testing.T) {
	z := zone("example.com TXT v=spf1 ip4:192.0.2.1 -all")
	want(t, "ip4", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPass)
	if strings.Join(z.Queries, ",") != "TXT example.com" {
		t.Errorf("queries = %v, want only the TXT query", z.Queries)
	}
}

// TestTXTStringsConcatenated checks a record published as several
// character-strings. The Resolver contract (and net.Resolver) joins them
// without spaces, so a term split across strings stays whole.
//
// checklist: SPF-REC-02
func TestTXTStringsConcatenated(t *testing.T) {
	z := zone("example.com TXT " + strings.Join([]string{"v=spf1 ip4:192.0", ".2.1 -all"}, ""))
	want(t, "split term", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPass)
}

// TestRecordSelection checks that only records beginning with exactly
// "v=spf1" followed by a space or the end are SPF records, and that a domain
// with none of them gives none.
//
// checklist: SPF-REC-03 SPF-REC-04
func TestRecordSelection(t *testing.T) {
	cases := []struct {
		txt  []string
		want spf.Result
	}{
		{[]string{"v=spf1 +all"}, spf.ResultPass},
		{[]string{"V=SPF1 +all"}, spf.ResultPass},
		{[]string{"v=spf1"}, spf.ResultNeutral},
		{[]string{"v=spf1    "}, spf.ResultNeutral},
		{[]string{"v=spf10 +all"}, spf.ResultNone},
		{[]string{"v=spf1+all"}, spf.ResultNone},
		{[]string{" v=spf1 +all"}, spf.ResultNone},
		{[]string{"spf2.0/pra +all"}, spf.ResultNone},
		{[]string{"google-site-verification=abc", "v=spf1 -all"}, spf.ResultFail},
		{[]string{"some other text"}, spf.ResultNone},
		{[]string{""}, spf.ResultNone},
	}
	for _, c := range cases {
		z := zone()
		z.TXT["example.com"] = c.txt
		want(t, strings.Join(c.txt, " | "), mailFrom(z, "192.0.2.1", "a@example.com"), c.want)
	}
	z := zone("example.com A 192.0.2.1")
	want(t, "no TXT records", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultNone)
}

// TestMultipleRecords checks that a domain publishing more than one SPF
// record gives permerror.
//
// checklist: SPF-REC-05
func TestMultipleRecords(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 +all",
		"example.com TXT v=spf1 -all",
	)
	want(t, "two records", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPermError)
}

// TestRecordLookupErrors checks the record lookup: a server failure or a
// timeout is temperror, and a name that does not exist is none.
//
// checklist: SPF-REC-06 SPF-REC-07
func TestRecordLookupErrors(t *testing.T) {
	z := zone(
		"servfail.example SERVFAIL TXT",
		"timeout.example TIMEOUT TXT",
	)
	want(t, "SERVFAIL", mailFrom(z, "192.0.2.1", "a@servfail.example"), spf.ResultTempError)
	want(t, "timeout", mailFrom(z, "192.0.2.1", "a@timeout.example"), spf.ResultTempError)
	want(t, "NXDOMAIN", mailFrom(z, "192.0.2.1", "a@nowhere.example"), spf.ResultNone)
}

// TestMalformedDomain checks that a malformed domain gives none without a DNS
// query: a label over 63 characters, an empty label, a name over 253
// characters, a single label, or a numeric top-level label.
//
// checklist: SPF-EVAL-02
func TestMalformedDomain(t *testing.T) {
	z := zone()
	long := strings.Repeat("a", 64)
	for _, d := range []string{
		long + ".example.com",
		"a..example.com",
		".example.com",
		strings.Repeat("abcdefghi.", 26) + "com",
		"com",
		"example.123",
		"exa mple.com",
	} {
		want(t, d, mailFrom(z, "192.0.2.1", "a@"+d), spf.ResultNone)
	}
	if len(z.Queries) != 0 {
		t.Errorf("queries = %v, want none", z.Queries)
	}
	z = zone("example.com TXT v=spf1 +all")
	want(t, "63-character label", mailFrom(z, "192.0.2.1", "a@"+strings.Repeat("a", 63)+".example.com"), spf.ResultNone)
	want(t, "trailing dot", mailFrom(z, "192.0.2.1", "a@example.com."), spf.ResultPass)
}

// TestInternationalizedDomain checks that internationalized names in a record
// must be A-labels (§4.3; RFC 8616 §4 leaves this unchanged): a U-label in a
// domain-spec is outside the macro-string grammar, so the record is a syntax
// error (permerror) and the name is never queried, while the A-label form
// works.
//
// checklist: SPF-EVAL-03
func TestInternationalizedDomain(t *testing.T) {
	for rec, result := range map[string]spf.Result{
		"v=spf1 a:xn--bcher-kva.example -all":       spf.ResultPass,
		"v=spf1 a:bücher.example -all":              spf.ResultPermError,
		"v=spf1 include:xn--bcher-kva.example -all": spf.ResultPass,
		"v=spf1 include:bücher.example -all":        spf.ResultPermError,
	} {
		z := zone(
			"example.com TXT "+rec,
			"xn--bcher-kva.example TXT v=spf1 +all",
			"xn--bcher-kva.example A 192.0.2.1",
			"bücher.example TXT v=spf1 +all",
			"bücher.example A 192.0.2.1",
		)
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), result)
		for _, q := range z.Queries {
			if strings.Contains(q, "ü") {
				t.Errorf("%s: queried U-label name %q", rec, q)
			}
		}
	}
}

// TestSyntaxErrorAnywhere checks that the whole record is validated before
// any term is evaluated: a syntax error after a matching mechanism, or after
// a DNS-querying one, still gives permerror and nothing is looked up.
//
// checklist: SPF-EVAL-05
func TestSyntaxErrorAnywhere(t *testing.T) {
	for _, rec := range []string{
		"v=spf1 +all foo:bar",
		"v=spf1 a:other.example -all ip4:192.0.2",
		"v=spf1 include:other.example redirect=",
		"v=spf1 ip4:192.0.2.1 x=%",
	} {
		z := zone("example.com TXT "+rec, "other.example TXT v=spf1 +all", "other.example A 192.0.2.1")
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultPermError)
		if len(z.Queries) != 1 {
			t.Errorf("%s: queries = %v, want only the record lookup", rec, z.Queries)
		}
	}
}

// TestQualifiers checks the qualifier of a matching mechanism: "+" (the
// default) gives pass, "-" fail, "~" softfail and "?" neutral.
//
// checklist: SPF-EVAL-07
func TestQualifiers(t *testing.T) {
	for rec, res := range map[string]spf.Result{
		"v=spf1 all":  spf.ResultPass,
		"v=spf1 +all": spf.ResultPass,
		"v=spf1 -all": spf.ResultFail,
		"v=spf1 ~all": spf.ResultSoftfail,
		"v=spf1 ?all": spf.ResultNeutral,
	} {
		z := zone("example.com TXT " + rec)
		got := mailFrom(z, "192.0.2.1", "a@example.com")
		want(t, rec, got, res)
		if got.Mechanism != strings.TrimPrefix(rec, "v=spf1 ") {
			t.Errorf("%s: Mechanism = %q", rec, got.Mechanism)
		}
	}
}

// TestFirstMatchWins checks that mechanisms are evaluated left to right and
// the first match decides, even when later ones would match too.
//
// checklist: SPF-EVAL-07
func TestFirstMatchWins(t *testing.T) {
	z := zone("example.com TXT v=spf1 -ip4:192.0.2.1 ~ip4:192.0.2.0/24 ip4:192.0.0.0/16 -all")
	want(t, "first", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultFail)
	want(t, "second", mailFrom(z, "192.0.2.2", "a@example.com"), spf.ResultSoftfail)
	want(t, "third", mailFrom(z, "192.0.3.1", "a@example.com"), spf.ResultPass)
	want(t, "last", mailFrom(z, "198.51.100.1", "a@example.com"), spf.ResultFail)
}

// TestExceptionStopsEvaluation checks that a mechanism returning an exception
// ends evaluation with that exception, so later mechanisms are not evaluated.
//
// checklist: SPF-EVAL-08
func TestExceptionStopsEvaluation(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a:broken.example a:later.example +all",
		"broken.example SERVFAIL A",
	)
	want(t, "temperror", mailFrom(z, "192.0.2.1", "a@example.com"), spf.ResultTempError)
	if z.Count("A", "later.example") != 0 {
		t.Error("evaluation continued after the exception")
	}
}

// TestDefaultResult checks that a record whose mechanisms all fail to match,
// and which has no redirect, gives neutral with the "default" mechanism.
//
// checklist: SPF-EVAL-09
func TestDefaultResult(t *testing.T) {
	z := zone("example.com TXT v=spf1 ip4:198.51.100.1 exp=explain.example")
	got := mailFrom(z, "192.0.2.1", "a@example.com")
	want(t, "no match", got, spf.ResultNeutral)
	if got.Mechanism != "default" {
		t.Errorf("Mechanism = %q, want default", got.Mechanism)
	}
}

// TestDefaultTargetName checks that a, mx and ptr without a domain-spec use
// the current <domain>, including inside an include.
//
// checklist: SPF-EVAL-10
func TestDefaultTargetName(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 include:inc.example -all",
		"inc.example TXT v=spf1 a mx ptr -all",
		"inc.example A 192.0.2.1",
		"inc.example MX mx.inc.example",
		"mx.inc.example A 192.0.2.2",
		"192.0.2.3 PTR host.inc.example",
		"host.inc.example A 192.0.2.3",
	)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		want(t, ip, mailFrom(z, ip, "a@example.com"), spf.ResultPass)
	}
	want(t, "other", mailFrom(z, "192.0.2.4", "a@example.com"), spf.ResultFail)
}

// TestMalformedTargetName checks the choice §4.8 leaves open: a target-name
// that is not a valid domain after macro expansion is treated as a name that
// does not exist (a void lookup that does not match) for a, mx and exists, and
// gives permerror for include and redirect.
//
// checklist: SPF-EVAL-11
func TestMalformedTargetName(t *testing.T) {
	label := strings.Repeat("x", 64)
	z := zone(
		"a.example TXT v=spf1 a:%{l}.example.org -all",
		"mx.example TXT v=spf1 mx:%{l}.example.org -all",
		"exists.example TXT v=spf1 exists:%{l}.example.org -all",
		"ptr.example TXT v=spf1 ptr:%{l}.example.org -all",
		"void.example TXT v=spf1 a:%{l}.example.org a:%{l}.example.org a:%{l}.example.org -all",
		"include.example TXT v=spf1 include:%{l}.example.org -all",
		"redirect.example TXT v=spf1 redirect=%{l}.example.org",
		"single.example TXT v=spf1 a:%{l} -all",
		"numeric.example TXT v=spf1 a:%{i} -all",
		"192.0.2.1 PTR x.example.org",
	)
	for _, d := range []string{"a", "mx", "exists", "ptr"} {
		want(t, d, mailFrom(z, "192.0.2.1", label+"@"+d+".example"), spf.ResultFail)
	}
	want(t, "empty label", mailFrom(z, "192.0.2.1", "x..y@a.example"), spf.ResultFail)
	want(t, "void limit", mailFrom(z, "192.0.2.1", label+"@void.example"), spf.ResultPermError)
	want(t, "include", mailFrom(z, "192.0.2.1", label+"@include.example"), spf.ResultPermError)
	want(t, "redirect", mailFrom(z, "192.0.2.1", label+"@redirect.example"), spf.ResultPermError)
	want(t, "single label", mailFrom(z, "192.0.2.1", "foo@single.example"), spf.ResultFail)
	want(t, "numeric top label", mailFrom(z, "192.0.2.1", "foo@numeric.example"), spf.ResultFail)
	if n := z.Count("A", ""); n != 0 {
		t.Errorf("%d address queries for malformed names, want 0", n)
	}
}

// TestSevenResults checks that check_host() produces each of the seven
// results, and only those.
//
// checklist: SPF-RESULT-01
func TestSevenResults(t *testing.T) {
	z := zone(
		"pass.example TXT v=spf1 +all",
		"fail.example TXT v=spf1 -all",
		"softfail.example TXT v=spf1 ~all",
		"neutral.example TXT v=spf1 ?all",
		"none.example A 192.0.2.1",
		"temperror.example SERVFAIL TXT",
		"permerror.example TXT v=spf1 bogus",
	)
	for _, r := range []spf.Result{spf.ResultPass, spf.ResultFail, spf.ResultSoftfail, spf.ResultNeutral, spf.ResultNone, spf.ResultTempError, spf.ResultPermError} {
		want(t, string(r), mailFrom(z, "192.0.2.1", "a@"+string(r)+".example"), r)
	}
}

// TestInvalidClientIP checks that a check without a valid client address
// gives permerror and queries nothing.
//
// checklist: SPF-ID-01
func TestInvalidClientIP(t *testing.T) {
	z := zone("example.com TXT v=spf1 +all")
	got := spf.CheckMailFrom(context.Background(), netip.Addr{}, "a@example.com", testHELO, opts(z))
	want(t, "zero address", got, spf.ResultPermError)
	if len(z.Queries) != 0 {
		t.Errorf("queries = %v, want none", z.Queries)
	}
}
