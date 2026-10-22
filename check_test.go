package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
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
	want(t, "matching arguments", mailFrom(z, "192.0.2.1", "alice@example.com"), ResultPass)
	want(t, "other client", mailFrom(z, "192.0.2.2", "alice@example.com"), ResultFail)
	want(t, "other sender", mailFrom(z, "192.0.2.1", "bob@example.com"), ResultFail)
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
		want(t, from, mailFrom(z, "192.0.2.1", from), ResultPass)
	}
	want(t, "bang path has no domain", mailFrom(z, "192.0.2.1", "relay.example!alice"), ResultNone)
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
	got := CheckHELO(ctx, netip.MustParseAddr("192.0.2.1"), "mail.example.net", opts(z))
	want(t, "HELO identity", got, ResultPass)
}

// TestCheckHELOInvalid checks that a HELO that is not a multi-label domain
// name, such as an address literal, gives none without any DNS query.
//
// checklist: SPF-ID-05 SPF-EVAL-02
func TestCheckHELOInvalid(t *testing.T) {
	z := zone()
	for _, helo := range []string{"[192.0.2.1]", "192.0.2.1", "localhost", "", "mail..example.net", "-"} {
		got := CheckHELO(context.Background(), netip.MustParseAddr("192.0.2.1"), helo, opts(z))
		want(t, helo, got, ResultNone)
	}
	if len(z.queries) != 0 {
		t.Errorf("queries = %v, want none", z.queries)
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
		want(t, "null sender "+from, mailFrom(z, "192.0.2.1", from), ResultPass)
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
		got := CheckHost(context.Background(), ip, "example.com", sender, testHELO, opts(z))
		want(t, sender, got, ResultPass)
	}
	got := CheckHost(context.Background(), ip, "example.com", "", testHELO, opts(z))
	want(t, "empty sender", got, ResultPass)
}

// TestRecordLookupTXTOnly checks that the record is fetched with a TXT query
// and nothing else (the SPF RR type is no longer used).
//
// checklist: SPF-REC-01
func TestRecordLookupTXTOnly(t *testing.T) {
	z := zone("example.com TXT v=spf1 ip4:192.0.2.1 -all")
	want(t, "ip4", mailFrom(z, "192.0.2.1", "a@example.com"), ResultPass)
	if strings.Join(z.queries, ",") != "TXT example.com" {
		t.Errorf("queries = %v, want only the TXT query", z.queries)
	}
}

// TestTXTStringsConcatenated checks a record published as several
// character-strings. The Resolver contract (and net.Resolver) joins them
// without spaces, so a term split across strings stays whole.
//
// checklist: SPF-REC-02
func TestTXTStringsConcatenated(t *testing.T) {
	z := zone("example.com TXT " + strings.Join([]string{"v=spf1 ip4:192.0", ".2.1 -all"}, ""))
	want(t, "split term", mailFrom(z, "192.0.2.1", "a@example.com"), ResultPass)
}

// TestRecordSelection checks that only records beginning with exactly
// "v=spf1" followed by a space or the end are SPF records, and that a domain
// with none of them gives none.
//
// checklist: SPF-REC-03 SPF-REC-04
func TestRecordSelection(t *testing.T) {
	cases := []struct {
		txt  []string
		want Result
	}{
		{[]string{"v=spf1 +all"}, ResultPass},
		{[]string{"V=SPF1 +all"}, ResultPass},
		{[]string{"v=spf1"}, ResultNeutral},
		{[]string{"v=spf1    "}, ResultNeutral},
		{[]string{"v=spf10 +all"}, ResultNone},
		{[]string{"v=spf1+all"}, ResultNone},
		{[]string{" v=spf1 +all"}, ResultNone},
		{[]string{"spf2.0/pra +all"}, ResultNone},
		{[]string{"google-site-verification=abc", "v=spf1 -all"}, ResultFail},
		{[]string{"some other text"}, ResultNone},
		{[]string{""}, ResultNone},
	}
	for _, c := range cases {
		z := zone()
		z.txt["example.com"] = c.txt
		want(t, strings.Join(c.txt, " | "), mailFrom(z, "192.0.2.1", "a@example.com"), c.want)
	}
	z := zone("example.com A 192.0.2.1")
	want(t, "no TXT records", mailFrom(z, "192.0.2.1", "a@example.com"), ResultNone)
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
	want(t, "two records", mailFrom(z, "192.0.2.1", "a@example.com"), ResultPermError)
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
	want(t, "SERVFAIL", mailFrom(z, "192.0.2.1", "a@servfail.example"), ResultTempError)
	want(t, "timeout", mailFrom(z, "192.0.2.1", "a@timeout.example"), ResultTempError)
	want(t, "NXDOMAIN", mailFrom(z, "192.0.2.1", "a@nowhere.example"), ResultNone)
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
		want(t, d, mailFrom(z, "192.0.2.1", "a@"+d), ResultNone)
	}
	if len(z.queries) != 0 {
		t.Errorf("queries = %v, want none", z.queries)
	}
	z = zone("example.com TXT v=spf1 +all")
	want(t, "63-character label", mailFrom(z, "192.0.2.1", "a@"+strings.Repeat("a", 63)+".example.com"), ResultNone)
	want(t, "trailing dot", mailFrom(z, "192.0.2.1", "a@example.com."), ResultPass)
}

// TestInternationalizedDomain checks that internationalized names in a record
// must be A-labels (§4.3; RFC 8616 §4 leaves this unchanged): a U-label in a
// domain-spec is outside the macro-string grammar, so the record is a syntax
// error (permerror) and the name is never queried, while the A-label form
// works.
//
// checklist: SPF-EVAL-03
func TestInternationalizedDomain(t *testing.T) {
	for rec, result := range map[string]Result{
		"v=spf1 a:xn--bcher-kva.example -all":       ResultPass,
		"v=spf1 a:bücher.example -all":              ResultPermError,
		"v=spf1 include:xn--bcher-kva.example -all": ResultPass,
		"v=spf1 include:bücher.example -all":        ResultPermError,
	} {
		z := zone(
			"example.com TXT "+rec,
			"xn--bcher-kva.example TXT v=spf1 +all",
			"xn--bcher-kva.example A 192.0.2.1",
			"bücher.example TXT v=spf1 +all",
			"bücher.example A 192.0.2.1",
		)
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), result)
		for _, q := range z.queries {
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
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), ResultPermError)
		if len(z.queries) != 1 {
			t.Errorf("%s: queries = %v, want only the record lookup", rec, z.queries)
		}
	}
}

// TestRecordSyntax checks the term grammar: terms are separated by one or
// more spaces, a modifier is a name followed by "=", mechanism and modifier
// names are case-insensitive, and anything else is a syntax error.
//
// checklist: SPF-EVAL-06
func TestRecordSyntax(t *testing.T) {
	valid := []string{
		"v=spf1",
		"v=spf1 -all",
		"v=spf1   a   mx   -all  ",
		"v=spf1 A MX:example.org PTR IP4:192.0.2.0/24 IP6:2001:db8::/32 EXISTS:%{i}.example.org INCLUDE:example.org ~ALL",
		"v=spf1 Redirect=example.org",
		"v=spf1 EXP=explain.example.org -all",
		"v=spf1 a/24 a//64 a/24//64 a:example.org/24 a:example.org//64 a:example.org/24//64 mx/0 mx//0",
		"v=spf1 ip4:192.0.2.1/0 ip4:192.0.2.1/32 ip6:::1 ip6:::1/0 ip6:::1/128 ip6:::FFFF:192.0.2.1",
		"v=spf1 a:example.org. a:%{d} a:%{d}.%% a:%{d}.%_ a:%{d}.%- a:foo-bar.x-y a:foo.1-2",
		"v=spf1 a:%{d2r+-/}.example.org a:%{L}.example.org a:%{IR}.example.org",
		"v=spf1 ptr:example.org -all",
		"v=spf1 foo=bar foo=baz x-y.z_w=%{d}",
		"v=spf1 a:foo/bar.example.org",
		"v=spf1 a:a=b.example.org",
	}
	for _, rec := range valid {
		if _, err := parseRecord(rec); err != nil {
			t.Errorf("parseRecord(%q) = %v, want valid", rec, err)
		}
	}
	invalid := []string{
		"v=spf1 -",
		"v=spf1 foo",
		"v=spf1 all:example.org",
		"v=spf1 all/24",
		"v=spf1 -all.",
		"v=spf1 include",
		"v=spf1 include:",
		"v=spf1 include/24",
		"v=spf1 exists",
		"v=spf1 exists:example.org/24",
		"v=spf1 ptr/24",
		"v=spf1 ptr:",
		"v=spf1 a:",
		"v=spf1 a:/24",
		"v=spf1 a/",
		"v=spf1 a/33",
		"v=spf1 a//129",
		"v=spf1 a/024",
		"v=spf1 a/24/24",
		"v=spf1 a/x",
		"v=spf1 a:example.org/",
		"v=spf1 a:examplecom",
		"v=spf1 a:example.123",
		"v=spf1 a:example.-com",
		"v=spf1 a:example.com-",
		"v=spf1 a:example.c_m",
		"v=spf1 a:example.com..",
		"v=spf1 a:%{d}.",
		"v=spf1 a:example.org:8080",
		"v=spf1 ip4",
		"v=spf1 ip4:",
		"v=spf1 ip4/24",
		"v=spf1 ip4:192.0.2",
		"v=spf1 ip4:192.0.2.01",
		"v=spf1 ip4:192.0.2.256",
		"v=spf1 ip4:192.0.2.1/33",
		"v=spf1 ip4:192.0.2.1/",
		"v=spf1 ip4:192.0.2.1//64",
		"v=spf1 ip4:::1",
		"v=spf1 ip6:192.0.2.1",
		"v=spf1 ip6:::1/129",
		"v=spf1 ip6:fe80::1%eth0",
		"v=spf1 ip6:2001:db8:::1",
		"v=spf1 redirect=",
		"v=spf1 redirect=examplecom",
		"v=spf1 exp=",
		"v=spf1 +redirect=example.org",
		"v=spf1 1x=y",
		"v=spf1 a\texample.org",
		"v=spf1 a:exämple.org",
	}
	for _, rec := range invalid {
		if _, err := parseRecord(rec); err == nil {
			t.Errorf("parseRecord(%q) = nil, want a syntax error", rec)
		}
	}
	if _, err := parseRecord("not spf"); err == nil {
		t.Error("parseRecord accepted a non-SPF string")
	}
}

// TestQualifiers checks the qualifier of a matching mechanism: "+" (the
// default) gives pass, "-" fail, "~" softfail and "?" neutral.
//
// checklist: SPF-EVAL-07
func TestQualifiers(t *testing.T) {
	for rec, res := range map[string]Result{
		"v=spf1 all":  ResultPass,
		"v=spf1 +all": ResultPass,
		"v=spf1 -all": ResultFail,
		"v=spf1 ~all": ResultSoftfail,
		"v=spf1 ?all": ResultNeutral,
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
	want(t, "first", mailFrom(z, "192.0.2.1", "a@example.com"), ResultFail)
	want(t, "second", mailFrom(z, "192.0.2.2", "a@example.com"), ResultSoftfail)
	want(t, "third", mailFrom(z, "192.0.3.1", "a@example.com"), ResultPass)
	want(t, "last", mailFrom(z, "198.51.100.1", "a@example.com"), ResultFail)
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
	want(t, "temperror", mailFrom(z, "192.0.2.1", "a@example.com"), ResultTempError)
	if z.count("A", "later.example") != 0 {
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
	want(t, "no match", got, ResultNeutral)
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
		want(t, ip, mailFrom(z, ip, "a@example.com"), ResultPass)
	}
	want(t, "other", mailFrom(z, "192.0.2.4", "a@example.com"), ResultFail)
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
		want(t, d, mailFrom(z, "192.0.2.1", label+"@"+d+".example"), ResultFail)
	}
	want(t, "empty label", mailFrom(z, "192.0.2.1", "x..y@a.example"), ResultFail)
	want(t, "void limit", mailFrom(z, "192.0.2.1", label+"@void.example"), ResultPermError)
	want(t, "include", mailFrom(z, "192.0.2.1", label+"@include.example"), ResultPermError)
	want(t, "redirect", mailFrom(z, "192.0.2.1", label+"@redirect.example"), ResultPermError)
	want(t, "single label", mailFrom(z, "192.0.2.1", "foo@single.example"), ResultFail)
	want(t, "numeric top label", mailFrom(z, "192.0.2.1", "foo@numeric.example"), ResultFail)
	if n := z.count("A", ""); n != 0 {
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
	for _, r := range []Result{ResultPass, ResultFail, ResultSoftfail, ResultNeutral, ResultNone, ResultTempError, ResultPermError} {
		want(t, string(r), mailFrom(z, "192.0.2.1", "a@"+string(r)+".example"), r)
	}
}

// TestInvalidClientIP checks that a check without a valid client address
// gives permerror and queries nothing.
//
// checklist: SPF-ID-01
func TestInvalidClientIP(t *testing.T) {
	z := zone("example.com TXT v=spf1 +all")
	got := CheckMailFrom(context.Background(), netip.Addr{}, "a@example.com", testHELO, opts(z))
	want(t, "zero address", got, ResultPermError)
	if len(z.queries) != 0 {
		t.Errorf("queries = %v, want none", z.queries)
	}
}

// TestDefaultOptions checks the defaults of a nil *Options: the system
// resolver (not reached here, as the domain is malformed) and the default
// timeout.
//
// checklist: SPF-LIMIT-07
func TestDefaultOptions(t *testing.T) {
	got := CheckHost(context.Background(), netip.MustParseAddr("192.0.2.1"), "invalid", "a@invalid", testHELO, nil)
	want(t, "nil options", got, ResultNone)
	e := newEvaluator(context.Background(), netip.MustParseAddr("192.0.2.1"), "example.com", "a@example.com", "", &Options{})
	if e.resolver == nil || e.now == nil {
		t.Error("nil Options fields were not defaulted")
	}
	if DefaultTimeout < 20*time.Second {
		t.Errorf("DefaultTimeout = %v, want at least 20s", DefaultTimeout)
	}
}

// TestTimeout checks the elapsed-time limit: an evaluation that runs over
// Options.Timeout, or over the context's deadline, gives temperror.
//
// checklist: SPF-LIMIT-06
func TestTimeout(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a:one.example a:two.example mx:three.example -all",
		"one.example A 198.51.100.1",
		"two.example A 198.51.100.2",
		"three.example MX mx.three.example",
	)
	z.wait = 20 * time.Millisecond
	o := opts(z)
	o.Timeout = 30 * time.Millisecond
	start := time.Now()
	got := CheckMailFrom(context.Background(), netip.MustParseAddr("192.0.2.1"), "a@example.com", testHELO, o)
	want(t, "options timeout", got, ResultTempError)
	if time.Since(start) > 5*time.Second {
		t.Error("evaluation did not stop at the time limit")
	}

	// An expired context fails each kind of lookup before it is made.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, rec := range []string{"v=spf1 a -all", "v=spf1 mx -all", "v=spf1 ptr ?all"} {
		e := newEvaluator(ctx, netip.MustParseAddr("192.0.2.1"), "example.com", "a@example.com", "", opts(zone()))
		r, _ := parseRecord(rec)
		o := e.evaluate("example.com", r)
		if rec == "v=spf1 ptr ?all" {
			if o.result != ResultNeutral {
				t.Errorf("%s with expired context = %s, want neutral (ptr does not match)", rec, o.result)
			}
			continue
		}
		if o.result != ResultTempError {
			t.Errorf("%s with expired context = %s, want temperror", rec, o.result)
		}
	}
	got = CheckHost(ctx, netip.MustParseAddr("192.0.2.1"), "example.com", "a@example.com", "", opts(zone()))
	want(t, "expired context", got, ResultTempError)
}
