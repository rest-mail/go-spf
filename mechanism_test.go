package spf

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// Mechanisms (RFC 7208 §5) and the processing limits of §4.6.4.

// TestCIDRMatching checks address comparison: without a prefix length the
// addresses must be equal; with one, only that many high-order bits count.
//
// checklist: SPF-MECH-01
func TestCIDRMatching(t *testing.T) {
	z := zone(
		"host.example A 192.0.2.10",
		"host.example AAAA 2001:db8::10",
		"exact.example TXT v=spf1 a:host.example -all",
		"v4.example TXT v=spf1 a:host.example/24 -all",
		"v6.example TXT v=spf1 a:host.example//64 -all",
		"dual.example TXT v=spf1 a:host.example/31//127 -all",
		"zero.example TXT v=spf1 a:host.example/0//0 -all",
	)
	cases := []struct {
		domain, ip string
		want       Result
	}{
		{"exact.example", "192.0.2.10", ResultPass},
		{"exact.example", "192.0.2.11", ResultFail},
		{"exact.example", "2001:db8::10", ResultPass},
		{"exact.example", "2001:db8::11", ResultFail},
		{"v4.example", "192.0.2.200", ResultPass},
		{"v4.example", "192.0.3.10", ResultFail},
		{"v4.example", "2001:db8::11", ResultFail},
		{"v6.example", "2001:db8::ffff", ResultPass},
		{"v6.example", "2001:db8:0:1::10", ResultFail},
		{"v6.example", "192.0.2.11", ResultFail},
		{"dual.example", "192.0.2.11", ResultPass},
		{"dual.example", "192.0.2.12", ResultFail},
		{"dual.example", "2001:db8::11", ResultPass},
		{"dual.example", "2001:db8::12", ResultFail},
		{"zero.example", "203.0.113.1", ResultPass},
		{"zero.example", "2001:db8:ffff::1", ResultPass},
	}
	for _, c := range cases {
		want(t, c.domain+" "+c.ip, mailFrom(z, c.ip, "a@"+c.domain), c.want)
	}
}

// TestAddressFamilies checks that an IPv4 client is compared with A records
// and an IPv6 client with AAAA records, and that an IPv4-mapped IPv6 client
// address, or IPv4-mapped answers, are handled as IPv4.
//
// checklist: SPF-MECH-02
func TestAddressFamilies(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a:host.example mx -all",
		"example.com MX mx.example",
		"mx.example A 192.0.2.20",
		"host.example A 192.0.2.10",
		"host.example AAAA 2001:db8::10",
	)
	want(t, "IPv4", mailFrom(z, "192.0.2.10", "a@example.com"), ResultPass)
	if z.count("AAAA", "") != 0 {
		t.Errorf("IPv4 client made AAAA queries: %v", z.queries)
	}
	z.queries = nil
	want(t, "IPv6", mailFrom(z, "2001:db8::10", "a@example.com"), ResultPass)
	if z.count("A", "") != 0 {
		t.Errorf("IPv6 client made A queries: %v", z.queries)
	}
	want(t, "IPv4-mapped client", mailFrom(z, "::ffff:192.0.2.10", "a@example.com"), ResultPass)
	want(t, "IPv4-mapped client, mx", mailFrom(z, "::ffff:192.0.2.20", "a@example.com"), ResultPass)
	z.mapV4 = true
	want(t, "IPv4-mapped answers", mailFrom(z, "192.0.2.20", "a@example.com"), ResultPass)
}

// TestMechanismDNSErrors checks DNS failures inside mechanisms: a server
// failure or timeout ends evaluation with temperror, while a name that does
// not exist is an empty answer (a void lookup that does not match).
//
// checklist: SPF-MECH-03
func TestMechanismDNSErrors(t *testing.T) {
	z := zone(
		"a.example TXT v=spf1 a:bad.example -all",
		"mx.example TXT v=spf1 mx:bad.example -all",
		"mxhost.example TXT v=spf1 mx:mxs.example -all",
		"exists.example TXT v=spf1 exists:bad.example -all",
		"include.example TXT v=spf1 include:bad.example -all",
		"nx.example TXT v=spf1 a:nowhere.example mx:nowhere.example exists:nowhere.example -all",
		"bad.example SERVFAIL A",
		"bad.example TIMEOUT MX",
		"bad.example SERVFAIL TXT",
		"mxs.example MX good.example",
		"mxs.example MX bad.example",
		"good.example A 198.51.100.1",
	)
	for _, d := range []string{"a", "mx", "mxhost", "exists", "include"} {
		want(t, d, mailFrom(z, "192.0.2.1", "x@"+d+".example"), ResultTempError)
	}
	want(t, "NXDOMAIN", mailFrom(z, "192.0.2.1", "x@nx.example"), ResultPermError) // three voids
	z = zone(
		"nx.example TXT v=spf1 a:nowhere.example mx:nowhere.example -all",
		"mxs.example MX gone.example",
		"mxgone.example TXT v=spf1 mx:mxs.example -all",
	)
	want(t, "two voids", mailFrom(z, "192.0.2.1", "x@nx.example"), ResultFail)
	want(t, "MX host does not exist", mailFrom(z, "192.0.2.1", "x@mxgone.example"), ResultFail)
}

// TestAllEndsEvaluation checks that mechanisms after "all" are never
// evaluated.
//
// checklist: SPF-MECH-04
func TestAllEndsEvaluation(t *testing.T) {
	z := zone("example.com TXT v=spf1 -all a:later.example include:later.example")
	want(t, "all", mailFrom(z, "192.0.2.1", "a@example.com"), ResultFail)
	if len(z.queries) != 1 {
		t.Errorf("queries = %v, want only the record lookup", z.queries)
	}
}

// TestRedirectIgnoredWithAll checks that redirect is ignored when the record
// has an "all" mechanism, wherever the two appear.
//
// checklist: SPF-MECH-05
func TestRedirectIgnoredWithAll(t *testing.T) {
	for _, rec := range []string{
		"v=spf1 redirect=other.example ?all",
		"v=spf1 ?all redirect=other.example",
		"v=spf1 ip4:198.51.100.1 redirect=other.example ?all",
	} {
		z := zone("example.com TXT "+rec, "other.example TXT v=spf1 +all")
		want(t, rec, mailFrom(z, "192.0.2.1", "a@example.com"), ResultNeutral)
		if z.count("TXT", "other.example") != 0 {
			t.Errorf("%s: the redirect was followed", rec)
		}
	}
}

// TestInclude checks include: the target is evaluated with the same IP and
// sender, and its result maps to match, no match or an exception by the
// table of §5.2.
//
// checklist: SPF-MECH-06
func TestInclude(t *testing.T) {
	z := zone(
		"pass.example TXT v=spf1 +all",
		"fail.example TXT v=spf1 -all",
		"softfail.example TXT v=spf1 ~all",
		"neutral.example TXT v=spf1 ?all",
		"temperror.example SERVFAIL TXT",
		"permerror.example TXT v=spf1 bogus",
		"none.example A 192.0.2.1",
		"sender.example TXT v=spf1 exists:%{s}.%{i}.%{d}.check.test -all",
		"a@example.com.192.0.2.1.sender.example.check.test A 127.0.0.2",
	)
	cases := map[string]Result{
		"pass":      ResultFail, // -include matches
		"fail":      ResultNeutral,
		"softfail":  ResultNeutral,
		"neutral":   ResultNeutral,
		"temperror": ResultTempError,
		"permerror": ResultPermError,
		"none":      ResultPermError,
		"nxdomain":  ResultPermError,
		"sender":    ResultFail,
	}
	for name, res := range cases {
		z.txt["example.com"] = []string{"v=spf1 -include:" + name + ".example ?all"}
		got := mailFrom(z, "192.0.2.1", "a@example.com")
		want(t, "include "+name, got, res)
		if res == ResultFail && got.Mechanism != "-include:"+name+".example" {
			t.Errorf("include %s: Mechanism = %q", name, got.Mechanism)
		}
	}
}

// TestA checks the a mechanism: it matches when the client is one of the
// target's addresses.
//
// checklist: SPF-MECH-07
func TestA(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a a:other.example -all",
		"example.com A 192.0.2.10",
		"example.com A 192.0.2.11",
		"other.example A 198.51.100.1",
		"other.example AAAA 2001:db8::1",
	)
	for ip, res := range map[string]Result{
		"192.0.2.10":   ResultPass,
		"192.0.2.11":   ResultPass,
		"198.51.100.1": ResultPass,
		"2001:db8::1":  ResultPass,
		"192.0.2.12":   ResultFail,
		"2001:db8::2":  ResultFail,
	} {
		want(t, ip, mailFrom(z, ip, "a@example.com"), res)
	}
}

// TestMX checks the mx mechanism: it matches when the client is an address of
// one of the target's MX hosts, with prefix lengths, and a null MX is skipped.
//
// checklist: SPF-MECH-08
func TestMX(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 mx mx:other.example/30 -all",
		"example.com MX mx1.example.com",
		"example.com MX mx2.example.com",
		"mx1.example.com A 192.0.2.1",
		"mx2.example.com A 192.0.2.2",
		"mx2.example.com AAAA 2001:db8::2",
		"other.example MX mx.other.example",
		"mx.other.example A 198.51.100.4",
		"nullmx.example TXT v=spf1 mx -all",
		"nullmx.example MX .",
	)
	for ip, res := range map[string]Result{
		"192.0.2.1":    ResultPass,
		"192.0.2.2":    ResultPass,
		"2001:db8::2":  ResultPass,
		"198.51.100.7": ResultPass,
		"198.51.100.8": ResultFail,
		"192.0.2.3":    ResultFail,
	} {
		want(t, ip, mailFrom(z, ip, "a@example.com"), res)
	}
	want(t, "null MX", mailFrom(z, "192.0.2.1", "a@nullmx.example"), ResultFail)
}

// TestMXNoImplicitMX checks that a target without MX records is not matched
// against its own address records (no implicit MX).
//
// checklist: SPF-MECH-09
func TestMXNoImplicitMX(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 mx -all",
		"example.com A 192.0.2.1",
	)
	want(t, "no MX", mailFrom(z, "192.0.2.1", "a@example.com"), ResultFail)
	if z.count("A", "example.com") != 0 {
		t.Error("mx looked up the target's own addresses")
	}
}

// TestPTR checks the ptr mechanism: the client's PTR names are validated by a
// forward lookup, and ptr matches when a validated name is the target or a
// subdomain of it.
//
// checklist: SPF-MECH-10
func TestPTR(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 ptr -all",
		"other.example TXT v=spf1 ptr:example.com -all",
		"192.0.2.65 PTR amy.example.com.",
		"amy.example.com A 192.0.2.65",
		"192.0.2.10 PTR EXAMPLE.COM",
		"example.com A 192.0.2.10",
		"192.0.2.140 PTR mail-c.example.org",
		"mail-c.example.org A 192.0.2.140",
		"10.0.0.4 PTR bob.example.com",
		"bob.example.com A 192.0.2.66",
		"192.0.2.70 PTR badexample.com",
		"badexample.com A 192.0.2.70",
		"2001:db8::65 PTR amy6.example.com",
		"amy6.example.com AAAA 2001:db8::65",
	)
	for ip, res := range map[string]Result{
		"192.0.2.65":   ResultPass, // subdomain
		"192.0.2.10":   ResultPass, // the domain itself, case-insensitive
		"192.0.2.140":  ResultFail, // validated, but another domain
		"10.0.0.4":     ResultFail, // not validated
		"192.0.2.70":   ResultFail, // a suffix that is not a subdomain
		"2001:db8::65": ResultPass, // IPv6
	} {
		want(t, ip, mailFrom(z, ip, "a@example.com"), res)
	}
	want(t, "ptr:domain", mailFrom(z, "192.0.2.65", "a@other.example"), ResultPass)
}

// TestPTRErrors checks that a DNS error on the PTR lookup makes ptr not
// match (rather than temperror), and that an error on a name's address lookup
// skips that name and the search continues.
//
// checklist: SPF-MECH-11
func TestPTRErrors(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 ptr ?all",
		"192.0.2.1 SERVFAIL PTR",
		"192.0.2.2 PTR broken.example.com",
		"192.0.2.2 PTR good.example.com",
		"broken.example.com SERVFAIL A",
		"good.example.com A 192.0.2.2",
	)
	want(t, "PTR lookup fails", mailFrom(z, "192.0.2.1", "a@example.com"), ResultNeutral)
	want(t, "address lookup fails", mailFrom(z, "192.0.2.2", "a@example.com"), ResultPass)
}

// TestIP4IP6 checks ip4 and ip6: the client is compared with the network,
// whose prefix length defaults to /32 and /128.
//
// checklist: SPF-MECH-12
func TestIP4IP6(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 ip4:192.0.2.1 ip4:198.51.100.0/24 ip6:2001:db8::1 ip6:2001:db8:1::/48 -all",
		"zero.example TXT v=spf1 ip4:203.0.113.77/0 -all",
	)
	cases := map[string]Result{
		"192.0.2.1":           ResultPass,
		"192.0.2.2":           ResultFail,
		"198.51.100.255":      ResultPass,
		"2001:db8::1":         ResultPass,
		"2001:db8::2":         ResultFail,
		"2001:db8:1:ffff::1":  ResultPass,
		"2001:db8:2::1":       ResultFail,
		"fe80::1%eth0":        ResultFail,
		"::ffff:198.51.100.9": ResultPass,
	}
	for ip, res := range cases {
		want(t, ip, mailFrom(z, ip, "a@example.com"), res)
	}
	want(t, "/0", mailFrom(z, "1.2.3.4", "a@zero.example"), ResultPass)
}

// TestIPFamilyMismatch checks that an IPv4 client is matched only by ip4: an
// ip6 network never matches it, not even ::/0 or an IPv4-mapped network, and
// ip4 never matches an IPv6 client.
//
// checklist: SPF-MECH-13
func TestIPFamilyMismatch(t *testing.T) {
	z := zone(
		"v6.example TXT v=spf1 ip6:::/0 ip6:::ffff:0:0/96 -all",
		"v4.example TXT v=spf1 ip4:0.0.0.0/0 -all",
	)
	want(t, "ip6 vs IPv4", mailFrom(z, "192.0.2.1", "a@v6.example"), ResultFail)
	want(t, "ip4 vs IPv6", mailFrom(z, "2001:db8::1", "a@v4.example"), ResultFail)
}

// TestExists checks exists: the expanded name is looked up with an A query,
// even for an IPv6 client, and any A record matches.
//
// checklist: SPF-MECH-14
func TestExists(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 exists:%{l}.users.example -all",
		"alice.users.example A 127.0.0.2",
		"bob.users.example AAAA ::1",
	)
	want(t, "IPv4", mailFrom(z, "192.0.2.1", "alice@example.com"), ResultPass)
	want(t, "IPv6 client", mailFrom(z, "2001:db8::1", "alice@example.com"), ResultPass)
	want(t, "AAAA only", mailFrom(z, "2001:db8::1", "bob@example.com"), ResultFail)
	want(t, "absent", mailFrom(z, "192.0.2.1", "carol@example.com"), ResultFail)
	if z.count("AAAA", "") != 0 {
		t.Errorf("exists made an AAAA query: %v", z.queries)
	}
}

// TestLookupLimit checks that more than 10 DNS-querying terms (include, a,
// mx, ptr, exists and redirect) give permerror, and exactly 10 do not.
//
// checklist: SPF-LIMIT-01
func TestLookupLimit(t *testing.T) {
	lines := []string{"192.0.2.1 PTR x.example"}
	for i := 0; i < 12; i++ {
		lines = append(lines, fmt.Sprintf("h%d.example A 198.51.100.%d", i, i), fmt.Sprintf("h%d.example MX h%d.example", i, i))
	}
	terms := func(n int, kind string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, " %s:h%d.example", kind, i%12)
		}
		return b.String()
	}
	for _, kind := range []string{"a", "mx", "ptr"} {
		z := zone(append(lines, "ten.example TXT v=spf1"+terms(10, kind)+" -all", "eleven.example TXT v=spf1"+terms(11, kind)+" -all")...)
		want(t, kind+" x10", mailFrom(z, "192.0.2.1", "a@ten.example"), ResultFail)
		want(t, kind+" x11", mailFrom(z, "192.0.2.1", "a@eleven.example"), ResultPermError)
	}
	// exists either matches or is a void lookup, so it is tested as the 10th
	// and 11th term.
	z := zone(append(lines,
		"ten.example TXT v=spf1"+terms(9, "a")+" ?exists:h0.example -all",
		"eleven.example TXT v=spf1"+terms(10, "a")+" ?exists:h0.example -all",
	)...)
	want(t, "exists as 10th", mailFrom(z, "192.0.2.1", "a@ten.example"), ResultNeutral)
	want(t, "exists as 11th", mailFrom(z, "192.0.2.1", "a@eleven.example"), ResultPermError)
	z = zone(append(lines,
		"r.example TXT v=spf1"+terms(9, "a")+" redirect=s.example",
		"s.example TXT v=spf1 -all",
		"r2.example TXT v=spf1"+terms(10, "a")+" redirect=s.example",
		"i.example TXT v=spf1"+terms(10, "a")+" include:s.example -all",
	)...)
	want(t, "9 + redirect", mailFrom(z, "192.0.2.1", "a@r.example"), ResultFail)
	want(t, "10 + redirect", mailFrom(z, "192.0.2.1", "a@r2.example"), ResultPermError)
	want(t, "10 + include", mailFrom(z, "192.0.2.1", "a@i.example"), ResultPermError)
}

// TestLookupLimitIgnoresNonDNSTerms checks that all, ip4, ip6 and exp do not
// count towards the DNS-query limit.
//
// checklist: SPF-LIMIT-02
func TestLookupLimitIgnoresNonDNSTerms(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, " a:h.example ip4:198.51.100.%d ip6:2001:db8::%d", i, i)
	}
	z := zone(
		"example.com TXT v=spf1"+b.String()+" -all exp=explain.example",
		"h.example A 203.0.113.1",
		"explain.example TXT denied",
	)
	got := mailFrom(z, "192.0.2.1", "a@example.com")
	want(t, "10 a, 20 ip, exp", got, ResultFail)
	if got.Explanation != "denied" {
		t.Errorf("Explanation = %q", got.Explanation)
	}
}

// TestLookupLimitAcrossRecursion checks that the limit counts every term of
// the whole evaluation, across include and redirect, so a loop of includes
// ends in permerror.
//
// checklist: SPF-LIMIT-03
func TestLookupLimitAcrossRecursion(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 a:h.example a:h.example a:h.example include:one.example -all",
		"one.example TXT v=spf1 a:h.example a:h.example a:h.example redirect=two.example",
		"two.example TXT v=spf1 a:h.example a:h.example a:h.example +all",
		"h.example A 203.0.113.1",
		"loop.example TXT v=spf1 include:loop.example -all",
		"ping.example TXT v=spf1 redirect=pong.example",
		"pong.example TXT v=spf1 redirect=ping.example",
	)
	want(t, "12 terms across records", mailFrom(z, "192.0.2.1", "a@example.com"), ResultPermError)
	want(t, "include loop", mailFrom(z, "192.0.2.1", "a@loop.example"), ResultPermError)
	want(t, "redirect loop", mailFrom(z, "192.0.2.1", "a@ping.example"), ResultPermError)
}

// TestMXNameLimit checks that an mx term whose target lists more than 10 MX
// names gives permerror, and 10 do not.
//
// checklist: SPF-LIMIT-04
func TestMXNameLimit(t *testing.T) {
	lines := []string{"ten.example TXT v=spf1 mx:ten.mx -all", "eleven.example TXT v=spf1 mx:eleven.mx -all"}
	for i := 0; i < 11; i++ {
		if i < 10 {
			lines = append(lines, fmt.Sprintf("ten.mx MX m%d.example", i))
		}
		lines = append(lines, fmt.Sprintf("eleven.mx MX m%d.example", i), fmt.Sprintf("m%d.example A 192.0.2.%d", i, i+1))
	}
	z := zone(lines...)
	want(t, "10 MX names", mailFrom(z, "192.0.2.10", "a@ten.example"), ResultPass)
	want(t, "11 MX names", mailFrom(z, "192.0.2.1", "a@eleven.example"), ResultPermError)
}

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
	if z.count("A", "mail.example.com") != 0 {
		t.Error("the 11th PTR name was looked up")
	}
	if got := expandFor(t, z, "%{p}", "192.0.2.1", "a@example.com", "example.com", false); got != "h0.other.example" {
		t.Errorf("%%{p} = %q, want the first validated name", got)
	}
}

// TestVoidLookupLimit checks that more than two void lookups (no such name,
// or no records) give permerror, and two do not.
//
// checklist: SPF-LIMIT-08
func TestVoidLookupLimit(t *testing.T) {
	z := zone(
		"two.example TXT v=spf1 a:nx1.example exists:nx2.example -all",
		"three.example TXT v=spf1 a:nx1.example exists:nx2.example mx:nodata.example -all",
		"ptr.example TXT v=spf1 a:nx1.example exists:nx2.example ptr -all",
		"nodata.example TXT v=spf1 -all",
	)
	want(t, "two voids", mailFrom(z, "192.0.2.1", "a@two.example"), ResultFail)
	want(t, "three voids", mailFrom(z, "192.0.2.1", "a@three.example"), ResultPermError)
	want(t, "ptr void", mailFrom(z, "192.0.2.1", "a@ptr.example"), ResultPermError)
}

// TestCheckHostIPv6ZoneIgnored checks that a zone on the client address does
// not stop it from matching.
//
// checklist: SPF-MECH-01
func TestCheckHostIPv6ZoneIgnored(t *testing.T) {
	z := zone("example.com TXT v=spf1 ip6:fe80::/16 -all")
	got := CheckHost(context.Background(), netip.MustParseAddr("fe80::1%eth0"), "example.com", "a@example.com", "", opts(z))
	want(t, "zone", got, ResultPass)
}
