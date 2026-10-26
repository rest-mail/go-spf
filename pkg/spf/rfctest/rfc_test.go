package rfctest

import (
	"context"
	"strings"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
	"github.com/rest-mail/go-spf/pkg/spf/internal/dnstest"
)

// The examples of RFC 7208 Appendix A, and cases equivalent to the
// open-spf.org RFC 7208 test suite.

// appendixA is the DNS setup Appendix A's examples are based on. The CNAME of
// www.example.com is flattened into its addresses.
func appendixA(extra ...string) *dnstest.Zone {
	return zone(append([]string{
		"example.com MX mail-a.example.com",
		"example.com MX mail-b.example.com",
		"example.com A 192.0.2.10",
		"example.com A 192.0.2.11",
		"amy.example.com A 192.0.2.65",
		"bob.example.com A 192.0.2.66",
		"mail-a.example.com A 192.0.2.129",
		"mail-b.example.com A 192.0.2.130",
		"www.example.com A 192.0.2.10",
		"www.example.com A 192.0.2.11",
		"example.org MX mail-c.example.org",
		"mail-c.example.org A 192.0.2.140",
		"192.0.2.10 PTR example.com.",
		"192.0.2.11 PTR example.com.",
		"192.0.2.65 PTR amy.example.com.",
		"192.0.2.66 PTR bob.example.com.",
		"192.0.2.129 PTR mail-a.example.com.",
		"192.0.2.130 PTR mail-b.example.com.",
		"192.0.2.140 PTR mail-c.example.org.",
		"10.0.0.4 PTR bob.example.com.",
	}, extra...)...)
}

// TestAppendixA1 runs the simple examples of Appendix A.1: for each record
// published at example.com, the listed hosts pass and the others fail.
//
// checklist: SPF-EVAL-01 SPF-MECH-07 SPF-MECH-08 SPF-MECH-10 SPF-MECH-12
func TestAppendixA1(t *testing.T) {
	hosts := []string{"192.0.2.10", "192.0.2.11", "192.0.2.65", "192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131", "192.0.2.132", "192.0.2.140", "192.0.2.141", "192.0.2.144", "10.0.0.4"}
	cases := []struct {
		record string
		pass   []string
	}{
		{"v=spf1 +all", hosts},
		{"v=spf1 a -all", []string{"192.0.2.10", "192.0.2.11"}},
		{"v=spf1 a:example.org -all", nil},
		{"v=spf1 mx -all", []string{"192.0.2.129", "192.0.2.130"}},
		{"v=spf1 mx:example.org -all", []string{"192.0.2.140"}},
		{"v=spf1 mx mx:example.org -all", []string{"192.0.2.129", "192.0.2.130", "192.0.2.140"}},
		{"v=spf1 mx/30 mx:example.org/30 -all", []string{"192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131", "192.0.2.140", "192.0.2.141"}},
		{"v=spf1 ptr -all", []string{"192.0.2.10", "192.0.2.11", "192.0.2.65", "192.0.2.129", "192.0.2.130"}},
		{"v=spf1 ip4:192.0.2.128/28 -all", []string{"192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131", "192.0.2.132", "192.0.2.140", "192.0.2.141"}},
	}
	for _, c := range cases {
		z := appendixA("example.com TXT " + c.record)
		pass := map[string]bool{}
		for _, ip := range c.pass {
			pass[ip] = true
		}
		for _, ip := range hosts {
			res := spf.ResultFail
			if pass[ip] {
				res = spf.ResultPass
			}
			want(t, c.record+" from "+ip, mailFrom(z, ip, "user@example.com"), res)
		}
	}
}

// TestAppendixA2 runs the multiple-domain examples of Appendix A.2:
// example.org designates the union of example.com's and example.net's
// servers, and three subdomains share its record by redirect.
//
// checklist: SPF-EVAL-01 SPF-MECH-06 SPF-MOD-03
func TestAppendixA2(t *testing.T) {
	z := zone(
		"example.org TXT v=spf1 include:example.com include:example.net -all",
		"la.example.org TXT v=spf1 redirect=example.org",
		"ny.example.org TXT v=spf1 redirect=example.org",
		"sf.example.org TXT v=spf1 redirect=example.org",
		"example.com TXT v=spf1 a -all",
		"example.com A 192.0.2.10",
		"example.net TXT v=spf1 ip4:198.51.100.0/24 -all",
	)
	for _, d := range []string{"example.org", "la.example.org", "ny.example.org", "sf.example.org"} {
		want(t, d+" via example.com", mailFrom(z, "192.0.2.10", "user@"+d), spf.ResultPass)
		want(t, d+" via example.net", mailFrom(z, "198.51.100.7", "user@"+d), spf.ResultPass)
		want(t, d+" elsewhere", mailFrom(z, "203.0.113.1", "user@"+d), spf.ResultFail)
	}
}

// TestAppendixA3 runs the DNSBL-style example of Appendix A.3: users who send
// from arbitrary servers, and users who send from personal servers, are
// described with exists and macros.
//
// checklist: SPF-EVAL-01 SPF-MECH-14 SPF-MACRO-04
func TestAppendixA3(t *testing.T) {
	z := appendixA(
		"example.com TXT v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		"mobile-users._spf.example.com TXT v=spf1 exists:%{l1r+}.%{d}",
		"remote-users._spf.example.com TXT v=spf1 exists:%{ir}.%{l1r+}.%{d}",
		"mary.mobile-users._spf.example.com A 127.0.0.2",
		"fred.mobile-users._spf.example.com A 127.0.0.2",
		"15.15.168.192.joel.remote-users._spf.example.com A 127.0.0.2",
		"16.15.168.192.joel.remote-users._spf.example.com A 127.0.0.2",
	)
	cases := []struct {
		ip, sender string
		want       spf.Result
	}{
		{"203.0.113.9", "mary@example.com", spf.ResultPass},
		{"203.0.113.9", "fred@example.com", spf.ResultPass},
		{"203.0.113.9", "mary+lists@example.com", spf.ResultPass},
		{"192.168.15.15", "joel@example.com", spf.ResultPass},
		{"192.168.15.16", "joel@example.com", spf.ResultPass},
		{"192.168.15.17", "joel@example.com", spf.ResultFail},
		{"203.0.113.9", "joel@example.com", spf.ResultFail},
		{"203.0.113.9", "bob@example.com", spf.ResultFail},
		{"192.0.2.129", "bob@example.com", spf.ResultPass},
	}
	for _, c := range cases {
		want(t, c.sender+" from "+c.ip, mailFrom(z, c.ip, c.sender), c.want)
	}
}

// TestAppendixA4 runs the multiple-requirements example of Appendix A.4 (a
// host must be in 192.0.2.0/24 and have valid reverse DNS in example.com).
// As erratum 6216 reports, the published "-ptr" checks names under
// ptr._spf.example.com, so as printed the example fails every host; with the
// erratum's "-ptr:example.com" it works as the text intends.
//
// checklist: SPF-EVAL-01 SPF-MECH-06 SPF-MECH-10
func TestAppendixA4(t *testing.T) {
	records := []string{
		"example.com TXT v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all",
		"ip4._spf.example.com TXT v=spf1 -ip4:192.0.2.0/24 +all",
	}
	asPrinted := appendixA(append(records, "ptr._spf.example.com TXT v=spf1 -ptr +all")...)
	corrected := appendixA(append(records, "ptr._spf.example.com TXT v=spf1 -ptr:example.com +all")...)
	for ip, res := range map[string]spf.Result{
		"192.0.2.65":  spf.ResultPass, // in range, reverse DNS in example.com
		"192.0.2.140": spf.ResultFail, // in range, reverse DNS in example.org
		"192.0.2.200": spf.ResultFail, // in range, no reverse DNS
		"10.0.0.4":    spf.ResultFail, // out of range
	} {
		want(t, "as printed, "+ip, mailFrom(asPrinted, ip, "user@example.com"), spf.ResultFail)
		want(t, "corrected, "+ip, mailFrom(corrected, ip, "user@example.com"), res)
	}
}

// TestOpenSPFEquivalents covers the scenarios of the open-spf.org RFC 7208
// test suite, section by section, with cases written for this package. (The
// suite itself is BSD-licensed, so it is not copied into this MIT
// repository.)
//
// checklist: SPF-EVAL-01
func TestOpenSPFEquivalents(t *testing.T) {
	z := zone(
		// Initial processing
		"toolong.example TXT v=spf1 +all",
		"hosterror.example SERVFAIL TXT",
		"emptylabel.example TXT v=spf1 +all",
		// Record lookup and selection
		"nospace1.example TXT v=spf1mx",
		"nospace2.example TXT v=spf1=mx",
		"spf2.example TXT spf2.0/mfrom +all",
		"spf2.example TXT v=spf1 -all",
		"twospf.example TXT v=spf1 +all",
		"twospf.example TXT v=spf1 ~all",
		"case.example TXT V=sPf1 +ALL",
		"spaces.example TXT v=spf1   ip4:192.0.2.1    -all   ",
		// Record evaluation
		"detect-modifier.example TXT v=spf1 a:x=y.example -all",
		"x=y.example A 192.0.2.1",
		"default.example TXT v=spf1 ip4:198.51.100.1",
		"redirect-after-all.example TXT v=spf1 -all redirect=pass.example",
		"pass.example TXT v=spf1 +all",
		"badmod.example TXT v=spf1 =foo -all",
		"numname.example TXT v=spf1 9foo=bar -all",
		// all
		"all-arg.example TXT v=spf1 -all:foo",
		"all-cidr.example TXT v=spf1 -all/8",
		"all-neutral.example TXT v=spf1 ?all",
		// ptr
		"ptr-cidr.example TXT v=spf1 ptr/0 -all",
		"ptr-empty.example TXT v=spf1 ptr: -all",
		"ptr-match.example TXT v=spf1 ptr:example.net -all",
		"192.0.2.1 PTR mail.example.net",
		"mail.example.net A 192.0.2.1",
		// a
		"a-colon.example TXT v=spf1 a:example.org:8080 -all",
		"a-dual-cidr.example TXT v=spf1 a:host.example/24//64 -all",
		"host.example A 192.0.2.200",
		"a-numeric-top.example TXT v=spf1 a:foo.123 -all",
		"a-dash-top.example TXT v=spf1 a:foo.bar- -all",
		"a-only-top.example TXT v=spf1 a:examplenet -all",
		"a-bad-cidr4.example TXT v=spf1 a/33 -all",
		"a-bad-cidr6.example TXT v=spf1 a//129 -all",
		"a-multi-ip.example TXT v=spf1 a:multi.example -all",
		"multi.example A 198.51.100.1",
		"multi.example A 192.0.2.1",
		// include
		"include-none.example TXT v=spf1 include:nospf.example -all",
		"nospf.example A 192.0.2.1",
		"include-softfail.example TXT v=spf1 include:soft.example ?all",
		"soft.example TXT v=spf1 ~all",
		"include-empty.example TXT v=spf1 include: -all",
		"include-cidr.example TXT v=spf1 include:pass.example/24 -all",
		// mx
		"mx-empty.example TXT v=spf1 mx: -all",
		"mx-implicit.example TXT v=spf1 mx -all",
		"mx-implicit.example A 192.0.2.1",
		"mx-multi.example TXT v=spf1 mx:mx.multi.example -all",
		"mx.multi.example MX a.multi.example",
		"mx.multi.example MX b.multi.example",
		"b.multi.example A 192.0.2.1",
		// exists
		"exists-empty.example TXT v=spf1 exists: -all",
		"exists-cidr.example TXT v=spf1 exists:pass.example/24 -all",
		"exists-v6.example TXT v=spf1 exists:aaaaonly.example -all",
		"aaaaonly.example AAAA 2001:db8::1",
		// ip4 / ip6
		"ip4-noaddr.example TXT v=spf1 ip4 -all",
		"ip4-short.example TXT v=spf1 ip4:192.0.2 -all",
		"ip4-mapped.example TXT v=spf1 ip6:::ffff:192.0.2.1 -all",
		"ip6-v4.example TXT v=spf1 ip6:::/0 -all",
		"ip6-bad.example TXT v=spf1 ip6:::1/129 -all",
		// exp and other modifiers
		"exp-fail.example TXT v=spf1 -all exp=msg.example",
		"msg.example TXT %{i} is not allowed for %{d}",
		"exp-twice.example TXT v=spf1 -all exp=msg.example exp=msg.example",
		"exp-syntax.example TXT v=spf1 -all exp=%{x}.example",
		"redirect-none.example TXT v=spf1 redirect=nospf.example",
		"redirect-cancels-exp.example TXT v=spf1 redirect=e2.example exp=msg.example",
		"e2.example TXT v=spf1 -all",
		"unknown-mod.example TXT v=spf1 -all moose=frog",
		// macros
		"macro-bad.example TXT v=spf1 -exists:%(ir).list.example",
		"macro-lr.example TXT v=spf1 exists:%{lr-}.list.example -all",
		"b.a.list.example A 127.0.0.2",
		"macro-v6.example TXT v=spf1 exists:%{ir}.%{v}.list.example -all",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.list.example A 127.0.0.2",
		"macro-exp-only.example TXT v=spf1 exists:%{t}.list.example -all",
		"macro-trailing.example TXT v=spf1 -include:%{d}.list.example. +all",
		// limits
		"void3.example TXT v=spf1 a:v1.example a:v2.example a:v3.example ?all",
		"include-loop.example TXT v=spf1 include:include-loop.example -all",
	)
	cases := []struct {
		section, name, ip, sender string
		want                      spf.Result
	}{
		{"initial processing", "long label", "192.0.2.1", "a@" + strings.Repeat("t", 64) + ".toolong.example", spf.ResultNone},
		{"initial processing", "empty label", "192.0.2.1", "a@a..emptylabel.example", spf.ResultNone},
		{"initial processing", "DNS error", "192.0.2.1", "a@hosterror.example", spf.ResultTempError},
		{"initial processing", "no local part", "192.0.2.1", "@pass.example", spf.ResultPass},
		{"record lookup", "NXDOMAIN", "192.0.2.1", "a@nowhere.example", spf.ResultNone},
		{"selecting records", "no space after version", "192.0.2.1", "a@nospace1.example", spf.ResultNone},
		{"selecting records", "equals after version", "192.0.2.1", "a@nospace2.example", spf.ResultNone},
		{"selecting records", "spf2 ignored", "192.0.2.1", "a@spf2.example", spf.ResultFail},
		{"selecting records", "two v=spf1", "192.0.2.1", "a@twospf.example", spf.ResultPermError},
		{"selecting records", "case", "192.0.2.1", "a@case.example", spf.ResultPass},
		{"record evaluation", "extra spaces", "192.0.2.1", "a@spaces.example", spf.ResultPass},
		{"record evaluation", "= in a domain-spec", "192.0.2.1", "a@detect-modifier.example", spf.ResultPass},
		{"record evaluation", "default neutral", "192.0.2.1", "a@default.example", spf.ResultNeutral},
		{"record evaluation", "redirect after all", "192.0.2.1", "a@redirect-after-all.example", spf.ResultFail},
		{"record evaluation", "modifier without name", "192.0.2.1", "a@badmod.example", spf.ResultPermError},
		{"record evaluation", "modifier name starts with digit", "192.0.2.1", "a@numname.example", spf.ResultPermError},
		{"all", "argument", "192.0.2.1", "a@all-arg.example", spf.ResultPermError},
		{"all", "CIDR", "192.0.2.1", "a@all-cidr.example", spf.ResultPermError},
		{"all", "neutral", "192.0.2.1", "a@all-neutral.example", spf.ResultNeutral},
		{"ptr", "CIDR", "192.0.2.1", "a@ptr-cidr.example", spf.ResultPermError},
		{"ptr", "empty domain", "192.0.2.1", "a@ptr-empty.example", spf.ResultPermError},
		{"ptr", "match", "192.0.2.1", "a@ptr-match.example", spf.ResultPass},
		{"ptr", "no match", "192.0.2.2", "a@ptr-match.example", spf.ResultFail},
		{"a", "port", "192.0.2.1", "a@a-colon.example", spf.ResultPermError},
		{"a", "dual CIDR v4", "192.0.2.9", "a@a-dual-cidr.example", spf.ResultPass},
		{"a", "dual CIDR v6", "2001:db8::1", "a@a-dual-cidr.example", spf.ResultFail},
		{"a", "numeric top label", "192.0.2.1", "a@a-numeric-top.example", spf.ResultPermError},
		{"a", "dash at end of top label", "192.0.2.1", "a@a-dash-top.example", spf.ResultPermError},
		{"a", "only a top label", "192.0.2.1", "a@a-only-top.example", spf.ResultPermError},
		{"a", "IPv4 CIDR too long", "192.0.2.1", "a@a-bad-cidr4.example", spf.ResultPermError},
		{"a", "IPv6 CIDR too long", "192.0.2.1", "a@a-bad-cidr6.example", spf.ResultPermError},
		{"a", "several addresses", "192.0.2.1", "a@a-multi-ip.example", spf.ResultPass},
		{"include", "target without SPF", "192.0.2.1", "a@include-none.example", spf.ResultPermError},
		{"include", "softfail does not match", "192.0.2.1", "a@include-softfail.example", spf.ResultNeutral},
		{"include", "empty domain", "192.0.2.1", "a@include-empty.example", spf.ResultPermError},
		{"include", "CIDR", "192.0.2.1", "a@include-cidr.example", spf.ResultPermError},
		{"mx", "empty domain", "192.0.2.1", "a@mx-empty.example", spf.ResultPermError},
		{"mx", "no implicit MX", "192.0.2.1", "a@mx-implicit.example", spf.ResultFail},
		{"mx", "second MX, first without address", "192.0.2.1", "a@mx-multi.example", spf.ResultPass},
		{"exists", "empty domain", "192.0.2.1", "a@exists-empty.example", spf.ResultPermError},
		{"exists", "CIDR", "192.0.2.1", "a@exists-cidr.example", spf.ResultPermError},
		{"exists", "AAAA does not count", "2001:db8::1", "a@exists-v6.example", spf.ResultFail},
		{"ip4", "no address", "192.0.2.1", "a@ip4-noaddr.example", spf.ResultPermError},
		{"ip4", "short address", "192.0.2.1", "a@ip4-short.example", spf.ResultPermError},
		{"ip6", "IPv4-mapped network vs IPv4", "192.0.2.1", "a@ip4-mapped.example", spf.ResultFail},
		{"ip6", "::/0 vs IPv4", "192.0.2.1", "a@ip6-v4.example", spf.ResultFail},
		{"ip6", "CIDR too long", "2001:db8::1", "a@ip6-bad.example", spf.ResultPermError},
		{"exp", "fail", "192.0.2.1", "a@exp-fail.example", spf.ResultFail},
		{"exp", "twice", "192.0.2.1", "a@exp-twice.example", spf.ResultPermError},
		{"exp", "syntax error in exp=", "192.0.2.1", "a@exp-syntax.example", spf.ResultPermError},
		{"redirect", "target without SPF", "192.0.2.1", "a@redirect-none.example", spf.ResultPermError},
		{"redirect", "exp of the original dropped", "192.0.2.1", "a@redirect-cancels-exp.example", spf.ResultFail},
		{"modifiers", "unknown modifier", "192.0.2.1", "a@unknown-mod.example", spf.ResultFail},
		{"macros", "bad percent", "192.0.2.1", "a@macro-bad.example", spf.ResultPermError},
		{"macros", "reverse local-part", "192.0.2.1", "a-b@macro-lr.example", spf.ResultPass},
		{"macros", "IPv6 reverse", "2001:db8::1", "a@macro-v6.example", spf.ResultPass},
		{"macros", "exp-only letter", "192.0.2.1", "a@macro-exp-only.example", spf.ResultPermError},
		{"macros", "include target without a record", "192.0.2.1", "a@macro-trailing.example", spf.ResultPermError},
		{"limits", "three void lookups", "192.0.2.1", "a@void3.example", spf.ResultPermError},
		{"limits", "include loop", "192.0.2.1", "a@include-loop.example", spf.ResultPermError},
	}
	for _, c := range cases {
		got := spf.CheckMailFrom(context.Background(), mustAddr(c.ip), c.sender, testHELO, opts(z))
		want(t, c.section+": "+c.name, got, c.want)
	}
	if got := mailFrom(z, "192.0.2.1", "a@exp-fail.example"); got.Explanation != "192.0.2.1 is not allowed for exp-fail.example" {
		t.Errorf("exp: %q", got.Explanation)
	}
	if got := mailFrom(z, "192.0.2.1", "a@redirect-cancels-exp.example"); got.Explanation != "" {
		t.Errorf("redirect kept the original exp: %q", got.Explanation)
	}
}
