package syntax

import (
	"testing"
)

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
		if _, err := ParseRecord(rec); err != nil {
			t.Errorf("ParseRecord(%q) = %v, want valid", rec, err)
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
		if _, err := ParseRecord(rec); err == nil {
			t.Errorf("ParseRecord(%q) = nil, want a syntax error", rec)
		}
	}
	if _, err := ParseRecord("not spf"); err == nil {
		t.Error("ParseRecord accepted a non-SPF string")
	}
}
