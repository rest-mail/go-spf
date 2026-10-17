package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Fuzz tests. Their seed corpora are in testdata/fuzz/<FuzzName>; CI runs each
// target for a fixed time, and any crash it finds is fixed and kept there as a
// seed.

var results = map[Result]bool{
	ResultNone: true, ResultNeutral: true, ResultPass: true, ResultFail: true,
	ResultSoftfail: true, ResultTempError: true, ResultPermError: true,
}

// FuzzParseRecord parses arbitrary records. A record that parses must hold
// only well-formed directives, and must evaluate to one of the seven results.
//
// checklist: SPF-EVAL-06 SPF-SEC-01
func FuzzParseRecord(f *testing.F) {
	f.Add("v=spf1 a mx -all")
	f.Fuzz(func(t *testing.T, txt string) {
		rec, err := parseRecord(txt)
		if err != nil {
			return
		}
		if !isSPFRecord(txt) {
			t.Fatalf("parsed a record without the v=spf1 version: %q", txt)
		}
		for _, d := range rec.directives {
			if !strings.Contains("+-~?", string(d.qualifier)) || d.cidr4 < 0 || d.cidr4 > 32 || d.cidr6 < 0 || d.cidr6 > 128 {
				t.Fatalf("bad directive %+v in %q", d, txt)
			}
			switch d.name {
			case "all", "include", "a", "mx", "ptr", "exists":
			case "ip4", "ip6":
				if !d.prefix.IsValid() {
					t.Fatalf("invalid network in %q", d.text)
				}
			default:
				t.Fatalf("unknown mechanism %q parsed", d.name)
			}
		}
		z := zone("192.0.2.1 PTR host.example.com", "host.example.com A 192.0.2.1")
		z.txt["example.com"] = []string{txt}
		if got := mailFrom(z, "192.0.2.1", "user@example.com"); !results[got.Result] {
			t.Fatalf("result %q for %q", got.Result, txt)
		}
	})
}

// FuzzExpandMacros expands arbitrary macro-strings for arbitrary senders. A
// target-name must come out as a valid domain of at most 253 characters, and
// expansion must stay bounded.
//
// checklist: SPF-MACRO-04 SPF-SEC-01
func FuzzExpandMacros(f *testing.F) {
	f.Add("%{ir}.%{l1r-}.lp._spf.%{d2}", "strong-bad", true)
	f.Fuzz(func(t *testing.T, spec, local string, v4 bool) {
		ip := mustAddr("2001:db8::cb01")
		if v4 {
			ip = mustAddr("192.0.2.3")
		}
		z := zone("192.0.2.3 PTR mx.example.org", "mx.example.org A 192.0.2.3")
		e := newEvaluator(context.Background(), ip, "email.example.com", local+"@email.example.com", local, opts(z))
		if toks, err := checkDomainSpec(spec); err == nil {
			name, ok, exc := e.target(toks, "email.example.com", true)
			if exc == nil && ok && (len(name) > 253 || !validDomain(name)) {
				t.Fatalf("target %q from %q is not a valid domain", name, spec)
			}
		}
		if toks, err := parseMacroString(spec, true); err == nil {
			s, exc := e.expand(toks, "email.example.com", false)
			if exc != nil || len(s) > maxExpansion+3*(len(local)+len(spec)+300) {
				t.Fatalf("explanation expansion of %q: %d bytes, %v", spec, len(s), exc)
			}
		}
	})
}

// FuzzCheckHost evaluates arbitrary records and senders end to end. The result
// must be one of the seven, and the text returned printable and bounded.
//
// checklist: SPF-EVAL-01 SPF-SEC-01
func FuzzCheckHost(f *testing.F) {
	f.Add("v=spf1 include:inc.example.com -all exp=exp.example.com", "user@example.com", "192.0.2.1")
	f.Fuzz(func(t *testing.T, txt, sender, ip string) {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			addr = mustAddr("192.0.2.1")
		}
		z := zone(
			"inc.example.com TXT v=spf1 a:host.example.com ~all",
			"exp.example.com TXT %{i} is not allowed to send for %{o}",
			"host.example.com A 192.0.2.1",
			"host.example.com AAAA 2001:db8::1",
			"example.com MX host.example.com",
			"192.0.2.1 PTR host.example.com",
		)
		z.txt["example.com"] = []string{txt}
		got := CheckMailFrom(context.Background(), addr, sender, "mail.example.net", opts(z))
		if !results[got.Result] {
			t.Fatalf("result %q", got.Result)
		}
		if printable(got.Reason) != got.Reason || printable(got.Explanation) != got.Explanation || len(got.Explanation) > maxExplanation {
			t.Fatalf("unsafe text: %+v", got)
		}
		if got.Explanation != "" && got.Result != ResultFail {
			t.Fatalf("explanation on %s", got.Result)
		}
	})
}
