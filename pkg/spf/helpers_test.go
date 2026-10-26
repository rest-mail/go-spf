package spf

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rest-mail/go-spf/pkg/spf/internal/dnstest"
	"github.com/rest-mail/go-spf/pkg/spf/internal/syntax"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testHELO is the HELO name the tests' clients greet with.
const testHELO = "mail.example.net"

// zone builds the in-memory DNS a test evaluates against; see dnstest.New.
func zone(lines ...string) *dnstest.Zone { return dnstest.New(lines...) }

// mailFrom runs CheckMailFrom against z with a fixed clock and receiver.
func mailFrom(z *dnstest.Zone, ip, sender string) Response {
	return CheckMailFrom(context.Background(), netip.MustParseAddr(ip), sender, testHELO, opts(z))
}

func opts(z *dnstest.Zone) *Options {
	return &Options{
		Resolver: z,
		Receiver: "mx.receiver.example",
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	}
}

// want fails the test unless got carries the wanted result.
func want(t *testing.T, label string, got Response, result Result) {
	t.Helper()
	if got.Result != result {
		t.Errorf("%s: result = %s (%s), want %s", label, got.Result, got.Reason, result)
	}
}

// expandFor expands a domain-spec for a test evaluator. It fails the test on a
// syntax error.
func expandFor(t *testing.T, z *dnstest.Zone, spec, ip, sender, domain string, explain bool) string {
	t.Helper()
	toks, err := syntax.ParseMacroString(spec, explain)
	if err != nil {
		t.Fatalf("parse %q: %v", spec, err)
	}
	e := newEvaluator(context.Background(), netip.MustParseAddr(ip), domain, sender, "mail.example.net", opts(z))
	s, exc := e.expand(toks, domain, !explain)
	if exc != nil {
		t.Fatalf("expand %q: %s", spec, exc.reason)
	}
	return s
}
