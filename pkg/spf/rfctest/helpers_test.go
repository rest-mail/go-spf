package rfctest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rest-mail/go-spf/pkg/spf"
	"github.com/rest-mail/go-spf/pkg/spf/internal/dnstest"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testHELO is the HELO name the tests' clients greet with.
const testHELO = "mail.example.net"

// zone builds the in-memory DNS a test evaluates against; see dnstest.New.
func zone(lines ...string) *dnstest.Zone { return dnstest.New(lines...) }

// mailFrom runs CheckMailFrom against z with a fixed clock and receiver.
func mailFrom(z *dnstest.Zone, ip, sender string) spf.Response {
	return spf.CheckMailFrom(context.Background(), netip.MustParseAddr(ip), sender, testHELO, opts(z))
}

func opts(z *dnstest.Zone) *spf.Options {
	return &spf.Options{
		Resolver: z,
		Receiver: "mx.receiver.example",
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	}
}

// want fails the test unless got carries the wanted result.
func want(t *testing.T, label string, got spf.Response, result spf.Result) {
	t.Helper()
	if got.Result != result {
		t.Errorf("%s: result = %s (%s), want %s", label, got.Result, got.Reason, result)
	}
}
