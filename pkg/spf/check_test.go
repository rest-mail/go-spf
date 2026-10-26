package spf

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rest-mail/go-spf/pkg/spf/internal/syntax"
)

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
	z.Wait = 20 * time.Millisecond
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
		r, _ := syntax.ParseRecord(rec)
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
