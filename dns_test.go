package spf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNS is an in-memory Resolver. No test touches the network.
//
// A name that has no record of any type does not exist (NXDOMAIN, a
// *net.DNSError with IsNotFound); a name that exists but has no record of the
// asked type answers with no records and a nil error (NODATA). Names are
// case-insensitive and a trailing dot is ignored.
type fakeDNS struct {
	mu      sync.Mutex
	txt     map[string][]string
	addr    map[string][]netip.Addr
	mx      map[string][]string
	ptr     map[string][]string // keyed by IP address string
	fail    map[string]error    // keyed by "TYPE name"
	queries []string            // "TYPE name", in order
	mapV4   bool                // answer A queries with IPv4-mapped IPv6, as net.Resolver can
	wait    time.Duration       // delay every answer, honouring the context
}

var (
	errServFail = &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	errTimeout  = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
)

// zone builds a fakeDNS from lines of "name TYPE data". TYPE is TXT (data is
// the rest of the line, spaces included; an empty data is an empty string),
// A or AAAA (an address), MX (a host name), PTR (name is an IP address, data a
// host name), or SERVFAIL / TIMEOUT (data is the query type that fails).
func zone(lines ...string) *fakeDNS {
	z := &fakeDNS{
		txt:  map[string][]string{},
		addr: map[string][]netip.Addr{},
		mx:   map[string][]string{},
		ptr:  map[string][]string{},
		fail: map[string]error{},
	}
	for _, line := range lines {
		name, rest, _ := strings.Cut(line, " ")
		typ, data, _ := strings.Cut(rest, " ")
		name = canon(name)
		switch typ {
		case "TXT":
			z.txt[name] = append(z.txt[name], data)
		case "A", "AAAA":
			z.addr[name] = append(z.addr[name], netip.MustParseAddr(data))
		case "MX":
			z.mx[name] = append(z.mx[name], data)
		case "PTR":
			z.ptr[name] = append(z.ptr[name], data)
		case "SERVFAIL":
			z.fail[data+" "+name] = errServFail
		case "TIMEOUT":
			z.fail[data+" "+name] = errTimeout
		default:
			panic("zone: bad line " + line)
		}
	}
	return z
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func canon(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (z *fakeDNS) exists(name string) bool {
	_, t := z.txt[name]
	_, a := z.addr[name]
	_, m := z.mx[name]
	return t || a || m
}

// answer logs a query and returns its injected error, the NXDOMAIN error, or
// nil when the name exists.
func (z *fakeDNS) answer(ctx context.Context, typ, name string) error {
	if z.wait > 0 {
		select {
		case <-time.After(z.wait):
		case <-ctx.Done():
			return &net.DNSError{Err: ctx.Err().Error(), Name: name, IsTimeout: true}
		}
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.queries = append(z.queries, typ+" "+name)
	if err := z.fail[typ+" "+name]; err != nil {
		return err
	}
	if typ != "PTR" && !z.exists(name) {
		return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return nil
}

func (z *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = canon(name)
	if err := z.answer(ctx, "TXT", name); err != nil {
		return nil, err
	}
	return z.txt[name], nil
}

func (z *fakeDNS) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	host = canon(host)
	typ := map[string]string{"ip4": "A", "ip6": "AAAA"}[network]
	if err := z.answer(ctx, typ, host); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range z.addr[host] {
		if a.Is4() == (network == "ip4") {
			if z.mapV4 && a.Is4() {
				a = netip.AddrFrom16(a.As16())
			}
			out = append(out, a)
		}
	}
	return out, nil
}

func (z *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	name = canon(name)
	if err := z.answer(ctx, "MX", name); err != nil {
		return nil, err
	}
	var out []*net.MX
	for i, h := range z.mx[name] {
		if !strings.HasSuffix(h, ".") {
			h += "."
		}
		out = append(out, &net.MX{Host: h, Pref: uint16(10 * (i + 1))})
	}
	return out, nil
}

func (z *fakeDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := z.answer(ctx, "PTR", addr); err != nil {
		return nil, err
	}
	names, ok := z.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

// count returns how many queries of the form "TYPE name" were made; an empty
// name counts every query of that type.
func (z *fakeDNS) count(typ, name string) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := 0
	for _, q := range z.queries {
		if q == typ+" "+name || (name == "" && strings.HasPrefix(q, typ+" ")) {
			n++
		}
	}
	return n
}

// testHELO is the HELO name the tests' clients greet with.
const testHELO = "mail.example.net"

// mailFrom runs CheckMailFrom against z with a fixed clock and receiver.
func mailFrom(z *fakeDNS, ip, sender string) Response {
	return CheckMailFrom(context.Background(), netip.MustParseAddr(ip), sender, testHELO, opts(z))
}

func opts(z *fakeDNS) *Options {
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
func expandFor(t *testing.T, z *fakeDNS, spec, ip, sender, domain string, explain bool) string {
	t.Helper()
	toks, err := parseMacroString(spec, explain)
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
