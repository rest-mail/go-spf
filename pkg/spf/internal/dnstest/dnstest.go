// Package dnstest is the in-memory DNS that the go-spf tests evaluate records
// against. Zone satisfies spf.Resolver, so no test touches the network. It is
// internal: a test helper, not part of the library's API.
package dnstest

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Zone is an in-memory spf.Resolver.
//
// A name that has no record of any type does not exist (NXDOMAIN, a
// *net.DNSError with IsNotFound); a name that exists but has no record of the
// asked type answers with no records and a nil error (NODATA). Names are
// case-insensitive and a trailing dot is ignored.
type Zone struct {
	mu      sync.Mutex
	TXT     map[string][]string
	Addr    map[string][]netip.Addr
	MX      map[string][]string
	PTR     map[string][]string // keyed by IP address string
	Fail    map[string]error    // keyed by "TYPE name"
	Queries []string            // "TYPE name", in order
	MapV4   bool                // answer A queries with IPv4-mapped IPv6, as net.Resolver can
	Wait    time.Duration       // delay every answer, honouring the context
}

var (
	errServFail = &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	errTimeout  = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
)

// New builds a Zone from lines of "name TYPE data". TYPE is TXT (data is
// the rest of the line, spaces included; an empty data is an empty string),
// A or AAAA (an address), MX (a host name), PTR (name is an IP address, data a
// host name), or SERVFAIL / TIMEOUT (data is the query type that fails).
func New(lines ...string) *Zone {
	z := &Zone{
		TXT:  map[string][]string{},
		Addr: map[string][]netip.Addr{},
		MX:   map[string][]string{},
		PTR:  map[string][]string{},
		Fail: map[string]error{},
	}
	for _, line := range lines {
		name, rest, _ := strings.Cut(line, " ")
		typ, data, _ := strings.Cut(rest, " ")
		name = Canon(name)
		switch typ {
		case "TXT":
			z.TXT[name] = append(z.TXT[name], data)
		case "A", "AAAA":
			z.Addr[name] = append(z.Addr[name], netip.MustParseAddr(data))
		case "MX":
			z.MX[name] = append(z.MX[name], data)
		case "PTR":
			z.PTR[name] = append(z.PTR[name], data)
		case "SERVFAIL":
			z.Fail[data+" "+name] = errServFail
		case "TIMEOUT":
			z.Fail[data+" "+name] = errTimeout
		default:
			panic("dnstest: bad line " + line)
		}
	}
	return z
}

// Canon lower-cases a DNS name and drops a trailing dot, as Zone does with the
// names it is asked for.
func Canon(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (z *Zone) exists(name string) bool {
	_, t := z.TXT[name]
	_, a := z.Addr[name]
	_, m := z.MX[name]
	return t || a || m
}

// answer logs a query and returns its injected error, the NXDOMAIN error, or
// nil when the name exists.
func (z *Zone) answer(ctx context.Context, typ, name string) error {
	if z.Wait > 0 {
		select {
		case <-time.After(z.Wait):
		case <-ctx.Done():
			return &net.DNSError{Err: ctx.Err().Error(), Name: name, IsTimeout: true}
		}
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.Queries = append(z.Queries, typ+" "+name)
	if err := z.Fail[typ+" "+name]; err != nil {
		return err
	}
	if typ != "PTR" && !z.exists(name) {
		return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return nil
}

func (z *Zone) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = Canon(name)
	if err := z.answer(ctx, "TXT", name); err != nil {
		return nil, err
	}
	return z.TXT[name], nil
}

func (z *Zone) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	host = Canon(host)
	typ := map[string]string{"ip4": "A", "ip6": "AAAA"}[network]
	if err := z.answer(ctx, typ, host); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range z.Addr[host] {
		if a.Is4() == (network == "ip4") {
			if z.MapV4 && a.Is4() {
				a = netip.AddrFrom16(a.As16())
			}
			out = append(out, a)
		}
	}
	return out, nil
}

func (z *Zone) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	name = Canon(name)
	if err := z.answer(ctx, "MX", name); err != nil {
		return nil, err
	}
	var out []*net.MX
	for i, h := range z.MX[name] {
		if !strings.HasSuffix(h, ".") {
			h += "."
		}
		out = append(out, &net.MX{Host: h, Pref: uint16(10 * (i + 1))})
	}
	return out, nil
}

func (z *Zone) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := z.answer(ctx, "PTR", addr); err != nil {
		return nil, err
	}
	names, ok := z.PTR[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

// Count returns how many queries of the form "TYPE name" were made; an empty
// name counts every query of that type.
func (z *Zone) Count(typ, name string) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := 0
	for _, q := range z.Queries {
		if q == typ+" "+name || (name == "" && strings.HasPrefix(q, typ+" ")) {
			n++
		}
	}
	return n
}
