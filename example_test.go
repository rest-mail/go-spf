package spf_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/rest-mail/go-spf"
)

// staticDNS is a tiny in-memory spf.Resolver, so the example needs no real
// DNS. In production, leave Options.Resolver nil to use the system resolver.
type staticDNS map[string][]string

func (d staticDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := d[name]; ok {
		return txt, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (staticDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (staticDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (staticDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

// Example checks a message's HELO and MAIL FROM identities. RFC 7208
// recommends checking HELO first; whether a HELO result settles the matter is
// the receiver's policy.
func Example() {
	opts := &spf.Options{Resolver: staticDNS{
		"mail.example.com": {"v=spf1 ip4:192.0.2.25 -all"},
		"example.com":      {"v=spf1 ip4:192.0.2.0/24 -all exp=why.example.com"},
		"why.example.com":  {"%{i} may not send mail for %{d}"},
	}}
	ctx := context.Background()

	for _, ip := range []string{"192.0.2.25", "198.51.100.7"} {
		client := netip.MustParseAddr(ip)
		helo := spf.CheckHELO(ctx, client, "mail.example.com", opts)
		from := spf.CheckMailFrom(ctx, client, "alice@example.com", "mail.example.com", opts)
		fmt.Printf("%s: helo=%s mailfrom=%s (%s)\n", ip, helo.Result, from.Result, from.Mechanism)
		if from.Explanation != "" {
			fmt.Printf("  example.com explains: %s\n", from.Explanation)
		}
	}
	// Output:
	// 192.0.2.25: helo=pass mailfrom=pass (ip4:192.0.2.0/24)
	// 198.51.100.7: helo=fail mailfrom=fail (-all)
	//   example.com explains: 198.51.100.7 may not send mail for example.com
}
