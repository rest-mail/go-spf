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
//
// checklist: SPF-MOD-09
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

// tracingDNS records the actual library lookup order. Only DNS is replaced;
// each example runs the public SPF evaluator against these records.
type tracingDNS struct {
	staticDNS
	queries []string
}

func (d *tracingDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	d.queries = append(d.queries, name)
	if name == "error.example" {
		return nil, &net.DNSError{Err: "server failure", IsTemporary: true}
	}
	return d.staticDNS.LookupTXT(ctx, name)
}

// ExampleCheckMailFrom_identityChecks demonstrates a conservative caller policy:
// always check MAIL FROM, even when HELO reaches a definitive result. This
// satisfies the required fallback for every nondefinitive HELO result and when
// no HELO check is performed. The query trace proves HELO runs first when used.
// The library itself does not choose which identities a receiver checks.
//
// checklist: SPF-ID-06 SPF-ID-07
func ExampleCheckMailFrom_identityChecks() {
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.25")
	for _, helo := range []string{
		"missing.example", "neutral.example", "softfail.example", "error.example",
		"broken.example", "pass.example", "fail.example", "unchecked",
	} {
		dns := &tracingDNS{staticDNS: staticDNS{
			"neutral.example":  {"v=spf1 ?all"},
			"softfail.example": {"v=spf1 ~all"},
			"broken.example":   {"v=spf1 invalid"},
			"pass.example":     {"v=spf1 +all"},
			"fail.example":     {"v=spf1 -all"},
			"sender.example":   {"v=spf1 ip4:192.0.2.25 -all"},
		}}
		opts := &spf.Options{Resolver: dns}
		heloResult := "unchecked"
		if helo != "unchecked" {
			heloResult = string(spf.CheckHELO(ctx, ip, helo, opts).Result)
		}
		from := spf.CheckMailFrom(ctx, ip, "alice@sender.example", helo, opts)
		fmt.Printf("helo=%s mailfrom=%s queries=%v\n", heloResult, from.Result, dns.queries)
	}
	// Output:
	// helo=none mailfrom=pass queries=[missing.example sender.example]
	// helo=neutral mailfrom=pass queries=[neutral.example sender.example]
	// helo=softfail mailfrom=pass queries=[softfail.example sender.example]
	// helo=temperror mailfrom=pass queries=[error.example sender.example]
	// helo=permerror mailfrom=pass queries=[broken.example sender.example]
	// helo=pass mailfrom=pass queries=[pass.example sender.example]
	// helo=fail mailfrom=pass queries=[fail.example sender.example]
	// helo=unchecked mailfrom=pass queries=[sender.example]
}

// ExampleResult_receiverPolicy demonstrates one receiver's SPF-only disposition.
// Other checks (for example spam filtering) may still reject mail. Neutral and
// none take exactly the same action, and softfail alone never causes rejection.
// Fail and error cases are included to make the distinction observable; callers
// choose their own policy and send any SMTP replies themselves.
//
// checklist: SPF-RESULT-02 SPF-RESULT-05
func ExampleResult_receiverPolicy() {
	opts := &spf.Options{Resolver: &tracingDNS{staticDNS: staticDNS{
		"neutral.example":  {"v=spf1 ?all"},
		"softfail.example": {"v=spf1 ~all"},
		"pass.example":     {"v=spf1 +all"},
		"fail.example":     {"v=spf1 -all"},
		"broken.example":   {"v=spf1 invalid"},
	}}}
	for _, domain := range []string{
		"missing.example", "neutral.example", "softfail.example", "pass.example",
		"fail.example", "error.example", "broken.example",
	} {
		response := spf.CheckMailFrom(context.Background(), netip.MustParseAddr("192.0.2.25"),
			"alice@"+domain, "mail.sender.example", opts)
		var action string
		switch response.Result {
		case spf.ResultNone, spf.ResultNeutral, spf.ResultSoftfail, spf.ResultPass:
			action = "continue other checks"
		case spf.ResultFail:
			action = "reject"
		case spf.ResultTempError:
			action = "defer"
		case spf.ResultPermError:
			action = "reject invalid policy"
		}
		fmt.Printf("%s: %s\n", response.Result, action)
	}
	// Output:
	// none: continue other checks
	// neutral: continue other checks
	// softfail: continue other checks
	// pass: continue other checks
	// fail: reject
	// temperror: defer
	// permerror: reject invalid policy
}
