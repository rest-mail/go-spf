package spf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rest-mail/go-spf/pkg/spf/internal/idna"
)

// Result is the outcome of an SPF check (RFC 7208 §2.6). Its string value is
// the one Received-SPF and Authentication-Results (RFC 8601 spf=) carry.
type Result string

// The seven SPF results of RFC 7208 §2.6.
const (
	// ResultNone means no syntactically valid domain could be checked, or the
	// domain publishes no SPF record.
	ResultNone Result = "none"
	// ResultNeutral means the domain explicitly states nothing about the client.
	ResultNeutral Result = "neutral"
	// ResultPass means the client is authorized to use the identity.
	ResultPass Result = "pass"
	// ResultFail means the client is explicitly not authorized.
	ResultFail Result = "fail"
	// ResultSoftfail means the client is probably not authorized.
	ResultSoftfail Result = "softfail"
	// ResultTempError means a transient (usually DNS) error stopped the check.
	ResultTempError Result = "temperror"
	// ResultPermError means the domain's record could not be interpreted.
	ResultPermError Result = "permerror"
)

// DefaultTimeout bounds one evaluation when Options.Timeout is zero. RFC 7208
// §4.6.4 asks that the limit allow at least 20 seconds.
const DefaultTimeout = 20 * time.Second

// Response is the outcome of one check.
type Response struct {
	// Result is the SPF result.
	Result Result
	// Mechanism is the directive that decided the result, as written in the
	// record (for example "-all" or "include:_spf.example.com"), or "default"
	// when no mechanism matched and the record's implicit ?all applied. It is
	// empty when no record was evaluated to the end (none, temperror,
	// permerror).
	Mechanism string
	// Explanation is set only for a fail result: the domain's exp= text after
	// macro expansion (RFC 7208 §6.2), or empty when the record has no usable
	// exp= modifier. It is third-party text; show it as coming from the domain.
	Explanation string
	// Reason is a short human-readable account of how the result was reached.
	Reason string
}

// Resolver is the DNS the evaluator queries. Its methods match *net.Resolver,
// so net.DefaultResolver is used when Options.Resolver is nil.
//
// An implementation reports a name that does not exist (NXDOMAIN), or that has
// no records of the requested type, either by returning no records and a nil
// error or by returning a *net.DNSError whose IsNotFound field is true. Any
// other error, a timeout included, is a transient DNS failure and leads to
// temperror. LookupTXT returns one string per TXT record, with the record's
// character-strings concatenated without spaces, as net.Resolver does.
// LookupNetIP is called with network "ip4" for A records and "ip6" for AAAA
// records.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Options tune an evaluation. A nil *Options, or a zero field, takes the
// default described on the field.
type Options struct {
	// Resolver answers the DNS queries. Nil uses net.DefaultResolver.
	Resolver Resolver
	// Timeout bounds the wall-clock time of one evaluation, DNS included
	// (RFC 7208 §4.6.4); running over it gives temperror. Zero means
	// DefaultTimeout. A deadline on the context also applies.
	Timeout time.Duration
	// Receiver is the receiving host's domain name, which the %{r} macro of an
	// explanation expands to. Empty expands to "unknown".
	Receiver string
	// Now returns the current time for the %{t} macro of an explanation. Nil
	// uses time.Now.
	Now func() time.Time
}

// CheckHELO checks the "HELO" identity (RFC 7208 §2.3): whether ip may send
// mail as a host that greeted with helo. The check runs check_host() with helo
// as both the domain and the sender, so the sender macros see
// postmaster@<helo>. A HELO that is not a multi-label domain name, such as an
// address literal, gives none.
func CheckHELO(ctx context.Context, ip netip.Addr, helo string, opts *Options) Response {
	return CheckHost(ctx, ip, helo, helo, helo, opts)
}

// CheckMailFrom checks the "MAIL FROM" identity (RFC 7208 §2.4): whether ip may
// send mail with the reverse-path mailFrom. mailFrom is the address from the
// MAIL command, with or without angle brackets; a source route ("@a,@b:") is
// dropped. An empty mailFrom (the null reverse-path) checks postmaster@<helo>.
// helo is the HELO/EHLO name, which the %{h} macro expands to.
func CheckMailFrom(ctx context.Context, ip netip.Addr, mailFrom, helo string, opts *Options) Response {
	sender := strings.TrimSuffix(strings.TrimPrefix(mailFrom, "<"), ">")
	if strings.HasPrefix(sender, "@") {
		// A source route (RFC 5321 Appendix C) names relays, not the sender.
		if i := strings.IndexByte(sender, ':'); i >= 0 {
			sender = sender[i+1:]
		}
	}
	if sender == "" {
		return CheckHost(ctx, ip, helo, "postmaster@"+helo, helo, opts)
	}
	domain := sender
	if i := strings.LastIndexByte(sender, '@'); i >= 0 {
		domain = sender[i+1:]
	}
	return CheckHost(ctx, ip, domain, sender, helo, opts)
}

// CheckHost is the check_host() function of RFC 7208 §4. It evaluates the SPF
// policy of domain for a client at ip, where sender is the identity being
// checked (an address, or a bare domain whose local-part becomes
// "postmaster") and helo is the HELO/EHLO name for the %{h} macro. An
// IPv4-mapped IPv6 address is checked as the IPv4 address it carries. U-labels
// in domain, in sender's domain and in helo are converted to A-labels first
// (RFC 8616 §4).
func CheckHost(ctx context.Context, ip netip.Addr, domain, sender, helo string, opts *Options) Response {
	if opts == nil {
		opts = &Options{}
	}
	if !ip.IsValid() {
		return Response{Result: ResultPermError, Reason: "invalid client IP address"}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// RFC 8616 §4: U-labels become A-labels before the check, in the queried
	// domain and in the names the macros expand. The sender's local-part is
	// left as it is; an EAI local-part in %{s} or %{l} will rarely match.
	domain, helo = idna.ToALabels(domain), idna.ToALabels(helo)
	if i := strings.LastIndexByte(sender, '@'); i >= 0 {
		sender = sender[:i+1] + idna.ToALabels(sender[i+1:])
	} else {
		sender = idna.ToALabels(sender)
	}

	e := newEvaluator(ctx, ip, domain, sender, helo, opts)
	o := e.checkHost(strings.TrimSuffix(domain, "."))
	resp := Response{Result: o.result, Mechanism: o.mechanism, Reason: printable(o.reason)}
	if o.result == ResultFail && o.exp != nil {
		resp.Explanation = e.explain(o.exp, o.domain)
	}
	return resp
}
