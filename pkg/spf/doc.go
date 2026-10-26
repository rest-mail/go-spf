// Package spf evaluates Sender Policy Framework policies (SPF, RFC 7208).
//
// SPF lets a domain publish, in a DNS TXT record, which hosts may send mail
// that uses the domain in the SMTP "MAIL FROM" or "HELO" identity. A receiver
// evaluates that record against the connecting client's IP address and gets
// one of seven results: none, neutral, pass, fail, softfail, temperror or
// permerror.
//
// The package implements the whole check_host() function of RFC 7208 section
// 4: every mechanism (all, include, a, mx, ptr, ip4, ip6, exists), both
// modifiers (redirect, exp), the full macro language of section 7, and the
// processing limits of section 4.6.4. It depends only on the Go standard
// library. All DNS goes through the Resolver interface, which *net.Resolver
// satisfies, so tests and callers with their own DNS can supply another.
//
// # Checking a message
//
// RFC 7208 recommends checking the HELO identity first, then the MAIL FROM
// identity when the HELO check reached no definitive result. A nil *Options
// uses the system resolver and the default limits:
//
//	ip := netip.MustParseAddr("192.0.2.1")
//	helo := spf.CheckHELO(ctx, ip, "mail.example.com", nil)
//	from := spf.CheckMailFrom(ctx, ip, "alice@example.com", "mail.example.com", nil)
//	fmt.Println(helo.Result, from.Result)
//
// CheckHost is check_host() itself, for callers that choose the identity and
// domain themselves.
package spf
