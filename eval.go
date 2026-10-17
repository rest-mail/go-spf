package spf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// RFC 7208 §4.6.4 processing limits.
const (
	maxLookups     = 10 // terms that query DNS: include, a, mx, ptr, exists, redirect
	maxVoidLookups = 2  // terms whose lookup found no such name or no records
	maxMXNames     = 10 // MX names an mx term may resolve
	maxPTRNames    = 10 // PTR names a ptr term or %{p} may resolve
)

// Defensive bounds of this implementation.
const (
	// maxExpansion bounds a macro expansion. A longer domain-spec expansion is
	// treated as a malformed name; no real record comes near it, and it stops a
	// hostile record from making the evaluator build huge strings.
	maxExpansion = 8192
	// maxExplanation bounds the explanation string, which RFC 7208 §6.2 allows
	// so that it fits an SMTP reply line.
	maxExplanation = 400
)

// outcome is the result of one check_host() evaluation.
type outcome struct {
	result    Result
	reason    string
	mechanism string       // the deciding directive, or "default"
	exp       []macroToken // exp= of the record whose mechanism gave fail
	domain    string       // that record's <domain>, for its macros
}

func fail(result Result, reason string) outcome { return outcome{result: result, reason: reason} }

// evaluator holds the state of one check: the arguments that stay fixed
// through include and redirect, and the counters that enforce the §4.6.4
// limits across the whole evaluation (§4.1).
type evaluator struct {
	ctx      context.Context
	resolver Resolver
	ip       netip.Addr
	network  string // "ip4" or "ip6": the address lookups ip is compared with
	sender   string // %{s}
	local    string // %{l}
	senderDN string // %{o}
	helo     string // %{h}
	receiver string // %{r}
	now      func() time.Time

	lookups int
	voids   int

	ptrDone  bool     // the PTR names of ip have been fetched
	ptrNames []string // validated names of ip (§5.5), for ptr and %{p}
}

func newEvaluator(ctx context.Context, ip netip.Addr, domain, sender, helo string, opts *Options) *evaluator {
	e := &evaluator{
		ctx:      ctx,
		resolver: opts.Resolver,
		ip:       ip.Unmap().WithZone(""),
		helo:     helo,
		receiver: opts.Receiver,
		now:      opts.Now,
	}
	if e.resolver == nil {
		e.resolver = net.DefaultResolver
	}
	if e.now == nil {
		e.now = time.Now
	}
	e.network = "ip6"
	if e.ip.Is4() {
		e.network = "ip4"
	}
	// §4.3: a sender without a local-part gets "postmaster".
	e.local, e.senderDN = "", sender
	if i := strings.LastIndexByte(sender, '@'); i >= 0 {
		e.local, e.senderDN = sender[:i], sender[i+1:]
	}
	if e.local == "" {
		e.local = "postmaster"
	}
	e.senderDN = strings.TrimSuffix(e.senderDN, ".")
	if e.senderDN == "" {
		e.senderDN = strings.TrimSuffix(domain, ".")
	}
	e.sender = e.local + "@" + e.senderDN
	return e
}

// checkHost evaluates the SPF record of domain (§4.3 to §4.7).
func (e *evaluator) checkHost(domain string) outcome {
	if !validDomain(domain) {
		return fail(ResultNone, "no valid domain to check: "+strconv.Quote(domain))
	}
	txts, err := e.lookupTXT(domain)
	if err != nil {
		if notFound(err) {
			return fail(ResultNone, domain+" does not exist")
		}
		return fail(ResultTempError, "TXT lookup for "+domain+": "+err.Error())
	}
	var spf []string
	for _, t := range txts {
		if isSPFRecord(t) {
			spf = append(spf, t)
		}
	}
	switch len(spf) {
	case 0:
		return fail(ResultNone, domain+" publishes no SPF record")
	case 1:
	default:
		return fail(ResultPermError, domain+" publishes more than one SPF record")
	}
	rec, err := parseRecord(spf[0])
	if err != nil {
		return fail(ResultPermError, "SPF record of "+domain+": "+err.Error())
	}
	return e.evaluate(domain, rec)
}

// evaluate runs the mechanisms of rec left to right (§4.6.2), then the
// redirect modifier if none matched (§6.1), else the default neutral (§4.7).
// A record with an "all" mechanism never reaches redirect: "all" always
// matches, which is what §5.1 and §6.1 require.
func (e *evaluator) evaluate(domain string, rec *record) outcome {
	for i := range rec.directives {
		d := &rec.directives[i]
		matched, exc := e.match(domain, d)
		if exc != nil {
			return *exc
		}
		if matched {
			o := outcome{result: qualifierResult(d.qualifier), mechanism: d.text, reason: "matched " + d.text}
			if o.result == ResultFail {
				o.exp, o.domain = rec.exp, domain
			}
			return o
		}
	}
	if rec.redirect == nil {
		return outcome{result: ResultNeutral, mechanism: "default", reason: "no mechanism matched"}
	}
	if exc := e.countLookup(); exc != nil {
		return *exc
	}
	target, ok, exc := e.target(rec.redirect, domain, true)
	if exc != nil {
		return *exc
	}
	if !ok {
		return fail(ResultPermError, "redirect target is not a valid domain")
	}
	o := e.checkHost(target)
	if o.result == ResultNone {
		return fail(ResultPermError, "redirect="+target+": "+o.reason)
	}
	return o
}

// match evaluates one mechanism. It returns whether it matched, or a non-nil
// outcome for an exception (temperror or permerror) that ends evaluation.
func (e *evaluator) match(domain string, d *directive) (bool, *outcome) {
	switch d.name {
	case "all":
		return true, nil
	case "ip4", "ip6":
		return d.prefix.Contains(e.ip), nil
	}
	if exc := e.countLookup(); exc != nil {
		return false, exc
	}
	target, ok, exc := e.target(d.spec, domain, true)
	if exc != nil {
		return false, exc
	}
	switch d.name {
	case "include":
		return e.matchInclude(target, ok)
	case "ptr":
		return e.matchPTR(target, ok)
	}
	if !ok {
		// §4.8 leaves a malformed target-name to the implementation; it is
		// treated as a name that does not exist, so as a void lookup.
		return false, e.countVoid()
	}
	switch d.name {
	case "a":
		addrs, exc := e.lookupAddrs(target, e.network)
		return e.anyMatch(addrs, d), exc
	case "mx":
		return e.matchMX(target, d)
	default: // exists: an A lookup whatever the client's family (§5.7)
		addrs, exc := e.lookupAddrs(target, "ip4")
		return len(addrs) > 0, exc
	}
}

// matchInclude evaluates include (§5.2) by the table there: pass matches;
// fail, softfail and neutral do not; temperror stays temperror; permerror and
// none become permerror.
func (e *evaluator) matchInclude(target string, ok bool) (bool, *outcome) {
	if !ok {
		return false, &outcome{result: ResultPermError, reason: "include target is not a valid domain"}
	}
	o := e.checkHost(target)
	switch o.result {
	case ResultPass:
		return true, nil
	case ResultFail, ResultSoftfail, ResultNeutral:
		return false, nil
	case ResultTempError:
		return false, &outcome{result: ResultTempError, reason: "include:" + target + ": " + o.reason}
	default:
		return false, &outcome{result: ResultPermError, reason: "include:" + target + ": " + o.reason}
	}
}

// matchMX evaluates mx (§5.4): the address records of each MX name, with no
// fallback to the target's own addresses when it has no MX (§5.4) and at most
// maxMXNames names (§4.6.4).
func (e *evaluator) matchMX(target string, d *directive) (bool, *outcome) {
	if err := e.ctx.Err(); err != nil {
		return false, timedOut(err)
	}
	mxs, err := e.resolver.LookupMX(e.ctx, target)
	if err != nil && !notFound(err) {
		return false, &outcome{result: ResultTempError, reason: "MX lookup for " + target + ": " + err.Error()}
	}
	if len(mxs) == 0 {
		return false, e.countVoid()
	}
	if len(mxs) > maxMXNames {
		return false, &outcome{result: ResultPermError, reason: "MX of " + target + " lists more than 10 names"}
	}
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			continue // a null MX (RFC 7505) names no host
		}
		addrs, exc := e.queryAddrs(host, e.network)
		if exc != nil {
			return false, exc
		}
		if e.anyMatch(addrs, d) {
			return true, nil
		}
	}
	return false, nil
}

// matchPTR evaluates ptr (§5.5): it matches when a validated name of the
// client is the target or a subdomain of it. DNS errors make it not match; a
// PTR lookup that finds nothing is a void lookup.
func (e *evaluator) matchPTR(target string, ok bool) (bool, *outcome) {
	if !ok {
		return false, nil
	}
	names, void := e.validatedNames()
	if void {
		if exc := e.countVoid(); exc != nil {
			return false, exc
		}
	}
	target = strings.ToLower(target)
	for _, name := range names {
		if name == target || strings.HasSuffix(name, "."+target) {
			return true, nil
		}
	}
	return false, nil
}

// validatedNames returns the client's validated domain names (§5.5): the
// first maxPTRNames PTR names of ip whose own addresses include ip. The PTR
// lookup is made once per evaluation; void reports that this call made it and
// it found no names.
func (e *evaluator) validatedNames() (names []string, void bool) {
	if e.ptrDone {
		return e.ptrNames, false
	}
	e.ptrDone = true
	if e.ctx.Err() != nil {
		return nil, false
	}
	ptrs, err := e.resolver.LookupAddr(e.ctx, e.ip.String())
	if err != nil {
		return nil, notFound(err)
	}
	if len(ptrs) > maxPTRNames {
		ptrs = ptrs[:maxPTRNames]
	}
	for _, name := range ptrs {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		addrs, exc := e.queryAddrs(name, e.network)
		if exc != nil {
			continue // a lookup error skips this name (§5.5)
		}
		for _, a := range addrs {
			if a.Unmap() == e.ip {
				e.ptrNames = append(e.ptrNames, name)
				break
			}
		}
	}
	return e.ptrNames, len(ptrs) == 0
}

// validatedName is the value of %{p} (§7.3): the domain itself if validated,
// else a validated subdomain of it, else any validated name, else "unknown".
func (e *evaluator) validatedName(domain string) string {
	names, _ := e.validatedNames()
	domain = strings.ToLower(domain)
	for _, n := range names {
		if n == domain {
			return n
		}
	}
	for _, n := range names {
		if strings.HasSuffix(n, "."+domain) {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return "unknown"
}

// anyMatch reports whether ip is in the network of any of addrs under d's
// prefix lengths (§5).
func (e *evaluator) anyMatch(addrs []netip.Addr, d *directive) bool {
	bits := d.cidr4
	if e.network == "ip6" {
		bits = d.cidr6
	}
	for _, a := range addrs {
		if p, err := a.Unmap().Prefix(bits); err == nil && p.Contains(e.ip) {
			return true
		}
	}
	return false
}

// lookupAddrs is the address lookup of an a or exists term: a missing name or
// an empty answer is a void lookup, and any other error a temperror (§5).
func (e *evaluator) lookupAddrs(name, network string) ([]netip.Addr, *outcome) {
	addrs, exc := e.queryAddrs(name, network)
	if exc == nil && len(addrs) == 0 {
		exc = e.countVoid()
	}
	return addrs, exc
}

// queryAddrs looks up the addresses of name in one family. A missing name is
// an empty answer; any other error is a temperror.
func (e *evaluator) queryAddrs(name, network string) ([]netip.Addr, *outcome) {
	if err := e.ctx.Err(); err != nil {
		return nil, timedOut(err)
	}
	addrs, err := e.resolver.LookupNetIP(e.ctx, network, name)
	if err != nil && !notFound(err) {
		return nil, &outcome{result: ResultTempError, reason: "address lookup for " + name + ": " + err.Error()}
	}
	return addrs, nil
}

// lookupTXT fetches the TXT records of name, after checking the time limit.
func (e *evaluator) lookupTXT(name string) ([]string, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	return e.resolver.LookupTXT(e.ctx, name)
}

// countLookup charges one DNS-querying term against the limit of §4.6.4.
func (e *evaluator) countLookup() *outcome {
	e.lookups++
	if e.lookups > maxLookups {
		return &outcome{result: ResultPermError, reason: "more than 10 DNS-querying terms"}
	}
	return nil
}

// countVoid charges one void lookup against the limit of §4.6.4.
func (e *evaluator) countVoid() *outcome {
	e.voids++
	if e.voids > maxVoidLookups {
		return &outcome{result: ResultPermError, reason: "more than 2 void lookups"}
	}
	return nil
}

// target expands a domain-spec into a target-name (§4.8): the current domain
// when spec is absent, else the expansion with one trailing dot dropped and
// cut from the left to 253 characters (§7.3). ok is false when the result is
// not a valid domain name.
func (e *evaluator) target(spec []macroToken, domain string, counted bool) (name string, ok bool, exc *outcome) {
	if spec == nil {
		return domain, true, nil
	}
	name, exc = e.expand(spec, domain, counted)
	if exc != nil || len(name) > maxExpansion {
		return "", false, exc
	}
	name = strings.TrimSuffix(name, ".")
	for len(name) > 253 {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false, nil
		}
		name = name[i+1:]
	}
	return name, validDomain(name), nil
}

// expand expands a parsed macro-string for the record of domain (§7). counted
// says whether a %{p} lookup is charged against the DNS-query limit, as it is
// for terms but not for the explanation (§4.6.4). The result stops growing
// once it is longer than maxExpansion.
func (e *evaluator) expand(toks []macroToken, domain string, counted bool) (string, *outcome) {
	var b strings.Builder
	for _, t := range toks {
		if b.Len() > maxExpansion {
			break
		}
		if t.letter == 0 {
			b.WriteString(t.lit)
			continue
		}
		var v string
		switch t.letter {
		case 's':
			v = e.sender
		case 'l':
			v = e.local
		case 'o':
			v = e.senderDN
		case 'd':
			v = domain
		case 'i':
			v = e.dottedIP()
		case 'p':
			if counted && !e.ptrDone {
				if exc := e.countLookup(); exc != nil {
					return "", exc
				}
			}
			v = e.validatedName(domain)
		case 'v':
			v = "ip6"
			if e.ip.Is4() {
				v = "in-addr"
			}
		case 'h':
			v = orUnknown(e.helo)
		case 'c':
			v = e.ip.String()
		case 'r':
			v = orUnknown(e.receiver)
		default: // 't'
			v = strconv.FormatInt(e.now().Unix(), 10)
		}
		v = t.transform(v)
		if t.urlEsc {
			v = urlEscape(v)
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

// explain computes the explanation string of a fail result (§6.2). Any
// problem fetching or parsing it gives an empty explanation, as if the record
// had no exp= modifier. The text is limited to printable US-ASCII and to
// maxExplanation characters.
func (e *evaluator) explain(spec []macroToken, domain string) string {
	target, ok, exc := e.target(spec, domain, false)
	if exc != nil || !ok {
		return ""
	}
	txts, err := e.lookupTXT(target)
	if err != nil || len(txts) != 1 {
		return ""
	}
	toks, err := parseMacroString(txts[0], true)
	if err != nil {
		return ""
	}
	s, _ := e.expand(toks, domain, false)
	s = printable(s)
	if len(s) > maxExplanation {
		s = s[:maxExplanation]
	}
	return s
}

// dottedIP is the %{i} value (§7.3): dotted-quad for IPv4, and for IPv6 the 32
// nibbles separated by dots.
func (e *evaluator) dottedIP() string {
	if e.ip.Is4() {
		return e.ip.String()
	}
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 63)
	for _, c := range e.ip.As16() {
		b = append(b, hex[c>>4], '.', hex[c&0xf], '.')
	}
	return string(b[:len(b)-1])
}

// validDomain reports whether name is a domain check_host() can evaluate
// (§4.3): visible US-ASCII only (internationalized names must arrive as
// A-labels), at most 253 characters, at least two labels of 1 to 63
// characters, and a final label that satisfies the toplabel rule of §7.1, so
// that an address literal is not mistaken for a domain.
func validDomain(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || !isTopLabel(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			if l[i] < 0x21 || l[i] > 0x7e {
				return false
			}
		}
	}
	return true
}

// notFound reports whether a resolver error means the name does not exist or
// has no records of the requested type (RCODE 3, or an empty answer), which
// SPF treats as an answer rather than a failure.
func notFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	// net.Resolver reports a name with addresses only in the other family as
	// an *net.AddrError ("no suitable address").
	var addrErr *net.AddrError
	return errors.As(err, &addrErr)
}

func timedOut(err error) *outcome {
	return &outcome{result: ResultTempError, reason: "SPF evaluation timed out: " + err.Error()}
}

func qualifierResult(q byte) Result {
	switch q {
	case '-':
		return ResultFail
	case '~':
		return ResultSoftfail
	case '?':
		return ResultNeutral
	default:
		return ResultPass
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// printable replaces every byte outside printable US-ASCII with "?", so text
// that reaches a header field or an SMTP reply cannot break it (§6.2, §9.1).
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] < 0x20 || b[j] > 0x7e {
					b[j] = '?'
				}
			}
			return string(b)
		}
	}
	return s
}
