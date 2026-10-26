package syntax

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// SPF record syntax (RFC 7208 §4.5, §4.6.1, §5, §6 and the collected ABNF of
// §12). ParseRecord validates the whole record before anything is evaluated:
// a syntax error anywhere makes check_host() return permerror without
// interpreting any term (§4.6).

// Directive is one parsed mechanism with its qualifier.
type Directive struct {
	Text      string       // the term as written, for Response.Mechanism
	Qualifier byte         // '+', '-', '~' or '?'
	Name      string       // lowercase mechanism name
	Spec      []MacroToken // domain-spec; nil when absent
	Prefix    netip.Prefix // ip4 and ip6 networks
	CIDR4     int          // a and mx IPv4 prefix length
	CIDR6     int          // a and mx IPv6 prefix length
}

// Record is a parsed SPF Record.
type Record struct {
	Directives []Directive
	Redirect   []MacroToken // redirect= domain-spec; nil when absent
	Exp        []MacroToken // exp= domain-spec; nil when absent
}

// IsSPFRecord reports whether a TXT string is an SPF version 1 record: it
// begins with "v=spf1" followed by a space or the end of the string (§4.5).
// ABNF literals are case-insensitive (§12).
func IsSPFRecord(txt string) bool {
	return len(txt) >= 6 && strings.EqualFold(txt[:6], "v=spf1") && (len(txt) == 6 || txt[6] == ' ')
}

// ParseRecord parses an SPF record, which must satisfy IsSPFRecord.
func ParseRecord(txt string) (*Record, error) {
	if !IsSPFRecord(txt) {
		return nil, errors.New("not an SPF version 1 record")
	}
	r := &Record{}
	for _, term := range strings.Split(txt[6:], " ") {
		if term == "" {
			continue
		}
		if name, value, ok := cutModifier(term); ok {
			if err := r.addModifier(strings.ToLower(name), value); err != nil {
				return nil, fmt.Errorf("%s: %w", term, err)
			}
			continue
		}
		d, err := parseDirective(term)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", term, err)
		}
		r.Directives = append(r.Directives, d)
	}
	return r, nil
}

// cutModifier splits a modifier term into its name and value. A modifier is a
// name (ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )) followed by "=" (§4.6.1).
func cutModifier(term string) (name, value string, ok bool) {
	eq := strings.IndexByte(term, '=')
	if eq <= 0 || !isAlpha(term[0]) {
		return "", "", false
	}
	for i := 1; i < eq; i++ {
		c := term[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return "", "", false
		}
	}
	return term[:eq], term[eq+1:], true
}

// addModifier records a redirect or exp modifier, refusing a second one (§6),
// and checks the syntax of any other modifier, which is otherwise ignored.
func (r *Record) addModifier(name, value string) error {
	var slot *[]MacroToken
	switch name {
	case "redirect":
		slot = &r.Redirect
	case "exp":
		slot = &r.Exp
	default:
		_, err := ParseMacroString(value, false)
		return err
	}
	if *slot != nil {
		return errors.New("modifier appears more than once")
	}
	toks, err := CheckDomainSpec(value)
	if err != nil {
		return err
	}
	*slot = toks
	return nil
}

// parseDirective parses one directive: an optional qualifier and a mechanism
// with its arguments (§4.6.1, §5).
func parseDirective(term string) (Directive, error) {
	d := Directive{Text: term, Qualifier: '+', CIDR4: 32, CIDR6: 128}
	if strings.IndexByte("+-~?", term[0]) >= 0 {
		d.Qualifier = term[0]
		term = term[1:]
	}
	end := strings.IndexAny(term, ":/")
	if end < 0 {
		end = len(term)
	}
	d.Name = strings.ToLower(term[:end])
	rest := term[end:]

	var err error
	switch d.Name {
	case "all":
		if rest != "" {
			err = errors.New("all takes no argument")
		}
	case "include", "exists":
		if !strings.HasPrefix(rest, ":") {
			return d, errors.New(d.Name + " needs a domain-spec")
		}
		d.Spec, err = CheckDomainSpec(rest[1:])
	case "ptr":
		if rest != "" {
			if rest[0] != ':' {
				return d, errors.New("ptr takes no CIDR length")
			}
			d.Spec, err = CheckDomainSpec(rest[1:])
		}
	case "a", "mx":
		err = d.parseHostArgs(rest)
	case "ip4", "ip6":
		err = d.parseNetwork(rest)
	default:
		err = errors.New("unknown mechanism")
	}
	return d, err
}

// parseHostArgs parses the arguments of a and mx: [ ":" domain-spec ]
// [ dual-cidr-length ].
func (d *Directive) parseHostArgs(rest string) error {
	if rest == "" {
		return nil
	}
	spec, err := d.cutDualCIDR(rest)
	if err != nil {
		return err
	}
	if rest[0] == '/' {
		if spec != "" {
			return errors.New("invalid CIDR length")
		}
		return nil
	}
	d.Spec, err = CheckDomainSpec(spec[1:])
	return err
}

// cutDualCIDR removes a trailing dual-cidr-length ("/N", "//N" or "/N//N")
// from s, records the prefix lengths, and returns what precedes it. A
// domain-spec may itself contain "/", so the lengths are taken from the end.
func (d *Directive) cutDualCIDR(s string) (string, error) {
	if i := strings.LastIndex(s, "//"); i >= 0 && isDigits(s[i+2:]) {
		n, err := parseCIDR(s[i+2:], 128)
		if err != nil {
			return "", err
		}
		d.CIDR6, s = n, s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 && isDigits(s[i+1:]) {
		n, err := parseCIDR(s[i+1:], 32)
		if err != nil {
			return "", err
		}
		d.CIDR4, s = n, s[:i]
	}
	return s, nil
}

// parseNetwork parses the ":" network [ "/" length ] argument of ip4 and ip6
// (§5.6). The address must be in the mechanism's family; omitted octets,
// leading zeros and zones are refused.
func (d *Directive) parseNetwork(rest string) error {
	if !strings.HasPrefix(rest, ":") {
		return errors.New(d.Name + " needs a network")
	}
	network, length, hasLength := strings.Cut(rest[1:], "/")
	addr, err := netip.ParseAddr(network)
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("invalid %s network %q", d.Name, network)
	}
	bits := 32
	if d.Name == "ip6" {
		bits = 128
	}
	if addr.Is4() != (bits == 32) {
		return fmt.Errorf("%q is not an %s address", network, d.Name)
	}
	if hasLength {
		if bits, err = parseCIDR(length, bits); err != nil {
			return err
		}
	}
	d.Prefix = netip.PrefixFrom(addr, bits).Masked()
	return nil
}

// parseCIDR parses a CIDR prefix length: "0", or digits without a leading zero,
// at most limit (§5.6).
func parseCIDR(s string, limit int) (int, error) {
	if !isDigits(s) || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("invalid CIDR length %q", s)
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	if n > limit {
		return 0, fmt.Errorf("CIDR length %d exceeds %d", n, limit)
	}
	return n, nil
}

// isDigits reports whether s is one or more ASCII digits.
func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}
