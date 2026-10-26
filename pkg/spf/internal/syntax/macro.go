package syntax

import (
	"errors"
	"fmt"
	"strings"
)

// Macros (RFC 7208 §7).
//
// A macro-string is parsed once, when the record is parsed, into tokens; a
// syntax error anywhere makes the whole record a permerror (§4.6). Expansion
// then only substitutes values, so it cannot fail on syntax.

// MacroToken is one piece of a parsed macro-string: literal text, or a
// %{...} macro with its transformers.
type MacroToken struct {
	Lit      string // literal text; empty for a %{...} macro
	escape   bool   // the literal came from %%, %_ or %- (a macro-expand)
	Letter   byte   // lowercase macro letter; 0 for literal text
	URLEsc   bool   // uppercase letter: URL-escape the value (§7.3)
	digits   int    // keep this many right-hand parts; 0 keeps all
	reverse  bool   // the "r" transformer
	delims   string // split characters; "" means "."
	expanded bool   // any transformer or delimiter given
}

// maxMacroDigits caps the DIGIT transformer while parsing, so a long digit run
// cannot overflow. A larger count would keep every part anyway: no macro value
// has that many.
const maxMacroDigits = 1 << 14

// escapes are the expansions of %%, %_ and %- (§7.1).
var escapes = map[byte]string{'%': "%", '_': " ", '-': "%20"}

// macroLetters are the letters valid in any macro-string; expLetters may only
// appear in explanation text (§7.2).
const (
	macroLetters = "slodiphv"
	expLetters   = "crt"
	delimiters   = ".-+,/_="
)

// ParseMacroString parses a macro-string (§7.1). With explain set it parses an
// explain-string instead: spaces are literal text and the c, r and t macros are
// allowed.
func ParseMacroString(s string, explain bool) ([]MacroToken, error) {
	var toks []MacroToken
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			toks = append(toks, MacroToken{Lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		if c != '%' {
			if !isMacroLiteral(c) && (!explain || c != ' ') {
				return nil, fmt.Errorf("invalid character %q", c)
			}
			lit.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, errors.New("'%' at end of macro-string")
		}
		switch s[i+1] {
		case '%', '_', '-':
			flush()
			toks = append(toks, MacroToken{Lit: escapes[s[i+1]], escape: true})
			i += 2
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, errors.New("unterminated '%{'")
			}
			t, err := parseMacro(s[i+2:i+end], explain)
			if err != nil {
				return nil, err
			}
			flush()
			toks = append(toks, t)
			i += end + 1
		default:
			return nil, fmt.Errorf("'%%' followed by %q", s[i+1])
		}
	}
	flush()
	return toks, nil
}

// parseMacro parses the body of %{...}: a letter, an optional digit count, an
// optional "r", and optional delimiters.
func parseMacro(body string, explain bool) (MacroToken, error) {
	if body == "" {
		return MacroToken{}, errors.New("empty macro")
	}
	t := MacroToken{Letter: lower(body[0]), URLEsc: body[0] >= 'A' && body[0] <= 'Z'}
	if !strings.ContainsRune(macroLetters, rune(t.Letter)) &&
		(!explain || !strings.ContainsRune(expLetters, rune(t.Letter))) {
		return MacroToken{}, fmt.Errorf("invalid macro letter %q", body[0])
	}
	rest := body[1:]
	t.expanded = rest != ""
	n := 0
	for n < len(rest) && isDigit(rest[n]) {
		if t.digits < maxMacroDigits {
			t.digits = t.digits*10 + int(rest[n]-'0')
		}
		n++
	}
	if n > 0 && t.digits == 0 {
		return MacroToken{}, errors.New("macro digit transformer must be nonzero")
	}
	t.digits = min(t.digits, maxMacroDigits)
	rest = rest[n:]
	if rest != "" && lower(rest[0]) == 'r' {
		t.reverse = true
		rest = rest[1:]
	}
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(delimiters, rest[i]) < 0 {
			return MacroToken{}, fmt.Errorf("invalid macro delimiter %q", rest[i])
		}
	}
	t.delims = rest
	return t, nil
}

// isMacroLiteral reports whether c is a macro-literal: a visible US-ASCII
// character other than "%" (§7.1).
func isMacroLiteral(c byte) bool { return c >= 0x21 && c <= 0x7e && c != '%' }

// CheckDomainSpec parses a domain-spec (§7.1): a macro-string that ends either
// in a macro-expand or in "." toplabel with an optional trailing dot.
func CheckDomainSpec(spec string) ([]MacroToken, error) {
	toks, err := ParseMacroString(spec, false)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("empty domain-spec")
	}
	last := toks[len(toks)-1]
	if last.Letter != 0 || last.escape {
		return toks, nil
	}
	tail := strings.TrimSuffix(last.Lit, ".")
	dot := strings.LastIndexByte(tail, '.')
	if dot < 0 || !IsTopLabel(tail[dot+1:]) {
		return nil, fmt.Errorf("domain-spec %q does not end in a valid top-level label", spec)
	}
	return toks, nil
}

// IsTopLabel reports whether s matches the toplabel rule of §7.1: letters,
// digits and hyphens, not all digits, and neither starting nor ending with a
// hyphen.
func IsTopLabel(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	alpha, hyphen := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isAlpha(c):
			alpha = true
		case c == '-':
			hyphen = true
		case !isDigit(c):
			return false
		}
	}
	return alpha || hyphen
}

// Transform applies a macro's transformers (§7.3): split the value on the
// delimiters, optionally reverse the parts, keep the right-hand ones, and
// rejoin them with ".".
func (t MacroToken) Transform(v string) string {
	if !t.expanded {
		return v
	}
	delims := t.delims
	if delims == "" {
		delims = "."
	}
	var parts []string
	start := 0
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(delims, v[i]) >= 0 {
			parts = append(parts, v[start:i])
			start = i + 1
		}
	}
	parts = append(parts, v[start:])
	if t.reverse {
		for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
			parts[l], parts[r] = parts[r], parts[l]
		}
	}
	if t.digits > 0 && t.digits < len(parts) {
		parts = parts[len(parts)-t.digits:]
	}
	return strings.Join(parts, ".")
}

// URLEscape percent-encodes every character outside the RFC 3986 unreserved
// set, as uppercase macros require (§7.3).
func URLEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
