package spf

import (
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// toALabels converts every U-label of domain to its A-label (xn-- punycode)
// form, as RFC 8616 §4 requires before a name from an internationalized MAIL
// FROM is used for SPF, both for the record lookup and for the macros that
// carry it (%{d}, %{o}, %{s}). An all-ASCII label is returned as it is; a
// label with non-ASCII runes is lower-cased (Unicode simple folding) and
// punycode-encoded. A name that is not valid UTF-8 is returned unchanged, so
// it stays malformed (§4.3) and gives none.
//
// A name with a U-label that IDNA2008 cannot allow is returned unchanged as
// well, so it is malformed and gives none, and nothing is looked up for it:
// see validULabel for what is refused. The rest of IDNA2008 (NFC
// normalization, special folds such as ß, the per-code-point tables) is out of
// scope for a dependency-free evaluator; only deliberately unusual spellings
// differ.
func toALabels(domain string) string {
	if isASCII(domain) || !utf8.ValidString(domain) {
		return domain
	}
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if !isASCII(label) && !validULabel(label) {
			return domain
		}
		labels[i] = labelToASCII(label)
	}
	return strings.Join(labels, ".")
}

// validULabel reports whether a non-ASCII label passes the IDNA2008 checks
// that need no Unicode tables (RFC 5891 §4.2.3, RFC 5892):
//   - no control, format, surrogate, private-use or separator code point,
//     all DISALLOWED;
//   - no ZERO WIDTH NON-JOINER or ZERO WIDTH JOINER (U+200C, U+200D). They
//     are CONTEXTJ, valid only after a virama (RFC 5892 Appendix A.1, A.2),
//     and telling a virama apart needs the combining-class table, so both are
//     refused: a rare valid name gives none rather than an invalid one being
//     looked up;
//   - it does not begin with a combining mark (§4.2.3.2);
//   - it neither begins nor ends with a hyphen, and has no "--" in its third
//     and fourth positions (§4.2.3.1).
func validULabel(label string) bool {
	runes := []rune(label)
	if len(runes) == 0 {
		return false
	}
	if unicode.Is(unicode.M, runes[0]) {
		return false
	}
	if runes[0] == '-' || runes[len(runes)-1] == '-' {
		return false
	}
	if len(runes) >= 4 && runes[2] == '-' && runes[3] == '-' {
		return false
	}
	for _, r := range runes {
		switch {
		case r == 0x200C, r == 0x200D:
			return false
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Z):
			return false
		}
	}
	return true
}

// labelToASCII returns the A-label form of one DNS label. An all-ASCII label
// (an existing xn-- label included) is returned unchanged.
func labelToASCII(label string) string {
	// An A-label has at most 63 characters, at least one per code point, so a
	// longer label is left as it is (and is then no valid domain); this also
	// bounds the quadratic encoder.
	if isASCII(label) || utf8.RuneCountInString(label) > 63 {
		return label
	}
	return "xn--" + punycodeEncode(strings.ToLower(label))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Punycode (RFC 3492) bootstring parameters for IDNA.
const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128 // first non-ASCII code point
	punyDelimiter   = '-'
)

// punycodeEncode encodes a string of Unicode code points into its punycode
// (RFC 3492) basic-string form, i.e. the part that follows the xn-- prefix in an
// IDNA A-label. This is the RFC 3492 reference "Encoding procedure" adapted to
// Go. Its input is at most 63 code points (see labelToASCII), so delta stays
// below 64 * 0x110000 and cannot overflow, which the reference code checks.
func punycodeEncode(input string) string {
	runes := []rune(input)
	var out strings.Builder

	// Copy all basic (ASCII) code points first, in order.
	basic := 0
	for _, r := range runes {
		if r < punyInitialN {
			out.WriteByte(byte(r))
			basic++
		}
	}
	handled := basic
	if basic > 0 {
		out.WriteByte(punyDelimiter)
	}

	n := punyInitialN
	delta := 0
	bias := punyInitialBias
	for handled < len(runes) {
		// Find the next-smallest code point not yet handled.
		m := math.MaxInt32
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := punyBase; ; k += punyBase {
					t := punyThreshold(k, bias)
					if q < t {
						break
					}
					out.WriteByte(punyDigit(t + (q-t)%(punyBase-t)))
					q = (q - t) / (punyBase - t)
				}
				out.WriteByte(punyDigit(q))
				bias = punyAdapt(delta, handled+1, handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return out.String()
}

func punyThreshold(k, bias int) int {
	switch {
	case k <= bias+punyTMin:
		return punyTMin
	case k >= bias+punyTMax:
		return punyTMax
	default:
		return k - bias
	}
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

// punyDigit maps a value 0..35 to its punycode digit: 0..25 -> 'a'..'z',
// 26..35 -> '0'..'9'.
func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
