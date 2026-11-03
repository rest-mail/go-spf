package spf

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// SMTPReply is the SMTP reply RFC 7208 §8 recommends when a receiver rejects
// mail on an SPF result.
type SMTPReply struct {
	// Code is the SMTP reply code: 550 or 451.
	Code int
	// Enhanced is the enhanced status code (RFC 3463) RFC 7372 §3.2 registers
	// for SPF: 5.7.23 "SPF validation failed" for fail, and 4.7.24 or 5.7.24
	// "SPF validation error" for temperror and permerror. RFC 7372 assigns
	// them in place of the 5.7.1, 4.4.3 and 5.5.2 that RFC 7208 §8 names.
	Enhanced string
	// Text is the reply text: printable US-ASCII, with no line breaks.
	Text string
}

// String gives the reply as one SMTP reply line without its CRLF, for
// example "550 5.7.23 SPF validation failed".
func (r SMTPReply) String() string {
	return strconv.Itoa(r.Code) + " " + r.Enhanced + " " + r.Text
}

// SMTPReply names the reply RFC 7208 §8 recommends if the receiver rejects
// mail on r: 550 5.7.23 for fail (§8.4), 451 4.7.24 for temperror (§8.6) and
// 550 5.7.24 for permerror (§8.7), with the enhanced codes of RFC 7372 §3.2.
// For none, neutral, pass and softfail, which §8 does not suggest rejecting
// on, and for a value that is not an SPF result, ok is false.
//
// The method does not decide to reject; the receiver's policy does.
func (r Result) SMTPReply() (reply SMTPReply, ok bool) {
	switch r {
	case ResultFail:
		return SMTPReply{Code: 550, Enhanced: "5.7.23", Text: "SPF validation failed"}, true
	case ResultTempError:
		return SMTPReply{Code: 451, Enhanced: "4.7.24", Text: "SPF validation error, try again later"}, true
	case ResultPermError:
		return SMTPReply{Code: 550, Enhanced: "5.7.24", Text: "SPF validation error"}, true
	}
	return SMTPReply{}, false
}

// SMTPReply is Result.SMTPReply for the response's result, except that a fail
// carrying an explanation (RFC 7208 §6.2) has the explanation as its text.
// The explanation is third-party text from the sender's domain; it is used
// only when it is printable US-ASCII, as the evaluator always makes it.
func (r Response) SMTPReply() (reply SMTPReply, ok bool) {
	reply, ok = r.Result.SMTPReply()
	if ok && r.Result == ResultFail && r.Explanation != "" && isPrintable(r.Explanation) {
		reply.Text = r.Explanation
	}
	return reply, ok
}

// Identity names the identity an SPF check authorized (RFC 7208 §2.3, §2.4),
// as the identity key of Received-SPF carries it (§9.1).
type Identity string

// The identities RFC 7208 checks.
const (
	// IdentityMailFrom is the MAIL FROM identity, checked by CheckMailFrom.
	IdentityMailFrom Identity = "mailfrom"
	// IdentityHELO is the HELO identity, checked by CheckHELO.
	IdentityHELO Identity = "helo"
)

// CheckInputs are the inputs of one check, as Received-SPF records them.
type CheckInputs struct {
	// ClientIP is the address of the SMTP client that was checked.
	ClientIP netip.Addr
	// Identity is the identity that was checked. Empty leaves out the
	// identity key; the comment then speaks of the MAIL FROM sender.
	Identity Identity
	// MailFrom is the reverse-path from the MAIL command, as passed to
	// CheckMailFrom. Empty, or "<>", is the null reverse-path, recorded as
	// postmaster@<HELO> as the check used it.
	MailFrom string
	// HELO is the HELO/EHLO name the client gave.
	HELO string
	// Receiver is the host name of the receiving host, the SPF verifier.
	Receiver string
}

const (
	// maxHeaderValue is the longest value Received-SPF takes in, in octets.
	maxHeaderValue = 1000
	// maxHeaderWord is the longest run of a value without a space, in octets.
	// Escaping at most doubles it, so a folded line stays far below the
	// 998-octet limit of RFC 5322 §2.1.1.
	maxHeaderWord = 400
	// foldWidth is the line length RFC 5322 §2.1.1 recommends.
	foldWidth = 78
)

// ReceivedSPF builds the value of a Received-SPF header field (RFC 7208 §9.1)
// recording the response of the check with the inputs in: the result, a
// comment in the words of §9.1's examples, and the key-value pairs receiver,
// client-ip, envelope-from, helo, identity, mechanism (when a mechanism, or
// the "default" of §9.1, decided the result) and problem (the response's
// Reason, for temperror and permerror). The value is one line, without the
// field name and without CRLF.
//
// Each value is written as a dot-atom when it is one, and as a quoted-string
// otherwise. A value is left out, and "unknown" stands in for it in the
// comment, when it is empty, holds any byte outside printable US-ASCII (so a
// CR or LF can never reach the header), is longer than 1000 octets, or has
// more than 400 octets without a space. An error is returned only when the
// response's Result is not one of the seven SPF results.
//
// Placing the field above every other Received-SPF field and above the
// receiver's own Received field stays with the mail server (§9.1).
func (r Response) ReceivedSPF(in CheckInputs) (string, error) {
	if !r.Result.valid() {
		return "", fmt.Errorf("spf: %q is not an SPF result", string(r.Result))
	}
	receiver, _ := headerText(in.Receiver)
	helo, _ := headerText(in.HELO)
	var ip string
	if in.ClientIP.IsValid() {
		ip = in.ClientIP.Unmap().WithZone("").String()
	}
	sender, _ := headerText(senderOf(in.MailFrom, in.HELO))
	identity := string(in.Identity)
	if !isIdentityName(identity) {
		identity = ""
	}
	mechanism, _ := headerText(r.Mechanism)
	var problem string
	if r.Result == ResultTempError || r.Result == ResultPermError {
		problem, _ = headerText(r.Reason)
	}

	subject := sender
	if in.Identity == IdentityHELO {
		subject = helo
	}

	var b strings.Builder
	b.WriteString(string(r.Result))
	b.WriteString(" (")
	if receiver != "" {
		b.WriteString(commentText(receiver))
		b.WriteString(": ")
	}
	b.WriteString(commentText(r.Result.comment(orUnknown(subject), orUnknown(ip), problem)))
	b.WriteString(")")

	pairs := []struct{ key, value string }{
		{"receiver", receiver},
		{"client-ip", ip},
		{"envelope-from", sender},
		{"helo", helo},
		{"identity", identity},
		{"mechanism", mechanism},
		{"problem", problem},
	}
	sep := " "
	for _, p := range pairs {
		if p.value == "" {
			continue
		}
		b.WriteString(sep)
		b.WriteString(p.key)
		b.WriteByte('=')
		b.WriteString(keyValue(p.value))
		sep = "; "
	}
	return b.String(), nil
}

// ReceivedSPFField is ReceivedSPF as a whole header field: "Received-SPF: ",
// the value folded at spaces so that each line keeps within 78 octets where
// a space allows it (RFC 5322 §2.1.1, §2.2.3), and a closing CRLF. Folding
// never splits a word, and no line exceeds 998 octets.
func (r Response) ReceivedSPFField(in CheckInputs) (string, error) {
	value, err := r.ReceivedSPF(in)
	if err != nil {
		return "", err
	}
	return fold("Received-SPF: "+value) + "\r\n", nil
}

// valid reports whether r is one of the seven SPF results.
func (r Result) valid() bool {
	switch r {
	case ResultNone, ResultNeutral, ResultPass, ResultFail, ResultSoftfail, ResultTempError, ResultPermError:
		return true
	}
	return false
}

// comment is the Received-SPF comment for r after the receiver's name, in the
// words of the examples of RFC 7208 §9.1 and RFC 4408 §7.
func (r Result) comment(subject, ip, problem string) string {
	switch r {
	case ResultPass:
		return "domain of " + subject + " designates " + ip + " as permitted sender"
	case ResultFail:
		return "domain of " + subject + " does not designate " + ip + " as permitted sender"
	case ResultSoftfail:
		return "domain of transitioning " + subject + " does not designate " + ip + " as permitted sender"
	case ResultNeutral:
		return ip + " is neither permitted nor denied by domain of " + subject
	case ResultNone:
		return "domain of " + subject + " does not designate permitted sender hosts"
	}
	s := "error in processing during lookup of " + subject
	if problem != "" {
		s += ": " + problem
	}
	return s
}

// senderOf gives the sender CheckMailFrom checks for the reverse-path
// mailFrom: the address of reversePath, or postmaster@<helo> for the null
// reverse-path.
func senderOf(mailFrom, helo string) string {
	if sender := reversePath(mailFrom); sender != "" {
		return sender
	}
	return "postmaster@" + helo
}

// reversePath gives the address of the reverse-path mailFrom, without angle
// brackets or source route; empty for the null reverse-path.
func reversePath(mailFrom string) string {
	sender := strings.TrimSuffix(strings.TrimPrefix(mailFrom, "<"), ">")
	if strings.HasPrefix(sender, "@") {
		// A source route (RFC 5321 Appendix C) names relays, not the sender.
		if i := strings.IndexByte(sender, ':'); i >= 0 {
			sender = sender[i+1:]
		}
	}
	return sender
}

// headerText returns s when Received-SPF may carry it: non-empty printable
// US-ASCII, at most maxHeaderValue octets, without a run of more than
// maxHeaderWord octets that holds no space.
func headerText(s string) (string, bool) {
	if s == "" || len(s) > maxHeaderValue || !isPrintable(s) {
		return "", false
	}
	for _, word := range strings.Split(s, " ") {
		if len(word) > maxHeaderWord {
			return "", false
		}
	}
	return s, true
}

func isPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// isIdentityName reports whether s matches the name rule of RFC 7208 §12:
// ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ).
func isIdentityName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// isAtext reports whether c is atext (RFC 5322 §3.2.3).
func isAtext(c byte) bool {
	return isAlpha(c) || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// isDotAtom reports whether s is a dot-atom-text (RFC 5322 §3.2.3).
func isDotAtom(s string) bool {
	for _, atom := range strings.Split(s, ".") {
		if atom == "" {
			return false
		}
		for i := 0; i < len(atom); i++ {
			if !isAtext(atom[i]) {
				return false
			}
		}
	}
	return true
}

// keyValue writes a printable US-ASCII value as the dot-atom / quoted-string
// of RFC 7208 §9.1's key-value-pair.
func keyValue(s string) string {
	if isDotAtom(s) {
		return s
	}
	return `"` + escape(s, `"\`) + `"`
}

// commentText escapes printable US-ASCII text for a comment (RFC 5322
// §3.2.2), where "(", ")" and "\" must be quoted pairs.
func commentText(s string) string { return escape(s, `()\`) }

func escape(s, special string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(special, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fold folds a one-line header field at spaces (RFC 5322 §2.2.3) so lines
// keep within foldWidth octets where a space allows it. Every space in a
// Received-SPF value is folding white space: none follows a lone backslash,
// since escape never quotes a space. It folds only before a non-empty word,
// so no line holds white space alone.
func fold(s string) string {
	words := strings.Split(s, " ")
	var b strings.Builder
	b.WriteString(words[0])
	n := len(words[0])
	for _, w := range words[1:] {
		if w != "" && n+1+len(w) > foldWidth {
			b.WriteString("\r\n")
			n = 0
		}
		b.WriteByte(' ')
		b.WriteString(w)
		n += 1 + len(w)
	}
	return b.String()
}
