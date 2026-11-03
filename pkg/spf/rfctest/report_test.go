package rfctest

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
)

// TestSMTPReply checks the reply RFC 7208 §8 recommends for each result, with
// the enhanced status codes RFC 7372 §3.2 assigns in place of §8's: 550
// 5.7.23 for fail (§8.4), 451 4.7.24 for temperror (§8.6) and 550 5.7.24 for
// permerror (§8.7), and no reply for the results §8 does not reject on.
//
// checklist: SPF-RESULT-03 SPF-RESULT-06 SPF-RESULT-07
func TestSMTPReply(t *testing.T) {
	for _, tc := range []struct {
		result spf.Result
		ok     bool
		line   string
	}{
		{spf.ResultNone, false, ""},
		{spf.ResultNeutral, false, ""},
		{spf.ResultPass, false, ""},
		{spf.ResultSoftfail, false, ""},
		{spf.ResultFail, true, "550 5.7.23 SPF validation failed"},
		{spf.ResultTempError, true, "451 4.7.24 SPF validation error, try again later"},
		{spf.ResultPermError, true, "550 5.7.24 SPF validation error"},
		{spf.Result("bogus"), false, ""},
		{spf.Result(""), false, ""},
	} {
		reply, ok := tc.result.SMTPReply()
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.result, ok, tc.ok)
			continue
		}
		if !ok {
			if reply != (spf.SMTPReply{}) {
				t.Errorf("%q: reply = %+v, want zero", tc.result, reply)
			}
			continue
		}
		if got := reply.String(); got != tc.line {
			t.Errorf("%q: reply = %q, want %q", tc.result, got, tc.line)
		}
	}

	// A real check: a fail with the domain's explanation gives that text.
	z := zone(
		"fail.example TXT v=spf1 -all exp=why.fail.example",
		"why.fail.example TXT %{i} may not send for %{d}",
		"bare.example TXT v=spf1 -all",
		"broken.example TXT v=spf1 bogus",
	)
	for _, tc := range []struct{ sender, line string }{
		{"a@fail.example", "550 5.7.23 192.0.2.1 may not send for fail.example"},
		{"a@bare.example", "550 5.7.23 SPF validation failed"},
		{"a@broken.example", "550 5.7.24 SPF validation error"},
	} {
		reply, ok := mailFrom(z, "192.0.2.1", tc.sender).SMTPReply()
		if !ok || reply.String() != tc.line {
			t.Errorf("%s: reply = %q, %v, want %q", tc.sender, reply.String(), ok, tc.line)
		}
	}

	// An explanation a caller set with a line break never reaches the reply.
	resp := spf.Response{Result: spf.ResultFail, Explanation: "go away\r\n250 OK"}
	if reply, _ := resp.SMTPReply(); reply.Text != "SPF validation failed" {
		t.Errorf("injected explanation: text = %q", reply.Text)
	}
	if reply, ok := (spf.Response{Result: spf.ResultPass, Explanation: "x"}).SMTPReply(); ok {
		t.Errorf("pass: reply = %+v, want none", reply)
	}
}

// TestReceivedSPF checks the Received-SPF field value (§9.1) built from a real
// check for each of the seven results: the result, a comment, and the
// receiver, client-ip, envelope-from, helo, identity, mechanism and problem
// keys. Recording a fail that is accepted is what §8.4 asks for.
//
// checklist: SPF-HDR-01 SPF-HDR-03 SPF-RESULT-04
func TestReceivedSPF(t *testing.T) {
	z := zone(
		"pass.example TXT v=spf1 ip4:192.0.2.0/24 -all",
		"fail.example TXT v=spf1 -all",
		"softfail.example TXT v=spf1 ~all",
		"neutral.example TXT v=spf1 a:nothing.neutral.example",
		"none.example A 192.0.2.1",
		"temperror.example SERVFAIL TXT",
		"permerror.example TXT v=spf1 bogus",
	)
	in := spf.CheckInputs{
		ClientIP: mustAddr("192.0.2.1"),
		Identity: spf.IdentityMailFrom,
		HELO:     testHELO,
		Receiver: "mx.receiver.example",
	}
	const keys = ` receiver=mx.receiver.example; client-ip=192.0.2.1; envelope-from="a@%s.example"; helo=mail.example.net; identity=mailfrom`
	for _, tc := range []struct {
		result  spf.Result
		comment string
		extra   string
	}{
		{spf.ResultPass, "domain of a@pass.example designates 192.0.2.1 as permitted sender", `; mechanism="ip4:192.0.2.0/24"`},
		{spf.ResultFail, "domain of a@fail.example does not designate 192.0.2.1 as permitted sender", "; mechanism=-all"},
		{spf.ResultSoftfail, "domain of transitioning a@softfail.example does not designate 192.0.2.1 as permitted sender", "; mechanism=~all"},
		{spf.ResultNeutral, "192.0.2.1 is neither permitted nor denied by domain of a@neutral.example", "; mechanism=default"},
		{spf.ResultNone, "domain of a@none.example does not designate permitted sender hosts", ""},
		{spf.ResultTempError, "error in processing during lookup of a@temperror.example: TXT lookup for temperror.example: lookup : server misbehaving", `; problem="TXT lookup for temperror.example: lookup : server misbehaving"`},
		{spf.ResultPermError, "error in processing during lookup of a@permerror.example: SPF record of permerror.example: bogus: unknown mechanism", `; problem="SPF record of permerror.example: bogus: unknown mechanism"`},
	} {
		in.MailFrom = "<a@" + string(tc.result) + ".example>"
		resp := spf.CheckMailFrom(t.Context(), in.ClientIP, in.MailFrom, in.HELO, opts(z))
		want(t, string(tc.result), resp, tc.result)
		got, err := resp.ReceivedSPF(in)
		if err != nil {
			t.Fatalf("%s: %v", tc.result, err)
		}
		wantValue := string(tc.result) + " (mx.receiver.example: " + tc.comment + ")" +
			strings.ReplaceAll(keys, "%s", string(tc.result)) + tc.extra
		if got != wantValue {
			t.Errorf("%s:\n got %s\nwant %s", tc.result, got, wantValue)
		}
	}

	// The HELO identity names the HELO host in the comment, and the null
	// reverse-path is recorded as postmaster@<HELO>, the sender it checks.
	hz := zone("mail.example.net TXT v=spf1 +all")
	helo := spf.CheckHELO(t.Context(), mustAddr("2001:db8::1"), testHELO, opts(hz))
	got, err := helo.ReceivedSPF(spf.CheckInputs{
		ClientIP: mustAddr("2001:db8::1"),
		Identity: spf.IdentityHELO,
		MailFrom: "<>",
		HELO:     testHELO,
	})
	const wantHELO = `pass (domain of mail.example.net designates 2001:db8::1 as permitted sender) client-ip="2001:db8::1"; envelope-from="postmaster@mail.example.net"; helo=mail.example.net; identity=helo; mechanism=+all`
	if err != nil || got != wantHELO {
		t.Errorf("HELO identity:\n got %s, %v\nwant %s", got, err, wantHELO)
	}

	if _, err := (spf.Response{Result: "maybe"}).ReceivedSPF(in); err == nil {
		t.Error("unknown result: no error")
	}
	if _, err := (spf.Response{}).ReceivedSPFField(in); err == nil {
		t.Error("empty result: no error from ReceivedSPFField")
	}
}

// TestReceivedSPFQuoting checks that every value in Received-SPF is a
// dot-atom or a correctly escaped quoted-string, that comment specials are
// escaped, and that a value carrying a line break or any byte outside
// printable US-ASCII is left out, so a value from the SMTP session can never
// inject a header field (§9.1, §11.5.1).
//
// checklist: SPF-HDR-04
func TestReceivedSPFQuoting(t *testing.T) {
	resp := spf.Response{Result: spf.ResultPermError, Reason: `bad (term) "x" \ y`, Mechanism: ""}
	got, err := resp.ReceivedSPF(spf.CheckInputs{
		ClientIP: netip.MustParseAddr("::ffff:192.0.2.7"),
		Identity: spf.IdentityMailFrom,
		MailFrom: `@relay.example:"odd \"one\""@sender.example`,
		HELO:     "[192.0.2.7]",
		Receiver: "mx (primary)",
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantQuoted = `permerror (mx \(primary\): error in processing during lookup of "odd \\"one\\""@sender.example: bad \(term\) "x" \\ y) ` +
		`receiver="mx (primary)"; client-ip=192.0.2.7; envelope-from="\"odd \\\"one\\\"\"@sender.example"; helo="[192.0.2.7]"; identity=mailfrom; problem="bad (term) \"x\" \\ y"`
	if got != wantQuoted {
		t.Errorf("quoting:\n got %s\nwant %s", got, wantQuoted)
	}

	// A name that is not a dot-atom, such as one with a trailing dot, is
	// quoted rather than written bare.
	got, _ = (spf.Response{Result: spf.ResultNone}).ReceivedSPF(spf.CheckInputs{HELO: "host.example."})
	if want := `none (domain of postmaster@host.example. does not designate permitted sender hosts) envelope-from="postmaster@host.example."; helo="host.example."`; got != want {
		t.Errorf("trailing dot:\n got %s\nwant %s", got, want)
	}

	// CRLF injection through every caller-supplied input.
	inject := "x.example\r\nX-Injected: yes"
	resp = spf.Response{Result: spf.ResultTempError, Reason: "dns\nX-Injected: yes", Mechanism: "-all\r\nX-Injected: yes"}
	in := spf.CheckInputs{
		ClientIP: mustAddr("192.0.2.1"),
		Identity: spf.Identity("helo\r\nX-Injected: yes"),
		MailFrom: "a@" + inject,
		HELO:     inject,
		Receiver: inject,
	}
	got, err = resp.ReceivedSPF(in)
	const wantInjected = `temperror (error in processing during lookup of unknown) client-ip=192.0.2.1`
	if err != nil || got != wantInjected {
		t.Errorf("injection:\n got %q, %v\nwant %q", got, err, wantInjected)
	}
	field, _ := resp.ReceivedSPFField(in)
	if rest := strings.ReplaceAll(strings.TrimSuffix(field, "\r\n"), "\r\n ", " "); strings.ContainsAny(rest, "\r\n") || strings.Contains(field, "X-Injected") {
		t.Errorf("injection reached the field: %q", field)
	}

	// Non-ASCII, NUL, tab, DEL, an over-long value and a bad identity name
	// are left out; nothing outside printable US-ASCII reaches the value.
	for _, bad := range []string{"m\u00fcller.example", "a\x00b", "a\tb", "a\x7fb", strings.Repeat("a", 401), strings.Repeat("a b", 400)} {
		got, _ := (spf.Response{Result: spf.ResultNone}).ReceivedSPF(spf.CheckInputs{
			Identity: spf.Identity("9" + bad), MailFrom: "u@" + bad, HELO: bad, Receiver: bad,
		})
		if want := "none (domain of unknown does not designate permitted sender hosts)"; got != want {
			t.Errorf("%q:\n got %q\nwant %q", bad, got, want)
		}
	}
}

// TestReceivedSPFField checks the whole folded field: it starts with the
// field name, ends in one CRLF, folds only at spaces before a non-empty word,
// keeps lines within 78 octets where a space allows it and every line within
// the 998 octets of RFC 5322 §2.1.1, and unfolds to exactly the value.
//
// checklist: SPF-HDR-05
func TestReceivedSPFField(t *testing.T) {
	long := strings.Repeat("abcdefghij", 39) // 390 octets, the longest kind of word kept
	for _, tc := range []struct {
		name string
		resp spf.Response
		in   spf.CheckInputs
	}{
		{"short", spf.Response{Result: spf.ResultPass, Mechanism: "+all"}, spf.CheckInputs{ClientIP: mustAddr("192.0.2.1")}},
		{"typical", spf.Response{Result: spf.ResultFail, Mechanism: "-all"}, spf.CheckInputs{
			ClientIP: mustAddr("2001:db8::1"), Identity: spf.IdentityMailFrom,
			MailFrom: "someone.with.a.long.name@subdomain.of.a.long.sender.example", HELO: "outbound-relay-17.mail.sender.example",
			Receiver: "mx1.receiving.example",
		}},
		{"long words", spf.Response{Result: spf.ResultPermError, Reason: long + " and " + strings.Repeat(`"\`, 195)}, spf.CheckInputs{
			ClientIP: mustAddr("192.0.2.1"), MailFrom: `"` + long[:190] + `"@` + long[:190], HELO: long, Receiver: long,
		}},
		{"spaces", spf.Response{Result: spf.ResultTempError, Reason: "a  b   c" + strings.Repeat(" word", 60)}, spf.CheckInputs{}},
	} {
		value, err := tc.resp.ReceivedSPF(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		field, err := tc.resp.ReceivedSPFField(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.HasPrefix(field, "Received-SPF: ") || !strings.HasSuffix(field, "\r\n") {
			t.Errorf("%s: field %q lacks its name or CRLF", tc.name, field)
			continue
		}
		body := strings.TrimSuffix(field, "\r\n")
		if unfolded := strings.ReplaceAll(body, "\r\n", ""); unfolded != "Received-SPF: "+value {
			t.Errorf("%s: unfolds to\n%q\nwant\n%q", tc.name, unfolded, "Received-SPF: "+value)
		}
		lines := strings.Split(body, "\r\n")
		for i, line := range lines {
			if len(line) > 998 {
				t.Errorf("%s: line %d is %d octets", tc.name, i, len(line))
			}
			if strings.ContainsAny(line, "\r\n") {
				t.Errorf("%s: line %d holds a bare CR or LF", tc.name, i)
			}
			if i > 0 && (len(line) < 2 || line[0] != ' ' || line[1] == ' ') {
				t.Errorf("%s: continuation line %d %q does not start with one space before a word", tc.name, i, line)
			}
			if len(line) > 78 && strings.Contains(strings.TrimSpace(line), " ") {
				t.Errorf("%s: line %d is %d octets but holds a space to fold at", tc.name, i, len(line))
			}
		}
		if tc.name != "short" && len(lines) < 2 {
			t.Errorf("%s: not folded: %q", tc.name, field)
		}
	}
}
