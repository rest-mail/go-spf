# RFC 7208 checklist

Every requirement [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) places on
an SPF verifier, item by item, with the tests that cover it. The list takes in
every MUST, MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED and NOT RECOMMENDED that
applies to a verifier, plus the normative behaviour of check_host() that
carries no keyword (level "Normative"; section 4 makes that whole description
binding). Requirements on publishers of records are left out.

An item that does not apply to a library (because it is the receiving MTA's
policy, say) says "n/a" and why. CI checks this file against the tests with
`go run ./internal/checklist`; the format is described in the
[README](README.md#the-rfc-checklist).

Five caller responsibilities (SPF-ID-06/07, SPF-MOD-09 and
SPF-RESULT-02/05) are mapped to executable usage examples. These examples
run the public evaluator with injected DNS and check its results, query order
and displayed text. They demonstrate compliant caller behaviour; the library
still does not select identities, apply message disposition or present text
on a caller's behalf. The remaining n/a rows retain their individual reasons,
including SMTP and header handling outside this package and the
nonconfigurable void limit.

## Identities (§2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-ID-01 | 2.2, 4.1 | MUST | Evaluate check_host() with the client IP, the identity's domain, and the identity as the sender. | `TestCheckMailFromArguments`, `TestInvalidClientIP` |
| SPF-ID-02 | 2.2 | NOT RECOMMENDED | Check identities other than MAIL FROM and HELO against SPF records without the publishing ADMD's approval. | n/a: the library checks the identity its caller passes; CheckMailFrom and CheckHELO are its only identity-specific entry points, and which identities to check is the receiver's policy. |
| SPF-ID-03 | 2.2 | Normative | Extract the domain from MAIL FROM correctly despite source routes, the %-hack and bang paths. | `TestCheckMailFromExtractsDomain` |
| SPF-ID-04 | 2.3 | RECOMMENDED | Check the HELO identity separately, with the HELO name as the sender. | `TestCheckHELO` |
| SPF-ID-05 | 2.3 | Normative | Perform the HELO check only when the HELO name is a valid multi-label domain name (an address literal is not). | `TestCheckHELOInvalid` |
| SPF-ID-06 | 2.3 | RECOMMENDED | Check HELO before MAIL FROM when both are checked. | `ExampleCheckMailFrom_identityChecks` |
| SPF-ID-07 | 2.4 | MUST | Check MAIL FROM when a HELO check was not performed or reached no definitive result. | `ExampleCheckMailFrom_identityChecks` |
| SPF-ID-08 | 2.4 | Normative | With a null reverse-path, the MAIL FROM identity is postmaster@<HELO name>. | `TestCheckMailFromNullSender` |
| SPF-ID-09 | 2.5 | SHOULD | Perform the check during the SMTP transaction that receives the mail. | n/a: when the check runs is the caller's; the library has no SMTP session. |

## Records (§3, §4.4, §4.5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-REC-01 | 3.1, 4.4 | Normative | Look the record up with a TXT query only (never the retired SPF RR type). | `TestRecordLookupTXTOnly` |
| SPF-REC-02 | 3.3 | MUST | Treat a TXT record of several character-strings as their concatenation without spaces. | `TestTXTStringsConcatenated` |
| SPF-REC-03 | 4.5 | Normative | Discard records that do not begin with exactly "v=spf1" followed by a space or the end ("v=spf10" is discarded). | `TestRecordSelection` |
| SPF-REC-04 | 4.5 | Normative | With no SPF record left after selection, return none. | `TestRecordSelection` |
| SPF-REC-05 | 3.2, 4.5 | Normative | With more than one SPF record, return permerror. | `TestMultipleRecords` |
| SPF-REC-06 | 4.4 | Normative | A server failure, any other error RCODE, or a timeout on the record lookup returns temperror. | `TestRecordLookupErrors` |
| SPF-REC-07 | 4.3 | Normative | A record lookup answered with NXDOMAIN returns none. | `TestRecordLookupErrors` |

## Evaluation (§4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-EVAL-01 | 4 | MUST | Produce results semantically equivalent to the check_host() description (shown on the RFC's own examples and on cases equivalent to the open-spf.org suite). | `FuzzCheckHost`, `TestAppendixA1`, `TestAppendixA2`, `TestAppendixA3`, `TestAppendixA4`, `TestOpenSPFEquivalents` |
| SPF-EVAL-02 | 4.3 | Normative | Return none for a malformed domain (label over 63 characters, empty label, over 253 characters) or one that is not multi-label. | `TestCheckHELOInvalid`, `TestMalformedDomain` |
| SPF-EVAL-03 | 4.3 | MUST | Internationalized domain names are encoded as A-labels (a U-label domain is malformed). | `TestInternationalizedDomain` |
| SPF-EVAL-04 | 4.3 | Normative | Substitute "postmaster" for a missing local-part of the sender. | `TestSenderWithoutLocalPart` |
| SPF-EVAL-05 | 4.6 | Normative | Validate the syntax of the whole record first; a syntax error anywhere returns permerror before any term is evaluated. | `TestSyntaxErrorAnywhere` |
| SPF-EVAL-06 | 4.6.1, 12 | Normative | Parse terms by the ABNF: separated by spaces, modifiers are name "=" value, names case-insensitive, anything else a syntax error. | `TestRecordSyntax`, `FuzzParseRecord` |
| SPF-EVAL-07 | 4.6.2 | Normative | Evaluate mechanisms left to right; the first match returns its qualifier's result (+ pass, - fail, ~ softfail, ? neutral; + by default). | `TestQualifiers`, `TestFirstMatchWins` |
| SPF-EVAL-08 | 4.6.2 | Normative | A mechanism that returns an exception ends evaluation with that exception. | `TestExceptionStopsEvaluation` |
| SPF-EVAL-09 | 4.7 | Normative | When no mechanism matches and there is no redirect, return neutral. | `TestDefaultResult` |
| SPF-EVAL-10 | 4.8 | Normative | A mechanism without a domain-spec uses the current <domain> as its target-name. | `TestDefaultTargetName` |
| SPF-EVAL-11 | 4.8 | Normative | Handle a syntactically invalid target-name after macro expansion consistently (here: a name that does not exist; permerror for include and redirect). | `TestMalformedTargetName` |

## Processing limits (§4.6.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-LIMIT-01 | 4.6.4 | MUST | Limit include, a, mx, ptr, exists and redirect to 10 per evaluation; exceeding the limit returns permerror. | `TestLookupLimit` |
| SPF-LIMIT-02 | 4.6.4 | Normative | all, ip4, ip6 and exp do not count towards the DNS-query limit. | `TestLookupLimitIgnoresNonDNSTerms` |
| SPF-LIMIT-03 | 4.1 | Normative | Track the DNS-query limit globally across include and redirect recursion. | `TestLookupLimitAcrossRecursion` |
| SPF-LIMIT-04 | 4.6.4, 5.4 | MUST NOT | An mx term must not resolve more than 10 MX names; exceeding the limit returns permerror. | `TestMXNameLimit` |
| SPF-LIMIT-05 | 4.6.4, 5.5 | MUST | For ptr and %{p}, ignore PTR names after the first 10. | `TestPTRNameLimit` |
| SPF-LIMIT-06 | 4.6.4 | SHOULD | Limit the elapsed time of an evaluation; exceeding it returns temperror. | `TestTimeout` |
| SPF-LIMIT-07 | 4.6.4 | SHOULD | The elapsed-time limit allows at least 20 seconds. | `TestDefaultOptions` |
| SPF-LIMIT-08 | 4.6.4, 11.1 | SHOULD | Limit void lookups (NXDOMAIN or no answers) to two; exceeding the limit returns permerror. | `TestVoidLookupLimit` |
| SPF-LIMIT-09 | 4.6.4 | RECOMMENDED | If the void-lookup limit is configurable, it defaults to two. | n/a: the limit is fixed at two, not configurable. |

## Mechanisms (§5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-MECH-01 | 5 | Normative | Without a CIDR length, compare addresses for equality; with one, compare that many high-order bits. | `TestCIDRMatching`, `TestCheckHostIPv6ZoneIgnored` |
| SPF-MECH-02 | 5 | Normative | Fetch A records for an IPv4 client and AAAA records for an IPv6 client; treat an IPv4-mapped IPv6 client as IPv4. | `TestAddressFamilies` |
| SPF-MECH-03 | 5 | Normative | A DNS error (RCODE other than 0 or 3) or timeout in a mechanism returns temperror; NXDOMAIN is treated as an empty answer. | `TestMechanismDNSErrors` |
| SPF-MECH-04 | 5.1 | MUST | Ignore mechanisms after "all". | `TestAllEndsEvaluation` |
| SPF-MECH-05 | 5.1, 6.1 | MUST | Ignore redirect when the record has an "all" mechanism anywhere. | `TestRedirectIgnoredWithAll` |
| SPF-MECH-06 | 5.2 | Normative | include evaluates check_host() on the target with the same IP and sender, and maps its result by the table of 5.2. | `TestInclude`, `TestAppendixA2`, `TestAppendixA4` |
| SPF-MECH-07 | 5.3 | Normative | a matches when the client is one of the target-name's addresses. | `TestA`, `TestAppendixA1` |
| SPF-MECH-08 | 5.4 | Normative | mx matches when the client is an address of one of the target-name's MX hosts. | `TestMX`, `TestAppendixA1` |
| SPF-MECH-09 | 5.4 | MUST NOT | Do not apply the implicit-MX rule: a target without MX records is not matched against its own addresses. | `TestMXNoImplicitMX` |
| SPF-MECH-10 | 5.5 | MUST | Support ptr: validate the client's PTR names by forward lookup, and match a validated name equal to or under the target-name. | `TestPTR`, `TestAppendixA1`, `TestAppendixA4` |
| SPF-MECH-11 | 5.5 | Normative | A DNS error on the PTR lookup makes ptr not match; an error on a name's address lookup skips that name. | `TestPTRErrors` |
| SPF-MECH-12 | 5.6 | Normative | ip4 and ip6 match the client against the network, with /32 and /128 by default and strict address and length syntax. | `TestIP4IP6`, `TestAppendixA1` |
| SPF-MECH-13 | 5, 5.6 | Normative | An IPv4 client is matched only by ip4; ip6 never matches it, and ip4 never matches an IPv6 client. | `TestIPFamilyMismatch` |
| SPF-MECH-14 | 5.7 | Normative | exists looks up the expanded name with an A query, even for an IPv6 client, and matches if any A record is returned. | `TestExists`, `TestAppendixA3` |

## Modifiers (§6)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-MOD-01 | 6 | MUST NOT | redirect and exp each appear at most once; a record with either twice returns permerror. | `TestDuplicateModifiers` |
| SPF-MOD-02 | 6 | MUST | Ignore unrecognized modifiers wherever and however often they appear. | `TestUnknownModifiers` |
| SPF-MOD-03 | 6.1 | Normative | redirect applies when no mechanism matched; the target's result is the result, except that none or a malformed target gives permerror. | `TestRedirect`, `TestAppendixA2` |
| SPF-MOD-04 | 6.2 | MUST | Without an exp modifier, return a default or an empty explanation. | `TestExplanationAbsent` |
| SPF-MOD-05 | 6.2 | Normative | Compute the explanation for a fail from a mechanism match; a DNS error, no record, several records or a syntax error means no explanation. | `TestExplanation`, `TestExplanationProblems` |
| SPF-MOD-06 | 6.2 | Normative | The explanation TXT strings are concatenated and macro-expanded as an explain-string. | `TestExplanationMacros` |
| SPF-MOD-07 | 6.2 | MUST | Limit the explanation string to US-ASCII. | `TestExplanationASCII` |
| SPF-MOD-08 | 6.2 | MAY | Limit the length of the explanation string. | `TestExplanationLength` |
| SPF-MOD-09 | 6.2 | SHOULD | Make clear that the explanation comes from a third party. | `Example` |
| SPF-MOD-10 | 6.2 | MUST NOT | During include, do not use the exp of the included target. | `TestExplanationScope` |
| SPF-MOD-11 | 6.2 | MUST NOT | After redirect, do not use the exp of the original domain. | `TestExplanationScope` |

## Macros (§7)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-MACRO-01 | 7.1 | Normative | "%%" expands to "%", "%_" to a space and "%-" to "%20". | `TestMacroEscapes` |
| SPF-MACRO-02 | 7.3 | Normative | A "%" not followed by "{", "%", "-" or "_", or any other malformed macro, is a syntax error (permerror). | `TestMacroSyntaxErrors` |
| SPF-MACRO-03 | 7.2 | Normative | Expand s, l, o, d, i, p, v and h; c, r and t are allowed only in explanation text. | `TestMacroLetters`, `TestExpOnlyMacros` |
| SPF-MACRO-04 | 7.3 | Normative | Transformers split on the delimiters ("." by default), optionally reverse, keep the right-hand parts, and rejoin with "."; empty parts are kept. | `FuzzExpandMacros`, `TestMacroTransformers`, `TestAppendixA3` |
| SPF-MACRO-05 | 7.3 | MUST | Accept trailing dots in domain names. | `TestTrailingDots` |
| SPF-MACRO-06 | 7.3 | MUST | A digit transformer is nonzero. | `TestMacroSyntaxErrors` |
| SPF-MACRO-07 | 7.3 | MUST | Support digit transformers of at least 127; more parts than available keeps them all. | `TestMacroTransformers` |
| SPF-MACRO-08 | 7.3 | Normative | s, l and o keep the original sender through include and redirect. | `TestSenderMacrosAcrossRecursion` |
| SPF-MACRO-09 | 7.3 | Normative | i is the dotted quad (IPv4) or dotted nibbles (IPv6); c is a conventional text form. | `TestMacroIPForms` |
| SPF-MACRO-10 | 7.3 | SHOULD | p prefers the domain itself, then a subdomain of it, then any validated name; "unknown" when there is none or on a DNS error. | `TestMacroP` |
| SPF-MACRO-11 | 7.3 | SHOULD | r is the receiving host's domain name, or "unknown". | `TestExplanationMacros` |
| SPF-MACRO-12 | 7.3 | Normative | t is the current time in seconds since the epoch; h is the HELO/EHLO name. | `TestMacroLetters`, `TestExplanationMacros` |
| SPF-MACRO-13 | 7.3 | Normative | An expanded name over 253 characters loses labels from the left until it fits. | `TestTargetTruncation` |
| SPF-MACRO-14 | 7.3 | MUST | Uppercase macros are URL-escaped: every character outside the RFC 3986 unreserved set. | `TestMacroURLEscape` |
| SPF-MACRO-15 | 7.4 | Normative | The expansion examples of 7.4 expand as shown. | `TestMacroExamples` |

## Results and their handling (§2.6, §8)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-RESULT-01 | 2.6, 4.2 | Normative | check_host() returns one of none, neutral, pass, fail, softfail, temperror and permerror. | `TestSevenResults` |
| SPF-RESULT-02 | 8.2 | MUST | Treat neutral exactly like none. | `ExampleResult_receiverPolicy` |
| SPF-RESULT-03 | 8.4 | SHOULD | Reject a fail during SMTP with reply code 550 (5.7.1). | n/a: the library sends no SMTP replies. |
| SPF-RESULT-04 | 8.4 | SHOULD | If a fail is accepted, add a Received-SPF or Authentication-Results field. | n/a: the library writes no header fields. |
| SPF-RESULT-05 | 8.5 | SHOULD NOT | Reject a message on softfail alone. | `ExampleResult_receiverPolicy` |
| SPF-RESULT-06 | 8.6 | SHOULD | Reject a temperror during SMTP with reply code 451 (4.4.3). | n/a: the library sends no SMTP replies. |
| SPF-RESULT-07 | 8.7 | SHOULD | Reject a permerror during SMTP with reply code 550 (5.5.2). | n/a: the library sends no SMTP replies. |

## Recording the result (§9)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-HDR-01 | 9 | RECOMMENDED | Record the result in the message header. | n/a: the library writes no header fields; its caller does. |
| SPF-HDR-02 | 9.1 | MUST | Prepend Received-SPF above the receiver's Received field and above any other Received-SPF. | n/a: the library writes no header fields. |
| SPF-HDR-03 | 9.1 | SHOULD | Give a comment and the client-ip, helo and envelope-from keys in Received-SPF. | n/a: the library writes no header fields; Response carries the mechanism and reason a caller needs. |
| SPF-HDR-04 | 9.1, 11.5.1 | MUST | Header content holds no invalid characters or sender-supplied malicious data (the library's part: Reason and Explanation are printable US-ASCII). | `TestResponseTextIsPrintable` |

## Security (§11)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-SEC-01 | 11.5.3 | Normative | Be prepared for hostile content that macros carry from the sender into DNS queries. | `FuzzParseRecord`, `FuzzExpandMacros`, `FuzzCheckHost`, `TestHostileMacroInput` |
