# go-spf

[![CI](https://github.com/rest-mail/go-spf/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-spf/actions/workflows/ci.yml)
[![Coverage gate: >=95%](https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)](COVERAGE.md)
[![Checklist: 84/104 mapped](https://img.shields.io/badge/checklist-84%2F104%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-spf.svg)](https://pkg.go.dev/github.com/rest-mail/go-spf/pkg/spf)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-spf)](https://goreportcard.com/report/github.com/rest-mail/go-spf)

SPF ([RFC 7208]) evaluation for Go, from the [REST Mail](https://rest-mail.com)
project. Standard library only: no external dependencies.

Sender Policy Framework lets a domain publish, in a DNS TXT record, which hosts
may send mail that uses the domain in the SMTP `MAIL FROM` or `HELO` identity.
A receiver evaluates the record against the connecting client's IP address and
gets one of seven results: `none`, `neutral`, `pass`, `fail`, `softfail`,
`temperror` or `permerror`. go-spf is a complete implementation of RFC 7208's
`check_host()` function, checked against the RFC in [CHECKLIST.md](CHECKLIST.md).
You pass it the client's address and the identities from the SMTP session; it
queries DNS through a resolver you can replace, and returns the result.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start](#quick-start): [check a message](#check-a-message), [your own DNS](#your-own-dns)
- [Features](#features): [the API](#the-api)
- [What the library does and what the host must do](#what-the-library-does-and-what-the-host-must-do)
- [RFC conformance](#rfc-conformance): [the checklist](#the-rfc-checklist), [what it does not do](#what-it-does-not-do), [badges and coverage](#badges-and-coverage), [the reusable workflow](#reusable-rfc-verification-workflow)
- [Changelog](#changelog)
- [Licence](#licence)

## Install

```sh
go get github.com/rest-mail/go-spf@latest
```

The module declares go 1.25. The API reference is on
[pkg.go.dev](https://pkg.go.dev/github.com/rest-mail/go-spf/pkg/spf).

## Packages

| Import path | What it holds |
|-------------|---------------|
| `github.com/rest-mail/go-spf/pkg/spf` | The library: `CheckMailFrom`, `CheckHELO`, `CheckHost`, `Result` and its seven values, `Response`, `Resolver`, `Options` and `DefaultTimeout`. |
| `pkg/spf/internal/syntax` | The record and macro-string grammar of RFC 7208. Internal: not importable. |
| `pkg/spf/internal/idna` | The A-label conversion of RFC 8616 §4: the IDNA2008 checks and punycode. Internal: not importable. |
| `pkg/spf/internal/dnstest` | The in-memory DNS zone the tests evaluate records against. Internal: not importable. |
| `pkg/spf/rfctest` | The black-box RFC test suite, driving only the public API. Tests only. |

Upgrading from v0.1 or earlier: the root package is gone, so import
`github.com/rest-mail/go-spf/pkg/spf`. Every name in it is unchanged.
[CHANGELOG.md](CHANGELOG.md#020---2026-10-26) has the old-to-new table.

## Quick start

### Check a message

```go
package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rest-mail/go-spf/pkg/spf"
)

func main() {
	ctx := context.Background()
	client := netip.MustParseAddr("192.0.2.25")

	// RFC 7208 recommends checking HELO first, then MAIL FROM. A nil
	// *spf.Options uses the system resolver and the default limits.
	helo := spf.CheckHELO(ctx, client, "mail.example.com", nil)
	from := spf.CheckMailFrom(ctx, client, "alice@example.com", "mail.example.com", nil)

	fmt.Println("helo:", helo.Result, helo.Reason)
	fmt.Println("mailfrom:", from.Result, from.Mechanism)
	if from.Result == spf.ResultFail && from.Explanation != "" {
		fmt.Println("example.com explains:", from.Explanation)
	}
}
```

### Your own DNS

`Options` takes a `Resolver`, the time limit, the receiver's name for `%{r}`
and a clock for `%{t}`. Any zero field takes its default:

```go
opts := &spf.Options{
	Resolver: resolver,              // your DNS; nil uses net.DefaultResolver
	Timeout:  10 * time.Second,      // zero uses spf.DefaultTimeout (20 seconds)
	Receiver: "mx.receiver.example", // what %{r} expands to; empty gives "unknown"
}
res := spf.CheckMailFrom(ctx, client, "<alice@example.com>", "mail.example.com", opts)
```

`Example` in [`pkg/spf/example_test.go`](pkg/spf/example_test.go) runs whole
checks against a static in-memory resolver, and two more examples there show a
receiver's identity order and result policy.

## Features

| Feature | RFC | Notes |
|---------|-----|-------|
| `check_host()` | [RFC 7208] §4 | The whole function: record lookup and selection, strict syntax, left-to-right evaluation and all seven results. |
| Mechanisms | §5 | `all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6` and `exists`, with dual CIDR lengths on `a` and `mx`. `ptr` is evaluated, though the RFC discourages publishing it. |
| Modifiers | §6 | `redirect=` and `exp=`. The explanation is expanded and returned for a `fail`. Unknown modifiers are checked for syntax and ignored. |
| Macros | §7 | The full macro language: every letter, `%{p}` and the explanation-only `%{c}`, `%{r}` and `%{t}` included, with the digit, reverse and delimiter transformers and URL escaping. |
| Processing limits | §4.6.4 | 10 DNS-querying terms, 2 void lookups, 10 MX names per `mx`, 10 PTR names per `ptr` or `%{p}`, and a time limit (20 seconds by default). |
| Identities | §2.3, §2.4 | `MAIL FROM`, with the null reverse-path and source routes, and `HELO`. |
| Internationalized names | [RFC 8616] §4 | U-labels in the domain, the sender's domain and the HELO name are checked as A-labels. |
| DNS | | Behind a `Resolver` interface that `*net.Resolver` satisfies. |
| Safe output | §11 | `Reason` and `Explanation` are always printable US-ASCII, and the explanation is at most 400 characters. |

### The API

- `spf.CheckMailFrom(ctx, ip, mailFrom, helo, opts)` checks the `MAIL FROM`
  identity. `mailFrom` may carry angle brackets and a source route; an empty
  one (the null reverse-path) checks `postmaster@<helo>`.
- `spf.CheckHELO(ctx, ip, helo, opts)` checks the `HELO` identity. A HELO that
  is not a multi-label domain name (an address literal, say) gives `none`.
- `spf.CheckHost(ctx, ip, domain, sender, helo, opts)` is `check_host()`
  itself, for callers that choose the identity and domain themselves.
- Each returns a `Response`: the `Result`; the `Mechanism` that decided it (or
  `default` when the record's implicit `?all` applied); for a `fail`, the
  domain's `Explanation`, which is third-party text to be shown as such; and a
  human-readable `Reason`.
- An IPv4-mapped IPv6 client address is checked as the IPv4 address it
  carries. A zero `netip.Addr` gives `permerror`.

## What the library does and what the host must do

Each area below says what go-spf handles and what stays with the host, the
mail server that calls it. The [checklist](CHECKLIST.md) records these
boundaries row by row.

### Identities and timing

The library:

- Checks the identity it is given, `MAIL FROM` or `HELO`, with the RFC's
  rules for the null reverse-path, a sender without a local-part
  (`postmaster`) and a HELO that is not a domain name.

The host:

- Chooses which identities to check and when. RFC 7208 recommends the `HELO`
  check first, then `MAIL FROM` when `HELO` gave no definitive result, during
  the SMTP transaction. The executable examples show this order, and checking
  `MAIL FROM` when `HELO` was not checked.
- Applies its own policy to the result: whether to reject, and with which SMTP
  reply. A sensible policy treats `neutral` exactly like `none` and never
  rejects on `softfail` alone, as `ExampleResult_receiverPolicy` shows.

### DNS

The library:

- Sends every query through `Options.Resolver`, so no test touches the
  network. `*net.Resolver` satisfies the interface below, and
  `net.DefaultResolver` is the default.
- Gives `temperror` for every DNS error other than "not found", a timeout
  included, as RFC 7208 requires, and bounds the whole evaluation by
  `Options.Timeout` and any deadline on the context.

The host:

- Supplies a resolver that reports a name that does not exist, or has no
  records of the asked type, with no records and a nil error or with a
  `*net.DNSError` whose `IsNotFound` is true. `LookupTXT` returns one string
  per TXT record with its character-strings joined without spaces, as
  `net.Resolver` does.
- Caches DNS answers, if it wants caching, in its resolver.

```go
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}
```

### Results and the explanation

The library:

- Returns the result, the deciding mechanism and a reason. `Reason` and
  `Explanation` are printable US-ASCII, so they cannot break a header field
  or an SMTP reply.

The host:

- Shows the `Explanation` of a `fail` as the domain's text, not its own.
- Records the result in the message, in a `Received-SPF` or
  `Authentication-Results` field, and places that field above any existing
  `Received-SPF` field.

### Internationalized names

The library:

- Converts U-labels in the domain, the sender's domain and the HELO name to
  A-labels (`xn--` punycode) before the check (RFC 8616 §4), so
  `a@bücher.example` looks up `xn--bcher-kva.example`, and `%{d}`, `%{o}`,
  `%{s}` and `%{h}` expand to A-labels.
- Refuses a U-label that IDNA2008 cannot allow: one with a control, format,
  space or private-use code point, a ZERO WIDTH (NON-)JOINER, a leading
  combining mark, a leading or trailing hyphen, or `--` in its third and
  fourth positions. Such a name gives `none`, and nothing is looked up for it.

The host:

- Publishes, or expects, names in records as A-labels already; a U-label in a
  record is a syntax error.
- Expects little from a UTF-8 local-part: it is left as it is, so `%{l}` and
  `%{s}` built from one rarely match.

### Choices the RFC leaves open

Where RFC 7208 leaves a detail to the implementation, go-spf takes the simplest
secure option:

- **A target-name that is not a valid domain after macro expansion** (§4.8):
  for `a`, `mx` and `exists` it is treated as a name that does not exist,
  which is a void lookup that does not match, and no query is sent. For
  `include` and `redirect` it is a `permerror`. Valid means visible US-ASCII,
  labels of 1 to 63 characters, at least two labels, and a top-level label
  that is not all digits.
- **`%{p}`** counts against the 10-query limit the first time it is used in a
  record's terms; the PTR lookup is made once per evaluation and shared with
  `ptr`. In an explanation it is not counted, as `exp` is not.
- **A `ptr` lookup that finds no names** is a void lookup.
- **`%{h}` with no HELO name, and `%{r}` with no `Options.Receiver`,** expand
  to `unknown`.
- **No `exp=`** gives an empty explanation.
- **The explanation** is cut to 400 characters, so it fits an SMTP reply line.
- **A macro expansion longer than 8192 bytes** is treated as a malformed name.
  No real record comes near it, and it stops a hostile record and sender from
  making the evaluator build huge strings.

## RFC conformance

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the verifier requirements of RFC 7208, and
the SPF section of RFC 8616, item by item. Each mapped row names the tests
that prove it. Most are in [`pkg/spf/rfctest`](pkg/spf/rfctest), which drives
only the public API with an in-memory DNS zone, as a mail server would. Tests
that need the evaluator's internals sit beside it in `pkg/spf`, and the record
grammar's own test in `pkg/spf/internal/syntax`. The checklist also records
the section audit, and marks publisher and caller duties `n/a` with the
reason.

The RFC's own examples are tests: the record evaluations of Appendix A and the
macro expansions of section 7.4. The [open-spf.org RFC 7208 test
suite](https://github.com/sdgathman/pyspf/blob/master/test/rfc7208-tests.yml)
is BSD-licensed, so it is not copied into this MIT repository; instead
`TestOpenSPFEquivalents` covers its scenarios, section by section, with cases
written for this package.

The checklist is a Markdown file of tables with this header:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SPF-EVAL-05 | 4.6 | Normative | Validate the syntax of the whole record first. | `TestSyntaxErrorAnywhere` |
| SPF-ID-09 | 2.5 | SHOULD | Perform the check during the SMTP transaction. | n/a: the library has no SMTP session. |
```

- **ID** is unique, upper case, and ends in a number: a prefix for the RFC, an
  area, and a sequence number (`SPF-EVAL-05`).
- **Section** is the RFC section (or sections) the requirement comes from.
- **Level** is the RFC 2119 keyword it carries (`MUST`, `MUST NOT`, `SHOULD`,
  `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, ...), or `Normative`
  for normative text without a keyword.
- **Requirement** says what is required, in one line (no `|`).
- **Tests** lists the test functions that cover it, separated by commas, or
  says `n/a:` and why it does not apply.

Each test names the items it covers in its doc comment:

```go
// TestSyntaxErrorAnywhere checks that the whole record is validated before
// any term is evaluated.
//
// checklist: SPF-EVAL-05
func TestSyntaxErrorAnywhere(t *testing.T) {
```

[`internal/checklist`](internal/checklist/main.go) checks one against the
other in CI. `go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]`
scans the `_test.go` files of the given package directories (default `.`;
subdirectories are not scanned) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

CI passes it every package directory that holds tests:

```sh
go run ./internal/checklist pkg/spf pkg/spf/rfctest pkg/spf/internal/syntax pkg/spf/internal/idna
```

### What it does not do

Some gaps are deliberate, and go-spf will not fill them. Others are planned,
each with an issue. The checklist records every one as an `n/a` row with its
reason.

#### Not supported, by design

| Area | What go-spf does | Why |
|------|------------------|-----|
| The SMTP session | Returns a result. It sends no SMTP reply, does not choose when to check, and never rejects mail. | The mail server owns the session and its policy. Keeping them out keeps the library usable from any MTA. |
| The message header | Writes no header field, and does not place or fold one. | The library never sees the message. Placing `Received-SPF` above the others and keeping it within line limits need the whole header. |
| The void-lookup limit | Fixed at two, not configurable. | Two is what RFC 7208 §4.6.4 recommends. The limit is a defence against hostile records, and a setting could only loosen it. |
| DNS caching | Caches nothing between checks. | Caching belongs in the resolver, where the host can share it with its other lookups and honour TTLs. |
| Full IDNA2008 mapping | Lower-cases a U-label but applies no NFC normalization or special folds (such as ß), and refuses a ZERO WIDTH (NON-)JOINER even after a virama. | These need Unicode tables beyond the standard library, and the library takes no dependencies. Only deliberately unusual spellings differ, and they give `none`, never a wrong `pass`. |

#### Not planned

| Area | What go-spf does |
|------|------------------|
| Publishing records | Evaluates published records only: no record generator or linter for record size, `ptr` use or modifier placement. Those are the publishing domain's duties. |
| Authentication-Results ([RFC 8601]) and DMARC | Not implemented. They combine SPF with DKIM and belong in a layer above go-spf, which supplies the SPF result they need. |

#### Planned

| Gap | Issue |
|-----|-------|
| No method names the SMTP reply that RFC 7208 §8 recommends for `fail`, `temperror` and `permerror`. | [#10](https://github.com/rest-mail/go-spf/issues/10) |
| No builder for the `Received-SPF` field value (§9.1) from a check. | [#11](https://github.com/rest-mail/go-spf/issues/11) |

### Badges and coverage

The badges at the top are checked by `TestReadmeChecklistBadge` in
`internal/checklist`, which reads the checklist directories from CI's own
configuration, and by the workflow fixtures in `.github/tests`. The checklist
badge counts mapped rows over all rows: the 20 `n/a` rows are in the
denominator, so the badge never claims more than the tests prove. The
coverage badge shows the floor CI enforces, not a measured figure; each CI
run prints the measured statement coverage in its **RFC proof** log. CI
measures with `-coverpkg`, so the black-box suite counts toward the packages
it exercises. The statements left uncovered on purpose are listed, each with
a reason, in [COVERAGE.md](COVERAGE.md).

```sh
go test -race ./...    # all tests, no network
go test -run='^$' -fuzz='^FuzzParseRecord$' -fuzztime=30s ./pkg/spf
GOMAXPROCS=1 python3 -m unittest discover -s .github/tests -v
```

Three fuzz targets in `pkg/spf` run in CI for 30 seconds each:
`FuzzParseRecord` (record parsing), `FuzzExpandMacros` (macro expansion) and
`FuzzCheckHost` (whole evaluations). Their seed corpora are in
`pkg/spf/testdata/fuzz`.

### Reusable RFC verification workflow

[`.github/workflows/rfc-verification.yml`](.github/workflows/rfc-verification.yml)
is a shared `workflow_call` entry point. Our own CI calls it by local path, so
the caller and the workflow always come from the same commit. It runs Go
1.25.10, build and vet of `./...`, golangci-lint v2.11.4, fresh race tests
with atomic coverage across the selected packages, the fixed **95% minimum**,
the checklist command, and each selected fuzz target for **30 seconds**.
Failed runs upload `**/testdata/fuzz` crashers. Permissions remain
`contents: read`; no secrets or caller-supplied commands or source refs are
accepted.

All inputs are typed GitHub strings containing nonempty JSON arrays:

| Input | Default | Meaning |
|-------|---------|---------|
| `packages` | `["./..."]` | Local Go package patterns tested with race coverage, measured across all of them (`-coverpkg`). Include every implementation package; document intentional uncovered statements in `COVERAGE.md`. |
| `checklist-dirs` | `["."]` | Local package directories scanned by `go run ./internal/checklist -file CHECKLIST.md`. No recursive patterns. |
| `fuzz-targets` | Required | Objects with exactly `package` (one local package) and `target` (one exact `FuzzName`), e.g. `[{"package":"./pkg/spf","target":"FuzzParseRecord"}]`. |

Paths must be `.` or start with `./`; recursive `/...` is allowed only in
`packages`. Flags, traversal, shell syntax, regex fuzz selectors, empty arrays
and duplicate fuzz targets are refused. A named fuzz target must exist in
`go test -list=^Fuzz` output; it is run with an anchored exact selector.
Missing, duplicate, malformed or out-of-range coverage totals fail closed.
Each caller supplies its own compatible `internal/checklist`, `CHECKLIST.md`,
tests, `go.mod` and `COVERAGE.md`.

The caller keeps the required **Build & Test** context as an `always()`
aggregate depending on both the reusable RFC job and the offline workflow
fixtures. Only `success` from both yields success; failure, cancellation or a
skipped job cannot satisfy the gate. Other callers should keep their required
context with the same fail-closed aggregation, since a reusable job adds its
own nested check name.

An external caller pins a reviewed merge commit by its full 40-character SHA,
`rest-mail/go-spf/.github/workflows/rfc-verification.yml@<reviewed-merge-SHA>`,
as the job-level `uses`, and passes the three inputs with `with`, as our
[CI caller](.github/workflows/ci.yml) does. Do not copy our local workflow
path into a different repository or pin an unpublished branch. Checkout inside
the reusable job checks out the **caller** repository. The proof helper is
embedded in the reusable YAML, so it needs no second checkout and does not
infer the called repository from `github.workflow_sha`. The cross-repository
migration is tracked in
[rest-mail-server#374](https://github.com/rest-mail/rest-mail-server/issues/374).

The offline fixtures in `.github/tests` run the embedded Python gate with
recorded race and fuzz commands and small synthetic coverage reports, run the
real checklist command against temporary checklists, and check that every
directory and fuzz target `ci.yml` names exists. They do not replace GitHub's
actual race, coverage or fuzz proofs.

## Changelog

Recent releases; see [CHANGELOG.md](CHANGELOG.md) for the complete history.

### v0.2.0 (2026-10-26)

The library moves to `pkg/spf`, with its grammar and IDNA code in internal
packages and a black-box RFC suite in `pkg/spf/rfctest` (breaking: the import
path changes; the changelog has a migration table). Checks answer as in
v0.1.2.

### v0.1.2 (2026-10-23)

A U-label that IDNA2008 cannot allow is no longer converted and looked up; the
name gives `none`.

### v0.1.1 (2026-10-23)

Internationalized names (RFC 8616 §4): U-labels in the MAIL FROM domain, the
sender's domain and the HELO name are checked as A-labels (breaking: they gave
`none` before). The checklist covers RFC 8616 and the full RFC 7208 section
audit.

### v0.1.0 (2026-10-17)

A complete RFC 7208 `check_host()`: every mechanism and modifier, the macro
language, the processing limits and all seven results, with `CheckMailFrom`
and `CheckHELO` for the two identities.

## Licence

[MIT](LICENSE) © 2026 rest-mail contributors

[RFC 7208]: https://www.rfc-editor.org/rfc/rfc7208
[RFC 8616]: https://www.rfc-editor.org/rfc/rfc8616
[RFC 8601]: https://www.rfc-editor.org/rfc/rfc8601
