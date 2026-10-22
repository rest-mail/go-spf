# go-spf

[![CI](https://github.com/rest-mail/go-spf/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-spf/actions/workflows/ci.yml)
[![Coverage gate: >=95%](https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)](COVERAGE.md)
[![Checklist: 84/104 mapped](https://img.shields.io/badge/checklist-84%2F104%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-spf.svg)](https://pkg.go.dev/github.com/rest-mail/go-spf)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-spf)](https://goreportcard.com/report/github.com/rest-mail/go-spf)

SPF ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)) evaluation for Go,
from the [REST Mail](https://rest-mail.com) project. Standard library only, no
external dependencies.

## About

Sender Policy Framework lets a domain publish, in a DNS TXT record, which hosts
may send mail that uses the domain in the SMTP `MAIL FROM` or `HELO` identity.
A receiver evaluates the record against the connecting client's IP address and
gets one of seven results: `none`, `neutral`, `pass`, `fail`, `softfail`,
`temperror` or `permerror`.

This package is a complete implementation of RFC 7208's `check_host()`
function, checked against the RFC in [CHECKLIST.md](CHECKLIST.md). The
checklist records the section audit and distinguishes evaluator proofs from
publisher and MTA duties.

## Features

- Every mechanism: `all`, `include`, `a`, `mx`, `ptr` (evaluated, though the
  RFC discourages publishing it), `ip4`, `ip6` and `exists`.
- Both modifiers: `redirect=` and `exp=`, with the explanation string expanded
  and returned for a `fail`.
- The full macro language of section 7, `%{p}` and the explanation-only
  `%{c}`, `%{r}` and `%{t}` included.
- The processing limits of section 4.6.4: 10 DNS-querying terms, 2 void
  lookups, 10 MX names per `mx`, 10 PTR names per `ptr` or `%{p}`, and a time
  limit (20 seconds by default).
- Both identities: the `MAIL FROM` check (with the null reverse-path) and the
  `HELO` check.
- Strict parsing: a syntax error anywhere in a record is a `permerror` before
  anything is evaluated.
- DNS behind a `Resolver` interface that `*net.Resolver` satisfies; tests use an
  in-memory resolver.
- Zero external dependencies.

## Install

```sh
go get github.com/rest-mail/go-spf
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rest-mail/go-spf"
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

## Checking

- `CheckMailFrom(ctx, ip, mailFrom, helo, opts)` checks the `MAIL FROM`
  identity. `mailFrom` may carry angle brackets and a source route; an empty
  one (the null reverse-path) checks `postmaster@<helo>`.
- `CheckHELO(ctx, ip, helo, opts)` checks the `HELO` identity. A HELO that is
  not a multi-label domain name (an address literal, say) gives `none`.
- `CheckHost(ctx, ip, domain, sender, helo, opts)` is `check_host()` itself.

Internationalized names (RFC 8616 §4): U-labels in the domain, in the
sender's domain and in the HELO name are converted to A-labels (`xn--`
punycode) before the check, so `a@bücher.example` looks up
`xn--bcher-kva.example` and `%{d}`, `%{o}`, `%{s}` and `%{h}` expand to
A-labels. A UTF-8 local-part is left as it is, so `%{l}` and `%{s}` built
from one rarely match. Names in a published record must already be A-labels.
The conversion lower-cases a non-ASCII label but does not apply the full
IDNA2008 mapping (NFC normalization, special folds such as ß).

Each returns a `Response`: the `Result`; the `Mechanism` that decided it (or
`default` when the record's implicit `?all` applied); for a `fail`, the
domain's `Explanation`, which is third-party text to be shown as such; and a
human-readable `Reason`. `Reason` and `Explanation` are always printable
US-ASCII, so they cannot break a header field or an SMTP reply.

An IPv4-mapped IPv6 client address is checked as the IPv4 address it carries.

Executable examples demonstrate checking HELO before MAIL FROM, checking
MAIL FROM even when HELO gives no definitive result (or is not checked),
attributing third-party explanations, and a receiver policy that treats
`neutral` exactly like `none` and never rejects on `softfail` alone. These
five checklist mappings prove the examples; callers remain responsible for
identity selection, SMTP replies and message handling.

## DNS

`Options.Resolver` takes any `Resolver`:

```go
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}
```

`*net.Resolver` satisfies it, and `net.DefaultResolver` is the default. A custom
resolver reports a name that does not exist, or has no records of the asked
type, with no records and a nil error or with a `*net.DNSError` whose
`IsNotFound` is true. Every other error, a timeout included, is a transient
failure and gives `temperror`, as RFC 7208 requires. `LookupTXT` returns one
string per TXT record with its character-strings joined without spaces, as
`net.Resolver` does.

## Choices the RFC leaves open

Where RFC 7208 leaves a detail to the implementation, this package takes the
simplest secure option:

- **A target-name that is not a valid domain after macro expansion** (section
  4.8): for `a`, `mx` and `exists` it is treated as a name that does not exist,
  which is a void lookup that does not match, and no query is sent. For
  `include` and `redirect` it is a `permerror`. Valid means visible US-ASCII,
  labels of 1 to 63 characters, at least two labels, and a top-level label that
  is not all digits.
- **`%{p}`** counts against the 10-query limit the first time it is used in a
  record's terms; the PTR lookup is made once per evaluation and shared with
  `ptr`. In an explanation it is not counted, as `exp` is not.
- **A `ptr` lookup that finds no names** is a void lookup.
- **`%{h}` with no HELO name, and `%{r}` with no `Options.Receiver`,** expand to
  `unknown`.
- **No `exp=`** gives an empty explanation.
- **The explanation** is cut to 400 characters, so it fits an SMTP reply line.
- **A macro expansion longer than 8192 bytes** is treated as a malformed name.
  No real record comes near it, and it stops a hostile record and sender from
  making the evaluator build huge strings.
- **The void-lookup limit** is fixed at the RECOMMENDED two, not configurable.
- **A zero `netip.Addr`** client gives `permerror`.

## Testing

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist         # CHECKLIST.md and the tests agree
go test -run='^$' -fuzz='^FuzzParseRecord$' -fuzztime=30s .
```

CI also fails below 95% statement coverage; the lines left uncovered on
purpose are listed, each with a reason, in [COVERAGE.md](COVERAGE.md). The fuzz
targets are `FuzzParseRecord` (record parsing), `FuzzExpandMacros` (macro
expansion) and `FuzzCheckHost` (whole evaluations); CI runs each for 30
seconds, and their seed corpora are in `testdata/fuzz`.

The coverage badge shows the enforced minimum; measured statement coverage
is printed in each CI run's **RFC proof** log. The checklist badge counts
requirements mapped to tests over all checklist rows, including the 20
`n/a` rows with documented reasons. Each n/a row names a publisher/caller duty,
a condition that does not hold, or missing library functionality. The three
API proposals remain undecided in
[CHECKLIST.md](CHECKLIST.md#left-for-the-owner). CI checks the badge against
the actual checklist and its test mappings. The CI badge reports whether verification
passed.

The RFC's own examples are tests: the record evaluations of Appendix A and the
macro expansions of section 7.4. The [open-spf.org RFC 7208 test
suite](https://github.com/sdgathman/pyspf/blob/master/test/rfc7208-tests.yml) is
BSD-licensed, so it is not copied into this MIT repository; instead
`TestOpenSPFEquivalents` covers its scenarios, section by section, with cases
written for this package.

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the RFC's requirements item by item, and a
small program, [`internal/checklist`](internal/checklist/main.go), checks it
against the tests in CI. The reusable workflow invokes this existing checker;
other libraries keep their checked-in compatible checker and checklist.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

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

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

### Reusable RFC verification workflow

[`.github/workflows/rfc-verification.yml`](.github/workflows/rfc-verification.yml)
is the shared `workflow_call` entry point. Our own CI calls it by local path,
so the caller and workflow always come from the same commit. It retains Go
1.25.10, build and vet of `./...`, golangci-lint v2.11.4, fresh race tests
with atomic coverage, the fixed **95% minimum** (aiming for 100%), the existing
checklist CLI, and each selected fuzz target for **30 seconds**. Failed runs
upload `**/testdata/fuzz` crashers. Permissions remain `contents: read`; no
secrets or caller-supplied commands or source refs are accepted.

All inputs are typed GitHub strings containing nonempty JSON arrays:

| Input | Default | Meaning |
|-------|---------|---------|
| `packages` | `["./..."]` | Local Go package patterns measured by race coverage. Include every implementation package; document intentional uncovered statements in `COVERAGE.md`. |
| `checklist-dirs` | `["."]` | Local package directories scanned by `go run ./internal/checklist -file CHECKLIST.md`. No recursive patterns. |
| `fuzz-targets` | Required | Objects with exactly `package` (one local package) and `target` (one exact `FuzzName`), e.g. `[{"package":".","target":"FuzzParseRecord"}]`. |

Paths must be `.` or start with `./`; recursive `/...` is allowed only in
`packages`. Flags, traversal, shell syntax, regex fuzz selectors, empty arrays
and duplicate fuzz targets are refused. A named fuzz target must exist in
`go test -list=^Fuzz` output; it is run with an anchored exact selector.
Missing, duplicate, malformed or out-of-range coverage totals fail closed.
Each caller supplies its own compatible `internal/checklist`, `CHECKLIST.md`,
tests, `go.mod` and `COVERAGE.md`; this extraction does not remove checker
implementations from other repositories.

The caller keeps the existing required **Build & Test** context as an
`always()` aggregate depending on both the reusable RFC job and the offline
workflow fixtures. Only `success` from both yields success; failure,
cancellation or a skipped job cannot satisfy the gate. Future callers should
retain their required context with the same fail-closed aggregation pattern,
since a reusable job adds its own nested check name.

For future external callers, **after this PR merges**, review the merge commit
and pin its full 40-character SHA in
`rest-mail/go-spf/.github/workflows/rfc-verification.yml@<reviewed-merge-SHA>`.
Use that as the job-level `uses`, and pass the three inputs with `with`, as in
our [CI caller](.github/workflows/ci.yml). Do not copy our local workflow path
into a different repository or pin an unpublished branch. Checkout inside the
reusable job intentionally checks out the **caller** repository. The proof
helper is embedded in the reusable YAML, so it needs no second checkout and
does not infer the called repository from `github.workflow_sha`.

This is the first host/self-call slice of
[rest-mail-server#374](https://github.com/rest-mail/rest-mail-server/issues/374);
cross-repository migration remains open. Workflow syntax and context behavior
follow GitHub's [reusable workflow documentation](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
and [contexts reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

Focused offline gate fixtures (standard-library Python; a cached Go toolchain
compiles only the existing checklist CLI):

```sh
GOMAXPROCS=1 python3 -m unittest discover -s .github/tests -v
```

The fixtures execute the embedded Python gate with recorded race/fuzz command
execution and small synthetic coverage reports, plus the real checklist CLI
against temporary checklists. They do not replace GitHub's actual race,
coverage or 30-second fuzz proofs.

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-spf](https://pkg.go.dev/github.com/rest-mail/go-spf).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © 2026 rest-mail contributors
