# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); releases are Go
module tags of the form `vMAJOR.MINOR.PATCH`.

## [Unreleased]

## [0.2.0] - 2026-10-26

### Changed (breaking)

- The library moves out of the module root into packages. The module path is
  unchanged (`github.com/rest-mail/go-spf`), but the root package is gone:
  - `github.com/rest-mail/go-spf/pkg/spf` holds the whole public API:
    `CheckMailFrom`, `CheckHELO`, `CheckHost`, `Result` and its seven values,
    `Response`, `Resolver`, `Options` and `DefaultTimeout`.
  - `pkg/spf/internal/syntax` (the record and macro-string grammar),
    `pkg/spf/internal/idna` (the RFC 8616 A-label conversion) and
    `pkg/spf/internal/dnstest` (the tests' in-memory DNS zone) are internal,
    so they are not importable.
- No exported name changes, and every check answers as it did in v0.1.2.

Migration: replace the import path.

| Before (v0.1) | After (v0.2) |
|---------------|--------------|
| `import "github.com/rest-mail/go-spf"` | `import "github.com/rest-mail/go-spf/pkg/spf"` |
| `spf.CheckMailFrom`, `spf.CheckHELO`, `spf.CheckHost`, `spf.Result`, `spf.Result*`, `spf.Response`, `spf.Resolver`, `spf.Options`, `spf.DefaultTimeout` | unchanged, now from `.../pkg/spf` |

### Changed

- The RFC tests that need only the public API move to a black-box suite,
  `pkg/spf/rfctest`. Tests that need the evaluator's internals stay beside it
  in `pkg/spf`. Every test, fuzz target and example is kept.
- The reusable RFC verification workflow measures coverage with `-coverpkg`
  over the packages it tests, so a black-box suite counts toward the packages
  it exercises. Its fixtures check that every checklist directory and fuzz
  target the caller names exists.

## [0.1.2] - 2026-10-23

### Fixed

- A U-label that IDNA2008 cannot allow is no longer converted and looked up
  (#8): one with a control, format, space or private-use code point, a ZERO
  WIDTH (NON-)JOINER, a leading combining mark, or a hyphen in a forbidden
  place. The name stays malformed and gives `none`, with no DNS query, as any
  non-ASCII name did before 0.1.1.

## [0.1.1] - 2026-10-23

### Changed

- **Breaking:** RFC 8616 §4: a U-label MAIL FROM domain, sender domain or HELO
  name is now converted to A-labels and checked, instead of giving `none` as
  a malformed name. Macros expand the A-label form. Names that are not valid
  UTF-8 still give `none`; U-labels in a record are still a syntax error.

### Added

- RFC 8616 §4 checklist rows SPF-EAI-01 to 03 and their tests. README
  checklist badge is now 84/104.

- RFC 7208 section audit: 13 additional checklist rows, including previously
  omitted publisher recommendations and full-header length/ordering duties.
  New evaluator tests prove modifier positions, deferred explanation DNS and
  literal expanded target names. README checklist badge is now 81/101; the
  three owner API proposals remain undecided.

- Every remaining n/a RFC 7208 row now says whether it is the caller's job, a
  condition that does not hold, or needs new public API. The three API
  proposals that would cover seven of them are listed in CHECKLIST.md's "Left
  for the owner" section. README badge stays 78/88.

- Five formerly n/a RFC 7208 rows now have executable caller examples covering
  HELO ordering and MAIL FROM fallback, third-party explanation attribution,
  neutral/none equivalence and softfail handling. Checklist mappings distinguish
  example behaviour from policy enforced by the library; README badge is 78/88.

- README coverage-gate and RFC checklist badges, checked in CI against the
  enforced coverage minimum and the checklist's actual test mappings.

## [0.1.0] - 2026-10-17

### Added

- A complete RFC 7208 `check_host()`: the `all`, `include`, `a`, `mx`, `ptr`,
  `ip4`, `ip6` and `exists` mechanisms; the `redirect` and `exp` modifiers; the
  full macro language of section 7; the processing limits of section 4.6.4;
  and all seven results. `CheckMailFrom` and `CheckHELO` check the two
  identities. DNS goes through a `Resolver` interface that `*net.Resolver`
  satisfies. The evaluator started as a port of the one in REST Mail's server
  and was completed to the RFC. (rest-mail/rest-mail-server#373)
- `CHECKLIST.md`, which maps every verifier requirement of RFC 7208 to its
  tests, and `internal/checklist`, which checks the two agree in CI.
- Tests for the RFC's Appendix A examples and section 7.4 macro examples, cases
  equivalent to the open-spf.org test suite, and fuzz tests for record
  parsing, macro expansion and whole evaluations.
