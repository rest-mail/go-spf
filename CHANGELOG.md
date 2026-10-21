# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); releases are Go
module tags of the form `vMAJOR.MINOR.PATCH`.

## [Unreleased]

### Added

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
