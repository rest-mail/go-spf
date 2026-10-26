# Coverage exceptions

CI fails when statement coverage of `./...` falls below 95%. It measures with
`-coverpkg`, so the black-box suite in `pkg/spf/rfctest` counts toward the
packages it exercises. These are the statements left uncovered on purpose,
each with the reason. Add an entry here whenever you leave a statement
uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover completely; CI also runs the command itself. |
| `pkg/spf/internal/idna/idna.go` | `validULabel` | `return false` for an empty label | Unreachable: `ToALabels` calls it only for a label with a non-ASCII rune, which is never empty. The guard keeps the function correct on its own. |
| `pkg/spf/internal/dnstest/dnstest.go` | `New` | `panic("dnstest: bad line " + line)` | A test helper's guard: it fires only when a test writes a malformed zone line, which is a bug in that test. |
