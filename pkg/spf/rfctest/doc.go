// Package rfctest is the black-box RFC conformance suite for go-spf. Its tests
// use only the public API of package spf, the way a mail server would: each one
// evaluates records served by an in-memory DNS zone through spf.CheckHost,
// spf.CheckMailFrom or spf.CheckHELO, and names the CHECKLIST.md items it
// covers. Tests that need the evaluator's internals live beside it, in package
// spf; tests of the record grammar live in package syntax.
package rfctest
