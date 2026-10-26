package rfctest

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rest-mail/go-spf/pkg/spf"
)

// TestModifierPositions checks that publication advice about putting modifiers
// last does not become an evaluator syntax restriction. Both modifier orders
// and every position among mechanisms have identical results and DNS effects.
//
// checklist: SPF-MOD-12
func TestModifierPositions(t *testing.T) {
	modifiers := [][]string{
		{"exp=outer-exp.example", "redirect=target.example"},
		{"redirect=target.example", "exp=outer-exp.example"},
	}
	for _, mods := range modifiers {
		for first := 0; first < 4; first++ {
			for second := first + 1; second < 4; second++ {
				terms := make([]string, 4)
				terms[first], terms[second] = mods[0], mods[1]
				mechanisms := []string{"ip4:192.0.2.1", "-ip4:192.0.2.2"}
				for i, next := 0, 0; i < len(terms); i++ {
					if terms[i] == "" {
						terms[i] = mechanisms[next]
						next++
					}
				}
				record := "v=spf1"
				for _, term := range terms {
					record += " " + term
				}
				t.Run(record, func(t *testing.T) {
					for _, tc := range []struct {
						ip, mechanism, explanation string
						result                     spf.Result
						queries                    []string
					}{
						{"192.0.2.1", "ip4:192.0.2.1", "", spf.ResultPass, []string{"TXT example.com"}},
						{"192.0.2.2", "-ip4:192.0.2.2", "outer example.com", spf.ResultFail, []string{"TXT example.com", "TXT outer-exp.example"}},
						{"192.0.2.3", "-all", "target target.example", spf.ResultFail, []string{"TXT example.com", "TXT target.example", "TXT target-exp.example"}},
					} {
						z := zone(
							"example.com TXT "+record,
							"target.example TXT v=spf1 -all exp=target-exp.example",
							"outer-exp.example TXT outer %{d}",
							"target-exp.example TXT target %{d}",
						)
						got := mailFrom(z, tc.ip, "alice@example.com")
						if got.Result != tc.result || got.Mechanism != tc.mechanism || got.Explanation != tc.explanation {
							t.Errorf("%s: got %+v, want %s / %s / %q", tc.ip, got, tc.result, tc.mechanism, tc.explanation)
						}
						if !reflect.DeepEqual(z.Queries, tc.queries) {
							t.Errorf("%s: queries = %v, want %v", tc.ip, z.Queries, tc.queries)
						}
					}
				})
			}
		}
	}
}

// TestExplanationLookupTiming checks that exp DNS and macro processing happen
// only for the final fail, never for other results or an included domain's
// fail. An unused %{p} in exp must not cause a reverse lookup either.
//
// checklist: SPF-MOD-13
func TestExplanationLookupTiming(t *testing.T) {
	for _, tc := range []struct {
		name, record string
		result       spf.Result
		queries      []string
	}{
		{"pass", "v=spf1 +all", spf.ResultPass, []string{"TXT example.com"}},
		{"neutral", "v=spf1 ?all", spf.ResultNeutral, []string{"TXT example.com"}},
		{"default", "v=spf1", spf.ResultNeutral, []string{"TXT example.com"}},
		{"softfail", "v=spf1 ~all", spf.ResultSoftfail, []string{"TXT example.com"}},
		{"temperror", "v=spf1 a:broken.example", spf.ResultTempError, []string{"TXT example.com", "A broken.example"}},
		{"permerror", "v=spf1 unknown", spf.ResultPermError, []string{"TXT example.com"}},
		{"include", "v=spf1 include:included.example ?all", spf.ResultNeutral, []string{"TXT example.com", "TXT included.example"}},
		{"fail", "v=spf1 -all", spf.ResultFail, []string{"TXT example.com", "PTR 192.0.2.1", "TXT unknown.exp.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := zone(
				"example.com TXT "+tc.record+" exp=%{p}.exp.example",
				"included.example TXT v=spf1 -all exp=included-exp.example",
				"included-exp.example TXT must not be fetched",
				"unknown.exp.example TXT denied",
				"broken.example SERVFAIL A",
			)
			got := mailFrom(z, "192.0.2.1", "alice@example.com")
			want(t, tc.name, got, tc.result)
			explanation := ""
			if tc.result == spf.ResultFail {
				explanation = "denied"
			}
			if got.Explanation != explanation {
				t.Errorf("explanation = %q, want %q", got.Explanation, explanation)
			}
			if !reflect.DeepEqual(z.Queries, tc.queries) {
				t.Errorf("queries = %v, want %v", z.Queries, tc.queries)
			}
		})
	}
}

// TestExpandedTargetNotEscaped checks the DNS name sent through the public
// evaluator, including sender text that looks like a macro and a literal plus.
// The expansion result is neither reparsed as macros nor URL-escaped.
//
// checklist: SPF-EVAL-12
func TestExpandedTargetNotEscaped(t *testing.T) {
	z := zone(
		"example.com TXT v=spf1 exists:%{l}._spf.%{d} -all",
		"%{i}+tag._spf.example.com A 127.0.0.2",
	)
	got := spf.CheckMailFrom(context.Background(), netip.MustParseAddr("192.0.2.1"), "%{i}+tag@example.com", testHELO, opts(z))
	want(t, "literal expansion", got, spf.ResultPass)
	expected := []string{"TXT example.com", "A %{i}+tag._spf.example.com"}
	if !reflect.DeepEqual(z.Queries, expected) {
		t.Errorf("queries = %v, want %v", z.Queries, expected)
	}
}
