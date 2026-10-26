// Package syntax parses SPF records and macro-strings (RFC 7208 §§4.5, 4.6.1,
// 5, 6 and 7, and the collected ABNF of §12). ParseRecord checks a whole record
// before anything is evaluated, so a syntax error anywhere is a permerror
// without any term being interpreted (§4.6). Macro-strings are parsed into
// tokens once, with the record; MacroToken.Transform and URLEscape are the
// parts of expansion that need no DNS. Package spf evaluates what this package
// parses.
package syntax
