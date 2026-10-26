// Package idna converts internationalized domain names to their A-label
// (xn-- punycode) form, as RFC 8616 §4 requires before an SPF check. It holds
// only what SPF needs: the IDNA2008 checks that refuse a U-label outright, and
// RFC 3492 punycode encoding. ToALabels is its entry point.
package idna
