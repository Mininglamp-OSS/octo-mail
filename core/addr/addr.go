// Package addr holds small, dependency-free helpers for pulling parts out of an
// email address string. These are deliberately lenient (they accept
// angle-bracketed and untrimmed input and never error) — call sites that need
// strict RFC 5321 parsing use mox's smtp.ParseAddress instead. Centralizing them
// here keeps the several mailflow packages from each hand-rolling "find the @".
package addr

import "strings"

// Domain returns the domain part of an email address, or "" if there is no
// well-formed domain. Surrounding whitespace and angle brackets are stripped, and
// both a missing localpart and a missing domain yield "".
func Domain(address string) string {
	address = strings.Trim(strings.TrimSpace(address), "<>")
	i := strings.LastIndexByte(address, '@')
	if i <= 0 || i == len(address)-1 {
		return ""
	}
	return address[i+1:]
}
