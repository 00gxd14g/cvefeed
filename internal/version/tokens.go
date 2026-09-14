package version

import "strings"

// tokenKind distinguishes the two things a version string is made of once the
// punctuation is stripped.
type tokenKind int

const (
	tokenNumeric tokenKind = iota
	tokenAlpha
)

// token is one run of digits or letters, together with the punctuation byte
// that introduced it. The separator is kept because it is the only evidence
// available about what a trailing component means: "1.0-1" is a distro revision
// and "1.0.0-1" is a semver pre-release, and they sort in opposite directions.
type token struct {
	kind tokenKind
	text string
	sep  byte
}

// tokenize splits s into digit and letter runs. Every other byte is punctuation
// and only survives as the sep of the token that follows it.
func tokenize(s string) []token {
	var out []token
	var sep byte
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case isDigit(c):
			j := i
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			out = append(out, token{kind: tokenNumeric, text: s[i:j], sep: sep})
			sep = 0
			i = j
		case isLetter(c):
			j := i
			for j < len(s) && isLetter(s[j]) {
				j++
			}
			out = append(out, token{kind: tokenAlpha, text: s[i:j], sep: sep})
			sep = 0
			i = j
		default:
			sep = c
			i++
		}
	}
	return out
}

// stripV removes the decorative leading "v" that Go, GitHub tags and half the
// CNAs put in front of a number. It is removed only when a digit follows, so
// that a product genuinely named "vim" or a version "v" is left alone.
func stripV(s string) string {
	if len(s) >= 2 && (s[0] == 'v' || s[0] == 'V') && isDigit(s[1]) {
		return s[1:]
	}
	return s
}

// compareNumericText orders two digit runs by value without parsing them into
// an integer. Corpus versions include date stamps and 20-digit build counters,
// and rpm hit this exact bug: atoi overflowed and long releases compared wrong.
func compareNumericText(a, b string) int {
	a, b = trimZeroes(a), trimZeroes(b)
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return sign(strings.Compare(a, b))
}

// trimZeroes strips leading zeroes but never empties the string of a zero.
func trimZeroes(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isDigit(c) || isLetter(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
