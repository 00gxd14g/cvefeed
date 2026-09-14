package version

import "strings"

// alpineSuffixRanks orders the suffix words apk knows, from apk-tools
// src/version.c. The pre suffixes are negative so that they sort below a
// version carrying no suffix at all, and the post suffixes are positive so they
// sort above it. Their relative order is the order of apk's own two arrays.
var alpineSuffixRanks = map[string]int{
	"alpha": -4,
	"beta":  -3,
	"pre":   -2,
	"rc":    -1,
	"cvs":   1,
	"svn":   2,
	"git":   3,
	"hg":    4,
	"p":     5,
}

// alpineVersion is an apk version: dotted numbers, an optional single letter,
// any number of _suffix[number] groups, and an optional -rN package revision.
type alpineVersion struct {
	numbers  []alpineNumber
	letter   string
	suffixes []alpineSuffix
	// revision is "" when the version states none, which is BELOW "-r0".
	revision string
}

// alpineNumber is one dotted component of an apk version.
//
// The leading zeroes are kept apart from the digits because apk does not read
// "05" as the number five. get_token()'s TOKEN_DIGIT_OR_ZERO case emits a
// synthetic token worth -(extra zeroes) *before* it reads the digits, so a
// zero-padded component sorts as a fraction: 1.0.05 < 1.0.4, and 1.00 < 1.0.
// Comparing the digits by value instead inverts the order of real Alpine
// versions -- nasm ships 2.15.05 and 2.16.01.
type alpineNumber struct {
	zeroes int // leading '0' bytes, always 0 for the first component
	digits string
}

type alpineSuffix struct {
	rank int
	// number is "" when the suffix states none, which is BELOW "0" for the same
	// reason an absent revision is: apk runs out of tokens sooner.
	number string
}

// compareAlpine orders two apk versions.
//
// Three traps, all of which show up in Wolfi and Chainguard data as much as in
// Alpine's own, and all settled by apk-tools src/version.c rather than by what
// the version strings look like they mean:
//
//   - _alpha, _beta, _pre and _rc sort BELOW the bare version while _p (and the
//     vcs suffixes) sort above it. Reading _p1 as a pre-release would report
//     every security-patched package as unfixed.
//   - A component with a leading zero is not the number it spells. See
//     alpineNumber.
//   - The -rN package revision is where the security fix usually lands, and an
//     absent -rN is not -r0. apk_version_compare_blob_fuzzy() runs the two
//     strings out of tokens at different token types -- TOKEN_END for "1.2.3"
//     and TOKEN_REVISION_NO for "1.2.3-r0" -- and its tail rule puts the side
//     that terminated first BELOW the other. An APKBUILD's first build does
//     carry pkgrel 0, but apk's comparator is what decides whether an installed
//     1.2.3-r0 is inside a bound of 1.2.3, and it says no.
//
// A trailing numeric component makes a version larger, so 1.0 sorts below
// 1.0.0. That follows the Gentoo-derived model apk implements and is the one
// place where this comparator and compareGeneric deliberately disagree; the
// differential test against "apk version -t" is what settles it.
func compareAlpine(a, b string) (int, Certainty, bool) {
	pa, oka := parseAlpine(a)
	pb, okb := parseAlpine(b)
	if !oka || !okb {
		n, _, ok := compareGeneric(a, b)
		return n, Heuristic, ok
	}

	for i := 0; i < len(pa.numbers) || i < len(pb.numbers); i++ {
		switch {
		case i >= len(pa.numbers):
			return -1, Exact, true
		case i >= len(pb.numbers):
			return 1, Exact, true
		}
		if n := compareAlpineNumbers(pa.numbers[i], pb.numbers[i]); n != 0 {
			return n, Exact, true
		}
	}
	if pa.letter != pb.letter {
		return sign(strings.Compare(pa.letter, pb.letter)), Exact, true
	}

	for i := 0; i < len(pa.suffixes) || i < len(pb.suffixes); i++ {
		switch {
		case i >= len(pa.suffixes):
			return -sign(pb.suffixes[i].rank), Exact, true
		case i >= len(pb.suffixes):
			return sign(pa.suffixes[i].rank), Exact, true
		}
		x, y := pa.suffixes[i], pb.suffixes[i]
		if x.rank != y.rank {
			return sign(x.rank - y.rank), Exact, true
		}
		if n := compareAlpineStated(x.number, y.number); n != 0 {
			return n, Exact, true
		}
	}
	return compareAlpineStated(pa.revision, pb.revision), Exact, true
}

// compareAlpineNumbers orders one dotted component against another.
func compareAlpineNumbers(a, b alpineNumber) int {
	switch {
	case a.zeroes > 0 && b.zeroes > 0:
		// Both carry apk's synthetic token; it is worth -(extra zeroes), so
		// more padding sorts lower: 1.00 < 1.0 and 1.005 < 1.05.
		if n := sign(b.zeroes - a.zeroes); n != 0 {
			return n
		}
	case a.zeroes > 0:
		// The synthetic token is at most zero and a component with no padding
		// opens with a digit of at least one, so the padded side loses before
		// its digits are ever read: 1.05 < 1.5.
		return -1
	case b.zeroes > 0:
		return 1
	}
	return compareNumericText(a.digits, b.digits)
}

// compareAlpineStated orders a revision or suffix number that may be absent.
// Absent is below stated, however small the stated one is.
func compareAlpineStated(a, b string) int {
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	return compareNumericText(a, b)
}

// parseAlpine reads the apk grammar and fails on anything outside it, leaving
// the caller to fall back. Being strict here is what keeps a Debian or semver
// string from being silently read as apk.
func parseAlpine(s string) (alpineVersion, bool) {
	var out alpineVersion

	rest := stripV(s)
	if i := strings.LastIndex(rest, "-r"); i >= 0 {
		if rev := rest[i+2:]; isAllDigits(rev) {
			out.revision, rest = rev, rest[:i]
		}
	}
	if strings.IndexByte(rest, '-') >= 0 || rest == "" {
		return out, false
	}

	numbers := rest
	if i := strings.IndexByte(rest, '_'); i >= 0 {
		numbers, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}

	// A single trailing letter is part of the version number, not a suffix:
	// 1.0a follows 1.0.
	if n := len(numbers); n > 0 && isLetter(numbers[n-1]) {
		out.letter, numbers = strings.ToLower(numbers[n-1:]), numbers[:n-1]
	}
	if numbers == "" {
		return out, false
	}
	for i, part := range strings.Split(numbers, ".") {
		if !isAllDigits(part) {
			return out, false
		}
		number := alpineNumber{digits: part}
		if i > 0 {
			// Only a component introduced by a '.' is read as
			// TOKEN_DIGIT_OR_ZERO; the first one is a plain TOKEN_DIGIT, so
			// "05.1" and "5.1" are one version.
			for j := 0; j < len(part) && part[j] == '0'; j++ {
				number.zeroes++
			}
		}
		out.numbers = append(out.numbers, number)
	}

	for rest != "" {
		if rest[0] != '_' {
			return out, false
		}
		rest = rest[1:]
		word := rest
		for i := 0; i < len(rest); i++ {
			if !isLetter(rest[i]) {
				word = rest[:i]
				break
			}
		}
		rank, known := alpineSuffixRanks[strings.ToLower(word)]
		if !known {
			return out, false
		}
		rest = rest[len(word):]
		number := ""
		i := 0
		for i < len(rest) && isDigit(rest[i]) {
			i++
		}
		if i > 0 {
			number, rest = rest[:i], rest[i:]
		}
		out.suffixes = append(out.suffixes, alpineSuffix{rank: rank, number: number})
	}
	return out, true
}
