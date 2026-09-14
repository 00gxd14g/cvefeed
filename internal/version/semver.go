package version

import "strings"

// semverParts is a semantic version decomposed for ordering. Build metadata is
// absent on purpose: clause 10 of the specification says it is ignored when
// determining precedence, so "1.0.0+build.1" and "1.0.0" are one version.
type semverParts struct {
	release []string // numeric core components, most significant first
	pre     []string // dot separated pre-release identifiers
}

// compareSemver orders two versions under Semantic Versioning 2.0.0.
//
// Producers declare SEMVER far more often than they ship it: GHSA normalises
// Composer and RubyGems ranges into semver-shaped strings, and CNAs type a
// four-component kernel version SEMVER without blinking. Anything the grammar
// rejects therefore falls through to compareGeneric rather than being refused,
// and the certainty says the declaration was not honoured.
func compareSemver(a, b string) (int, Certainty, bool) {
	pa, ca, oka := parseSemver(a)
	pb, cb, okb := parseSemver(b)
	if !oka || !okb {
		n, _, ok := compareGeneric(a, b)
		return n, Heuristic, ok
	}
	return compareSemverParts(pa, pb), weakest(ca, cb), true
}

func compareSemverParts(a, b semverParts) int {
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		x, y := "0", "0"
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if n := compareNumericText(x, y); n != 0 {
			return n
		}
	}

	// Clause 9: a pre-release version has lower precedence than the associated
	// normal version. Reading it the other way round reports every released
	// system as still carrying the flaw its release candidate had.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}

	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := isNumericIdentifier(x), isNumericIdentifier(y)
		switch {
		case xn && yn:
			if n := compareNumericText(x, y); n != 0 {
				return n
			}
		case xn:
			// Clause 11: numeric identifiers always have lower precedence than
			// alphanumeric ones.
			return -1
		case yn:
			return 1
		default:
			if n := strings.Compare(x, y); n != 0 {
				return sign(n)
			}
		}
	}
	// A larger set of pre-release fields wins when all the preceding ones are
	// equal: 1.0.0-alpha sorts before 1.0.0-alpha.1.
	return sign(len(a.pre) - len(b.pre))
}

// parseSemver reads a version leniently and reports how much repair it took.
//
// The repairs are the ones every semver implementation performs when coercing
// (a "v" prefix, a missing minor or patch) plus two the corpus forces:
// components past the third, which the Linux CNA emits as a matter of course,
// and the RubyGems habit of putting a pre-release behind a dot ("1.0.0.rc1").
//
// The grade says whether the specification decided the pair. Coercing a short
// version is order preserving and stays Exact; the other repairs read the
// string as something the grammar does not describe, and they are Heuristic:
// a fourth component is not semver, however naturally it orders, and a
// hyphen with nothing behind it ("1.0.0-") is not a pre-release of anything.
func parseSemver(s string) (semverParts, Certainty, bool) {
	var out semverParts
	certainty := Exact

	s = stripV(strings.TrimPrefix(clean(s), "="))
	if s == "" {
		return out, "", false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, out.pre = s[:i], splitPre(s[i+1:])
		if len(out.pre) == 0 {
			// Clause 9 requires at least one identifier after the hyphen.
			// "1.0.0-" orders as 1.0.0 — there is nothing else it can order
			// as — but the producer wrote something the grammar refuses.
			certainty = Heuristic
		}
	}
	if core == "" {
		return out, "", false
	}

	for i, part := range strings.Split(core, ".") {
		switch {
		case part == "":
			return out, "", false
		case isAllDigits(part):
			if len(part) > 1 && part[0] == '0' {
				// Clause 2 forbids leading zeroes, so a producer writing "01"
				// is using some other numbering and may mean something by it.
				certainty = Heuristic
			}
			if i >= 3 {
				// Clause 2 defines exactly three components. A fourth is the
				// kernel's, or a distribution's, and comparing it numerically
				// is the right reading — but it is a reading, not the rule.
				certainty = Heuristic
			}
			out.release = append(out.release, part)
		case i > 0 && len(out.pre) == 0 && isLetter(part[0]):
			// RubyGems spells a pre-release "1.0.0.rc1", which Gem::Version
			// orders exactly as semver orders "1.0.0-rc1". Rewriting it is a
			// reinterpretation of the string, so the grade drops.
			out.pre = splitPre(strings.Join(strings.Split(core, ".")[i:], "."))
			certainty = Heuristic
			return out, certainty, len(out.release) > 0
		default:
			return out, "", false
		}
	}
	return out, certainty, true
}

// splitPre splits a pre-release on dots. Empty identifiers are invalid semver
// but harmless to order, so they are kept rather than failing the whole parse.
func splitPre(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

func isNumericIdentifier(s string) bool { return s != "" && isAllDigits(s) }

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
