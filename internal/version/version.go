// Package version orders version strings under the ordering scheme the upstream
// advisory declares for them, and refuses to order the pairs that no scheme can
// decide.
//
// The refusal is the point. A scanner is trusted for as long as its matches are
// real, and the cheapest way to manufacture a false positive is to invent an
// ordering: to compare a git commit hash against a release number, or to read a
// CNA's free-text "CUSTOM" bound as if it were semver. Two mechanisms keep an
// unprovable answer from being reported as a proven one:
//
//   - ErrNotComparable, for operands that carry no order at all. Commit hashes,
//     sentinel bounds ("unspecified", "*") and strings a scheme's grammar
//     rejects outright never receive a number.
//   - Certainty, for pairs decided only after repairing an operand or by a
//     fallback rule the scheme itself does not define. The answer is returned,
//     graded Heuristic, and the caller downgrades any match resting on it.
//
// The plurality of the stored corpus (127,515 of 348,339 ranges) declares
// versionType CUSTOM, which is the CNA stating that they declared no ordering.
// Those resolve to Generic, which answers what dotted-numeric comparison proves
// and refuses the rest. Generic is the default precisely because it cannot
// manufacture a confident answer, so any future change that lets it guess more
// freely also removes the reason it is safe to default to.
//
// Dependency direction: nothing in this package may import internal/match or
// internal/inventory.
package version

import (
	"errors"
	"fmt"
	"strings"
)

// Scheme identifies a version ordering.
type Scheme string

const (
	// Semver is Semantic Versioning 2.0.0. It also serves the ecosystems whose
	// advisories GHSA normalises into semver-shaped strings, which is most of
	// the language ecosystems.
	Semver Scheme = "SEMVER"
	// Debian is dpkg's epoch, upstream version and revision ordering, tilde
	// included. opam's manual defines OCaml package ordering on the same model.
	Debian Scheme = "DEBIAN"
	// RPM is rpmvercmp over an epoch, version and release, with tilde and
	// caret. Every Red Hat, SUSE, Rocky, Alma, Mageia and openEuler bound.
	RPM Scheme = "RPM"
	// Alpine is apk's ordering: dotted numbers, a patch letter, pre and post
	// suffixes and the -rN rebuild counter that carries most Alpine fixes.
	Alpine Scheme = "ALPINE"
	// Maven is ComparableVersion, the ordering the Maven POM reference points
	// at rather than describes.
	Maven Scheme = "MAVEN"
	// Python is PEP 440, where dev sorts below pre, pre below the release and
	// post above it.
	Python Scheme = "PYTHON"
	// Go is the Go modules ordering: semver, with pseudo-versions falling out
	// as pre-releases and "+incompatible" as build metadata.
	Go Scheme = "GO"
	// Generic is the ordering for data that declares none. It decides what
	// dotted-numeric comparison proves and refuses the rest, which is what
	// makes it safe as the default for CUSTOM-typed ranges.
	Generic Scheme = "GENERIC"
	// Opaque is not an ordering. It marks identifiers, chiefly git commit
	// hashes, that have no order to implement, and every comparison under it
	// is refused.
	Opaque Scheme = "OPAQUE"
)

// ErrNotComparable is returned when an operand cannot be ordered under a scheme.
var ErrNotComparable = errors.New("version: not comparable")

// Certainty grades how much of an ordering answer the scheme's own rules proved.
type Certainty string

const (
	// Exact means the scheme's published rules decided the pair as written.
	Exact Certainty = "exact"

	// Heuristic means the pair was decided only after an operand was repaired,
	// or by a rule the scheme does not itself define. The ordering is the best
	// reading of the data, not a proof, and a match built on it is at most
	// probable.
	Heuristic Certainty = "heuristic"
)

// Ordered reports whether a scheme defines a usable total order.
func Ordered(s Scheme) bool {
	switch s {
	case Semver, Debian, RPM, Alpine, Maven, Python, Go, Generic:
		return true
	}
	return false
}

// Compare returns -1, 0 or +1, or ErrNotComparable.
//
// The ordering specification requires every comparison to carry a certainty
// grade and this signature has nowhere to put one, so the grade is dropped
// here. That is a real loss: Compare reports "1.0-2 sorts after 1.0" with the
// same face whether the scheme proved it or a fallback guessed it. Anything
// that turns a comparison into a reported vulnerability should call
// CompareCertain instead and carry the grade into its evidence.
func Compare(s Scheme, a, b string) (int, error) {
	n, _, err := CompareCertain(s, a, b)
	return n, err
}

// CompareCertain is Compare with the certainty channel kept.
//
// On error the returned certainty is the empty string: a refusal is not a
// weakly held answer, it is the absence of one.
func CompareCertain(s Scheme, a, b string) (int, Certainty, error) {
	if !Ordered(s) {
		return 0, "", notComparable(s, a, b, "scheme defines no ordering")
	}
	ca, cb := clean(a), clean(b)
	if why, bad := unusable(ca); bad {
		return 0, "", notComparable(s, a, b, "left operand "+why)
	}
	if why, bad := unusable(cb); bad {
		return 0, "", notComparable(s, a, b, "right operand "+why)
	}
	if ca == cb {
		return 0, Exact, nil
	}

	var (
		n  int
		c  Certainty
		ok bool
	)
	switch s {
	case Semver:
		n, c, ok = compareSemver(ca, cb)
	case Debian:
		n, c, ok = compareDebian(ca, cb)
	case RPM:
		n, c, ok = compareRPM(ca, cb)
	case Alpine:
		n, c, ok = compareAlpine(ca, cb)
	case Maven:
		n, c, ok = compareMaven(ca, cb)
	case Python:
		n, c, ok = comparePython(ca, cb)
	case Go:
		n, c, ok = compareGoMod(ca, cb)
	default:
		// Generic, and any ordered scheme added later without a case here. The
		// fallback is deliberately the ordering that assumes least, so the cost
		// of forgetting a case is missed precision rather than a false match.
		n, c, ok = compareGeneric(ca, cb)
	}
	if !ok {
		return 0, "", notComparable(s, a, b, "no rule in this scheme orders these operands")
	}
	return n, c, nil
}

// LooksLikeCommit reports whether s names a git object rather than a release.
//
// SchemeFor already routes GIT-typed ranges to Opaque, but commit hashes also
// arrive inside ranges typed CUSTOM, SEMVER or nothing at all, and the kernel
// CNA mixes them with real versions in the same record. Comparing one against a
// version invents an order between two things that share no scale, so every
// scheme runs this guard before parsing.
//
// A run of digits with no hex letter is a date or a build number far more often
// than it is a hash, so those are only refused once they are improbably long.
func LooksLikeCommit(s string) bool {
	s = clean(s)
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	letter := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			letter = true
		default:
			return false
		}
	}
	return letter || len(s) >= 32
}

// unusable reports why an operand can never be ordered, in words that make the
// resulting error auditable by a human reading a scan report.
func unusable(s string) (string, bool) {
	switch k := ClassifySentinel(s); k {
	case SentinelEmpty:
		return "is empty", true
	case SentinelAll, SentinelUnknown:
		// A sentinel means "no bound stated"; it is resolved by the range
		// evaluator before any comparator sees it. Reaching here means a caller
		// skipped that step, and answering would order a version against a word.
		return "is the " + k.String() + " sentinel, which is not a version", true
	}
	if LooksLikeCommit(s) {
		return "looks like a commit hash, which has no order against a version", true
	}
	return "", false
}

// notComparableError names a refused pair without paying for the sentence that
// describes it until something renders one.
//
// A refusal is the expected outcome across much of a scan rather than an
// exceptional one -- the specification's own metric is that Heuristic plus
// Undecidable should be the majority of CUSTOM-typed evaluations -- and
// internal/match discards the text as soon as errors.Is has matched. Building
// it with fmt.Errorf cost more than the comparison it reported on.
type notComparableError struct {
	scheme Scheme
	a, b   string
	reason string
}

func (e *notComparableError) Error() string {
	return fmt.Sprintf("version: compare %q and %q under %s: %s: %v",
		e.a, e.b, e.scheme, e.reason, ErrNotComparable)
}

// Unwrap is what keeps errors.Is(err, ErrNotComparable) true for every refusal.
func (e *notComparableError) Unwrap() error { return ErrNotComparable }

func notComparable(s Scheme, a, b, reason string) error {
	return &notComparableError{scheme: s, a: a, b: b, reason: reason}
}

// clean strips the wrapping upstream data routinely carries: surrounding space,
// and the quotes some CSAF documents and CNA records leave around a version.
func clean(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		break
	}
	return s
}

// weakest returns the lower of two certainties, because a comparison is only as
// well founded as its worst-founded step.
func weakest(a, b Certainty) Certainty {
	if a == Heuristic || b == Heuristic {
		return Heuristic
	}
	return Exact
}
