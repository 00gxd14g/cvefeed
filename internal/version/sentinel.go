package version

import "strings"

// Sentinel classifies the placeholder strings upstreams use where a version
// belongs. Recognition is scheme independent and happens before any parsing: a
// sentinel is never handed to a comparator.
type Sentinel int

// The sentinel classes. Their meaning depends on the field they were found in,
// which is the range evaluator's business, not this package's:
//
//	Introduced: empty, all and unknown all mean unbounded below, and zero means
//	    the same. "0" is the OSV schema's required spelling for "from the
//	    beginning of time", not the version zero.
//	Fixed, LastAffected: empty, all and unknown mean no upper bound at all. An
//	    upper bound the producer refused to state carries exactly as much
//	    information as one they omitted, so refusing to distinguish them is the
//	    honest reading. Zero means the window is EMPTY and nothing is affected;
//	    Alpine's secdb uses "0" as its not-affected pseudo-version, and a literal
//	    reading agrees, since no version sorts below zero in any scheme.
//	discrete Versions: empty and unknown assert nothing and are dropped, all
//	    matches every version of the product, and zero is a real version string.
//	    A package genuinely versioned 0 exists, and unlike a bound, a discrete
//	    entry cannot be a beginning-of-time marker.
const (
	// NotSentinel means the string is an ordinary version.
	NotSentinel Sentinel = iota
	// SentinelEmpty is the empty string.
	SentinelEmpty
	// SentinelAll is a wildcard: "*", "-", "any", "all", "all versions".
	SentinelAll
	// SentinelUnknown is a refusal to state: "unspecified", "unknown", "n/a",
	// "na", "none", "not applicable".
	SentinelUnknown
	// SentinelZero is the literal "0", which is a sentinel in a bound and a
	// version everywhere else.
	SentinelZero
)

// String names the sentinel class for error messages and evidence strings.
func (s Sentinel) String() string {
	switch s {
	case SentinelEmpty:
		return "empty"
	case SentinelAll:
		return "all-versions"
	case SentinelUnknown:
		return "unknown-version"
	case SentinelZero:
		return "zero"
	}
	return "not-a-sentinel"
}

// ClassifySentinel reports which placeholder class s belongs to, after trimming
// space and paired surrounding quotes and case folding.
//
// The set is closed. "0.0", "0.0.0" and "v0" are real versions and must keep
// comparing as such: widening this set silently converts stated bounds into
// unbounded ones, and an unbounded range matches every version there is.
func ClassifySentinel(s string) Sentinel {
	switch strings.ToLower(clean(s)) {
	case "":
		return SentinelEmpty
	case "*", "-", "any", "all", "all versions":
		return SentinelAll
	case "unspecified", "unknown", "n/a", "na", "none", "not applicable":
		return SentinelUnknown
	case "0":
		return SentinelZero
	}
	return NotSentinel
}
