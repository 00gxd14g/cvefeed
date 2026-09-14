package version

import (
	"regexp"
	"strings"
)

// pep440Pattern is the canonical regular expression from the PyPA Version
// Specifiers specification, kept verbatim so that a spec change is a one line
// diff here. It is case insensitive and anchored, and the "v" prefix, the
// separator characters and the shorthand spellings are all part of it.
var pep440Pattern = regexp.MustCompile(`(?i)\A\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*\z`)

// pep440 is a PEP 440 version reduced to its comparison key. The sentinel
// ranks reproduce the infinities packaging.version._cmpkey uses, because the
// ordering of the four release kinds is not lexical and cannot be faked:
// dev < pre < release < post, with a local version above its own base.
type pep440 struct {
	epoch   string
	release []string
	preSort int // preSortDev, a pre-release letter rank, or preSortFinal
	preNum  string
	postSet bool
	postNum string
	devSet  bool
	devNum  string
	local   []string
}

const (
	preSortDev   = -1 // a dev release with no pre-release sorts below every pre
	preSortFinal = 3  // no pre-release at all sorts above every pre
)

var pep440PreRanks = map[string]int{"a": 0, "b": 1, "rc": 2}

// pep440PreAliases normalises the spellings PEP 440 declares equivalent. "c",
// "pre" and "preview" all mean rc, which is why 1.0c1 and 1.0rc1 are one
// version and both sort below 1.0.
var pep440PreAliases = map[string]string{
	"alpha":   "a",
	"a":       "a",
	"beta":    "b",
	"b":       "b",
	"c":       "rc",
	"pre":     "rc",
	"preview": "rc",
	"rc":      "rc",
}

// comparePython orders two PEP 440 versions. Anything the specification's own
// regular expression rejects is not a Python version, whatever the producer
// declared, so it falls back to the generic ordering at a reduced certainty.
func comparePython(a, b string) (int, Certainty, bool) {
	pa, oka := parsePEP440(a)
	pb, okb := parsePEP440(b)
	if !oka || !okb {
		n, _, ok := compareGeneric(a, b)
		return n, Heuristic, ok
	}
	return comparePEP440(pa, pb), Exact, true
}

func comparePEP440(a, b pep440) int {
	if n := compareNumericText(a.epoch, b.epoch); n != 0 {
		return n
	}
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
	if a.preSort != b.preSort {
		return sign(a.preSort - b.preSort)
	}
	if a.preSort >= 0 && a.preSort < preSortFinal {
		if n := compareNumericText(a.preNum, b.preNum); n != 0 {
			return n
		}
	}
	// An absent post release sorts below any stated one, and an absent dev
	// release above any stated one. Both are the opposite of what a naive
	// "missing means zero" rule would do.
	switch {
	case a.postSet && !b.postSet:
		return 1
	case !a.postSet && b.postSet:
		return -1
	case a.postSet && b.postSet:
		if n := compareNumericText(a.postNum, b.postNum); n != 0 {
			return n
		}
	}
	switch {
	case a.devSet && !b.devSet:
		return -1
	case !a.devSet && b.devSet:
		return 1
	case a.devSet && b.devSet:
		if n := compareNumericText(a.devNum, b.devNum); n != 0 {
			return n
		}
	}
	return compareLocalVersion(a.local, b.local)
}

// compareLocalVersion orders the "+local" segments: numeric segments compare
// numerically and outrank alphabetic ones, and a version with no local part at
// all sorts below one that has any.
func compareLocalVersion(a, b []string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		switch {
		case i >= len(a):
			return -1
		case i >= len(b):
			return 1
		}
		x, y := a[i], b[i]
		xn, yn := isAllDigits(x), isAllDigits(y)
		switch {
		case xn && yn:
			if n := compareNumericText(x, y); n != 0 {
				return n
			}
		case xn:
			return 1
		case yn:
			return -1
		default:
			if n := strings.Compare(x, y); n != 0 {
				return sign(n)
			}
		}
	}
	return 0
}

func parsePEP440(s string) (pep440, bool) {
	var out pep440
	m := pep440Pattern.FindStringSubmatch(strings.ToLower(clean(s)))
	if m == nil {
		return out, false
	}
	group := func(name string) string { return m[pep440Pattern.SubexpIndex(name)] }

	out.epoch = "0"
	if e := group("epoch"); e != "" {
		out.epoch = e
	}
	out.release = strings.Split(group("release"), ".")

	out.preSort = preSortFinal
	if l := group("pre_l"); l != "" {
		out.preSort = pep440PreRanks[pep440PreAliases[l]]
		out.preNum = "0"
		if n := group("pre_n"); n != "" {
			out.preNum = n
		}
	}
	if group("post") != "" {
		out.postSet = true
		out.postNum = "0"
		if n := group("post_n1"); n != "" {
			out.postNum = n
		} else if n := group("post_n2"); n != "" {
			out.postNum = n
		}
	}
	if group("dev") != "" {
		out.devSet = true
		out.devNum = "0"
		if n := group("dev_n"); n != "" {
			out.devNum = n
		}
	}
	if out.preSort == preSortFinal && !out.postSet && out.devSet {
		// _cmpkey: a plain dev release sorts below even the earliest alpha of
		// the same release, so it cannot share the "no pre-release" rank.
		out.preSort = preSortDev
	}
	if l := group("local"); l != "" {
		out.local = strings.FieldsFunc(l, func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		})
	}
	return out, true
}
