package version

import "strings"

// preReleaseRanks orders the words that every numbering convention agrees sort
// below the release they qualify. Their order relative to each other is a
// convention rather than a rule, which is why any comparison that consults this
// table is graded Heuristic -- including one that consults it only to find two
// spellings equal, because the pair then rests on the table just as heavily as
// an unequal one does.
//
// Single letters are deliberately absent. OpenSSL's 1.0.2a sorts AFTER 1.0.2,
// while semver's 1.0.2-a sorts before it; nothing in an unclassified version
// string tells the two apart, so a lone letter stays undecidable.
var preReleaseRanks = map[string]int{
	"dev":       0,
	"devel":     0,
	"alpha":     1,
	"beta":      2,
	"milestone": 3,
	"snapshot":  4,
	"pre":       5,
	"preview":   5,
	"cr":        6,
	"rc":        6,
}

func preReleaseRank(word string) int {
	if r, ok := preReleaseRanks[strings.ToLower(word)]; ok {
		return r
	}
	return -1
}

// compareGeneric orders two version strings using only what dotted-numeric
// comparison proves, and gives up on everything else.
//
// This is the scheme every CVE List row lands in, because those rows carry no
// ecosystem and declare versionType CUSTOM. It therefore decides the plurality
// of the corpus, and its refusals are what keep that plurality from turning
// into confident nonsense: given "1.0.0-0" and "1.0.0-0ubuntu3" it answers "I
// cannot tell", which is the truth until someone tells it these are Debian
// versions.
//
// The shape of the algorithm is the specification's §3.4 and not a token walk,
// because a token walk loses the separator. Walking "1.0-3" and "1.0.2" side by
// side pairs the 3 with the 2 and answers "greater, exact", an answer dpkg, rpm
// and semver all contradict: the leading "1.0" is the whole version core on the
// left, and a tail hanging off it cannot reach past the "2" of the right. So
// the core is split off first and compared with zero padding, and only then is
// anything asked of the tail.
func compareGeneric(a, b string) (int, Certainty, bool) {
	a, b = stripV(a), stripV(b)
	if hasEpoch(a) || hasEpoch(b) {
		// "1:7.3" declares an epoch, and in the only two schemes that have one
		// the epoch outranks everything behind it: dpkg and rpm both sort
		// "1:7.3" above "4", while reading the 1 as a first component sorts it
		// below. Nothing else in the corpus writes a colon into a version, so
		// the colon is not ambiguous -- it is simply a rule this scheme does
		// not implement.
		return 0, "", false
	}
	ca, ta := splitNumericCore(a)
	cb, tb := splitNumericCore(b)
	if len(ca) == 0 || len(cb) == 0 {
		// "latest", "Not Fixed", "log4j-core*": a string that does not start
		// with a number has no core to compare, and "everything sorts above
		// punctuation" is a rule nobody wrote down.
		return 0, "", false
	}

	c := Exact
	for i := 0; i < len(ca) || i < len(cb); i++ {
		x, y := "0", "0"
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if n := compareNumericText(x, y); n != 0 {
			if (i >= len(ca) && !subordinateTail(ta)) || (i >= len(cb) && !subordinateTail(tb)) {
				// The difference is at a position the shorter core does not
				// have, so it exists only because that core was padded -- and
				// the tail sitting where the padding went is not one every
				// scheme reads as subordinate. See subordinateTail.
				return 0, "", false
			}
			return n, c, true
		}
		if x != y {
			// "1.01" and "1.1" are one number spelled two ways -- or two
			// numbers under a scheme that reads the zero as significant.
			c = Heuristic
		}
	}

	switch {
	case len(ta) == 0 && len(tb) == 0:
		// "1.0" and "1.0.0" name one release in every scheme that reaches here.
		return 0, c, true

	case len(ca) != len(cb):
		// The cores matched only after zero padding, and one side carries a
		// tail. Which side that puts on top is a fork no unclassified string
		// resolves: dpkg reads "1.0-3" as upstream 1.0 and sorts it below
		// "1.0.0-2", semver reads it as 1.0.0 pre-release 3 and sorts it above.
		// Whenever the padding did the work, the tail is not ours to read.
		return 0, "", false

	case len(tb) == 0:
		n, tc, ok := tailOrder(ta)
		return n, weakest(c, tc), ok

	case len(ta) == 0:
		n, tc, ok := tailOrder(tb)
		return -n, weakest(c, tc), ok
	}
	return compareTails(ta, tb, c)
}

// splitNumericCore splits s into its leading dotted-numeric components and the
// tokens of whatever follows them.
//
// The core is the part this scheme can prove things about; the tail is the part
// where a package revision and a pre-release wear the same clothes. The split
// is what keeps the two from being compared against each other by position.
func splitNumericCore(s string) ([]string, []token) {
	var core []string
	i := 0
	for {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == i {
			break
		}
		core = append(core, s[i:j])
		i = j
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			i++
			continue
		}
		break
	}
	return core, tokenize(s[i:])
}

// subordinateTail reports whether a tail is one that every scheme reads as
// hanging below the core it follows rather than as continuing it.
//
// Only "-" and "~" qualify. dpkg ranks both below the "." that opens a further
// component, and rpm and semver read them as a release or pre-release marker,
// so "1.0-3" and "1.0~3" are below "1.0.2" under all of them. "_" is the
// counter-example that forces the check: dpkg ranks it ABOVE "." (order() is
// the byte value, and "_" is 0x5f against "." at 0x2e) and rpm drops separators
// altogether and reads "1.0_3" as three components, so both of them sort it
// above "1.0.2" while apk and a semver reading sort it below.
func subordinateTail(tail []token) bool {
	return len(tail) == 0 || tail[0].sep == '-' || tail[0].sep == '~'
}

// hasEpoch reports whether s opens with a "N:" epoch declaration.
func hasEpoch(s string) bool {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return i > 0 && i < len(s) && s[i] == ':'
}

// gluedToLetters reports whether the token at i is one piece of a longer mixed
// identifier such as "0ubuntu3" or "rc2", rather than a component of its own.
//
// It is the difference between two readings that disagree: dpkg and rpm chop
// such an identifier into runs and compare the digit runs by value, while
// semver keeps it whole and compares it as text, which reverses "rc2" against
// "rc10" and puts "2" below "0ubuntu3" instead of above it. The answer is still
// the more likely of the two, so it is returned -- graded.
func gluedToLetters(tokens []token, i int) bool {
	return tokens[i].sep == 0 || (i+1 < len(tokens) && tokens[i+1].sep == 0)
}

// compareTails orders two non-empty tails that hang off cores of the same shape.
// c carries in the certainty the core comparison earned, because a comparison is
// only as well founded as its weakest step.
func compareTails(ta, tb []token, c Certainty) (int, Certainty, bool) {
	for i := 0; ; i++ {
		switch {
		case i >= len(ta) && i >= len(tb):
			return 0, c, true
		case i >= len(ta):
			n, tc, ok := tailOrder(tb[i:])
			return -n, weakest(c, tc), ok
		case i >= len(tb):
			n, tc, ok := tailOrder(ta[i:])
			return n, weakest(c, tc), ok
		}

		x, y := ta[i], tb[i]
		switch {
		case x.sep == '~' && y.sep != '~':
			// Debian and rpm agree that "~" sorts below everything; no third
			// scheme defines it at all. Very likely, still not proven.
			return -1, weakest(c, Heuristic), true
		case y.sep == '~' && x.sep != '~':
			return 1, weakest(c, Heuristic), true
		case x.sep != y.sep:
			// "1.0-1" against "1.0_1": the separator is the only evidence of
			// what a tail component means, and the two sides disagree about it.
			return 0, "", false
		}

		switch {
		case x.kind == tokenNumeric && y.kind == tokenNumeric:
			if gluedToLetters(ta, i) || gluedToLetters(tb, i) {
				c = weakest(c, Heuristic)
			}
			if n := compareNumericText(x.text, y.text); n != 0 {
				return n, c, true
			}
			if x.text != y.text {
				c = Heuristic
			}
		case x.kind == tokenAlpha && y.kind == tokenAlpha:
			if strings.EqualFold(x.text, y.text) {
				continue
			}
			rx, ry := preReleaseRank(x.text), preReleaseRank(y.text)
			if rx < 0 || ry < 0 {
				// "0ubuntu3" against "0deb9u1": two vendors' words, no scale.
				return 0, "", false
			}
			c = weakest(c, Heuristic)
			if rx == ry {
				continue
			}
			return sign(rx - ry), c, true
		default:
			// A number where the other side has a word, under the same
			// separator: "1.0-1" against "1.0-rc1". dpkg puts the number below
			// the word (order() ranks a digit under any letter) and rpm puts it
			// above (a numeric segment is newer than an alphabetic one), so the
			// two readings straddle the boundary and neither may be reported.
			return 0, "", false
		}
	}
}

// tailOrder decides what a trailing run of components does to the version that
// carries it, when the other version has run out. The returned sign is from the
// point of view of the side that still has tokens.
func tailOrder(rest []token) (int, Certainty, bool) {
	first := rest[0]
	switch {
	case first.sep == '~':
		// Debian and rpm both define "~" as sorting below everything, including
		// the empty string. No third scheme defines it, so the reading is very
		// likely and still not proven.
		return -1, Heuristic, true

	case first.kind == tokenAlpha && preReleaseRank(first.text) >= 0:
		// "1.0-alpha" against "1.0". dpkg would read the tail as a package
		// revision and put it above, but no distro numbers a revision "alpha",
		// while every upstream that writes the word means a pre-release.
		return -1, Heuristic, true
	}

	// The fork this package exists to refuse. "2.15.0-1ubuntu2" is above
	// "2.15.0" for dpkg, which reads the tail as a package revision, and below
	// it for semver, which reads the same tail as a pre-release. A CUSTOM range
	// never said which applies, and the two readings put the target on opposite
	// sides of a fix boundary, so neither may be reported. Answering at a
	// reduced grade would still be answering.
	//
	// The trap: the marker does not have to be on the first leftover token.
	// "1.0.0-1" against "1.0" runs out with a "." component in hand and the
	// ambiguous "-1" behind it, and reading only the first token answers "+1,
	// exact" for a pair dpkg and semver put on opposite sides. Scan all of it.
	for _, t := range rest {
		if ambiguousSeparator(t.sep) || t.sep == '~' {
			return 0, "", false
		}
	}

	if first.kind == tokenNumeric {
		// A further component makes the version larger. Note that a trailing
		// zero does NOT make it equal here, the way "1.0" and "1.0.0" are equal
		// in the core: dpkg, rpm and semver all sort "1.0-1" below "1.0-1.0",
		// because inside a tail the extra component is another pre-release or
		// revision field rather than a padded-out release number.
		c := Exact
		if gluedToLetters(rest, 0) {
			c = Heuristic
		}
		return 1, c, true
	}
	return 0, "", false
}

// ambiguousSeparator reports whether a separator could be introducing either a
// package revision or a pre-release. Those are the two readings that sort in
// opposite directions, which is what makes the tail behind one undecidable
// rather than merely uncertain.
func ambiguousSeparator(sep byte) bool {
	return sep == '-' || sep == '_' || sep == '+'
}
