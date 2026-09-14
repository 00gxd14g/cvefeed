package version

import "strings"

// compareDebian orders two Debian versions, epoch first, then upstream version,
// then Debian revision, exactly as dpkg_version_compare does.
//
// The ordering also covers opam, whose manual defines OCaml package version
// ordering on Debian's model, tilde included.
func compareDebian(a, b string) (int, Certainty, bool) {
	ea, ua, ra, ca := splitDebian(a)
	eb, ub, rb, cb := splitDebian(b)
	c := weakest(ca, cb)

	if n := compareNumericText(ea, eb); n != 0 {
		return n, c, true
	}
	if n := verrevcmp(ua, ub); n != 0 {
		return n, c, true
	}
	// An absent revision is the empty string, which verrevcmp sorts below any
	// stated one: 1.0 is older than 1.0-1, and the Debian archive agrees.
	return verrevcmp(ra, rb), c, true
}

// splitDebian breaks "[epoch:]upstream[-revision]" apart. The revision is taken
// from the LAST hyphen, per deb-version(7): an upstream version is allowed to
// contain hyphens, a revision is not.
//
// The certainty reports whether the string is a version dpkg would accept. It
// is graded down rather than refused because verrevcmp is defined over any byte
// string and still produces a stable, sensible order for the near misses that
// security trackers publish.
func splitDebian(s string) (epoch, upstream, revision string, certainty Certainty) {
	certainty = Exact
	epoch = "0"

	rest := s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		if head := rest[:i]; isAllDigits(head) {
			epoch, rest = head, rest[i+1:]
		} else {
			// A colon that is not an epoch marker is not valid in an upstream
			// version either; order it anyway and say the string is off-spec.
			certainty = Heuristic
		}
	}
	upstream = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		upstream, revision = rest[:i], rest[i+1:]
	}

	if upstream == "" || !isDigit(upstream[0]) || !validDebian(upstream, ".+-:~") || !validDebian(revision, ".+~") {
		certainty = Heuristic
	}
	return epoch, upstream, revision, certainty
}

func validDebian(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && strings.IndexByte(extra, s[i]) < 0 {
			return false
		}
	}
	return true
}

// debianOrder is dpkg's order(): the weight of a single character when two
// non-digit runs are compared.
//
// Everything about Debian ordering that surprises people lives in this
// function. The tilde weighs less than the end of the string, which is why
// 1.0~rc1 sorts before 1.0 and why a "~" bound is not a typo. Letters weigh
// their ASCII value, so uppercase sorts before lowercase, and every other
// punctuation character weighs more than any letter.
func debianOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// verrevcmp is dpkg's verrevcmp() from lib/dpkg/version.c, ported directly.
// A byte past the end of a string is read as NUL, which orders as 0: above a
// tilde, level with a digit run, below every letter.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debianOrder(a[i])
			}
			if j < len(b) {
				bc = debianOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		// A digit run that outlasts the other is the larger number, whatever
		// the leading digits said.
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}
