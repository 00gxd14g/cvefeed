package version

import "strings"

// compareRPM orders two RPM EVRs: epoch, then version, then release, as
// rpmVersionCompare does. A missing epoch is zero, and a missing release sorts
// below any stated one.
//
// The certainty is always Exact. Unlike dpkg, rpmvercmp() accepts any byte
// string and defines an order over it, so whatever it answers is rpm's answer
// and there is no such thing as a near miss to grade down.
func compareRPM(a, b string) (int, Certainty, bool) {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)

	if n := compareNumericText(ea, eb); n != 0 {
		return n, Exact, true
	}
	if n := rpmvercmp(va, vb); n != 0 {
		return n, Exact, true
	}
	return rpmvercmp(ra, rb), Exact, true
}

// splitEVR breaks "[epoch:]version[-release]" apart the way rpm's parseEVR
// does, taking the release from the last hyphen.
func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	rest := s
	if i := strings.IndexByte(rest, ':'); i > 0 && isAllDigits(rest[:i]) {
		epoch, rest = rest[:i], rest[i+1:]
	}
	version = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		version, release = rest[:i], rest[i+1:]
	}
	return epoch, version, release
}

// rpmvercmp is rpm's rpmvercmp() from rpmio/rpmvercmp.c, ported directly.
//
// Three of its rules are the ones that get reimplemented wrong:
//
//   - "~" (rpm 4.10) sorts before everything, so 1.0~rc1 precedes 1.0. It is
//     how a distro ships a pre-release without it looking newer than the final.
//   - "^" (rpm 4.15) sorts after everything, so 1.0^ follows 1.0. It is the
//     mirror image, for a snapshot taken after a release.
//   - A numeric segment always outranks an alphabetic one, and a longer digit
//     run always outranks a shorter one once leading zeroes are gone. The
//     digits are compared as text because a release counter can outgrow an int,
//     which is the bug this loop was rewritten to fix upstream.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		aTilde, bTilde := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		aCaret, bCaret := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			// The exhaustion checks come first, and in this order: a version
			// that ended is the base version, and the base version is older
			// than any caret snapshot of it.
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		numeric := isDigit(a[i])
		si, sj := i, j
		if numeric {
			for si < len(a) && isDigit(a[si]) {
				si++
			}
			for sj < len(b) && isDigit(b[sj]) {
				sj++
			}
		} else {
			for si < len(a) && isLetter(a[si]) {
				si++
			}
			for sj < len(b) && isLetter(b[sj]) {
				sj++
			}
		}
		if sj == j {
			// The segments are of different types. Numeric wins.
			if numeric {
				return 1
			}
			return -1
		}

		segA, segB := a[i:si], b[j:sj]
		if numeric {
			segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if n := strings.Compare(segA, segB); n != 0 {
			return sign(n)
		}
		i, j = si, sj
	}

	// Equal through every segment: whichever still has characters left wins,
	// and if neither does the separators were the only difference.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}
