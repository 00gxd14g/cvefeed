package version

import (
	"strconv"
	"strings"
)

// mavenQualifiers is ComparableVersion's qualifier order. The empty string is
// the release itself and sits in the middle: everything before it is a
// pre-release, and "sp" (service pack) is the one qualifier that ships after.
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// mavenAliases are the spellings Maven folds together before ordering.
var mavenAliases = map[string]string{
	"ga":      "",
	"final":   "",
	"release": "",
	"cr":      "rc",
}

// mavenReleaseIndex is comparableQualifier("") and therefore the pivot every
// qualifier is measured against.
const mavenReleaseIndex = "5"

type mavenKind int

const (
	mavenInt mavenKind = iota
	mavenString
	mavenList
)

type mavenItem struct {
	kind mavenKind
	num  string
	str  string
	list []*mavenItem
}

// compareMaven orders two versions the way org.apache.maven.artifact.versioning
// .ComparableVersion does, which is the definition the Maven POM reference
// points at rather than a description of it.
//
// The algorithm is worth porting rather than approximating because its answers
// are not guessable: 1.0 equals 1 equals 1.0.0, an unknown qualifier such as
// 1.0-foo sorts AFTER the plain 1.0 while a known one such as 1.0-rc1 sorts
// before it, and a dash starts a whole nested list so that 1.0-1 sorts below
// 1.0.1. GHSA carries every Java advisory in these terms.
func compareMaven(a, b string) (int, Certainty, bool) {
	// ComparableVersion accepts any string and orders it, so there is no parse
	// failure to fall back from and nothing to grade down.
	return compareMavenItems(parseMaven(a), parseMaven(b)), Exact, true
}

// parseMaven is ComparableVersion.parseVersion. A dot continues the current
// list; a dash, and any transition between digits and letters, opens a nested
// one; each list then has its trailing "null" items (zero, and the release
// qualifier) removed so that 1.0.0 and 1 compare equal.
func parseMaven(version string) *mavenItem {
	version = strings.ToLower(version)
	items := &mavenItem{kind: mavenList}
	list := items
	stack := []*mavenItem{list}

	isDigits := false
	start := 0
	for i := 0; i < len(version); i++ {
		c := version[i]
		switch {
		case c == '.':
			if i == start {
				list.list = append(list.list, &mavenItem{kind: mavenInt, num: "0"})
			} else {
				list.list = append(list.list, parseMavenItem(isDigits, version[start:i], false))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.list = append(list.list, &mavenItem{kind: mavenInt, num: "0"})
			} else {
				list.list = append(list.list, parseMavenItem(isDigits, version[start:i], false))
			}
			start = i + 1
			next := &mavenItem{kind: mavenList}
			list.list = append(list.list, next)
			list = next
			stack = append(stack, list)
		case isDigit(c):
			if !isDigits && i > start {
				// A letter run followed by digits is read as if the producer
				// had written a dash, so that "1.0.0.X1" sorts below
				// "1.0.0-X2". Opening the nested list BEFORE the letter run is
				// what makes ".rc1" and "-rc1" the same version rather than
				// merely adjacent ones: it puts the qualifier at the same depth
				// under both spellings, so the zeroes in front of it normalise
				// away. maven-artifact 3.8.6 appended the qualifier to the
				// enclosing list instead and made "1.0.0.rc1" sort ABOVE
				// "1.0.0-rc1"; 3.9.x and the Debian maven-artifact-3.x both
				// order them equal, and Spring and JBoss spell their
				// qualifiers with the dot ("5.3.20.RELEASE", "3.0.0.M1").
				if len(list.list) > 0 {
					next := &mavenItem{kind: mavenList}
					list.list = append(list.list, next)
					list = next
					stack = append(stack, list)
				}
				list.list = append(list.list, parseMavenItem(false, version[start:i], true))
				start = i
				next := &mavenItem{kind: mavenList}
				list.list = append(list.list, next)
				list = next
				stack = append(stack, list)
			}
			isDigits = true
		default:
			if isDigits && i > start {
				list.list = append(list.list, parseMavenItem(true, version[start:i], false))
				start = i
				next := &mavenItem{kind: mavenList}
				list.list = append(list.list, next)
				list = next
				stack = append(stack, list)
			}
			isDigits = false
		}
	}
	if len(version) > start {
		// A qualifier that ends the string opens a nested list of its own, the
		// same way one that precedes digits does, so that "1.0.0.foo" is 1
		// qualified by foo rather than 1.0.0 with a fourth component. Without
		// it "12.+build" and "12+build" parse to different shapes.
		if !isDigits && len(list.list) > 0 {
			next := &mavenItem{kind: mavenList}
			list.list = append(list.list, next)
			list = next
			stack = append(stack, list)
		}
		list.list = append(list.list, parseMavenItem(isDigits, version[start:], false))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		normalizeMaven(stack[i])
	}
	return items
}

func parseMavenItem(digits bool, buf string, followedByDigit bool) *mavenItem {
	if digits {
		return &mavenItem{kind: mavenInt, num: trimZeroes(buf)}
	}
	value := buf
	if followedByDigit && len(value) == 1 {
		// a1 is alpha-1, b1 is beta-1, m1 is milestone-1.
		switch value[0] {
		case 'a':
			value = "alpha"
		case 'b':
			value = "beta"
		case 'm':
			value = "milestone"
		}
	}
	if alias, ok := mavenAliases[value]; ok {
		value = alias
	}
	return &mavenItem{kind: mavenString, str: value}
}

// normalizeMaven drops trailing items that mean nothing, which is what makes
// 1.0.0, 1.0 and 1 the same version. It walks past a non-null nested list
// rather than stopping at it, exactly as ComparableVersion.normalize does.
func normalizeMaven(item *mavenItem) {
	for i := len(item.list) - 1; i >= 0; i-- {
		last := item.list[i]
		if mavenIsNull(last) {
			item.list = append(item.list[:i], item.list[i+1:]...)
		} else if last.kind != mavenList {
			break
		}
	}
}

func mavenIsNull(item *mavenItem) bool {
	switch item.kind {
	case mavenInt:
		return item.num == "0"
	case mavenString:
		return mavenComparableQualifier(item.str) == mavenReleaseIndex
	}
	return len(item.list) == 0
}

// mavenComparableQualifier returns the sort key of a qualifier: its index in
// the known list, or "7-<qualifier>" for an unknown one, which is why an
// unrecognised qualifier sorts after every recognised one AND after the
// release. These keys are compared as strings, as they are in Maven.
func mavenComparableQualifier(q string) string {
	for i, known := range mavenQualifiers {
		if q == known {
			return string(rune('0' + i))
		}
	}
	return strconv.Itoa(len(mavenQualifiers)) + "-" + q
}

func compareMavenItems(a, b *mavenItem) int {
	switch a.kind {
	case mavenInt:
		switch {
		case b == nil:
			if a.num == "0" {
				return 0
			}
			return 1
		case b.kind == mavenInt:
			return compareNumericText(a.num, b.num)
		default:
			// A number outranks a qualifier and a nested list alike.
			return 1
		}
	case mavenString:
		switch {
		case b == nil:
			return sign(strings.Compare(mavenComparableQualifier(a.str), mavenReleaseIndex))
		case b.kind == mavenInt:
			return -1
		case b.kind == mavenString:
			return sign(strings.Compare(mavenComparableQualifier(a.str), mavenComparableQualifier(b.str)))
		default:
			return -1
		}
	}

	switch {
	case b == nil:
		if len(a.list) == 0 {
			// "1-" normalises to "1", so an empty list is the release itself.
			return 0
		}
		// Every item of the list is compared against the absent one, not just
		// the first (MNG-6964). Stopping at the first says 1.2.3-ga.1 equals
		// 1.2.3, because "ga" is the release qualifier and compares zero, and
		// then never reads the ".1" that puts it above. normalize() cannot
		// strip that leading null item, because a non-null item follows it.
		for _, item := range a.list {
			if n := compareMavenItems(item, nil); n != 0 {
				return n
			}
		}
		return 0
	case b.kind == mavenInt:
		return -1
	case b.kind == mavenString:
		return 1
	}
	for i := 0; i < len(a.list) || i < len(b.list); i++ {
		var l, r *mavenItem
		if i < len(a.list) {
			l = a.list[i]
		}
		if i < len(b.list) {
			r = b.list[i]
		}
		var n int
		if l == nil {
			n = -compareMavenItems(r, nil)
		} else {
			n = compareMavenItems(l, r)
		}
		if n != 0 {
			return n
		}
	}
	return 0
}
