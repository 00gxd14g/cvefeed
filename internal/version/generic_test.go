package version

import "testing"

func TestGenericDecidesDottedNumericExactly(t *testing.T) {
	// This is the scheme every CVE List row lands in, so what it decides
	// exactly is what the scanner can state as fact.
	checkOrderCertain(t, Generic, Exact, []orderCase{
		{"4.2.0", "4.3", -1},
		{"2.4.3", "2.4.4", -1},
		{"1.9", "1.10", -1},
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.0.0", 0},
		{"1.0", "1.0.1", -1},
		{"v1.0", "1.0", 0},
		// Android security patch levels chunk into numbers and compare exactly.
		{"2023-06-01", "2023-07-05", -1},
		{"2023-06-01", "2023-06-01", 0},
	})
}

func TestGenericComparesTheNumericCoreBeforeAnythingHangingOffIt(t *testing.T) {
	// The separator is not decoration, and walking the two versions component
	// by component throws it away: it pairs the "3" of "1.0-3" with the "2" of
	// "1.0.2" and answers "greater, exact". Every candidate reading contradicts
	// that. "1.0-3" has the core 1.0, and a revision or a pre-release hanging
	// off that core cannot reach past a third component of the other side --
	// dpkg, rpm, semver, Maven and PEP 440 all put it below.
	checkOrderCertain(t, Generic, Exact, []orderCase{
		{"1.0-3", "1.0.2", -1},
		{"1.0~3", "1.0.2", -1},
		{"2.15.0-2", "2.15.0.1", -1},
		{"1.0-1", "1.0.1", -1},
		// Away from the boundary the tail never gets a say, because a differing
		// core component settles the comparison first.
		{"2.14.0-1ubuntu2", "2.15.0", -1},
	})
}

func TestGenericAnswersPunctuationQuestionsOnlyAsHeuristics(t *testing.T) {
	checkOrderCertain(t, Generic, Heuristic, []orderCase{
		// Two spellings of one number, or two numbers under a scheme that reads
		// the zero as significant.
		{"1.01", "1.1", 0},
		{"1.01", "1.1.0", 0},
		// "~" is defined by Debian and rpm and by nobody else.
		{"1.0~rc1", "1.0", -1},
		{"1.0~1", "1.0-1", -1},
		// A recognised pre-release word sorts below the release it qualifies;
		// the words' order relative to each other is convention, not rule.
		{"1.0-alpha", "1.0", -1},
		{"1.0-alpha", "1.0-beta", -1},
		{"1.0-beta", "1.0-rc1", -1},
	})
}

func TestGenericGradesEveryAnswerThatConsultedThePreReleaseTable(t *testing.T) {
	// The table equates "cr" with "rc" and "pre" with "preview" by convention,
	// not by rule. An answer that used it to equate two words and then let the
	// next component decide rests on the convention exactly as heavily as one
	// where the words ranked differently, so it carries the same grade. The
	// grade is the whole mechanism: internal/match turns Generic plus Heuristic
	// into a refusal, and reports an Exact as proven.
	checkOrderCertain(t, Generic, Heuristic, []orderCase{
		{"1.0-cr1", "1.0-rc2", -1},
		{"1.0-pre1", "1.0-preview2", -1},
		{"1.0-dev1", "1.0-devel2", -1},
	})
}

func TestGenericRefusesVendorSuffixesItCannotOrder(t *testing.T) {
	// The Canonical row from the corpus: introduced 1.0.0-0, last affected
	// 1.0.0-0ubuntu3. Without being told these are Debian versions, no rule
	// orders "ubuntu3" against nothing, and inventing one here would put every
	// Ubuntu package in range of every Ubuntu advisory.
	requireNotComparable(t, Generic, "1.0.0-0", "1.0.0-0ubuntu3")
	requireNotComparable(t, Generic, "1.0.0-0ubuntu3", "1.0.0-0deb9u1")
	// A lone trailing letter is a later patch in OpenSSL's numbering and an
	// alpha in semver's. Nothing in the string tells the two apart.
	requireNotComparable(t, Generic, "1.0.2a", "1.0.2")
	// The boundary tie: dpkg reads "-2" as a package revision and puts
	// "1.0-2" above "1.0", semver reads the same tail as a pre-release and puts
	// it below. The two readings land on opposite sides of a fix boundary, so
	// there is no grade at which either may be reported.
	requireNotComparable(t, Generic, "1.0-2", "1.0")
	requireNotComparable(t, Generic, "2.15.0-1ubuntu2", "2.15.0")
	requireNotComparable(t, Generic, "1.0", "1.0-0")
	// The same tie, reached with the ambiguous separator one component deeper
	// than the point where the two versions part company. Reading only the
	// first leftover component answers "1.0.0-1 is above 1.0, exactly", for a
	// pair dpkg (+1) and semver (-1) put on opposite sides.
	requireNotComparable(t, Generic, "1.0.0-1", "1.0")
	requireNotComparable(t, Generic, "1.0.0-0", "1.0")
	requireNotComparable(t, Generic, "1.0", "1.0.0-0ubuntu3")
	// Padding "1.0" out to "1.0.0" is only a convention about the core. Once a
	// tail hangs off the shorter side, which side the padding puts on top is
	// the scheme's business: dpkg sorts 1.0-3 below 1.0.0-2 and semver above.
	requireNotComparable(t, Generic, "1.0-3", "1.0.0-2")
	requireNotComparable(t, Generic, "1.0.0~rc1", "1.0")
	// Same separator, and still no order: dpkg ranks a digit below any letter
	// and rpm ranks a numeric segment above an alphabetic one.
	requireNotComparable(t, Generic, "1.0-1", "1.0-rc1")
	// Different separators mean the two sides disagree about what the tail is.
	requireNotComparable(t, Generic, "1.0-1", "1.0_1")

	requireNotComparable(t, Generic, "latest", "1.0")
	requireNotComparable(t, Generic, "trunk", "stable")
	// Real upper bounds from the CVE List. None of them is a version.
	requireNotComparable(t, Generic, "log4j-core*", "2.15.0")
	requireNotComparable(t, Generic, "Not Fixed", "1.0")
}

// genericAdversaries are the shapes that make GENERIC choose between two
// readings: revisions, pre-releases, epochs, vendor suffixes and the padding
// boundary where a shorter core meets a longer one.
var genericAdversaries = []string{
	"1.0", "1.0.0", "1.0.1", "1.0.2", "1.0-1", "1.0-2", "1.0-3", "1.0.0-0",
	"1.0.0-1", "1.0.0-2", "1.0.0-0ubuntu3", "1.0~3", "1.0~rc1", "1.0.0~rc1",
	"1.0-alpha", "1.0-rc1", "1.0-rc2", "1.0-rc10", "1.0_3", "1.0+3", "1.0a",
	"2.15.0", "2.15.0-2", "2.15.0.1", "2.15.0-1ubuntu2", "1:1.0", "1:0.5",
	"2023-06-01", "2023-07-05", "1.01", "1.1", "0", "0.9", "10.0",
	"1.0-1.0", "1.0-rc", "1.0-rc0", "1.0.0.0", "1.0-0",
}

func TestGenericExactAnswersNeverContradictSemver(t *testing.T) {
	// An answer graded Exact is reported to the user as proven, so no such
	// answer may contradict a scheme the producer might have meant. Semver is
	// one of the two readings of every ambiguous tail -- the other is dpkg,
	// which oracle_test.go asks directly -- and this package already implements
	// it, so it can be asked here without an external tool.
	//
	// Equalities where one core is a zero-padded prefix of the other are the
	// documented exception: "1.0" and "1.0.0" are one release by §3.4, which is
	// a convention about unclassified data rather than a claim about semver.
	for _, a := range genericAdversaries {
		for _, b := range genericAdversaries {
			n, c, err := CompareCertain(Generic, a, b)
			if err != nil || c != Exact {
				continue
			}
			pa, ca, oka := parseSemver(a)
			pb, cb, okb := parseSemver(b)
			if !oka || !okb || ca != Exact || cb != Exact {
				continue
			}
			ta, _ := splitNumericCore(a)
			tb, _ := splitNumericCore(b)
			if n == 0 && len(ta) != len(tb) {
				continue
			}
			if want := compareSemverParts(pa, pb); n != want {
				t.Errorf("CompareCertain(Generic, %q, %q) = %d exact, semver orders them %d",
					a, b, n, want)
			}
		}
	}
}

func TestGenericHandlesTheCorpusRowsVerbatim(t *testing.T) {
	// Three real rows, compared against the versions a scan would carry.
	checkOrder(t, Generic, []orderCase{
		// xfree86: last affected 4.2.0.
		{"4.1.0", "4.2.0", -1},
		{"4.2.1", "4.2.0", 1},
		// Open Build Service: fixed 2.4.4, introduced unspecified.
		{"2.4.3", "2.4.4", -1},
		{"2.4.4", "2.4.4", 0},
	})
}
