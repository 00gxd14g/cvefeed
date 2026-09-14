package version

import (
	"errors"
	"strings"
	"testing"
)

// orderCase is one ordering claim: a sorts before b (-1), alongside it (0) or
// after it (+1). Every case is checked in both directions, so the tables in
// this package double as an antisymmetry suite.
type orderCase struct {
	a, b string
	want int
}

func checkOrder(t *testing.T, s Scheme, cases []orderCase) {
	t.Helper()
	for _, tc := range cases {
		got, err := Compare(s, tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%s, %q, %q) = error %v, want %d", s, tc.a, tc.b, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", s, tc.a, tc.b, got, tc.want)
		}
		back, err := Compare(s, tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%s, %q, %q) = error %v, want %d", s, tc.b, tc.a, err, -tc.want)
			continue
		}
		if back != -tc.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d (antisymmetry)", s, tc.b, tc.a, back, -tc.want)
		}
	}
}

// checkOrderCertain is checkOrder with the grade asserted as well, in both
// directions.
//
// The grade is not decoration: internal/match turns a Generic answer graded
// Heuristic into a refusal and reports an Exact one as proven, so a table that
// checks only the sign keeps passing while an answer quietly promotes itself
// from "guessed" to "proved".
func checkOrderCertain(t *testing.T, s Scheme, want Certainty, cases []orderCase) {
	t.Helper()
	checkOrder(t, s, cases)
	for _, tc := range cases {
		for _, pair := range [][2]string{{tc.a, tc.b}, {tc.b, tc.a}} {
			if c := certaintyOf(t, s, pair[0], pair[1]); c != want {
				t.Errorf("certainty of Compare(%s, %q, %q) = %q, want %q",
					s, pair[0], pair[1], c, want)
			}
		}
	}
}

// checkChain asserts that every version in the list sorts strictly before every
// later one, which covers transitivity as well as the individual steps.
func checkChain(t *testing.T, s Scheme, versions []string) {
	t.Helper()
	for i := 0; i < len(versions); i++ {
		for j := i + 1; j < len(versions); j++ {
			checkOrder(t, s, []orderCase{{versions[i], versions[j], -1}})
		}
	}
}

func certaintyOf(t *testing.T, s Scheme, a, b string) Certainty {
	t.Helper()
	_, c, err := CompareCertain(s, a, b)
	if err != nil {
		t.Fatalf("CompareCertain(%s, %q, %q) = error %v, want an answer", s, a, b, err)
	}
	return c
}

func requireNotComparable(t *testing.T, s Scheme, a, b string) {
	t.Helper()
	n, c, err := CompareCertain(s, a, b)
	if !errors.Is(err, ErrNotComparable) {
		t.Fatalf("CompareCertain(%s, %q, %q) = (%d, %q, %v), want ErrNotComparable", s, a, b, n, c, err)
	}
	if n != 0 || c != "" {
		t.Errorf("CompareCertain(%s, %q, %q) returned (%d, %q) alongside its refusal, want (0, \"\")", s, a, b, n, c)
	}
}

func TestOpaqueSchemeNeverOrdersAnything(t *testing.T) {
	// Two identical commit hashes are still not ordered: equality is an
	// ordering claim, and the scheme exists to say there is no ordering.
	for _, tc := range []struct{ a, b string }{
		{"1.0.0", "1.0.1"},
		{"c5a4b7e", "c5a4b7e"},
		{"", "1.0.0"},
	} {
		requireNotComparable(t, Opaque, tc.a, tc.b)
	}
	if Ordered(Opaque) {
		t.Error("Ordered(Opaque) = true, want false")
	}
}

func TestUnknownSchemeIsRefusedRatherThanGuessed(t *testing.T) {
	requireNotComparable(t, Scheme("MADE_UP"), "1.0.0", "1.0.1")
	if Ordered(Scheme("MADE_UP")) {
		t.Error("Ordered(MADE_UP) = true, want false")
	}
	for _, s := range []Scheme{Semver, Debian, RPM, Alpine, Maven, Python, Go, Generic} {
		if !Ordered(s) {
			t.Errorf("Ordered(%s) = false, want true", s)
		}
	}
}

func TestCommitHashesAreNeverComparedToVersions(t *testing.T) {
	// The kernel CNA mixes commit bounds with version bounds inside one record,
	// so this guard has to fire in every scheme, not only where GIT was declared.
	hashes := []string{
		"daa7c04131f5",
		"5b8e3d1a2f4c6d8e0a2b4c6d8e0a2b4c6d8e0a2b",
		"C5A4B7E9",
		"deadbeef",
	}
	for _, s := range []Scheme{Semver, Debian, RPM, Alpine, Maven, Python, Go, Generic} {
		for _, h := range hashes {
			requireNotComparable(t, s, h, "1.0.0")
			requireNotComparable(t, s, "1.0.0", h)
		}
	}
}

func TestVersionsThatMerelyLookHexadecimalAreStillVersions(t *testing.T) {
	// A date stamp and a build counter are all digits; refusing them would cost
	// real matches, so only improbably long digit runs are treated as hashes.
	for _, s := range []string{"20230601", "1.0.0", "6.1", "abc", "12345"} {
		if LooksLikeCommit(s) {
			t.Errorf("LooksLikeCommit(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"c5a4b7e", "0123456789abcdef0123456789abcdef", "DAA7C04131F5"} {
		if !LooksLikeCommit(s) {
			t.Errorf("LooksLikeCommit(%q) = false, want true", s)
		}
	}
}

func TestSentinelBoundsAreNeverHandedToAComparator(t *testing.T) {
	sentinels := []string{
		"", "   ", "*", "-", "any", "ANY", "all", "all versions",
		"unspecified", "Unspecified", "unknown", "n/a", "N/A", "na",
		"none", "not applicable", `"unspecified"`, "  *  ",
	}
	for _, s := range []Scheme{Semver, Debian, RPM, Alpine, Maven, Python, Go, Generic} {
		for _, v := range sentinels {
			requireNotComparable(t, s, v, "1.0.0")
			requireNotComparable(t, s, "1.0.0", v)
		}
	}
}

func TestSentinelZeroIsAVersionNotAPlaceholder(t *testing.T) {
	// "0" means "beginning of time" in an OSV introduced bound and "empty
	// range" in a fixed bound, but both readings belong to the range evaluator.
	// By the time a comparator sees it, it is the version zero.
	checkOrder(t, Generic, []orderCase{
		{"0", "0.0.1", -1},
		{"0", "1", -1},
		{"0", "0", 0},
	})
	checkOrder(t, Semver, []orderCase{{"0", "0.0.1", -1}})
}

func TestClassifySentinelKeepsTheSetClosed(t *testing.T) {
	cases := []struct {
		in   string
		want Sentinel
	}{
		{"", SentinelEmpty},
		{"  ", SentinelEmpty},
		{`""`, SentinelEmpty},
		{"*", SentinelAll},
		{"-", SentinelAll},
		{"any", SentinelAll},
		{"All Versions", SentinelAll},
		{"unspecified", SentinelUnknown},
		{"UNKNOWN", SentinelUnknown},
		{"n/a", SentinelUnknown},
		{"none", SentinelUnknown},
		{"0", SentinelZero},
		// Widening the set would silently turn stated bounds into unbounded
		// ones, and an unbounded range matches every version there is.
		{"0.0", NotSentinel},
		{"0.0.0", NotSentinel},
		{"v0", NotSentinel},
		{"nan", NotSentinel},
		{"noneofit", NotSentinel},
	}
	for _, tc := range cases {
		if got := ClassifySentinel(tc.in); got != tc.want {
			t.Errorf("ClassifySentinel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRefusalNamesBothOperandsAndTheScheme(t *testing.T) {
	// A scan report has to be auditable by a human who was not here when it ran.
	_, err := Compare(Debian, "unspecified", "1.2.3-1")
	if err == nil {
		t.Fatal("Compare returned no error for a sentinel operand")
	}
	for _, want := range []string{"unspecified", "1.2.3-1", "DEBIAN", "not comparable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestCompareAgreesWithCompareCertain(t *testing.T) {
	cases := []struct {
		scheme Scheme
		a, b   string
	}{
		{Semver, "1.0.0", "1.0.1"},
		{Debian, "1:1.0", "2.0"},
		{RPM, "1.0~rc1", "1.0"},
		{Alpine, "1.0-r1", "1.0-r2"},
		{Maven, "1.0-alpha-1", "1.0"},
		{Python, "1.0.dev1", "1.0"},
		{Go, "v1.2.3", "v1.2.4"},
		{Generic, "4.2.0", "4.3"},
	}
	for _, tc := range cases {
		want, wantErr := Compare(tc.scheme, tc.a, tc.b)
		got, _, gotErr := CompareCertain(tc.scheme, tc.a, tc.b)
		if got != want || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("Compare(%s, %q, %q) = (%d, %v), CompareCertain = (%d, %v)",
				tc.scheme, tc.a, tc.b, want, wantErr, got, gotErr)
		}
	}
}

func TestQuotedAndPaddedOperandsAreUnwrapped(t *testing.T) {
	// CSAF documents and a handful of CNAs ship the quotes with the value.
	checkOrder(t, Semver, []orderCase{
		{`"1.0.0"`, "1.0.1", -1},
		{" 1.0.0 ", "1.0.0", 0},
		{"'2.0.0'", `"2.0.0"`, 0},
	})
}

// The refusal path is the one the specification expects to dominate a scan, so
// it is the one worth measuring. BenchmarkGenericRefused should stay within
// reach of BenchmarkGenericDecided; when it drifts, something on the refusal
// path has started doing work the caller throws away.
func BenchmarkGenericDecided(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Compare(Generic, "2.14.0", "2.15.0"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenericRefused(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Compare(Generic, "1.0.0-0", "1.0.0-0ubuntu3"); err == nil {
			b.Fatal("the pair was decided")
		}
	}
}
