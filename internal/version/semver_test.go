package version

import "testing"

func TestSemverPrereleasePrecedenceFollowsClauseEleven(t *testing.T) {
	// The example ladder from the specification. Its two surprises are that a
	// pre-release sorts below the release it precedes, and that a numeric
	// identifier sorts below an alphanumeric one.
	checkChain(t, Semver, []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	})
	checkChain(t, Semver, []string{"1.0.0", "2.0.0", "2.1.0", "2.1.1"})
}

func TestSemverBuildMetadataIsIgnoredForPrecedence(t *testing.T) {
	// Clause 10. Treating build metadata as ordering data would split one
	// release into several and put a rebuild ahead of its own fix.
	checkOrder(t, Semver, []orderCase{
		{"1.0.0+build.1", "1.0.0", 0},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"1.0.0-alpha+001", "1.0.0-alpha+002", 0},
		{"1.0.0+build.1", "1.0.1", -1},
	})
}

func TestSemverAcceptsTheDecorationsProducersActuallyShip(t *testing.T) {
	checkOrder(t, Semver, []orderCase{
		{"v1.0.0", "1.0.0", 0},
		{"=1.0.0", "1.0.0", 0},
		{"V2.0.0", "v1.9.9", 1},
		// Coercion of a short version is order preserving, so it stays exact.
		{"1.2", "1.2.0", 0},
		{"1", "1.0.0", 0},
		{"1.2", "1.3", -1},
	})
	if c := certaintyOf(t, Semver, "1.2", "1.3"); c != Exact {
		t.Errorf("certainty for a two component version = %q, want %q", c, Exact)
	}
}

func TestSemverHandlesTheKernelsFourComponentVersions(t *testing.T) {
	// The Linux CNA types dotted numeric bounds SEMVER, including the historic
	// four component ones. Refusing them would drop 27,477 records worth of
	// bounds; comparing the extra component numerically costs nothing.
	checkOrder(t, Semver, []orderCase{
		{"5.15.32", "5.15.33", -1},
		{"5.15.32", "5.15.32.1", -1},
		{"2.6.32.71", "2.6.32.72", -1},
		{"6.1", "6.1.1", -1},
		{"6.1-rc1", "6.1", -1},
	})
}

func TestSemverInputsThatOnlyClaimToBeSemverAreGradedDown(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// RubyGems puts a pre-release behind a dot, which Gem::Version orders
		// exactly as semver orders a hyphen.
		{"1.0.0.rc1", "1.0.0", -1},
		{"1.0.0.rc1", "1.0.0.rc2", -1},
		// Leading zeroes are forbidden by clause 2, so the producer is using
		// some other numbering and may mean something by it.
		{"2021.03.09", "2021.3.10", -1},
		// Clause 2 defines exactly three components. The kernel's fourth is
		// ordered numerically because nothing else makes sense, but that is
		// a reading of the string, not the specification deciding.
		{"5.15.32", "5.15.32.1", -1},
		{"2.6.32.71", "2.6.32.72", -1},
		// Clause 9 requires an identifier after the hyphen; "1.0.0-" can only
		// order as 1.0.0, and it is still not a version the grammar admits.
		{"1.0.0-", "1.0.1", -1},
	}
	for _, tc := range cases {
		checkOrder(t, Semver, []orderCase{{tc.a, tc.b, tc.want}})
		if c := certaintyOf(t, Semver, tc.a, tc.b); c != Heuristic {
			t.Errorf("certainty for %q vs %q = %q, want %q", tc.a, tc.b, c, Heuristic)
		}
	}

	// A pre-release identifier that happens to be a distro revision is valid
	// semver and stays exact, even though it reads like Debian.
	checkOrder(t, Semver, []orderCase{{"1.0.0-0ubuntu3", "1.0.0", -1}})
	if c := certaintyOf(t, Semver, "1.0.0-0ubuntu3", "1.0.0"); c != Exact {
		t.Errorf("certainty for a valid pre-release = %q, want %q", c, Exact)
	}
}

func TestSemverProseIsRefusedRatherThanGuessedAt(t *testing.T) {
	// "SEMVER" is a claim, not a guarantee. When the claim is false and nothing
	// else can order the operands either, the answer is a refusal.
	for _, v := range []string{"not-a-version", "before rewrite", "latest"} {
		requireNotComparable(t, Semver, v, "1.0.0")
	}
}

func TestGoModuleVersionsOrderAsSemverIncludingPseudoVersions(t *testing.T) {
	checkOrder(t, Go, []orderCase{
		// A pseudo-version is a pre-release of its base, so it sorts below the
		// tagged release, and two of them order by their UTC timestamps.
		{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0", -1},
		{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0-20201109021931-aaa7c04131f5", -1},
		{"v1.2.3", "v1.2.4", -1},
		// "+incompatible" is build metadata and carries no precedence, which is
		// what golang.org/x/mod/semver reports too.
		{"v2.0.0+incompatible", "v2.0.0", 0},
		{"v2.0.0+incompatible", "v2.0.1", -1},
		{"v1.9.0", "v1.10.0", -1},
	})
}
