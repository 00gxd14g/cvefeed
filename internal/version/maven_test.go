package version

import "testing"

func TestMavenQualifiersOrderAroundTheRelease(t *testing.T) {
	// The release sits in the middle of Maven's qualifier list: alpha, beta,
	// milestone, rc and snapshot come before it, and sp comes after. An
	// unrecognised qualifier also sorts after the release, which is the rule
	// most reimplementations get backwards.
	checkChain(t, Maven, []string{
		"1.0-alpha-1", "1.0-alpha-2", "1.0-beta-1", "1.0-milestone-1",
		"1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp", "1.0-foo",
	})
}

func TestMavenFoldsAliasesAndShorthandQualifiers(t *testing.T) {
	checkOrder(t, Maven, []orderCase{
		{"1.0-ga", "1.0", 0},
		{"1.0-final", "1.0", 0},
		{"1.0-release", "1.0", 0},
		{"1.0-cr1", "1.0-rc1", 0},
		{"1.0-SNAPSHOT", "1.0-snapshot", 0},
		// a, b and m are alpha, beta and milestone when a digit follows.
		{"1a1", "1-alpha-1", 0},
		{"1b2", "1-beta-2", 0},
		{"1m3", "1-milestone-3", 0},
		{"1a", "1-a", 0},
	})
}

func TestMavenComparesAWholeNestedListAgainstAnAbsentItem(t *testing.T) {
	// MNG-6964. A nested list whose first item is "null" -- an integer zero, or
	// a release-equivalent qualifier such as ga, final or release -- cannot be
	// normalised away when a non-null item follows it, so comparing only that
	// first item answers "equal" for versions ComparableVersion sorts apart.
	// At a fix boundary that reports an affected component as patched.
	checkOrder(t, Maven, []orderCase{
		{"1.2.3-ga.1", "1.2.3", 1},
		{"1.2.3-final.1", "1.2.3", 1},
		{"1.2.3-release.2", "1.2.3", 1},
		{"1.0-0.1", "1.0", 1},
		// A list that is null all the way through is still equal to nothing.
		{"1.0-0.0", "1.0", 0},
	})
}

func TestMavenTrailingZeroesAndReleaseQualifiersAreInsignificant(t *testing.T) {
	checkOrder(t, Maven, []orderCase{
		{"1", "1.0", 0},
		{"1", "1.0.0", 0},
		{"1.0", "1.0.0", 0},
		{"1", "1-0", 0},
		{"1.0", "1.0-0", 0},
	})
}

func TestMavenDashOpensANestedListSoDottedComponentsOutrankIt(t *testing.T) {
	// 2.0-1 is a qualifier list hanging off 2.0, while 2.0.1 is a third
	// component of the version itself, and Maven orders the list below the
	// number. This is why a build number never overtakes a patch release.
	checkOrder(t, Maven, []orderCase{
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0-2", -1},
		{"2.0-1", "2.0.1", -1},
		{"2.0.1", "2.0.1-xyz", -1},
		{"2.0.1-xyz", "2.0.1-123", -1},
		{"2.0.1-klm", "2.0.1-lmn", -1},
	})
}

func TestMavenOrdersNumbersBeforeQualifiersAtEveryDepth(t *testing.T) {
	checkOrder(t, Maven, []orderCase{
		{"1.0.0", "1.1", -1},
		{"1.0.1", "1.1", -1},
		{"1.1", "1.2.0", -1},
		{"1.5", "2", -1},
		{"1.0-alpha-1-SNAPSHOT", "1.0-alpha-1", -1},
		{"1.0-alpha-1", "1.0", -1},
	})
}
