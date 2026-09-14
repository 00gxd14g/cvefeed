package version

import "testing"

func TestDebianTildeSortsBeforeEverythingIncludingNothing(t *testing.T) {
	// This is the whole reason a distro can ship 1.0~rc1 and have the eventual
	// 1.0 upgrade over it. Reading "~" as ordinary punctuation puts the release
	// candidate above the release and reports patched systems as vulnerable.
	checkChain(t, Debian, []string{"1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"})
	checkOrder(t, Debian, []orderCase{
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0-1~bpo11+1", "1.0-1", -1},
		{"2.2.4-1~deb11u1", "2.2.4-1", -1},
	})
}

func TestDebianEpochOutranksEveryUpstreamVersion(t *testing.T) {
	checkOrder(t, Debian, []orderCase{
		{"1:1.0", "2.0", 1},
		{"1:1.0", "1.0", 1},
		{"2:0.1", "1:9.9", 1},
		// An absent epoch is zero, not "unstated".
		{"0:1.0", "1.0", 0},
	})
}

func TestDebianRevisionIsComparedAfterUpstreamAndSeparately(t *testing.T) {
	checkOrder(t, Debian, []orderCase{
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-10", "1.0-9", 1},
		// The revision comes from the LAST hyphen: an upstream version is
		// allowed to contain one, a revision is not.
		{"1.0-beta-1", "1.0-beta-2", -1},
		// Upstream "1.0-beta" beats upstream "1.0" because a hyphen weighs more
		// than the end of the string, which is dpkg's answer too.
		{"1.0-beta-1", "1.0-1", 1},
	})
}

func TestDebianUppercaseSortsBeforeLowercaseAndLettersBeforePunctuation(t *testing.T) {
	// dpkg weighs a letter by its ASCII value and every other character by its
	// value plus 256, which is why "+" beats every letter.
	checkOrder(t, Debian, []orderCase{
		{"1.0A", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"1.0", "1.0+deb1", -1},
		{"1.0.0", "1.0", 1},
	})
}

func TestDebianDigitRunsCompareByValueNotByText(t *testing.T) {
	checkOrder(t, Debian, []orderCase{
		{"1.9", "1.10", -1},
		{"1.010", "1.10", 0},
		{"1.0-9", "1.0-10", -1},
		// A release counter can outgrow every integer type; the comparison is
		// done on the digits themselves so it cannot overflow.
		{"1.0-99999999999999999999999", "1.0-100000000000000000000000", -1},
	})
}

func TestDebianOffSpecVersionsAreOrderedButGradedDown(t *testing.T) {
	// verrevcmp is defined over any byte string, so a near miss still gets a
	// stable answer. What it does not get is the claim that dpkg would agree.
	if c := certaintyOf(t, Debian, "1.0-1", "1.0-2"); c != Exact {
		t.Errorf("certainty for well formed Debian versions = %q, want %q", c, Exact)
	}
	if c := certaintyOf(t, Debian, "release-2.0", "release-3.0"); c != Heuristic {
		t.Errorf("certainty for a version dpkg would reject = %q, want %q", c, Heuristic)
	}
}
