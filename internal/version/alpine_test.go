package version

import "testing"

func TestAlpinePreSuffixesSortBelowAndPostSuffixesAboveTheBareVersion(t *testing.T) {
	// _alpha, _beta, _pre and _rc are pre-releases; _p and the vcs suffixes are
	// post-releases. Reading _p1 as a pre-release would report every package
	// carrying a security patch revision as still unpatched.
	checkChain(t, Alpine, []string{
		"1.0_alpha1", "1.0_alpha2", "1.0_beta1", "1.0_pre1", "1.0_rc1",
		"1.0", "1.0_cvs1", "1.0_svn1", "1.0_git1", "1.0_hg1", "1.0_p1", "1.0_p2",
	})
}

func TestAlpineRevisionIsOrderedLastAndAbsentSortsBelowR0(t *testing.T) {
	// The -rN rebuild is where an Alpine security fix usually lands, so it has
	// to order. An absent -rN is NOT -r0, however much the APKBUILD convention
	// suggests it: apk_version_compare_blob_fuzzy() runs "1.0" out of tokens at
	// TOKEN_END and "1.0-r0" at TOKEN_REVISION_NO, and its tail rule sorts the
	// side that terminated first below the other. Reading them as equal lets an
	// installed 1.2.3-r0 sit inside a bound of {last_affected: 1.2.3} that apk
	// places it above.
	checkOrder(t, Alpine, []orderCase{
		{"1.0", "1.0-r0", -1},
		{"1.2.3", "1.2.3-r0", -1},
		{"1.0-r0", "1.0-r1", -1},
		{"1.0-r1", "1.0-r10", -1},
		{"1.0-r10", "1.1-r0", -1},
		{"1.0_p1-r0", "1.0_p1-r1", -1},
		// The same rule one level up: a suffix that states no number runs out
		// of tokens before one that states zero.
		{"1.0_p", "1.0_p0", -1},
		{"1.0_alpha", "1.0_alpha0", -1},
		// The revision digits are read as a plain number, with no leading-zero
		// rule, because they are not introduced by a ".".
		{"1.0-r00", "1.0-r0", 0},
	})
}

func TestAlpineLeadingZeroesSortAComponentBelowTheNumberItSpells(t *testing.T) {
	// apk does not read "05" as five. get_token()'s TOKEN_DIGIT_OR_ZERO case
	// emits a synthetic token worth -(extra zeroes) before the digits, so a
	// padded component sorts as a fraction of the unpadded ones. Comparing the
	// digits by value inverts the order of versions Alpine actually ships --
	// nasm is at 2.15.05 and 2.16.01 -- and reports a patched package as
	// unpatched at certainty Exact.
	checkOrder(t, Alpine, []orderCase{
		{"1.0.05", "1.0.4", -1},
		{"1.0.05-r0", "1.0.4-r0", -1},
		{"2.16.05", "2.16.4", -1},
		{"1.0.010", "1.0.9", -1},
		{"1.05", "1.5", -1},
		{"1.00", "1.0", -1},
		{"1.005", "1.05", -1},
		// The padded component still orders against other padded ones by value,
		// and still sits above the same component without the padding.
		{"1.0.05", "1.0.06", -1},
		{"1.0.05", "1.0.0", 1},
		{"1.0.05", "1.0.5", -1},
		// Only a component introduced by a "." gets the rule: the first one is
		// read as a plain number, so "05.1" and "5.1" are one version.
		{"05.1", "5.1", 0},
		{"00.1", "0.1", 0},
	})
}

func TestAlpineNumbersAndTrailingLetterOrderBeforeAnySuffix(t *testing.T) {
	checkOrder(t, Alpine, []orderCase{
		{"1.0", "1.1", -1},
		{"1.9", "1.10", -1},
		{"1.0", "1.0.1", -1},
		// A trailing letter is part of the number, not a qualifier: 1.0a is a
		// later release than 1.0, the way OpenSSL numbered its patches.
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0b", -1},
		{"1.0b", "1.1", -1},
		// apk's model is Gentoo's: a further component makes a larger version,
		// so 1.0 and 1.0.0 are two versions rather than one. This is the one
		// place where this comparator and the generic one disagree on purpose.
		{"1.0", "1.0.0", -1},
	})
}

func TestAlpineRejectsWhatIsNotAnApkVersionRatherThanMisreadingIt(t *testing.T) {
	// A Debian or semver string wearing an Alpine label falls back to the
	// generic ordering, and the certainty is what says so.
	if c := certaintyOf(t, Alpine, "1.2.3-r4", "1.2.4-r0"); c != Exact {
		t.Errorf("certainty for apk versions = %q, want %q", c, Exact)
	}
	if c := certaintyOf(t, Alpine, "1.0-alpha", "1.0"); c != Heuristic {
		t.Errorf("certainty for a non-apk version = %q, want %q", c, Heuristic)
	}
	checkOrder(t, Alpine, []orderCase{{"1.0-alpha", "1.0", -1}})
}
