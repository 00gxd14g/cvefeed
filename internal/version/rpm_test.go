package version

import "testing"

func TestRPMTildeSortsBeforeAndCaretSortsAfterTheBaseVersion(t *testing.T) {
	// "~" (rpm 4.10) is how a pre-release ships without looking newer than the
	// release; "^" (rpm 4.15) is its mirror image for a post-release snapshot.
	// Both are punctuation to any comparator that has not been taught them, and
	// getting either backwards inverts the answer for a whole distro.
	checkChain(t, RPM, []string{"1.0~rc1", "1.0~rc2", "1.0", "1.0^", "1.0^git1", "1.0^git2"})
	checkOrder(t, RPM, []orderCase{
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
		{"1.0~beta", "1.0~rc1", -1},
	})
}

func TestRPMEpochOutranksVersionAndDefaultsToZero(t *testing.T) {
	checkOrder(t, RPM, []orderCase{
		{"1:1.0-1", "2.0-1", 1},
		{"2:1.0-1", "1:9.9-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1.0-1", "1:0.1-1", -1},
	})
}

func TestRPMReleaseIsComparedAfterVersion(t *testing.T) {
	checkOrder(t, RPM, []orderCase{
		{"1.0-1.el8", "1.0-2.el8", -1},
		{"1.0-1.el8", "1.0-1.el9", -1},
		{"1.0-1.el8_9.2", "1.0-1.el8_9.10", -1},
		{"1.0", "1.0-1", -1},
		{"1.2.3-1.el8", "1.2.4-1.el8", -1},
	})
}

func TestRPMNumericSegmentsOutrankAlphabeticOnes(t *testing.T) {
	checkOrder(t, RPM, []orderCase{
		{"1.a", "1.1", -1},
		{"1.0", "1.0a", -1},
		{"1.0.1", "1.0.a", 1},
		// Segment separators carry no weight of their own: only what they
		// separate is compared.
		{"1.0.1", "1_0_1", 0},
	})
}

func TestRPMDigitRunsCompareByLengthThenTextSoTheyCannotOverflow(t *testing.T) {
	// rpmvercmp was rewritten upstream for exactly this: atoi() overflowed on
	// long release counters and the comparison silently went wrong.
	checkOrder(t, RPM, []orderCase{
		{"1.9", "1.10", -1},
		{"1.0010", "1.10", 0},
		{"1.0-99999999999999999999999", "1.0-100000000000000000000000", -1},
		{"1.0-100000000000000000000000", "1.0-100000000000000000000001", -1},
	})
}

func TestRPMAnswersAreAlwaysExact(t *testing.T) {
	// rpmvercmp accepts any byte string and defines an order over it, so there
	// is no such thing as an rpm version it merely guesses at.
	for _, tc := range []struct{ a, b string }{
		{"1.0-1", "1.0-2"},
		{"totally-not-an-evr", "1.0-1"},
		{"1.0~rc1", "1.0^git1"},
	} {
		if c := certaintyOf(t, RPM, tc.a, tc.b); c != Exact {
			t.Errorf("certainty for RPM %q vs %q = %q, want %q", tc.a, tc.b, c, Exact)
		}
	}
}
