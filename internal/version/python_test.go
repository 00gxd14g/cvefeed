package version

import "testing"

func TestPEP440OrdersDevBeforePreBeforeReleaseBeforePost(t *testing.T) {
	// The ladder from the PyPA version specifiers spec, in its published order.
	// None of these steps is lexical: "dev" sorts below "a" while "post" sorts
	// above the bare release, and a missing post is not a post of zero.
	checkChain(t, Python, []string{
		"1.0.dev456",
		"1.0a1",
		"1.0a2.dev456",
		"1.0a12.dev456",
		"1.0a12",
		"1.0b1.dev456",
		"1.0b2",
		"1.0b2.post345.dev456",
		"1.0b2.post345",
		"1.0rc1.dev456",
		"1.0rc1",
		"1.0",
		"1.0+abc.5",
		"1.0+abc.7",
		"1.0+5",
		"1.0.post456.dev34",
		"1.0.post456",
		"1.0.15",
		"1.1.dev1",
	})
}

func TestPEP440EpochOutranksEveryRelease(t *testing.T) {
	checkOrder(t, Python, []orderCase{
		{"1!1.0", "2.0", 1},
		{"1!1.0", "1.0", 1},
		{"2!0.1", "1!9.9", 1},
		{"0!1.0", "1.0", 0},
	})
}

func TestPEP440NormalisesSpellingsBeforeOrdering(t *testing.T) {
	checkOrder(t, Python, []orderCase{
		{"1.0a1", "1.0-alpha-1", 0},
		{"1.0b1", "1.0.beta1", 0},
		{"1.0rc1", "1.0c1", 0},
		{"1.0rc1", "1.0-preview-1", 0},
		{"1.0.post1", "1.0-1", 0},
		{"1.0.post1", "1.0rev1", 0},
		{"1.0.post1", "1.0-r1", 0},
		{"v1.0", "1.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.0.0", 0},
		// An implicit number is zero: "1.0a" is "1.0a0".
		{"1.0a", "1.0a0", 0},
		{"1.0.dev", "1.0.dev0", 0},
	})
}

func TestPEP440LocalVersionSortsAboveItsOwnBase(t *testing.T) {
	// A local build of 1.0 is newer than 1.0, and a numeric local segment
	// outranks an alphabetic one however long the alphabetic one is.
	checkOrder(t, Python, []orderCase{
		{"1.0", "1.0+local", -1},
		{"1.0+abc", "1.0+5", -1},
		{"1.0+1", "1.0+2", -1},
		{"1.0+abc", "1.0+abc.1", -1},
		{"1.0+abc.1", "1.0.post1", -1},
	})
}

func TestPEP440RejectsWhatItIsNotAndSaysSo(t *testing.T) {
	if c := certaintyOf(t, Python, "1.0a1", "1.0"); c != Exact {
		t.Errorf("certainty for PEP 440 versions = %q, want %q", c, Exact)
	}
	// A Debian-shaped string declared PyPI is not a PEP 440 version, whatever
	// the producer said, so it drops to the generic ordering.
	if c := certaintyOf(t, Python, "1.0-1ubuntu1", "1.0-2ubuntu1"); c != Heuristic {
		t.Errorf("certainty for a non-PEP-440 version = %q, want %q", c, Heuristic)
	}
}
