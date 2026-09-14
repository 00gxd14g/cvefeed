package version

import "testing"

// Both operands come from outside: one from a target's package database or a
// service banner, the other from an advisory written by a stranger. Compare has
// to survive any pair, and it has to stay a consistent ordering — an answer that
// contradicts itself when the arguments swap would make findings depend on
// argument order.
func FuzzCompare(f *testing.F) {
	seeds := []string{
		"1.0.0", "2.14.1", "3.0.7-1", "1:7.3", "0", "",
		"1.0.0-rc1", "2.0-beta9", "log4j-core*", "Upgrade to the latest version.",
		"1.0.2a", "05.1", "1.0_p", "4.17.20", "1.10.0", "1.9",
	}
	for _, a := range seeds {
		for _, b := range seeds {
			f.Add("SEMVER", a, b)
		}
	}
	for _, s := range []string{"DEBIAN", "RPM", "ALPINE", "MAVEN", "PYTHON", "GO", "GENERIC", "", "NONSENSE"} {
		f.Add(s, "1.0.0", "1.0.1")
	}

	f.Fuzz(func(t *testing.T, scheme, a, b string) {
		s := Scheme(scheme)
		ab, errAB := Compare(s, a, b)
		ba, errBA := Compare(s, b, a)

		// Either both directions decide or neither does. One-way decidability
		// would mean a finding appears or vanishes depending on which side the
		// caller passed first.
		if (errAB == nil) != (errBA == nil) {
			t.Fatalf("scheme %q: %q vs %q decided one way only (%v / %v)", scheme, a, b, errAB, errBA)
		}
		if errAB != nil {
			return
		}
		if ab != -ba {
			t.Fatalf("scheme %q: compare(%q,%q)=%d but compare(%q,%q)=%d; not antisymmetric",
				scheme, a, b, ab, b, a, ba)
		}
		// Reflexivity: a version equals itself under every scheme that can read
		// it at all.
		if self, err := Compare(s, a, a); err == nil && self != 0 {
			t.Fatalf("scheme %q: %q does not equal itself (%d)", scheme, a, self)
		}
	})
}
