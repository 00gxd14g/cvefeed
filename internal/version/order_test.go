package version

import (
	"math/rand"
	"strconv"
	"testing"
)

// schemeCorpora are the version strings each scheme is exercised against as an
// order rather than as individual pairs. A comparator that answers every table
// case correctly and still fails here is not usable: a range check asks for
// "v >= introduced AND v < fixed", which is only meaningful if the answers form
// a consistent order.
var schemeCorpora = map[Scheme][]string{
	Semver: {
		"0.0.1", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0+build.5",
		"1.0.1", "1.1.0", "1.2", "2.0.0", "2.0.0-rc.1", "v2.1.3", "5.15.32",
		"5.15.32.1", "10.0.0", "1.0.0-0ubuntu3",
	},
	Debian: {
		"0.1", "1.0~~", "1.0~", "1.0~rc1", "1.0~rc2", "1.0", "1.0a", "1.0+deb1",
		"1.0-1", "1.0-1~bpo11+1", "1.0-2", "1.0-10", "1.0.0", "1.1", "1:0.5",
		"1:1.0-1", "2:0.1", "2.2.4-1~deb11u1", "2.2.4-1", "9.9",
	},
	RPM: {
		"1.0~rc1", "1.0~rc2", "1.0", "1.0^", "1.0^git1", "1.0-1", "1.0-2",
		"1.0-1.el8", "1.0-1.el9", "1.0-2.el8", "1.0.1-1", "1.2.3-1.el8",
		"1.2.3-2.el8", "1.2.4-1.el8", "1:1.0-1", "2:0.1-1", "0.9-1", "1.0-1.el8_9.2",
		"1.0-1.el8_9.10", "10.0-1",
	},
	Alpine: {
		"1.0_alpha1", "1.0_alpha2", "1.0_beta1", "1.0_pre1", "1.0_rc1", "1.0-r0",
		"1.0", "1.0-r1", "1.0-r10", "1.0a", "1.0b", "1.0.0", "1.0.1", "1.0_p1",
		"1.0_p1-r1", "1.0_p2", "1.1", "1.10", "2.0-r0", "0.9-r3",
		// apk's two rules that no other scheme shares: a leading zero sorts a
		// component below the number it spells, and a stated -r0 sorts above a
		// version that states no revision at all.
		"1.00", "1.05", "1.5", "1.0.05", "1.0.5", "1.2.3", "1.2.3-r0", "1.0_p",
	},
	Maven: {
		"1", "1.0", "1.0.0", "1.0-alpha-1", "1.0-alpha-2", "1.0-beta-1",
		"1.0-milestone-1", "1.0-rc1", "1.0-cr1", "1.0-SNAPSHOT", "1.0-ga",
		"1.0-sp", "1.0-foo", "1.0-1", "1.0-2", "1.0.1", "1.1", "2.0", "2.0.1-xyz",
		"2.0.1-123",
	},
	Python: {
		"0.9", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12", "1.0b2",
		"1.0b2.post345", "1.0rc1", "1.0", "1.0+abc.5", "1.0+5", "1.0.post456",
		"1.0.15", "1.1.dev1", "1.1", "1!0.1", "2.0", "1.0-1", "v1.2", "1.0.post1",
	},
	Go: {
		"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0", "v0.1.0", "v1.0.0-rc.1",
		"v1.0.0", "v1.0.1", "v1.2.3", "v1.9.0", "v1.10.0", "v2.0.0+incompatible",
		"v2.0.0", "v2.0.1", "v3.0.0",
	},
	Generic: {
		"0.9", "1.0", "1.0.0", "1.0.1", "1.0.2", "1.1", "2.0", "4.2.0", "4.3",
		"2023-06-01", "2023-07-05", "1.01", "10.0", "1.0-2", "1.0-3", "20240101",
	},
}

// compareMatrix precomputes every pairwise answer so the triple loop below is
// cheap. A false entry in decided marks a pair the scheme refused, which is a
// legitimate outcome and simply removes that pair from the property checks.
func compareMatrix(t *testing.T, s Scheme, versions []string) ([][]int, [][]bool) {
	t.Helper()
	n := len(versions)
	order := make([][]int, n)
	decided := make([][]bool, n)
	for i := range order {
		order[i] = make([]int, n)
		decided[i] = make([]bool, n)
		for j := range order[i] {
			v, err := Compare(s, versions[i], versions[j])
			order[i][j], decided[i][j] = v, err == nil
		}
	}
	return order, decided
}

func checkOrderProperties(t *testing.T, s Scheme, versions []string) {
	t.Helper()
	order, decided := compareMatrix(t, s, versions)

	for i, v := range versions {
		if !decided[i][i] || order[i][i] != 0 {
			t.Errorf("Compare(%s, %q, %q) is not zero: a version has to equal itself", s, v, v)
		}
	}
	for i := range versions {
		for j := range versions {
			if decided[i][j] != decided[j][i] {
				t.Errorf("Compare(%s, %q, %q) decided but the reverse did not", s, versions[i], versions[j])
				continue
			}
			if decided[i][j] && order[i][j] != -order[j][i] {
				t.Errorf("Compare(%s, %q, %q) = %d but the reverse = %d, want them opposite",
					s, versions[i], versions[j], order[i][j], order[j][i])
			}
		}
	}
	for i := range versions {
		for j := range versions {
			if !decided[i][j] || order[i][j] > 0 {
				continue
			}
			for k := range versions {
				if !decided[j][k] || order[j][k] > 0 || !decided[i][k] {
					continue
				}
				if order[i][k] > 0 {
					t.Errorf("transitivity broken under %s: %q <= %q <= %q, yet %q > %q",
						s, versions[i], versions[j], versions[k], versions[i], versions[k])
				}
			}
		}
	}
}

func TestEverySchemeProducesAConsistentOrder(t *testing.T) {
	for s, versions := range schemeCorpora {
		s, versions := s, versions
		t.Run(string(s), func(t *testing.T) {
			checkOrderProperties(t, s, versions)
		})
	}
}

// generateVersions builds version-shaped strings from the pieces the corpus
// actually contains: epochs, dotted numbers, patch letters, tilde and caret
// bounds, qualifiers and revisions. The seed is fixed so a failure is a bug
// report someone can reproduce rather than a flake.
func generateVersions(n int) []string {
	r := rand.New(rand.NewSource(20260818))
	qualifiers := []string{"alpha", "beta", "rc", "pre", "p", "post", "dev", "SNAPSHOT", "git"}
	separators := []string{".", "-", "_", "~", "^", "+"}

	out := make([]string, 0, n)
	for len(out) < n {
		v := ""
		if r.Intn(6) == 0 {
			v += strconv.Itoa(r.Intn(3)) + ":"
		}
		for c := r.Intn(3) + 1; c > 0; c-- {
			if !endsInDigitBoundary(v) {
				v += "."
			}
			v += strconv.Itoa(r.Intn(12))
		}
		if r.Intn(5) == 0 {
			v += string(rune('a' + r.Intn(3)))
		}
		if r.Intn(2) == 0 {
			v += separators[r.Intn(len(separators))] + qualifiers[r.Intn(len(qualifiers))]
			if r.Intn(2) == 0 {
				v += strconv.Itoa(r.Intn(5))
			}
		}
		if r.Intn(3) == 0 {
			v += "-r" + strconv.Itoa(r.Intn(4))
		}
		out = append(out, v)
	}
	return out
}

func endsInDigitBoundary(v string) bool {
	return v == "" || v[len(v)-1] == ':'
}

func TestGeneratedVersionsKeepTheOrderingProperties(t *testing.T) {
	versions := generateVersions(45)
	for _, s := range []Scheme{Semver, Debian, RPM, Alpine, Maven, Python, Go, Generic} {
		s := s
		t.Run(string(s), func(t *testing.T) {
			checkOrderProperties(t, s, versions)
		})
	}
}
