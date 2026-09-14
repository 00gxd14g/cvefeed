package version

import (
	"os/exec"
	"strings"
	"testing"
)

// The three schemes with a reference implementation on disk are checked against
// it rather than against a table someone typed from memory. These tests skip
// when the tool is absent, so they cost nothing on a machine that lacks it and
// catch a divergence on any machine that has it.

func TestDebianOrderingMatchesDpkg(t *testing.T) {
	tool, err := exec.LookPath("dpkg")
	if err != nil {
		t.Skip("dpkg is not installed; nothing to differ against")
	}
	oracle := func(a, b string) (int, bool) {
		if err := exec.Command(tool, "--compare-versions", a, "lt", b).Run(); err == nil {
			return -1, true
		}
		if err := exec.Command(tool, "--compare-versions", a, "eq", b).Run(); err == nil {
			return 0, true
		}
		if err := exec.Command(tool, "--compare-versions", a, "gt", b).Run(); err == nil {
			return 1, true
		}
		// dpkg refuses versions outside its grammar; those are ours to order.
		return 0, false
	}
	checkAgainstOracle(t, Debian, schemeCorpora[Debian], oracle)
}

func TestRPMOrderingMatchesRpmdevVercmp(t *testing.T) {
	tool, err := exec.LookPath("rpmdev-vercmp")
	if err != nil {
		t.Skip("rpmdev-vercmp is not installed; nothing to differ against")
	}
	oracle := func(a, b string) (int, bool) {
		// rpmdev-vercmp exits 0 when equal, 11 when the first EVR is newer and
		// 12 when the second is.
		err := exec.Command(tool, a, b).Run()
		if err == nil {
			return 0, true
		}
		exit, ok := err.(*exec.ExitError)
		if !ok {
			return 0, false
		}
		switch exit.ExitCode() {
		case 11:
			return 1, true
		case 12:
			return -1, true
		}
		return 0, false
	}
	checkAgainstOracle(t, RPM, schemeCorpora[RPM], oracle)
}

func TestAlpineOrderingMatchesApkVersion(t *testing.T) {
	tool, err := exec.LookPath("apk")
	if err != nil {
		t.Skip("apk is not installed; nothing to differ against")
	}
	oracle := func(a, b string) (int, bool) {
		out, err := exec.Command(tool, "version", "-t", a, b).Output()
		if err != nil {
			return 0, false
		}
		switch strings.TrimSpace(string(out)) {
		case "<":
			return -1, true
		case "=":
			return 0, true
		case ">":
			return 1, true
		}
		return 0, false
	}
	checkAgainstOracle(t, Alpine, schemeCorpora[Alpine], oracle)
}

func TestGenericExactAnswersNeverContradictDpkg(t *testing.T) {
	// The other half of the same property: GENERIC grades an answer Exact only
	// when no reading of the string contradicts it, and dpkg is the reading
	// most likely to. Every pair it decides at Exact is put to dpkg, which is
	// the authority for the "-1ubuntu2" tails and the "N:" epochs the corpus is
	// full of. Padding variants are the documented exception, as in
	// TestGenericExactAnswersNeverContradictSemver.
	tool, err := exec.LookPath("dpkg")
	if err != nil {
		t.Skip("dpkg is not installed; nothing to differ against")
	}
	oracle := func(a, b string) (int, bool) {
		if err := exec.Command(tool, "--compare-versions", a, "lt", b).Run(); err == nil {
			return -1, true
		}
		if err := exec.Command(tool, "--compare-versions", a, "eq", b).Run(); err == nil {
			return 0, true
		}
		if err := exec.Command(tool, "--compare-versions", a, "gt", b).Run(); err == nil {
			return 1, true
		}
		return 0, false
	}
	// Antisymmetry is established in version_test.go, so one direction of each
	// pair is enough here and keeps the process spawning down.
	seen := map[string]bool{}
	var versions []string
	for _, v := range append(genericAdversaries, schemeCorpora[Generic]...) {
		if !seen[v] {
			seen[v] = true
			versions = append(versions, v)
		}
	}
	for i := range versions {
		for j := i + 1; j < len(versions); j++ {
			a, b := versions[i], versions[j]
			n, c, err := CompareCertain(Generic, a, b)
			if err != nil || c != Exact {
				continue
			}
			ca, _ := splitNumericCore(a)
			cb, _ := splitNumericCore(b)
			if n == 0 && len(ca) != len(cb) {
				continue
			}
			want, ok := oracle(a, b)
			if !ok {
				continue
			}
			if n != want {
				t.Errorf("CompareCertain(Generic, %q, %q) = %d exact, dpkg orders them %d",
					a, b, n, want)
			}
		}
	}
}

func checkAgainstOracle(t *testing.T, s Scheme, versions []string, oracle func(a, b string) (int, bool)) {
	t.Helper()
	compared := 0
	for i := range versions {
		for j := i + 1; j < len(versions); j++ {
			a, b := versions[i], versions[j]
			want, ok := oracle(a, b)
			if !ok {
				continue
			}
			got, err := Compare(s, a, b)
			if err != nil {
				t.Errorf("Compare(%s, %q, %q) refused, the reference implementation said %d", s, a, b, want)
				continue
			}
			if got != want {
				t.Errorf("Compare(%s, %q, %q) = %d, reference implementation says %d", s, a, b, got, want)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Errorf("no pair of %s versions reached the reference implementation", s)
	}
}
