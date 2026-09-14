package match

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/version"
)

func TestCommitBearingRangesResolveToOpaqueWhateverTheEcosystemSays(t *testing.T) {
	// dpkg and rpm ordering will compare any two strings and answer with a
	// straight face, so a hash must be caught before a scheme is chosen, not
	// after.
	for _, rangeType := range []string{"GIT", "ORIGINAL_COMMIT_FOR_FIX"} {
		if got, _ := resolveScheme(rangeType, "Debian", "6.1.55"); got != version.Opaque {
			t.Errorf("resolveScheme(%q, Debian) = %v, want OPAQUE", rangeType, got)
		}
	}
	for _, hash := range []string{"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "deadbeef", "ABCDEF1234567"} {
		if got, _ := resolveScheme("CUSTOM", "Debian", "6.1.55", hash); got != version.Opaque {
			t.Errorf("the hash bound %q under a known ecosystem resolved to %v, want OPAQUE", hash, got)
		}
	}
	for _, v := range []string{"6.1.55", "1.0", "20230101", "3.0.7-27.el9", "2.15.0-1ubuntu2"} {
		if got, _ := resolveScheme("CUSTOM", "Debian", v, "6.1.0"); got == version.Opaque {
			t.Errorf("the version %q was discarded as a commit hash", v)
		}
	}
}

func TestHeuristicOrderingUnderGenericIsRefusedButKeptUnderAnOrderedScheme(t *testing.T) {
	// An answer the scheme reached by convention is the best reading of the
	// data, not a proof. Under GENERIC nothing else is known, so the reading is
	// refused; under a scheme the producer named, it stands and costs a level.
	if _, _, err := compareVersions(version.Generic, "2.15.0-1ubuntu2", "2.15.0"); err == nil {
		t.Error("GENERIC decided the boundary the mainstream schemes disagree about")
	}
	if _, _, err := compareVersions(version.Debian, "2.15.0-1ubuntu2", "2.15.0"); err != nil {
		t.Errorf("DEBIAN refused a comparison dpkg defines: %v", err)
	}
}

func TestLowerBoundSentinelsAreEnumeratedAndUpperBoundSentinelsAreNot(t *testing.T) {
	// A missing lower bound widens the window downwards, which the row already
	// intended; a missing upper bound widens it to infinity, which it did not.
	for _, s := range []string{"", "0", "unspecified", "*", "-", "n/a", "N/A", "none"} {
		if !unboundedLower(s) {
			t.Errorf("unboundedLower(%q) = false", s)
		}
	}
	for _, s := range []string{"1.0", "0.0", "v2", "trunk"} {
		if unboundedLower(s) {
			t.Errorf("unboundedLower(%q) = true; widening this set turns stated bounds into unbounded ones", s)
		}
	}
	for _, s := range []string{"unspecified", "n/a", "*", "-", "unknown", "all versions"} {
		if !sentinelUpper(s) {
			t.Errorf("sentinelUpper(%q) = false", s)
		}
	}
	if sentinelUpper("") {
		t.Error("an absent upper bound is absence, not a sentinel: open-ended windows are real statements")
	}
}

func TestVersionListSentinelsAreDiscardedAndAllVersionsIsFlagged(t *testing.T) {
	listed, all := usableVersions([]string{"n/a", "unspecified", "", "2.4.4", "unknown", "0"})
	if all {
		t.Error("no entry claimed every version")
	}
	if len(listed) != 1 || listed[0] != "2.4.4" {
		t.Fatalf("usable versions = %v, want [2.4.4]", listed)
	}
	if _, all := usableVersions([]string{"all versions"}); !all {
		t.Error("an all-versions claim must be recognised rather than compared")
	}
}

func TestUnionKeepsTheStrongestPositiveAndRefusesToClearOnDoubt(t *testing.T) {
	ordered := elementResult{verdict: vInRange, grade: vgOrdered}
	unbounded := elementResult{verdict: vInRange, grade: vgUnbounded}
	clear := elementResult{verdict: vNotInRange, grade: vgOrdered}
	doubt := elementResult{verdict: vUndecided, grade: vgUndecidable, review: "opaque_scheme:GIT"}

	if got := unionOf([]elementResult{unbounded, ordered}); got.grade != vgOrdered {
		t.Errorf("union grade = %v, want the strongest positive", got.grade)
	}
	if got := unionOf([]elementResult{doubt, ordered}); got.verdict != vInRange {
		t.Error("an undecidable window cannot retract a positive one")
	}
	if got := unionOf([]elementResult{doubt, clear}); got.verdict != vUndecided {
		t.Error("one window we could not decide denies a clean bill of health")
	}
	if got := unionOf([]elementResult{clear, clear}); got.verdict != vNotInRange {
		t.Error("every window clear is a negative")
	}
}

func TestCommonRangeTypeOnlyAppliesWhenEveryWindowAgrees(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"one declared type", []string{"SEMVER"}, "SEMVER"},
		{"a fix commit does not count as a type", []string{"SEMVER", "ORIGINAL_COMMIT_FOR_FIX"}, "SEMVER"},
		{"mixed types leave the list untyped", []string{"SEMVER", "RPM"}, ""},
		{"no types at all", []string{"", ""}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ranges := make([]model.VersionRange, 0, len(tc.in))
			for _, typ := range tc.in {
				ranges = append(ranges, model.VersionRange{Type: typ, Introduced: "0"})
			}
			if got := commonRangeType(ranges); got != tc.want {
				t.Fatalf("commonRangeType(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEpochsAreElidedOnlyWhenExactlyOneSideStatesOne(t *testing.T) {
	tests := []struct {
		name       string
		scheme     version.Scheme
		a, b       string
		wantA      string
		wantB      string
		wantElided bool
	}{
		{"only the installed side carries one", version.RPM, "1:3.0.7-1.el9", "3.0.7-2.el9", "3.0.7-1.el9", "3.0.7-2.el9", true},
		{"only the bound carries one", version.RPM, "3.0.7-1.el9", "1:3.0.7-2.el9", "3.0.7-1.el9", "3.0.7-2.el9", true},
		{"both carry one, so rpm's own rules apply", version.RPM, "1:3.0.7-1", "2:3.0.7-2", "1:3.0.7-1", "2:3.0.7-2", false},
		{"neither carries one", version.RPM, "3.0.7-1", "3.0.7-2", "3.0.7-1", "3.0.7-2", false},
		{"dpkg has epochs too", version.Debian, "2:1.2-1", "1.3-1", "1.2-1", "1.3-1", true},
		{"no other scheme has an epoch to elide", version.Semver, "1:1.2.3", "1.2.4", "1:1.2.3", "1.2.4", false},
		{"a colon that is not an epoch is left alone", version.RPM, "see: the advisory", "3.0.7", "see: the advisory", "3.0.7", false},
		{"an epoch with nothing after it states no version", version.RPM, "1:", "3.0.7", "1:", "3.0.7", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotA, gotB, elided := elideEpochs(tc.scheme, tc.a, tc.b)
			if gotA != tc.wantA || gotB != tc.wantB || elided != tc.wantElided {
				t.Fatalf("elideEpochs = (%q, %q, %v), want (%q, %q, %v)",
					gotA, gotB, elided, tc.wantA, tc.wantB, tc.wantElided)
			}
		})
	}

	// The whole point: with rpm's "absent = 0" the installed build sorts above
	// the bound and the host reads as patched.
	if n, _, err := version.CompareCertain(version.RPM, "1:3.0.7-1.el9", "3.0.7-2.el9"); err != nil || n <= 0 {
		t.Fatalf("rpm ordering of an epoch against an epoch-less bound = %d (%v); the elision guards this", n, err)
	}
	n, c, err := compareVersions(version.RPM, "1:3.0.7-1.el9", "3.0.7-2.el9")
	if err != nil || n >= 0 {
		t.Fatalf("compareVersions = %d (%v), want the installed build below the bound", n, err)
	}
	if !c.epochElided {
		t.Error("the elision was applied without being recorded, which hides the one assumption that could have flipped the verdict")
	}
}

func TestSchemeResolutionPrefersTheEcosystemOverTheDeclaredType(t *testing.T) {
	tests := []struct {
		name      string
		rangeType string
		ecosystem string
		want      version.Scheme
		overrode  bool
	}{
		{"a declared type cannot reorder Debian revisions", "SEMVER", "Debian", version.Debian, true},
		{"nor an rpm release", "SEMVER", "Red Hat", version.RPM, true},
		{"nor an apk rebuild counter", "SEMVER", "Alpine", version.Alpine, true},
		{"agreement needs no note", "SEMVER", "npm", version.Semver, false},
		{"an undeclared type falls to the ecosystem as before", "CUSTOM", "Debian", version.Debian, false},
		{"an ecosystem with no ordering of its own keeps the declared type", "SEMVER", "Bitnami", version.Semver, false},
		{"an unknown ecosystem keeps the declared type", "SEMVER", "SomeVendorOS", version.Semver, false},
		{"a commit type still beats both", "GIT", "Debian", version.Opaque, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, note := resolveScheme(tc.rangeType, tc.ecosystem, "1.0.0", "2.0.0")
			if got != tc.want {
				t.Fatalf("resolveScheme(%q, %q) = %v, want %v", tc.rangeType, tc.ecosystem, got, tc.want)
			}
			if (note != "") != tc.overrode {
				t.Fatalf("note = %q, want overridden = %v", note, tc.overrode)
			}
		})
	}
}

func TestSentinelUpperBoundNamesTheFieldThatTrippedIt(t *testing.T) {
	// A reviewer holding only the report has to be sent to the operand that
	// actually failed. Quoting whichever bound happens to be non-empty sends
	// them to the one that was fine.
	tests := []struct {
		name  string
		rng   model.VersionRange
		field string
		value string
	}{
		{"a sentinel Fixed", model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "unspecified"}, "Fixed", "unspecified"},
		{"a sentinel LastAffected beside a real Fixed",
			model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.0.0", LastAffected: "unspecified"}, "LastAffected", "unspecified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := evalRange(version.Semver, "1.0.0", tc.rng)
			if res.verdict != vUndecided || res.review != "sentinel_upper_bound" {
				t.Fatalf("evalRange = %v/%q, want undecided/sentinel_upper_bound", res.verdict, res.review)
			}
			if !strings.Contains(res.reason, tc.field) {
				t.Errorf("reason %q does not name the field that tripped the check", res.reason)
			}
			if !strings.Contains(res.reason, "bound is \""+tc.value+"\"") {
				t.Errorf("reason %q quotes the wrong operand as the one naming no version", res.reason)
			}
		})
	}
}

func TestEveryOverridingEcosystemActuallyResolvesToAnOrdering(t *testing.T) {
	// ecosystemOrdering lives here and the scheme table lives in
	// internal/version, so a family named here that the other table has never
	// heard of would silently replace a declared type with the generic
	// fallback: an override that loses information instead of adding it.
	// CRAN and Hackage are the two deliberate exceptions — their published
	// orderings are dotted-numeric, which is what GENERIC implements.
	genericByDesign := map[string]bool{"cran": true, "hackage": true}
	for family := range ecosystemOrdering {
		name := osvEcosystemName(family)
		got := version.SchemeFor("", name)
		if got == version.Generic && !genericByDesign[family] {
			t.Errorf("ecosystem %q (%s) overrides the declared type with %v, which decides nothing the type could not", family, name, got)
		}
		if fam, _ := splitEcosystem(name); fam != family {
			t.Errorf("ecosystem %q spells back as %q, which folds to %q: resolveScheme would never find it", family, name, fam)
		}
	}
}

func TestRefusalNamesTheOperandThatIsActuallyACommit(t *testing.T) {
	// The scheme goes opaque when either operand looks like a hash. A reviewer
	// told "the bound is a commit hash" when it was the inventory that recorded
	// one is sent to the operand that was fine.
	hash := "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	rng := model.VersionRange{Type: "CUSTOM", Introduced: "0", Fixed: "2.0.0"}

	res := undecidableRange(version.Opaque, hash, "2.0.0", rng, nil)
	if !strings.Contains(res.reason, "installed version \""+hash+"\" is a commit hash") {
		t.Errorf("reason %q does not name the installed version as the hash", res.reason)
	}
	if strings.Contains(res.reason, "bound \"2.0.0\" is a commit hash") {
		t.Errorf("reason %q calls the release bound a commit hash", res.reason)
	}

	res = undecidableRange(version.Opaque, "1.0", hash, rng, nil)
	if !strings.Contains(res.reason, "bound \""+hash+"\" is a commit hash") {
		t.Errorf("reason %q does not name the bound as the hash", res.reason)
	}

	// A GIT-typed window whose bounds are not hashes at all is refused for the
	// type, and the reason must not invent a hash.
	res = undecidableRange(version.Opaque, "1.0", "2.0", model.VersionRange{Type: "GIT", Fixed: "2.0"}, nil)
	if strings.Contains(res.reason, "commit hash") || !strings.Contains(res.reason, "GIT") {
		t.Errorf("reason %q for a GIT window with release-shaped bounds", res.reason)
	}

	// End to end: the component side is the hash.
	row := Affected{VulnID: "CVE-2026-0026", Vendor: "acme", Product: "libfoo", Source: "cvelist", Ranges: []model.VersionRange{rng}}
	got, ev := Evaluate(Component{Name: "libfoo", Vendor: "acme", Version: hash}, row)
	if got != Undecidable || !strings.Contains(ev.Reason, "installed version \""+hash+"\" is a commit hash") {
		t.Fatalf("Evaluate = %v (%s), want Undecidable naming the installed hash", got, ev.Reason)
	}
}

func TestVersionListSchemeIsResolvedFromTheComponentAndTheDeclaredTypeOnly(t *testing.T) {
	hash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	listed := plainVersions([]string{"1.0.0", "2.0.0", hash})
	elems, _ := evalVersionList("", "npm", "1.0", listed, false, true, "versions")
	if len(elems) != 2 {
		t.Fatalf("elements = %d, want the releases and the commits judged separately", len(elems))
	}
	if elems[0].scheme != version.Semver || elems[0].verdict != vInRange {
		t.Errorf("the releases were judged under %v as %v, want SEMVER/in range", elems[0].scheme, elems[0].verdict)
	}
	if elems[1].scheme != version.Opaque || elems[1].verdict != vNotInRange {
		t.Errorf("the commits were judged under %v as %v, want OPAQUE/not in range", elems[1].scheme, elems[1].verdict)
	}
}

func TestUnionPrefersTheUnconditionalPositiveAtEqualStrength(t *testing.T) {
	conditional := elementResult{verdict: vInRange, grade: vgOrdered, unproven: []string{"target_sw=wordpress"}}
	plain := elementResult{verdict: vInRange, grade: vgOrdered}
	if got := unionOf([]elementResult{conditional, plain}); len(got.unproven) != 0 {
		t.Errorf("the union carried the conditional window's caveat over an unconditional sibling: %v", got.unproven)
	}
	// A weaker unconditional window does not beat a stronger conditional one.
	weak := elementResult{verdict: vInRange, grade: vgUnbounded}
	if got := unionOf([]elementResult{conditional, weak}); got.grade != vgOrdered {
		t.Errorf("the union dropped to %v to shed a caveat", got.grade)
	}
}
