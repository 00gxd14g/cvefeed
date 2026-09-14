package match

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// npmLib is a component with the strongest identity a real inventory produces:
// a purl, which fixes the ecosystem, the namespace and the name in one token.
func npmLib(v string) Component {
	return Component{Name: "marked", Version: v, Ecosystem: "npm", PURL: "pkg:npm/marked@" + v}
}

func npmRow(ranges ...model.VersionRange) Affected {
	return Affected{
		VulnID: "CVE-2026-0001", Product: "marked", Ecosystem: "npm",
		PURL: "pkg:npm/marked", Ranges: ranges, Source: "osv",
	}
}

func TestFixedBoundExcludesTheFixVersionAndLastAffectedIncludesIt(t *testing.T) {
	tests := []struct {
		name    string
		version string
		rng     model.VersionRange
		want    Result
	}{
		{"below an exclusive fix is affected", "2.14.0",
			model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}, Match},
		{"the fix version itself is not affected", "2.15.0",
			model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}, NoMatch},
		{"above an exclusive fix is not affected", "2.15.1",
			model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}, NoMatch},
		{"the last affected version is affected", "4.2.0",
			model.VersionRange{Type: "SEMVER", Introduced: "0", LastAffected: "4.2.0"}, Match},
		{"one release past last affected is not", "4.2.1",
			model.VersionRange{Type: "SEMVER", Introduced: "0", LastAffected: "4.2.0"}, NoMatch},
		{"the introduced version itself is affected", "2.0.0",
			model.VersionRange{Type: "SEMVER", Introduced: "2.0.0", Fixed: "3.0.0"}, Match},
		{"one release below introduced is not", "1.9.9",
			model.VersionRange{Type: "SEMVER", Introduced: "2.0.0", Fixed: "3.0.0"}, NoMatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ev := Evaluate(npmLib(tc.version), npmRow(tc.rng))
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (reason: %s)", got, tc.want, ev.Reason)
			}
			// A verdict that does not name its numbers cannot be audited.
			if !strings.Contains(ev.Reason, tc.version) {
				t.Errorf("reason %q does not name the installed version", ev.Reason)
			}
			named := false
			for _, bound := range []string{tc.rng.Introduced, tc.rng.Fixed, tc.rng.LastAffected} {
				if bound != "" && bound != "0" && strings.Contains(ev.Reason, bound) {
					named = true
				}
			}
			if !named {
				t.Errorf("reason %q does not name the bound that decided it", ev.Reason)
			}
		})
	}
}

func TestExclusiveLowerBoundMarkerExcludesTheBoundItself(t *testing.T) {
	// internal/parse/nvd.go encodes versionStartExcluding as a string suffix.
	row := Affected{
		VulnID: "CVE-2026-0002", Vendor: "acme", Product: "libfoo", Source: "nvd",
		Ranges: []model.VersionRange{{Type: "CPE", Introduced: "1.2.3 (exclusive)", LastAffected: "1.4.0"}},
	}
	comp := Component{Name: "libfoo", Vendor: "acme", Version: "1.2.3"}
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("the excluded lower bound itself: got %v, want NoMatch (%s)", got, ev.Reason)
	}
	comp.Version = "1.2.4"
	if got, ev := Evaluate(comp, row); got != Match {
		t.Fatalf("one release above an exclusive lower bound: got %v, want Match (%s)", got, ev.Reason)
	}
}

func TestUnionOfWindowsTakesAnyPositiveAndNeedsEveryWindowClearForANegative(t *testing.T) {
	git := model.VersionRange{Type: "GIT", Introduced: "0", Fixed: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"}
	first := model.VersionRange{Type: "SEMVER", Introduced: "1.0.0", Fixed: "1.2.0"}
	second := model.VersionRange{Type: "SEMVER", Introduced: "2.0.0", Fixed: "2.4.0"}

	tests := []struct {
		name    string
		version string
		ranges  []model.VersionRange
		want    Result
	}{
		{"inside the second of two windows", "2.1.0", []model.VersionRange{first, second}, Match},
		{"inside the first of two windows", "1.1.0", []model.VersionRange{first, second}, Match},
		{"between two windows", "1.5.0", []model.VersionRange{first, second}, NoMatch},
		{"a positive window outvotes an undecidable sibling", "1.1.0", []model.VersionRange{git, first}, Match},
		{"an undecidable sibling denies a clean bill of health", "9.9.9", []model.VersionRange{git, first}, Undecidable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ev := Evaluate(npmLib(tc.version), npmRow(tc.ranges...)); got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
		})
	}
}

func TestZeroAndUnspecifiedAreUnboundedLowerBounds(t *testing.T) {
	// Both rows are verbatim from the corpus.
	xfree86 := Affected{
		VulnID: "CVE-2002-0164", Vendor: "xfree86", Product: "xfree86", Source: "cvelist",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0", LastAffected: "4.2.0"}},
	}
	obs := Affected{
		VulnID: "CVE-2021-0001", Vendor: "openSUSE", Product: "Open Build Service", Source: "cvelist",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "unspecified", Fixed: "2.4.4"}},
	}
	tests := []struct {
		name string
		comp Component
		row  Affected
		want Result
	}{
		{"introduced 0 covers an ancient version", Component{Name: "xfree86", Vendor: "xfree86", Version: "3.3.6"}, xfree86, Match},
		{"outside last affected with no default is unknown", Component{Name: "xfree86", Vendor: "xfree86", Version: "4.3.0"}, xfree86, Undecidable},
		{"introduced unspecified covers everything below the fix", Component{Name: "Open Build Service", Vendor: "openSUSE", Version: "2.4.0"}, obs, Match},
		{"outside the stated range with no default is unknown", Component{Name: "Open Build Service", Vendor: "openSUSE", Version: "2.4.4"}, obs, Undecidable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ev := Evaluate(tc.comp, tc.row); got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
		})
	}
}

func TestUnreadableUpperBoundIsUndecidableRatherThanUnbounded(t *testing.T) {
	row := npmRow(model.VersionRange{Type: "SEMVER", Introduced: "1.0.0", Fixed: "unspecified"})
	got, ev := Evaluate(npmLib("1.5.0"), row)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "sentinel_upper_bound") {
		t.Fatalf("review reason = %q, want sentinel_upper_bound", ev.Reason)
	}
}

func TestStatementWithNeitherRangesNorVersionsCannotDecideAnything(t *testing.T) {
	// The whole CSAF slice looks like this: the version is baked into a product
	// name string that internal/collect never split.
	csaf := Affected{
		VulnID: "CVE-2026-0003", Vendor: "Siemens", Product: "SIMATIC S7-1200 CPU family V4.5",
		Source: "csaf", Status: "known_affected",
	}
	comp := Component{Name: "SIMATIC S7-1200 CPU family V4.5", Vendor: "Siemens", Version: "4.5.1"}

	got, ev := Evaluate(comp, csaf)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "no_version_data") {
		t.Fatalf("review reason = %q, want no_version_data", ev.Reason)
	}
	if ev.Confidence != "" {
		t.Fatalf("confidence = %q, want none: an undecidable result is not a graded finding", ev.Confidence)
	}

	// A product-level negative cannot be shown to cover this particular build
	// either, so it goes to review rather than quietly clearing the component.
	csaf.Status = "not_affected"
	if got, ev := Evaluate(comp, csaf); got != Undecidable {
		t.Fatalf("negative product-level row = %v, want Undecidable (%s)", got, ev.Reason)
	}
}

func TestNegativeStatusSuppressesAndUnderInvestigationVoids(t *testing.T) {
	window := model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}
	tests := []struct {
		name   string
		status string
		want   Result
	}{
		{"affected reports the finding", "affected", Match},
		{"empty status is an affectedness claim by construction", "", Match},
		{"not_affected inverts it", "not_affected", Suppressed},
		{"unaffected is the same assertion spelled differently", "unaffected", Suppressed},
		{"fixed asserts this build carries the fix", "fixed", Suppressed},
		{"under_investigation neither affirms nor denies", "under_investigation", Undecidable},
		{"an unrecognised status is never read as affected", "probably-ok-honestly", Undecidable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := npmRow(window)
			row.Status = tc.status
			got, ev := Evaluate(npmLib("2.14.0"), row)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
			if tc.want == Suppressed && !strings.Contains(ev.Reason, "suppressed") {
				t.Errorf("a suppression must say so and carry the asserting statement: %q", ev.Reason)
			}
		})
	}
}

func TestCommitHashBoundsAreNeverComparedToAVersion(t *testing.T) {
	hash := "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	row := Affected{
		VulnID: "CVE-2026-0004", Product: "linux", Ecosystem: "Linux", Source: "osv",
		Ranges: []model.VersionRange{{Type: "GIT", Introduced: "0", Fixed: hash}},
	}
	comp := Component{Name: "linux", Version: "6.1.55", Ecosystem: "Linux"}
	got, ev := Evaluate(comp, row)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "opaque_scheme:GIT") {
		t.Fatalf("review reason = %q, want opaque_scheme:GIT", ev.Reason)
	}

	// The same guard has to hold when an ecosystem is known, because the
	// ecosystem override would otherwise hand the hash to dpkg ordering, which
	// compares any two strings and returns a confident answer.
	debRow := Affected{
		VulnID: "CVE-2026-0004", Product: "linux", Ecosystem: "Debian:12",
		PURL: "pkg:deb/debian/linux", Source: "osv",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0", Fixed: hash}},
	}
	debComp := Component{Name: "linux", Version: "6.1.55-1", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/linux@6.1.55-1"}
	if got, ev := Evaluate(debComp, debRow); got != Undecidable {
		t.Fatalf("hash bound under a known ecosystem = %v, want Undecidable (%s)", got, ev.Reason)
	}
}

func TestFixCommitRangesAreDiscardedRatherThanLeftUndecidable(t *testing.T) {
	// A row whose sibling window can decide must not be pinned to review by the
	// presence of a commit pointer.
	row := npmRow(
		model.VersionRange{Type: "ORIGINAL_COMMIT_FOR_FIX", Fixed: "ff0011223344556677889900aabbccddeeff0011"},
		model.VersionRange{Type: "SEMVER", Introduced: "1.0.0", Fixed: "1.2.0"},
	)
	if got, ev := Evaluate(npmLib("1.1.0"), row); got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if got, ev := Evaluate(npmLib("1.3.0"), row); got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}

	// On its own it carries no version information at all.
	only := npmRow(model.VersionRange{Type: "ORIGINAL_COMMIT_FOR_FIX", Fixed: "ff0011223344556677889900aabbccddeeff0011"})
	got, ev := Evaluate(npmLib("1.1.0"), only)
	if got != Undecidable || !strings.HasPrefix(ev.Reason, "no_version_data") {
		t.Fatalf("Evaluate = %v (%s), want Undecidable/no_version_data", got, ev.Reason)
	}
}

func TestGenericRefusesTheBoundaryTieItCannotDecide(t *testing.T) {
	// The mainstream schemes disagree at exactly this point: SemVer places
	// 2.15.0-1ubuntu2 below 2.15.0, dpkg places it above. A CUSTOM range has
	// not said which applies, so neither answer may be reported.
	row := Affected{
		VulnID: "CVE-2026-0005", Vendor: "acme", Product: "libfoo", Source: "cvelist",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0", Fixed: "2.15.0"}},
	}
	comp := Component{Name: "libfoo", Vendor: "acme", Version: "2.15.0-1ubuntu2"}
	got, ev := Evaluate(comp, row)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "generic_refused_tie") {
		t.Fatalf("review reason = %q, want generic_refused_tie", ev.Reason)
	}

	// Away from the boundary every scheme agrees, so GENERIC decides.
	comp.Version = "2.14.0-1ubuntu2"
	if got, ev := Evaluate(comp, row); got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
}

func TestAnOperandThatIsNotAVersionIsADifferentReviewQueueFromATie(t *testing.T) {
	row := Affected{
		VulnID: "CVE-2026-0013", Vendor: "acme", Product: "libfoo", Source: "cvelist",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0", Fixed: "trunk"}},
	}
	comp := Component{Name: "libfoo", Vendor: "acme", Version: "1.0.0"}
	got, ev := Evaluate(comp, row)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "unparseable_version:bound") {
		t.Fatalf("review reason = %q, want unparseable_version:bound", ev.Reason)
	}
}

func TestAnExplicitlyListedVersionOutweighsAnAllVersionsToken(t *testing.T) {
	row := Affected{
		VulnID: "CVE-2026-0014", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
		Versions: []string{"all versions", "2.4.4"}, Source: "cvelist",
	}
	if got, ev := Evaluate(npmLib("2.4.4"), row); got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if got, ev := Evaluate(npmLib("9.9.9"), row); got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
}

func TestKnownEcosystemDecidesWhatCustomLeftUndeclared(t *testing.T) {
	// Same operands as the refused tie above, but both sides name Debian, so
	// dpkg ordering applies and places the Ubuntu revision above the bound.
	row := Affected{
		VulnID: "CVE-2026-0005", Product: "libfoo", Ecosystem: "Debian:12",
		PURL: "pkg:deb/debian/libfoo", Source: "osv",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0", Fixed: "2.15.0"}},
	}
	comp := Component{
		Name: "libfoo", Version: "2.15.0-1ubuntu2", Ecosystem: "Debian:12",
		PURL: "pkg:deb/debian/libfoo@2.15.0-1ubuntu2?arch=amd64&distro=debian-12",
	}
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}
}

func TestDiscreteVersionsProveAffectedAndOnlyProveSafeWhenTheListIsClosed(t *testing.T) {
	tests := []struct {
		name    string
		version string
		row     Affected
		want    Result
	}{
		{"a listed version is affected", "2.4.4", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"2.4.0", "2.4.2", "2.4.4"}, Source: "cvelist"}, Match},
		{"equality is scheme-normalised, not byte-wise", "1.0", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"1.0.0"}, Source: "cvelist"}, Match},
		{"a CNA enumeration with an unaffected default is closed", "2.5.0", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"2.4.0"}, Source: "cvelist", DefaultState: "unaffected"}, NoMatch},
		{"an open enumeration proves nothing by absence", "2.5.0", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"2.4.0"}, Source: "osv"}, Undecidable},
		{"sentinel entries are discarded, not compared", "2.4.4", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"n/a", "unspecified", "2.4.4"}, Source: "cvelist"}, Match},
		{"a list of nothing but all versions is unfalsifiable", "2.4.4", Affected{
			VulnID: "CVE-2026-0006", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
			Versions: []string{"all versions"}, Source: "cvelist"}, Undecidable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ev := Evaluate(npmLib(tc.version), tc.row); got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
		})
	}
}

func TestAlpineFixedZeroMeansTheBuildWasNeverAffected(t *testing.T) {
	// Alpine secdb publishes fixed-in versions only and writes "0" for "not
	// affected". Read as a window that is [0, 0), which is empty, and the
	// silent false negative is indistinguishable from a correct suppression.
	row := Affected{
		VulnID: "CVE-2026-0007", Product: "openssl", Ecosystem: "Alpine:v3.19",
		PURL: "pkg:apk/alpine/openssl", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Fixed: "0"}},
	}
	comp := Component{
		Name: "openssl", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19",
		PURL: "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19",
	}
	got, ev := Evaluate(comp, row)
	if got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "alpine_fixed_zero") {
		t.Errorf("reason %q does not record why the empty window was not read literally", ev.Reason)
	}
}

func TestVersionlessComponentCanNeverProduceAFinding(t *testing.T) {
	comp := Component{Name: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked"}
	got, ev := Evaluate(comp, npmRow(model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}))
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
	}
	if !strings.HasPrefix(ev.Reason, "no_component_version") {
		t.Fatalf("review reason = %q, want no_component_version", ev.Reason)
	}
}

func TestEcosystemConflictIsARejectionNotADemotion(t *testing.T) {
	tests := []struct {
		name string
		comp Component
		row  Affected
		want Result
	}{
		{"a hardened-image rebuild is not a Debian package",
			Component{Name: "openssl", Version: "3.1.4-r5", Ecosystem: "Chainguard"},
			Affected{Product: "openssl", Ecosystem: "Debian:12", Source: "osv",
				Ranges: []model.VersionRange{{Introduced: "0"}}}, NoMatch},
		{"the same name in two language ecosystems is two packages",
			Component{Name: "marked", Version: "1.0.0", PURL: "pkg:npm/marked@1.0.0"},
			Affected{Product: "marked", Ecosystem: "PyPI", PURL: "pkg:pypi/marked", Source: "osv",
				Ranges: []model.VersionRange{{Introduced: "0"}}}, NoMatch},
		{"a Debian 11 statement is not about a Debian 12 host",
			Component{Name: "openssl", Version: "3.0.11-1", Ecosystem: "Debian:12"},
			Affected{Product: "openssl", Ecosystem: "Debian:11", Source: "osv",
				Ranges: []model.VersionRange{{Introduced: "0"}}}, NoMatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ev := Evaluate(tc.comp, tc.row)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
			if !strings.Contains(ev.Reason, "conflict") {
				t.Errorf("reason %q does not name the conflict", ev.Reason)
			}
		})
	}
}

func TestStrongChannelMismatchIsNotRescuedByAWeakerOne(t *testing.T) {
	// Both parties named the package precisely and the names differ. That is
	// positive evidence of non-applicability, so the shared product name must
	// not put them back together.
	row := Affected{
		VulnID: "CVE-2026-0008", Vendor: "acme", Product: "libfoo", Source: "nvd",
		CPEs:   []string{"cpe:2.3:a:acme:libbar:*:*:*:*:*:*:*:*"},
		Ranges: []model.VersionRange{{Type: "CPE", Introduced: "0", Fixed: "9.9.9"}},
	}
	comp := Component{
		Name: "libfoo", Vendor: "acme", Version: "1.0.0",
		CPE: "cpe:2.3:a:acme:libfoo:1.0.0:*:*:*:*:*:*:*",
	}
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}
}

func TestWildcardProductInAStoredCPEIsNotIdentity(t *testing.T) {
	// cpe:2.3:a:microsoft:*:... is "every Microsoft application". Reading it as
	// identity flags every Microsoft product for every Microsoft CVE, so the
	// channel is indeterminate and a weaker channel decides instead.
	row := Affected{
		VulnID: "CVE-2026-0009", Vendor: "microsoft", Product: "excel", Source: "nvd",
		CPEs:   []string{"cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*"},
		Ranges: []model.VersionRange{{Type: "CPE", Introduced: "0", Fixed: "9.9.9"}},
	}
	comp := Component{
		Name: "word", Vendor: "microsoft", Version: "2019",
		CPE: "cpe:2.3:a:microsoft:word:2019:*:*:*:*:*:*:*",
	}
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}
}

func TestPURLIdentityIgnoresBuildQualifiersAndKeepsNamespace(t *testing.T) {
	row := Affected{
		VulnID: "CVE-2026-0010", Product: "openssl", Ecosystem: "Debian:12",
		PURL: "pkg:deb/debian/openssl", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.0.11-1~deb12u2"}},
	}
	tests := []struct {
		name string
		comp Component
		want Result
	}{
		{"arch, distro and epoch qualifiers do not break equality", Component{
			Name: "openssl", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12",
			PURL: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12"}, Match},
		{"an unknown qualifier does not break equality", Component{
			Name: "openssl", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12",
			PURL: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?upstream_hint=yes"}, Match},
		{"a different namespace is a different package", Component{
			Name: "openssl", Version: "3.0.11-1~deb12u1", Ecosystem: "Ubuntu:22.04",
			PURL: "pkg:deb/ubuntu/openssl@3.0.11-1~deb12u1"}, NoMatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ev := Evaluate(tc.comp, row); got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
		})
	}
}

func TestSourcePackagePURLInOriginMatchesDistroAdvisories(t *testing.T) {
	// Debian and Ubuntu security data is keyed by source package. Testing only
	// the binary name misses every openssl advisory for an installed libssl3.
	row := Affected{
		VulnID: "CVE-2026-0011", Product: "openssl", Ecosystem: "Debian:12",
		PURL: "pkg:deb/debian/openssl", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.0.11-1~deb12u2"}},
	}
	comp := Component{
		Name: "libssl3", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12",
		PURL:   "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12",
		Origin: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=source&distro=debian-12",
	}
	if got, ev := Evaluate(comp, row); got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
}

func TestConfidenceIsTheFloorOfIdentityStrengthAndVersionStrength(t *testing.T) {
	semver := model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}
	custom := model.VersionRange{Type: "CUSTOM", Introduced: "0", Fixed: "2.15.0"}

	tests := []struct {
		name string
		comp Component
		row  Affected
		want Confidence
	}{
		{"exact purl and an ecosystem ordering", npmLib("2.14.0"), npmRow(semver), Confirmed},
		{"exact cpe identity but an ordering nobody declared",
			Component{Name: "libfoo", Vendor: "acme", Version: "1.5.0", CPE: "cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:*:*:*"},
			Affected{Vendor: "acme", Product: "libfoo", Source: "nvd",
				CPEs:   []string{"cpe:2.3:a:acme:libfoo:*:*:*:*:*:*:*:*"},
				Ranges: []model.VersionRange{{Type: "CPE", Introduced: "1.0.0", Fixed: "2.0.0"}}},
			Probable},
		{"an ecosystem that declares an ordering overrides a CUSTOM type",
			npmLib("2.14.0"), npmRow(custom), Confirmed},
		{"ecosystem and name on a lossless ecosystem is a purl by another spelling",
			Component{Name: "marked", Version: "2.14.0", Ecosystem: "npm"},
			Affected{Product: "marked", Ecosystem: "npm", Source: "osv", Ranges: []model.VersionRange{semver}},
			Confirmed},
		{"ecosystem and name where the pair is not a purl",
			Component{Name: "marked", Version: "2.14.0", Ecosystem: "Bitnami"},
			Affected{Product: "marked", Ecosystem: "Bitnami", Source: "osv", Ranges: []model.VersionRange{semver}},
			Probable},
		{"vendor and product are CNA free text",
			Component{Name: "libfoo", Vendor: "Acme Inc.", Version: "2.14.0"},
			Affected{Vendor: "acme", Product: "libfoo", Source: "cvelist", Ranges: []model.VersionRange{semver}},
			Possible},
		{"a bare product name is capped however good the comparison was",
			Component{Name: "libfoo", Version: "2.14.0"},
			Affected{Product: "libfoo", Source: "cvelist", Ranges: []model.VersionRange{semver}},
			Possible},
		{"a statement that claims every version is capped",
			npmLib("2.14.0"),
			npmRow(model.VersionRange{Type: "SEMVER", Introduced: "0"}),
			Possible},
		{"an unknown distro release costs a grade and caps the finding",
			Component{Name: "openssl", Version: "3.0.11-1", Ecosystem: "Debian"},
			Affected{Product: "openssl", Ecosystem: "Debian:12", Source: "osv",
				Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.0.11-2"}}},
			Possible},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ev := Evaluate(tc.comp, tc.row)
			if got != Match {
				t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
			}
			if ev.Confidence != tc.want {
				t.Fatalf("confidence = %q, want %q (%s)", ev.Confidence, tc.want, ev.Reason)
			}
		})
	}
}

func TestAnOrderingReachedByConventionCostsTheFindingALevel(t *testing.T) {
	// A gem-shaped prerelease (1.0.0.rc1) is not a SemVer string; the scheme
	// rewrites it and says so. The finding stands, because the producer named
	// the ecosystem, but it is not the same claim as a comparison the scheme
	// decided by its own rules.
	row := Affected{
		VulnID: "CVE-2026-0015", Product: "rails", Ecosystem: "RubyGems", Source: "osv",
		Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "1.0.0"}},
	}
	comp := Component{Name: "rails", Version: "1.0.0.rc1", Ecosystem: "RubyGems"}
	got, ev := Evaluate(comp, row)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if ev.Confidence != Probable {
		t.Fatalf("confidence = %q, want probable (%s)", ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "demoted") {
		t.Errorf("reason %q does not record why the finding was demoted", ev.Reason)
	}
}

func TestUnprovenCPEConstraintCapsTheFinding(t *testing.T) {
	// The row asserts vulnerability only when libfoo runs under WordPress. An
	// inventory that lists libfoo has not proven that, so the honest output is
	// an actionable question rather than a confirmed finding.
	row := Affected{
		VulnID: "CVE-2026-0012", Vendor: "acme", Product: "libfoo", Source: "nvd",
		CPEs:   []string{"cpe:2.3:a:acme:libfoo:*:*:*:*:*:wordpress:*:*"},
		Ranges: []model.VersionRange{{Type: "CPE", Introduced: "1.0.0", Fixed: "2.0.0"}},
	}
	comp := Component{
		Name: "libfoo", Vendor: "acme", Version: "1.5.0",
		CPE: "cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:*:*:*",
	}
	got, ev := Evaluate(comp, row)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if ev.Confidence != Possible {
		t.Fatalf("confidence = %q, want possible (%s)", ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "target_sw=wordpress") {
		t.Errorf("reason %q does not name the unproven constraint", ev.Reason)
	}
}

func TestMatchedOnNamesTheChannelThatDecided(t *testing.T) {
	tests := []struct {
		name string
		comp Component
		row  Affected
		want string
	}{
		{"purl", npmLib("2.14.0"), npmRow(model.VersionRange{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}), "purl"},
		{"cpe", Component{Name: "libfoo", Vendor: "acme", Version: "1.5.0", CPE: "cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:*:*:*"},
			Affected{Vendor: "acme", Product: "libfoo", Source: "nvd",
				CPEs:   []string{"cpe:2.3:a:acme:libfoo:*:*:*:*:*:*:*:*"},
				Ranges: []model.VersionRange{{Type: "CPE", Introduced: "1.0.0", Fixed: "2.0.0"}}}, "cpe"},
		{"ecosystem_name", Component{Name: "marked", Version: "2.14.0", Ecosystem: "npm"},
			Affected{Product: "marked", Ecosystem: "npm", Source: "osv",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}}}, "ecosystem_name"},
		{"vendor_product", Component{Name: "libfoo", Vendor: "acme", Version: "1.0.0"},
			Affected{Vendor: "acme", Product: "libfoo", Source: "cvelist",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.0.0"}}}, "vendor_product"},
		{"name", Component{Name: "libfoo", Version: "1.0.0"},
			Affected{Product: "libfoo", Source: "cvelist",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.0.0"}}}, "name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ev := Evaluate(tc.comp, tc.row)
			if got != Match {
				t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
			}
			if ev.MatchedOn != tc.want {
				t.Fatalf("MatchedOn = %q, want %q", ev.MatchedOn, tc.want)
			}
		})
	}
}

func TestUnprovenConstraintsStayWithTheConfigurationThatSuppliedTheVersion(t *testing.T) {
	// The ordinary NVD row shape: one ANY-version CPE whose bounds live in
	// Ranges, plus version-literal CPEs for the configurations that carry a
	// condition. The component is outside the range, and the only configuration
	// naming its version is the one that requires WordPress. Grading the row by
	// the unconstrained sibling's constraint set (there is none) reports a
	// conditional match as an unconditional one, and never says the word.
	row := Affected{
		VulnID: "CVE-2026-0016", Vendor: "acme", Product: "libfoo", Source: "nvd",
		CPEs: []string{
			"cpe:2.3:a:acme:libfoo:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:wordpress:*:*",
		},
		Ranges: []model.VersionRange{{Type: "CPE", Introduced: "2.0.0", Fixed: "3.0.0"}},
	}
	comp := Component{
		Name: "libfoo", Vendor: "acme", Version: "1.5.0",
		CPE: "cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:*:*:*",
	}
	got, ev := Evaluate(comp, row)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if ev.Confidence != Possible {
		t.Fatalf("confidence = %q, want possible (%s)", ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "target_sw=wordpress") {
		t.Errorf("reason %q never names the condition the matching configuration attaches", ev.Reason)
	}

	// The same row without the constrained configuration is unconditional, so
	// nothing may be capped: a caveat that fires when it should not is as
	// damaging to the tiers as one that does not fire when it should.
	plain := row
	plain.CPEs = []string{"cpe:2.3:a:acme:libfoo:*:*:*:*:*:*:*:*", "cpe:2.3:a:acme:libfoo:1.5.0:*:*:*:*:*:*:*"}
	if _, ev := Evaluate(comp, plain); strings.Contains(ev.Reason, "capped at possible") {
		t.Errorf("an unconditional configuration was capped anyway: %s", ev.Reason)
	}
}

func TestEpochIsElidedWhenOnlyOneSideStatesOne(t *testing.T) {
	// internal/inventory reads an epoch-bearing EVR off the rpm database while
	// advisory bounds routinely omit the epoch. Applying rpm's "absent = 0"
	// puts 1:3.0.7-1 above every bound written 3.0.7-2, which reports every
	// epoch-bearing package on every RHEL host as already patched.
	row := Affected{
		VulnID: "CVE-2026-0017", Product: "openssl", Ecosystem: "Red Hat:rhel_9",
		PURL: "pkg:rpm/redhat/openssl", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.0.7-2.el9"}},
	}
	comp := Component{
		Name: "openssl", Ecosystem: "Red Hat:rhel_9", Version: "1:3.0.7-1.el9",
		PURL: "pkg:rpm/redhat/openssl@3.0.7-1.el9?arch=x86_64&epoch=1&distro=rhel-9",
	}
	got, ev := Evaluate(comp, row)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "epoch_elided") {
		t.Errorf("reason %q does not record that the epoch was dropped", ev.Reason)
	}
	// The dropped epoch is exactly what could have moved the version across the
	// bound, so the answer stands one level lower than a clean comparison.
	if ev.Confidence != Probable {
		t.Errorf("confidence = %q, want probable: an elided epoch is a demotion (%s)", ev.Confidence, ev.Reason)
	}

	// Past the fix the elision must not manufacture a finding either.
	comp.Version = "1:3.0.7-3.el9"
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("a patched build = %v, want NoMatch (%s)", got, ev.Reason)
	}

	// Both sides stating an epoch is not an asymmetry, so rpm's own rules apply
	// unchanged and nothing is demoted.
	both := row
	both.Ranges = []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "1:3.0.7-2.el9"}}
	comp.Version = "1:3.0.7-1.el9"
	got, ev = Evaluate(comp, both)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if strings.Contains(ev.Reason, "epoch_elided") {
		t.Errorf("two stated epochs were compared as if one were missing: %s", ev.Reason)
	}
	if ev.Confidence != Confirmed {
		t.Errorf("confidence = %q, want confirmed (%s)", ev.Confidence, ev.Reason)
	}
}

func TestEcosystemOrderingBeatsTheDeclaredRangeType(t *testing.T) {
	// dpkg orders 2.15.0-1 ABOVE 2.15.0 and SemVer orders it below. Honouring
	// the declared type on a row where both sides named Debian reports a
	// patched host as a confirmed vulnerability, which is the highest-trust
	// tier the scanner has.
	tests := []struct {
		name    string
		comp    Component
		row     Affected
		want    Result
		wantSch string
	}{
		{"a declared SEMVER does not reorder Debian revisions",
			Component{Name: "libfoo", Version: "2.15.0-1", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo@2.15.0-1"},
			Affected{Product: "libfoo", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo", Source: "osv",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}}},
			NoMatch, "DEBIAN"},
		{"a declared SEMVER does not reorder an rpm release",
			Component{Name: "openssl", Version: "3.0.7-2.el9", Ecosystem: "Red Hat:rhel_9", PURL: "pkg:rpm/redhat/openssl@3.0.7-2.el9"},
			Affected{Product: "openssl", Ecosystem: "Red Hat:rhel_9", PURL: "pkg:rpm/redhat/openssl", Source: "osv",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "3.0.7"}}},
			NoMatch, "RPM"},
		{"below the bound the ecosystem ordering still finds it",
			Component{Name: "libfoo", Version: "2.14.0-1", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo@2.14.0-1"},
			Affected{Product: "libfoo", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo", Source: "osv",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}}},
			Match, "DEBIAN"},
		{"an ecosystem with no ordering of its own leaves the declared type alone",
			Component{Name: "marked", Version: "2.14.0", Ecosystem: "Bitnami"},
			Affected{Product: "marked", Ecosystem: "Bitnami", Source: "osv",
				Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}}},
			Match, "SEMVER"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ev := Evaluate(tc.comp, tc.row)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
			if string(ev.Scheme) != tc.wantSch {
				t.Fatalf("scheme = %q, want %q (%s)", ev.Scheme, tc.wantSch, ev.Reason)
			}
		})
	}

	// A reviewer holding only the report has to be able to see that the type
	// the record declared was not the one that decided the comparison.
	overridden := Affected{Product: "libfoo", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo", Source: "osv",
		Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "0", Fixed: "2.15.0"}}}
	_, ev := Evaluate(Component{Name: "libfoo", Version: "2.14.0-1", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/libfoo@2.14.0-1"}, overridden)
	if !strings.Contains(ev.Reason, "scheme_source:ecosystem_override:SEMVER") {
		t.Errorf("reason %q does not record which type was overridden", ev.Reason)
	}
}

func TestAlpineFixedZeroClearsItsOwnWindowAndNotTheRow(t *testing.T) {
	// A negative window may not retract a positive one. The union rule runs one
	// way only: any positive is a positive, and a negative needs every window
	// to be provably clear.
	row := Affected{
		VulnID: "CVE-2026-0018", Product: "openssl", Ecosystem: "Alpine:v3.19",
		PURL: "pkg:apk/alpine/openssl", Source: "osv",
		Ranges: []model.VersionRange{
			{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.1.4-r6"},
			{Type: "ECOSYSTEM", Fixed: "0"},
		},
	}
	comp := Component{
		Name: "openssl", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19",
		PURL: "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19",
	}
	if got, ev := Evaluate(comp, row); got != Match {
		t.Fatalf("Evaluate = %v, want Match: the first window proves it (%s)", got, ev.Reason)
	}
	// Past the sibling window's fix, every window is clear and the row is too.
	comp.Version = "3.1.4-r7"
	if got, ev := Evaluate(comp, row); got != NoMatch {
		t.Fatalf("Evaluate = %v, want NoMatch (%s)", got, ev.Reason)
	}
}

func TestCPEVersionListsProveSafetyOnlyWhereTheSourceEnumerates(t *testing.T) {
	// NVD's configuration list is an enumeration of the builds an analyst
	// matched, so absence from it is a statement. A vendor advisory naming one
	// firmware build is not, and reading it as exhaustive asserts that an
	// unmentioned build is safe — on a plant controller, from a row that never
	// mentioned it.
	tests := []struct {
		name   string
		source string
		want   Result
	}{
		{"an NVD configuration list is exhaustive", "nvd", NoMatch},
		{"a CVE-5 record without a default does not establish safety", "cvelist", Undecidable},
		{"a vendor CSAF advisory names what it tested", "csaf", Undecidable},
		{"an OSV export of someone else's data proves nothing by absence", "osv", Undecidable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := Affected{
				VulnID: "CVE-2026-0019", Vendor: "siemens", Product: "simatic_s7-1200",
				Source: tc.source, Status: "known_affected",
				CPEs: []string{"cpe:2.3:o:siemens:simatic_s7-1200:4.5:*:*:*:*:*:*:*"},
			}
			comp := Component{
				Name: "simatic_s7-1200", Vendor: "siemens", Version: "4.5.1",
				CPE: "cpe:2.3:o:siemens:simatic_s7-1200:4.5.1:*:*:*:*:*:*:*",
			}
			got, ev := Evaluate(comp, row)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v (%s)", got, tc.want, ev.Reason)
			}
		})
	}
}

func TestAPlaceholderWhereAVersionBelongsIsNotAVersion(t *testing.T) {
	// "unknown" is what an SBOM producer writes when it does not know, and the
	// version-less rule exists so that an inventory which does not know cannot
	// generate findings. Testing only for the empty string keeps the letter of
	// the rule and none of its purpose.
	row := Affected{
		VulnID: "CVE-2026-0020", Vendor: "acme", Product: "libfoo", Source: "cvelist",
		Ranges: []model.VersionRange{{Type: "CUSTOM", Introduced: "0"}},
	}
	tests := []struct {
		version string
		review  string
	}{
		{"", "no_component_version"},
		{"unknown", "no_component_version"},
		{"n/a", "no_component_version"},
		{"NOASSERTION", "no_component_version"},
		{"NONE", "no_component_version"},
		{"*", "no_component_version"},
		{"-", "no_component_version"},
		// Not placeholders, but not versions either: an all-versions claim can
		// only be asserted against something a scheme can read.
		{"trunk", "unparseable_version:component"},
		{"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "opaque_scheme:CUSTOM"},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got, ev := Evaluate(Component{Name: "libfoo", Vendor: "acme", Version: tc.version}, row)
			if got != Undecidable {
				t.Fatalf("Evaluate = %v, want Undecidable (%s)", got, ev.Reason)
			}
			if !strings.HasPrefix(ev.Reason, tc.review) {
				t.Fatalf("review reason = %q, want %s", ev.Reason, tc.review)
			}
		})
	}

	// A package genuinely versioned 0 exists, and "0" is only a sentinel in a
	// bound. Refusing it here would drop real findings to guard a spelling that
	// does not occur on this side.
	if got, ev := Evaluate(Component{Name: "libfoo", Vendor: "acme", Version: "0"}, row); got != Match {
		t.Errorf("a component versioned 0 = %v, want Match (%s)", got, ev.Reason)
	}
}

func TestOneCommitHashInAVersionListDoesNotMakeTheWholeListLiteral(t *testing.T) {
	// The kernel CNA and others mix versionType git entries with real releases
	// in one versions[] array. Resolving the scheme from the whole list let the
	// one hash force byte-literal comparison on every entry, under which the
	// installed 1.0 was not the listed 1.0.0 and a closed CNA enumeration
	// reported the host safe.
	hash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	row := Affected{
		VulnID: "CVE-2026-0021", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked",
		Versions: []string{"1.0.0", "2.0.0"}, Source: "cvelist", DefaultState: "unaffected",
	}
	withHash := row
	withHash.Versions = []string{"1.0.0", "2.0.0", hash}

	want, wantEv := Evaluate(npmLib("1.0"), row)
	if want != Match {
		t.Fatalf("the list without the hash = %v, want Match (%s)", want, wantEv.Reason)
	}
	got, ev := Evaluate(npmLib("1.0"), withHash)
	if got != Match {
		t.Fatalf("the same list with a hash in it = %v, want Match (%s)", got, ev.Reason)
	}
	if ev.Confidence != wantEv.Confidence {
		t.Errorf("confidence with the hash = %q, without it %q; the hash must not weaken the entries it sits beside", ev.Confidence, wantEv.Confidence)
	}

	// The enumeration stays closed, so absence still proves safety.
	if got, ev := Evaluate(npmLib("3.0"), withHash); got != NoMatch {
		t.Fatalf("an unlisted version = %v, want NoMatch (%s)", got, ev.Reason)
	}

	// And the hash itself is still only ever compared literally: a component
	// built from that commit is affected, at the literal grade and no higher.
	built := Component{Name: "marked", Version: hash, Ecosystem: "npm", PURL: "pkg:npm/marked@" + hash}
	got, ev = Evaluate(built, withHash)
	if got != Match || ev.Confidence != Possible {
		t.Fatalf("a component at the listed commit = %v/%q, want Match/possible (%s)", got, ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "commit hashes") {
		t.Errorf("reason %q does not say the match was against the commit list", ev.Reason)
	}
}

func TestARangeCarriedByACPEKeepsThatCPEsConstraints(t *testing.T) {
	// NVD states each window against one applicability criteria string, and
	// that CPE's target_sw is what the window is conditional on. Flattening the
	// windows lost the carrier: this row's "below 2.0 under WordPress" beside an
	// unconditional libfoo:3.1 reported a Drupal-hosted libfoo 1.5 affected
	// outright, on a bound that never applied to it.
	wordpress := "cpe:2.3:a:acme:libfoo:*:*:*:*:*:wordpress:*:*"
	row := Affected{
		VulnID: "CVE-2026-0022", Vendor: "acme", Product: "libfoo", Source: "nvd",
		CPEs:   []string{wordpress, "cpe:2.3:a:acme:libfoo:3.1:*:*:*:*:*:*:*"},
		Ranges: []model.VersionRange{{Type: "CPE", Fixed: "2.0", CPE: wordpress}},
	}

	drupal := Component{
		Name: "libfoo", Vendor: "acme", Version: "1.5",
		CPE: "cpe:2.3:a:acme:libfoo:1.5:*:*:*:*:drupal:*:*",
	}
	got, ev := Evaluate(drupal, row)
	if got != NoMatch {
		t.Fatalf("libfoo under Drupal = %v, want NoMatch: the only window that covers 1.5 is a WordPress window (%s)", got, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "target_sw=wordpress") {
		t.Errorf("reason %q does not name the condition that took the window out", ev.Reason)
	}

	// An inventory that has not said what libfoo runs under gets a question,
	// not an unconditional finding.
	unknownHost := Component{
		Name: "libfoo", Vendor: "acme", Version: "1.5",
		CPE: "cpe:2.3:a:acme:libfoo:1.5:*:*:*:*:*:*:*",
	}
	got, ev = Evaluate(unknownHost, row)
	if got != Match || ev.Confidence != Possible {
		t.Fatalf("libfoo under an unstated host = %v/%q, want Match/possible (%s)", got, ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "unproven target_sw=wordpress") {
		t.Errorf("reason %q does not carry the carrier's condition as unproven", ev.Reason)
	}

	// A window with no carrier is unconditional, as it always was.
	plain := row
	plain.Ranges = []model.VersionRange{{Type: "CPE", Fixed: "2.0"}}
	got, ev = Evaluate(unknownHost, plain)
	if got != Match || strings.Contains(ev.Reason, "capped at possible") {
		t.Fatalf("an uncarried window = %v (%s), want an uncapped Match", got, ev.Reason)
	}
}

func TestWildcardVersionInAStoredCPEIsGlobbedNotCompared(t *testing.T) {
	// cpe:2.3:a:acme:libfoo:2.*:... means every 2.x build. Handed to a
	// comparator as a version, "2.*" equalled nothing, and under the closed NVD
	// configuration list an installed 2.1 came out provably safe.
	row := Affected{
		VulnID: "CVE-2026-0023", Vendor: "acme", Product: "libfoo", Source: "nvd",
		CPEs: []string{"cpe:2.3:a:acme:libfoo:2.*:*:*:*:*:*:*:*"},
	}
	comp := func(v string) Component {
		return Component{Name: "libfoo", Vendor: "acme", Version: v, CPE: "cpe:2.3:a:acme:libfoo:" + v + ":*:*:*:*:*:*:*"}
	}
	got, ev := Evaluate(comp("2.1"), row)
	if got != Match {
		t.Fatalf("2.1 against 2.* = %v, want Match (%s)", got, ev.Reason)
	}
	if ev.Confidence != Possible || !strings.Contains(ev.Reason, "pattern") {
		t.Errorf("a glob hit must be graded as a pattern match and say so: %q/%q", ev.Confidence, ev.Reason)
	}
	if got, ev := Evaluate(comp("3.1"), row); got != NoMatch {
		t.Fatalf("3.1 against 2.* on a closed NVD list = %v, want NoMatch (%s)", got, ev.Reason)
	}
	open := row
	open.Source = "csaf"
	if got, ev := Evaluate(comp("3.1"), open); got != Undecidable {
		t.Fatalf("3.1 against 2.* on an open list = %v, want Undecidable (%s)", got, ev.Reason)
	}
}

func TestDefaultStatusAffectedMakesUnlistedVersionsAffected(t *testing.T) {
	// A CVE-5 record with defaultStatus affected lists its exceptions, which
	// cve5.go moves to their own not_affected row; what stays on this row is
	// the CNA's examples, and a version absent from them is affected too.
	row := Affected{
		VulnID: "CVE-2026-0024", Vendor: "acme", Product: "libfoo", Source: "cvelist",
		Versions: []string{"1.0"}, DefaultState: "affected",
	}
	comp := func(v string) Component { return Component{Name: "libfoo", Vendor: "acme", Version: v} }

	if got, ev := Evaluate(comp("1.0"), row); got != Match || ev.Confidence != Possible {
		t.Fatalf("a listed version = %v/%q, want Match/possible on a bare name (%s)", got, ev.Confidence, ev.Reason)
	}
	got, ev := Evaluate(comp("2.0"), row)
	if got != Match || ev.Confidence != Possible {
		t.Fatalf("an unlisted version under defaultStatus affected = %v/%q, want Match/possible (%s)", got, ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "affected by default") {
		t.Errorf("reason %q does not say the finding rests on the default", ev.Reason)
	}
	if !strings.Contains(ev.Reason, "capped at possible") {
		t.Errorf("reason %q does not record that nothing was compared", ev.Reason)
	}

	// With nothing listed at all the row used to be no_version_data; the
	// default is version data.
	bare := row
	bare.Versions = nil
	if got, ev := Evaluate(comp("2.0"), bare); got != Match {
		t.Fatalf("a default-affected row with no list = %v, want Match (%s)", got, ev.Reason)
	}

	// The default is a claim about versions, so it cannot be asserted against
	// something no scheme can read.
	if got, ev := Evaluate(comp("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"), bare); got != Undecidable {
		t.Fatalf("a commit-versioned component under a default = %v, want Undecidable (%s)", got, ev.Reason)
	}

	// Only an explicit unaffected default closes the enumeration.
	for _, state := range []string{"unaffected", "not_affected"} {
		closed := row
		closed.DefaultState = state
		if got, ev := Evaluate(comp("2.0"), closed); got != NoMatch {
			t.Errorf("DefaultState %q: an unlisted version = %v, want NoMatch (%s)", state, got, ev.Reason)
		}
	}

	// A negative row never claims a default, whatever the field says: its list
	// is the exceptions themselves.
	negative := row
	negative.Status = "unaffected"
	if got, ev := Evaluate(comp("2.0"), negative); got != NoMatch {
		t.Fatalf("an unlisted version on the exceptions row = %v, want NoMatch (%s)", got, ev.Reason)
	}

	// The CSAF collector copies the product status into DefaultState. That is
	// a statement about the builds it names, not a default for the rest.
	csaf := Affected{
		VulnID: "CVE-2026-0024", Vendor: "acme", Product: "libfoo", Source: "csaf",
		Versions: []string{"1.0"}, Status: "known_affected", DefaultState: "known_affected",
	}
	if got, ev := Evaluate(comp("2.0"), csaf); got != Undecidable {
		t.Fatalf("an unlisted version on a CSAF row = %v, want Undecidable (%s)", got, ev.Reason)
	}
}

func TestPURLDistroQualifierDoesNotConflictWithTheHostsOwnRelease(t *testing.T) {
	// os-release says 3.18.4, the purl qualifier carries that verbatim, and
	// the advisory is filed under Alpine:v3.18. The three name one release.
	comp := Component{
		Name: "openssl", Version: "3.1.4-r5",
		PURL: "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.18.4",
	}
	row := Affected{
		VulnID: "CVE-2026-0025", Product: "openssl", Ecosystem: "Alpine:v3.18",
		PURL: "pkg:apk/alpine/openssl", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.1.5-r0"}},
	}
	got, ev := Evaluate(comp, row)
	if got != Match {
		t.Fatalf("Evaluate = %v, want Match (%s)", got, ev.Reason)
	}
	if strings.Contains(ev.Reason, "distro_release") {
		t.Errorf("the release was not recognised as the same one: %s", ev.Reason)
	}
}

// A negative statement is weighed against the positives about the same
// vulnerability, so it has to be graded on the same scale they are. Ungraded,
// a CSAF row that matched a purl-identified component on nothing but a shared
// product name read as the vendor's word and silenced a confirmed finding.
func TestASuppressionIsGradedExactlyAsTheMatchItWouldHaveBeen(t *testing.T) {
	comp := npmLib("4.0.9")

	strong := npmRow()
	strong.Status = "known_not_affected"
	strong.Versions = []string{"4.0.9"}
	got, ev := Evaluate(comp, strong)
	if got != Suppressed || ev.Confidence != Confirmed {
		t.Fatalf("purl negative = %v at %q (%s), want Suppressed at confirmed", got, ev.Confidence, ev.Reason)
	}

	weak := Affected{VulnID: "CVE-2026-0001", Vendor: "acme", Product: "marked",
		Versions: []string{"4.0.9"}, Status: "known_not_affected", Source: "csaf"}
	got, ev = Evaluate(comp, weak)
	if got != Suppressed || ev.Confidence != Possible {
		t.Fatalf("bare-name negative = %v at %q (%s), want Suppressed at possible", got, ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "capped at possible") {
		t.Errorf("a weak suppression must say why it is weak, like a weak match does: %s", ev.Reason)
	}
}

func TestResultSpellsItsName(t *testing.T) {
	cases := map[Result]string{NoMatch: "NoMatch", Match: "Match", Undecidable: "Undecidable", Suppressed: "Suppressed", Result(9): "Result(9)"}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(r), got, want)
		}
	}
}
