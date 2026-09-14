package version

import "testing"

func TestCommitRangeTypesOutrankTheEcosystem(t *testing.T) {
	// A GIT range inside the Linux ecosystem is a range of commits. Letting the
	// ecosystem win here would compare kernel commit hashes as if they were
	// versions, across 44,252 stored ranges.
	cases := []struct{ rangeType, ecosystem string }{
		{"GIT", "Linux"},
		{"GIT", "npm"},
		{"ORIGINAL_COMMIT_FOR_FIX", ""},
		{"commit", "Debian"},
		{"SHA", "PyPI"},
		{"REVISION_ID", "Maven"},
	}
	for _, tc := range cases {
		if got := SchemeFor(tc.rangeType, tc.ecosystem); got != Opaque {
			t.Errorf("SchemeFor(%q, %q) = %s, want OPAQUE", tc.rangeType, tc.ecosystem, got)
		}
	}
}

func TestDeclaredRangeTypeWinsOverTheEcosystem(t *testing.T) {
	cases := []struct {
		rangeType, ecosystem string
		want                 Scheme
	}{
		{"SEMVER", "Debian", Semver},
		{"semver", "", Semver},
		{"RPM", "npm", RPM},
		{"DEB", "Alpine", Debian},
		{"PEP440", "", Python},
		{"GOLANG", "", Go},
		{"APK", "", Alpine},
		{"MAVEN", "", Maven},
	}
	for _, tc := range cases {
		if got := SchemeFor(tc.rangeType, tc.ecosystem); got != tc.want {
			t.Errorf("SchemeFor(%q, %q) = %s, want %s", tc.rangeType, tc.ecosystem, got, tc.want)
		}
	}
}

func TestTypesThatDeclareNoOrderingDeferToTheEcosystem(t *testing.T) {
	// CUSTOM is the plurality of the corpus and means the CNA declared nothing.
	// An unrecognised type is the same statement made by accident, so both fall
	// through to the ecosystem and then to GENERIC.
	cases := []struct {
		rangeType, ecosystem string
		want                 Scheme
	}{
		{"CUSTOM", "", Generic},
		{"", "", Generic},
		{"CUSTOM", "Debian:11", Debian},
		{"ECOSYSTEM", "Alpine:v3.16", Alpine},
		{"PATCH", "Red Hat:rhel_aus:8.2", RPM},
		{"DATE", "PyPI", Python},
		{"OTP", "Hex", Semver},
		{"OTHER", "Maven", Maven},
		{"SOMETHING_NEW", "npm", Semver},
		{"SOMETHING_NEW", "an ecosystem nobody has heard of", Generic},
		{"CUSTOM", "openSUSE", RPM},
		{"CUSTOM", "Rocky Linux", RPM},
		{"CUSTOM", "  ubuntu  ", Debian},
		{"CUSTOM", "opam", Debian},
		{"CUSTOM", "Wolfi", Alpine},
		{"CUSTOM", "GIT", Opaque},
		{"CUSTOM", "OSS-Fuzz", Opaque},
		{"CUSTOM", "CRAN", Generic},
		{"CUSTOM", "Android", Generic},
	}
	for _, tc := range cases {
		if got := SchemeFor(tc.rangeType, tc.ecosystem); got != tc.want {
			t.Errorf("SchemeFor(%q, %q) = %s, want %s", tc.rangeType, tc.ecosystem, got, tc.want)
		}
	}
}

func TestReissuerEcosystemsResolveToTheEcosystemTheyRepublish(t *testing.T) {
	cases := []struct {
		ecosystem string
		want      Scheme
	}{
		{"TuxCare:Maven", Maven},
		{"TuxCare:PyPI", Python},
		{"Root:Debian", Debian},
		// A repository URL after the colon is not an ecosystem, and the head is
		// not a re-issuer, so the suffix is ignored rather than parsed.
		{"Maven:https://repo1.maven.org/maven2", Maven},
		// A re-issuer whose suffix names nothing keeps the safe placeholder.
		{"MinimOS", Generic},
		{"TuxCare:something-else", Generic},
		{"Bitnami", Generic},
	}
	for _, tc := range cases {
		if got := SchemeFor("", tc.ecosystem); got != tc.want {
			t.Errorf("SchemeFor(\"\", %q) = %s, want %s", tc.ecosystem, got, tc.want)
		}
	}
}

func TestPURLTypesNameAnEcosystemSchemeForCanResolve(t *testing.T) {
	cases := []struct {
		purlType string
		want     Scheme
	}{
		{"deb", Debian},
		{"rpm", RPM},
		{"apk", Alpine},
		{"npm", Semver},
		{"maven", Maven},
		{"pypi", Python},
		{"golang", Go},
		{"gem", Semver},
		{"cargo", Semver},
		{"composer", Semver},
		{"cran", Generic},
	}
	for _, tc := range cases {
		eco := EcosystemForPURLType(tc.purlType)
		if eco == "" {
			t.Errorf("EcosystemForPURLType(%q) = \"\", want an ecosystem", tc.purlType)
			continue
		}
		if got := SchemeFor("", eco); got != tc.want {
			t.Errorf("SchemeFor(\"\", EcosystemForPURLType(%q)=%q) = %s, want %s", tc.purlType, eco, got, tc.want)
		}
	}
	if got := EcosystemForPURLType("generic"); got != "" {
		t.Errorf("EcosystemForPURLType(\"generic\") = %q, want \"\"", got)
	}
}
