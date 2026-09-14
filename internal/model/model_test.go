package model

import (
	"reflect"
	"testing"
	"time"
)

func TestIdentifierPredicates(t *testing.T) {
	cases := []struct {
		id                            string
		isCVE, isGHSA, isEUVD, isGCVE bool
	}{
		{"CVE-2021-44228", true, false, false, false},
		{"cve-2021-44228", true, false, false, false},
		{"GHSA-jfh8-c2jp-5v3q", false, true, false, false},
		{"EUVD-2024-12345", false, false, true, false},
		{"GCVE-0-2023-40224", false, false, false, true},
		{"not-an-id", false, false, false, false},
	}
	for _, tc := range cases {
		if got := IsCVE(tc.id); got != tc.isCVE {
			t.Errorf("IsCVE(%q) = %v, want %v", tc.id, got, tc.isCVE)
		}
		if got := IsGHSA(tc.id); got != tc.isGHSA {
			t.Errorf("IsGHSA(%q) = %v, want %v", tc.id, got, tc.isGHSA)
		}
		if got := IsEUVD(tc.id); got != tc.isEUVD {
			t.Errorf("IsEUVD(%q) = %v, want %v", tc.id, got, tc.isEUVD)
		}
		if got := IsGCVE(tc.id); got != tc.isGCVE {
			t.Errorf("IsGCVE(%q) = %v, want %v", tc.id, got, tc.isGCVE)
		}
	}
}

func TestNormalizeID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cve-2021-44228", "CVE-2021-44228"},
		{"GHSA-JFH8-C2JP-5V3Q", "GHSA-jfh8-c2jp-5v3q"},
		{"euvd-2024-12345", "EUVD-2024-12345"},
		{"  CVE-2021-44228  ", "CVE-2021-44228"},
		{"", ""},
		{"something-else", "something-else"},
	}
	for _, tc := range cases {
		if got := NormalizeID(tc.in); got != tc.want {
			t.Errorf("NormalizeID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIdentifierRank(t *testing.T) {
	if r := IdentifierRank("CVE-2021-44228"); r != 0 {
		t.Errorf("CVE rank = %d, want 0", r)
	}
	if r := IdentifierRank("GHSA-jfh8-c2jp-5v3q"); r != 1 {
		t.Errorf("GHSA rank = %d, want 1", r)
	}
	if r := IdentifierRank("EUVD-2024-12345"); r != 2 {
		t.Errorf("EUVD rank = %d, want 2", r)
	}
	if r := IdentifierRank("GCVE-0-2023-40224"); r != 3 {
		t.Errorf("GCVE rank = %d, want 3", r)
	}
	if r := IdentifierRank("something-else"); r != 4 {
		t.Errorf("unknown rank = %d, want 4", r)
	}
}

func TestPickCanonicalID(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want string
	}{
		{"cve wins over ghsa", []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}, "CVE-2021-44228"},
		{"gcve never wins over cve", []string{"GCVE-0-2023-40224", "CVE-2023-40224"}, "CVE-2023-40224"},
		{"only ghsa present", []string{"GHSA-jfh8-c2jp-5v3q"}, "GHSA-jfh8-c2jp-5v3q"},
		{"empty and blank ignored", []string{"", "  ", "EUVD-2024-1"}, "EUVD-2024-1"},
		{"no valid ids", []string{"", "  "}, ""},
		{"tie broken lexicographically", []string{"z-unknown", "a-unknown"}, "a-unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PickCanonicalID(tc.ids); got != tc.want {
				t.Errorf("PickCanonicalID(%v) = %q, want %q", tc.ids, got, tc.want)
			}
		})
	}
}

func TestVulnerabilityAllIdentifiers(t *testing.T) {
	v := &Vulnerability{
		ID:      "cve-2021-44228",
		Aliases: []string{"GHSA-JFH8-C2JP-5V3Q", "cve-2021-44228", "EUVD-2024-1"},
	}
	got := v.AllIdentifiers()
	want := []string{"CVE-2021-44228", "EUVD-2024-1", "GHSA-jfh8-c2jp-5v3q"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllIdentifiers() = %v, want %v", got, want)
	}
}

func TestRatingFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, "NONE"}, {-1, "NONE"}, {3.9, "LOW"}, {4.0, "MEDIUM"},
		{6.9, "MEDIUM"}, {7.0, "HIGH"}, {8.9, "HIGH"}, {9.0, "CRITICAL"}, {10.0, "CRITICAL"},
	}
	for _, tc := range cases {
		if got := RatingFromScore(tc.score); got != tc.want {
			t.Errorf("RatingFromScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestCVSSTypeFromVector(t *testing.T) {
	cases := []struct{ vector, want string }{
		{"CVSS:4.0/AV:N/AC:L", "CVSS_V4_0"},
		{"CVSS:3.1/AV:N/AC:L", "CVSS_V3_1"},
		{"CVSS:3.0/AV:N/AC:L", "CVSS_V3_0"},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:P", "CVSS_V2"},
		{"", "OTHER"},
		{"garbage", "OTHER"},
	}
	for _, tc := range cases {
		if got := CVSSTypeFromVector(tc.vector); got != tc.want {
			t.Errorf("CVSSTypeFromVector(%q) = %q, want %q", tc.vector, got, tc.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want *time.Time
	}{
		{"rfc3339", "2024-06-02T08:30:00Z", ptr(time.Date(2024, 6, 2, 8, 30, 0, 0, time.UTC))},
		{"date only", "2024-06-02", ptr(time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC))},
		{"euvd spelling", "Jun 2, 2024, 8:30:05 AM", ptr(time.Date(2024, 6, 2, 8, 30, 5, 0, time.UTC))},
		{"empty", "", nil},
		{"garbage", "not-a-date", nil},
		// A slash-separated date is ambiguous between month/day and day/month,
		// no upstream emits one, and parsing it as the US order turned the 3rd
		// of April into the 4th of March.
		{"ambiguous slash date", "03/04/2026", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseTime(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Errorf("ParseTime(%q) = %v, want nil", tc.in, got)
				}
				return
			}
			if got == nil || !got.Equal(*tc.want) {
				t.Errorf("ParseTime(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDedupeStrings(t *testing.T) {
	got := DedupeStrings([]string{"b", "", "a", " b ", "a", "  "})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DedupeStrings = %v, want %v", got, want)
	}
}

func ptr(t time.Time) *time.Time { return &t }

// Two spellings of the same assertion reaching the store means a scanner reads
// patched software as vulnerable, so the vocabulary is pinned in one place.
func TestNormalizeStatus(t *testing.T) {
	cases := map[string]string{
		"affected":            StatusAffected,
		"known_affected":      StatusAffected,
		"unaffected":          StatusNotAffected,
		"not_affected":        StatusNotAffected,
		"known_not_affected":  StatusNotAffected,
		"Known Not Affected":  StatusNotAffected,
		"fixed":               StatusFixed,
		"first_fixed":         StatusFixed,
		"under_investigation": StatusUnderInvestigation,
		// An unrecognised vendor spelling is not silently promoted to a claim.
		"probably fine": "",
		"":              "",
	}
	for in, want := range cases {
		if got := NormalizeStatus(in); got != want {
			t.Errorf("NormalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

// CVSS v2 has three bands and no Critical. Scoring a v2 10.0 with the v3 table
// published a rating the metric itself never produces.
func TestCVSSV2RatingHasNoCriticalBand(t *testing.T) {
	cases := map[float64]string{
		0:    "NONE",
		0.5:  "LOW",
		3.9:  "LOW",
		4.0:  "MEDIUM",
		6.9:  "MEDIUM",
		7.0:  "HIGH",
		9.0:  "HIGH",
		10.0: "HIGH",
	}
	for score, want := range cases {
		if got := RatingFromScoreV2(score); got != want {
			t.Errorf("RatingFromScoreV2(%v) = %q, want %q", score, got, want)
		}
	}
}
