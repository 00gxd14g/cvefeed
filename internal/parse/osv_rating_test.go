package parse

import "testing"

// GHSA publishes most advisories with a CVSS v4.0 vector and no number. This
// code does not compute v4.0, so the statement used to carry no rating at
// all, and where it was the record's only statement the record was published
// with an empty rating: 3,494 of them in the live corpus. GitHub sets
// database_specific.severity from the very score it does not export, so that
// band is the honest fallback for the gap.
func TestOSVUnscorableVectorTakesThePublishersBand(t *testing.T) {
	raw := []byte(`{
	  "id":"GHSA-2h23-c973-x63q","modified":"2025-04-12T02:27:53Z",
	  "aliases":["CVE-2011-4782"],
	  "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N/E:U"}],
	  "database_specific":{"severity":"LOW"}}`)
	v, err := OSVToModel(raw, "ghsa")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Severities) != 1 {
		t.Fatalf("severities = %+v, want exactly the v4.0 statement", v.Severities)
	}
	got := v.Severities[0]
	if got.Type != "CVSS_V4_0" || got.Score != 0 {
		t.Fatalf("statement = %+v, want an unscored v4.0 vector", got)
	}
	if got.Rating != "LOW" {
		t.Errorf("rating = %q, want LOW from database_specific.severity", got.Rating)
	}
}

// A band derived from a real number is never replaced by the publisher's
// word, and the publisher's word is spelled the way the rating filter
// expects: GitHub says "moderate" where CVSS says MEDIUM.
func TestOSVPublishersBandOnlyFillsTheGap(t *testing.T) {
	raw := []byte(`{
	  "id":"GHSA-aaaa-bbbb-cccc","modified":"2026-01-01T00:00:00Z",
	  "severity":[
	    {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	    {"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
	  ],
	  "database_specific":{"severity":"Moderate"}}`)
	v, err := OSVToModel(raw, "ghsa")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	ratings := map[string]string{}
	for _, s := range v.Severities {
		ratings[s.Type] = s.Rating
	}
	if ratings["CVSS_V3_1"] != "CRITICAL" {
		t.Errorf("v3.1 rating = %q, want CRITICAL computed from the vector, not the publisher's band", ratings["CVSS_V3_1"])
	}
	if ratings["CVSS_V4_0"] != "MEDIUM" {
		t.Errorf("v4.0 rating = %q, want MEDIUM (GitHub's \"Moderate\")", ratings["CVSS_V4_0"])
	}
}

// CVSS:3.1/.../C:N/I:N/A:N scores 0.0 by the formula. That is a score with
// the band NONE, not a missing one; treating the zero as "not computed" left
// 29 live records with a vector, no score and an empty rating.
func TestOSVAZeroScoreVectorIsRatedNone(t *testing.T) {
	raw := []byte(`{
	  "id":"GHSA-dddd-eeee-ffff","modified":"2026-01-01T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}],
	  "database_specific":{"severity":"LOW"}}`)
	v, err := OSVToModel(raw, "ghsa")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Severities) != 1 {
		t.Fatalf("severities = %+v, want one", v.Severities)
	}
	if got := v.Severities[0]; got.Score != 0 || got.Rating != "NONE" {
		t.Errorf("statement = %+v, want score 0 rated NONE, not the publisher's band", got)
	}
}

func TestCVSSBaseScoreTellsAComputedZeroFromAnUnreadableVector(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
		ok     bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0, true},
		{"CVSS:3.1/AV:N/AC:L", 0, false},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		score, ok := cvssBaseScore(c.vector)
		if score != c.score || ok != c.ok {
			t.Errorf("cvssBaseScore(%q) = (%v, %v), want (%v, %v)", c.vector, score, ok, c.score, c.ok)
		}
	}
}
