package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestPickCanonicalID(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want string
	}{
		{"cve beats ghsa", []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}, "CVE-2021-44228"},
		{"cve beats euvd", []string{"EUVD-2025-4893", "CVE-2025-1111"}, "CVE-2025-1111"},
		{"ghsa beats euvd", []string{"EUVD-2025-4893", "GHSA-jfh8-c2jp-5v3q"}, "GHSA-jfh8-c2jp-5v3q"},
		{"gcve loses to cve", []string{"GCVE-0-2023-40224", "CVE-2023-40224"}, "CVE-2023-40224"},
		{"case is normalised", []string{"cve-2021-44228"}, "CVE-2021-44228"},
		{"empty input", []string{"", "   "}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := model.PickCanonicalID(tc.ids); got != tc.want {
				t.Fatalf("PickCanonicalID(%v) = %q, want %q", tc.ids, got, tc.want)
			}
		})
	}
}

func TestNormalizeIDKeepsGHSATailLowercase(t *testing.T) {
	if got := model.NormalizeID("GHSA-JFH8-C2JP-5V3Q"); got != "GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("NormalizeID = %q", got)
	}
}

func TestPickPrimarySeverity(t *testing.T) {
	sevs := []model.Severity{
		{Type: "CVSS_V3_1", Score: 7.5, Source: "osv", Provider: "github"},
		{Type: "CVSS_V3_1", Score: 9.8, Source: "cvelist", Provider: "acme"},
		{Type: "CVSS_V2", Score: 10.0, Source: "nvd", Provider: "nvd@nist.gov"},
	}
	got := PickPrimarySeverity(sevs)
	if got == nil {
		t.Fatal("no severity picked")
	}
	// v3.1 outranks v2 despite the higher v2 number, and among the two v3.1
	// statements the CNA record outranks the OSV mirror.
	if got.Source != "cvelist" || got.Score != 9.8 {
		t.Fatalf("primary = %+v, want the cvelist v3.1 statement", got)
	}
}

func TestPickPrimarySeverityPrefersAScoredStatement(t *testing.T) {
	// GHSA routinely publishes a v4.0 vector with no number alongside a scored
	// v3.1 statement. Ranking by CVSS version alone elected the v4.0 entry and
	// published rating NONE for a critical vulnerability.
	sevs := []model.Severity{
		{Type: "CVSS_V4_0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", Source: "ghsa"},
		{Type: "CVSS_V3_1", Score: 9.8, Rating: "CRITICAL", Source: "ghsa"},
	}
	got := PickPrimarySeverity(sevs)
	if got == nil {
		t.Fatal("no severity picked")
	}
	if got.Score != 9.8 || got.Rating != "CRITICAL" {
		t.Fatalf("primary = %+v, want the scored v3.1 statement", got)
	}
}

func TestPickPrimarySeverityFallsBackToUnscored(t *testing.T) {
	sevs := []model.Severity{
		{Type: "CVSS_V4_0", Vector: "CVSS:4.0/AV:N/AC:L", Source: "ghsa"},
	}
	got := PickPrimarySeverity(sevs)
	if got == nil || got.Type != "CVSS_V4_0" {
		t.Fatalf("primary = %+v, want the v4.0 vector when nothing is scored", got)
	}
	if got.Rating != "" {
		t.Errorf("rating = %q, want empty rather than a fabricated NONE", got.Rating)
	}
}

func TestPickPrimarySeverityWithNoScores(t *testing.T) {
	if got := PickPrimarySeverity(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %+v", got)
	}
	if got := PickPrimarySeverity([]model.Severity{{Type: "OTHER", Source: "osv"}}); got != nil {
		t.Fatalf("expected nil when neither score nor vector present, got %+v", got)
	}
}

func TestMergePrefersAuthoritativeSource(t *testing.T) {
	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	existing := &model.Vulnerability{
		ID:          "CVE-2024-1",
		Title:       "OSV title",
		Description: "OSV description",
		Source:      "osv",
		Published:   &newer,
		Modified:    &older,
		Aliases:     []string{"GHSA-jfh8-c2jp-5v3q"},
		Severities:  []model.Severity{{Type: "CVSS_V3_1", Score: 7.5, Source: "osv"}},
	}
	incoming := &model.Vulnerability{
		ID:          "CVE-2024-1",
		Title:       "CNA title",
		Description: "CNA description",
		Source:      "cvelist",
		Published:   &older,
		Modified:    &newer,
		Aliases:     []string{"EUVD-2024-99"},
		Severities:  []model.Severity{{Type: "CVSS_V3_1", Score: 9.8, Source: "cvelist"}},
	}

	got := Merge(asDoc(existing), incoming)

	if got.Title != "CNA title" || got.Description != "CNA description" {
		t.Errorf("authoritative source should win text fields, got %q / %q", got.Title, got.Description)
	}
	if got.Source != "cvelist" {
		t.Errorf("source = %q, want cvelist", got.Source)
	}
	if !got.Published.Equal(older) {
		t.Errorf("published = %v, want the earliest (%v)", got.Published, older)
	}
	if !got.Modified.Equal(newer) {
		t.Errorf("modified = %v, want the latest (%v)", got.Modified, newer)
	}
	if len(got.Aliases) != 2 {
		t.Errorf("aliases should union, got %v", got.Aliases)
	}
	if len(got.Severities) != 2 {
		t.Errorf("both severity statements should be retained, got %+v", got.Severities)
	}
	if p := PickPrimarySeverity(got.Severities); p == nil || p.Source != "cvelist" {
		t.Errorf("primary severity = %+v", p)
	}
}

func TestMergeLowerRankOnlyFillsGaps(t *testing.T) {
	existing := &model.Vulnerability{
		ID: "CVE-2024-2", Title: "CNA title", Description: "", Source: "cvelist",
	}
	incoming := &model.Vulnerability{
		ID: "CVE-2024-2", Title: "OSV title", Description: "OSV fills the gap", Source: "osv",
	}
	got := Merge(asDoc(existing), incoming)
	if got.Title != "CNA title" {
		t.Errorf("less authoritative source overwrote a populated field: %q", got.Title)
	}
	if got.Description != "OSV fills the gap" {
		t.Errorf("empty field should be filled by any source, got %q", got.Description)
	}
	if got.Source != "cvelist" {
		t.Errorf("source demoted to %q", got.Source)
	}
}

func TestMergeWithNilExistingCopiesSlices(t *testing.T) {
	in := &model.Vulnerability{
		ID:         "CVE-2024-3",
		Source:     "nvd",
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 5, Source: "nvd"}},
	}
	got := Merge(nil, in)
	got.Severities[0].Score = 1
	if in.Severities[0].Score != 5 {
		t.Fatal("Merge aliased the caller's slice instead of copying it")
	}
}

func TestAllIdentifiersDedupesAndNormalises(t *testing.T) {
	v := &model.Vulnerability{
		ID:      "cve-2021-44228",
		Aliases: []string{"CVE-2021-44228", "GHSA-JFH8-C2JP-5V3Q", "", "  "},
	}
	got := v.AllIdentifiers()
	if len(got) != 2 {
		t.Fatalf("AllIdentifiers = %v, want 2 unique entries", got)
	}
	if got[0] != "CVE-2021-44228" || got[1] != "GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("AllIdentifiers = %v", got)
	}
}

func TestMergeKeepsRelatedOutOfAliases(t *testing.T) {
	existing := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "osv",
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
		Related: []string{"CVE-2026-2"},
	}
	in := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "osv",
		Related: []string{"CVE-2026-3"},
	}
	out := Merge(asDoc(existing), in)
	if len(out.Related) != 2 {
		t.Fatalf("related = %v, want both preserved", out.Related)
	}
	for _, a := range out.Aliases {
		if a == "CVE-2026-2" || a == "CVE-2026-3" {
			t.Fatalf("aliases = %v, a related id must never become an identity edge", out.Aliases)
		}
	}
}

// A backfill run after a delta run carries an older snapshot of the same
// source; applying it would roll the record back.
func TestMergeRejectsAStalerSnapshotOfTheSameSource(t *testing.T) {
	newer := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	older := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	existing := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", Description: "current text", Modified: &newer,
	}
	stale := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", Description: "old text", Modified: &older,
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
	}
	out := Merge(asDoc(existing), stale)
	if out.Description != "current text" {
		t.Errorf("description = %q, want the newer text retained", out.Description)
	}
	if !out.Modified.Equal(newer) {
		t.Errorf("modified = %v, want %v", out.Modified, newer)
	}
	if len(out.Aliases) != 1 {
		t.Errorf("aliases = %v, want identity edges taken even from a stale snapshot", out.Aliases)
	}
}

func TestMergeStillAcceptsAnOlderRecordFromAMoreAuthoritativeSource(t *testing.T) {
	newer := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	older := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	existing := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "osv", Description: "mirror text", Modified: &newer,
	}
	cna := &model.Vulnerability{
		ID: "CVE-2026-1", Source: "cvelist", Description: "cna text", Modified: &older,
	}
	out := Merge(asDoc(existing), cna)
	if out.Description != "cna text" {
		t.Errorf("description = %q; the version guard must only apply within one source", out.Description)
	}
}

func TestMergeCarriesEnrichmentStatus(t *testing.T) {
	existing := &model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist"}
	in := &model.Vulnerability{ID: "CVE-2026-1", Source: "nvd", EnrichmentStatus: "Deferred"}
	if out := Merge(asDoc(existing), in); out.EnrichmentStatus != "Deferred" {
		t.Fatalf("enrichment status = %q, want Deferred", out.EnrichmentStatus)
	}
}

func TestDefaultAttributionsCoverEveryCollector(t *testing.T) {
	want := []string{"cvelist", "nvd", "fkie", "vulnrichment", "osv", "ghsa",
		"euvd", "gcve", "csaf", "kev", "epss"}
	have := map[string]bool{}
	for _, a := range DefaultAttributions() {
		have[a.Source] = true
		if a.Notice == "" {
			t.Errorf("%s has no notice text", a.Source)
		}
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("no attribution recorded for %q", w)
		}
	}
}

func TestNVDNoticeIsTheSentenceNISTAsksFor(t *testing.T) {
	const want = "This product uses the NVD API but is not endorsed or certified by the NVD."
	if NVDNotice != want {
		t.Fatalf("NVDNotice = %q, want the verbatim NIST wording", NVDNotice)
	}
}

func TestEffectiveLimitClamps(t *testing.T) {
	cases := map[int]int{0: DefaultPageSize, -5: DefaultPageSize, 25: 25,
		MaxPageSize: MaxPageSize, MaxPageSize + 1: MaxPageSize}
	for in, want := range cases {
		if got := EffectiveLimit(in); got != want {
			t.Errorf("EffectiveLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

// asDoc turns a bare record into the document the store would hold after
// writing it, so a merge test exercises what a second arrival actually meets.
func asDoc(v *model.Vulnerability) *Document { return Merge(nil, v) }

// The record was built from the CNA (January) and OSV (June). The CNA publishes
// an update in March. March is older than June, but June is OSV's stamp, not
// the CNA's; against the CNA's own last word the March update is new and has
// to be taken. Comparing against the cross-source newest silently froze the
// CNA view of most records, because OSV re-stamps its modified field often.
func TestMergeAcceptsASameSourceUpdateNewerThanThatSourcesLast(t *testing.T) {
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mar := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	jun := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	doc := asDoc(&model.Vulnerability{
		ID: "CVE-2026-1", Source: "cvelist", SourceRecordID: "CVE-2026-1",
		Description: "cna january", Modified: &jan,
	})
	doc = Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "osv", SourceRecordID: "CVE-2026-1",
		Description: "osv text", Modified: &jun,
	})
	if !doc.Modified.Equal(jun) {
		t.Fatalf("modified = %v, want the newest across sources (%v)", doc.Modified, jun)
	}

	out := Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "cvelist", SourceRecordID: "CVE-2026-1",
		Description: "cna march", Modified: &mar,
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 9.8, Source: "cvelist"}},
	})
	if out.Description != "cna march" {
		t.Errorf("description = %q; the CNA's March update was rejected as older than OSV's June stamp", out.Description)
	}
	if len(out.Severities) != 1 {
		t.Errorf("severities = %+v, want the CNA's new score taken", out.Severities)
	}
	if !out.Modified.Equal(jun) {
		t.Errorf("modified = %v, want the cross-source newest kept (%v)", out.Modified, jun)
	}
	if c := out.Contributions[contributionKey(&out.Vulnerability)]; c.Modified == nil || !c.Modified.Equal(mar) {
		t.Errorf("cvelist's last modified = %v, want %v", c.Modified, mar)
	}
}

// CSAF publishes several advisories per CVE, each with its own date. An older
// advisory arriving after a newer one is not a stale copy of it.
func TestMergeDoesNotTreatAnOlderRecordOfTheSameSourceAsStale(t *testing.T) {
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	jun := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	doc := asDoc(&model.Vulnerability{
		ID: "CVE-2026-1", Source: "csaf", SourceRecordID: "rhsa-2026-2#CVE-2026-1", Modified: &jun,
		Affected: []model.Affected{{Vendor: "redhat", Product: "kernel", Status: "affected", Source: "csaf"}},
	})
	out := Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "csaf", SourceRecordID: "rhsa-2026-1#CVE-2026-1", Modified: &jan,
		Affected: []model.Affected{{Vendor: "redhat", Product: "openssl", Status: "fixed", Source: "csaf"}},
	})
	if len(out.Affected) != 2 {
		t.Fatalf("affected = %+v, want both advisories' statements", out.Affected)
	}
}

// NVD narrows a configuration: the statement it no longer makes must go.
func TestMergeRetiresTheStatementsARecordNoLongerMakes(t *testing.T) {
	d1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	wide := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, Source: "nvd"}
	narrow := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}, Source: "nvd"}
	ref := model.Reference{URL: "https://example.org/gone", Source: "nvd"}

	doc := asDoc(&model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", SourceRecordID: "CVE-2026-1", Modified: &d1,
		Affected: []model.Affected{wide, narrow}, References: []model.Reference{ref},
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 5, Provider: "nvd@nist.gov", Source: "nvd"}},
	})
	// The CNA's statement must survive an NVD re-merge untouched.
	doc = Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "cvelist", SourceRecordID: "CVE-2026-1", Modified: &d1,
		Affected: []model.Affected{{Vendor: "acme", Product: "widget", Status: "affected", Source: "cvelist"}},
	})
	out := Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", SourceRecordID: "CVE-2026-1", Modified: &d2,
		Affected: []model.Affected{narrow},
	})
	if len(out.Affected) != 2 {
		t.Fatalf("affected = %+v, want NVD's narrowed statement plus the CNA's", out.Affected)
	}
	for _, a := range out.Affected {
		if a.Source == "nvd" && a.CPEs[0] == wide.CPEs[0] {
			t.Error("the statement NVD withdrew is still in the document")
		}
	}
	if len(out.References) != 0 {
		t.Errorf("references = %+v, want the reference NVD dropped to be gone", out.References)
	}
	if len(out.Severities) != 0 {
		t.Errorf("severities = %+v, want the score NVD dropped to be gone", out.Severities)
	}
}

// Two advisories from one source name the same product. When one of them
// stops naming it, the other still does, and the statement stays.
func TestMergeKeepsAStatementAnotherRecordOfTheSameSourceStillMakes(t *testing.T) {
	d1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	kernel := model.Affected{Vendor: "redhat", Product: "kernel", Status: "affected", Source: "csaf"}
	doc := asDoc(&model.Vulnerability{
		ID: "CVE-2026-1", Source: "csaf", SourceRecordID: "rhsa-1#CVE-2026-1", Modified: &d1,
		Affected: []model.Affected{kernel},
	})
	doc = Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "csaf", SourceRecordID: "rhsa-2#CVE-2026-1", Modified: &d1,
		Affected: []model.Affected{kernel},
	})
	out := Merge(doc, &model.Vulnerability{
		ID: "CVE-2026-1", Source: "csaf", SourceRecordID: "rhsa-1#CVE-2026-1", Modified: &d2,
		Affected: []model.Affected{{Vendor: "redhat", Product: "kernel-rt", Status: "affected", Source: "csaf"}},
	})
	products := map[string]bool{}
	for _, a := range out.Affected {
		products[a.Product] = true
	}
	if !products["kernel"] || !products["kernel-rt"] || len(products) != 2 {
		t.Fatalf("affected products = %v, want kernel (still claimed by rhsa-2) and kernel-rt", products)
	}
}

// A losing record reached through an alias edge is not among the incoming
// record's identifiers, so unless the fold itself keeps it, nothing lists it.
func TestMergeAllKeepsEveryFoldedIdentifierAsAnAlias(t *testing.T) {
	docs := []*Document{
		asDoc(&model.Vulnerability{ID: "GHSA-jfh8-c2jp-5v3q", Source: "ghsa", Aliases: []string{"EUVD-2026-1"}}),
		asDoc(&model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist"}),
	}
	out := mergeAll(docs, "CVE-2026-1")
	have := map[string]bool{}
	for _, a := range out.Aliases {
		have[a] = true
	}
	if !have["GHSA-jfh8-c2jp-5v3q"] || !have["EUVD-2026-1"] {
		t.Fatalf("aliases = %v, want the folded GHSA id kept alongside its own aliases", out.Aliases)
	}
}

func TestWithdrawnIsClearedWhenTheSourceThatSetItRetractsIt(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	doc := asDoc(&model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist"})
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", Withdrawn: &when})
	if doc.Withdrawn == nil {
		t.Fatal("withdrawn not set by the source that asserted it")
	}
	// The CNA says nothing about withdrawal — it has no such field — and must
	// not clear what OSV said.
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist", Title: "update"})
	if doc.Withdrawn == nil {
		t.Fatal("a record from a source that never speaks of withdrawal cleared it")
	}
	// OSV un-withdraws: the record comes round without the field.
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "osv"})
	if doc.Withdrawn != nil {
		t.Fatalf("withdrawn = %v after the asserting source retracted it, want cleared", doc.Withdrawn)
	}
}

func TestWithdrawnIsNotOverwrittenByALowerRankedSource(t *testing.T) {
	first := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	doc := asDoc(&model.Vulnerability{ID: "CVE-2026-1", Source: "ghsa", Withdrawn: &first})
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", Withdrawn: &later})
	if !doc.Withdrawn.Equal(first) {
		t.Errorf("withdrawn = %v; OSV outranks nothing here and must not replace GHSA's date", doc.Withdrawn)
	}
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist", Withdrawn: &later})
	if !doc.Withdrawn.Equal(later) {
		t.Errorf("withdrawn = %v; the CNA outranks GHSA and may replace it", doc.Withdrawn)
	}
}

// A type this code does not know must not tie with CVSS v4.0, which is what a
// map's zero default gave it.
func TestUnknownSeverityTypeRanksBelowEveryKnownOne(t *testing.T) {
	sevs := []model.Severity{
		{Type: "VENDOR_SCALE", Score: 9.0, Source: "cvelist"},
		{Type: "CVSS_V2", Score: 5.0, Source: "nvd"},
	}
	got := PickPrimarySeverity(sevs)
	if got == nil || got.Type != "CVSS_V2" {
		t.Fatalf("primary = %+v, want the CVSS v2 statement over an unrecognised type", got)
	}
}

func TestHistoryLimitAboveTheMaximumClampsToTheMaximum(t *testing.T) {
	cases := map[int]int{0: DefaultHistoryLimit, -1: DefaultHistoryLimit, 7: 7,
		MaxHistoryLimit: MaxHistoryLimit, MaxHistoryLimit + 100: MaxHistoryLimit}
	for in, want := range cases {
		if got := historyLimit(in); got != want {
			t.Errorf("historyLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestAffectedFingerprintSeparatesStatementsThatDifferOnlyInRangesOrDefaultState(t *testing.T) {
	base := model.Affected{Vendor: "linux", Product: "kernel", Source: "cvelist"}
	withRange := base
	withRange.Ranges = []model.VersionRange{{Introduced: "abc123", Fixed: "def456", Type: "GIT"}}
	otherRange := base
	otherRange.Ranges = []model.VersionRange{{Introduced: "abc123", Fixed: "0123ab", Type: "GIT"}}
	withDefault := base
	withDefault.DefaultState = "affected"

	seen := map[string]string{}
	for name, a := range map[string]model.Affected{
		"bare": base, "range": withRange, "other range": otherRange, "default": withDefault,
	} {
		fp := affectedFingerprint(a)
		if prev, dup := seen[fp]; dup {
			t.Errorf("%q and %q share a fingerprint; the later one would overwrite the earlier", name, prev)
		}
		seen[fp] = name
	}
}

func TestNormalisePURLKeepsAScopedNamespace(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/@angular/core":                          "pkg:npm/@angular/core",
		"pkg:npm/@angular/core@12.0.0":                   "pkg:npm/@angular/core",
		"pkg:golang/github.com/Masterminds/goutils@v1.1": "pkg:golang/github.com/masterminds/goutils",
		"pkg:deb/debian/curl@7.88.1-10?arch=amd64":       "pkg:deb/debian/curl",
		"pkg:golang/example.com/mod#sub/dir":             "pkg:golang/example.com/mod",
	}
	for in, want := range cases {
		if got := normalisePURL(in); got != want {
			t.Errorf("normalisePURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// OSV feeds one CVE through several records: a withdrawn GHSA entry beside a
// live PYSEC entry. Keyed on the source, each PYSEC arrival cleared what GHSA
// set and each GHSA arrival set it again, so the document's hash and history
// moved on every run for a record nothing upstream had touched.
func TestWithdrawnSurvivesAnotherRecordOfTheSameSource(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ghsa := &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", SourceRecordID: "GHSA-aaaa-bbbb-cccc", Withdrawn: &when}
	pysec := &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", SourceRecordID: "PYSEC-2026-1"}

	doc := asDoc(&model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist", SourceRecordID: "CVE-2026-1"})
	for i, in := range []*model.Vulnerability{ghsa, pysec, ghsa, pysec} {
		doc = Merge(doc, in)
		if doc.Withdrawn == nil {
			t.Fatalf("withdrawn cleared after arrival %d (%s); only the record that set it may clear it", i, in.SourceRecordID)
		}
		if doc.WithdrawnBy != contributionKey(ghsa) {
			t.Fatalf("withdrawn_by = %q after arrival %d, want the GHSA record throughout", doc.WithdrawnBy, i)
		}
	}
	// The record that set it can still retract it.
	doc = Merge(doc, &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", SourceRecordID: "GHSA-aaaa-bbbb-cccc"})
	if doc.Withdrawn != nil {
		t.Fatal("the withdrawing record came round without the field and did not clear it")
	}
}

// A document written before withdrawals were attributed to a record — one
// holding only the old withdrawn_source, or nothing at all — recorded which
// source withdrew it at best. Any record of that source coming round without
// the field clears it: refusing to guess left such a withdrawal set forever.
func TestALegacyWithdrawalIsClearedByTheSourceThatSetIt(t *testing.T) {
	var legacy Document
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-1","source":"cvelist",
	    "withdrawn":"2026-05-01T00:00:00Z","withdrawn_source":"osv"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	out := Merge(&legacy, &model.Vulnerability{ID: "CVE-2026-1", Source: "cvelist", SourceRecordID: "CVE-2026-1", Title: "cna update"})
	if out.Withdrawn == nil {
		t.Fatal("the CNA never spoke of withdrawal and must not clear what OSV said")
	}
	if out.WithdrawnSource != "" || out.WithdrawnBy != sourceOnlyKey("osv") {
		t.Errorf("withdrawn_source = %q, withdrawn_by = %q; want the legacy field folded into a source-only key", out.WithdrawnSource, out.WithdrawnBy)
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), "withdrawn_source") {
		t.Error("the legacy field was written back out")
	}
	out = Merge(out, &model.Vulnerability{ID: "CVE-2026-1", Source: "osv", SourceRecordID: "PYSEC-2026-1"})
	if out.Withdrawn != nil {
		t.Fatal("a record of the withdrawing source came round without the field and did not clear a legacy withdrawal")
	}

	// Older still: the document says nothing about who withdrew it. Its own
	// source is the only candidate.
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	older := &Document{Vulnerability: model.Vulnerability{ID: "CVE-2026-2", Source: "osv", Withdrawn: &when}}
	out = Merge(older, &model.Vulnerability{ID: "CVE-2026-2", Source: "cvelist", SourceRecordID: "CVE-2026-2"})
	if out.Withdrawn == nil {
		t.Fatal("another source cleared a withdrawal it never made")
	}
	out = Merge(out, &model.Vulnerability{ID: "CVE-2026-2", Source: "osv", SourceRecordID: "GHSA-xxxx-yyyy-zzzz"})
	if out.Withdrawn != nil {
		t.Fatal("the document's own source came round without the field and did not clear an unattributed withdrawal")
	}
}

// A document written before contributions were tracked has no entry for the
// record that made it. On the first re-merge that used to mean no stale guard
// — a backfill's older snapshot overwrote the newer text while Modified stayed
// newer — and nothing to retire, so a statement the record had since dropped
// stayed forever.
func TestALegacyDocumentIsGuardedAndRetiredLikeATrackedOne(t *testing.T) {
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	jun := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	jul := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	wide := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, Source: "nvd"}
	narrow := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}, Source: "nvd"}
	cna := model.Affected{Vendor: "acme", Product: "widget", Status: "affected", Source: "cvelist"}

	legacy := func() *Document {
		return &Document{Vulnerability: model.Vulnerability{
			ID: "CVE-2026-1", Source: "nvd", SourceRecordID: "CVE-2026-1", Description: "june text", Modified: &jun,
			Affected: []model.Affected{wide, narrow, cna},
		}}
	}

	stale := Merge(legacy(), &model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", SourceRecordID: "CVE-2026-1", Description: "january text", Modified: &jan,
		Affected: []model.Affected{narrow},
	})
	if stale.Description != "june text" || len(stale.Affected) != 3 {
		t.Fatalf("description = %q, affected = %d; an older snapshot of the document's own source was applied over the newer one", stale.Description, len(stale.Affected))
	}

	fresh := Merge(legacy(), &model.Vulnerability{
		ID: "CVE-2026-1", Source: "nvd", SourceRecordID: "CVE-2026-1", Description: "july text", Modified: &jul,
		Affected: []model.Affected{narrow},
	})
	if fresh.Description != "july text" {
		t.Fatalf("description = %q, want the newer snapshot applied", fresh.Description)
	}
	var nvd, other []string
	for _, a := range fresh.Affected {
		if a.Source == "nvd" {
			nvd = append(nvd, a.CPEs[0])
		} else {
			other = append(other, a.Source)
		}
	}
	if len(nvd) != 1 || nvd[0] != narrow.CPEs[0] {
		t.Errorf("nvd statements = %v, want exactly the narrowed one; the legacy wide statement was never retired", nvd)
	}
	if len(other) != 1 || other[0] != "cvelist" {
		t.Errorf("other statements = %v, want the CNA's untouched", other)
	}

	// A source the legacy document never held gets an empty entry and an
	// older record from it is not stale: not knowing is not evidence.
	osv := Merge(legacy(), &model.Vulnerability{
		ID: "CVE-2026-1", Source: "osv", SourceRecordID: "GHSA-aaaa-bbbb-cccc", Description: "osv text", Modified: &jan,
		Affected: []model.Affected{{Ecosystem: "npm", Product: "widget", Source: "osv"}},
	})
	if len(osv.Affected) != 4 {
		t.Errorf("affected = %d after a first OSV arrival, want the legacy three plus OSV's", len(osv.Affected))
	}
}
