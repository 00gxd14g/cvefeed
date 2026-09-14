package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func noRows(err error) bool               { return err == sql.ErrNoRows }
func containsNUL(s string) bool           { return strings.ContainsRune(s, 0) }
func vectorOnly(vector, source string) model.Severity {
	return model.Severity{Type: model.CVSSTypeFromVector(vector), Vector: vector, Source: source}
}

// A record whose only statement is a vector this code cannot score used to
// be stored with primary_rating ” — neither a band nor the NULL that means
// unscored — and the stats counted it under a rating of "".
func TestAVectorOnlyPrimaryIsStoredAsUnscoredNotEmpty(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "CVE-2026-9001", Source: "ghsa", SourceRecordID: "GHSA-aaaa-bbbb-cccc",
		Severities: []model.Severity{vectorOnly("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N/E:U", "ghsa")},
	}
	if _, err := st.UpsertVulnerability(ctx, in); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	var typ string
	var rating, vector sql.NullString
	var score sql.NullFloat64
	if err := st.db.QueryRowContext(ctx,
		`SELECT primary_severity_type, primary_score, primary_rating, primary_vector FROM vulnerabilities WHERE id = $1`,
		"CVE-2026-9001").Scan(&typ, &score, &rating, &vector); err != nil {
		t.Fatal(err)
	}
	if typ != "CVSS_V4_0" || !vector.Valid || score.Valid {
		t.Errorf("primary = (%s, %v, %v), want the unscored v4.0 vector", typ, score, vector)
	}
	if rating.Valid {
		t.Errorf("primary_rating = %q, want NULL", rating.String)
	}
	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stats.ByRating[""]; ok {
		t.Errorf("by_rating counts a rating of \"\": %v", stats.ByRating)
	}
	if stats.ByRating["UNSCORED"] != 1 {
		t.Errorf("by_rating = %v, want UNSCORED: 1", stats.ByRating)
	}

	// A band that the parser did supply for the unscored vector is stored.
	in.Severities[0].Rating = "LOW"
	if _, err := st.UpsertVulnerability(ctx, in); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := st.db.QueryRowContext(ctx,
		`SELECT primary_rating FROM vulnerabilities WHERE id = $1`, "CVE-2026-9001").Scan(&rating); err != nil {
		t.Fatal(err)
	}
	if rating.String != "LOW" {
		t.Errorf("primary_rating = %v, want LOW", rating)
	}
}

// PostgreSQL's text type rejects a NUL byte and jsonb rejects the \u0000
// escape, so one such character anywhere in a record failed the whole
// upsert. The derived columns are scrubbed; the document keeps the bytes.
func TestARecordCarryingNULBytesStillPersists(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "CVE-2026-9002", Source: "osv", SourceRecordID: "GHSA-dddd-eeee-ffff",
		Title:       "title\x00with nul",
		Description: "desc\x00ription",
		Tags:        []string{"dis\x00puted"},
		Severities:  []model.Severity{{Type: "CVSS_V3_1", Score: 5.0, Rating: "MEDIUM", Provider: "p\x00", Source: "osv"}},
		References:  []model.Reference{{URL: "https://example.org/\x00", Name: "n\x00", Source: "osv"}},
		Affected: []model.Affected{{Ecosystem: "npm", Product: "left\x00pad", Source: "osv",
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "1.0\x00"}}}},
		SSVC: &model.SSVC{Exploitation: "none\x00", Source: "osv"},
	}
	if _, err := st.UpsertVulnerability(ctx, in); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	var title, description string
	if err := st.db.QueryRowContext(ctx,
		`SELECT title, description FROM vulnerabilities WHERE id = $1`, "CVE-2026-9002").Scan(&title, &description); err != nil {
		t.Fatal(err)
	}
	if containsNUL(title) || title != "titlewith nul" || description != "description" {
		t.Errorf("stored text = %q / %q, want the NUL removed", title, description)
	}
	var refs, affected, sevs int
	for _, q := range []struct {
		sql string
		n   *int
	}{
		{`SELECT count(*) FROM vuln_reference WHERE vuln_id = $1`, &refs},
		{`SELECT count(*) FROM vuln_affected WHERE vuln_id = $1`, &affected},
		{`SELECT count(*) FROM vuln_severity WHERE vuln_id = $1`, &sevs},
	} {
		if err := st.db.QueryRowContext(ctx, q.sql, "CVE-2026-9002").Scan(q.n); err != nil {
			t.Fatal(err)
		}
	}
	if refs != 1 || affected != 1 || sevs != 1 {
		t.Errorf("child rows = %d/%d/%d, want 1/1/1", refs, affected, sevs)
	}
	d, err := st.GetVulnerability(ctx, "CVE-2026-9002")
	if err != nil {
		t.Fatalf("GetVulnerability() error = %v", err)
	}
	if d.Description != "desc\x00ription" {
		t.Errorf("document description = %q, want the original bytes kept", d.Description)
	}
}

// An alias arriving in the publisher's spelling is stored once, canonically.
func TestAnAliasSpelledInLowerCaseIsStoredOnce(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "ghsa-jfh8-c2jp-5v3q", Source: "osv", SourceRecordID: "ghsa-jfh8-c2jp-5v3q",
		Aliases: []string{"cve-2026-9003"},
	}
	canonical, err := st.UpsertVulnerability(ctx, in)
	if err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if canonical != "CVE-2026-9003" {
		t.Fatalf("canonical = %q, want CVE-2026-9003", canonical)
	}
	var n int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_aliases WHERE vuln_id = $1`, canonical).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("alias rows = %d, want 2 (the canonical id and the GHSA)", n)
	}
	d, err := st.GetVulnerability(ctx, "CVE-2026-9003")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Aliases) != 1 || d.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("aliases = %v, want [GHSA-jfh8-c2jp-5v3q]", d.Aliases)
	}
	if err := st.db.QueryRowContext(ctx,
		`SELECT 1 FROM vuln_aliases WHERE alias = $1`, "cve-2026-9003").Scan(&n); !noRows(err) {
		t.Errorf("lower-case alias row present (err=%v), want none", err)
	}
}

// A list page carries the headline of each record, not its bulk: the
// affected statements and references stay on the detail endpoint and in the
// export. Everything else keeps its place and its name.
func TestListItemsLeaveOutAffectedAndReferences(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "CVE-2026-9004", Title: "t", Source: "cvelist", SourceRecordID: "CVE-2026-9004",
		Aliases:    []string{"GHSA-aaaa-bbbb-cccc"},
		CWEs:       []string{"CWE-79"},
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 7.5, Rating: "HIGH", Source: "cvelist"}},
		References: []model.Reference{{URL: "https://example.org/a", Source: "cvelist"}},
		Affected:   []model.Affected{{Vendor: "acme", Product: "widget", Status: "affected", Source: "cvelist"}},
	}
	if _, err := st.UpsertVulnerability(ctx, in); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	res, err := st.ListVulnerabilities(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("ListVulnerabilities() error = %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(res.Items))
	}
	item := res.Items[0]
	if item.Affected != nil || item.References != nil {
		t.Errorf("list item carries affected=%d references=%d, want neither", len(item.Affected), len(item.References))
	}
	if item.Title != "t" || len(item.Aliases) != 1 || len(item.CWEs) != 1 || len(item.Severities) != 1 {
		t.Errorf("list item lost a headline field: %+v", item)
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"affected"`) || strings.Contains(string(body), `"references"`) {
		t.Errorf("list item JSON still names the elided fields: %s", body)
	}

	d, err := st.GetVulnerability(ctx, "CVE-2026-9004")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Affected) != 1 || len(d.References) != 1 {
		t.Errorf("detail lost affected/references: %d/%d", len(d.Affected), len(d.References))
	}
	var streamed int
	err = st.StreamVulnerabilities(ctx, ListFilter{}, func(r *ExportRecord) error {
		streamed += len(r.Affected) + len(r.References)
		return nil
	})
	if err != nil || streamed != 2 {
		t.Errorf("export carries %d affected+references (err=%v), want 2", streamed, err)
	}
}
