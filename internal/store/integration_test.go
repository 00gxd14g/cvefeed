package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// These tests need a real PostgreSQL. Set CVEFEED_TEST_DATABASE_URL to run
// them; without it they skip, so `go test ./...` stays hermetic.
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_USER=cvefeed \
//	    -e POSTGRES_DB=cvefeed -p 55432:5432 postgres:16-alpine
//	CVEFEED_TEST_DATABASE_URL='postgres://cvefeed:test@localhost:55432/cvefeed?sslmode=disable' \
//	    go test ./internal/store/
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CVEFEED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CVEFEED_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	dsn, err := isolatedSchema(ctx, dsn, "cvefeed_test_store")
	if err != nil {
		t.Fatalf("isolate test schema: %v", err)
	}
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Each test starts from an empty corpus but keeps the schema, which also
	// exercises Migrate's idempotency on every run.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	for _, tbl := range []string{
		"vuln_history", "vuln_affected", "vuln_reference", "vuln_severity",
		"vuln_aliases", "epss", "kev", "raw_records", "vulnerabilities", "sources",
	} {
		if _, err := st.db.ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatalf("clear %s: %v", tbl, err)
		}
	}
	return st
}

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestMigrateIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	// A second and third pass must not fail: the binary runs Migrate on every
	// start, and version 2 only ever adds.
	for i := 0; i < 2; i++ {
		if err := st.Migrate(ctx); err != nil {
			t.Fatalf("Migrate() pass %d error = %v", i+2, err)
		}
	}
	var versions int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != len(migrations) {
		t.Fatalf("schema_migrations has %d rows, want %d", versions, len(migrations))
	}
}

func TestUpsertAndGet(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "CVE-2026-1000", Title: "t", Description: "d", State: "PUBLISHED",
		Published: ts("2026-01-01T00:00:00Z"), Modified: ts("2026-02-01T00:00:00Z"),
		EnrichmentStatus: "Deferred",
		Tags:             []string{"disputed"},
		Aliases:          []string{"GHSA-jfh8-c2jp-5v3q"},
		CWEs:             []string{"CWE-79"},
		Severities: []model.Severity{
			{Type: "CVSS_V3_1", Score: 9.8, Rating: "CRITICAL", Provider: "acme", Source: "cvelist"},
		},
		References: []model.Reference{{URL: "https://example.org/a", Source: "cvelist"}},
		Affected: []model.Affected{
			{Vendor: "acme", Product: "widget", Status: "affected", Source: "cvelist"},
			{Vendor: "acme", Product: "widget", Status: "fixed", Source: "cvelist"},
		},
		Source: "cvelist", SourceRecordID: "CVE-2026-1000",
		Raw: json.RawMessage(`{"cveMetadata":{"cveId":"CVE-2026-1000"}}`),
	}
	if _, err := st.UpsertVulnerability(ctx, in); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	// The alias resolves to the same record.
	d, err := st.GetVulnerability(ctx, "ghsa-jfh8-c2jp-5v3q")
	if err != nil {
		t.Fatalf("GetVulnerability(alias) error = %v", err)
	}
	if d.ID != "CVE-2026-1000" {
		t.Fatalf("id = %q, want the canonical CVE", d.ID)
	}
	if d.EnrichmentStatus != "Deferred" {
		t.Errorf("enrichment status = %q, want Deferred", d.EnrichmentStatus)
	}

	// Both VEX statuses survive: they differ only by status, which has to be
	// part of the affected row's identity.
	var affected int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_affected WHERE vuln_id = $1`, "CVE-2026-1000").Scan(&affected); err != nil {
		t.Fatal(err)
	}
	if affected != 2 {
		t.Fatalf("vuln_affected rows = %d, want 2 (affected and fixed)", affected)
	}
}

// Re-applying a byte-identical record must not append a history row. A bulk
// re-ingest otherwise writes one per record per source per run.
func TestUnchangedUpsertWritesNoHistory(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	in := &model.Vulnerability{
		ID: "CVE-2026-1001", Description: "d", State: "PUBLISHED",
		Modified: ts("2026-02-01T00:00:00Z"),
		Source:   "cvelist", SourceRecordID: "CVE-2026-1001",
	}
	for i := 0; i < 3; i++ {
		if _, err := st.UpsertVulnerability(ctx, in); err != nil {
			t.Fatalf("UpsertVulnerability() pass %d error = %v", i, err)
		}
	}
	var rows int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_history WHERE vuln_id = $1`, "CVE-2026-1001").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("vuln_history rows = %d after three identical upserts, want 1", rows)
	}
}

// Folding two previously separate records must keep both documents' content and
// must not abort the transaction on a duplicate child row.
func TestFoldPreservesBothDocuments(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	ghsa := &model.Vulnerability{
		ID: "GHSA-jfh8-c2jp-5v3q", Title: "github title", State: "PUBLISHED",
		Modified: ts("2026-01-01T00:00:00Z"),
		Severities: []model.Severity{
			{Type: "CVSS_V3_1", Score: 7.5, Rating: "HIGH", Provider: "github", Source: "ghsa"},
		},
		References: []model.Reference{{URL: "https://example.org/shared", Source: "ghsa"}},
		Source:     "ghsa", SourceRecordID: "GHSA-jfh8-c2jp-5v3q",
	}
	if _, err := st.UpsertVulnerability(ctx, ghsa); err != nil {
		t.Fatalf("seed ghsa: %v", err)
	}

	cve := &model.Vulnerability{
		ID: "CVE-2026-1002", Description: "cna description", State: "PUBLISHED",
		Modified: ts("2026-02-01T00:00:00Z"),
		// The alias is what ties the two previously separate records together
		// and triggers the fold.
		Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
		// Same (type, provider, source) key as the seeded row: repointing the
		// child with UPDATE would raise a unique violation and abort the
		// transaction, losing the whole record.
		Severities: []model.Severity{
			{Type: "CVSS_V3_1", Score: 7.5, Rating: "HIGH", Provider: "github", Source: "ghsa"},
		},
		References: []model.Reference{{URL: "https://example.org/shared", Source: "ghsa"}},
		Source:     "cvelist", SourceRecordID: "CVE-2026-1002",
	}
	if _, err := st.UpsertVulnerability(ctx, cve); err != nil {
		t.Fatalf("fold: %v", err)
	}

	d, err := st.GetVulnerability(ctx, "GHSA-jfh8-c2jp-5v3q")
	if err != nil {
		t.Fatalf("GetVulnerability() error = %v", err)
	}
	if d.ID != "CVE-2026-1002" {
		t.Fatalf("canonical id = %q, want the CVE", d.ID)
	}
	if d.Title != "github title" {
		t.Errorf("title = %q; the folded record's content must survive the merge", d.Title)
	}
	if d.Description != "cna description" {
		t.Errorf("description = %q, want the CNA text", d.Description)
	}

	var losers int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vulnerabilities WHERE id = $1`, "GHSA-jfh8-c2jp-5v3q").Scan(&losers); err != nil {
		t.Fatal(err)
	}
	if losers != 0 {
		t.Errorf("the folded id still has its own row")
	}
}

func TestKEVFlagIsClearedWhenAnEntryLeavesTheCatalogue(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, id := range []string{"CVE-2026-1003", "CVE-2026-1004"} {
		if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: id, State: "PUBLISHED", Source: "cvelist", SourceRecordID: id,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	both := []model.KEV{
		{CVEID: "CVE-2026-1003", CatalogVersion: "2026.08.01", Sources: []string{"cisa_kev"}, Source: "kev"},
		{CVEID: "CVE-2026-1004", CatalogVersion: "2026.08.01", Sources: []string{"cisa_kev"}, Source: "kev"},
	}
	if err := st.UpsertKEV(ctx, both); err != nil {
		t.Fatalf("UpsertKEV() error = %v", err)
	}
	if got := kevFlag(t, st, "CVE-2026-1004"); !got {
		t.Fatal("in_kev = false after the entry was catalogued")
	}

	// CISA withdraws one entry: the row goes, and the flag must follow.
	if _, err := st.db.ExecContext(ctx, `DELETE FROM kev WHERE cve_id = $1`, "CVE-2026-1004"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKEV(ctx, both[:1]); err != nil {
		t.Fatalf("UpsertKEV() error = %v", err)
	}
	if got := kevFlag(t, st, "CVE-2026-1004"); got {
		t.Fatal("in_kev is still true for a CVE that left the catalogue")
	}
	if got := kevFlag(t, st, "CVE-2026-1003"); !got {
		t.Fatal("in_kev was cleared for a CVE that is still catalogued")
	}
}

func kevFlag(t *testing.T, st *Store, id string) bool {
	t.Helper()
	var flag bool
	if err := st.db.QueryRow(`SELECT in_kev FROM vulnerabilities WHERE id = $1`, id).Scan(&flag); err != nil {
		if err == sql.ErrNoRows {
			t.Fatalf("no row for %s", id)
		}
		t.Fatal(err)
	}
	return flag
}

func TestEPSSRoundTripAndFilters(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, id := range []string{"CVE-2026-1005", "CVE-2026-1006"} {
		if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: id, State: "PUBLISHED", Source: "cvelist", SourceRecordID: id,
			Severities: []model.Severity{
				{Type: "CVSS_V3_1", Score: 9.8, Rating: "CRITICAL", Source: "cvelist"},
			},
			Affected: []model.Affected{{Vendor: "siemens", Product: "widget", Source: "cvelist"}},
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	day := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertEPSS(ctx, []model.EPSS{
		{CVEID: "CVE-2026-1005", Score: 0.9, Percentile: 0.99, ScoreDate: day, ModelVersion: "v2026.06.15"},
		{CVEID: "CVE-2026-1006", Score: 0.1, Percentile: 0.4, ScoreDate: day, ModelVersion: "v2026.06.15"},
	}); err != nil {
		t.Fatalf("UpsertEPSS() error = %v", err)
	}

	min := 0.5
	res, err := st.ListVulnerabilities(ctx, ListFilter{EPSSMin: &min})
	if err != nil {
		t.Fatalf("ListVulnerabilities() error = %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("epss_min=0.5 matched %d records, want 1", res.Total)
	}
	if res.Limit != DefaultPageSize {
		t.Errorf("limit = %d, want the applied default %d", res.Limit, DefaultPageSize)
	}

	// The vendor filter is one of the documented ones and needs its index.
	res, err = st.ListVulnerabilities(ctx, ListFilter{Vendor: "SIEMENS"})
	if err != nil {
		t.Fatalf("vendor filter error = %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("vendor filter matched %d, want 2", res.Total)
	}

	d, err := st.GetVulnerability(ctx, "CVE-2026-1005")
	if err != nil {
		t.Fatal(err)
	}
	if d.EPSS == nil || d.EPSS.ModelVersion != "v2026.06.15" {
		t.Errorf("epss = %+v, want the model version recorded", d.EPSS)
	}
}

func TestStreamExportCarriesEnrichment(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-1007", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-1007",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKEV(ctx, []model.KEV{
		{CVEID: "CVE-2026-1007", Sources: []string{"cisa_kev"}, Source: "kev"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEPSS(ctx, []model.EPSS{
		{CVEID: "CVE-2026-1007", Score: 0.42, Percentile: 0.9,
			ScoreDate: time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatal(err)
	}

	var seen int
	err := st.StreamVulnerabilities(ctx, ListFilter{}, func(rec *ExportRecord) error {
		seen++
		if !rec.InKEV {
			t.Error("export record does not carry the KEV flag the CSV header advertises")
		}
		if rec.EPSSScore == 0 {
			t.Error("export record does not carry the EPSS score")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamVulnerabilities() error = %v", err)
	}
	if seen != 1 {
		t.Fatalf("streamed %d records, want 1", seen)
	}
}

func TestAttributionIsSeededOnMigrate(t *testing.T) {
	st := testStore(t)
	rows, err := st.Attributions(context.Background())
	if err != nil {
		t.Fatalf("Attributions() error = %v", err)
	}
	if len(rows) != len(DefaultAttributions()) {
		t.Fatalf("attribution rows = %d, want %d", len(rows), len(DefaultAttributions()))
	}
	var nvd *Attribution
	for i := range rows {
		if rows[i].Source == "nvd" {
			nvd = &rows[i]
		}
	}
	if nvd == nil || nvd.Notice != NVDNotice {
		t.Fatalf("nvd attribution = %+v, want the verbatim NIST notice", nvd)
	}
}

func TestSourceCursorRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.SaveCursor(ctx, "nvd", json.RawMessage(`{"last_modified":"2026-08-18T00:00:00Z"}`), 12, nil); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}
	raw, err := st.LoadCursor(ctx, "nvd")
	if err != nil {
		t.Fatalf("LoadCursor() error = %v", err)
	}
	var cursor map[string]string
	if err := json.Unmarshal(raw, &cursor); err != nil {
		t.Fatalf("cursor is not an object: %v", err)
	}
	if cursor["last_modified"] != "2026-08-18T00:00:00Z" {
		t.Fatalf("cursor = %v", cursor)
	}

	states, err := st.SourceStates(ctx)
	if err != nil {
		t.Fatalf("SourceStates() error = %v", err)
	}
	if len(states) != 1 || states[0].RecordsSeen != 12 {
		t.Fatalf("states = %+v, want one row with 12 records seen", states)
	}
}

func TestStatsCounts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-1008", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-1008",
		Severities: []model.Severity{
			{Type: "CVSS_V3_1", Score: 9.8, Rating: "CRITICAL", Source: "cvelist"},
		},
		Raw: json.RawMessage(`{"x":1}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRaw(ctx, "cvelist", "CVE-2026-1008", []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}

	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Vulnerabilities != 1 {
		t.Errorf("vulnerabilities = %d, want 1", stats.Vulnerabilities)
	}
	if stats.RawRecords != 1 {
		t.Errorf("raw_records = %d, want 1", stats.RawRecords)
	}
	if stats.ByRating["CRITICAL"] != 1 {
		t.Errorf("by_rating = %v, want one CRITICAL", stats.ByRating)
	}
}

func TestRawChangedDetectsContent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	changed, err := st.RawChanged(ctx, "osv", "OSV-1", []byte(`{"a":1}`))
	if err != nil || !changed {
		t.Fatalf("RawChanged(new) = %v/%v, want true", changed, err)
	}
	if _, err := st.SaveRaw(ctx, "osv", "OSV-1", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	changed, err = st.RawChanged(ctx, "osv", "OSV-1", []byte(`{"a":1}`))
	if err != nil || changed {
		t.Fatalf("RawChanged(same) = %v/%v, want false", changed, err)
	}
	changed, err = st.RawChanged(ctx, "osv", "OSV-1", []byte(`{"a":2}`))
	if err != nil || !changed {
		t.Fatalf("RawChanged(different) = %v/%v, want true", changed, err)
	}
}

// An alias edge records who asserted it: a bad upstream claim can collapse two
// real vulnerabilities, and an unattributable merge cannot be investigated.
func TestAliasEdgesCarryTheirSource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-1009", State: "PUBLISHED",
		Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
		Source:  "osv", SourceRecordID: "CVE-2026-1009",
	}); err != nil {
		t.Fatal(err)
	}
	var source string
	if err := st.db.QueryRowContext(ctx,
		`SELECT COALESCE(source,'') FROM vuln_aliases WHERE alias = $1`,
		"GHSA-jfh8-c2jp-5v3q").Scan(&source); err != nil {
		t.Fatal(err)
	}
	if source != "osv" {
		t.Fatalf("alias source = %q, want the asserting collector", source)
	}
}

// resolveExisting reaches records through vuln_aliases, and an alias edge can
// name an identifier that has no vulnerabilities row of its own — OSV records
// routinely list a dozen CVE aliases, most of which are not stored yet. Folding
// then has losers that exist only as names.
//
// That is the case this covers, because the enrichment carry aggregates over
// those losers: an aggregate with no GROUP BY returns one row even when nothing
// matched, and bool_or over zero rows is NULL. "false OR NULL" is NULL, so the
// write violated in_kev's NOT NULL constraint and the whole upsert was lost.
func TestFoldCarriesEnrichmentWhenTheLosersAreNamesWithoutRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-2001", State: "PUBLISHED",
		Source: "cvelist", SourceRecordID: "CVE-2026-2001",
	}); err != nil {
		t.Fatalf("seed canonical: %v", err)
	}
	// in_kev is false here, which is what makes the NULL fatal: "true OR NULL"
	// is true and would have survived.
	var inKEV bool
	if err := st.db.QueryRowContext(ctx,
		`SELECT in_kev FROM vulnerabilities WHERE id = $1`, "CVE-2026-2001").Scan(&inKEV); err != nil {
		t.Fatal(err)
	}
	if inKEV {
		t.Fatal("canonical seeded with in_kev already true; the test would pass for the wrong reason")
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := foldRecords(ctx, tx,
		[]string{"CVE-2026-2001", "CVE-1999-0001", "CVE-1999-0002"}, "CVE-2026-2001"); err != nil {
		t.Fatalf("foldRecords() error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := st.db.QueryRowContext(ctx,
		`SELECT in_kev FROM vulnerabilities WHERE id = $1`, "CVE-2026-2001").Scan(&inKEV); err != nil {
		t.Fatal(err)
	}
	if inKEV {
		t.Error("in_kev became true although no loser was ever in the catalogue")
	}
}

// A writer must not wait forever for a row lock. PostgreSQL does not notice a
// client that vanished without closing its connection, so its transaction keeps
// holding whatever it locked; every later writer then queues behind a session
// that will never commit. Observed live: 26 backends stacked on one
// "SELECT doc FROM vulnerabilities WHERE id = $1 FOR UPDATE", the oldest 26
// minutes deep, after earlier ingest containers were stopped mid-transaction.
//
// A bounded wait turns that from a permanent hang into an error the caller can
// retry, which is the difference between a stuck ingest and a slow one.
func TestAWriterBlockedOnALockGivesUpInsteadOfWaitingForever(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-3001", State: "PUBLISHED",
		Source: "cvelist", SourceRecordID: "CVE-2026-3001",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Stand in for the vanished client: a transaction that takes the same row
	// lock the upsert needs and never lets go.
	holder, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var doc []byte
	if err := holder.QueryRowContext(ctx,
		`SELECT doc FROM vulnerabilities WHERE id = $1 FOR UPDATE`, "CVE-2026-3001").Scan(&doc); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: "CVE-2026-3001", State: "PUBLISHED", Title: "second writer",
			Source: "osv", SourceRecordID: "CVE-2026-3001",
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the second writer succeeded although the row was locked")
		}
	case <-time.After(lockTimeout + 20*time.Second):
		t.Fatalf("the second writer was still waiting after %s; a dead lock holder stalls the ingest forever",
			lockTimeout)
	}
}

// Two processes starting together — the API container restarting while `make
// delta` opens a second one — used to both see the same pending version and
// both run it, which for the type conversions meant hex-encoding the corpus.
// Migrate now waits for the migration lock; this holds it from another session
// and checks that Migrate does not finish until it is released.
func TestMigrateWaitsForTheAdvisoryLock(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	holder, err := st.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		t.Fatalf("take the lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- st.Migrate(ctx) }()

	select {
	case err := <-done:
		t.Fatalf("Migrate returned (%v) while another session held the migration lock", err)
	case <-time.After(1500 * time.Millisecond):
	}
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockKey); err != nil {
		t.Fatalf("release the lock: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate() error = %v after the lock was released", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Migrate did not finish after the lock was released")
	}
}

// A restored dump of an older schema_migrations over a converted corpus is the
// one way left to make migrations 4 and 6 run twice. Their second run must be
// a no-op: a bytea column re-converted with convert_to(x::text) holds the hex
// spelling of every row afterwards.
func TestReplayingMigrationsDoesNotCorruptByteaColumns(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.SaveRaw(ctx, "cvelist", "CVE-2026-4001", []byte(`{"cveMetadata":{"cveId":"CVE-2026-4001"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-4001", Title: "kept", State: "PUBLISHED",
		Source: "cvelist", SourceRecordID: "CVE-2026-4001",
	}); err != nil {
		t.Fatal(err)
	}
	var rawBefore, docBefore []byte
	if err := st.db.QueryRowContext(ctx, `SELECT content FROM raw_records WHERE record_id = 'CVE-2026-4001'`).Scan(&rawBefore); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT doc FROM vulnerabilities WHERE id = 'CVE-2026-4001'`).Scan(&docBefore); err != nil {
		t.Fatal(err)
	}

	if _, err := st.db.ExecContext(ctx, `DELETE FROM schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() replay error = %v", err)
	}

	var rawAfter, docAfter []byte
	if err := st.db.QueryRowContext(ctx, `SELECT content FROM raw_records WHERE record_id = 'CVE-2026-4001'`).Scan(&rawAfter); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT doc FROM vulnerabilities WHERE id = 'CVE-2026-4001'`).Scan(&docAfter); err != nil {
		t.Fatal(err)
	}
	if string(rawAfter) != string(rawBefore) {
		t.Errorf("raw_records.content changed under a replayed migration 4: %q -> %q", rawBefore, rawAfter)
	}
	if string(docAfter) != string(docBefore) {
		t.Errorf("vulnerabilities.doc changed under a replayed migration 6")
	}
	d, err := st.GetVulnerability(ctx, "CVE-2026-4001")
	if err != nil || d.Title != "kept" {
		t.Fatalf("GetVulnerability after replay = %+v, %v; want the record readable", d, err)
	}
	var versions int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != len(migrations) {
		t.Errorf("schema_migrations has %d rows after replay, want %d", versions, len(migrations))
	}
}

func TestCheckSchemaReportsPendingMigrations(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema() on a migrated schema = %v, want nil", err)
	}
	last := migrations[len(migrations)-1].version
	if _, err := st.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, last); err != nil {
		t.Fatal(err)
	}
	err := st.CheckSchema(ctx)
	if err == nil {
		t.Fatal("CheckSchema() = nil with a migration pending")
	}
	if want := "[" + itoa(last) + "]"; !contains(err.Error(), want) {
		t.Errorf("error %q does not name the pending version %s", err, want)
	}
	if _, err := st.db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckSchema(ctx); err == nil || !contains(err.Error(), "not initialised") {
		t.Errorf("CheckSchema() without schema_migrations = %v, want an initialisation error", err)
	}
	// CheckSchema changed nothing; Migrate repairs what the test broke.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := st.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema() after Migrate = %v, want nil", err)
	}
}

func itoa(n int) string { return fmt.Sprint(n) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// ["linux", "curl"]: linux fills any shared budget on its own and curl gets no
// candidates, so its vulnerabilities go unreported with nothing to say so.
// The limit has to apply per key, and hitting it has to be visible.
func TestACommonNameDoesNotStarveOtherKeysOfCandidates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	prev := maxCandidatesPerQuery
	maxCandidatesPerQuery = 3
	t.Cleanup(func() { maxCandidatesPerQuery = prev })

	var linux []model.Affected
	for i := 0; i < 8; i++ {
		linux = append(linux, model.Affected{
			Vendor: "linux", Product: "linux", Versions: []string{fmt.Sprintf("6.%d", i)}, Source: "cvelist",
		})
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-5001", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-5001",
		Affected: linux,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-5002", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-5002",
		Affected: []model.Affected{{Vendor: "haxx", Product: "curl", Source: "cvelist"}},
	}); err != nil {
		t.Fatal(err)
	}

	set, err := st.FindAffectedCandidates(ctx, []CandidateQuery{{Name: "linux"}, {Name: "curl"}})
	if err != nil {
		t.Fatalf("FindAffectedCandidates() error = %v", err)
	}
	if got := len(set.Statements[1]); got != 1 {
		t.Errorf("curl got %d candidates, want 1; the common name took its share", got)
	}
	if got := len(set.Statements[0]); got != 3 {
		t.Errorf("linux got %d candidates, want exactly the per-key limit of 3", got)
	}
	if !set.Truncated[0] {
		t.Error("linux hit the limit and the caller was not told")
	}
	if set.Truncated[1] {
		t.Error("curl was reported truncated although all of its candidates were returned")
	}
	// The plain lookup still works for callers that do not read the report.
	plain, err := st.AffectedCandidates(ctx, []CandidateQuery{{Name: "curl"}})
	if err != nil || len(plain[0]) != 1 {
		t.Fatalf("AffectedCandidates() = %v, %v; want the one curl statement", plain, err)
	}
}

// The stored side of the purl lookup is normalised by the index expression and
// the asking side by normalisePURL. Any difference between them is a purl that
// is never found, so both are held to one table of answers.
func TestPURLLookupKeyIsTheSameInGoAndSQL(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	cases := map[string]string{
		"pkg:rpm/redhat/kernel@4.18.0-553.el8?arch=x86_64": "pkg:rpm/redhat/kernel",
		"pkg:golang/github.com/Masterminds/goutils@v1.1.0": "pkg:golang/github.com/masterminds/goutils",
		"pkg:npm/@angular/core":                            "pkg:npm/@angular/core",
		"pkg:npm/@angular/core@12.0.0#sub/path":            "pkg:npm/@angular/core",
		"pkg:golang/example.com/mod#sub/dir":               "pkg:golang/example.com/mod",
		"pkg:deb/debian/curl@7.88.1-10?arch=amd64":         "pkg:deb/debian/curl",
		// Two '@'s: the version is the last one. '@[^/]*$' cut at the first
		// in SQL while Go cut at the last, and the two keys never met.
		"pkg:npm/a@b@c": "pkg:npm/a@b",
	}
	expr := strings.Replace(purlKeyExpr, "purl", "$1::text", 1)
	for in, want := range cases {
		if got := normalisePURL(in); got != want {
			t.Errorf("normalisePURL(%q) = %q, want %q", in, got, want)
		}
		var got string
		if err := st.db.QueryRowContext(ctx, "SELECT "+expr, in).Scan(&got); err != nil {
			t.Fatalf("SQL key for %q: %v", in, err)
		}
		if got != want {
			t.Errorf("SQL key(%q) = %q, want %q", in, got, want)
		}
	}
}

// CSAF stores full purls with their version; the scanner asks with a different
// version and different letter case. Neither was found before.
func TestFullPurlsAreFoundByTheirBaseKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-5003", State: "PUBLISHED", Source: "csaf", SourceRecordID: "rhsa#CVE-2026-5003",
		Affected: []model.Affected{{
			Vendor: "redhat", Product: "kernel", Status: "affected", Source: "csaf",
			PURL: "pkg:rpm/redhat/kernel@4.18.0-553.el8?arch=x86_64",
		}, {
			Ecosystem: "Go", Product: "github.com/Masterminds/goutils", Source: "csaf",
			PURL: "pkg:golang/github.com/Masterminds/goutils@v1.1.0",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	set, err := st.FindAffectedCandidates(ctx, []CandidateQuery{
		{PURL: "pkg:rpm/redhat/kernel@4.18.0-600.el8?arch=aarch64"},
		{PURL: "pkg:golang/github.com/masterminds/goutils@v1.1.1"},
	})
	if err != nil {
		t.Fatalf("FindAffectedCandidates() error = %v", err)
	}
	for i := range []int{0, 1} {
		if len(set.Statements[i]) != 1 {
			t.Errorf("query %d found %d statements, want 1", i, len(set.Statements[i]))
		}
	}

	// The lookup must be an index lookup: with sequential scans disabled the
	// planner has to name the expression index, and it only can if the query
	// expression matches the indexed one.
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	plan := explain(t, tx, `SELECT vuln_id FROM vuln_affected WHERE purl IS NOT NULL AND `+purlKeyExpr+` = $1`,
		"pkg:rpm/redhat/kernel")
	if !strings.Contains(plan, "vuln_affected_purl_key_idx") {
		t.Errorf("purl lookup does not use the key index:\n%s", plan)
	}
}

func explain(t *testing.T, tx *sql.Tx, query string, args ...any) string {
	t.Helper()
	rows, err := tx.QueryContext(context.Background(), "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// The Linux CNA emits one statement carrying a git range next to one carrying
// only unaffected versions for the same product; keyed without the ranges the
// second overwrote the first. And the default state, which is what makes
// "only these versions are unaffected" mean anything, has to reach the scanner.
func TestStatementsThatDifferOnlyInRangesAreBothStoredWithTheirDefaultState(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-5004", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-5004",
		Affected: []model.Affected{{
			Vendor: "linux", Product: "linux kernel", Source: "cvelist", DefaultState: "affected",
			Ranges: []model.VersionRange{{Introduced: "1a2b3c", Fixed: "4d5e6f", Type: "GIT"}},
		}, {
			Vendor: "linux", Product: "linux kernel", Source: "cvelist", DefaultState: "unaffected",
			Versions: []string{"6.1.2"},
		}, {
			Vendor: "linux", Product: "linux kernel", Source: "cvelist", DefaultState: "affected",
			Ranges: []model.VersionRange{{Introduced: "6.2", Fixed: "6.2.9", Type: "SEMVER"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_affected WHERE vuln_id = 'CVE-2026-5004'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Fatalf("vuln_affected rows = %d, want 3; statements differing only in ranges collapsed", rows)
	}
	set, err := st.FindAffectedCandidates(ctx, []CandidateQuery{{Name: "linux kernel"}})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]int{}
	for _, s := range set.Statements[0] {
		states[s.DefaultState]++
	}
	if states["affected"] != 2 || states["unaffected"] != 1 {
		t.Errorf("default states returned = %v, want two affected and one unaffected", states)
	}
}

// EUVD says GHSA-x; the CVE says EUVD. The GHSA record loses the fold through
// the alias edge alone, so it is not among the CVE's identifiers, and unless
// the fold keeps it the merged record stops listing it.
func TestFoldKeepsTheLosingIdentifierAsAnAlias(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "EUVD-2026-1", State: "PUBLISHED", Source: "euvd", SourceRecordID: "EUVD-2026-1",
		Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-6001", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-6001",
		Aliases: []string{"EUVD-2026-1"},
	}); err != nil {
		t.Fatal(err)
	}
	d, err := st.GetVulnerability(ctx, "CVE-2026-6001")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, a := range d.Aliases {
		have[a] = true
	}
	if !have["GHSA-jfh8-c2jp-5v3q"] || !have["EUVD-2026-1"] {
		t.Fatalf("aliases = %v, want both the folded GHSA id and the EUVD id", d.Aliases)
	}
}

// NVD narrows a CPE configuration. The statement it withdrew must leave the
// affected table, which is where the scanner reads, not only the document.
func TestReMergingARecordRetiresItsWithdrawnRowsFromTheTables(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	wide := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, Source: "nvd"}
	narrow := model.Affected{Vendor: "acme", Product: "widget", CPEs: []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}, Source: "nvd"}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-6002", State: "PUBLISHED", Source: "nvd", SourceRecordID: "CVE-2026-6002",
		Modified:   ts("2026-01-01T00:00:00Z"),
		Affected:   []model.Affected{wide, narrow},
		References: []model.Reference{{URL: "https://example.org/gone", Source: "nvd"}},
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 5, Provider: "nvd@nist.gov", Source: "nvd"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-6002", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-6002",
		Affected: []model.Affected{{Vendor: "acme", Product: "widget", Status: "affected", Source: "cvelist"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-6002", State: "PUBLISHED", Source: "nvd", SourceRecordID: "CVE-2026-6002",
		Modified: ts("2026-02-01T00:00:00Z"),
		Affected: []model.Affected{narrow},
	}); err != nil {
		t.Fatal(err)
	}

	count := func(q string) int {
		t.Helper()
		var n int
		if err := st.db.QueryRowContext(ctx, q, "CVE-2026-6002").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM vuln_affected WHERE vuln_id = $1 AND source = 'nvd'`); n != 1 {
		t.Errorf("nvd affected rows = %d, want 1; the withdrawn configuration is still matched", n)
	}
	if n := count(`SELECT count(*) FROM vuln_affected WHERE vuln_id = $1 AND source = 'cvelist'`); n != 1 {
		t.Errorf("cvelist affected rows = %d, want 1; another source's rows were touched", n)
	}
	if n := count(`SELECT count(*) FROM vuln_reference WHERE vuln_id = $1`); n != 0 {
		t.Errorf("reference rows = %d, want the dropped reference gone", n)
	}
	if n := count(`SELECT count(*) FROM vuln_severity WHERE vuln_id = $1`); n != 0 {
		t.Errorf("severity rows = %d, want the dropped score gone", n)
	}
}

// Every collector stamps FetchedAt with the time of the run. Hashing it made
// every re-ingest a change, so the "nothing changed" guard never fired in
// production and each run appended a history row per record.
func TestARefetchOfAnUnchangedDocumentWritesNothing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: "CVE-2026-6003", Description: "d", State: "PUBLISHED",
			Modified: ts("2026-02-01T00:00:00Z"),
			Source:   "cvelist", SourceRecordID: "CVE-2026-6003",
			Affected:  []model.Affected{{Vendor: "acme", Product: "widget", Source: "cvelist"}},
			FetchedAt: time.Now().Add(time.Duration(i) * time.Hour),
		}); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	var rows int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM vuln_history WHERE vuln_id = $1`, "CVE-2026-6003").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("vuln_history rows = %d after three fetches of one unchanged document, want 1", rows)
	}
}

// A record with several CVE aliases joins to several KEV and EPSS rows. The
// propagation must pick the same one every run, or the value flips and
// updated_at moves on every sync for a record nothing touched.
func TestEnrichmentIsStableForARecordWithSeveralCVEAliases(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "GHSA-jfh8-c2jp-5v3q", State: "PUBLISHED", Source: "ghsa", SourceRecordID: "GHSA-jfh8-c2jp-5v3q",
		Aliases: []string{"CVE-2026-7001", "CVE-2026-7002"},
	}); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	epss := []model.EPSS{
		{CVEID: "CVE-2026-7001", Score: 0.1, Percentile: 0.3, ScoreDate: day},
		{CVEID: "CVE-2026-7002", Score: 0.9, Percentile: 0.99, ScoreDate: day},
	}
	early, late := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	kev := []model.KEV{
		{CVEID: "CVE-2026-7001", DateAdded: &late, Sources: []string{"cisa_kev"}, Source: "kev"},
		{CVEID: "CVE-2026-7002", DateAdded: &early, Sources: []string{"cisa_kev"}, Source: "kev"},
	}
	if err := st.UpsertEPSS(ctx, epss); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKEV(ctx, kev); err != nil {
		t.Fatal(err)
	}

	// The CVE wins the canonical id, so the row is looked up through the alias.
	read := func() (float64, time.Time, time.Time) {
		t.Helper()
		var score float64
		var added, updated time.Time
		if err := st.db.QueryRowContext(ctx, `
			SELECT v.epss_score, v.kev_date_added, v.updated_at
			  FROM vulnerabilities v JOIN vuln_aliases a ON a.vuln_id = v.id
			 WHERE a.alias = $1`,
			"GHSA-jfh8-c2jp-5v3q").Scan(&score, &added, &updated); err != nil {
			t.Fatal(err)
		}
		return score, added, updated
	}
	score, added, updated := read()
	if score != 0.9 {
		t.Errorf("epss_score = %v, want the highest of the aliases' scores as the detail endpoint reports", score)
	}
	if !added.Equal(early) {
		t.Errorf("kev_date_added = %v, want the earliest listing (%v)", added, early)
	}

	for i := 0; i < 3; i++ {
		if err := st.SyncEnrichment(ctx); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertEPSS(ctx, epss); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertKEV(ctx, kev); err != nil {
			t.Fatal(err)
		}
	}
	score2, added2, updated2 := read()
	if score2 != score || !added2.Equal(added) {
		t.Errorf("enrichment moved between identical syncs: epss %v -> %v, kev %v -> %v", score, score2, added, added2)
	}
	if !updated2.Equal(updated) {
		t.Errorf("updated_at moved from %v to %v across syncs that changed nothing", updated, updated2)
	}
}

// An entry without sources, catalogued twice: the merge of two empty arrays
// aggregates over zero rows, and array_agg over zero rows is NULL, which the
// NOT NULL column rejects — and with it the whole catalogue load.
func TestKEVUpsertToleratesEntriesWithoutSources(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	entry := []model.KEV{{CVEID: "CVE-2026-7003", Source: "kev"}}
	for i := 0; i < 2; i++ {
		if err := st.UpsertKEV(ctx, entry); err != nil {
			t.Fatalf("UpsertKEV() pass %d error = %v", i+1, err)
		}
	}
	var sources pq.StringArray
	if err := st.db.QueryRowContext(ctx, `SELECT kev_sources FROM kev WHERE cve_id = $1`, "CVE-2026-7003").Scan(&sources); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Errorf("kev_sources = %v, want empty", sources)
	}
}

func TestRefreshCPEVendorRankRebuildsTheRanking(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	seed := func(id, vendor string) {
		t.Helper()
		if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: id, State: "PUBLISHED", Source: "nvd", SourceRecordID: id,
			Affected: []model.Affected{{Vendor: vendor, Product: "nginx", Source: "nvd",
				CPEs: []string{"cpe:2.3:a:" + vendor + ":nginx:*:*:*:*:*:*:*:*"}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("CVE-2026-7004", "f5")
	seed("CVE-2026-7005", "f5")
	seed("CVE-2026-7006", "igor_sysoev")

	for i := 0; i < 2; i++ {
		if err := st.RefreshCPEVendorRank(ctx); err != nil {
			t.Fatalf("RefreshCPEVendorRank() pass %d error = %v", i+1, err)
		}
	}
	vendors, err := st.CPEVendorsFor(ctx, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if len(vendors) != 2 || vendors[0] != "f5" {
		t.Fatalf("CPEVendorsFor(nginx) = %v, want f5 first then igor_sysoev", vendors)
	}
	// The build table must not linger on the pooled connection.
	var leftover int
	if err := st.db.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_tables WHERE tablename = 'cpe_vendor_rank_build'`).Scan(&leftover); err != nil {
		t.Fatal(err)
	}
	if leftover != 0 {
		t.Error("the temporary build table survived the refresh")
	}
}

// The state filter upper-cases the column so that ?state=published matches;
// the index has to be on the same expression or the filter is a table scan.
func TestStateFilterUsesAnIndex(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
		ID: "CVE-2026-7007", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-7007",
	}); err != nil {
		t.Fatal(err)
	}
	res, err := st.ListVulnerabilities(ctx, ListFilter{States: []string{"published"}})
	if err != nil || res.Total != 1 {
		t.Fatalf("state filter = %+v, %v; want the one record regardless of case", res, err)
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	clause, args := buildWhere(ListFilter{States: []string{"PUBLISHED"}})
	plan := explain(t, tx, "SELECT v.id FROM vulnerabilities v"+clause, args...)
	if !strings.Contains(plan, "vuln_state_upper_idx") {
		t.Errorf("state filter does not use the upper(state) index:\n%s", plan)
	}
}

// A full catalogue load says what is in the catalogue and, by omission, what
// has left it. UpsertKEV only ever added, so the stale-flag statement it ran
// afterwards never found a missing row to act on and a withdrawn entry kept
// its "actively exploited" flag forever.
func TestReplaceKEVRetiresEntriesThatLeftTheCatalogue(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, id := range []string{"CVE-2026-8101", "CVE-2026-8102", "CVE-2026-8103"} {
		if _, err := st.UpsertVulnerability(ctx, &model.Vulnerability{
			ID: id, State: "PUBLISHED", Source: "cvelist", SourceRecordID: id,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	cisa := func(id string) model.KEV {
		return model.KEV{CVEID: id, CatalogVersion: "2026.09.01", Sources: []string{"cisa_kev"}, Source: "kev"}
	}
	if err := st.ReplaceKEV(ctx, []model.KEV{cisa("CVE-2026-8101"), cisa("CVE-2026-8102")}); err != nil {
		t.Fatalf("ReplaceKEV() error = %v", err)
	}
	// ENISA's consolidated list carries the third, and also the second.
	if err := st.UpsertKEV(ctx, []model.KEV{
		{CVEID: "CVE-2026-8102", Sources: []string{"cisa_kev", "eu_kev"}, Source: "euvd"},
		{CVEID: "CVE-2026-8103", Sources: []string{"eu_kev"}, Source: "euvd"},
	}); err != nil {
		t.Fatalf("UpsertKEV() error = %v", err)
	}
	for _, id := range []string{"CVE-2026-8101", "CVE-2026-8102", "CVE-2026-8103"} {
		if !kevFlag(t, st, id) {
			t.Fatalf("%s not flagged after being catalogued", id)
		}
	}

	// CISA drops both of its entries. The first was CISA's alone and goes;
	// the second is still on ENISA's list and stays; the third was never
	// CISA's to withdraw.
	if err := st.ReplaceKEV(ctx, []model.KEV{cisa("CVE-2026-8199")}); err != nil {
		t.Fatalf("ReplaceKEV() error = %v", err)
	}
	var rows int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM kev WHERE cve_id = $1`, "CVE-2026-8101").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Error("the kev row for an entry that left the catalogue is still there")
	}
	if kevFlag(t, st, "CVE-2026-8101") {
		t.Error("in_kev is still true for a CVE that left the catalogue")
	}
	if !kevFlag(t, st, "CVE-2026-8102") {
		t.Error("in_kev was cleared for a CVE ENISA still lists")
	}
	if !kevFlag(t, st, "CVE-2026-8103") {
		t.Error("in_kev was cleared for a CVE CISA never listed")
	}

	// An empty catalogue is a failed fetch, not a catalogue.
	if err := st.ReplaceKEV(ctx, nil); err == nil {
		t.Error("ReplaceKEV(nil) succeeded; it would have cleared every flag in the corpus")
	}
	if !kevFlag(t, st, "CVE-2026-8102") {
		t.Error("the refused empty catalogue still cleared a flag")
	}
}

// Two collectors delivering the first copy of one identifier at the same
// moment both resolved it to nothing, both merged from nothing, and the second
// INSERT ... ON CONFLICT DO UPDATE replaced the first's document with one that
// had never seen it. The advisory lock on the identifier serialises them, so
// the second finds the first's row and merges into it.
func TestTwoFirstWritersOfOneIdentifierBothSurvive(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// A race is not reproduced by one attempt; several rounds with a start
	// barrier make the window wide enough to fall into reliably.
	for round := 0; round < 12; round++ {
		id := fmt.Sprintf("CVE-2026-82%02d", round)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, src := range []string{"cvelist", "osv"} {
			wg.Add(1)
			go func(i int, src string) {
				defer wg.Done()
				<-start
				_, errs[i] = st.UpsertVulnerability(ctx, &model.Vulnerability{
					ID: id, State: "PUBLISHED", Source: src, SourceRecordID: id,
					References: []model.Reference{{URL: "https://" + src + ".example/" + id, Source: src}},
				})
			}(i, src)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", round, i, err)
			}
		}

		var sources pq.StringArray
		if err := st.db.QueryRowContext(ctx, `SELECT sources FROM vulnerabilities WHERE id = $1`, id).Scan(&sources); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		have := map[string]bool{}
		for _, s := range sources {
			have[s] = true
		}
		if !have["cvelist"] || !have["osv"] {
			t.Fatalf("round %d: sources = %v, want both writers' contributions; the second overwrote the first", round, sources)
		}
		d, err := st.GetVulnerability(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.References) != 2 {
			t.Fatalf("round %d: references = %+v, want one from each writer", round, d.References)
		}
	}
}
