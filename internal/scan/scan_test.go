package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// These tests need a real PostgreSQL, because the candidate lookup is half the
// behaviour under test and stubbing it out would only prove the stub works.
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_USER=cvefeed \
//	    -e POSTGRES_DB=cvefeed -p 55432:5432 postgres:16-alpine
//	CVEFEED_TEST_DATABASE_URL='postgres://cvefeed:test@localhost:55432/cvefeed?sslmode=disable' \
//	    go test ./internal/scan/
func testScanner(t *testing.T) *Scanner {
	t.Helper()
	dsn := os.Getenv("CVEFEED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CVEFEED_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	dsn, err := isolatedSchema(ctx, dsn, "cvefeed_test_scan")
	if err != nil {
		t.Fatalf("isolate test schema: %v", err)
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	for _, tbl := range []string{
		"vuln_history", "vuln_affected", "vuln_reference", "vuln_severity",
		"vuln_aliases", "epss", "kev", "raw_records", "vulnerabilities",
	} {
		if _, err := st.DB().ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatalf("clear %s: %v", tbl, err)
		}
	}
	return &Scanner{Store: st}
}

func seed(t *testing.T, s *Scanner, v *model.Vulnerability) {
	t.Helper()
	if _, err := s.Store.UpsertVulnerability(context.Background(), v); err != nil {
		t.Fatalf("seed %s: %v", v.ID, err)
	}
}

func TestScanFindsAnAffectedPackageAndSparesThePatchedOne(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0001", State: "PUBLISHED", Source: "osv", SourceRecordID: "CVE-2026-0001",
		Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 9.8, Rating: "CRITICAL", Source: "osv"}},
		Affected: []model.Affected{{
			Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
			Status: model.StatusAffected, Source: "osv",
		}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "marked", Version: "4.0.9", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.9", Origin: "test"},
		{Name: "marked", Version: "4.0.10", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.10", Origin: "test"},
	}, Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want exactly one (the patched build must not match)", len(report.Findings))
	}
	f := report.Findings[0]
	if f.Component.Version != "4.0.9" {
		t.Errorf("matched %s, want the vulnerable 4.0.9", f.Component.Version)
	}
	if f.Evidence.Confidence != match.Confirmed {
		t.Errorf("confidence = %q, want confirmed for an exact purl and an ordered range", f.Evidence.Confidence)
	}
	if f.Vulnerability.Rating != "CRITICAL" {
		t.Errorf("rating = %q; the finding must carry the severity a caller prioritises on", f.Vulnerability.Rating)
	}
	if f.Evidence.Reason == "" {
		t.Error("no reason recorded; a finding that cannot be audited will not be believed")
	}
}

// The corpus is full of statements whose bounds are prose. They must not become
// findings, and they must not disappear either.
func TestScanRefusesAnUnorderableBoundInsteadOfGuessing(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0002", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-0002",
		Affected: []model.Affected{{
			Vendor: "acme", Product: "widget",
			// Taken from the shape of real CVE List records: the fix field
			// holds a sentence rather than a version.
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "Upgrade to the latest version.", Type: "CUSTOM"}},
			Status: model.StatusAffected, Source: "cvelist",
		}},
	})

	comp := []match.Component{{Name: "widget", Version: "1.2.3", Vendor: "acme", Origin: "test"}}

	report, err := s.Scan(ctx, comp, Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want none: the bound is not a version", len(report.Findings))
	}

	report, err = s.Scan(ctx, comp, Options{IncludeUndecidable: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Undecidable) == 0 {
		t.Fatal("the statement vanished entirely; an operator auditing coverage needs to see it")
	}
	if len(report.Findings) != 0 {
		t.Error("an undecidable statement leaked into the findings")
	}
}

func TestScanGradesAWeakIdentityDown(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0003", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-0003",
		Affected: []model.Affected{{
			Product: "openssl",
			Ranges:  []model.VersionRange{{Introduced: "3.0.0", Fixed: "3.0.15", Type: "SEMVER"}},
			Status:  model.StatusAffected, Source: "cvelist",
		}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "openssl", Version: "3.0.7", Origin: "test"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want one", len(report.Findings))
	}
	if got := report.Findings[0].Evidence.Confidence; got != match.Possible {
		t.Fatalf("confidence = %q, want possible: a bare product name is not evidence of identity", got)
	}

	// And the default floor keeps it out of a report the operator acts on.
	report, err = s.Scan(ctx, []match.Component{
		{Name: "openssl", Version: "3.0.7", Origin: "test"},
	}, Options{MinConfidence: match.Probable})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("findings = %d at min-confidence probable, want none", len(report.Findings))
	}
}

func TestScanOrdersKnownExploitationFirst(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	for _, id := range []string{"CVE-2026-0010", "CVE-2026-0011"} {
		seed(t, s, &model.Vulnerability{
			ID: id, State: "PUBLISHED", Source: "osv", SourceRecordID: id,
			Severities: []model.Severity{{Type: "CVSS_V3_1", Score: 5.0, Rating: "MEDIUM", Source: "osv"}},
			Affected: []model.Affected{{
				Ecosystem: "npm", Product: "left-pad", PURL: "pkg:npm/left-pad",
				Ranges: []model.VersionRange{{Introduced: "0", Fixed: "9.9.9", Type: "SEMVER"}},
				Status: model.StatusAffected, Source: "osv",
			}},
		})
	}
	// The second one is known to be exploited in the wild.
	if err := s.Store.UpsertKEV(ctx, []model.KEV{
		{CVEID: "CVE-2026-0011", Sources: []string{"cisa_kev"}, Source: "kev"},
	}); err != nil {
		t.Fatalf("UpsertKEV() error = %v", err)
	}

	report, err := s.Scan(ctx, []match.Component{
		{Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/left-pad@1.0.0", Origin: "test"},
	}, Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
	if report.Findings[0].Vulnerability.ID != "CVE-2026-0011" {
		t.Fatalf("first finding = %s, want the KEV entry: exploitation outranks everything else",
			report.Findings[0].Vulnerability.ID)
	}
}

// A statement that says the product is NOT affected must never produce a
// finding, whatever the version comparison says.
func TestScanHonoursANotAffectedStatement(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0004", State: "PUBLISHED", Source: "csaf", SourceRecordID: "CVE-2026-0004",
		Affected: []model.Affected{{
			Ecosystem: "npm", Product: "safe-pkg", PURL: "pkg:npm/safe-pkg",
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "9.9.9", Type: "SEMVER"}},
			Status: model.StatusNotAffected, Source: "csaf",
		}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "safe-pkg", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/safe-pkg@1.0.0", Origin: "test"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want none: the vendor asserted this product is not affected",
			len(report.Findings))
	}
}

func TestScanOfAnEmptyInventoryIsNotAnError(t *testing.T) {
	s := testScanner(t)
	report, err := s.Scan(context.Background(), nil, Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 0 || report.Components != 0 {
		t.Fatalf("report = %+v, want an empty one", report)
	}
	if report.Notice == "" {
		t.Error("no attribution notice on the report")
	}
}

// One vulnerability can be described by several statements about the same
// component — a CVE List entry, an OSV entry and an NVD entry for one package —
// and reporting each of them would print the same finding several times over.
// The report is a list of things to fix, and one thing to fix is one line.
func TestOneVulnerabilityOnOneComponentIsOneFinding(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	// The same flaw, stated by three sources, each with its own identity path.
	for _, src := range []string{"osv", "nvd", "cvelist"} {
		seed(t, s, &model.Vulnerability{
			ID: "CVE-2026-7001", State: "PUBLISHED", Source: src, SourceRecordID: "CVE-2026-7001/" + src,
			Affected: []model.Affected{{
				Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
				Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
				Status: model.StatusAffected, Source: src,
			}},
		})
	}

	report, err := s.Scan(ctx, []match.Component{
		{Name: "marked", Version: "4.0.9", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.9", Origin: "netscan:10.0.0.1:80"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 {
		for _, f := range report.Findings {
			t.Logf("  %s from %s", f.Vulnerability.ID, f.Statement.Source)
		}
		t.Fatalf("findings = %d, want 1: three statements about one flaw on one component", len(report.Findings))
	}
}

// The same software at two versions on two ports is two components, and a
// vulnerability affecting both is two findings — one per service to fix.
func TestTheSameProductOnTwoPortsIsTwoFindings(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-7002", State: "PUBLISHED", Source: "nvd", SourceRecordID: "CVE-2026-7002",
		Affected: []model.Affected{{
			Vendor: "openbsd", Product: "openssh",
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "9.9", Type: "SEMVER"}},
			Status: model.StatusAffected, Source: "nvd",
		}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "openssh", Version: "8.9p1", Vendor: "openbsd", Origin: "netscan:10.0.0.1:22"},
		{Name: "openssh", Version: "8.4p1", Vendor: "openbsd", Origin: "netscan:10.0.0.1:2222"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: two services, each with its own version", len(report.Findings))
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		seen[f.Component.Origin] = true
	}
	if len(seen) != 2 {
		t.Errorf("both findings came from the same service: %v", seen)
	}
}

// A vendor's negative statement is the VEX assertion the format exists to
// carry, and it outranks a positive from another source about the same
// vulnerability on the same component.
func TestANegativeStatementFromOneSourceRetiresAMatchFromAnother(t *testing.T) {
	comp := match.Component{Name: "marked", Version: "4.0.9", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.9", Origin: "test"}
	positive := store.AffectedStatement{
		VulnID: "CVE-2026-0030", Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
		Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
		Status: model.StatusAffected, Source: "osv",
	}
	vex := store.AffectedStatement{
		VulnID: "CVE-2026-0030", Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
		Versions: []string{"4.0.9"}, Status: "known_not_affected", Source: "csaf",
	}

	for _, order := range [][]store.AffectedStatement{{positive, vex}, {vex, positive}} {
		v := evaluateComponent(comp, order, match.Possible, true)
		if len(v.matched) != 0 {
			t.Fatalf("matched = %d, want none: the vendor retired this vulnerability for this build", len(v.matched))
		}
		if len(v.suppressed) != 1 {
			t.Fatalf("suppressed = %d, want the retired finding kept for audit", len(v.suppressed))
		}
		f := v.suppressed[0]
		if f.Statement.Source != "osv" || f.Vulnerability.ID != "CVE-2026-0030" {
			t.Errorf("suppressed finding is %s from %s, want the osv match", f.Vulnerability.ID, f.Statement.Source)
		}
		if !strings.Contains(f.Evidence.Reason, "csaf") {
			t.Errorf("the suppressed finding does not name the statement that retired it: %s", f.Evidence.Reason)
		}
	}

	// A negative statement that does not cover the installed build retires
	// nothing: it carries no information about this component.
	elsewhere := vex
	elsewhere.Versions = []string{"4.0.8"}
	if v := evaluateComponent(comp, []store.AffectedStatement{positive, elsewhere}, match.Possible, true); len(v.matched) != 1 || len(v.suppressed) != 0 {
		t.Fatalf("a negative about another build: matched = %d, suppressed = %d, want 1/0", len(v.matched), len(v.suppressed))
	}

	// Nor does a negative about a different vulnerability.
	other := vex
	other.VulnID = "CVE-2026-0031"
	if v := evaluateComponent(comp, []store.AffectedStatement{positive, other}, match.Possible, true); len(v.matched) != 1 {
		t.Fatalf("a negative about another vulnerability: matched = %d, want 1", len(v.matched))
	}

	// The open questions about a retired vulnerability are retired with it:
	// the vendor answered them.
	question := store.AffectedStatement{
		VulnID: "CVE-2026-0030", Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
		Ranges: []model.VersionRange{{Introduced: "0", Fixed: "see the advisory", Type: "CUSTOM"}},
		Status: model.StatusAffected, Source: "cvelist",
	}
	if v := evaluateComponent(comp, []store.AffectedStatement{question, vex}, match.Possible, true); len(v.undecided) != 0 {
		t.Fatalf("undecided = %d, want none once the vendor has answered", len(v.undecided))
	}
	if v := evaluateComponent(comp, []store.AffectedStatement{question}, match.Possible, true); len(v.undecided) != 1 {
		t.Fatalf("undecided = %d without the vendor's answer, want 1", len(v.undecided))
	}
}

func TestScanReportsAMatchTheVendorRetiredAsSuppressed(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-7003", State: "PUBLISHED", Source: "osv", SourceRecordID: "CVE-2026-7003/osv",
		Affected: []model.Affected{{
			Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
			Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
			Status: model.StatusAffected, Source: "osv",
		}},
	})
	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-7003", State: "PUBLISHED", Source: "csaf", SourceRecordID: "CVE-2026-7003/csaf",
		Affected: []model.Affected{{
			Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
			Versions: []string{"4.0.9"},
			Status:   model.StatusNotAffected, Source: "csaf",
		}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "marked", Version: "4.0.9", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.9", Origin: "test"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want none: the vendor says 4.0.9 is not affected", len(report.Findings))
	}
	if len(report.Suppressed) != 1 || report.Suppressed[0].Vulnerability.ID != "CVE-2026-7003" {
		t.Fatalf("suppressed = %+v, want the retired osv finding", report.Suppressed)
	}
}

// A vendor's negative outranks a positive only when it is at least as well
// founded. A CSAF row naming "acme"/"marked" with no purl, ecosystem or CPE
// matched a purl-identified npm package on nothing but the product name, and
// used to silence OSV's confirmed finding about it — one loosely named product
// per vendor was a blanket exemption for every package that shared its name.
func TestANegativeStatementRetiresOnlyAMatchItOutweighs(t *testing.T) {
	comp := match.Component{Name: "marked", Version: "4.0.9", Ecosystem: "npm", PURL: "pkg:npm/marked@4.0.9", Origin: "test"}
	confirmed := store.AffectedStatement{
		VulnID: "CVE-2026-0040", Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
		Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
		Status: model.StatusAffected, Source: "osv",
	}
	weakNegative := store.AffectedStatement{
		VulnID: "CVE-2026-0040", Vendor: "acme", Product: "marked",
		Versions: []string{"4.0.9"}, Status: "known_not_affected", Source: "csaf",
	}
	strongNegative := store.AffectedStatement{
		VulnID: "CVE-2026-0040", Ecosystem: "npm", Product: "marked", PURL: "pkg:npm/marked",
		Versions: []string{"4.0.9"}, Status: "known_not_affected", Source: "csaf",
	}

	// Weak negative against a confirmed match: the match stands, and the
	// negative is on the record for whoever reads the reason.
	for _, order := range [][]store.AffectedStatement{{confirmed, weakNegative}, {weakNegative, confirmed}} {
		v := evaluateComponent(comp, order, match.Possible, true)
		if len(v.matched) != 1 || len(v.suppressed) != 0 {
			t.Fatalf("weak negative: matched = %d, suppressed = %d, want 1/0: a bare-name row is not the vendor speaking about this purl", len(v.matched), len(v.suppressed))
		}
		f := v.matched[0]
		if f.Evidence.Confidence != match.Confirmed {
			t.Errorf("the surviving finding is %q, want confirmed", f.Evidence.Confidence)
		}
		if !strings.Contains(f.Evidence.Reason, "csaf") || !strings.Contains(f.Evidence.Reason, "not taken") {
			t.Errorf("the finding does not record the negative it declined: %s", f.Evidence.Reason)
		}
		if f.RetiredBy != nil {
			t.Error("a finding that stands must not name a retiring statement")
		}
	}

	// Strong negative against the same match: retired, and the report says
	// by which statement.
	v := evaluateComponent(comp, []store.AffectedStatement{confirmed, strongNegative, weakNegative}, match.Possible, true)
	if len(v.matched) != 0 || len(v.suppressed) != 1 {
		t.Fatalf("strong negative: matched = %d, suppressed = %d, want 0/1", len(v.matched), len(v.suppressed))
	}
	if r := v.suppressed[0].RetiredBy; r == nil || r.Source != "csaf" || r.PURL != "pkg:npm/marked" {
		t.Errorf("retired_by = %+v, want the purl-identified csaf statement, not the bare-name one", r)
	}

	// A weak negative does outweigh an equally weak positive: ties go to the
	// vendor, which is the VEX reading this scanner exists to honour.
	weakPositive := store.AffectedStatement{
		VulnID: "CVE-2026-0040", Vendor: "acme", Product: "marked",
		Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.0.10", Type: "SEMVER"}},
		Status: model.StatusAffected, Source: "cvelist",
	}
	bare := match.Component{Name: "marked", Version: "4.0.9", Origin: "test"}
	v = evaluateComponent(bare, []store.AffectedStatement{weakPositive, weakNegative}, match.Possible, true)
	if len(v.matched) != 0 || len(v.suppressed) != 1 {
		t.Fatalf("equal grades: matched = %d, suppressed = %d, want 0/1", len(v.matched), len(v.suppressed))
	}
}

// The store caps how many statements one lookup key returns. A component that
// hit the cap was tested against a sample of the corpus, and the report has to
// say so by name or "nothing found" for it reads as "nothing there".
func TestReportNamesAComponentWhoseCandidatesWereTruncated(t *testing.T) {
	s := testScanner(t)
	ctx := context.Background()

	// The store's limit is not reachable from here, so the corpus is made big
	// enough to hit it: one statement per version, all under one product name.
	const over = 2001
	linux := make([]model.Affected, 0, over)
	for i := 0; i < over; i++ {
		linux = append(linux, model.Affected{
			Vendor: "linux", Product: "linux", Versions: []string{fmt.Sprintf("6.%d", i)},
			Status: model.StatusAffected, Source: "cvelist",
		})
	}
	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0050", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-0050",
		Affected: linux,
	})
	seed(t, s, &model.Vulnerability{
		ID: "CVE-2026-0051", State: "PUBLISHED", Source: "cvelist", SourceRecordID: "CVE-2026-0051",
		Affected: []model.Affected{{Vendor: "haxx", Product: "curl", Versions: []string{"8.0.0"}, Status: model.StatusAffected, Source: "cvelist"}},
	})

	report, err := s.Scan(ctx, []match.Component{
		{Name: "linux", Version: "6.0", Origin: "test"},
		{Name: "curl", Version: "8.0.0", Origin: "test"},
	}, Options{MinConfidence: match.Possible})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Truncated) != 1 || report.Truncated[0] != "linux 6.0" {
		t.Fatalf("truncated = %v, want exactly the component whose candidates were cut, named with its version", report.Truncated)
	}
}
