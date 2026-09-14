package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/00gxd14g/cvefeed/internal/config"
	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/scan"
	"github.com/00gxd14g/cvefeed/internal/store"
)

func TestParseFilterDefaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/vulns", nil)
	f, err := parseFilter(r)
	if err != nil {
		t.Fatalf("parseFilter() error = %v", err)
	}
	if f.Text != "" || f.Limit != 0 || f.Offset != 0 || f.KEVOnly {
		t.Errorf("unexpected non-zero defaults: %+v", f)
	}
}

func TestParseFilterFullQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet,
		"/v1/vulns?kev=true&epss_min=0.5&modified_since=2026-08-10&score_min=7&score_max=10"+
			"&rating=HIGH,CRITICAL&source=nvd,cvelist&cwe=CWE-79&limit=25&offset=50&q=widget"+
			"&vendor=siemens&product=widget&ecosystem=Maven&cpe=cpe:2.3:a&purl=pkg:maven/x&order_by=modified",
		nil)
	f, err := parseFilter(r)
	if err != nil {
		t.Fatalf("parseFilter() error = %v", err)
	}
	if !f.KEVOnly {
		t.Error("KEVOnly = false, want true")
	}
	if f.EPSSMin == nil || *f.EPSSMin != 0.5 {
		t.Errorf("EPSSMin = %v, want 0.5", f.EPSSMin)
	}
	if f.ScoreMin == nil || *f.ScoreMin != 7 {
		t.Errorf("ScoreMin = %v, want 7", f.ScoreMin)
	}
	if f.ScoreMax == nil || *f.ScoreMax != 10 {
		t.Errorf("ScoreMax = %v, want 10", f.ScoreMax)
	}
	if f.ModifiedSince == nil || f.ModifiedSince.Format("2006-01-02") != "2026-08-10" {
		t.Errorf("ModifiedSince = %v", f.ModifiedSince)
	}
	if len(f.Ratings) != 2 || f.Ratings[0] != "HIGH" || f.Ratings[1] != "CRITICAL" {
		t.Errorf("Ratings = %v", f.Ratings)
	}
	if len(f.Sources) != 2 {
		t.Errorf("Sources = %v", f.Sources)
	}
	if f.Limit != 25 || f.Offset != 50 {
		t.Errorf("Limit/Offset = %d/%d, want 25/50", f.Limit, f.Offset)
	}
	if f.Text != "widget" || f.Vendor != "siemens" || f.Product != "widget" || f.Ecosystem != "Maven" {
		t.Errorf("text fields wrong: %+v", f)
	}
}

func TestParseFilterInvalidValues(t *testing.T) {
	cases := []string{
		"/v1/vulns?score_min=notanumber",
		"/v1/vulns?epss_min=notanumber",
		"/v1/vulns?modified_since=not-a-date",
		"/v1/vulns?limit=0",
		"/v1/vulns?limit=abc",
		"/v1/vulns?offset=-1",
	}
	for _, target := range cases {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := parseFilter(r); err == nil {
			t.Errorf("parseFilter(%s) expected an error", target)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Errorf("splitCSV(\"\") = %v, want nil", got)
	}
	got := splitCSV("a, b ,,c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("abcdefghij", 5); got != "abcde…" {
		t.Errorf("truncate long = %q", got)
	}
}

func TestFmtTime(t *testing.T) {
	if got := fmtTime(nil); got != "" {
		t.Errorf("fmtTime(nil) = %q, want empty", got)
	}
	tm := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := fmtTime(&tm); got != "2024-01-02T03:04:05Z" {
		t.Errorf("fmtTime = %q", got)
	}
}

func TestAuthMiddleware(t *testing.T) {
	s := &Server{cfg: &config.Config{APIToken: "secret"}, log: slog.Default()}
	called := false
	next := func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }
	handler := s.auth(next)

	// Missing token is rejected.
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/v1/vulns", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if called {
		t.Error("handler ran without a valid token")
	}

	// Wrong token is rejected.
	called = false
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/vulns", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	handler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}

	// Correct token passes through.
	called = false
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/v1/vulns", nil)
	r.Header.Set("Authorization", "Bearer secret")
	handler(w, r)
	if !called {
		t.Error("handler did not run with a valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestAuthMiddlewareOpenWhenNoTokenConfigured(t *testing.T) {
	s := &Server{cfg: &config.Config{APIToken: ""}, log: slog.Default()}
	called := false
	handler := s.auth(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/vulns", nil))
	if !called {
		t.Error("handler did not run when no API token is configured")
	}
}

func TestHandleHealth(t *testing.T) {
	s := New(nil, &config.Config{}, slog.Default())
	w := httptest.NewRecorder()
	s.handleHealth(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %v, want ok", body["status"])
	}
}

func TestHandleIndex(t *testing.T) {
	s := New(nil, &config.Config{}, slog.Default())
	w := httptest.NewRecorder()
	s.handleIndex(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestBearerTokenRequiresTheScheme(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer secret", "secret", true},
		{"bearer secret", "secret", true}, // RFC 7235: the scheme is case-insensitive
		{"BEARER secret", "secret", true},
		{"secret", "", false}, // a bare token is not a bearer credential
		{"Basic secret", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := bearerToken(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Errorf("bearerToken(%q) = %q/%v, want %q/%v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCanonicalURLPerIdentifierNamespace(t *testing.T) {
	cases := map[string]string{
		"CVE-2021-44228":      "https://www.cve.org/CVERecord?id=CVE-2021-44228",
		"GHSA-jfh8-c2jp-5v3q": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
		"EUVD-2025-23900":     "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-23900",
		"GCVE-1-2026-1":       "https://vulnerability.circl.lu/vuln/GCVE-1-2026-1",
		"PYSEC-2025-19":       "https://osv.dev/vulnerability/PYSEC-2025-19",
	}
	for id, want := range cases {
		if got := canonicalURL(id); got != want {
			t.Errorf("canonicalURL(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestTruncateDoesNotSplitARune(t *testing.T) {
	// "ü" is two bytes; cutting at an odd offset used to emit invalid UTF-8.
	s := strings.Repeat("ü", 10)
	got := truncate(s, 5)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate() produced invalid UTF-8: %q", got)
	}
}

func TestCSVSafeNeutralisesFormulas(t *testing.T) {
	for _, in := range []string{"=cmd|'/c calc'!A1", "+1+1", "-1", "@SUM(A1)"} {
		if got := csvSafe(in); got[0] != '\'' {
			t.Errorf("csvSafe(%q) = %q, want a leading quote", in, got)
		}
	}
	if got := csvSafe("CVE-2021-44228"); got != "CVE-2021-44228" {
		t.Errorf("csvSafe() altered ordinary text: %q", got)
	}
}

func TestParseFilterRejectsBadValues(t *testing.T) {
	cases := []string{
		"/v1/vulns?limit=100000",  // above the documented cap
		"/v1/vulns?order_by=drop", // not an ordering the store knows
		"/v1/vulns?rating=SPICY",  // not a CVSS band
		"/v1/vulns?kev=maybe",     // not a boolean
	}
	for _, target := range cases {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := parseFilter(r); err == nil {
			t.Errorf("parseFilter(%s) = nil error, want a 400-worthy rejection", target)
		}
	}
}

func TestParseFilterAcceptsStateFilter(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/vulns?state=PUBLISHED,REJECTED", nil)
	f, err := parseFilter(r)
	if err != nil {
		t.Fatalf("parseFilter() error = %v", err)
	}
	if len(f.States) != 2 {
		t.Fatalf("states = %v, want two", f.States)
	}
}

// Handler() must be constructible: Go's ServeMux panics at registration time on
// conflicting patterns, which no handler-level test would ever reach.
func TestHandlerRoutesAreRegisterable(t *testing.T) {
	s := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.Handler()
	if h == nil {
		t.Fatal("Handler() = nil")
	}

	// The index answers, and an unknown path under it does not.
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/", http.StatusOK},
		{"/nope", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}

// An unknown /v1 path must be refused before it reveals anything about which
// endpoints exist.
func TestUnknownV1PathIsAuthenticated(t *testing.T) {
	s := New(nil, &config.Config{APIToken: "secret"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/does-not-exist", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /v1/does-not-exist = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/does-not-exist", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("authenticated GET /v1/does-not-exist = %d, want 404", rec.Code)
	}
}

// The index carries the notice NIST asks every NVD API consumer to display.
func TestIndexCarriesTheNVDNotice(t *testing.T) {
	s := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("index is not JSON: %v", err)
	}
	if body["notice"] != store.NVDNotice {
		t.Fatalf("notice = %v, want the NVD sentence", body["notice"])
	}
}

// The CLI and the HTTP API are two doors onto one scanner, and they must not
// disagree about what a caller who expressed no preference gets. The scan
// package's editorial rule is that the default reports only what was proven;
// leaving Options.MinConfidence zero opts into `possible` instead, which on the
// project's own fixture turns 65 findings into 321 by admitting 256 matches
// that rest on a bare product name.
func TestScanEndpointDefaultsToTheSameFloorAsTheCommand(t *testing.T) {
	if scan.DefaultMinConfidence != match.Probable {
		t.Fatalf("DefaultMinConfidence = %q, want probable", scan.DefaultMinConfidence)
	}
	// The command's flag default and the API's implicit default are the same
	// constant, so they cannot drift apart in one place only.
	opt, err := scanOptionsFromQueryErr(url.Values{})
	if err != nil {
		t.Fatalf("an empty query was refused: %v", err)
	}
	if opt.MinConfidence != scan.DefaultMinConfidence {
		t.Errorf("API default = %q, want %q", opt.MinConfidence, scan.DefaultMinConfidence)
	}
}

func TestScanEndpointStillHonoursAnExplicitFloor(t *testing.T) {
	opt, err := scanOptionsFromQueryErr(url.Values{"min_confidence": {"possible"}})
	if err != nil {
		t.Fatalf("min_confidence=possible was refused: %v", err)
	}
	if opt.MinConfidence != match.Possible {
		t.Errorf("min_confidence=possible gave %q", opt.MinConfidence)
	}
}

// The log line that says a scan was requested is the operator's record of
// what this service was made to connect to. Written before the engine was
// validated, it recorded a scan for requests that were refused, and the
// record then said a host had been scanned when nothing was ever sent to it.
func TestARequestRefusedForItsEngineIsNotLoggedAsAScan(t *testing.T) {
	var buf bytes.Buffer
	srv := New(nil, &config.Config{TargetScanEnabled: true},
		slog.New(slog.NewTextHandler(&buf, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/scan/target",
		strings.NewReader(`{"host":"127.0.0.1","ports":"22","engine":"bogus"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown engine", w.Code)
	}
	if strings.Contains(buf.String(), "target scan requested") {
		t.Errorf("a refused request was logged as a scan:\n%s", buf.String())
	}
}

// GET /v1/vulns/{id}/history for an identifier the corpus has never seen is
// a 404, not an empty change log: `{"entries": []}` tells the caller the
// record exists and has never changed, which is the opposite of the truth.
// The store answers the existence question, so this needs a real one.
//
//	CVEFEED_TEST_DATABASE_URL='postgres://cvefeed:test@localhost:5432/cvefeed?sslmode=disable' \
//	    go test ./internal/api/
func TestHistoryOfAnUnknownRecordIsNotFound(t *testing.T) {
	dsn := os.Getenv("CVEFEED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CVEFEED_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	dsn, err := isolatedSchema(ctx, dsn, "cvefeed_test_api")
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

	srv := New(st, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/v1/vulns/CVE-1999-99999/history", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an identifier the corpus has never seen; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "CVE-1999-99999 not found") {
		t.Errorf("body = %s, want it to name the identifier that was not found", w.Body.String())
	}
}

// isolatedSchema puts this package's tables in a schema of its own, the way
// the store's own tests do: `go test ./...` runs packages concurrently, and
// two packages migrating and clearing one schema fail in ways that look like
// product defects.
func isolatedSchema(ctx context.Context, dsn, schema string) (string, error) {
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		return "", err
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		return "", fmt.Errorf("create schema %s: %w", schema, err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// The endpoint makes the service connect to a host the caller names, which is a
// capability nothing else in this API has. It must be off unless an operator
// turned it on, and it must say so rather than failing obscurely.
func TestTargetScanIsOffUnlessEnabled(t *testing.T) {
	srv := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/scan/target",
		strings.NewReader(`{"host":"127.0.0.1","ports":"22"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 while target scanning is disabled", w.Code)
	}
	if !strings.Contains(w.Body.String(), "CVEFEED_TARGET_SCAN_ENABLED") {
		t.Errorf("body = %s, want it to name the switch that turns this on", w.Body.String())
	}
}

// A port list large enough to be a sweep is refused, because borrowing a
// shared service's network position for one is a different operation from
// scanning a host.
func TestTargetScanRefusesASweep(t *testing.T) {
	srv := New(nil, &config.Config{TargetScanEnabled: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/scan/target",
		strings.NewReader(`{"host":"127.0.0.1","ports":"1-65535"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a full sweep", w.Code)
	}
}

func TestTargetScanRequiresAHost(t *testing.T) {
	srv := New(nil, &config.Config{TargetScanEnabled: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/scan/target", strings.NewReader(`{"ports":"22"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 without a host", w.Code)
	}
}

// exportRecords builds a stream source that yields n records and then fails
// with failWith (nil for a clean end). It stands in for a store whose query
// breaks at a chosen row, which no real database does on request.
func exportRecords(n int, failWith error) streamFunc {
	return func(_ context.Context, _ store.ListFilter, fn func(*store.ExportRecord) error) error {
		for i := 0; i < n; i++ {
			rec := &store.ExportRecord{}
			rec.ID = fmt.Sprintf("CVE-2024-%04d", i+1)
			rec.Title = "record " + strconv.Itoa(i+1)
			if err := fn(rec); err != nil {
				return err
			}
		}
		return failWith
	}
}

// serveExport runs the export handler and reports whether it broke the
// connection, which net/http expresses as a panic with http.ErrAbortHandler.
func serveExport(t *testing.T, s *Server, target string) (rec *httptest.ResponseRecorder, aborted bool) {
	t.Helper()
	rec = httptest.NewRecorder()
	func() {
		defer func() {
			switch v := recover(); v {
			case nil:
			case http.ErrAbortHandler:
				aborted = true
			default:
				t.Fatalf("handler panicked with %v, want http.ErrAbortHandler or nothing", v)
			}
		}()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	}()
	return rec, aborted
}

func exportServer(stream streamFunc) *Server {
	s := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.stream = stream
	return s
}

// A query that fails before its first row has committed nothing to the wire,
// so the client can still be told in the status line. Answering 200 with a
// marker appended to an empty body made a database outage look like an empty
// corpus to anyone checking the status alone.
func TestExportThatFailsBeforeAnyRowIsAServerError(t *testing.T) {
	for _, format := range []string{"ndjson", "csv"} {
		s := exportServer(exportRecords(0, errors.New("connection reset")))
		rec, aborted := serveExport(t, s, "/v1/export?format="+format)
		if aborted {
			t.Errorf("%s: connection was broken although a status could still be sent", format)
		}
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500", format, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q, want the JSON error body's", format, ct)
		}
		if cd := rec.Header().Get("Content-Disposition"); cd != "" {
			t.Errorf("%s: an error body is still offered as a download: %q", format, cd)
		}
		if strings.Contains(rec.Body.String(), "id,state") {
			t.Errorf("%s: the CSV header leaked into the error body: %s", format, rec.Body.String())
		}
	}
}

// Once rows are out the status is spent. The remaining signal is the marker
// and a connection that does not end cleanly; a client that sees a normal end
// of stream has no reason to look for a marker.
func TestExportThatFailsMidStreamMarksAndBreaksTheConnection(t *testing.T) {
	s := exportServer(exportRecords(3, errors.New("connection reset")))
	rec, aborted := serveExport(t, s, "/v1/export")
	if !aborted {
		t.Fatal("the connection ended cleanly after a truncated export")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 that was already committed", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"CVE-2024-0003"`) {
		t.Errorf("rows written before the failure are missing:\n%s", body)
	}
	if !strings.Contains(body, `"error":"export truncated: connection reset"`) {
		t.Errorf("no truncation marker in the body:\n%s", body)
	}
}

// The csv.Writer buffers; writing the marker straight to the response put it
// in front of the rows it was meant to follow, and a reader saw a truncation
// notice at the top of a file whose rows then continued as if nothing were
// wrong. Enough rows to spill the writer's buffer, so that some of them have
// really reached the client and the status is spent.
func TestExportCSVFlushesRowsBeforeTheTruncationMarker(t *testing.T) {
	s := exportServer(exportRecords(400, errors.New("connection reset")))
	rec, aborted := serveExport(t, s, "/v1/export?format=csv")
	if !aborted {
		t.Fatal("the connection ended cleanly after a truncated export")
	}
	body := rec.Body.String()
	lastRow := strings.Index(body, "CVE-2024-0400")
	marker := strings.Index(body, "export truncated")
	if lastRow < 0 || marker < 0 {
		t.Fatalf("body lacks a row or the marker:\n%s", body)
	}
	if marker < lastRow {
		t.Errorf("the marker precedes the last row:\n%s", body)
	}
	if !strings.HasPrefix(body, "id,state,published") {
		t.Errorf("the header is not first:\n%s", body)
	}
}

// "Rows written" is not "bytes sent". The csv.Writer holds 4 KB before it
// writes anything, so a stream that failed on its third row had committed
// nothing to the wire — the header and rows were still in memory, the status
// line was still free — and the client was nonetheless sent a 200 with a
// marker on the end, when it could have been told plainly.
func TestExportCSVThatFailsWhileStillBufferedIsAServerError(t *testing.T) {
	s := exportServer(exportRecords(3, errors.New("connection reset")))
	rec, aborted := serveExport(t, s, "/v1/export?format=csv")
	if aborted {
		t.Fatal("the connection was broken although nothing had reached the client")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: nothing had been sent, so the status line was still free", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "id,state,published") || strings.Contains(body, "CVE-2024-0001") {
		t.Errorf("buffered rows leaked into the error response:\n%s", body)
	}
	if !strings.Contains(body, "export failed") {
		t.Errorf("body = %s, want the error", body)
	}
	if rec.Header().Get("Content-Disposition") != "" {
		t.Error("an error body is offered as a download")
	}
}

// Every body carries upstream text, so every format needs the sniffing guard,
// not only JSON.
func TestExportAndFeedResponsesDisableContentSniffing(t *testing.T) {
	for _, target := range []string{"/v1/export", "/v1/export?format=csv"} {
		s := exportServer(exportRecords(1, nil))
		rec, aborted := serveExport(t, s, target)
		if aborted || rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, aborted = %v", target, rec.Code, aborted)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", target, got)
		}
	}
	// A clean CSV export ends with its rows flushed and no marker.
	s := exportServer(exportRecords(1, nil))
	rec, _ := serveExport(t, s, "/v1/export?format=csv")
	if body := rec.Body.String(); !strings.Contains(body, "CVE-2024-0001") || strings.Contains(body, "truncated") {
		t.Errorf("clean CSV export body:\n%s", body)
	}
}

// deadlineWriter is a ResponseWriter that can take a read deadline, as the
// real net/http one can. It records what it was given.
type deadlineWriter struct {
	http.ResponseWriter
	deadline time.Time
}

func (d *deadlineWriter) SetReadDeadline(t time.Time) error {
	d.deadline = t
	return nil
}

// http.ResponseController finds SetReadDeadline by unwrapping the writer it is
// handed. The logging middleware wraps every handler's writer, so without an
// Unwrap on the wrapper the body-read deadline was never armed on any request
// that came through the server.
func TestStatusRecorderLetsTheResponseControllerReachTheRealWriter(t *testing.T) {
	inner := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	wrapped := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	limitBodyRead(wrapped)
	if inner.deadline.IsZero() {
		t.Fatal("the read deadline never reached the underlying writer")
	}
	if remaining := time.Until(inner.deadline); remaining <= 0 || remaining > bodyReadTimeout {
		t.Errorf("deadline is %v away, want within %v", remaining, bodyReadTimeout)
	}

	// A writer with no deadline support is served anyway; the deadline is a
	// bound, not a requirement.
	limitBodyRead(&statusRecorder{ResponseWriter: httptest.NewRecorder()})
}

// A request that was deliberately aborted is the one most worth a log line,
// and a log call sequenced after ServeHTTP never ran for it.
func TestLoggingRecordsARequestThatBrokeItsConnection(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	h := logging(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("panic = %v, want http.ErrAbortHandler to propagate", v)
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/export", nil))
	}()
	if !strings.Contains(buf.String(), "path=/v1/export") {
		t.Errorf("the aborted request was not logged: %q", buf.String())
	}
}

// The API's rule is that an out-of-range limit is a 400, not a silent clamp:
// a client paging on the number it asked for would otherwise skip entries.
// Both checks run before the store is touched, which is why a nil store
// serves here.
func TestOutOfRangeLimitsAreRejectedNotClamped(t *testing.T) {
	s := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.Handler()
	for _, target := range []string{
		"/v1/vulns/CVE-2024-0001/history?limit=501",
		"/v1/feed.atom?limit=201",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", target, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "limit must be at most") {
			t.Errorf("GET %s body = %s, want it to name the ceiling", target, rec.Body.String())
		}
	}
}

// The index is how a client discovers the surface; an endpoint it does not
// list is one nobody finds.
func TestIndexListsEveryEndpoint(t *testing.T) {
	s := New(nil, &config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var body struct {
		Endpoints []string `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("index is not JSON: %v", err)
	}
	listed := map[string]bool{}
	for _, e := range body.Endpoints {
		listed[e] = true
	}
	for _, want := range []string{"POST /v1/scan", "POST /v1/scan/target", "GET /v1/feed.atom"} {
		if !listed[want] {
			t.Errorf("index does not list %q: %v", want, body.Endpoints)
		}
	}
}

// A misspelled filter used to be ignored, and the caller got the whole
// unfiltered corpus with a 200 in place of the filtered page they asked for.
func TestParseFilterRejectsUnknownParameters(t *testing.T) {
	for _, target := range []string{
		"/v1/vulns?severity=HIGH",
		"/v1/vulns?published_from=2026-01-01",
		"/v1/vulns?limit=10&sort=score",
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		_, err := parseFilter(r)
		if err == nil {
			t.Errorf("parseFilter(%s) = nil error, want a rejection", target)
			continue
		}
		if !strings.Contains(err.Error(), "unknown query parameter") {
			t.Errorf("parseFilter(%s) error = %q, want it to name the unknown parameter", target, err)
		}
	}
}

// Every enumerated or typed filter refuses a value outside its vocabulary,
// the way README promises; state and source used to return an empty page.
func TestParseFilterRejectsInvalidEnumsAndRanges(t *testing.T) {
	cases := []string{
		"/v1/vulns?state=bogus",
		"/v1/vulns?source=bogus",
		"/v1/vulns?source=nvd,bogus",
		"/v1/vulns?score_min=11",
		"/v1/vulns?score_max=-1",
		"/v1/vulns?epss_min=2",
		"/v1/vulns?score_min=8&score_max=7",
		"/v1/vulns?q=a%00b",
		"/v1/vulns?published_since=nope",
	}
	for _, target := range cases {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := parseFilter(r); err == nil {
			t.Errorf("parseFilter(%s) = nil error, want a 400-worthy rejection", target)
		}
	}
	ok := "/v1/vulns?state=published,WITHDRAWN&source=nvd,ghsa&score_min=0&score_max=10&epss_min=0.5&format=csv"
	if _, err := parseFilter(httptest.NewRequest(http.MethodGet, ok, nil)); err != nil {
		t.Errorf("parseFilter(%s) refused a valid query: %v", ok, err)
	}
}

func TestScanOptionsRejectBadBooleanAndUnknownParameters(t *testing.T) {
	if _, err := scanOptionsFromQueryErr(url.Values{"undecidable": {"yes"}}); err == nil {
		t.Error("undecidable=yes was accepted")
	}
	if _, err := scanOptionsFromQueryErr(url.Values{"min_confidance": {"possible"}}); err == nil {
		t.Error("a misspelled option was ignored")
	}
	opt, err := scanOptionsFromQueryErr(url.Values{"undecidable": {"true"}})
	if err != nil || !opt.IncludeUndecidable {
		t.Errorf("undecidable=true: opt=%+v err=%v", opt, err)
	}
}

// A record identifier PostgreSQL cannot take is a bad request, not a query
// failure: the server used to answer 500 for a NUL byte in the path.
func TestNULInAnIdentifierIsABadRequest(t *testing.T) {
	s := &Server{cfg: &config.Config{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := s.Handler()
	for _, path := range []string{"/v1/vulns/CVE-2021-1%00", "/v1/vulns/CVE-2021-1%00/history"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", path, rec.Code)
		}
	}
}

// An export format nobody serves is refused, not quietly answered as NDJSON.
func TestExportRefusesAnUnknownFormat(t *testing.T) {
	s := &Server{cfg: &config.Config{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/export?format=xml", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("format=xml = %d, want 400: %s", rec.Code, rec.Body)
	}
}
