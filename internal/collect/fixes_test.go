package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
)

// ------------------------------------------------------------------- GCVE

// Vulnerability-Lookup pages newest-first under a fixed since= date and a run
// is bounded to vlMaxPages pages. Restarting every run from page 1 read the
// same newest thousand records over and over and never reached the rest of
// the window: with more records than one run can cover, the collector could
// never finish and its cursor never moved.
func TestGCVEResumesAnOpenWindowAcrossRuns(t *testing.T) {
	const total = vlMaxPages*vlPageSize + 60
	records := make([]string, total)
	for i := range records {
		records[i] = fmt.Sprintf(`{"gcve_id":"GCVE-1-2026-%04d","summary":"s"}`, i)
	}
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		u, err := url.Parse(req.URL)
		if err != nil {
			return nil, err
		}
		if u.Host == "gcve.eu" {
			return textResponse(req, `[]`, nil), nil
		}
		page, _ := strconv.Atoi(u.Query().Get("page"))
		per, _ := strconv.Atoi(u.Query().Get("per_page"))
		if page < 1 || per < 1 {
			return nil, fmt.Errorf("bad paging in %s", req.URL)
		}
		start := min((page-1)*per, total)
		end := min(start+per, total)
		return textResponse(req, "["+strings.Join(records[start:end], ",")+"]", nil), nil
	}

	c := &GCVECollector{BaseURL: "https://vl.example"}
	cursor := map[string]string{}
	seen := map[string]bool{}

	r, sink := newTestRun(t, ModeDelta, ff, cursor)
	if err := c.Run(context.Background(), r); err != nil {
		t.Fatalf("first run: %v; hitting the page ceiling is pacing, not failure", err)
	}
	for _, id := range sink.seen() {
		seen[id] = true
	}
	if got := ff.count("/api/vulnerability/"); got != vlMaxPages {
		t.Fatalf("first run read %d pages, want exactly the %d-page ceiling", got, vlMaxPages)
	}
	if cursor["last_run"] != "" {
		t.Fatalf("last_run = %q after an incomplete walk; the window is not covered yet", cursor["last_run"])
	}
	if cursor["vl_page"] != fmt.Sprint(vlMaxPages+1) {
		t.Fatalf("vl_page = %q, want the walk to resume at page %d", cursor["vl_page"], vlMaxPages+1)
	}

	ff.reset()
	r, sink = newTestRun(t, ModeDelta, ff, cursor)
	if err := c.Run(context.Background(), r); err != nil {
		t.Fatalf("second run: %v", err)
	}
	for _, id := range sink.seen() {
		seen[id] = true
	}
	if len(seen) != total {
		t.Fatalf("two runs covered %d of %d records; the walk did not resume past the ceiling", len(seen), total)
	}
	// 60 records past the ceiling are two full pages and one short one.
	if got := ff.count("/api/vulnerability/"); got != 3 {
		t.Errorf("second run read %d pages, want the remaining 3 rather than the window from page 1", got)
	}
	if cursorTime(cursor, "last_run") == nil {
		t.Error("last_run not set after the window was fully read")
	}
	for _, k := range []string{"vl_since", "vl_page", "vl_started"} {
		if _, ok := cursor[k]; ok {
			t.Errorf("%s survived a completed walk", k)
		}
	}
}

// The watermark of a completed walk is the walk's start, not its end: a record
// updated while later pages were being read sits on page 1, which was already
// passed, and only a window starting at the walk's start sees it again.
func TestGCVEWatermarkIsTheWalkStart(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		return textResponse(req, `[]`, nil), nil
	}
	started := time.Now().UTC().Add(-2 * time.Hour)
	cursor := map[string]string{}
	vlSetResume(cursor, started.AddDate(0, 0, -30), 3, started)

	r, _ := newTestRun(t, ModeDelta, ff, cursor)
	if err := (&GCVECollector{BaseURL: "https://vl.example"}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := cursorTime(cursor, "last_run"); got == nil || !got.Equal(started) {
		t.Fatalf("last_run = %v, want the resumed walk's start %v", got, started)
	}
	if ff.count("page=3") != 1 {
		t.Errorf("resumed walk did not continue at page 3: %v", ff.calls)
	}
}

// ---------------------------------------------------------------- CVE List

// The baseline asset is the 00:00Z snapshot; the release tag is when the
// release was published, up to a day later. Resting the cursor on the tag hour
// skipped every change between midnight and the tag, permanently.
func TestCVEListBaselineCursorRestsOnTheMidnightCut(t *testing.T) {
	record := []byte(`{"cveMetadata":{"cveId":"CVE-2026-1234","state":"PUBLISHED"},"containers":{"cna":{}}}`)
	inner := zipBytes(t, map[string][]byte{"cves/2026/1xxx/CVE-2026-1234.json": record})
	outer := zipBytes(t, map[string][]byte{"cves.zip": inner})

	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		switch req.URL {
		case cvelistReleaseAPI:
			return textResponse(req, `{
			  "tag_name":"cve_2026-08-18_2200Z","published_at":"2026-08-18T22:05:00Z",
			  "assets":[{"name":"2026-08-18_all_CVEs_at_midnight.zip.zip",
			             "browser_download_url":"https://github.example/asset.zip.zip"}]}`, nil), nil
		case "https://github.example/asset.zip.zip":
			return bytesResponse(req, outer), nil
		}
		return unknownURL(req)
	}

	r, sink := newTestRun(t, ModeBackfill, ff, nil)
	if err := (&CVEListCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if ids := sink.seen(); len(ids) != 1 || ids[0] != "CVE-2026-1234" {
		t.Fatalf("emitted %v, want the one baseline record", ids)
	}
	want := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	if got := cursorTime(r.Cursor, "last_delta"); got == nil || !got.Equal(want) {
		t.Fatalf("last_delta = %v, want the asset's midnight cut %v, not the release tag hour", got, want)
	}
}

func TestBaselineCutTimePrefersTheEarlierOfTagAndMidnight(t *testing.T) {
	midnight := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		tag, asset string
		want       time.Time
	}{
		{"cve_2026-08-18_2200Z", "2026-08-18_all_CVEs_at_midnight.zip.zip", midnight},
		{"cve_2026-08-17_2300Z", "2026-08-18_all_CVEs_at_midnight.zip.zip", time.Date(2026, 8, 17, 23, 0, 0, 0, time.UTC)},
		{"cve_2026-08-18_1000Z", "all_CVEs_at_midnight.zip.zip", time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)},
		{"garbage", "2026-08-18_all_CVEs_at_midnight.zip.zip", midnight},
		{"garbage", "nothing", time.Time{}},
	}
	for _, tc := range cases {
		if got := baselineCutTime(tc.tag, tc.asset); !got.Equal(tc.want) {
			t.Errorf("baselineCutTime(%q, %q) = %v, want %v", tc.tag, tc.asset, got, tc.want)
		}
	}
}

// delta.json describes the newest publication run and deltaLog.json repeats
// it as its first element. Without merging the two by fetchTime every record
// of the newest run was fetched and emitted twice whenever the log was read.
func TestCVEListDeltaFetchesEachRecordOncePerRun(t *testing.T) {
	now := time.Now().UTC()
	stamp := func(t time.Time) string { return t.Format("2006-01-02T15:04:05.000Z") }
	newest, older := now.Add(-time.Hour).Truncate(time.Millisecond), now.Add(-90*time.Minute).Truncate(time.Millisecond)

	newestRun := fmt.Sprintf(`{"fetchTime":%q,"numberOfChanges":1,
	  "new":[{"cveId":"CVE-2026-1","githubLink":"https://raw.example/CVE-2026-1.json"}],"updated":[]}`, stamp(newest))
	olderRun := fmt.Sprintf(`{"fetchTime":%q,"numberOfChanges":1,"new":[],
	  "updated":[{"cveId":"CVE-2026-2","githubLink":"https://raw.example/CVE-2026-2.json"}]}`, stamp(older))

	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		switch req.URL {
		case cvelistDelta:
			return textResponse(req, newestRun, nil), nil
		case cvelistDeltaLog:
			return textResponse(req, "["+newestRun+","+olderRun+"]", nil), nil
		case "https://raw.example/CVE-2026-1.json":
			return textResponse(req, `{"cveMetadata":{"cveId":"CVE-2026-1","state":"PUBLISHED"}}`, nil), nil
		case "https://raw.example/CVE-2026-2.json":
			return textResponse(req, `{"cveMetadata":{"cveId":"CVE-2026-2","state":"PUBLISHED"}}`, nil), nil
		}
		return unknownURL(req)
	}

	cursor := map[string]string{}
	setCursorTime(cursor, "last_delta", now.Add(-2*time.Hour))
	r, sink := newTestRun(t, ModeDelta, ff, cursor)
	if err := (&CVEListCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := ff.count("CVE-2026-1.json"); got != 1 {
		t.Errorf("CVE-2026-1 fetched %d times, want once; delta.json and the log describe the same run", got)
	}
	if ids := sink.seen(); len(ids) != 2 {
		t.Errorf("emitted %v, want each record once", ids)
	}
	if got := cursorTime(cursor, "last_delta"); got == nil || !got.Equal(newest) {
		t.Errorf("last_delta = %v, want the newest run's fetchTime %v at full precision", got, newest)
	}
}

// --------------------------------------------------------------------- NVD

func nvdPage(records ...string) string {
	return fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":0,"totalResults":%d,"vulnerabilities":[%s]}`,
		len(records), len(records), strings.Join(records, ","))
}

// A backfill walks the whole corpus with no date filter, so a record modified
// after its page was read is only covered by the next delta. The newest
// lastModified seen says nothing about that boundary: one late record on the
// last page hid every earlier page's changes behind it.
func TestNVDBackfillCursorRestsOnTheWalkStart(t *testing.T) {
	late := time.Now().UTC().Add(48 * time.Hour)
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		return textResponse(req, nvdPage(
			`{"cve":{"id":"CVE-2026-1","lastModified":"2026-08-01T00:00:00.000"}}`,
			fmt.Sprintf(`{"cve":{"id":"CVE-2026-2","lastModified":%q}}`, late.Format("2006-01-02T15:04:05.000")),
		), nil), nil
	}

	before := time.Now().UTC()
	r, sink := newTestRun(t, ModeBackfill, ff, nil)
	if err := (&NVDCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(sink.seen()) != 2 {
		t.Fatalf("emitted %v", sink.seen())
	}
	got := cursorTime(r.Cursor, "last_modified")
	if got == nil {
		t.Fatal("last_modified not set")
	}
	lo, hi := before.Add(-nvdBackfillOverlap), time.Now().UTC().Add(-nvdBackfillOverlap)
	if got.Before(lo) || got.After(hi) {
		t.Fatalf("last_modified = %v, want the walk start minus the overlap (between %v and %v)", got, lo, hi)
	}
	for _, k := range []string{"backfill_index", "backfill_started"} {
		if _, ok := r.Cursor[k]; ok {
			t.Errorf("%s survived a completed walk", k)
		}
	}
}

// A resumed walk keeps the start of the first attempt: pages read before the
// interruption are just as stale as they would be in one long walk.
func TestNVDResumedBackfillKeepsTheOriginalStart(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		return textResponse(req, nvdPage(`{"cve":{"id":"CVE-2026-1","lastModified":"2026-08-01T00:00:00.000"}}`), nil), nil
	}
	started := time.Now().UTC().Add(-36 * time.Hour).Truncate(time.Millisecond)
	cursor := map[string]string{"backfill_index": "0"}
	setCursorTime(cursor, "backfill_started", started)

	r, _ := newTestRun(t, ModeBackfill, ff, cursor)
	if err := (&NVDCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := started.Add(-nvdBackfillOverlap)
	if got := cursorTime(cursor, "last_modified"); got == nil || !got.Equal(want) {
		t.Fatalf("last_modified = %v, want the original start minus the overlap %v", got, want)
	}
}

// -------------------------------------------------------------------- CSAF

// A changes.csv that parsed is authoritative even when nothing in it is newer
// than the cursor. Treating "nothing new" as "no changes.csv" re-downloaded
// the provider's whole index on every quiet run.
func TestCSAFDirectoryKeepsAnEmptyChangesCSVRatherThanFallingBackToTheIndex(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		switch {
		case strings.HasSuffix(req.URL, "/changes.csv"):
			return textResponse(req, "\"2024/rhsa-2024_0001.json\",\"2024-01-01T00:00:00Z\"\n", nil), nil
		case strings.HasSuffix(req.URL, "/index.txt"):
			return textResponse(req, "2024/rhsa-2024_0001.json\n2023/rhsa-2023_0001.json\n", nil), nil
		}
		return unknownURL(req)
	}
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r, _ := newTestRun(t, ModeDelta, ff, nil)
	got, err := (&CSAFCollector{}).directoryEntries(context.Background(), r, "https://csaf.example/advisories", &since)
	if err != nil {
		t.Fatalf("directoryEntries() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("entries = %v, want none: nothing in changes.csv is newer than the cursor", got)
	}
	if ff.count("index.txt") != 0 {
		t.Fatal("index.txt was fetched although changes.csv was readable; that re-downloads the whole corpus")
	}
}

func TestCSAFDirectoryFallsBackToTheIndexOnlyWithoutAUsableChangesCSV(t *testing.T) {
	for name, changes := range map[string]*string{
		"missing":      nil,
		"unparseable":  ptr("<html>not a csv</html>"),
		"no json rows": ptr("README.txt,2026-01-01T00:00:00Z\n"),
	} {
		t.Run(name, func(t *testing.T) {
			ff := &fakeFetcher{}
			ff.handle = func(req httpx.Request) (*httpx.Response, error) {
				switch {
				case strings.HasSuffix(req.URL, "/changes.csv") && changes != nil:
					return textResponse(req, *changes, nil), nil
				case strings.HasSuffix(req.URL, "/index.txt"):
					return textResponse(req, "2024/rhsa-2024_0001.json\n", nil), nil
				}
				return unknownURL(req)
			}
			since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			r, _ := newTestRun(t, ModeDelta, ff, nil)
			got, err := (&CSAFCollector{}).directoryEntries(context.Background(), r, "https://csaf.example/advisories", &since)
			if err != nil {
				t.Fatalf("directoryEntries() error = %v", err)
			}
			if _, ok := got["https://csaf.example/advisories/2024/rhsa-2024_0001.json"]; !ok || len(got) != 1 {
				t.Fatalf("entries = %v, want the index.txt listing", got)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// CSAF 2.1 advisories put a v4 and a v3 score in the same scores[] entry for
// the same products. Choosing one dropped the other.
func TestParseCSAFKeepsBothV3AndV4FromOneScoresEntry(t *testing.T) {
	raw := []byte(`{
	  "document":{"title":"X","publisher":{"name":"Vendor"},"tracking":{"id":"VSA-1","version":"1"}},
	  "vulnerabilities":[{"cve":"CVE-2026-1","scores":[{
	     "cvss_v3":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
	     "cvss_v4":{"baseScore":8.7,"baseSeverity":"HIGH","vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
	     "products":["P1"]}]}]
	}`)
	out := parseCSAF(raw, "csaf", "")
	if len(out) != 1 {
		t.Fatalf("parseCSAF() produced %d records", len(out))
	}
	types := map[string]bool{}
	for _, s := range out[0].Severities {
		types[s.Type] = true
	}
	if !types["CVSS_V4_0"] || !types["CVSS_V3_1"] {
		t.Fatalf("severity types = %v, want both the v4 and the v3 statement", types)
	}
}

// --------------------------------------------------------------------- KEV

// When the catalogue body arrives with an unchanged catalogVersion there is
// nothing to apply, but the response still carried a fresh ETag. Not saving it
// left the next run's If-None-Match stale, so the 3 MB catalogue was pulled on
// every run for as long as the version stayed put.
func TestKEVSavesAFreshETagWhenTheCatalogVersionIsUnchanged(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		if req.URL != kevURLs[0] {
			return unknownURL(req)
		}
		hdr := http.Header{}
		hdr.Set("ETag", `"fresh"`)
		return textResponse(req, `{"catalogVersion":"2026.08.14","dateReleased":"2026-08-14T00:00:00Z","count":1,
		  "vulnerabilities":[{"cveID":"CVE-2026-1","dateAdded":"2026-08-14"}]}`, hdr), nil
	}
	cursor := map[string]string{"catalog_version": "2026.08.14", "etag_" + kevURLs[0]: `"stale"`}
	r, sink := newTestRun(t, ModeDelta, ff, cursor)
	if err := (&KEVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if sink.kevCalls != 0 {
		t.Errorf("catalogue applied %d times although its version had not moved", sink.kevCalls)
	}
	if got := cursor["etag_"+kevURLs[0]]; got != `"fresh"` {
		t.Fatalf("etag = %q, want the fresh validator saved so the next run can get a 304", got)
	}
}

// The runner persists the cursor even when Run fails. An ETag saved before
// the sink call therefore survived a failed store, and the next run sent
// If-None-Match with the new validator, got a 304 and never applied the
// catalogue the sink had rejected — until CISA changed the file again.
func TestKEVKeepsTheOldETagWhenTheSinkFails(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		if req.URL != kevURLs[0] {
			return unknownURL(req)
		}
		if req.IfNoneMatch == `"fresh"` {
			return &httpx.Response{
				URL: req.URL, Status: http.StatusNotModified, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader("")), NotModified: true, ETag: `"fresh"`,
			}, nil
		}
		hdr := http.Header{}
		hdr.Set("ETag", `"fresh"`)
		return textResponse(req, `{"catalogVersion":"2026.08.15","dateReleased":"2026-08-15T00:00:00Z","count":1,
		  "vulnerabilities":[{"cveID":"CVE-2026-2","dateAdded":"2026-08-15"}]}`, hdr), nil
	}
	cursor := map[string]string{"catalog_version": "2026.08.14", "etag_" + kevURLs[0]: `"stale"`}
	r, sink := newTestRun(t, ModeDelta, ff, cursor)
	sink.kevErr = errors.New("disk full")

	if err := (&KEVCollector{}).Run(context.Background(), r); err == nil {
		t.Fatal("Run() = nil, want the store failure reported")
	}
	if got := cursor["etag_"+kevURLs[0]]; got != `"stale"` {
		t.Fatalf("etag = %q after a failed store, want the old validator kept so the next run fetches again", got)
	}
	if got := cursor["catalog_version"]; got != "2026.08.14" {
		t.Fatalf("catalog_version = %q after a failed store, want the old one", got)
	}

	// The next run, with the cursor the runner persisted, must apply the
	// catalogue rather than be told 304.
	sink.kevErr = nil
	if err := (&KEVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if len(sink.kev) != 1 {
		t.Fatalf("second run stored %d entries, want the catalogue applied", len(sink.kev))
	}
	if got := cursor["etag_"+kevURLs[0]]; got != `"fresh"` {
		t.Errorf("etag = %q after a successful store, want the fresh validator", got)
	}
	if got := cursor["catalog_version"]; got != "2026.08.15" {
		t.Errorf("catalog_version = %q, want the applied version", got)
	}
}

// ------------------------------------------------------------------ cursor

// `ingest -since` rewinds by rewriting timestamp-valued cursor entries, but
// GCVE's resume state is a bare date and a page number. Both survived the
// replay, so the next run resumed the old window at the old page instead of
// starting over from the replay instant.
func TestReplayCursorRewindsAnOpenGCVEWalk(t *testing.T) {
	cursor := map[string]string{}
	vlSetResume(cursor,
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), 7,
		time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC))
	replayCursor(cursor, time.Date(2025, 3, 11, 0, 0, 0, 0, time.UTC))
	if since, page, _, ok := vlResume(cursor); ok {
		t.Fatalf("vlResume() = (%v, %d, ok) after a replay; the open walk must be discarded", since, page)
	}
}

// Upstream timestamps carry milliseconds. A cursor rounded down to the second
// sits just before the last record it covers, so that record — and for the
// CVE List the whole last publication run — was re-fetched on every run.
func TestCursorTimeKeepsSubSecondPrecision(t *testing.T) {
	cursor := map[string]string{}
	want := time.Date(2026, 8, 18, 10, 30, 0, 123_000_000, time.UTC)
	setCursorTime(cursor, "last_modified", want)
	got := cursorTime(cursor, "last_modified")
	if got == nil || !got.Equal(want) {
		t.Fatalf("cursorTime() = %v, want %v with its milliseconds intact", got, want)
	}
	// Whole seconds still read back, and replayCursor still recognises the
	// value as a timestamp.
	if got := cursorTime(map[string]string{"k": "2026-08-18T10:30:00Z"}, "k"); got == nil {
		t.Fatal("a whole-second cursor written by an older build no longer parses")
	}
	replayCursor(cursor, time.Date(2025, 3, 11, 0, 0, 0, 0, time.UTC))
	if cursor["last_modified"] != "2025-03-11T00:00:00Z" {
		t.Fatalf("replayCursor left %q; a nanosecond cursor was not recognised as a timestamp", cursor["last_modified"])
	}
}

// ---------------------------------------------------------------- StoreSink

// Between "is the sink closed?" and "count me as in flight" Close could see
// zero in-flight sends, close the queue, and the caller then sent on a closed
// channel — a panic that took the whole ingest down. The two must be one
// atomic step.
func TestStoreSinkCloseNeverRacesASendOntoAClosedQueue(t *testing.T) {
	for i := 0; i < 300; i++ {
		s := &StoreSink{Workers: 2, QueueDepth: 4, persistFn: func(context.Context, *model.Vulnerability) {}}
		v := &model.Vulnerability{ID: "CVE-2026-1"}
		if err := s.Vulnerability(context.Background(), v); err != nil {
			t.Fatalf("Vulnerability() error = %v", err)
		}

		var wg sync.WaitGroup
		panics := make(chan any, 8)
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if p := recover(); p != nil {
						panics <- p
					}
				}()
				for {
					if err := s.Vulnerability(context.Background(), v); err != nil {
						return
					}
				}
			}()
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		wg.Wait()
		select {
		case p := <-panics:
			t.Fatalf("iteration %d: a sender panicked: %v", i, p)
		default:
		}
	}
}

// ------------------------------------------------------------------- fetch

type eofTracker struct {
	io.Reader
	sawEOF bool
}

func (e *eofTracker) Read(p []byte) (int, error) {
	n, err := e.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		e.sawEOF = true
	}
	return n, err
}

func (e *eofTracker) Close() error { return nil }

// A recording body finalises its bundle entry on the read path when it sees
// EOF; json.Decoder never asks for it, so fetchJSON reads on to the end.
func TestFetchJSONReadsThroughToEOF(t *testing.T) {
	body := &eofTracker{Reader: strings.NewReader(`{"ok":true}` + "\n")}
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		return &httpx.Response{URL: req.URL, Status: 200, Header: http.Header{}, Body: body}, nil
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := fetchJSON(context.Background(), ff, "https://example.org/x.json", &out); err != nil {
		t.Fatalf("fetchJSON() error = %v", err)
	}
	if !out.OK {
		t.Fatal("decoded nothing")
	}
	if !body.sawEOF {
		t.Fatal("the body was closed before EOF; a recorder on the read path never saw the document end")
	}
}

// --------------------------------------------------------------------- zip

// A member over the cap used to be cut off at the cap and handed on as if it
// were complete. A truncated JSON document parses as garbage at best.
func TestReadZipMemberRefusesAnOversizedMemberRatherThanTruncating(t *testing.T) {
	path := writeZip(t, "big.zip", map[string][]byte{
		"big.json":   []byte(strings.Repeat("x", 100)),
		"small.json": []byte(`{"ok":true}`),
	})
	zr, err := openZip(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		data, err := readZipMemberLimit(f, 64)
		switch f.Name {
		case "big.json":
			if err == nil {
				t.Fatalf("a %d-byte member read under a 64-byte cap returned %d bytes and no error", 100, len(data))
			}
		case "small.json":
			if err != nil || string(data) != `{"ok":true}` {
				t.Fatalf("small member: data=%q err=%v", data, err)
			}
		}
	}
}

// keep json imported for fixtures that decode fake pages
var _ = json.Valid

// CISA's catalogue is loaded as a whole, so the sink can retire what left it;
// ENISA's consolidated dump mirrors other catalogues and may lag them, so it
// must only add. Loading the dump as a catalogue would drop an entry CISA
// added an hour ago.
func TestOnlyTheOwningCollectorLoadsAKEVCatalogue(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		switch {
		case req.URL == kevURLs[0]:
			return textResponse(req, `{"catalogVersion":"2026.09.01","dateReleased":"2026-09-01T00:00:00Z","count":1,
			  "vulnerabilities":[{"cveID":"CVE-2026-1","dateAdded":"2026-09-01"}]}`, http.Header{}), nil
		case strings.HasSuffix(req.URL, "/kev/dump"):
			return textResponse(req, `[{"cveId":"CVE-2026-2","dateAdded":"2026-09-01","sources":["cisa_kev"]}]`, http.Header{}), nil
		}
		return unknownURL(req)
	}
	r, sink := newTestRun(t, ModeDelta, ff, map[string]string{})
	if err := (&KEVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("KEVCollector.Run() error = %v", err)
	}
	if sink.kevCatalogueCalls != 1 {
		t.Fatalf("CISA catalogue loaded as a catalogue %d times, want 1", sink.kevCatalogueCalls)
	}

	r2, sink2 := newTestRun(t, ModeDelta, ff, map[string]string{})
	if err := (&EUVDCollector{}).kevDump(context.Background(), r2); err != nil {
		t.Fatalf("kevDump() error = %v", err)
	}
	if sink2.kevCatalogueCalls != 0 {
		t.Fatalf("the consolidated dump was loaded as a catalogue; it must only add")
	}
	if sink2.kevCalls != 1 {
		t.Fatalf("dump applied %d times, want 1", sink2.kevCalls)
	}
}

// ------------------------------------------------------- future timestamps

// An upstream timestamp in the future is a typo, not a fact, and the store
// compares against it: PYSEC-2025-19 was published with modified 2027-07-09
// and froze every later update of CVE-2025-1889 as "older". Emit drops it and
// leaves the sane timestamps alone.
func TestEmitDropsTimestampsFromTheFuture(t *testing.T) {
	future := time.Now().UTC().Add(futureSlack + time.Hour)
	recent := time.Now().UTC().Add(-time.Hour)
	r, sink := newTestRun(t, ModeDelta, &fakeFetcher{}, nil)
	v := &model.Vulnerability{
		ID: "CVE-2025-1889", Source: "gcve", SourceRecordID: "PYSEC-2025-19",
		Modified: &future, Published: &recent,
	}
	if err := r.Emit(context.Background(), v); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	if v.Modified != nil {
		t.Errorf("Modified = %v, want dropped", v.Modified)
	}
	if v.Published == nil || !v.Published.Equal(recent) {
		t.Errorf("Published = %v, want %v untouched", v.Published, recent)
	}
	if len(sink.seen()) != 1 {
		t.Errorf("emitted %v, want the record", sink.seen())
	}
}

// The OSV watermark is derived from the archive's own modified stamps, so one
// record dated in the future would carry it past every real change and the
// newest-first delta walk would then stop before reading any of them.
func TestOSVBackfillWatermarkNeverPassesTheRunStart(t *testing.T) {
	future := time.Now().UTC().Add(365 * 24 * time.Hour)
	archive := zipBytes(t, map[string][]byte{
		"PYSEC-2025-19.json": []byte(fmt.Sprintf(`{"id":"PYSEC-2025-19","modified":%q,"aliases":["CVE-2025-1889"]}`,
			future.Format(time.RFC3339))),
		"GHSA-aaaa-bbbb-cccc.json": []byte(`{"id":"GHSA-aaaa-bbbb-cccc","modified":"2026-08-01T00:00:00Z"}`),
	})
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		if strings.HasSuffix(req.URL, "all.zip") {
			return bytesResponse(req, archive), nil
		}
		return unknownURL(req)
	}

	before := time.Now().UTC()
	r, sink := newTestRun(t, ModeBackfill, ff, nil)
	if err := (&OSVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(sink.seen()) != 2 {
		t.Fatalf("emitted %v, want both records", sink.seen())
	}
	got := cursorTime(r.Cursor, "last_modified")
	if got == nil {
		t.Fatal("last_modified not set")
	}
	lo, hi := before.Add(-osvOverlap), time.Now().UTC().Add(-osvOverlap)
	if got.Before(lo) || got.After(hi) {
		t.Fatalf("last_modified = %v, want the run start minus the overlap (between %v and %v)", got, lo, hi)
	}
}

// ---------------------------------------------------------- NVD empty page

// An empty page before totalResults is a broken response, not the end of the
// walk. Taking it as the end dropped the resume index and declared a backfill
// complete with most of the corpus unread.
func TestNVDEmptyPageBeforeTheTotalHoldsTheResumeIndex(t *testing.T) {
	ff := &fakeFetcher{}
	ff.handle = func(req httpx.Request) (*httpx.Response, error) {
		u, _ := url.Parse(req.URL)
		if u.Query().Get("startIndex") == "0" {
			return textResponse(req, `{"resultsPerPage":1,"startIndex":0,"totalResults":3,"vulnerabilities":[{"cve":{"id":"CVE-2026-1","lastModified":"2026-08-01T00:00:00.000"}}]}`, nil), nil
		}
		return textResponse(req, `{"resultsPerPage":0,"startIndex":1,"totalResults":3,"vulnerabilities":[]}`, nil), nil
	}
	r, sink := newTestRun(t, ModeBackfill, ff, nil)
	if err := (&NVDCollector{}).Run(context.Background(), r); err == nil {
		t.Fatal("Run() = nil, want an error for an empty page before the total")
	}
	if len(sink.seen()) != 1 {
		t.Fatalf("emitted %v, want the one record the first page carried", sink.seen())
	}
	if got := r.Cursor["backfill_index"]; got != "1" {
		t.Errorf("backfill_index = %q, want 1 so the empty page is asked for again", got)
	}
	if _, ok := r.Cursor["last_modified"]; ok {
		t.Error("last_modified was placed on a walk that did not complete")
	}
}
