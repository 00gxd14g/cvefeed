package airgap

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
)

// writeEvilArchive builds a tar.gz containing a single entry whose name
// escapes the extraction root, simulating a maliciously crafted bundle.
func writeEvilArchive(path string) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	content := []byte("escaped")
	if err := tw.WriteHeader(&tar.Header{
		Name: "../escape.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func TestRecordThenFetchRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}

	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("ETag", `"v1"`)
	if err := rec.Record("https://example.org/a.json", hdr, 200, strings.NewReader(`{"ok":true}`)); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	n, size := rec.Stats()
	if n != 1 {
		t.Errorf("entry count = %d, want 1", n)
	}
	if size != int64(len(`{"ok":true}`)) {
		t.Errorf("total bytes = %d, want %d", size, len(`{"ok":true}`))
	}

	f, err := NewFetcher(dir, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	resp, err := f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json"})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
	if !resp.FromBundle {
		t.Error("FromBundle = false, want true")
	}
	if resp.ETag != `"v1"` {
		t.Errorf("ETag = %q, want v1", resp.ETag)
	}
}

func TestFetchConditionalNotModified(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	hdr := http.Header{}
	hdr.Set("ETag", `"v1"`)
	if err := rec.Record("https://example.org/a.json", hdr, 200, strings.NewReader("data")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	resp, err := f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json", IfNoneMatch: `"v1"`})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	if !resp.NotModified {
		t.Error("NotModified = false, want true")
	}
}

func TestFetchMissingURLWithoutAcceptNotFound(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	_, err = f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/missing.json"})
	if err == nil {
		t.Fatal("expected an error for a URL absent from the bundle")
	}
}

func TestFetchMissingURLWithAcceptNotFound(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	_, err = f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/missing.json", AcceptNotFound: true})
	if err != httpx.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFetchDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Record("https://example.org/a.json", http.Header{}, 200, strings.NewReader("original")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	// Corrupt the blob on disk without updating the manifest's checksum.
	entries, err := filepath.Glob(filepath.Join(dir, "blobs", "*", "*.bin"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one blob, got %v (err=%v)", entries, err)
	}
	if err := os.WriteFile(entries[0], []byte("corrupted!"), 0o644); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	f, err := NewFetcher(dir, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	_, err = f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json"})
	if err == nil {
		t.Fatal("expected a checksum mismatch error")
	}
}

func TestNewFetcherWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewFetcher(dir, false); err == nil {
		t.Fatal("expected an error when no manifest.json exists")
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	src := t.TempDir()
	rec, err := NewRecorder(src)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Record("https://example.org/a.json", http.Header{}, 200, strings.NewReader("payload")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := Pack(src, archive); err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	if err := Unpack(archive, dst); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	f, err := NewFetcher(dst, true)
	if err != nil {
		t.Fatalf("NewFetcher() on restored bundle error = %v", err)
	}
	defer f.Close()
	resp, err := f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json"})
	if err != nil {
		t.Fatalf("Fetch() after round trip error = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Errorf("body = %q, want payload", body)
	}

	createdAt, count, total := f.Info()
	if createdAt.IsZero() {
		t.Error("Info() created_at is zero")
	}
	if count != 1 {
		t.Errorf("Info() count = %d, want 1", count)
	}
	if total != int64(len("payload")) {
		t.Errorf("Info() total = %d, want %d", total, len("payload"))
	}
}

func TestUnpackRejectsPathTraversal(t *testing.T) {
	// Build a malicious tar.gz by hand containing a "../escape" entry.
	archive := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := writeEvilArchive(archive); err != nil {
		t.Fatalf("writeEvilArchive: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := Unpack(archive, dst); err == nil {
		t.Fatal("expected Unpack to reject a path-traversal entry")
	}
}

func TestFetcherURLsSorted(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	for _, u := range []string{"https://example.org/z.json", "https://example.org/a.json"} {
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader("x")); err != nil {
			t.Fatalf("Record(%s) error = %v", u, err)
		}
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	urls := f.URLs()
	if len(urls) != 2 || urls[0] != "https://example.org/a.json" || urls[1] != "https://example.org/z.json" {
		t.Errorf("URLs() = %v, want sorted a.json, z.json", urls)
	}
}

// The documented `make pack` writes the archive inside the directory it packs.
// Without the self-check the walk feeds the growing archive back into itself.
func TestPackSkipsItsOwnArchiveInsideTheBundle(t *testing.T) {
	src := t.TempDir()
	rec, err := NewRecorder(src)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Record("https://example.org/a.json", http.Header{}, 200, strings.NewReader("payload")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	archive := filepath.Join(src, "cvefeed-bundle.tar.gz")
	if err := Pack(src, archive); err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	for _, name := range tarNames(t, archive) {
		if strings.HasSuffix(name, "cvefeed-bundle.tar.gz") {
			t.Fatalf("the archive contains itself: %v", name)
		}
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := Unpack(archive, dst); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if _, err := NewFetcher(dst, true); err != nil {
		t.Fatalf("NewFetcher() on restored bundle error = %v", err)
	}
}

// A symlink in the bundle directory made Pack write a link header and then
// copy the target's bytes after it, which tar rejects with "write too long"
// and leaves a partial archive behind.
func TestPackSkipsSymlinksRatherThanWritingABrokenArchive(t *testing.T) {
	src := t.TempDir()
	rec, err := NewRecorder(src)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Record("https://example.org/a.json", http.Header{}, 200, strings.NewReader("payload")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if err := os.Symlink(filepath.Join(src, manifestName), filepath.Join(src, "manifest-link.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(src, "does-not-exist"), filepath.Join(src, "dangling")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := Pack(src, archive); err != nil {
		t.Fatalf("Pack() error = %v, want the links skipped", err)
	}
	for _, name := range tarNames(t, archive) {
		if name == "manifest-link.json" || name == "dangling" {
			t.Fatalf("archive contains the symlink %q", name)
		}
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := Unpack(archive, dst); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	f, err := NewFetcher(dst, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	resp, err := f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json"})
	if err != nil {
		t.Fatalf("Fetch() after round trip error = %v", err)
	}
	resp.Body.Close()
}

func tarNames(t *testing.T, archive string) []string {
	t.Helper()
	in, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		names = append(names, hdr.Name)
	}
}

// GCVE, EUVD and NVD put a date derived from the cursor or the clock into the
// URL. A bundle harvested yesterday therefore holds yesterday's URLs, and the
// air-gapped side, running today with its own cursor, asks for today's. An
// exact-URL lookup served nothing at all.
func TestFetchReplaysADateWindowRecordedYesterday(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	today := time.Now().UTC()

	gcve := func(day time.Time, page int) string {
		return "https://vulnerability.circl.lu/api/vulnerability/?date_sort=updated&page=" +
			fmt.Sprint(page) + "&per_page=25&since=" + day.Format("2006-01-02")
	}
	nvd := func(from, to time.Time) string {
		q := url.Values{}
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", "0")
		q.Set("lastModStartDate", from.Format("2006-01-02T15:04:05.000-07:00"))
		q.Set("lastModEndDate", to.Format("2006-01-02T15:04:05.000-07:00"))
		return "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q.Encode()
	}
	for u, body := range map[string]string{
		gcve(yesterday, 1):                        `["page1"]`,
		gcve(yesterday, 2):                        `["page2"]`,
		nvd(yesterday.Add(-time.Hour), yesterday): `{"vulnerabilities":[]}`,
		"https://gcve.eu/dist/gcve.json":          `[]`,
	} {
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader(body)); err != nil {
			t.Fatalf("Record(%s) error = %v", u, err)
		}
	}

	f, err := NewFetcher(dir, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	for u, want := range map[string]string{
		gcve(today, 1):                      `["page1"]`,
		gcve(today, 2):                      `["page2"]`,
		nvd(today.Add(-2*time.Hour), today): `{"vulnerabilities":[]}`,
		"https://gcve.eu/dist/gcve.json":    `[]`,
	} {
		resp, err := f.Fetch(context.Background(), httpx.Request{URL: u})
		if err != nil {
			t.Fatalf("Fetch(%s) error = %v; a window recorded yesterday must replay today", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Errorf("Fetch(%s) = %q, want %q", u, body, want)
		}
	}
	// The non-volatile parameters still have to match: page 3 was never
	// recorded and must not be answered with someone else's page.
	if _, err := f.Fetch(context.Background(), httpx.Request{URL: gcve(today, 3)}); err == nil {
		t.Fatal("an unrecorded page was served from another page's entry")
	}
}

// When a bundle holds several windows of the same resource, the one nearest
// the requested dates is the honest answer.
func TestFetchPicksTheNearestRecordedWindow(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	const base = "https://euvdservices.enisa.europa.eu/api/search?page=0&size=100"
	day := func(offset int) string {
		return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC).AddDate(0, 0, offset).Format("2006-01-02")
	}
	for offset, body := range map[int]string{-10: "old", -1: "recent"} {
		u := base + "&fromDate=" + day(offset-90) + "&toDate=" + day(offset)
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader(body)); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()

	for offset, want := range map[int]string{0: "recent", -12: "old", -5: "recent"} {
		u := base + "&fromDate=" + day(offset-90) + "&toDate=" + day(offset)
		resp, err := f.Fetch(context.Background(), httpx.Request{URL: u})
		if err != nil {
			t.Fatalf("Fetch(%s) error = %v", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Errorf("window ending %s served %q, want %q", day(offset), body, want)
		}
	}
}

// End to end through the online client: the collectors decode JSON with
// json.Decoder and close the body right after, before the Read that would
// return EOF. On a chunked body the terminating chunk arrives separately, so
// a recorder that waited for the consumer to see EOF never captured a single
// JSON response. The bundle must contain the entry and replay it.
func TestRecorderCapturesAJSONResponseClosedBeforeEOF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"cve_2026-08-18_1000Z"}`))
		// Flushing forces chunked encoding; returning later delays the
		// terminating chunk so the client cannot see it with the data.
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	c := httpx.NewClient(httpx.ClientOptions{Timeout: 5 * time.Second, UserAgent: "cvefeed-test", Recorder: rec})
	defer c.Close()

	u := srv.URL + "/repos/CVEProject/cvelistV5/releases/latest"
	resp, err := c.Fetch(context.Background(), httpx.Request{URL: u})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if rel.Tag != "cve_2026-08-18_1000Z" {
		t.Fatalf("decoded tag = %q", rel.Tag)
	}

	if n, _ := rec.Stats(); n != 1 {
		t.Fatalf("bundle has %d entries, want the JSON response recorded", n)
	}
	f, err := NewFetcher(dir, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	replay, err := f.Fetch(context.Background(), httpx.Request{URL: u})
	if err != nil {
		t.Fatalf("replay Fetch() error = %v", err)
	}
	defer replay.Body.Close()
	body, _ := io.ReadAll(replay.Body)
	if string(body) != `{"tag_name":"cve_2026-08-18_1000Z"}` {
		t.Fatalf("replayed body = %q", body)
	}
	if !replay.FromBundle {
		t.Error("FromBundle = false")
	}
}

// A bundle can hold several windows of a paged resource, and the nearest
// window for one page is not necessarily the window the walk started in. With
// window A's pages 0 and 2000 recorded and window B's page 0 only, a walk of B
// was handed A's page 2000 without a word, so NVD continued under B's
// totalResults with A's records and then claimed to have covered B.
func TestFetchDoesNotSpliceAnotherWindowsPageIntoAWalk(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	nvd := func(from, to time.Time, start int) string {
		q := url.Values{}
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", fmt.Sprint(start))
		q.Set("lastModStartDate", from.Format("2006-01-02T15:04:05.000-07:00"))
		q.Set("lastModEndDate", to.Format("2006-01-02T15:04:05.000-07:00"))
		return "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q.Encode()
	}
	day := func(y, m, d int) time.Time { return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC) }
	aFrom, aTo := day(2026, 6, 1), day(2026, 8, 1)
	bFrom, bTo := day(2026, 7, 1), day(2026, 9, 1)
	for u, body := range map[string]string{
		nvd(aFrom, aTo, 0):    `{"window":"A","startIndex":0,"totalResults":4000}`,
		nvd(aFrom, aTo, 2000): `{"window":"A","startIndex":2000}`,
		nvd(bFrom, bTo, 0):    `{"window":"B","startIndex":0,"totalResults":2500}`,
	} {
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader(body)); err != nil {
			t.Fatalf("Record(%s) error = %v", u, err)
		}
	}
	fetch := func(f *Fetcher, u string) (string, error) {
		resp, err := f.Fetch(context.Background(), httpx.Request{URL: u})
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	// B's walk on the day it was recorded: page 0 is an exact hit, and page
	// 2000 must be missing rather than A's.
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	if got, err := fetch(f, nvd(bFrom, bTo, 0)); err != nil || !strings.Contains(got, `"B"`) {
		t.Fatalf("B page 0 = %q, %v; want B's own page", got, err)
	}
	if _, err := fetch(f, nvd(bFrom, bTo, 2000)); !errors.Is(err, httpx.ErrOffline) {
		t.Fatalf("B page 2000 error = %v, want ErrOffline rather than A's page 2000", err)
	}
	f.Close()

	// The same walks a day later, when every page is a fallback: B's walk pins
	// itself to B on page 0 and still refuses A's page 2000, while A's walk is
	// served both pages from A.
	f, err = NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	shift := func(d time.Time) time.Time { return d.AddDate(0, 0, 1) }
	if got, err := fetch(f, nvd(shift(bFrom), shift(bTo), 0)); err != nil || !strings.Contains(got, `"B"`) {
		t.Fatalf("B' page 0 = %q, %v; want the nearest window, B", got, err)
	}
	if _, err := fetch(f, nvd(shift(bFrom), shift(bTo), 2000)); !errors.Is(err, httpx.ErrOffline) {
		t.Fatalf("B' page 2000 error = %v, want ErrOffline once the walk is pinned to B", err)
	}
	for _, start := range []int{0, 2000} {
		got, err := fetch(f, nvd(shift(aFrom), shift(aTo), start))
		if err != nil {
			t.Fatalf("A' page %d error = %v; a walk of A must be served from A", start, err)
		}
		if !strings.Contains(got, `"A"`) || !strings.Contains(got, fmt.Sprintf(`"startIndex":%d`, start)) {
			t.Fatalf("A' page %d = %q, want A's page %d", start, got, start)
		}
	}
}

// Pages are fetched concurrently by some collectors; the pin bookkeeping must
// not race.
func TestFetchPinsAreSafeForConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	const base = "https://vulnerability.circl.lu/api/vulnerability/?date_sort=updated&per_page=25"
	for page := 1; page <= 4; page++ {
		u := fmt.Sprintf("%s&page=%d&since=2026-08-01", base, page)
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader(fmt.Sprintf(`["page%d"]`, page))); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := fmt.Sprintf("%s&page=%d&since=2026-08-02", base, i%4+1)
			resp, err := f.Fetch(context.Background(), httpx.Request{URL: u})
			if err != nil {
				t.Errorf("Fetch(%s) error = %v", u, err)
				return
			}
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
}

// An entry that lacks one of the dates the request carries is a different
// request, not the same one with other values. Scored on the dates it did
// have, it contributed nothing for the missing one and beat every honest
// candidate on ties.
func TestFetchIgnoresAnEntryMissingOneOfTheRequestedDates(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	const base = "https://euvdservices.enisa.europa.eu/api/search?page=0&size=100"
	for u, body := range map[string]string{
		base + "&fromDate=2026-08-01":                   "open-ended",
		base + "&fromDate=2026-08-02&toDate=2026-08-19": "bounded",
	} {
		if err := rec.Record(u, http.Header{}, 200, strings.NewReader(body)); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	f, err := NewFetcher(dir, false)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	resp, err := f.Fetch(context.Background(), httpx.Request{URL: base + "&fromDate=2026-08-01&toDate=2026-08-20"})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "bounded" {
		t.Fatalf("served %q, want the entry that carries both requested dates", body)
	}
}

// filepath.Walk reports a symlinked root as the link itself and descends no
// further, so a bundle reached through a link — a "current" pointer to the
// latest harvest — packed to an empty archive.
func TestPackFollowsASymlinkedBundleRoot(t *testing.T) {
	real := t.TempDir()
	rec, err := NewRecorder(real)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Record("https://example.org/a.json", http.Header{}, 200, strings.NewReader("payload")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// The archive is written inside the linked tree, as `make pack` does, so
	// the self-output check has to see through the link as well.
	archive := filepath.Join(link, "cvefeed-bundle.tar.gz")
	if err := Pack(link, archive); err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	names := tarNames(t, archive)
	var manifest, blob bool
	for _, name := range names {
		switch {
		case name == manifestName:
			manifest = true
		case strings.HasPrefix(name, "blobs/") && strings.HasSuffix(name, ".bin"):
			blob = true
		case strings.HasSuffix(name, "cvefeed-bundle.tar.gz"):
			t.Fatalf("the archive contains itself: %v", names)
		}
	}
	if !manifest || !blob {
		t.Fatalf("archive entries = %v, want the manifest and the blob of the linked bundle", names)
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := Unpack(archive, dst); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	f, err := NewFetcher(dst, true)
	if err != nil {
		t.Fatalf("NewFetcher() error = %v", err)
	}
	defer f.Close()
	resp, err := f.Fetch(context.Background(), httpx.Request{URL: "https://example.org/a.json"})
	if err != nil {
		t.Fatalf("Fetch() after round trip error = %v", err)
	}
	resp.Body.Close()
}
