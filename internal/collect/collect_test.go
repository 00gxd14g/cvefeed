package collect

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// writeZip builds a zip whose members are the given name -> content pairs and
// returns its path.
func writeZip(t *testing.T, name string, members map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for n, body := range members {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("create member %s: %v", n, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("write member %s: %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return path
}

func zipBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, body := range members {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("create member %s: %v", n, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("write member %s: %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close inner zip: %v", err)
	}
	return buf.Bytes()
}

func TestWalkZipJSONReadsFlatArchive(t *testing.T) {
	path := writeZip(t, "flat.zip", map[string][]byte{
		"deltaCves/CVE-2026-1.json": []byte(`{"a":1}`),
		"deltaCves/CVE-2026-2.json": []byte(`{"a":2}`),
		"deltaCves/README.md":       []byte("ignored"),
	})

	var seen []string
	if err := walkZipJSON(path, nil, func(name string, data []byte) error {
		seen = append(seen, name)
		return nil
	}); err != nil {
		t.Fatalf("walkZipJSON() error = %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("visited %v, want the two .json members", seen)
	}
}

// The CVE List baseline release asset is an outer zip whose only member is
// cves.zip. A single-level walk emits nothing at all, which silently left the
// authoritative corpus unloaded while reporting success.
func TestWalkZipJSONDescendsIntoNestedArchive(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{
		"cves/2026/1xxx/CVE-2026-1234.json": []byte(`{"cveMetadata":{"cveId":"CVE-2026-1234"}}`),
		"cves/2026/1xxx/CVE-2026-1235.json": []byte(`{"cveMetadata":{"cveId":"CVE-2026-1235"}}`),
	})
	path := writeZip(t, "baseline.zip.zip", map[string][]byte{"cves.zip": inner})

	accept := func(name string) bool {
		base := name[len(name)-len(filepath.Base(name)):]
		return len(base) > 4 && base[:4] == "CVE-"
	}
	var seen int
	if err := walkZipJSON(path, accept, func(name string, data []byte) error {
		seen++
		return nil
	}); err != nil {
		t.Fatalf("walkZipJSON() error = %v", err)
	}
	if seen != 2 {
		t.Fatalf("emitted %d records from a nested baseline, want 2", seen)
	}
}

func TestWalkZipJSONReportsUnreadableMemberWithoutAborting(t *testing.T) {
	// A member stored with a compression method the reader does not know cannot
	// be opened, but the rest of the archive must still be ingested.
	path := filepath.Join(t.TempDir(), "mixed.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// Write method 99 through a pass-through compressor; no reader registers a
	// decompressor for it, so opening that member fails.
	zw.RegisterCompressor(99, func(w io.Writer) (io.WriteCloser, error) {
		return nopWriteCloser{w}, nil
	})
	broken, err := zw.CreateHeader(&zip.FileHeader{Name: "broken.json", Method: 99})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = broken.Write([]byte(`{"x":1}`))
	good, err := zw.Create("good.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = good.Write([]byte(`{"x":2}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var emitted, failed int
	if err := walkZipJSONErr(path, nil, func(name string, data []byte) error {
		emitted++
		return nil
	}, func(name string, err error) {
		failed++
	}); err != nil {
		t.Fatalf("walkZipJSONErr() error = %v, want the run to survive one bad member", err)
	}
	if emitted != 1 || failed != 1 {
		t.Fatalf("emitted=%d failed=%d, want 1 and 1", emitted, failed)
	}
}

func TestCursorTimeRoundTrip(t *testing.T) {
	cursor := map[string]string{}
	want := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC)
	setCursorTime(cursor, "last_run", want)

	got := cursorTime(cursor, "last_run")
	if got == nil || !got.Equal(want) {
		t.Fatalf("cursorTime() = %v, want %v", got, want)
	}
}

func TestCursorTimeRejectsGarbage(t *testing.T) {
	// A cursor that cannot be parsed must read as "absent". Returning a nil
	// pointer that a caller then dereferences crashed the whole serve process.
	for _, raw := range []string{"", "not-a-time", "2026-02-26"} {
		if got := cursorTime(map[string]string{"k": raw}, "k"); got != nil {
			t.Errorf("cursorTime(%q) = %v, want nil", raw, got)
		}
	}
}

func TestReplayCursorRewindsTimestampsAndClearsCaching(t *testing.T) {
	cursor := map[string]string{
		"last_modified":   "2026-08-18T10:00:00Z",
		"etag":            `"abc123"`,
		"etag_2024":       `"def456"`,
		"catalog_version": "2026.08.14",
		"backfill_index":  "4000",
	}
	at := time.Date(2025, 3, 11, 0, 0, 0, 0, time.UTC)
	replayCursor(cursor, at)

	if got := cursor["last_modified"]; got != "2025-03-11T00:00:00Z" {
		t.Errorf("last_modified = %q, want the replay instant", got)
	}
	for _, k := range []string{"etag", "etag_2024", "catalog_version"} {
		if _, ok := cursor[k]; ok {
			t.Errorf("%s survived the replay; upstream would answer 304 and fetch nothing", k)
		}
	}
	if cursor["backfill_index"] != "4000" {
		t.Errorf("non-timestamp cursor entries must be left alone, got %q", cursor["backfill_index"])
	}
}

func TestExtractScoreDateHandlesBothFIRSTSpellings(t *testing.T) {
	cases := []struct {
		name string
		rec  []string
		want string
	}{
		{
			"rfc3339 with Z",
			[]string{"#model_version:v2026.06.15", "score_date:2026-08-17T12:03:47Z"},
			"2026-08-17",
		},
		{
			"numeric offset without a colon",
			[]string{"#model_version:v2025.03.14", "score_date:2026-08-17T00:00:00+0000"},
			"2026-08-17",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractScoreDate(tc.rec)
			if got == nil {
				t.Fatalf("extractScoreDate(%v) = nil", tc.rec)
			}
			if got.Format("2006-01-02") != tc.want {
				t.Fatalf("score_date = %s, want %s", got.Format("2006-01-02"), tc.want)
			}
		})
	}
}

func TestExtractModelVersion(t *testing.T) {
	rec := []string{"#model_version:v2026.06.15", "score_date:2026-08-17T12:03:47Z"}
	if got := extractModelVersion(rec); got != "v2026.06.15" {
		t.Fatalf("extractModelVersion() = %q, want v2026.06.15", got)
	}
	if got := extractModelVersion([]string{"cve", "epss", "percentile"}); got != "" {
		t.Fatalf("extractModelVersion(header) = %q, want empty", got)
	}
}

func TestReleaseTagTime(t *testing.T) {
	got := releaseTagTime("cve_2026-08-18_1000Z")
	want := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("releaseTagTime() = %v, want %v", got, want)
	}
	if got := releaseTagTime("not-a-tag"); !got.IsZero() {
		t.Fatalf("releaseTagTime(garbage) = %v, want zero", got)
	}
}

func openZip(path string) (*zip.ReadCloser, error) { return zip.OpenReader(path) }
