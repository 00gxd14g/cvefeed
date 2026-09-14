// Package airgap implements the offline transfer bundle.
//
// The workflow it supports is:
//
//	(internet side)   cvefeed ingest --record /out/bundle      → writes bundle
//	(sneakernet)      cvefeed bundle pack /out/bundle b.tar.gz → single file
//	(air-gapped side) cvefeed bundle unpack b.tar.gz /in/bundle
//	                  cvefeed ingest --bundle /in/bundle       → same collectors
//
// Collectors are unaware of which side they run on: both Recorder and Fetcher
// here speak the httpx contract.
package airgap

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
)

const manifestName = "manifest.json"

// Entry describes one captured HTTP response.
type Entry struct {
	URL         string    `json:"url"`
	File        string    `json:"file"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	Status      int       `json:"status"`
	ContentType string    `json:"content_type,omitempty"`
	ETag        string    `json:"etag,omitempty"`
	LastMod     string    `json:"last_modified,omitempty"`
	CapturedAt  time.Time `json:"captured_at"`
}

// Manifest is the bundle index.
type Manifest struct {
	Version    int              `json:"version"`
	CreatedAt  time.Time        `json:"created_at"`
	Tool       string           `json:"tool"`
	Entries    map[string]Entry `json:"entries"` // keyed by URL
	TotalBytes int64            `json:"total_bytes"`
}

// Recorder captures responses into a bundle directory.
type Recorder struct {
	dir string

	mu       sync.Mutex
	manifest *Manifest
}

// NewRecorder opens (or creates) a bundle directory for writing.
func NewRecorder(dir string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		return nil, fmt.Errorf("airgap: create bundle dir: %w", err)
	}
	m, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if m == nil {
		m = &Manifest{Version: 1, CreatedAt: time.Now().UTC(), Tool: "cvefeed", Entries: map[string]Entry{}}
	}
	return &Recorder{dir: dir, manifest: m}, nil
}

// Record streams body to a content-addressed blob and indexes it under url.
func (r *Recorder) Record(url string, header http.Header, status int, body io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Join(r.dir, "blobs"), ".partial-*")
	if err != nil {
		return fmt.Errorf("airgap: temp blob: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), body)
	if cerr := tmp.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("airgap: write blob for %s: %w", url, err)
	}

	sum := hex.EncodeToString(h.Sum(nil))
	rel := filepath.Join("blobs", sum[:2], sum+".bin")
	abs := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("airgap: blob dir: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil && !os.IsExist(err) {
		if _, statErr := os.Stat(abs); statErr != nil {
			return fmt.Errorf("airgap: place blob: %w", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.manifest.Entries[url]; ok {
		r.manifest.TotalBytes -= old.Size
	}
	r.manifest.Entries[url] = Entry{
		URL:         url,
		File:        filepath.ToSlash(rel),
		SHA256:      sum,
		Size:        size,
		Status:      status,
		ContentType: header.Get("Content-Type"),
		ETag:        header.Get("ETag"),
		LastMod:     header.Get("Last-Modified"),
		CapturedAt:  time.Now().UTC(),
	}
	r.manifest.TotalBytes += size
	// The manifest is rewritten after every response on purpose. Batching it
	// would make a harvest cheaper, but an interrupted harvest would then leave
	// blobs on disk that no index references — and the whole point of a bundle
	// is that whatever crossed the gap is usable on the other side.
	return r.flushLocked()
}

// Flush writes the manifest to disk.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked()
}

func (r *Recorder) flushLocked() error {
	path := filepath.Join(r.dir, manifestName)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("airgap: write manifest: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r.manifest); err != nil {
		f.Close()
		return fmt.Errorf("airgap: encode manifest: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("airgap: close manifest: %w", err)
	}
	return os.Rename(tmp, path)
}

// Stats reports entry count and total captured bytes.
func (r *Recorder) Stats() (int, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.manifest.Entries), r.manifest.TotalBytes
}

// Fetcher serves previously recorded responses. It satisfies httpx.Fetcher, so
// collectors run unmodified on an isolated network.
type Fetcher struct {
	dir      string
	manifest *Manifest
	verify   bool

	// byShape indexes the entries whose URL carries a volatile date parameter
	// under the URL with those parameters removed, so a request for the same
	// page of a different window can still be served. See volatileParams.
	byShape map[string][]Entry

	// pinned remembers, per walk (see walkKey), which recorded window served
	// it, so every later page of that walk comes from the same window. The
	// pages of a paged resource were recorded as one consistent set — NVD's
	// totalResults on page 0 counts the records pages 1..n carry — and
	// splicing another window's page into the walk, which the nearest-window
	// choice on its own would do whenever the pinned window lacks the page,
	// makes the collector walk another window's records and then claim a
	// coverage it does not have. Collectors fetch pages concurrently, so the
	// map is guarded.
	mu     sync.Mutex
	pinned map[string]string
}

// pagingParams are the query parameters that step through a paged resource.
// They are removed, together with the volatile dates, to form the family a
// walk's pages share.
var pagingParams = map[string]bool{
	"startIndex": true,
	"page":       true,
}

// volatileParams are the query parameters whose values a collector derives
// from its cursor or from the clock rather than from the resource it wants:
// the window GCVE asks Vulnerability-Lookup for with since=, the publication
// window EUVD pages with fromDate/toDate, and the lastModified range NVD
// walks. Two runs a day apart ask for the same pages under different values,
// so an exact-URL lookup could only ever replay a bundle on the day it was
// recorded — and the air-gapped side never runs on that day.
var volatileParams = map[string]bool{
	"since":            true,
	"fromDate":         true,
	"toDate":           true,
	"lastModStartDate": true,
	"lastModEndDate":   true,
	"pubStartDate":     true,
	"pubEndDate":       true,
}

// urlShape strips the volatile parameters from a URL. It returns the rest as
// the key that "the same page of a different window" shares, plus the
// stripped values so the nearest window can be chosen among several. ok is
// false for a URL that has no volatile parameter at all.
func urlShape(raw string) (shape string, dates map[string]time.Time, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, false
	}
	q := u.Query()
	dates = map[string]time.Time{}
	for k := range q {
		if !volatileParams[k] {
			continue
		}
		ok = true
		if t, tok := parseVolatileDate(q.Get(k)); tok {
			dates[k] = t
		}
		q.Del(k)
	}
	if !ok {
		return "", nil, false
	}
	u.RawQuery = q.Encode()
	return u.String(), dates, true
}

// parseVolatileDate reads the two spellings the collectors use: a bare date
// (GCVE, EUVD) and RFC 3339 with a fractional second and offset (NVD).
func parseVolatileDate(v string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// window renders the volatile values a URL carries as one canonical string —
// sorted "key=value" pairs — so two entries recorded in the same harvest
// window compare equal whatever page they are. An empty string means the URL
// carries no volatile parameter.
func window(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	pairs := make([]string, 0, len(volatileParams))
	for k := range q {
		if volatileParams[k] {
			pairs = append(pairs, k+"="+q.Get(k))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// walkKey identifies the walk a request belongs to: the request family — the
// URL with both the volatile dates and the paging parameters removed, which
// every page of one walk shares — together with the window the request asks
// for. Keying on the requested window rather than the family alone lets one
// process walk several windows of the same resource in turn (NVD splits a long
// range into 120-day windows, each starting again at startIndex=0) and lets a
// bundle holding several windows still answer each request with its nearest
// one; only the pages of one and the same walk are held to one window. ok is
// false for a URL without a volatile parameter.
func walkKey(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	q := u.Query()
	hasVolatile := false
	for k := range q {
		if volatileParams[k] {
			hasVolatile = true
			q.Del(k)
		} else if pagingParams[k] {
			q.Del(k)
		}
	}
	if !hasVolatile {
		return "", false
	}
	u.RawQuery = q.Encode()
	return u.String() + "\x00" + window(raw), true
}

// pin records that the walk req belongs to was served from the window of
// entryURL. An exact-URL hit pins as well: a bundle that holds window B's
// page 0 and window A's pages 0 and 2000 would otherwise serve B page 0
// exactly and then hand B's walk A's page 2000 on the first fallback.
func (f *Fetcher) pin(reqURL, entryURL string) {
	key, ok := walkKey(reqURL)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pinned == nil {
		f.pinned = map[string]string{}
	}
	f.pinned[key] = window(entryURL)
}

func indexShapes(m *Manifest) map[string][]Entry {
	out := map[string][]Entry{}
	for u, e := range m.Entries {
		if shape, _, ok := urlShape(u); ok {
			out[shape] = append(out[shape], e)
		}
	}
	return out
}

// nearest finds the recorded entry that asked for the same resource as rawURL
// with the closest volatile dates. Distance is the sum over the request's
// date parameters of how far the recorded value lies from the requested one;
// ties go to the most recent capture, then to the URL, so the choice is
// deterministic.
//
// Once a walk has been served from one window (by an earlier fallback or by
// an exact hit) only that window's entries are candidates, and a page the
// window lacks is reported missing rather than borrowed from another window.
// The first fallback of a walk pins it to the window it chose.
func (f *Fetcher) nearest(rawURL string) (Entry, bool) {
	shape, want, ok := urlShape(rawURL)
	if !ok {
		return Entry{}, false
	}
	key, _ := walkKey(rawURL)

	f.mu.Lock()
	defer f.mu.Unlock()
	pinnedWindow, isPinned := f.pinned[key]

	var (
		best     Entry
		bestDist time.Duration
		found    bool
	)
	for _, e := range f.byShape[shape] {
		if isPinned && window(e.URL) != pinnedWindow {
			continue
		}
		_, have, _ := urlShape(e.URL)
		var dist time.Duration
		complete := true
		for k, t := range want {
			ht, ok := have[k]
			if !ok {
				// An entry without one of the requested dates is not the
				// same request with other values. Scoring it on the dates it
				// does have gave it a distance of zero for the missing one,
				// which won every tie against an honest candidate.
				complete = false
				break
			}
			d := t.Sub(ht)
			if d < 0 {
				d = -d
			}
			dist += d
		}
		if !complete {
			continue
		}
		better := !found || dist < bestDist ||
			(dist == bestDist && (e.CapturedAt.After(best.CapturedAt) ||
				(e.CapturedAt.Equal(best.CapturedAt) && e.URL < best.URL)))
		if better {
			best, bestDist, found = e, dist, true
		}
	}
	if found && !isPinned {
		if f.pinned == nil {
			f.pinned = map[string]string{}
		}
		f.pinned[key] = window(best.URL)
	}
	return best, found
}

// NewFetcher opens a bundle directory for reading. When verify is true every
// blob's SHA-256 is checked on read, which is what you want for media that
// crossed an air gap.
func NewFetcher(dir string, verify bool) (*Fetcher, error) {
	m, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("airgap: no %s in %s", manifestName, dir)
	}
	return &Fetcher{dir: dir, manifest: m, verify: verify, byShape: indexShapes(m)}, nil
}

// Fetch returns the recorded response for req.URL.
func (f *Fetcher) Fetch(ctx context.Context, req httpx.Request) (*httpx.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.lookup(req)
}

func (f *Fetcher) lookup(req httpx.Request) (*httpx.Response, error) {
	e, ok := f.manifest.Entries[req.URL]
	if ok {
		f.pin(req.URL, e.URL)
	} else {
		// The exact URL is preferred; a request that differs only in its date
		// window falls back to the nearest window the harvest recorded.
		e, ok = f.nearest(req.URL)
	}
	if !ok {
		if req.AcceptNotFound {
			return nil, httpx.ErrNotFound
		}
		return nil, fmt.Errorf("%w: %s", httpx.ErrOffline, req.URL)
	}
	if req.IfNoneMatch != "" && e.ETag != "" && req.IfNoneMatch == e.ETag {
		return &httpx.Response{
			URL: req.URL, Status: http.StatusNotModified, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader("")), NotModified: true,
			ETag: e.ETag, LastModified: e.LastMod, FromBundle: true,
		}, nil
	}

	// The manifest is transport data, so its paths are untrusted: a crafted
	// bundle could otherwise name ../../etc/passwd and have the collector
	// happily "replay" it.
	path, err := safeJoin(f.dir, e.File)
	if err != nil {
		return nil, fmt.Errorf("airgap: blob for %s: %w", req.URL, err)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("airgap: open blob for %s: %w", req.URL, err)
	}
	if f.verify {
		h := sha256.New()
		if _, err := io.Copy(h, fh); err != nil {
			fh.Close()
			return nil, fmt.Errorf("airgap: hash blob for %s: %w", req.URL, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != e.SHA256 {
			fh.Close()
			return nil, fmt.Errorf("airgap: blob for %s is corrupt: manifest %s, actual %s", req.URL, e.SHA256, got)
		}
		if _, err := fh.Seek(0, io.SeekStart); err != nil {
			fh.Close()
			return nil, fmt.Errorf("airgap: rewind blob for %s: %w", req.URL, err)
		}
	}

	hdr := http.Header{}
	if e.ContentType != "" {
		hdr.Set("Content-Type", e.ContentType)
	}
	if e.ETag != "" {
		hdr.Set("ETag", e.ETag)
	}
	if e.LastMod != "" {
		hdr.Set("Last-Modified", e.LastMod)
	}
	return &httpx.Response{
		URL: req.URL, Status: e.Status, Header: hdr, Body: fh,
		ETag: e.ETag, LastModified: e.LastMod, FromBundle: true,
	}, nil
}

// Close is a no-op; blobs are opened per request.
func (f *Fetcher) Close() error { return nil }

// URLs lists every URL present in the bundle, sorted.
func (f *Fetcher) URLs() []string {
	out := make([]string, 0, len(f.manifest.Entries))
	for u := range f.manifest.Entries {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// Info reports the bundle's creation time, entry count and byte total.
func (f *Fetcher) Info() (time.Time, int, int64) {
	return f.manifest.CreatedAt, len(f.manifest.Entries), f.manifest.TotalBytes
}

// safeJoin resolves rel under root and refuses anything that escapes it.
func safeJoin(root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	cleaned := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute path %q", rel)
	}
	target := filepath.Join(root, cleaned)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if absTarget != absRoot && !strings.HasPrefix(absTarget, absRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes the bundle directory", rel)
	}
	return absTarget, nil
}

func readManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("airgap: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("airgap: parse manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return &m, nil
}

// Pack writes a bundle directory into a single gzipped tar for transport.
//
// The output is skipped if it lands inside the directory being packed, which is
// exactly what the documented `make pack` invocation does. Without the check
// the walk feeds the growing archive back into itself and tar aborts with
// "write too long", leaving an oversized partial file behind.
func Pack(dir, outFile string) error {
	if _, err := readManifest(dir); err != nil {
		return err
	}
	// filepath.Walk does not follow a symlink at the root: it reports the link
	// itself, which is neither a directory to descend into nor a regular file
	// to copy, so a bundle reached through a link (a "current" symlink to the
	// latest harvest, say) packed to an empty archive. The real path is walked
	// instead, and the output is resolved the same way so the self-output
	// check below still recognises an archive written inside the linked tree.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("airgap: resolve bundle dir: %w", err)
	}
	out, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("airgap: create %s: %w", outFile, err)
	}
	defer out.Close()
	absOut, err := filepath.EvalSymlinks(outFile)
	if err == nil {
		absOut, err = filepath.Abs(absOut)
	}
	if err != nil {
		return fmt.Errorf("airgap: resolve %s: %w", outFile, err)
	}

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), ".partial-") {
			return nil
		}
		if abs, aerr := filepath.Abs(path); aerr == nil && abs == absOut {
			return nil
		}
		// Walk reports a symlink as itself, so FileInfoHeader would write a
		// zero-length link header while the copy below follows the link and
		// appends its target's bytes — tar aborts with "write too long" and
		// the archive is left broken. Nothing the recorder writes is a link,
		// and Unpack refuses links on the other side, so they are simply not
		// part of a bundle.
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if walkErr != nil {
		tw.Close()
		gz.Close()
		return fmt.Errorf("airgap: pack: %w", walkErr)
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		return fmt.Errorf("airgap: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("airgap: close gzip: %w", err)
	}
	return nil
}

// Unpack expands a packed bundle into dir, rejecting path traversal entries.
func Unpack(inFile, dir string) error {
	in, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("airgap: open %s: %w", inFile, err)
	}
	defer in.Close()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("airgap: gzip reader: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("airgap: mkdir %s: %w", dir, err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	const (
		maxEntries   = 5_000_000
		maxEntrySize = 8 << 30  // 8 GiB: larger than any single upstream artefact
		maxTotalSize = 64 << 30 // 64 GiB: a full corpus with headroom
	)
	var entries int
	var totalBytes int64

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("airgap: tar read: %w", err)
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("airgap: refusing archive with more than %d entries", maxEntries)
		}
		target, jerr := safeJoin(root, hdr.Name)
		if jerr != nil {
			return fmt.Errorf("airgap: refusing entry outside bundle root: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			// Bounded copy: a gzip bomb otherwise fills the disk of the
			// isolated host the bundle was carried to.
			n, err := io.Copy(f, io.LimitReader(tr, maxEntrySize+1))
			if err != nil {
				f.Close()
				return err
			}
			if n > maxEntrySize {
				f.Close()
				return fmt.Errorf("airgap: entry %q exceeds %d bytes", hdr.Name, int64(maxEntrySize))
			}
			totalBytes += n
			if totalBytes > maxTotalSize {
				f.Close()
				return fmt.Errorf("airgap: archive expands beyond %d bytes", int64(maxTotalSize))
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			// Symlinks and devices have no business in a data bundle.
			return fmt.Errorf("airgap: unsupported tar entry type %q for %s", string(hdr.Typeflag), hdr.Name)
		}
	}
}
