package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/parse"
)

// ---------------------------------------------------------------- CVE List v5

// CVEListCollector consumes the authoritative CVE List in CVE JSON 5.1 format.
//
// Backfill pulls the nightly "all CVEs at midnight" release asset. Delta reads
// cves/delta.json — 700 bytes, rewritten every few minutes — and falls back to
// cves/deltaLog.json only when the gap is wider than the current delta covers.
type CVEListCollector struct{}

// Name identifies the collector.
func (c *CVEListCollector) Name() string { return "cvelist" }

const (
	cvelistReleaseAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
	cvelistDelta      = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
	cvelistDeltaLog   = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"

	// deltaLogHorizon is how far back the published log reaches. The CVE
	// Program shortened it from 30 to 15 days during the February 2026 date
	// normalisation. Past this a delta cannot close the gap and only a fresh
	// baseline can, so the collector says so instead of silently skipping.
	deltaLogHorizon = 15 * 24 * time.Hour
)

type ghRelease struct {
	TagName     string `json:"tag_name"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type deltaLogEntry struct {
	FetchTime       string          `json:"fetchTime"`
	NumberOfChanges int             `json:"numberOfChanges"`
	New             []deltaLogItem  `json:"new"`
	Updated         []deltaLogItem  `json:"updated"`
	Error           json.RawMessage `json:"error"`
}

type deltaLogItem struct {
	CVEID       string `json:"cveId"`
	GitHubLink  string `json:"githubLink"`
	DateUpdated string `json:"dateUpdated"`
}

// Run executes the collector.
func (c *CVEListCollector) Run(ctx context.Context, r *Run) error {
	if r.Mode == ModeBackfill || r.Cursor["last_delta"] == "" {
		return c.backfill(ctx, r)
	}
	return c.delta(ctx, r)
}

func (c *CVEListCollector) backfill(ctx context.Context, r *Run) error {
	var rel ghRelease
	if err := fetchJSON(ctx, r.Fetcher, cvelistReleaseAPI, &rel); err != nil {
		return fmt.Errorf("cvelist: release metadata: %w", err)
	}
	assetURL, assetName := "", ""
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "all_CVEs_at_midnight") && strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
			assetURL, assetName = a.BrowserDownloadURL, a.Name
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("cvelist: release %s has no midnight baseline asset", rel.TagName)
	}

	// The cursor must not advance past the moment the baseline was cut, or
	// every change published between the midnight snapshot and the end of a
	// multi-hour download is skipped forever.
	baselineAt := baselineCutTime(rel.TagName, assetName)
	if baselineAt.IsZero() {
		if t := model.ParseTime(rel.PublishedAt); t != nil {
			baselineAt = *t
		}
	}
	if baselineAt.IsZero() {
		baselineAt = time.Now().UTC()
	}
	r.Log.Info("downloading CVE List baseline", "release", rel.TagName, "cut_at", baselineAt.Format(time.RFC3339))

	path, err := fetchToTemp(ctx, r.Fetcher, assetURL, "cvelist-*.zip")
	if err != nil {
		return fmt.Errorf("cvelist: baseline download: %w", err)
	}
	defer os.Remove(path)

	accept := func(name string) bool {
		base := name[strings.LastIndex(name, "/")+1:]
		return strings.HasPrefix(base, "CVE-")
	}
	var emitted, unparseable int64
	// The baseline asset is a zip inside a zip (…_all_CVEs_at_midnight.zip.zip
	// contains cves.zip); walkZipJSON descends into it.
	err = walkZipJSONErr(path, accept, func(name string, data []byte) error {
		v, perr := parse.CVE5ToModel(data, c.Name())
		if perr != nil {
			unparseable++
			r.Log.Debug("skipping unparseable record", "member", name, "error", perr)
			return nil
		}
		emitted++
		return r.Emit(ctx, v)
	}, func(name string, err error) {
		unparseable++
		r.Log.Warn("baseline member unreadable", "member", name, "error", err)
	})
	if err != nil {
		return err
	}
	// A baseline that yields nothing is a broken assumption about the archive
	// layout, not an empty upstream. Advancing the cursor here would hide it
	// forever behind the delta path.
	if emitted == 0 {
		return fmt.Errorf("cvelist: baseline %s produced no records (archive layout changed?)", rel.TagName)
	}
	r.Log.Info("CVE List baseline ingested", "records", emitted, "skipped", unparseable)

	setCursorTime(r.Cursor, "last_delta", baselineAt)
	r.Cursor["baseline_release"] = rel.TagName
	return nil
}

// baselineCutTime is the instant the baseline asset was cut. The asset is the
// midnight snapshot — YYYY-MM-DD_all_CVEs_at_midnight.zip.zip — while the
// release tag (cve_YYYY-MM-DD_HHMMZ) records when the release was published,
// which can be most of a day later. Resting the cursor on the tag hour skipped
// every change published between 00:00Z and that hour, permanently: the delta
// path never looks behind its cursor. The cut is therefore the earlier of the
// two, and the tag only stands in when the asset name carries no date.
func baselineCutTime(tag, asset string) time.Time {
	tagAt := releaseTagTime(tag)
	midnight := assetMidnight(asset)
	switch {
	case midnight.IsZero():
		return tagAt
	case tagAt.IsZero() || midnight.Before(tagAt):
		return midnight
	default:
		return tagAt
	}
}

// assetMidnight reads the date that leads a baseline asset name and returns
// 00:00Z of that day.
func assetMidnight(asset string) time.Time {
	base := asset[strings.LastIndex(asset, "/")+1:]
	if len(base) < len("2006-01-02") {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", base[:len("2006-01-02")])
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// releaseTagTime parses the CVE List release tag, e.g. cve_2026-08-18_1000Z.
func releaseTagTime(tag string) time.Time {
	i := strings.Index(tag, "_")
	if i < 0 {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02_1504Z", tag[i+1:])
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (c *CVEListCollector) delta(ctx context.Context, r *Run) error {
	since := cursorTime(r.Cursor, "last_delta")

	// cves/delta.json is a few hundred bytes and covers the most recent
	// publication run. deltaLog.json is 20 MB. Polling the small file first is
	// what the research prescribes; the log is only needed to close a gap.
	//
	// Both live on raw.githubusercontent.com, which served a stale delta.json
	// for hours in May 2026 — hence the explicit no-cache.
	var latest deltaLogEntry
	if err := fetchJSONOpts(ctx, r.Fetcher, httpx.Request{URL: cvelistDelta, NoCache: true}, &latest); err != nil {
		return fmt.Errorf("cvelist: delta.json: %w", err)
	}
	latestTime := model.ParseTime(latest.FetchTime)

	entries := []deltaLogEntry{latest}
	needLog := since == nil || latestTime == nil
	if since != nil && latestTime != nil {
		// delta.json only describes its own run. Anything older than that run
		// has to come from the log.
		needLog = since.Before(latestTime.Add(-time.Minute))
	}
	if since != nil && time.Since(*since) > deltaLogHorizon {
		r.Log.Warn("cursor is older than the published delta log; a fresh baseline is required",
			"cursor", since.Format(time.RFC3339), "horizon", deltaLogHorizon.String())
		return c.backfill(ctx, r)
	}
	if needLog {
		var logged []deltaLogEntry
		if err := fetchJSONOpts(ctx, r.Fetcher, httpx.Request{URL: cvelistDeltaLog, NoCache: true}, &logged); err != nil {
			return fmt.Errorf("cvelist: delta log: %w", err)
		}
		entries = append(entries, logged...)
	}

	// Work oldest-first so the cursor can stop at the last run that completed
	// without a single failed fetch.
	//
	// Runs are keyed by fetchTime: delta.json describes the newest run and
	// deltaLog.json repeats that same run as its first element, so without
	// the merge every record of the newest run was fetched and emitted twice
	// whenever the log was consulted.
	type run struct {
		at    time.Time
		items map[string]string
	}
	var runs []*run
	byTime := map[int64]*run{}
	for _, e := range entries {
		ft := model.ParseTime(e.FetchTime)
		if ft == nil {
			continue
		}
		if since != nil && !ft.After(*since) {
			continue
		}
		rn, ok := byTime[ft.UnixNano()]
		if !ok {
			rn = &run{at: *ft, items: map[string]string{}}
			byTime[ft.UnixNano()] = rn
			runs = append(runs, rn)
		}
		for _, item := range append(append([]deltaLogItem{}, e.New...), e.Updated...) {
			if item.GitHubLink != "" {
				rn.items[item.CVEID] = item.GitHubLink
			}
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].at.Before(runs[j].at) })

	if len(runs) == 0 {
		r.Log.Info("no CVE List changes since cursor")
		return nil
	}

	total := 0
	for _, rn := range runs {
		total += len(rn.items)
	}
	r.Log.Info("fetching changed CVE records", "runs", len(runs), "records", total)

	// lastGood is the newest point we can honestly claim to have consumed.
	// Advancing past a run that had a failed fetch would turn a transient HTTP
	// error into permanent data loss, because nothing ever revisits it.
	var lastGood time.Time
	var failures int
	for _, rn := range runs {
		if err := ctx.Err(); err != nil {
			break
		}
		clean := true
		for id, link := range rn.items {
			if err := ctx.Err(); err != nil {
				clean = false
				break
			}
			data, err := fetchBytesOpts(ctx, r.Fetcher, httpx.Request{URL: link, NoCache: true})
			if err != nil {
				r.Log.Warn("record fetch failed", "cve", id, "error", err)
				clean, failures = false, failures+1
				continue
			}
			v, perr := parse.CVE5ToModel(data, c.Name())
			if perr != nil {
				r.Log.Warn("record unparseable", "cve", id, "error", perr)
				clean, failures = false, failures+1
				continue
			}
			if err := r.Emit(ctx, v); err != nil {
				return err
			}
		}
		if !clean {
			break
		}
		lastGood = rn.at
	}

	if !lastGood.IsZero() {
		setCursorTime(r.Cursor, "last_delta", lastGood)
	}
	if failures > 0 {
		return fmt.Errorf("cvelist: %d record(s) could not be ingested; cursor held at %s",
			failures, cursorOrNever(lastGood))
	}
	return nil
}

func cursorOrNever(t time.Time) string {
	if t.IsZero() {
		return "its previous position"
	}
	return t.Format(time.RFC3339)
}

// ------------------------------------------------------------- Vulnrichment

// VulnrichmentCollector consumes CISA's ADP enrichment repository, which is
// where SSVC decision points and CISA-assigned CVSS/CWE values live. Since NVD
// stopped scoring every CVE in April 2026 this is a primary enrichment source
// rather than a nice-to-have.
type VulnrichmentCollector struct{}

// Name identifies the collector.
func (c *VulnrichmentCollector) Name() string { return "vulnrichment" }

const vulnrichmentZip = "https://api.github.com/repos/cisagov/vulnrichment/zipball"

// Run executes the collector. The repository is re-read whole; the ETag makes
// an unchanged run cost one conditional request, and the sink's content-hash
// check means an unchanged record costs one comparison rather than a merge.
func (c *VulnrichmentCollector) Run(ctx context.Context, r *Run) error {
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{
		URL:         vulnrichmentZip,
		IfNoneMatch: r.Cursor["etag"],
	})
	if err != nil {
		return fmt.Errorf("vulnrichment: fetch: %w", err)
	}
	if resp.NotModified {
		resp.Body.Close()
		r.Log.Info("vulnrichment unchanged since last run")
		setCursorTime(r.Cursor, "last_run", time.Now().UTC())
		return nil
	}

	tmp, err := os.CreateTemp("", "vulnrichment-*.zip")
	if err != nil {
		resp.Body.Close()
		return fmt.Errorf("vulnrichment: temp file: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)

	_, copyErr := io.Copy(tmp, resp.Body)
	tmp.Close()
	resp.Body.Close()
	if copyErr != nil {
		return fmt.Errorf("vulnrichment: download: %w", copyErr)
	}

	accept := func(name string) bool {
		base := name[strings.LastIndex(name, "/")+1:]
		return strings.HasPrefix(base, "CVE-")
	}
	var skipped int64
	if err := walkZipJSONErr(path, accept, func(name string, data []byte) error {
		v, perr := parse.CVE5ToModel(data, c.Name())
		if perr != nil {
			skipped++
			return nil
		}
		return r.Emit(ctx, v)
	}, func(name string, err error) {
		skipped++
		r.Log.Warn("vulnrichment member unreadable", "member", name, "error", err)
	}); err != nil {
		return err
	}
	if skipped > 0 {
		r.Log.Info("vulnrichment records skipped", "count", skipped)
	}

	if resp.ETag != "" {
		r.Cursor["etag"] = resp.ETag
	}
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	return nil
}

// --------------------------------------------------------------------- NVD

// NVDCollector reads the NVD CVE API 2.0. Its value is CPE applicability data,
// which nothing else publishes at this breadth.
type NVDCollector struct{}

// Name identifies the collector.
func (c *NVDCollector) Name() string { return "nvd" }

const nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdBackfillOverlap is how far behind a backfill's start the delta cursor is
// placed. The walk has no date filter, so a record modified after its page was
// read is only covered by the next delta; the start instant is that boundary,
// and the overlap absorbs clock skew between NVD and this host.
const nvdBackfillOverlap = time.Hour

type nvdResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

// Run executes the collector.
//
// Backfill pages the entire corpus with no date filter. Delta uses
// lastModStartDate/lastModEndDate, which the API caps at a 120-day window, so
// long gaps are walked window by window rather than requested in one shot.
func (c *NVDCollector) Run(ctx context.Context, r *Run) error {
	since := cursorTime(r.Cursor, "last_modified")
	if r.Mode == ModeBackfill || since == nil {
		// A cursor that exists but does not parse must not be dereferenced —
		// and must not silently restart a multi-hour backfill either, so say so.
		if r.Mode != ModeBackfill && r.Cursor["last_modified"] != "" {
			r.Log.Warn("nvd cursor is unreadable, falling back to a full walk",
				"cursor", r.Cursor["last_modified"])
		}
		_, err := c.page(ctx, r, nil, nil, "backfill")
		return err
	}

	now := time.Now().UTC()
	const maxWindow = 110 * 24 * time.Hour // stay inside the 120-day API limit

	for start := *since; start.Before(now); {
		end := start.Add(maxWindow)
		if end.After(now) {
			end = now
		}
		newest, err := c.page(ctx, r, &start, &end, "delta")
		if err != nil {
			return err
		}
		// Advance to the newest lastModified actually seen, not to the window
		// edge: NVD assigns lastModified server-side and a record touched while
		// the window was being paged would otherwise fall between two runs.
		mark := end
		if !newest.IsZero() && newest.Before(end) {
			mark = newest
		}
		setCursorTime(r.Cursor, "last_modified", mark)
		start = end
	}
	return nil
}

func (c *NVDCollector) page(ctx context.Context, r *Run, from, to *time.Time, label string) (time.Time, error) {
	const perPage = 2000
	startIndex := 0
	if label == "backfill" {
		if v, ok := r.Cursor["backfill_index"]; ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				r.Log.Warn("nvd resume index unreadable, restarting the walk", "value", v, "error", err)
			} else {
				startIndex = n
			}
		}
		// The walk's start is what the delta cursor will rest on, recorded
		// when the walk begins and kept across resumes: a record modified
		// after its page was read is missed by this walk however late the
		// walk finishes, and the newest lastModified seen says nothing about
		// that — it only says the walk saw one late record, which then hid
		// every earlier page's changes behind it.
		if cursorTime(r.Cursor, "backfill_started") == nil {
			setCursorTime(r.Cursor, "backfill_started", time.Now().UTC())
		}
	}

	var newest time.Time
	var skipped int64
	for {
		if err := ctx.Err(); err != nil {
			return newest, err
		}
		q := url.Values{}
		q.Set("resultsPerPage", fmt.Sprint(perPage))
		q.Set("startIndex", fmt.Sprint(startIndex))
		if from != nil && to != nil {
			q.Set("lastModStartDate", from.Format("2006-01-02T15:04:05.000-07:00"))
			q.Set("lastModEndDate", to.Format("2006-01-02T15:04:05.000-07:00"))
		}

		var resp nvdResponse
		if err := fetchJSON(ctx, r.Fetcher, nvdBase+"?"+q.Encode(), &resp); err != nil {
			return newest, fmt.Errorf("nvd: %s page %d: %w", label, startIndex, err)
		}
		for _, item := range resp.Vulnerabilities {
			v, perr := parse.NVDToModel(item.CVE, c.Name())
			if perr != nil {
				skipped++
				r.Log.Debug("nvd record unparseable", "error", perr)
				continue
			}
			if v.Modified != nil && v.Modified.After(newest) {
				newest = *v.Modified
			}
			if err := r.Emit(ctx, v); err != nil {
				return newest, err
			}
		}

		// NVD occasionally answers 200 with an empty page in the middle of a
		// walk. Taking that as the end declared the backfill complete — the
		// resume index was dropped and the delta cursor placed — with most of
		// the corpus unread; in delta mode the window was marked covered.
		// Refusing it keeps the resume index at this page, and the next run
		// asks for it again.
		if len(resp.Vulnerabilities) == 0 && startIndex < resp.TotalResults {
			return newest, fmt.Errorf("nvd: %s page at index %d returned no records with %d of %d read",
				label, startIndex, startIndex, resp.TotalResults)
		}
		startIndex += resp.ResultsPerPage
		if label == "backfill" {
			r.Cursor["backfill_index"] = fmt.Sprint(startIndex)
		}
		if resp.ResultsPerPage == 0 || startIndex >= resp.TotalResults {
			break
		}
		r.Log.Debug("nvd page done", "index", startIndex, "total", resp.TotalResults)
	}
	if skipped > 0 {
		r.Log.Info("nvd records skipped", "count", skipped, "mode", label)
	}

	if label == "backfill" {
		mark := time.Now().UTC()
		if started := cursorTime(r.Cursor, "backfill_started"); started != nil {
			mark = *started
		}
		delete(r.Cursor, "backfill_index")
		delete(r.Cursor, "backfill_started")
		setCursorTime(r.Cursor, "last_modified", mark.Add(-nvdBackfillOverlap))
	}
	return newest, nil
}

// -------------------------------------------------------------------- FKIE

// FKIECollector reads Fraunhofer FKIE's reconstruction of the NVD bulk feeds.
//
// NIST retired the legacy JSON 1.1 feeds in August 2025 and publishes official
// JSON 2.0 year files again since May 2025; this mirror is kept because it is
// one download per year, tracks the API within two hours, and keeps working
// when nvd.nist.gov rate-limits a backfill.
type FKIECollector struct{}

// Name identifies the collector.
func (c *FKIECollector) Name() string { return "fkie" }

const (
	fkieYearURL     = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-%d.json.xz"
	fkieModifiedURL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-Modified.json.xz"
	fkieFirstYear   = 1999
)

// Run executes the collector.
//
// Delta uses the purpose-built CVE-Modified feed rather than guessing which
// years changed: a 2015 CVE re-scored today appears there and in no year file
// a "current and previous year" heuristic would fetch.
func (c *FKIECollector) Run(ctx context.Context, r *Run) error {
	if r.Mode == ModeDelta {
		if err := c.ingestFeed(ctx, r, fkieModifiedURL, "modified"); err != nil {
			r.Log.Warn("fkie modified feed unavailable, falling back to recent years", "error", err)
			currentYear := time.Now().UTC().Year()
			for year := currentYear - 1; year <= currentYear; year++ {
				if err := c.ingestFeed(ctx, r, fmt.Sprintf(fkieYearURL, year), fmt.Sprint(year)); err != nil {
					r.Log.Warn("fkie year unavailable", "year", year, "error", err)
				}
			}
		}
		setCursorTime(r.Cursor, "last_run", time.Now().UTC())
		return nil
	}

	currentYear := time.Now().UTC().Year()
	var failures []string
	for year := fkieFirstYear; year <= currentYear; year++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.ingestFeed(ctx, r, fmt.Sprintf(fkieYearURL, year), fmt.Sprint(year)); err != nil {
			// One unavailable year must not forfeit the other twenty-seven.
			r.Log.Warn("fkie year failed", "year", year, "error", err)
			failures = append(failures, fmt.Sprint(year))
		}
	}
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	if len(failures) > 0 {
		return fmt.Errorf("fkie: %d year feed(s) failed: %s", len(failures), strings.Join(failures, ", "))
	}
	return nil
}

func (c *FKIECollector) ingestFeed(ctx context.Context, r *Run, u, label string) error {
	etagKey := "etag_" + label
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{
		URL:            u,
		IfNoneMatch:    r.Cursor[etagKey],
		AcceptNotFound: true,
	})
	if err != nil {
		if errors.Is(err, httpx.ErrNotFound) {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.NotModified {
		return nil
	}

	xzr, err := xz.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("xz reader: %w", err)
	}

	// The feed is decoded as a stream rather than unmarshalled whole: a year
	// file runs to hundreds of megabytes decompressed, and buffering every
	// record before emitting any makes the ingester's footprint a function of
	// upstream size.
	dec := json.NewDecoder(xzr)
	var (
		count   int64
		skipped int64
	)
	if err := streamJSONArrayField(dec, "cve_items", func(raw json.RawMessage) error {
		v, perr := parse.NVDToModel(raw, c.Name())
		if perr != nil {
			skipped++
			return nil
		}
		count++
		return r.Emit(ctx, v)
	}); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if resp.ETag != "" {
		r.Cursor[etagKey] = resp.ETag
	}
	r.Log.Debug("fkie feed ingested", "feed", label, "records", count, "skipped", skipped)
	return nil
}

// streamJSONArrayField walks a top-level object and streams the elements of one
// named array field without holding the whole document in memory.
func streamJSONArrayField(dec *json.Decoder, field string, fn func(json.RawMessage) error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected a JSON object, got %v", tok)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		if key != field {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return err
			}
			continue
		}
		open, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := open.(json.Delim); !ok || d != '[' {
			return fmt.Errorf("expected %s to be an array, got %v", field, open)
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return err
			}
			if err := fn(raw); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing ]
			return err
		}
	}
	return nil
}
