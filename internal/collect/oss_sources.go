package collect

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/parse"
)

// --------------------------------------------------------------------- OSV

// OSVCollector reads OSV.dev, which is the single point of access for Debian,
// Ubuntu, SUSE, Alpine, Rocky, PyPI, npm, Go, Maven, RubyGems, crates.io and
// more. A large share of these advisories never receive a CVE, so this is where
// "every vulnerability" stops being "every CVE".
type OSVCollector struct{}

// Name identifies the collector.
func (c *OSVCollector) Name() string { return "osv" }

const (
	osvAllZip     = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
	osvModifiedID = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
	osvRecordFmt  = "https://api.osv.dev/v1/vulns/%s"

	// osvOverlap is subtracted from every high-water mark. all.zip is a
	// snapshot cut some time before it is downloaded and OSV's own staleness
	// SLO is 15 minutes, so an exact watermark leaves a band of records that no
	// run ever looks at. The research prescribes "high-water-mark minus
	// overlap" for exactly this reason.
	osvOverlap = 6 * time.Hour

	// osvDeltaCeiling is the point where fetching changed records one at a time
	// stops being cheaper than re-reading the full export.
	osvDeltaCeiling = 20000
)

// Run executes the collector.
func (c *OSVCollector) Run(ctx context.Context, r *Run) error {
	if r.Mode == ModeBackfill || r.Cursor["last_modified"] == "" {
		return c.backfill(ctx, r, time.Time{})
	}
	return c.delta(ctx, r)
}

// backfill reads the full export. floor, when set, is a watermark derived
// elsewhere (the delta index) that the archive's own contents must not push
// forward past.
func (c *OSVCollector) backfill(ctx context.Context, r *Run, floor time.Time) error {
	r.Log.Info("downloading OSV full export")
	startedAt := time.Now().UTC()
	path, err := fetchToTemp(ctx, r.Fetcher, osvAllZip, "osv-all-*.zip")
	if err != nil {
		return fmt.Errorf("osv: download all.zip: %w", err)
	}
	defer os.Remove(path)

	var (
		newest  time.Time
		count   int64
		skipped int64
	)
	if err := walkZipJSONErr(path, nil, func(name string, data []byte) error {
		v, perr := parse.OSVToModel(data, c.Name())
		if perr != nil {
			skipped++
			return nil
		}
		// The watermark comes from the data, not from the clock. all.zip is a
		// snapshot generated before the download started, so stamping "now"
		// declares coverage of a window that was never read — and because
		// modified_id.csv is newest-first and the delta loop stops at the
		// watermark, everything in that window is skipped permanently.
		if v.Modified != nil && v.Modified.After(newest) {
			newest = *v.Modified
		}
		count++
		return r.Emit(ctx, v)
	}, func(name string, err error) {
		skipped++
		r.Log.Warn("osv archive member unreadable", "member", name, "error", err)
	}); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("osv: full export produced no records, refusing to advance the cursor")
	}
	r.Log.Info("osv full export ingested", "records", count, "skipped", skipped)

	mark := newest
	// A snapshot cannot contain a modification made after it was downloaded.
	// A record stamped in the future — PYSEC-2025-19 says 2027 — would carry
	// the watermark past every real change until that date, and the delta
	// walk, which stops at the watermark, would then skip all of them.
	if mark.IsZero() || mark.After(startedAt) {
		mark = startedAt
	}
	if !floor.IsZero() && floor.Before(mark) {
		mark = floor
	}
	setCursorTime(r.Cursor, "last_modified", mark.Add(-osvOverlap))
	return nil
}

// delta walks modified_id.csv, which OSV publishes in reverse chronological
// order specifically so consumers can stop reading at their last watermark.
func (c *OSVCollector) delta(ctx context.Context, r *Run) error {
	since := cursorTime(r.Cursor, "last_modified")

	ids, newest, err := c.changedIDs(ctx, r, since)
	if err != nil {
		return err
	}
	if len(ids) >= osvDeltaCeiling {
		// A gap this wide is cheaper to close with the full export. The floor
		// keeps the CSV-derived watermark, so the archive's older snapshot
		// cannot push the cursor forward past records it does not contain.
		r.Log.Warn("osv delta too large, falling back to full export", "pending", len(ids))
		return c.backfill(ctx, r, newest)
	}

	r.Log.Info("osv changed records", "count", len(ids))
	var failures int
	var skipped int64
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, ferr := fetchBytes(ctx, r.Fetcher, fmt.Sprintf(osvRecordFmt, id))
		if ferr != nil {
			r.Log.Warn("osv record fetch failed", "id", id, "error", ferr)
			failures++
			continue
		}
		v, perr := parse.OSVToModel(data, c.Name())
		if perr != nil {
			r.Log.Warn("osv record unparseable", "id", id, "error", perr)
			skipped++
			failures++
			continue
		}
		if err := r.Emit(ctx, v); err != nil {
			return err
		}
	}

	// Only advance when every changed record actually landed. Moving the
	// watermark past a failed fetch turns one transient error into permanent
	// data loss: the CSV is newest-first, so nothing ever revisits it.
	if failures > 0 {
		return fmt.Errorf("osv: %d record(s) could not be ingested; cursor held", failures)
	}
	if !newest.IsZero() {
		setCursorTime(r.Cursor, "last_modified", newest.Add(-osvOverlap))
	}
	return nil
}

// changedIDs reads modified_id.csv down to the watermark and returns the ids
// that changed plus the newest modification timestamp the index reports.
func (c *OSVCollector) changedIDs(ctx context.Context, r *Run, since *time.Time) ([]string, time.Time, error) {
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{URL: osvModifiedID})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("osv: modified_id.csv: %w", err)
	}
	defer resp.Body.Close()

	reader := csv.NewReader(bufio.NewReaderSize(resp.Body, 1<<20))
	reader.FieldsPerRecord = -1

	var ids []string
	newest := time.Time{}
	now := time.Now().UTC()
	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, newest, fmt.Errorf("osv: parse modified_id.csv: %w", err)
		}
		if len(rec) < 2 {
			continue
		}
		modified, terr := time.Parse(time.RFC3339, strings.TrimSpace(rec[0]))
		if terr != nil {
			continue // header row or unexpected line
		}
		if modified.After(newest) && !modified.After(now) {
			newest = modified
		}
		if since != nil && !modified.After(*since) {
			break // reverse chronological: everything below is already ingested
		}
		id := strings.TrimSpace(rec[1])
		if i := strings.LastIndex(id, "/"); i >= 0 {
			id = id[i+1:]
		}
		id = strings.TrimSuffix(id, ".json")
		if id != "" {
			ids = append(ids, id)
		}
		if len(ids) >= osvDeltaCeiling {
			break
		}
	}
	return ids, newest, nil
}

// -------------------------------------------------------------------- GHSA

// GHSACollector reads the GitHub Advisory Database repository directly. It
// overlaps OSV.dev but is fetched separately on purpose: GitHub publishes
// advisories here first, and the repository carries reviewed advisories that
// have no CVE at all.
type GHSACollector struct{}

// Name identifies the collector.
func (c *GHSACollector) Name() string { return "ghsa" }

const ghsaZip = "https://api.github.com/repos/github/advisory-database/zipball"

// Run executes the collector. The archive is conditional on its ETag, so an
// unchanged repository costs one request, and the sink's content-hash check
// means unchanged advisories cost a comparison rather than a merge.
func (c *GHSACollector) Run(ctx context.Context, r *Run) error {
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{
		URL:         ghsaZip,
		IfNoneMatch: r.Cursor["etag"],
	})
	if err != nil {
		return fmt.Errorf("ghsa: fetch: %w", err)
	}
	if resp.NotModified {
		resp.Body.Close()
		r.Log.Info("advisory database unchanged since last run")
		setCursorTime(r.Cursor, "last_run", time.Now().UTC())
		return nil
	}

	tmp, err := os.CreateTemp("", "ghsa-*.zip")
	if err != nil {
		resp.Body.Close()
		return fmt.Errorf("ghsa: temp file: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)

	_, copyErr := io.Copy(tmp, resp.Body)
	tmp.Close()
	resp.Body.Close()
	if copyErr != nil {
		return fmt.Errorf("ghsa: download: %w", copyErr)
	}

	reviewedOnly := r.Cursor["reviewed_only"] == "true"
	accept := func(name string) bool {
		if !strings.Contains(name, "/advisories/") {
			return false
		}
		if reviewedOnly && !strings.Contains(name, "/github-reviewed/") {
			return false
		}
		return strings.Contains(name[strings.LastIndex(name, "/")+1:], "GHSA-")
	}

	var reviewed, unreviewed, skipped int64
	if err := walkZipJSONErr(path, accept, func(name string, data []byte) error {
		v, perr := parse.OSVToModel(data, c.Name())
		if perr != nil {
			skipped++
			return nil
		}
		// The repository path is the only place the review status is recorded;
		// it is not in the advisory body. Unreviewed advisories carry no
		// package or version data, so a consumer has to be able to tell them
		// apart from the curated ones.
		if strings.Contains(name, "/github-reviewed/") {
			v.Tags = append(v.Tags, "github-reviewed")
			reviewed++
		} else {
			v.Tags = append(v.Tags, "github-unreviewed")
			unreviewed++
		}
		return r.Emit(ctx, v)
	}, func(name string, err error) {
		skipped++
		r.Log.Warn("ghsa member unreadable", "member", name, "error", err)
	}); err != nil {
		return err
	}
	if reviewed+unreviewed == 0 {
		return errors.New("ghsa: archive produced no advisories, refusing to record its etag")
	}
	r.Log.Info("advisory database ingested",
		"reviewed", reviewed, "unreviewed", unreviewed, "skipped", skipped)

	if resp.ETag != "" {
		r.Cursor["etag"] = resp.ETag
	}
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	return nil
}
