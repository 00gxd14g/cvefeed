package collect

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
)

// --------------------------------------------------------------------- KEV

// KEVCollector reads CISA's Known Exploited Vulnerabilities catalogue.
//
// It fetches from the cisagov/kev-data GitHub mirror by default rather than
// cisa.gov: the mirror is synchronised within minutes, carries a git history
// that makes changes auditable, and is CC0. The canonical cisa.gov feed is kept
// as the fallback so a GitHub outage cannot blind the most important signal in
// the whole pipeline.
type KEVCollector struct{}

// Name identifies the collector.
func (c *KEVCollector) Name() string { return "kev" }

var kevURLs = []string{
	"https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
	"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

type kevCatalog struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID             string   `json:"cveID"`
		VendorProject     string   `json:"vendorProject"`
		Product           string   `json:"product"`
		VulnerabilityName string   `json:"vulnerabilityName"`
		DateAdded         string   `json:"dateAdded"`
		ShortDescription  string   `json:"shortDescription"`
		RequiredAction    string   `json:"requiredAction"`
		DueDate           string   `json:"dueDate"`
		KnownRansomware   string   `json:"knownRansomwareCampaignUse"`
		Notes             string   `json:"notes"`
		CWEs              []string `json:"cwes"`
	} `json:"vulnerabilities"`
}

// Run executes the collector.
func (c *KEVCollector) Run(ctx context.Context, r *Run) error {
	var (
		catalog *kevCatalog
		lastErr error
		usedURL string
		etag    string
	)

	for _, u := range kevURLs {
		resp, err := r.Fetcher.Fetch(ctx, httpx.Request{URL: u, IfNoneMatch: r.Cursor["etag_"+u], NoCache: true})
		if err != nil {
			lastErr = err
			continue
		}
		if resp.NotModified {
			resp.Body.Close()
			r.Log.Info("kev catalogue unchanged", "url", u)
			setCursorTime(r.Cursor, "last_run", time.Now().UTC())
			return nil
		}
		body, err := httpx.ReadAllLimit(resp, 64<<20)
		if err != nil {
			lastErr = err
			continue
		}
		// A fresh struct per attempt. Decoding into a shared one lets a
		// partially decoded failed response leave fields behind that then
		// survive into whatever the next URL produces.
		var parsed kevCatalog
		if err := json.Unmarshal(body, &parsed); err != nil {
			lastErr = fmt.Errorf("kev: decode %s: %w", u, err)
			continue
		}
		catalog, usedURL, etag, lastErr = &parsed, u, resp.ETag, nil
		break
	}
	if lastErr != nil {
		return fmt.Errorf("kev: all sources failed: %w", lastErr)
	}
	if catalog == nil || len(catalog.Vulnerabilities) == 0 {
		return errors.New("kev: catalogue is empty, refusing to apply")
	}

	// saveETag records the validator the body came with. It is called only on
	// the two exits that leave the store consistent with the catalogue just
	// read. The runner persists the cursor even when Run returns an error, so
	// an ETag saved before the sink call would survive a failed store: the
	// next run's If-None-Match would then carry the new validator, get a 304
	// and never apply the catalogue the sink rejected — until CISA happened to
	// change the file again.
	saveETag := func() {
		if etag != "" {
			r.Cursor["etag_"+usedURL] = etag
		}
	}

	// catalogVersion is the upstream's own change marker. When it has not
	// moved there is nothing to apply, whatever the transport said about
	// caching. The fresh ETag is still saved: without it the next run's
	// If-None-Match carries a stale value and pulls the 3 MB catalogue again —
	// on every run, for as long as the version stays put.
	if v := strings.TrimSpace(catalog.CatalogVersion); v != "" && v == r.Cursor["catalog_version"] {
		saveETag()
		r.Log.Info("kev catalogue version unchanged", "version", v, "entries", len(catalog.Vulnerabilities))
		setCursorTime(r.Cursor, "last_run", time.Now().UTC())
		return nil
	}

	released := model.ParseTime(catalog.DateReleased)
	entries := make([]model.KEV, 0, len(catalog.Vulnerabilities))
	for _, e := range catalog.Vulnerabilities {
		id := model.NormalizeID(e.CVEID)
		if id == "" {
			continue
		}
		use := strings.TrimSpace(e.KnownRansomware)
		entries = append(entries, model.KEV{
			CVEID:             id,
			CatalogVersion:    catalog.CatalogVersion,
			DateReleased:      released,
			VendorProject:     e.VendorProject,
			Product:           e.Product,
			VulnerabilityName: e.VulnerabilityName,
			ShortDescription:  e.ShortDescription,
			RequiredAction:    e.RequiredAction,
			Notes:             e.Notes,
			CWEs:              model.DedupeStrings(e.CWEs),
			DateAdded:         model.ParseTime(e.DateAdded),
			DueDate:           model.ParseTime(e.DueDate),
			// The upstream field is three-state ("Known", "Unknown", ""); the
			// boolean keeps the query cheap and the string keeps the nuance.
			RansomwareUse:   use,
			KnownRansomware: strings.EqualFold(use, "known"),
			Sources:         []string{"cisa_kev"},
			Source:          c.Name(),
		})
	}

	// This is CISA's own catalogue in full, so an entry it no longer lists
	// has been withdrawn; the sink retires it. ENISA's consolidated dump is
	// not passed this way: it mirrors other catalogues and may lag them, and
	// retiring on its say-so would drop an entry CISA added an hour ago.
	if err := r.Sink.KEVCatalogue(ctx, entries); err != nil {
		return fmt.Errorf("kev: store: %w", err)
	}
	r.AddSeen(int64(len(entries)))

	saveETag()
	r.Cursor["catalog_version"] = catalog.CatalogVersion
	if released != nil {
		setCursorTime(r.Cursor, "date_released", *released)
	}
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	r.Log.Info("kev catalogue ingested", "entries", len(entries), "version", catalog.CatalogVersion, "url", usedURL)
	return nil
}

// -------------------------------------------------------------------- EPSS

// EPSSCollector reads FIRST's Exploit Prediction Scoring System.
//
// It takes the daily bulk CSV rather than the per-CVE API. The whole corpus is
// rescored every day, so pulling one gzipped file beats a quarter of a million
// API calls, and the URL is stable by design.
type EPSSCollector struct{}

// Name identifies the collector.
func (c *EPSSCollector) Name() string { return "epss" }

const epssCurrentCSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// Run executes the collector.
func (c *EPSSCollector) Run(ctx context.Context, r *Run) error {
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{
		URL:         epssCurrentCSV,
		IfNoneMatch: r.Cursor["etag"],
	})
	if err != nil {
		return fmt.Errorf("epss: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.NotModified {
		r.Log.Info("epss scores unchanged since last run")
		setCursorTime(r.Cursor, "last_run", time.Now().UTC())
		return nil
	}

	gz, err := gzip.NewReader(bufio.NewReaderSize(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("epss: gzip reader: %w", err)
	}
	defer gz.Close()

	scoreDate := time.Now().UTC().Truncate(24 * time.Hour)
	modelVersion := ""
	reader := csv.NewReader(gz)
	reader.FieldsPerRecord = -1

	scores := make([]model.EPSS, 0, 300000)
	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("epss: parse csv: %w", err)
		}
		if len(rec) == 0 {
			continue
		}
		// The file opens with a "#model_version:...,score_date:..." comment row
		// and then a header row; both fail the CVE test below.
		if strings.HasPrefix(rec[0], "#") {
			if d := extractScoreDate(rec); d != nil {
				scoreDate = *d
			}
			if mv := extractModelVersion(rec); mv != "" {
				modelVersion = mv
			}
			continue
		}
		if len(rec) < 3 || !model.IsCVE(rec[0]) {
			continue
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(rec[2]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		scores = append(scores, model.EPSS{
			CVEID: model.NormalizeID(rec[0]), Score: score, Percentile: pct,
			ScoreDate: scoreDate, ModelVersion: modelVersion, Source: c.Name(),
		})
	}

	if len(scores) == 0 {
		return errors.New("epss: no scores parsed, refusing to apply")
	}
	// A truncated download decompresses cleanly up to the cut and would
	// otherwise be applied as a much smaller corpus. FIRST scores every
	// published CVE every day, so a file an order of magnitude short of the
	// last run is a transfer failure, not a model change.
	if prev := cursorInt(r.Cursor, "row_count"); prev > 0 && len(scores) < prev/2 {
		return fmt.Errorf("epss: only %d rows parsed against %d last run; refusing to apply a likely truncated file",
			len(scores), prev)
	}

	if err := r.Sink.EPSS(ctx, scores); err != nil {
		return fmt.Errorf("epss: store: %w", err)
	}
	r.AddSeen(int64(len(scores)))

	if resp.ETag != "" {
		r.Cursor["etag"] = resp.ETag
	}
	r.Cursor["score_date"] = scoreDate.Format("2006-01-02")
	r.Cursor["model_version"] = modelVersion
	r.Cursor["row_count"] = strconv.Itoa(len(scores))
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	r.Log.Info("epss scores ingested",
		"count", len(scores), "score_date", scoreDate.Format("2006-01-02"), "model", modelVersion)
	return nil
}

// extractScoreDate pulls score_date out of the CSV's leading comment row so the
// stored date reflects the model run rather than our download time.
func extractScoreDate(rec []string) *time.Time {
	for _, field := range rec {
		field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(field), "#"))
		if !strings.HasPrefix(field, "score_date:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(field, "score_date:"))
		t := model.ParseTime(val)
		if t == nil {
			// FIRST has published both "…T12:03:47Z" and "…T00:00:00+0000".
			// The second spelling has no colon in the offset, which RFC3339
			// rejects.
			if parsed, err := time.Parse("2006-01-02T15:04:05-0700", val); err == nil {
				u := parsed.UTC()
				t = &u
			}
		}
		if t != nil {
			d := t.Truncate(24 * time.Hour)
			return &d
		}
	}
	return nil
}

// extractModelVersion pulls model_version out of the same comment row. Scores
// are only comparable within one model release, so the version travels with
// them.
func extractModelVersion(rec []string) string {
	for _, field := range rec {
		field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(field), "#"))
		if strings.HasPrefix(field, "model_version:") {
			return strings.TrimSpace(strings.TrimPrefix(field, "model_version:"))
		}
	}
	return ""
}

func cursorInt(cursor map[string]string, key string) int {
	n, err := strconv.Atoi(strings.TrimSpace(cursor[key]))
	if err != nil {
		return 0
	}
	return n
}
