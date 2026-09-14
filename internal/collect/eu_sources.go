package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/parse"
)

// -------------------------------------------------------------------- EUVD

// EUVDCollector reads the ENISA European Union Vulnerability Database, the
// NIS2 Article 12 repository. Beyond redundancy against a US-operated single
// point of failure, it carries EU CSIRT-coordinated advisories that never reach
// the CVE List, and a consolidated KEV that merges CISA KEV with EU KEV.
type EUVDCollector struct{}

// Name identifies the collector.
func (c *EUVDCollector) Name() string { return "euvd" }

const (
	euvdBase     = "https://euvdservices.enisa.europa.eu/api"
	euvdPageSize = 100 // API hard limit per request
	// euvdBackfillWindow bounds a delta run that has no cursor yet. Without it
	// the first "incremental" run walks the entire ~378,000-record corpus one
	// hundred records at a time.
	euvdBackfillWindow = 90 * 24 * time.Hour
)

type euvdSearchResponse struct {
	// Items stay raw so the stored document is the upstream's, not a
	// re-serialisation of the subset this parser happens to model.
	Items []json.RawMessage `json:"items"`
	Total int               `json:"total"`
}

type euvdItem struct {
	ID               string  `json:"id"`
	Description      string  `json:"description"`
	DatePublished    string  `json:"datePublished"`
	DateUpdated      string  `json:"dateUpdated"`
	BaseScore        float64 `json:"baseScore"`
	BaseScoreVersion string  `json:"baseScoreVersion"`
	BaseScoreVector  string  `json:"baseScoreVector"`
	References       string  `json:"references"`
	Aliases          string  `json:"aliases"`
	Assigner         string  `json:"assigner"`
	EPSS             float64 `json:"epss"`
	// The field is `exploitedSince` and it is a date string, not a boolean.
	// Decoding it as `exploitedSinceDate bool` silently dropped the EU
	// exploitation signal on every record — and would have failed the whole
	// page decode had the misspelled key ever existed.
	ExploitedSince string `json:"exploitedSince"`
	Products       []struct {
		ID      string `json:"id"`
		Product struct {
			Name   string `json:"name"`
			Vendor struct {
				Name string `json:"name"`
			} `json:"vendor"`
		} `json:"product"`
		ProductVersion string `json:"product_version"`
	} `json:"enisaIdProduct"`
	Vendors []struct {
		ID     string `json:"id"`
		Vendor struct {
			Name string `json:"name"`
		} `json:"vendor"`
	} `json:"enisaIdVendor"`
}

// Run executes the collector.
func (c *EUVDCollector) Run(ctx context.Context, r *Run) error {
	if err := c.searchWindow(ctx, r); err != nil {
		return err
	}
	return c.kevDump(ctx, r)
}

// searchWindow pages the search endpoint. In delta mode it restricts the window
// with fromDate so the paging stays short; in backfill mode it walks everything.
//
// EUVD has no updatedSince parameter — the research is explicit that the only
// cursor available is datePublished — so a delta window is a sliding
// publication window with deliberate overlap, not a modification watermark.
func (c *EUVDCollector) searchWindow(ctx context.Context, r *Run) error {
	q := url.Values{}
	q.Set("fromScore", "0")
	q.Set("toScore", "10")
	q.Set("size", fmt.Sprint(euvdPageSize))

	startedAt := time.Now().UTC()
	if r.Mode == ModeDelta {
		from := startedAt.Add(-euvdBackfillWindow)
		if since := cursorTime(r.Cursor, "last_run"); since != nil {
			from = since.Add(-48 * time.Hour)
		}
		q.Set("fromDate", from.Format("2006-01-02"))
		q.Set("toDate", startedAt.Format("2006-01-02"))
	}

	var (
		exploited []model.KEV
		seen      int
	)
	page := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q.Set("page", fmt.Sprint(page))

		var resp euvdSearchResponse
		if err := fetchJSON(ctx, r.Fetcher, euvdBase+"/search?"+q.Encode(), &resp); err != nil {
			return fmt.Errorf("euvd: search page %d: %w", page, err)
		}
		if len(resp.Items) == 0 {
			// An empty page before the reported total means the walk was cut
			// short. Committing the cursor here would declare the window
			// covered when it is not.
			if resp.Total > 0 && seen < resp.Total {
				return fmt.Errorf("euvd: page %d returned nothing with %d of %d records read",
					page, seen, resp.Total)
			}
			break
		}
		for _, raw := range resp.Items {
			v, kev := c.toModel(raw)
			if v == nil {
				continue
			}
			seen++
			if kev != nil {
				exploited = append(exploited, *kev)
			}
			if err := r.Emit(ctx, v); err != nil {
				return err
			}
		}

		page++
		if page*euvdPageSize >= resp.Total {
			break
		}
		if page > 20000 {
			return fmt.Errorf("euvd: refusing to page beyond %d pages", page)
		}
	}

	// ENISA's exploitation flag is the EU-side equivalent of KEV membership and
	// the README sells it as part of the consolidated catalogue, so it has to
	// reach the same table.
	if len(exploited) > 0 {
		if err := r.Sink.KEV(ctx, exploited); err != nil {
			return fmt.Errorf("euvd: store exploited flags: %w", err)
		}
		r.AddSeen(int64(len(exploited)))
		r.Log.Info("euvd exploited vulnerabilities recorded", "entries", len(exploited))
	}

	setCursorTime(r.Cursor, "last_run", startedAt)
	return nil
}

// toModel converts one EUVD record, and returns a KEV entry as well when ENISA
// marks it as exploited.
func (c *EUVDCollector) toModel(raw json.RawMessage) (*model.Vulnerability, *model.KEV) {
	var item euvdItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, nil
	}
	id := model.NormalizeID(item.ID)
	if id == "" {
		return nil, nil
	}

	v := &model.Vulnerability{
		ID:                id,
		Description:       item.Description,
		State:             "PUBLISHED",
		Published:         model.ParseTime(item.DatePublished),
		Modified:          model.ParseTime(item.DateUpdated),
		AssignerShortName: item.Assigner,
		Source:            c.Name(),
		SourceRecordID:    id,
		// The upstream document verbatim. Re-marshalling the parsed struct
		// stored a lossy copy under invented key names, which defeats the
		// whole point of keeping a raw layer to re-derive from.
		Raw: raw,
	}

	// EUVD packs aliases and references into newline-delimited strings.
	v.Aliases = model.DedupeStrings(splitLines(item.Aliases))
	for _, ref := range splitLines(item.References) {
		v.References = append(v.References, model.Reference{URL: ref, Source: c.Name()})
	}

	if item.BaseScoreVector != "" || item.BaseScore > 0 {
		typ := model.CVSSTypeFromVector(item.BaseScoreVector)
		if typ == "OTHER" {
			switch item.BaseScoreVersion {
			case "4.0":
				typ = "CVSS_V4_0"
			case "3.1":
				typ = "CVSS_V3_1"
			case "3.0":
				typ = "CVSS_V3_0"
			case "2.0":
				typ = "CVSS_V2"
			}
		}
		sev := model.Severity{
			Type: typ, Score: item.BaseScore, Vector: item.BaseScoreVector,
			Provider: "enisa", Source: c.Name(),
		}
		if item.BaseScore > 0 {
			sev.Rating = model.RatingFromScore(item.BaseScore)
		}
		v.Severities = append(v.Severities, sev)
	}

	fallbackVendor := ""
	if len(item.Vendors) > 0 {
		fallbackVendor = item.Vendors[0].Vendor.Name
	}
	for _, p := range item.Products {
		// Each product carries its own vendor. Attributing them all to the
		// first vendor in the record mislabels every multi-vendor advisory,
		// which is most ICS coordination cases.
		vendor := p.Product.Vendor.Name
		if vendor == "" {
			vendor = fallbackVendor
		}
		af := model.Affected{Vendor: vendor, Product: p.Product.Name, Source: c.Name()}
		if p.ProductVersion != "" {
			af.Versions = []string{p.ProductVersion}
		}
		v.Affected = append(v.Affected, af)
	}

	var kev *model.KEV
	if strings.TrimSpace(item.ExploitedSince) != "" {
		// KEV is keyed on a CVE id, so route through the CVE alias when there
		// is one and fall back to the EUVD id otherwise.
		target := id
		for _, a := range v.Aliases {
			if model.IsCVE(a) {
				target = a
				break
			}
		}
		kev = &model.KEV{
			CVEID:     target,
			DateAdded: model.ParseTime(item.ExploitedSince),
			Sources:   []string{"eu_exploited"},
			Source:    c.Name(),
		}
	}
	return v, kev
}

// kevDump ingests the consolidated CISA KEV + EU KEV list ENISA refreshes daily.
func (c *EUVDCollector) kevDump(ctx context.Context, r *Run) error {
	var entries []struct {
		CVEID     string   `json:"cveId"`
		EUVDID    string   `json:"euvdId"`
		DateAdded string   `json:"dateAdded"`
		Sources   []string `json:"sources"`
	}
	if err := fetchJSON(ctx, r.Fetcher, euvdBase+"/kev/dump", &entries); err != nil {
		r.Log.Warn("euvd kev dump unavailable", "error", err)
		return nil
	}

	out := make([]model.KEV, 0, len(entries))
	for _, e := range entries {
		id := model.NormalizeID(e.CVEID)
		if id == "" {
			continue
		}
		out = append(out, model.KEV{
			CVEID:     id,
			DateAdded: model.ParseTime(e.DateAdded),
			Sources:   e.Sources,
			Source:    c.Name(),
		})
	}
	if len(out) == 0 {
		return nil
	}
	if err := r.Sink.KEV(ctx, out); err != nil {
		return fmt.Errorf("euvd: store kev: %w", err)
	}
	r.AddSeen(int64(len(out)))
	r.Log.Info("euvd consolidated kev ingested", "entries", len(out))
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, part := range strings.Split(s, "\n") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// -------------------------------------------------------------------- GCVE

// GCVECollector reads a Vulnerability-Lookup instance (CIRCL's public service
// by default) and the signed GCVE Numbering Authority registry.
//
// GCVE matters here because it is the decentralised identifier scheme: GNA ID 0
// restates existing CVEs, so GCVE-0-2023-40224 and CVE-2023-40224 must collapse
// into one record. That mapping is emitted as an alias.
type GCVECollector struct {
	BaseURL string
}

// Name identifies the collector.
func (c *GCVECollector) Name() string { return "gcve" }

const (
	gcveRegistry = "https://gcve.eu/dist/gcve.json"
	// A Vulnerability-Lookup page is the union of whatever schemas its sources
	// use, and a single Red Hat CSAF document runs to megabytes: 100 records
	// came back as a 34 MB response that regularly truncated mid-transfer.
	vlPageSize = 25
	// CIRCL publishes 20 requests/minute and each page of 25 records runs to
	// several megabytes, because a page is the union of whatever schemas its
	// sources use and one Red Hat CSAF document is large. Sustained paging is
	// measurably unreliable past a couple of dozen pages, so a run is bounded
	// and the remainder is picked up on the next tick.
	vlMaxPages = 40
)

type gcveGNA struct {
	ID            int    `json:"id"`
	ShortName     string `json:"short_name"`
	FullName      string `json:"full_name"`
	GCVEURL       string `json:"gcve_url"`
	GCVEAPI       string `json:"gcve_api"`
	GCVEDump      string `json:"gcve_dump"`
	GCVEPullAPI   string `json:"gcve_pull_api"`
	CPEVendorName string `json:"cpe_vendor_name"`
}

// Run executes the collector.
func (c *GCVECollector) Run(ctx context.Context, r *Run) error {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://vulnerability.circl.lu"
	}

	// The GNA registry is small, signed and rarely changes; record it so the
	// air-gapped side can resolve GNA IDs to organisations.
	var gnas []gcveGNA
	if err := fetchJSON(ctx, r.Fetcher, gcveRegistry, &gnas); err != nil {
		r.Log.Warn("gcve registry unavailable", "error", err)
	} else {
		r.Cursor["gna_count"] = fmt.Sprint(len(gnas))
		if encoded, err := json.Marshal(gnaIndex(gnas)); err == nil {
			r.Cursor["gna_index"] = string(encoded)
		}
		r.Log.Info("gcve registry pulled", "gnas", len(gnas))
	}

	startedAt := time.Now().UTC()
	since := cursorTime(r.Cursor, "last_run")
	if since == nil || r.Mode == ModeBackfill {
		// Vulnerability-Lookup is a correlation service, not a bulk archive:
		// the sources it aggregates are already collected directly here. A
		// bounded window keeps this adapter useful without duplicating them.
		t := startedAt.AddDate(0, -3, 0)
		since = &t
	}

	// A walk that hit the page ceiling is resumed where it stopped rather
	// than restarted. The API only offers since= (a date) and page=, sorted
	// newest-first, so page N+1 of the same window is older than everything
	// already read: records updated in between push the boundary outwards,
	// which costs a few duplicates and never skips anything. Restarting from
	// page 1 read the same newest thousand records on every run, never
	// reached the older part of the window, and the collector could not
	// finish. A backfill deliberately starts a fresh walk.
	walkStart, page := startedAt, 1
	if r.Mode != ModeBackfill {
		if s, p, w, ok := vlResume(r.Cursor); ok {
			since, page, walkStart = s, p, w
			r.Log.Info("vulnerability-lookup resuming an open window",
				"since", since.Format("2006-01-02"), "page", page)
		}
	}
	vlSetResume(r.Cursor, *since, page, walkStart)

	total := 0
	complete := false
	var pageErr error
	read := 0
	for ; read < vlMaxPages; read++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("since", since.Format("2006-01-02"))
		q.Set("per_page", fmt.Sprint(vlPageSize))
		q.Set("page", fmt.Sprint(page))
		q.Set("date_sort", "updated")
		u := fmt.Sprintf("%s/api/vulnerability/?%s", base, q.Encode())

		// Streamed rather than buffered: the records are emitted as they are
		// decoded, so a response that dies mid-transfer still delivers
		// everything that arrived before the break.
		count, err := c.streamPage(ctx, r, u, &total)
		if err != nil {
			pageErr = fmt.Errorf("page %d: %w", page, err)
			break
		}
		if count < vlPageSize {
			complete = true
			break
		}
		page++
		// Persisted per page: the runner saves whatever is in the cursor even
		// when the run ends in an error, so a page that failed is retried and
		// the ones before it are not.
		r.Cursor["vl_page"] = fmt.Sprint(page)
	}

	r.Log.Info("vulnerability-lookup ingested",
		"records", total, "pages", read, "since", since.Format("2006-01-02"),
		"next_page", page, "complete", complete)

	// The watermark moves only when the whole window was read, and it moves
	// to the walk's start rather than its end: anything updated while the
	// pages were being read sits on page 1 of the next window, which begins
	// at that start. Re-reading a day is cheap — the sink compares content
	// hashes before it merges anything.
	if complete {
		vlClearResume(r.Cursor)
		setCursorTime(r.Cursor, "last_run", walkStart)
		return nil
	}
	if pageErr != nil {
		return fmt.Errorf("gcve: %w (walk resumes at page %d next run; %d records ingested)", pageErr, page, total)
	}
	// The ceiling is pacing, not failure: the walk made progress and the next
	// run continues from the page it stopped at.
	r.Log.Info("vulnerability-lookup window still open at the page ceiling; resuming next run",
		"pages", vlMaxPages, "next_page", page, "records", total)
	return nil
}

// vlResume reads the in-progress walk from the cursor: the window's since
// date, the next page to read and the instant the walk began. The three keys
// are only meaningful together.
//
// A replay-from rewrites vl_started to the replay instant like every other
// timestamp, so a resumed walk that then completes rests last_run on the
// replay instant and the following run re-reads from there, as intended.
func vlResume(cursor map[string]string) (since *time.Time, page int, walkStart time.Time, ok bool) {
	s, err := time.Parse("2006-01-02", cursor["vl_since"])
	if err != nil {
		return nil, 0, time.Time{}, false
	}
	p, err := strconv.Atoi(cursor["vl_page"])
	if err != nil || p < 1 {
		return nil, 0, time.Time{}, false
	}
	w := cursorTime(cursor, "vl_started")
	if w == nil {
		return nil, 0, time.Time{}, false
	}
	su := s.UTC()
	return &su, p, *w, true
}

func vlSetResume(cursor map[string]string, since time.Time, page int, walkStart time.Time) {
	cursor["vl_since"] = since.UTC().Format("2006-01-02")
	cursor["vl_page"] = fmt.Sprint(page)
	setCursorTime(cursor, "vl_started", walkStart)
}

func vlClearResume(cursor map[string]string) {
	delete(cursor, "vl_since")
	delete(cursor, "vl_page")
	delete(cursor, "vl_started")
}

// streamPage decodes one Vulnerability-Lookup page, emitting records as they
// are read, and reports how many the page contained.
func (c *GCVECollector) streamPage(ctx context.Context, r *Run, u string, total *int) (int, error) {
	resp, err := r.Fetcher.Fetch(ctx, httpx.Request{URL: u})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("read first token: %w", err)
	}

	count := 0
	emit := func(raw json.RawMessage) error {
		count++
		v := c.toModel(raw)
		if v == nil {
			return nil
		}
		*total++
		return r.Emit(ctx, v)
	}

	d, isDelim := tok.(json.Delim)
	switch {
	case isDelim && d == '[':
		// The public 5.x instance answers with a bare array; its own
		// documentation describes {metadata, data}. Both are accepted.
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return count, fmt.Errorf("decode record %d: %w", count, err)
			}
			if err := emit(raw); err != nil {
				return count, err
			}
		}
		return count, nil

	case isDelim && d == '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return count, err
			}
			key, _ := keyTok.(string)
			if key != "data" && key != "vulnerabilities" && key != "results" {
				var discard json.RawMessage
				if err := dec.Decode(&discard); err != nil {
					return count, err
				}
				continue
			}
			open, err := dec.Token()
			if err != nil {
				return count, err
			}
			if od, ok := open.(json.Delim); !ok || od != '[' {
				return count, fmt.Errorf("%s is not an array", key)
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return count, fmt.Errorf("decode record %d: %w", count, err)
				}
				if err := emit(raw); err != nil {
					return count, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return count, err
			}
		}
		return count, nil

	default:
		return 0, fmt.Errorf("unexpected JSON document starting with %v", tok)
	}
}

func gnaIndex(gnas []gcveGNA) map[string]string {
	out := make(map[string]string, len(gnas))
	for _, g := range gnas {
		name := g.ShortName
		if name == "" {
			name = g.FullName
		}
		out[fmt.Sprint(g.ID)] = name
	}
	return out
}

// decodeVLPage copes with both shapes a Vulnerability-Lookup instance returns.
//
// The documented response is {metadata:{...}, data:[...]}; the public 5.x
// instance answers with a bare JSON array. Decoding straight into a struct
// therefore failed with "cannot unmarshal array into Go value", which the
// caller logged as a warning and turned into a permanently empty collector.
func decodeVLPage(body []byte) ([]json.RawMessage, error) {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var envelope struct {
		Data            []json.RawMessage `json:"data"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Results         []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	switch {
	case len(envelope.Data) > 0:
		return envelope.Data, nil
	case len(envelope.Vulnerabilities) > 0:
		return envelope.Vulnerabilities, nil
	default:
		return envelope.Results, nil
	}
}

// toModel handles the several document shapes a Vulnerability-Lookup instance
// returns, since it republishes records in whatever schema their source used.
//
// In practice a single page mixes CSAF advisories (Red Hat), CVE 5.x records
// and OSV documents. Probing only for a flat {id, aliases, …} object dropped
// the overwhelming majority of them.
func (c *GCVECollector) toModel(raw []byte) *model.Vulnerability {
	var shape struct {
		CVEMetadata json.RawMessage `json:"cveMetadata"`
		Document    json.RawMessage `json:"document"`
		Affected    json.RawMessage `json:"affected"`
		ID          string          `json:"id"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil
	}

	switch {
	case len(shape.CVEMetadata) > 0:
		if v, err := parse.CVE5ToModel(raw, c.Name()); err == nil {
			return c.withGCVEAlias(v)
		}
	case len(shape.Document) > 0:
		for _, v := range parseCSAF(raw, c.Name(), "") {
			// One CSAF document describes many vulnerabilities; the caller
			// emits one record, so take the first and let the direct CSAF
			// collector handle full fidelity.
			return c.withGCVEAlias(v)
		}
		return nil
	case shape.ID != "" && len(shape.Affected) > 0:
		if v, err := parse.OSVToModel(raw, c.Name()); err == nil {
			return c.withGCVEAlias(v)
		}
	}
	return c.withGCVEAlias(c.probeGeneric(raw))
}

// probeGeneric handles the flat GCVE/VL shape.
func (c *GCVECollector) probeGeneric(raw []byte) *model.Vulnerability {
	var probe struct {
		ID          string   `json:"id"`
		GCVEID      string   `json:"gcve_id"`
		Aliases     []string `json:"aliases"`
		Title       string   `json:"title"`
		Summary     string   `json:"summary"`
		Description string   `json:"description"`
		Published   string   `json:"published"`
		Modified    string   `json:"modified"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil
	}
	id := probe.GCVEID
	if id == "" {
		id = probe.ID
	}
	id = model.NormalizeID(id)
	if id == "" {
		return nil
	}

	return &model.Vulnerability{
		ID:             id,
		Title:          firstNonEmpty(probe.Title, probe.Summary),
		Description:    firstNonEmpty(probe.Description, probe.Summary),
		State:          "PUBLISHED",
		Published:      model.ParseTime(probe.Published),
		Modified:       model.ParseTime(probe.Modified),
		Aliases:        probe.Aliases,
		Source:         c.Name(),
		SourceRecordID: id,
		Raw:            raw,
	}
}

// withGCVEAlias emits the GNA-0 equivalence. GCVE-0-YYYY-NNNN is by definition
// the CVE with the same tail; without the alias the two identifiers become two
// records for one flaw.
func (c *GCVECollector) withGCVEAlias(v *model.Vulnerability) *model.Vulnerability {
	if v == nil {
		return nil
	}
	v.Source = c.Name()
	if strings.HasPrefix(strings.ToUpper(v.ID), "GCVE-0-") {
		v.Aliases = append(v.Aliases, "CVE-"+strings.TrimPrefix(strings.ToUpper(v.ID), "GCVE-0-"))
	}
	v.Aliases = model.DedupeStrings(v.Aliases)
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// -------------------------------------------------------------------- CSAF

// CSAFCollector walks OASIS CSAF 2.0 providers. This is the OT/ICS path: the
// vendors that matter for industrial estates — Siemens, Schneider, Rockwell,
// Cisco, Red Hat, CERT-Bund — all publish machine-readable advisories through
// the standard discovery file, and their VEX statements say which products are
// genuinely affected rather than merely containing the component.
type CSAFCollector struct {
	Providers []string
}

// Name identifies the collector.
func (c *CSAFCollector) Name() string { return "csaf" }

type csafProviderMetadata struct {
	CanonicalURL string `json:"canonical_url"`
	Publisher    struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"publisher"`
	Distributions []struct {
		DirectoryURL string `json:"directory_url"`
		Rolie        struct {
			Feeds []struct {
				Summary  string `json:"summary"`
				TLPLabel string `json:"tlp_label"`
				URL      string `json:"url"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

type rolieFeed struct {
	Feed struct {
		Updated string `json:"updated"`
		Entry   []struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Updated string `json:"updated"`
			Link    []struct {
				Rel  string `json:"rel"`
				HRef string `json:"href"`
			} `json:"link"`
		} `json:"entry"`
	} `json:"feed"`
}

// Run executes the collector across every configured provider.
func (c *CSAFCollector) Run(ctx context.Context, r *Run) error {
	if len(c.Providers) == 0 {
		r.Log.Info("no CSAF providers configured; set CVEFEED_CSAF_PROVIDERS")
		return nil
	}
	var failures []string
	for _, p := range c.Providers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.runProvider(ctx, r, p); err != nil {
			r.Log.Warn("csaf provider failed", "provider", p, "error", err)
			failures = append(failures, p)
		}
	}
	setCursorTime(r.Cursor, "last_run", time.Now().UTC())
	if len(failures) == len(c.Providers) {
		return fmt.Errorf("csaf: every configured provider failed: %s", strings.Join(failures, ", "))
	}
	if len(failures) > 0 {
		return fmt.Errorf("csaf: %d of %d providers failed: %s",
			len(failures), len(c.Providers), strings.Join(failures, ", "))
	}
	return nil
}

func (c *CSAFCollector) runProvider(ctx context.Context, r *Run, provider string) error {
	metaURL := provider
	if !strings.HasSuffix(metaURL, ".json") {
		metaURL = strings.TrimRight(provider, "/") + "/.well-known/csaf/provider-metadata.json"
	}

	var meta csafProviderMetadata
	if err := fetchJSON(ctx, r.Fetcher, metaURL, &meta); err != nil {
		return fmt.Errorf("provider metadata: %w", err)
	}
	publisher := meta.Publisher.Name
	if publisher == "" {
		publisher = provider
	}
	// The cursor key is derived from the configured provider, not from the
	// publisher name in the document: an upstream that renames itself would
	// otherwise silently reset its own progress.
	sinceKey := "since_" + cursorKey(provider)
	since := cursorTime(r.Cursor, sinceKey)

	var feedURLs, directoryURLs []string
	for _, d := range meta.Distributions {
		for _, f := range d.Rolie.Feeds {
			if f.URL != "" {
				feedURLs = append(feedURLs, f.URL)
			}
		}
		if d.DirectoryURL != "" {
			directoryURLs = append(directoryURLs, d.DirectoryURL)
		}
	}
	if len(feedURLs) == 0 && len(directoryURLs) == 0 {
		return fmt.Errorf("provider advertises neither a ROLIE feed nor a directory distribution")
	}

	docs := map[string]time.Time{} // advisory URL -> updated
	for _, feedURL := range feedURLs {
		found, err := c.rolieEntries(ctx, r, feedURL)
		if err != nil {
			r.Log.Warn("csaf feed unreadable", "feed", feedURL, "error", err)
			continue
		}
		for u, at := range found {
			docs[u] = at
		}
	}
	// Directory distributions are a first-class part of the specification and
	// several verified providers (Red Hat, Schneider, NCSC-NL, SUSE) publish
	// only that way. Refusing them left most of the CSAF corpus unreachable.
	for _, dirURL := range directoryURLs {
		found, err := c.directoryEntries(ctx, r, dirURL, since)
		if err != nil {
			r.Log.Warn("csaf directory unreadable", "directory", dirURL, "error", err)
			continue
		}
		for u, at := range found {
			if _, ok := docs[u]; !ok {
				docs[u] = at
			}
		}
	}
	if len(docs) == 0 {
		return nil
	}

	type advisory struct {
		url string
		at  time.Time
	}
	pending := make([]advisory, 0, len(docs))
	for u, at := range docs {
		if since != nil && !at.IsZero() && !at.After(*since) {
			continue
		}
		pending = append(pending, advisory{url: u, at: at})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].at.Before(pending[j].at) })

	// lastGood only advances past advisories that were actually ingested, and
	// never past the moment this walk began: a feed entry dated in the future
	// would otherwise carry the cursor past every advisory published between
	// now and then.
	var lastGood time.Time
	var failures int
	startedAt := time.Now().UTC()
	for _, a := range pending {
		if err := ctx.Err(); err != nil {
			break
		}
		data, err := fetchBytes(ctx, r.Fetcher, a.url)
		if err != nil {
			r.Log.Warn("csaf advisory fetch failed", "url", a.url, "error", err)
			failures++
			break
		}
		// The specification requires integrity checking; a .sha256 sidecar is
		// published beside every advisory by conforming providers.
		if err := c.verifySHA256(ctx, r, a.url, data); err != nil {
			r.Log.Warn("csaf advisory failed integrity check", "url", a.url, "error", err)
			failures++
			break
		}
		emitted := 0
		for _, v := range parseCSAF(data, c.Name(), publisher) {
			emitted++
			if err := r.Emit(ctx, v); err != nil {
				return err
			}
		}
		if emitted == 0 {
			r.Log.Debug("csaf advisory yielded no records", "url", a.url)
		}
		if !a.at.IsZero() {
			lastGood = a.at
		}
	}

	if lastGood.After(startedAt) {
		lastGood = startedAt
	}
	if !lastGood.IsZero() {
		setCursorTime(r.Cursor, sinceKey, lastGood)
	}
	if failures > 0 {
		return fmt.Errorf("%d advisory(ies) could not be ingested; cursor held", failures)
	}
	return nil
}

// rolieEntries reads a ROLIE feed and returns advisory URL -> updated time.
func (c *CSAFCollector) rolieEntries(ctx context.Context, r *Run, feedURL string) (map[string]time.Time, error) {
	var feed rolieFeed
	if err := fetchJSON(ctx, r.Fetcher, feedURL, &feed); err != nil {
		return nil, err
	}
	base, _ := url.Parse(feedURL)
	out := map[string]time.Time{}
	for _, entry := range feed.Feed.Entry {
		href := ""
		for _, l := range entry.Link {
			if l.Rel == "self" {
				href = l.HRef
				break
			}
			if href == "" {
				href = l.HRef
			}
		}
		if href == "" || !strings.HasSuffix(strings.ToLower(href), ".json") {
			continue
		}
		// ROLIE hrefs are permitted to be relative to the feed.
		if base != nil {
			if ref, err := url.Parse(href); err == nil {
				href = base.ResolveReference(ref).String()
			}
		}
		var at time.Time
		if t := model.ParseTime(entry.Updated); t != nil {
			at = *t
		}
		out[href] = at
	}
	return out, nil
}

// directoryEntries reads a directory distribution: changes.csv when present
// (path,timestamp, newest first is not guaranteed) and index.txt otherwise.
func (c *CSAFCollector) directoryEntries(ctx context.Context, r *Run, dirURL string, since *time.Time) (map[string]time.Time, error) {
	base := strings.TrimRight(dirURL, "/") + "/"
	out := map[string]time.Time{}

	if body, err := fetchBytes(ctx, r.Fetcher, base+"changes.csv"); err == nil {
		rows := 0
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ",", 2)
			if len(parts) != 2 {
				continue
			}
			path := strings.Trim(strings.TrimSpace(parts[0]), `"`)
			stamp := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			if !strings.HasSuffix(strings.ToLower(path), ".json") {
				continue
			}
			rows++
			var at time.Time
			if t := model.ParseTime(stamp); t != nil {
				at = *t
			}
			if since != nil && !at.IsZero() && !at.After(*since) {
				continue
			}
			out[base+strings.TrimPrefix(path, "/")] = at
		}
		// A changes.csv that parsed is authoritative even when the since
		// filter leaves nothing of it: a provider that published nothing new
		// has nothing to fetch. Falling through to index.txt on an empty
		// result re-downloaded the provider's entire corpus on every quiet
		// run — Red Hat's is 680 KB of paths alone.
		if rows > 0 {
			return out, nil
		}
		r.Log.Warn("csaf changes.csv has no usable rows; using index.txt", "directory", dirURL)
	}

	// No usable changes.csv: fall back to the full index. Everything is
	// returned with a zero timestamp, and the sink's content hash keeps an
	// unchanged advisory cheap.
	body, err := fetchBytes(ctx, r.Fetcher, base+"index.txt")
	if err != nil {
		return nil, fmt.Errorf("neither changes.csv nor index.txt is readable: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		path := strings.TrimSpace(line)
		if path == "" || !strings.HasSuffix(strings.ToLower(path), ".json") {
			continue
		}
		out[base+strings.TrimPrefix(path, "/")] = time.Time{}
	}
	return out, nil
}

// verifySHA256 checks an advisory against its published digest when the
// provider publishes one. A missing sidecar is not an error — not every
// provider ships them — but a mismatch is.
func (c *CSAFCollector) verifySHA256(ctx context.Context, r *Run, advisoryURL string, data []byte) error {
	body, err := fetchBytes(ctx, r.Fetcher, advisoryURL+".sha256")
	if err != nil {
		return nil
	}
	want := strings.TrimSpace(string(body))
	if i := strings.IndexAny(want, " \t"); i > 0 {
		want = want[:i]
	}
	want = strings.ToLower(want)
	if len(want) != 64 {
		return nil
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("sha256 mismatch: published %s, computed %s", want, got)
	}
	return nil
}

func cursorKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// csafDocument covers the parts of CSAF 2.0 we map. A CSAF advisory describes
// many vulnerabilities at once, so one document yields many records.
type csafDocument struct {
	Document struct {
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			Version            string `json:"version"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
			Status             string `json:"status"`
		} `json:"tracking"`
		Publisher struct {
			Name string `json:"name"`
		} `json:"publisher"`
		Notes []csafNote `json:"notes"`
	} `json:"document"`
	RawProductTree  json.RawMessage `json:"product_tree"`
	Vulnerabilities []struct {
		CVE   string `json:"cve"`
		Title string `json:"title"`
		IDs   []struct {
			SystemName string `json:"system_name"`
			Text       string `json:"text"`
		} `json:"ids"`
		Notes []csafNote `json:"notes"`
		CWE   struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"cwe"`
		Scores []struct {
			CVSSV2 struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvss_v2"`
			CVSSV3 struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvss_v3"`
			CVSSV4 struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvss_v4"`
			Products []string `json:"products"`
		} `json:"scores"`
		ProductStatus struct {
			KnownAffected      []string `json:"known_affected"`
			KnownNotAffected   []string `json:"known_not_affected"`
			Fixed              []string `json:"fixed"`
			FirstFixed         []string `json:"first_fixed"`
			UnderInvestigation []string `json:"under_investigation"`
		} `json:"product_status"`
		References []struct {
			Category string `json:"category"`
			URL      string `json:"url"`
			Summary  string `json:"summary"`
		} `json:"references"`
	} `json:"vulnerabilities"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

func parseCSAF(raw []byte, source, publisher string) []*model.Vulnerability {
	var doc csafDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if publisher == "" {
		publisher = doc.Document.Publisher.Name
	}
	productNames := parseProductTree(doc.RawProductTree)

	published := model.ParseTime(doc.Document.Tracking.InitialReleaseDate)
	modified := model.ParseTime(doc.Document.Tracking.CurrentReleaseDate)
	// tracking.id plus version is the document's identity in CSAF. Keying only
	// on the id makes a revised advisory overwrite its predecessor in the raw
	// layer, which destroys the revision history the format is designed around.
	docKey := doc.Document.Tracking.ID
	if v := doc.Document.Tracking.Version; v != "" {
		docKey += "@" + v
	}

	var out []*model.Vulnerability
	for i, cv := range doc.Vulnerabilities {
		id := model.NormalizeID(cv.CVE)
		var aliases []string
		for _, extra := range cv.IDs {
			if extra.Text != "" {
				aliases = append(aliases, extra.Text)
			}
		}
		if id == "" {
			// Vendor and OT advisories routinely carry no CVE at all. Dropping
			// them discards exactly the coverage CSAF is collected for, so the
			// advisory's own tracking id becomes the record identifier.
			for _, a := range aliases {
				if model.IsCVE(a) {
					id = model.NormalizeID(a)
					break
				}
			}
		}
		if id == "" {
			id = doc.Document.Tracking.ID
			if len(doc.Vulnerabilities) > 1 {
				id = fmt.Sprintf("%s#%d", id, i+1)
			}
		}
		if strings.TrimSpace(id) == "" {
			continue
		}

		v := &model.Vulnerability{
			ID:             id,
			Title:          firstNonEmpty(cv.Title, doc.Document.Title),
			State:          "PUBLISHED",
			Published:      published,
			Modified:       modified,
			Aliases:        model.DedupeStrings(aliases),
			Source:         source,
			SourceRecordID: docKey + "#" + id,
			Raw:            raw,
		}
		if strings.EqualFold(doc.Document.Tracking.Status, "draft") {
			v.Tags = append(v.Tags, "csaf-draft")
		}
		for _, n := range append(append([]csafNote{}, cv.Notes...), doc.Document.Notes...) {
			if strings.EqualFold(n.Category, "description") || strings.EqualFold(n.Category, "summary") {
				v.Description = n.Text
				break
			}
		}
		if cv.CWE.ID != "" {
			v.CWEs = []string{cv.CWE.ID}
		}
		for _, s := range cv.Scores {
			// One scores[] entry may carry every CVSS version at once — CSAF
			// 2.1 documents state v4 beside v3 for the same products — so each
			// is kept independently rather than the newest shadowing the rest.
			if s.CVSSV4.VectorString != "" {
				v.Severities = append(v.Severities, model.Severity{
					Type: "CVSS_V4_0", Score: s.CVSSV4.BaseScore, Vector: s.CVSSV4.VectorString,
					Rating:   csafRating(s.CVSSV4.BaseSeverity, s.CVSSV4.BaseScore),
					Provider: publisher, Source: source,
				})
			}
			if s.CVSSV3.VectorString != "" {
				v.Severities = append(v.Severities, model.Severity{
					Type: model.CVSSTypeFromVector(s.CVSSV3.VectorString), Score: s.CVSSV3.BaseScore,
					Vector:   s.CVSSV3.VectorString,
					Rating:   csafRating(s.CVSSV3.BaseSeverity, s.CVSSV3.BaseScore),
					Provider: publisher, Source: source,
				})
			}
			// CVSS v2 is still the only score some long-lived OT advisories
			// carry, so it is kept alongside rather than dropped.
			if s.CVSSV2.VectorString != "" {
				v.Severities = append(v.Severities, model.Severity{
					Type: "CVSS_V2", Score: s.CVSSV2.BaseScore, Vector: s.CVSSV2.VectorString,
					Rating:   csafRating("", s.CVSSV2.BaseScore),
					Provider: publisher, Source: source,
				})
			}
		}
		for _, ref := range cv.References {
			if ref.URL != "" {
				v.References = append(v.References, model.Reference{
					URL: ref.URL, Name: ref.Summary, Tags: []string{strings.ToLower(ref.Category)}, Source: source,
				})
			}
		}
		// The VEX product status is the reason to collect CSAF at all: the
		// vendor asserting which of its products are genuinely exploitable,
		// which are fixed and which were investigated and found unaffected.
		for status, ids := range map[string][]string{
			model.StatusAffected:           cv.ProductStatus.KnownAffected,
			model.StatusFixed:              append(append([]string{}, cv.ProductStatus.Fixed...), cv.ProductStatus.FirstFixed...),
			model.StatusNotAffected:        cv.ProductStatus.KnownNotAffected,
			model.StatusUnderInvestigation: cv.ProductStatus.UnderInvestigation,
		} {
			for _, pid := range ids {
				v.Affected = append(v.Affected, affectedFromProduct(productNames[pid], pid, publisher, status, source))
			}
		}
		sort.SliceStable(v.Affected, func(i, j int) bool {
			if v.Affected[i].Status != v.Affected[j].Status {
				return v.Affected[i].Status < v.Affected[j].Status
			}
			return v.Affected[i].Product < v.Affected[j].Product
		})
		out = append(out, v)
	}
	return out
}

func csafRating(given string, score float64) string {
	if given != "" {
		return strings.ToUpper(given)
	}
	if score > 0 {
		return model.RatingFromScore(score)
	}
	return ""
}

// ensure the interface is satisfied at compile time
var _ httpx.Fetcher = (*httpx.Client)(nil)

// affectedFromProduct turns one CSAF product into an applicability statement,
// keeping the identity the document supplied.
//
// The product id is the fallback of last resort. Before it come the purl and
// the CPE the advisory attached, and then the branch path, because a statement
// whose product is a flattened display name cannot be matched against anything
// an inventory reports.
func affectedFromProduct(p csafProduct, productID, publisher, status, source string) model.Affected {
	a := model.Affected{
		Vendor: publisher, DefaultState: status, Status: status, Source: source,
	}
	if p.Vendor != "" {
		a.Vendor = p.Vendor
	}
	switch {
	case p.Product != "":
		a.Product = p.Product
	case p.Name != "":
		a.Product = p.Name
	default:
		a.Product = productID
	}
	a.PURL = p.PURL
	if p.CPE != "" {
		a.CPEs = []string{p.CPE}
	}
	// A stated version is a version, not a range: the advisory says this exact
	// build is in this state, so it is recorded as the one version the
	// statement covers rather than as an unbounded window.
	if p.Version != "" {
		a.Versions = []string{p.Version}
	}
	return a
}
