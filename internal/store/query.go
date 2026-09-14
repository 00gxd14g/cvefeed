package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// ErrNotFound is returned when a vulnerability identifier resolves to nothing.
var ErrNotFound = errors.New("store: not found")

// ---------------------------------------------------------------- enrichment

// SyncEnrichment re-links the KEV and EPSS tables to the vulnerability rows.
//
// It has to exist separately from the loaders because the loaders short-circuit
// when the upstream has not changed — the KEV catalogue moves a few times a
// week and EPSS once a day — while vulnerabilities are ingested continuously.
// Without a standalone sync, a CVE ingested after the last catalogue change
// would sit there with in_kev false until the catalogue happened to move again.
//
// Every statement is guarded by IS DISTINCT FROM, so a no-op run writes nothing.
func (s *Store) SyncEnrichment(ctx context.Context) error {
	statements := []struct {
		what string
		sql  string
	}{
		{"kev flags", propagateKEVSQL},
		{"stale kev flags", clearStaleKEVSQL},
		{"epss scores", propagateEPSSSQL},
	}
	for _, st := range statements {
		if _, err := s.db.ExecContext(ctx, st.sql); err != nil {
			return fmt.Errorf("store: sync %s: %w", st.what, err)
		}
	}
	return nil
}

// The propagation statements join through vuln_aliases, and a record with
// several CVE aliases — one OSV entry listing three CVEs, all catalogued —
// joins to several KEV or EPSS rows. UPDATE ... FROM applies whichever of them
// PostgreSQL happens to visit first, and the IS DISTINCT FROM guard then sees
// the other row as a difference on the next run: the value flipped between
// runs and updated_at moved on every sync for a record nothing had touched.
// One row per vulnerability is chosen first, by the same rule the detail
// endpoint uses, so the two never disagree: the earliest KEV listing, the
// highest EPSS score.
const propagateKEVSQL = `
    UPDATE vulnerabilities v
       SET in_kev = true, kev_date_added = k.date_added, updated_at = now()
      FROM (SELECT a.vuln_id, min(k.date_added) AS date_added
              FROM kev k JOIN vuln_aliases a ON a.alias = k.cve_id
             GROUP BY a.vuln_id) k
     WHERE v.id = k.vuln_id
       AND (v.in_kev IS DISTINCT FROM true OR v.kev_date_added IS DISTINCT FROM k.date_added)`

// CISA does occasionally withdraw an entry. A flag that only ever turns on
// leaves those records permanently labelled "actively exploited", which is
// the single strongest signal the API publishes.
const clearStaleKEVSQL = `
    UPDATE vulnerabilities v
       SET in_kev = false, kev_date_added = NULL, updated_at = now()
     WHERE v.in_kev
       AND NOT EXISTS (
             SELECT 1 FROM kev k JOIN vuln_aliases a ON a.alias = k.cve_id
              WHERE a.vuln_id = v.id)`

const propagateEPSSSQL = `
    UPDATE vulnerabilities v
       SET epss_score = e.score, epss_percentile = e.percentile,
           epss_date = e.score_date, updated_at = now()
      FROM (SELECT DISTINCT ON (a.vuln_id) a.vuln_id, e.score, e.percentile, e.score_date
              FROM epss e JOIN vuln_aliases a ON a.alias = e.cve_id
             ORDER BY a.vuln_id, e.score DESC, e.cve_id) e
     WHERE v.id = e.vuln_id
       AND (v.epss_date IS DISTINCT FROM e.score_date OR v.epss_score IS DISTINCT FROM e.score)`

// UpsertKEV writes catalogue entries and then propagates the flag onto the
// canonical vulnerability rows, resolving through the alias table so a KEV
// entry still lands when the flaw is filed under a non-CVE canonical id.
//
// It only ever adds. That is right for a partial load — ENISA's exploitation
// flags arrive a page at a time and say nothing about the entries they omit —
// and wrong for a full catalogue, where an entry that is absent has been
// withdrawn: the stale-flag statement below never fired, because the row it
// looks for was never removed. ReplaceKEV is the full-catalogue form.
func (s *Store) UpsertKEV(ctx context.Context, entries []model.KEV) error {
	if len(entries) == 0 {
		return nil
	}
	return s.writeKEV(ctx, entries, false)
}

// ReplaceKEV loads a complete catalogue: entries is everything the upstream
// currently lists, so a row this load does not mention has left it, and the
// row and the flag it put on the vulnerability go with it.
//
// Only the rows this catalogue owns are removed. The table is shared between
// catalogues — CISA's own list and ENISA's consolidated one both write it —
// and a CVE that ENISA still lists must not lose its row because CISA dropped
// theirs. A row belongs to this catalogue when the labels it carries
// (kev_sources) are all labels these entries carry; a row with no labels at
// all, which older loaders wrote, belongs to it when this collector was its
// last writer. An empty catalogue is refused rather than applied, because the
// one way to get one is a failed or truncated fetch, and applying it would
// clear every flag in the corpus.
//
// The collector for CISA's catalogue should call this rather than UpsertKEV;
// until it does, entries that leave the catalogue keep their flag.
func (s *Store) ReplaceKEV(ctx context.Context, entries []model.KEV) error {
	if len(entries) == 0 {
		return errors.New("store: refusing to replace the kev catalogue with an empty one")
	}
	return s.writeKEV(ctx, entries, true)
}

func (s *Store) writeKEV(ctx context.Context, entries []model.KEV, full bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: kev begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name, short_description,
                         required_action, notes, date_added, due_date, known_ransomware, kev_sources, source,
                         catalog_version, date_released, cwes, ransomware_use, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, now())
        ON CONFLICT (cve_id) DO UPDATE SET
            catalog_version = COALESCE(EXCLUDED.catalog_version, kev.catalog_version),
            date_released = COALESCE(EXCLUDED.date_released, kev.date_released),
            cwes = CASE WHEN EXCLUDED.cwes = '{}' THEN kev.cwes ELSE EXCLUDED.cwes END,
            ransomware_use = COALESCE(EXCLUDED.ransomware_use, kev.ransomware_use),
            vendor_project = COALESCE(EXCLUDED.vendor_project, kev.vendor_project),
            product = COALESCE(EXCLUDED.product, kev.product),
            vulnerability_name = COALESCE(EXCLUDED.vulnerability_name, kev.vulnerability_name),
            short_description = COALESCE(EXCLUDED.short_description, kev.short_description),
            required_action = COALESCE(EXCLUDED.required_action, kev.required_action),
            notes = COALESCE(EXCLUDED.notes, kev.notes),
            date_added = LEAST(COALESCE(EXCLUDED.date_added, kev.date_added), COALESCE(kev.date_added, EXCLUDED.date_added)),
            due_date = COALESCE(EXCLUDED.due_date, kev.due_date),
            known_ransomware = kev.known_ransomware OR EXCLUDED.known_ransomware,
            kev_sources = COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(kev.kev_sources || EXCLUDED.kev_sources) AS x), '{}'),
            source = EXCLUDED.source,
            updated_at = now()`)
	if err != nil {
		return fmt.Errorf("store: kev prepare: %w", err)
	}
	defer stmt.Close()

	var (
		loaded []string
		labels []string
		writer string
	)
	for _, e := range entries {
		id := model.NormalizeID(e.CVEID)
		if id == "" {
			continue
		}
		loaded = append(loaded, id)
		labels = append(labels, e.Sources...)
		if writer == "" {
			writer = e.Source
		}
		if _, err := stmt.ExecContext(ctx, id, nullStr(e.VendorProject), nullStr(e.Product),
			nullStr(e.VulnerabilityName), nullStr(e.ShortDescription), nullStr(e.RequiredAction),
			nullStr(e.Notes), dateOrNil(e.DateAdded), dateOrNil(e.DueDate), e.KnownRansomware,
			strArray(model.DedupeStrings(e.Sources)), e.Source,
			nullStr(e.CatalogVersion), dateOrNil(e.DateReleased), strArray(e.CWEs),
			nullStr(e.RansomwareUse)); err != nil {
			return fmt.Errorf("store: kev upsert %s: %w", id, err)
		}
	}

	if full {
		if _, err := tx.ExecContext(ctx, `
            DELETE FROM kev
             WHERE NOT (cve_id = ANY($1))
               AND CASE WHEN kev_sources = '{}' THEN source = $2
                        ELSE kev_sources <@ $3::text[] END`,
			pq.Array(loaded), writer, strArray(model.DedupeStrings(labels))); err != nil {
			return fmt.Errorf("store: retire kev entries: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, propagateKEVSQL); err != nil {
		return fmt.Errorf("store: propagate kev: %w", err)
	}
	if _, err := tx.ExecContext(ctx, clearStaleKEVSQL); err != nil {
		return fmt.Errorf("store: clear stale kev flags: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: kev commit: %w", err)
	}
	return nil
}

// UpsertEPSS writes the daily scores in batches and propagates them.
func (s *Store) UpsertEPSS(ctx context.Context, scores []model.EPSS) error {
	if len(scores) == 0 {
		return nil
	}
	// One transaction for the whole day's load. Committing batch by batch left
	// a window in which half the corpus carried today's scores and half
	// yesterday's, which is exactly the comparison EPSS is used for.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: epss begin: %w", err)
	}
	defer tx.Rollback()

	// Five parameters per row and PostgreSQL's limit of 65,535 parameters in
	// one statement put the ceiling at 13,107 rows; 2,000 keeps each statement
	// well under it and the round trips few.
	const batch = 2000
	for start := 0; start < len(scores); start += batch {
		end := start + batch
		if end > len(scores) {
			end = len(scores)
		}
		if err := upsertEPSSBatch(ctx, tx, scores[start:end]); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, propagateEPSSSQL); err != nil {
		return fmt.Errorf("store: propagate epss: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: epss commit: %w", err)
	}
	return nil
}

func upsertEPSSBatch(ctx context.Context, tx *sql.Tx, scores []model.EPSS) error {
	var (
		sb   strings.Builder
		args []any
	)
	sb.WriteString(`INSERT INTO epss (cve_id, score, percentile, score_date, model_version, updated_at) VALUES `)
	n := 0
	for _, e := range scores {
		id := model.NormalizeID(e.CVEID)
		if id == "" {
			continue
		}
		if n > 0 {
			sb.WriteString(",")
		}
		base := n * 5
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d, now())", base+1, base+2, base+3, base+4, base+5)
		args = append(args, id, e.Score, e.Percentile, e.ScoreDate, nullStr(e.ModelVersion))
		n++
	}
	if n == 0 {
		return nil
	}
	sb.WriteString(` ON CONFLICT (cve_id) DO UPDATE SET
            score = EXCLUDED.score, percentile = EXCLUDED.percentile,
            score_date = EXCLUDED.score_date, model_version = EXCLUDED.model_version,
            updated_at = now()
        WHERE epss.score_date <= EXCLUDED.score_date`)
	if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("store: epss batch: %w", err)
	}
	return nil
}

// ------------------------------------------------------------ source cursors

// SourceState is the persisted progress of one collector.
type SourceState struct {
	Name          string          `json:"name"`
	Cursor        json.RawMessage `json:"cursor"`
	LastRunAt     *time.Time      `json:"last_run_at,omitempty"`
	LastSuccessAt *time.Time      `json:"last_success_at,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	RecordsSeen   int64           `json:"records_seen"`
}

// LoadCursor returns the persisted cursor for a source ("{}" when unset).
func (s *Store) LoadCursor(ctx context.Context, source string) (json.RawMessage, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT cursor FROM sources WHERE name = $1`, source).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return json.RawMessage("{}"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: load cursor %s: %w", source, err)
	}
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.RawMessage(raw), nil
}

// SaveCursor records progress and the outcome of a run.
func (s *Store) SaveCursor(ctx context.Context, source string, cursor json.RawMessage, seen int64, runErr error) error {
	if len(cursor) == 0 {
		cursor = json.RawMessage("{}")
	}
	var errText any
	if runErr != nil {
		errText = runErr.Error()
	}
	success := "NULL"
	if runErr == nil {
		success = "now()"
	}
	q := fmt.Sprintf(`
        INSERT INTO sources (name, cursor, last_run_at, last_success_at, last_error, records_seen)
        VALUES ($1, $2::jsonb, now(), %s, $3, $4)
        ON CONFLICT (name) DO UPDATE SET
            cursor = EXCLUDED.cursor,
            last_run_at = now(),
            last_success_at = COALESCE(EXCLUDED.last_success_at, sources.last_success_at),
            last_error = EXCLUDED.last_error,
            records_seen = sources.records_seen + EXCLUDED.records_seen`, success)
	if _, err := s.db.ExecContext(ctx, q, source, string(cursor), errText, seen); err != nil {
		return fmt.Errorf("store: save cursor %s: %w", source, err)
	}
	return nil
}

// SourceStates lists every collector's persisted state.
func (s *Store) SourceStates(ctx context.Context) ([]SourceState, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT name, cursor, last_run_at, last_success_at, COALESCE(last_error, ''), records_seen
          FROM sources ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: source states: %w", err)
	}
	defer rows.Close()
	var out []SourceState
	for rows.Next() {
		var st SourceState
		var raw []byte
		if err := rows.Scan(&st.Name, &raw, &st.LastRunAt, &st.LastSuccessAt, &st.LastError, &st.RecordsSeen); err != nil {
			return nil, fmt.Errorf("store: scan source state: %w", err)
		}
		st.Cursor = json.RawMessage(raw)
		out = append(out, st)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------- queries

// ListFilter is the query surface behind GET /v1/vulns.
type ListFilter struct {
	ModifiedSince  *time.Time
	PublishedSince *time.Time
	ScoreMin       *float64
	ScoreMax       *float64
	EPSSMin        *float64
	KEVOnly        bool
	Ratings        []string
	Sources        []string
	CWEs           []string
	Text           string
	States         []string
	CPE            string
	PURL           string
	Product        string
	Vendor         string
	Ecosystem      string
	Limit          int
	Offset         int
	OrderBy        string // modified | published | score | epss | id
}

// ListResult carries a page of vulnerabilities. Limit and Offset are the values
// actually applied, which is what a paging client has to advance by — echoing
// the requested limit back while silently clamping it makes `offset += limit`
// either loop forever or skip records.
type ListResult struct {
	Total  int64                 `json:"total"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
	Items  []model.Vulnerability `json:"items"`
}

// MaxPageSize is the largest page /v1/vulns will return.
const MaxPageSize = 1000

// DefaultPageSize is applied when the caller asks for none.
const DefaultPageSize = 100

// EffectiveLimit reports the page size that will actually be used.
func EffectiveLimit(requested int) int {
	switch {
	case requested <= 0:
		return DefaultPageSize
	case requested > MaxPageSize:
		return MaxPageSize
	default:
		return requested
	}
}

// buildWhere renders the filter into a WHERE clause and its arguments. It is
// shared by the paged query and the streaming export so the two can never
// disagree about what a filter means.
func buildWhere(f ListFilter) (string, []any) {
	var (
		where []string
		args  []any
	)
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if f.ModifiedSince != nil {
		add("v.modified >= $%d", *f.ModifiedSince)
	}
	if f.PublishedSince != nil {
		add("v.published >= $%d", *f.PublishedSince)
	}
	if f.ScoreMin != nil {
		add("v.primary_score >= $%d", *f.ScoreMin)
	}
	if f.ScoreMax != nil {
		add("v.primary_score <= $%d", *f.ScoreMax)
	}
	if f.EPSSMin != nil {
		add("v.epss_score >= $%d", *f.EPSSMin)
	}
	if f.KEVOnly {
		where = append(where, "v.in_kev")
	}
	if len(f.Ratings) > 0 {
		add("upper(v.primary_rating) = ANY($%d)", pq.Array(upperAll(f.Ratings)))
	}
	if len(f.States) > 0 {
		add("upper(v.state) = ANY($%d)", pq.Array(upperAll(f.States)))
	}
	if len(f.Sources) > 0 {
		add("v.sources && $%d", pq.Array(f.Sources))
	}
	if len(f.CWEs) > 0 {
		add("v.cwes && $%d", pq.Array(f.CWEs))
	}
	if strings.TrimSpace(f.Text) != "" {
		add("v.search @@ plainto_tsquery('simple', $%d)", strings.TrimSpace(f.Text))
	}
	if f.CPE != "" {
		// Written as array containment rather than `= ANY(...)`: only the
		// containment operator can use the GIN index on vuln_affected.cpes.
		add("EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id AND a.cpes @> ARRAY[$%d]::text[])", f.CPE)
	}
	if f.PURL != "" {
		add("EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id AND a.purl = $%d)", f.PURL)
	}
	if f.Product != "" {
		add("EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id AND lower(a.product) = lower($%d))", f.Product)
	}
	if f.Vendor != "" {
		add("EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id AND lower(a.vendor) = lower($%d))", f.Vendor)
	}
	if f.Ecosystem != "" {
		add("EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id AND lower(a.ecosystem) = lower($%d))", f.Ecosystem)
	}

	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

func orderClause(orderBy string) string {
	switch orderBy {
	case "published":
		return "v.published DESC NULLS LAST"
	case "score":
		return "v.primary_score DESC NULLS LAST"
	case "epss":
		return "v.epss_score DESC NULLS LAST"
	case "id":
		return "v.id ASC"
	default:
		return "v.modified DESC NULLS LAST"
	}
}

// ListVulnerabilities runs a filtered, paginated query. Items are the stored
// documents without their affected statements and references; see the loop
// below. GetVulnerability and StreamVulnerabilities return them whole.
//
// The count and the page are read from one snapshot. As two statements on the
// pool they could see different states of a table the ingest writes to
// continuously, and a client walking pages by offset then received a total
// that no page sequence added up to. REPEATABLE READ pins both reads to the
// snapshot the first one took; read-only tells PostgreSQL it can hold no
// writes back for this transaction.
func (s *Store) ListVulnerabilities(ctx context.Context, f ListFilter) (*ListResult, error) {
	clause, args := buildWhere(f)

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: list begin: %w", err)
	}
	defer tx.Rollback()

	var total int64
	if err := tx.QueryRowContext(ctx,
		"SELECT count(*) FROM vulnerabilities v"+clause, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("store: count: %w", err)
	}

	limit := EffectiveLimit(f.Limit)
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	q := fmt.Sprintf("SELECT v.doc FROM vulnerabilities v%s ORDER BY %s, v.id ASC LIMIT $%d OFFSET $%d",
		clause, orderClause(f.OrderBy), len(args)-1, len(args))

	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	defer rows.Close()

	res := &ListResult{Total: total, Limit: limit, Offset: offset, Items: []model.Vulnerability{}}
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("store: scan list row: %w", err)
		}
		var v model.Vulnerability
		plain, derr := decompressDoc(doc)
		if derr != nil {
			return nil, derr
		}
		if err := json.Unmarshal(plain, &v); err != nil {
			return nil, fmt.Errorf("store: decode list row: %w", err)
		}
		// A page is a listing, not the records. The applicability statements
		// and references are the bulk of a document — one kernel CVE carries
		// 15,260 statements, 6.7 MB on its own — and a default page of a
		// hundred full documents weighed 27 MB. They stay on the detail
		// endpoint and in the export, which read the whole document.
		v.Affected = nil
		v.References = nil
		res.Items = append(res.Items, v)
	}
	return res, rows.Err()
}

// Detail is a vulnerability plus its enrichment.
type Detail struct {
	model.Vulnerability
	InKEV      bool        `json:"in_kev"`
	KEV        *model.KEV  `json:"kev,omitempty"`
	EPSS       *model.EPSS `json:"epss,omitempty"`
	MatchedVia string      `json:"matched_via,omitempty"`
}

// GetVulnerability resolves any identifier — canonical id or alias — to one record.
func (s *Store) GetVulnerability(ctx context.Context, id string) (*Detail, error) {
	norm := model.NormalizeID(id)
	var (
		canonical string
		doc       []byte
		inKEV     bool
	)
	err := s.db.QueryRowContext(ctx, `
        SELECT v.id, v.doc, v.in_kev
          FROM vuln_aliases a JOIN vulnerabilities v ON v.id = a.vuln_id
         WHERE a.alias = $1`, norm).Scan(&canonical, &doc, &inKEV)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get %s: %w", id, err)
	}

	d := &Detail{InKEV: inKEV}
	plain, derr := decompressDoc(doc)
	if derr != nil {
		return nil, derr
	}
	if err := json.Unmarshal(plain, &d.Vulnerability); err != nil {
		return nil, fmt.Errorf("store: decode %s: %w", canonical, err)
	}
	if canonical != norm {
		d.MatchedVia = norm
	}

	// Deterministic when a record has several CVE aliases: the earliest listing
	// is the one that describes when exploitation was first known.
	kevRow := s.db.QueryRowContext(ctx, `
        SELECT k.cve_id, COALESCE(k.vendor_project,''), COALESCE(k.product,''),
               COALESCE(k.vulnerability_name,''), COALESCE(k.short_description,''),
               COALESCE(k.required_action,''), COALESCE(k.notes,''),
               k.date_added, k.due_date, k.known_ransomware, k.kev_sources, k.source,
               COALESCE(k.catalog_version,''), k.date_released, k.cwes, COALESCE(k.ransomware_use,'')
          FROM kev k JOIN vuln_aliases a ON a.alias = k.cve_id
         WHERE a.vuln_id = $1
         ORDER BY k.date_added NULLS LAST, k.cve_id LIMIT 1`, canonical)
	var kev model.KEV
	var srcs, kevCWEs pq.StringArray
	switch err := kevRow.Scan(&kev.CVEID, &kev.VendorProject, &kev.Product, &kev.VulnerabilityName,
		&kev.ShortDescription, &kev.RequiredAction, &kev.Notes, &kev.DateAdded, &kev.DueDate,
		&kev.KnownRansomware, &srcs, &kev.Source,
		&kev.CatalogVersion, &kev.DateReleased, &kevCWEs, &kev.RansomwareUse); {
	case err == nil:
		kev.Sources = srcs
		kev.CWEs = kevCWEs
		d.KEV = &kev
	case errors.Is(err, sql.ErrNoRows):
	default:
		return nil, fmt.Errorf("store: get kev %s: %w", canonical, err)
	}

	// Highest score wins, then the id, so the answer does not change between
	// two identical requests when a record carries several CVE aliases.
	epssRow := s.db.QueryRowContext(ctx, `
        SELECT e.cve_id, e.score, e.percentile, e.score_date, COALESCE(e.model_version,'')
          FROM epss e JOIN vuln_aliases a ON a.alias = e.cve_id
         WHERE a.vuln_id = $1 ORDER BY e.score DESC, e.cve_id LIMIT 1`, canonical)
	var ep model.EPSS
	switch err := epssRow.Scan(&ep.CVEID, &ep.Score, &ep.Percentile, &ep.ScoreDate, &ep.ModelVersion); {
	case err == nil:
		ep.Source = "epss"
		d.EPSS = &ep
	case errors.Is(err, sql.ErrNoRows):
	default:
		return nil, fmt.Errorf("store: get epss %s: %w", canonical, err)
	}

	return d, nil
}

// HistoryEntry is one recorded change.
type HistoryEntry struct {
	ChangedAt time.Time       `json:"changed_at"`
	Source    string          `json:"source"`
	Change    json.RawMessage `json:"change"`
}

// MaxHistoryLimit is the most entries one History call returns.
const MaxHistoryLimit = 500

// DefaultHistoryLimit is applied when the caller asks for none.
const DefaultHistoryLimit = 100

// historyLimit clamps a requested history page size. Asking for more than the
// maximum gets the maximum, not the default: a client that asked for 600 and
// silently got 100 has no way to tell it was cut short.
func historyLimit(requested int) int {
	switch {
	case requested <= 0:
		return DefaultHistoryLimit
	case requested > MaxHistoryLimit:
		return MaxHistoryLimit
	default:
		return requested
	}
}

// History returns the change log for a vulnerability, newest first.
func (s *Store) History(ctx context.Context, id string, limit int) ([]HistoryEntry, error) {
	limit = historyLimit(limit)
	rows, err := s.db.QueryContext(ctx, `
        SELECT h.changed_at, h.source, h.change
          FROM vuln_history h
          JOIN vuln_aliases a ON a.vuln_id = h.vuln_id
         WHERE a.alias = $1
         ORDER BY h.changed_at DESC, h.id DESC LIMIT $2`, model.NormalizeID(id), limit)
	if err != nil {
		return nil, fmt.Errorf("store: history %s: %w", id, err)
	}
	defer rows.Close()
	out := []HistoryEntry{}
	for rows.Next() {
		var e HistoryEntry
		var raw []byte
		if err := rows.Scan(&e.ChangedAt, &e.Source, &raw); err != nil {
			return nil, fmt.Errorf("store: scan history: %w", err)
		}
		e.Change = json.RawMessage(raw)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExportRecord is a vulnerability plus the enrichment columns that live beside
// it rather than inside its document. The export advertises `epss` and `kev`
// columns, so the streaming path has to carry them.
type ExportRecord struct {
	model.Vulnerability
	InKEV          bool       `json:"in_kev"`
	KEVDateAdded   *time.Time `json:"kev_date_added,omitempty"`
	EPSSScore      float64    `json:"epss_score,omitempty"`
	EPSSPercentile float64    `json:"epss_percentile,omitempty"`
	EPSSDate       *time.Time `json:"epss_date,omitempty"`
}

// StreamVulnerabilities calls fn for every matching record without buffering the
// whole result set, which is what the NDJSON export endpoint needs.
//
// It runs one ordered query and iterates the driver's row stream. The previous
// LIMIT/OFFSET loop re-ran a full count(*) for every 500 rows — 600 sequential
// scans for a 300,000-record export — and, worse, paged over a sort key the
// delta collectors mutate underneath it, so any record whose `modified` moved
// during the export was silently skipped or emitted twice while the response
// still claimed 200 OK.
//
// f.Limit, when positive, caps the total number of records emitted; f.Offset is
// honoured as a starting position.
func (s *Store) StreamVulnerabilities(ctx context.Context, f ListFilter, fn func(*ExportRecord) error) error {
	clause, args := buildWhere(f)
	q := "SELECT v.doc, v.in_kev, v.kev_date_added, v.epss_score, v.epss_percentile, v.epss_date" +
		" FROM vulnerabilities v" + clause +
		" ORDER BY " + orderClause(f.OrderBy) + ", v.id ASC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if f.Offset > 0 {
		args = append(args, f.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("store: stream: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			doc       []byte
			rec       ExportRecord
			epssScore sql.NullFloat64
			epssPct   sql.NullFloat64
			epssDate  sql.NullTime
			kevAdded  sql.NullTime
		)
		if err := rows.Scan(&doc, &rec.InKEV, &kevAdded, &epssScore, &epssPct, &epssDate); err != nil {
			return fmt.Errorf("store: scan stream row: %w", err)
		}
		plain, derr := decompressDoc(doc)
		if derr != nil {
			return derr
		}
		if err := json.Unmarshal(plain, &rec.Vulnerability); err != nil {
			return fmt.Errorf("store: decode stream row: %w", err)
		}
		if kevAdded.Valid {
			t := kevAdded.Time
			rec.KEVDateAdded = &t
		}
		if epssScore.Valid {
			rec.EPSSScore = epssScore.Float64
		}
		if epssPct.Valid {
			rec.EPSSPercentile = epssPct.Float64
		}
		if epssDate.Valid {
			t := epssDate.Time
			rec.EPSSDate = &t
		}
		if err := fn(&rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Stats is the corpus summary behind GET /v1/stats.
type Stats struct {
	Vulnerabilities int64            `json:"vulnerabilities"`
	Aliases         int64            `json:"aliases"`
	RawRecords      int64            `json:"raw_records"`
	KEVEntries      int64            `json:"kev_entries"`
	EPSSScores      int64            `json:"epss_scores"`
	ByRating        map[string]int64 `json:"by_rating"`
	BySource        map[string]int64 `json:"by_source"`
	Unscored        int64            `json:"unscored"`
	NewestModified  *time.Time       `json:"newest_modified,omitempty"`
	OldestPublished *time.Time       `json:"oldest_published,omitempty"`
}

// Stats computes corpus counters.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{ByRating: map[string]int64{}, BySource: map[string]int64{}}

	if err := s.db.QueryRowContext(ctx, `
        SELECT (SELECT count(*) FROM vulnerabilities),
               (SELECT count(*) FROM vuln_aliases),
               (SELECT count(*) FROM raw_records),
               (SELECT count(*) FROM kev),
               (SELECT count(*) FROM epss),
               (SELECT count(*) FROM vulnerabilities WHERE primary_score IS NULL),
               (SELECT max(modified) FROM vulnerabilities),
               (SELECT min(published) FROM vulnerabilities)`).
		Scan(&st.Vulnerabilities, &st.Aliases, &st.RawRecords, &st.KEVEntries,
			&st.EPSSScores, &st.Unscored, &st.NewestModified, &st.OldestPublished); err != nil {
		return nil, fmt.Errorf("store: stats: %w", err)
	}

	ratingRows, err := s.db.QueryContext(ctx, `
        SELECT COALESCE(upper(primary_rating), 'UNSCORED'), count(*)
          FROM vulnerabilities GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("store: stats ratings: %w", err)
	}
	defer ratingRows.Close()
	for ratingRows.Next() {
		var k string
		var n int64
		if err := ratingRows.Scan(&k, &n); err != nil {
			return nil, fmt.Errorf("store: scan rating stat: %w", err)
		}
		st.ByRating[k] = n
	}
	if err := ratingRows.Err(); err != nil {
		return nil, err
	}

	srcRows, err := s.db.QueryContext(ctx, `
        SELECT s, count(*) FROM vulnerabilities, unnest(sources) AS s GROUP BY s ORDER BY 2 DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: stats sources: %w", err)
	}
	defer srcRows.Close()
	for srcRows.Next() {
		var k string
		var n int64
		if err := srcRows.Scan(&k, &n); err != nil {
			return nil, fmt.Errorf("store: scan source stat: %w", err)
		}
		st.BySource[k] = n
	}
	return st, srcRows.Err()
}

func dateOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func upperAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}
