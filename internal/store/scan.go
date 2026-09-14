package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// AffectedStatement is one stored applicability statement together with the
// vulnerability it belongs to. It is the unit a scanner tests a target
// component against.
type AffectedStatement struct {
	VulnID    string               `json:"vuln_id"`
	Vendor    string               `json:"vendor,omitempty"`
	Product   string               `json:"product,omitempty"`
	Ecosystem string               `json:"ecosystem,omitempty"`
	PURL      string               `json:"purl,omitempty"`
	CPEs      []string             `json:"cpes,omitempty"`
	Versions  []string             `json:"versions,omitempty"`
	Ranges    []model.VersionRange `json:"ranges,omitempty"`
	// DefaultState is what the source says about versions the ranges do not
	// mention: CVE 5.1's defaultStatus. "affected" with a list of unaffected
	// windows is a common CNA shape, and read without the default it says
	// the opposite of what the CNA meant.
	DefaultState string `json:"default_state,omitempty"`
	Status       string `json:"status,omitempty"`
	Source       string `json:"source"`
	// Fingerprint is the store's own identity for this statement, the same one
	// the unique constraint uses. It is what separates two statements that
	// describe the same product through different affected windows.
	Fingerprint string `json:"-"`
}

// CandidateQuery is the set of identities to look a component up by. Every
// non-empty field widens the candidate set; the caller decides afterwards which
// identity actually carries enough evidence to report.
type CandidateQuery struct {
	PURL      string
	Name      string
	Vendor    string
	Ecosystem string
}

// CandidateSet is what a candidate lookup returns: the statements per query
// index, and which query indexes had one of their identities hit the per-key
// limit. A truncated component was tested against a bounded sample of the
// corpus, so "no finding" for it means less than it does for the others.
type CandidateSet struct {
	Statements map[int][]AffectedStatement
	Truncated  map[int]bool
}

// maxCandidatesPerQuery bounds a single lookup key. A bare product name like
// "linux" or "core" matches tens of thousands of statements, and pulling all of
// them to discard almost all of them is how a scan turns into an outage. It is
// a variable only so a test can lower it; nothing else writes it.
var maxCandidatesPerQuery = 2000

// purlKeyExpr is the SQL that derives the lookup key from a stored purl:
// qualifiers and subpath cut off, the version stripped, the rest lower-cased.
// It is one string used by both the index and the queries, because the planner
// only uses an expression index for an expression that matches it exactly.
// normalisePURL is its Go counterpart and a test holds the two to the same
// answers.
//
// The version is the tail after the LAST '@' that holds no '/', which is what
// '[^/@]*$' spells: POSIX regexp_replace finds the leftmost match, and without
// the '@' in the class it cut pkg:npm/a@b@c at the first '@' while
// normalisePURL cut at the last. Changing this string changes the index
// expression; migration 10 is where the current one was built.
const purlKeyExpr = `lower(regexp_replace(split_part(split_part(purl, '?', 1), '#', 1), '@[^/@]*$', ''))`

// AffectedCandidates returns the statements that could plausibly describe the
// given components, keyed by the index of the query that found them. It is
// FindAffectedCandidates without the truncation report, kept for callers that
// do not surface it.
func (s *Store) AffectedCandidates(ctx context.Context, queries []CandidateQuery) (map[int][]AffectedStatement, error) {
	set, err := s.FindAffectedCandidates(ctx, queries)
	if err != nil {
		return nil, err
	}
	return set.Statements, nil
}

// FindAffectedCandidates returns the statements that could plausibly describe
// the given components, keyed by the index of the query that found them, and
// reports which components had a lookup key truncated.
//
// Lookups are batched by identity kind rather than issued per component: a
// container SBOM routinely carries a thousand components, and a round trip each
// would dominate the scan. Narrowing happens in the database, deciding happens
// in Go — the version comparison rules are far too involved for SQL.
//
// The limit applies per lookup key, through a LATERAL subquery with its own
// ORDER BY and LIMIT. One shared LIMIT across all keys let a common name take
// the whole budget: a query for ["linux", "curl"] returned four thousand rows
// about linux and none about curl, whose vulnerabilities then went unreported
// with nothing to say so — and which linux rows survived changed from run to
// run, because nothing ordered them.
func (s *Store) FindAffectedCandidates(ctx context.Context, queries []CandidateQuery) (*CandidateSet, error) {
	out := &CandidateSet{
		Statements: make(map[int][]AffectedStatement, len(queries)),
		Truncated:  map[int]bool{},
	}
	if len(queries) == 0 {
		return out, nil
	}

	// Deduplicate identical identities across components; a lockfile with the
	// same package at two versions asks the same question twice.
	type pairKey struct{ a, b string }

	purlFor := map[string][]int{}
	ecoName := map[pairKey][]int{}
	vendorProduct := map[pairKey][]int{}
	nameOnly := map[string][]int{}

	for i, q := range queries {
		if p := strings.TrimSpace(q.PURL); p != "" {
			purlFor[normalisePURL(p)] = append(purlFor[normalisePURL(p)], i)
		}
		name := strings.ToLower(strings.TrimSpace(q.Name))
		if name == "" {
			continue
		}
		if eco := strings.ToLower(strings.TrimSpace(q.Ecosystem)); eco != "" {
			k := pairKey{eco, name}
			ecoName[k] = append(ecoName[k], i)
		}
		if vendor := strings.ToLower(strings.TrimSpace(q.Vendor)); vendor != "" {
			k := pairKey{vendor, name}
			vendorProduct[k] = append(vendorProduct[k], i)
		}
		nameOnly[name] = append(nameOnly[name], i)
	}

	// Each lateral branch asks for one row more than the limit. Receiving it
	// is the signal that the key was cut; the row itself is dropped so the
	// caller never sees more than the limit.
	perKey := maxCandidatesPerQuery + 1
	seen := map[pairKey]int{}
	add := func(key pairKey, idx []int, st AffectedStatement) {
		seen[key]++
		if seen[key] > maxCandidatesPerQuery {
			for _, i := range idx {
				out.Truncated[i] = true
			}
			return
		}
		for _, i := range idx {
			out.Statements[i] = append(out.Statements[i], st)
		}
	}

	const columns = `a.vuln_id, COALESCE(a.vendor,''), COALESCE(a.product,''),
                   COALESCE(a.ecosystem,''), COALESCE(a.purl,''), a.cpes, a.versions,
                   a.ranges, COALESCE(a.status,''), COALESCE(a.default_state,''), a.source, a.fingerprint`

	// 1. PURL: the strongest identity, and an exact index lookup on the same
	// expression the index was built on. `purl IS NOT NULL` is what lets the
	// planner use that partial index.
	if len(purlFor) > 0 {
		keys := make([]string, 0, len(purlFor))
		for k := range purlFor {
			keys = append(keys, k)
		}
		rows, err := s.candidateRows(ctx, `
            SELECT `+columns+`, q.k AS k1, '' AS k2
              FROM unnest($1::text[]) AS q(k)
              JOIN LATERAL (
                   SELECT * FROM vuln_affected
                    WHERE purl IS NOT NULL AND `+purlKeyExpr+` = q.k
                    ORDER BY vuln_id, fingerprint
                    LIMIT $2) a ON true`, pq.Array(keys), perKey)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			add(pairKey{"purl", r.key1}, purlFor[r.key1], r.statement)
		}
	}

	// 2. ecosystem + name, and 3. vendor + product: both are pair lookups, so
	// they share one shape. leftCol is spliced into the SQL rather than bound,
	// which is only safe because it is never anything but one of the two
	// column-name literals in the calls below — nothing from a caller or a
	// query reaches it. Anyone adding a third lookup must keep it that way.
	pairLookup := func(m map[pairKey][]int, leftCol string) error {
		if len(m) == 0 {
			return nil
		}
		lefts := make([]string, 0, len(m))
		rights := make([]string, 0, len(m))
		for k := range m {
			lefts = append(lefts, k.a)
			rights = append(rights, k.b)
		}
		rows, err := s.candidateRows(ctx, `
            SELECT `+columns+`, q.l AS k1, q.r AS k2
              FROM unnest($1::text[], $2::text[]) AS q(l, r)
              JOIN LATERAL (
                   SELECT * FROM vuln_affected
                    WHERE lower(`+leftCol+`) = q.l AND lower(product) = q.r
                    ORDER BY vuln_id, fingerprint
                    LIMIT $3) a ON true`,
			pq.Array(lefts), pq.Array(rights), perKey)
		if err != nil {
			return err
		}
		for _, r := range rows {
			k := pairKey{r.key1, r.key2}
			add(pairKey{leftCol + "\x00" + r.key1, r.key2}, m[k], r.statement)
		}
		return nil
	}
	if err := pairLookup(ecoName, "ecosystem"); err != nil {
		return nil, err
	}
	if err := pairLookup(vendorProduct, "vendor"); err != nil {
		return nil, err
	}

	// 4. Bare product name. The weakest identity by far — "the thing on this
	// host is called curl" is not evidence that it is the same curl — but it is
	// the only identity an operating-system inventory without purls can offer,
	// so it is collected and left for the caller to grade down.
	if len(nameOnly) > 0 {
		keys := make([]string, 0, len(nameOnly))
		for k := range nameOnly {
			keys = append(keys, k)
		}
		rows, err := s.candidateRows(ctx, `
            SELECT `+columns+`, q.k AS k1, '' AS k2
              FROM unnest($1::text[]) AS q(k)
              JOIN LATERAL (
                   SELECT * FROM vuln_affected
                    WHERE lower(product) = q.k
                    ORDER BY vuln_id, fingerprint
                    LIMIT $2) a ON true`, pq.Array(keys), perKey)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			add(pairKey{"product", r.key1}, nameOnly[r.key1], r.statement)
		}
	}

	for i := range out.Statements {
		out.Statements[i] = dedupeStatements(out.Statements[i])
	}
	return out, nil
}

// candidateRow carries the statement plus the lookup key it was found under, so
// the caller can attribute it back to the component that asked. The key is two
// separate columns rather than one concatenated string: PostgreSQL cannot store
// a NUL in text, so any separator chosen for a composite key is a character that
// could legitimately appear in a product name.
type candidateRow struct {
	statement AffectedStatement
	key1      string
	key2      string
}

func (s *Store) candidateRows(ctx context.Context, query string, args ...any) ([]candidateRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: affected candidates: %w", err)
	}
	defer rows.Close()

	var out []candidateRow
	for rows.Next() {
		var (
			r        candidateRow
			cpes     pq.StringArray
			versions pq.StringArray
			ranges   []byte
		)
		if err := rows.Scan(&r.statement.VulnID, &r.statement.Vendor, &r.statement.Product,
			&r.statement.Ecosystem, &r.statement.PURL, &cpes, &versions, &ranges,
			&r.statement.Status, &r.statement.DefaultState, &r.statement.Source, &r.statement.Fingerprint,
			&r.key1, &r.key2); err != nil {
			return nil, fmt.Errorf("store: scan candidate: %w", err)
		}
		r.statement.CPEs = cpes
		r.statement.Versions = versions
		if len(ranges) > 0 {
			if err := json.Unmarshal(ranges, &r.statement.Ranges); err != nil {
				return nil, fmt.Errorf("store: decode ranges for %s: %w", r.statement.VulnID, err)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// dedupeStatements collapses the same statement arriving through more than one
// identity — a row found by both purl and product name is one statement, not two.
func dedupeStatements(in []AffectedStatement) []AffectedStatement {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, st := range in {
		// The store's own statement identity, which is what the unique
		// constraint uses. Keying on the product fields alone merges two
		// statements that describe the same product through different affected
		// windows — a vulnerability fixed on several release branches has one
		// statement per branch — and keeps whichever arrived first.
		k := st.VulnID + "\x00" + st.Fingerprint
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, st)
	}
	return out
}

// normalisePURL derives the lookup key from a purl: qualifiers and subpath cut
// off, the version stripped, the rest lower-cased. A target system reports
// pkg:deb/debian/curl@7.88.1-10?arch=amd64 while the advisory says
// pkg:deb/debian/curl; neither the architecture nor the release changes which
// vulnerability applies, and the version is carried separately by the
// component.
//
// It must produce exactly what purlKeyExpr produces in SQL, because the stored
// side is normalised by the index and the asking side here. The version is
// only the '@' after the last '/': in pkg:npm/@angular/core the '@' is part
// of the scope, and cutting there left "pkg:npm/".
func normalisePURL(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i >= 0 && !strings.Contains(p[i:], "/") {
		p = p[:i]
	}
	return strings.ToLower(p)
}

// VulnSummary is the reporting metadata a finding needs beyond the identifier.
type VulnSummary struct {
	ID             string     `json:"id"`
	Title          string     `json:"title,omitempty"`
	State          string     `json:"state,omitempty"`
	Rating         string     `json:"rating,omitempty"`
	Score          float64    `json:"score,omitempty"`
	Vector         string     `json:"vector,omitempty"`
	CWEs           []string   `json:"cwes,omitempty"`
	InKEV          bool       `json:"in_kev"`
	EPSSScore      float64    `json:"epss_score,omitempty"`
	EPSSPercentile float64    `json:"epss_percentile,omitempty"`
	Published      *time.Time `json:"published,omitempty"`
	Modified       *time.Time `json:"modified,omitempty"`
}

// VulnSummaries fetches reporting metadata for a set of identifiers in one round
// trip. Findings are useless without severity, exploitation status and EPSS —
// that is what turns a list of matches into a prioritised one.
func (s *Store) VulnSummaries(ctx context.Context, ids []string) (map[string]VulnSummary, error) {
	out := make(map[string]VulnSummary, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT v.id, COALESCE(v.title,''), COALESCE(v.state,''),
               COALESCE(v.primary_rating,''), v.primary_score, COALESCE(v.primary_vector,''),
               v.cwes, v.in_kev, v.epss_score, v.epss_percentile, v.published, v.modified
          FROM vulnerabilities v
         WHERE v.id = ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("store: vulnerability summaries: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			vs    VulnSummary
			cwes  pq.StringArray
			score sql.NullFloat64
			eScr  sql.NullFloat64
			ePct  sql.NullFloat64
			pub   sql.NullTime
			mod   sql.NullTime
		)
		if err := rows.Scan(&vs.ID, &vs.Title, &vs.State, &vs.Rating, &score, &vs.Vector,
			&cwes, &vs.InKEV, &eScr, &ePct, &pub, &mod); err != nil {
			return nil, fmt.Errorf("store: scan summary: %w", err)
		}
		vs.CWEs = cwes
		if score.Valid {
			vs.Score = score.Float64
		}
		if eScr.Valid {
			vs.EPSSScore = eScr.Float64
		}
		if ePct.Valid {
			vs.EPSSPercentile = ePct.Float64
		}
		if pub.Valid {
			t := pub.Time
			vs.Published = &t
		}
		if mod.Valid {
			t := mod.Time
			vs.Modified = &t
		}
		out[vs.ID] = vs
	}
	return out, rows.Err()
}

// cpeVendorLimit bounds how many vendors are considered for one product. A
// product name that matches dozens of vendors is one where the name alone is
// not evidence, and taking the most common of fifty is not better than taking
// the most common of five.
const cpeVendorLimit = 5

// CPEVendorsFor reports the CPE vendors this corpus files a product under,
// most-covering first.
//
// External scanners carry their own CPE dictionaries and those go stale: nmap
// still calls nginx "igor_sysoev:nginx", which names nothing here, while the
// corpus files it under "f5". A CPE that matches nothing does not announce
// itself — the finding silently degrades to a bare-name match and the default
// confidence floor hides it — so the corpus is asked rather than trusted to
// agree.
//
// Read from cpe_vendor_rank, which exists because asking vuln_affected directly
// costs an unnest across nine million rows for every question. When the table
// is empty — a corpus loaded before migration 5, or one never refreshed — it
// falls back to the slow query rather than answering wrongly.
func (s *Store) CPEVendorsFor(ctx context.Context, product string) ([]string, error) {
	product = strings.ToLower(strings.TrimSpace(product))
	if product == "" {
		return nil, nil
	}
	out, err := s.rankedVendors(ctx, product)
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		return out, nil
	}
	var ranked int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM cpe_vendor_rank`).Scan(&ranked); err == nil && ranked > 0 {
		// The table is populated and this product is genuinely not in it.
		return nil, nil
	}
	return s.scanVendors(ctx, product)
}

func (s *Store) rankedVendors(ctx context.Context, product string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT vendor FROM cpe_vendor_rank
         WHERE product = $1
         ORDER BY vulns DESC, vendor
         LIMIT $2`, product, cpeVendorLimit)
	if err != nil {
		return nil, fmt.Errorf("store: cpe vendors for %s: %w", product, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var vendor string
		if err := rows.Scan(&vendor); err != nil {
			return nil, fmt.Errorf("store: scan cpe vendor: %w", err)
		}
		out = append(out, vendor)
	}
	return out, rows.Err()
}

// scanVendors is the direct question, kept for a corpus whose ranking has not
// been built. Ordered by how many distinct vulnerabilities a vendor covers, not
// by how many rows it has: NVD enumerates every affected build as its own CPE,
// so row count measures how verbose a record is rather than how much it knows.
// For vsftpd, "redhat" has 31 rows carrying a single CVE from 2008, while
// "vsftpd_project" has 5 rows carrying five separate ones.
func (s *Store) scanVendors(ctx context.Context, product string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT split_part(c, ':', 4) AS vendor, count(DISTINCT vuln_id) AS n
          FROM vuln_affected, unnest(cpes) c
         WHERE split_part(c, ':', 5) = $1
           AND split_part(c, ':', 4) <> ''
         GROUP BY 1
         ORDER BY n DESC, vendor
         LIMIT $2`, product, cpeVendorLimit)
	if err != nil {
		return nil, fmt.Errorf("store: cpe vendors for %s: %w", product, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var vendor string
		var n int
		if err := rows.Scan(&vendor, &n); err != nil {
			return nil, fmt.Errorf("store: scan cpe vendor: %w", err)
		}
		out = append(out, vendor)
	}
	return out, rows.Err()
}

// RefreshCPEVendorRank recomputes the ranking from the corpus.
//
// Run after ingest rather than on a timer: the answer changes exactly when
// vuln_affected does, and the computation is a two-minute full scan that has no
// business happening while somebody waits for a report.
//
// The scan runs into a temporary table first, outside any transaction that
// touches cpe_vendor_rank. TRUNCATE takes an ACCESS EXCLUSIVE lock, and taking
// it before the two-minute aggregation meant every CPEVendorsFor — one per
// service a network scan identifies — waited behind the rebuild. Now the lock
// is held only for the copy from the temporary table, which is a second. The
// temporary table lives on one connection, so the whole thing is pinned to one.
func (s *Store) RefreshCPEVendorRank(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `
        DROP TABLE IF EXISTS pg_temp.cpe_vendor_rank_build;
        CREATE TEMP TABLE cpe_vendor_rank_build AS
        SELECT split_part(c, ':', 5) AS product, split_part(c, ':', 4) AS vendor,
               count(DISTINCT vuln_id)::integer AS vulns
          FROM vuln_affected, unnest(cpes) c
         WHERE split_part(c, ':', 5) <> '' AND split_part(c, ':', 4) <> ''
         GROUP BY 1, 2`); err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: build: %w", err)
	}
	// Whatever happens below, the build table must not outlive the call: the
	// connection goes back to the pool and the next borrower would find it.
	defer conn.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS pg_temp.cpe_vendor_rank_build`)

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `TRUNCATE cpe_vendor_rank`); err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO cpe_vendor_rank (product, vendor, vulns)
        SELECT product, vendor, vulns FROM pg_temp.cpe_vendor_rank_build`); err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: swap: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: refresh cpe vendor rank: commit: %w", err)
	}
	return nil
}
