// Package store owns all PostgreSQL access: schema, migrations, the
// merge-on-write upsert that collapses identifiers into one canonical record,
// and the read queries behind the HTTP API.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// Store is a handle on the database.
type Store struct {
	db *sql.DB
}

// Open connects and verifies reachability.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{db: db}, nil
}

// DB exposes the underlying pool for health checks.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the pool.
func (s *Store) Close() error { return s.db.Close() }

// lockTimeout bounds how long a writer waits for a row lock before giving up.
//
// Contention between concurrent writers on the same alias cluster is normal and
// clears in milliseconds; this is not aimed at that. It is aimed at a lock whose
// holder is never coming back. PostgreSQL does not notice a client that vanished
// without closing its connection, so a transaction killed mid-flight keeps its
// locks and every later writer queues behind it — observed live as 26 backends
// stacked on one row, the oldest 26 minutes deep, after ingest containers were
// stopped mid-transaction.
//
// Waiting forever turns that into a silent hang with no CPU, no network and no
// log line. A bounded wait turns it into an error the run can report and retry.
const lockTimeout = 30 * time.Second

// IsLockTimeout reports whether err is PostgreSQL giving up on a row lock
// (SQLSTATE 55P03): the other writer held it past lockTimeout. Nothing about
// the record is wrong, so the caller may simply try again.
func IsLockTimeout(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "55P03"
}

// sourceRank orders collectors by authority. Lower is more authoritative.
// The CNA record is the ground truth; CISA's ADP enrichment is next because it
// is the designated authorised publisher; NVD follows, and community or
// downstream mirrors come last.
var sourceRank = map[string]int{
	"cvelist":      0,
	"vulnrichment": 1,
	"nvd":          2,
	"fkie":         3,
	"csaf":         4,
	"euvd":         5,
	"gcve":         6,
	"ghsa":         7,
	"osv":          8,
}

func rankOf(source string) int {
	if r, ok := sourceRank[source]; ok {
		return r
	}
	return 100
}

const migrationSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sources (
    name            text PRIMARY KEY,
    cursor          jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_run_at     timestamptz,
    last_success_at timestamptz,
    last_error      text,
    records_seen    bigint NOT NULL DEFAULT 0
);

-- Every upstream document is kept verbatim. Normalisation logic changes over
-- time; re-deriving from raw is free, re-fetching 300k records is not.
--
-- content is bytea rather than jsonb because it is an archive: nothing queries
-- inside it, only content_sha256 is read, and jsonb parsed every document on
-- write for a structure no query uses while storing it larger than the text it
-- came from. It holds xz-compressed JSON — 16.9x smaller, measured on the real
-- corpus — and reads back through decompressRaw, which also passes through the
-- bare JSON that rows written before this change still hold.
CREATE TABLE IF NOT EXISTS raw_records (
    source         text NOT NULL,
    record_id      text NOT NULL,
    content        bytea NOT NULL,
    content_sha256 text NOT NULL,
    fetched_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, record_id)
);
CREATE INDEX IF NOT EXISTS raw_records_fetched_at_idx ON raw_records (fetched_at DESC);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                    text PRIMARY KEY,
    title                 text,
    description           text,
    state                 text,
    published             timestamptz,
    modified              timestamptz,
    withdrawn             timestamptz,
    assigner              text,
    cwes                  text[] NOT NULL DEFAULT '{}',
    primary_severity_type text,
    primary_score         double precision,
    primary_vector        text,
    primary_rating        text,
    primary_provider      text,
    epss_score            double precision,
    epss_percentile       double precision,
    epss_date             date,
    in_kev                boolean NOT NULL DEFAULT false,
    kev_date_added        date,
    ssvc                  jsonb,
    sources               text[] NOT NULL DEFAULT '{}',
    doc                   bytea NOT NULL,
    search                tsvector,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vuln_modified_idx    ON vulnerabilities (modified DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vuln_published_idx   ON vulnerabilities (published DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vuln_score_idx       ON vulnerabilities (primary_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vuln_epss_idx        ON vulnerabilities (epss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vuln_kev_idx         ON vulnerabilities (in_kev) WHERE in_kev;
CREATE INDEX IF NOT EXISTS vuln_updated_idx     ON vulnerabilities (updated_at DESC);
CREATE INDEX IF NOT EXISTS vuln_search_idx      ON vulnerabilities USING gin (search);
CREATE INDEX IF NOT EXISTS vuln_cwes_idx        ON vulnerabilities USING gin (cwes);
CREATE INDEX IF NOT EXISTS vuln_sources_idx     ON vulnerabilities USING gin (sources);

CREATE TABLE IF NOT EXISTS vuln_aliases (
    alias   text PRIMARY KEY,
    vuln_id text NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS vuln_aliases_vuln_idx ON vuln_aliases (vuln_id);

CREATE TABLE IF NOT EXISTS vuln_severity (
    vuln_id  text NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    type     text NOT NULL,
    provider text NOT NULL DEFAULT '',
    source   text NOT NULL,
    score    double precision,
    vector   text,
    rating   text,
    PRIMARY KEY (vuln_id, type, provider, source)
);

CREATE TABLE IF NOT EXISTS vuln_reference (
    vuln_id text NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    url     text NOT NULL,
    source  text NOT NULL,
    name    text,
    tags    text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (vuln_id, url, source)
);

CREATE TABLE IF NOT EXISTS vuln_affected (
    vuln_id     text NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    vendor      text,
    product     text,
    ecosystem   text,
    purl        text,
    cpes        text[] NOT NULL DEFAULT '{}',
    versions    text[] NOT NULL DEFAULT '{}',
    ranges      jsonb  NOT NULL DEFAULT '[]'::jsonb,
    source      text NOT NULL,
    PRIMARY KEY (vuln_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS vuln_affected_cpes_idx    ON vuln_affected USING gin (cpes);
CREATE INDEX IF NOT EXISTS vuln_affected_product_idx ON vuln_affected (lower(product));
CREATE INDEX IF NOT EXISTS vuln_affected_purl_idx    ON vuln_affected (purl) WHERE purl IS NOT NULL;

CREATE TABLE IF NOT EXISTS kev (
    cve_id             text PRIMARY KEY,
    vendor_project     text,
    product            text,
    vulnerability_name text,
    short_description  text,
    required_action    text,
    notes              text,
    date_added         date,
    due_date           date,
    known_ransomware   boolean NOT NULL DEFAULT false,
    kev_sources        text[] NOT NULL DEFAULT '{}',
    source             text NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id     text PRIMARY KEY,
    score      double precision NOT NULL,
    percentile double precision NOT NULL,
    score_date date NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS epss_score_idx ON epss (score DESC);

CREATE TABLE IF NOT EXISTS vuln_history (
    id         bigserial PRIMARY KEY,
    vuln_id    text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    source     text NOT NULL,
    change     jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS vuln_history_vuln_idx ON vuln_history (vuln_id, changed_at DESC);
`

// migration2SQL adds what the first schema could not express: NVD's enrichment
// state, VEX product status, the provenance fields the upstream terms of use
// require us to keep, and indexes for the filters the API advertises.
const migration2SQL = `
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS enrichment_status text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS tags text[] NOT NULL DEFAULT '{}';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS doc_sha256 text;

ALTER TABLE vuln_affected ADD COLUMN IF NOT EXISTS status text;

ALTER TABLE vuln_aliases ADD COLUMN IF NOT EXISTS source text;

ALTER TABLE kev ADD COLUMN IF NOT EXISTS catalog_version text;
ALTER TABLE kev ADD COLUMN IF NOT EXISTS date_released timestamptz;
ALTER TABLE kev ADD COLUMN IF NOT EXISTS cwes text[] NOT NULL DEFAULT '{}';
ALTER TABLE kev ADD COLUMN IF NOT EXISTS ransomware_use text;

ALTER TABLE epss ADD COLUMN IF NOT EXISTS model_version text;

-- The filters the README advertises need indexes; without them every vendor or
-- ecosystem query is a sequential scan of the affected table.
CREATE INDEX IF NOT EXISTS vuln_affected_vendor_idx    ON vuln_affected (lower(vendor));
CREATE INDEX IF NOT EXISTS vuln_affected_ecosystem_idx ON vuln_affected (lower(ecosystem));
CREATE INDEX IF NOT EXISTS vuln_affected_status_idx    ON vuln_affected (status) WHERE status IS NOT NULL;
CREATE INDEX IF NOT EXISTS vuln_rating_idx             ON vulnerabilities (upper(primary_rating));
CREATE INDEX IF NOT EXISTS vuln_state_idx              ON vulnerabilities (state);
-- The streaming export walks (modified DESC, id) as a keyset; a matching index
-- turns that walk into a single ordered scan.
CREATE INDEX IF NOT EXISTS vuln_modified_id_idx        ON vulnerabilities (modified DESC NULLS LAST, id);

-- Two spellings of the same assertion reached the affected table before the
-- status vocabulary was pinned down. A scanner that reads them as different
-- claims reports patched software as vulnerable.
UPDATE vuln_affected SET status = 'not_affected' WHERE status = 'unaffected';

-- Upstream terms of use require the notices to be reproduced by anything that
-- redistributes the data. Keeping them in a table rather than only in code
-- means an operator can audit and extend them without a rebuild.
CREATE TABLE IF NOT EXISTS attribution (
    source      text PRIMARY KEY,
    upstream    text NOT NULL,
    licence     text NOT NULL,
    notice      text NOT NULL,
    url         text,
    required    boolean NOT NULL DEFAULT false,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
`

// migration3SQL adds the composite indexes the scanner's candidate lookups need.
// A scan asks "which statements are about (ecosystem, name)" or
// "(vendor, product)" once per component, and an SBOM has hundreds of
// components; two single-column indexes make PostgreSQL choose between them and
// filter the rest, which is the difference between a scan and a table scan.
const migration3SQL = `
CREATE INDEX IF NOT EXISTS vuln_affected_eco_product_idx
    ON vuln_affected (lower(ecosystem), lower(product));
CREATE INDEX IF NOT EXISTS vuln_affected_vendor_product_idx
    ON vuln_affected (lower(vendor), lower(product));
-- The scanner looks a purl up without its qualifiers or version, because a
-- target reports pkg:deb/debian/curl@7.88.1-10?arch=amd64 and the advisory says
-- pkg:deb/debian/curl.
CREATE INDEX IF NOT EXISTS vuln_affected_purl_base_idx
    ON vuln_affected (split_part(purl, '?', 1)) WHERE purl IS NOT NULL;
`

// migrations are applied in order and recorded in schema_migrations. Version 1
// is the original schema; later versions only ever add. Running them on every
// start is deliberate — the deployment has one binary and no separate migration
// tool — but each step has to be idempotent because of it.
// migration4SQL converts raw_records.content from jsonb to bytea.
//
// Note for anyone repeating this: run it once and let it finish. The conversion
// rewrites the table and takes tens of minutes on a loaded corpus, and killing
// it part-way leaves a transaction holding the lock that every retry then
// queues behind. Two of those completing in sequence is worse than one being
// slow — the second sees a column that is already bytea, and `doc::text` on a
// bytea yields its hex representation, which it then stores as text. That
// happened here, to 1,096,576 rows, and was recoverable only because hex
// encoding is lossless.
//
// USING content::text::bytea rewrites the table, which needs as much free space
// as it already occupies. On the machine where this was written that was the
// resource that ran out, so the conversion does not compress anything: it
// changes the type, and rows shrink as the collectors rewrite them. An install
// with room to spare can reclaim the rest at once with
// `VACUUM FULL raw_records` after a re-ingest.
//
// The ALTER is wrapped in a check on the column's current type. Migrate now
// runs each step under a lock and in one transaction with its version row, so
// the double run described above should no longer be possible — but this is
// the one migration whose second run destroys data, and a guard that costs one
// catalogue lookup is cheaper than trusting that nothing ever restores an old
// schema_migrations table over a converted corpus. pg_attribute is consulted
// rather than information_schema because 'raw_records'::regclass resolves
// through search_path exactly as the ALTER itself does.
const migration4SQL = `
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = 'raw_records'::regclass
           AND a.attname = 'content'
           AND NOT a.attisdropped
           AND format_type(a.atttypid, a.atttypmod) = 'jsonb'
    ) THEN
        ALTER TABLE raw_records
            ALTER COLUMN content TYPE bytea USING convert_to(content::text, 'UTF8');
    END IF;
END $$;
`

// migration5SQL adds the CPE vendor ranking the network scanner consults.
//
// Answering "which vendor does this corpus file nginx under" from vuln_affected
// means unnesting an array across nine million rows, which no index can help
// with: measured at about six seconds per product, and a scan asks once per
// service it identifies. The scan of a single host spent longer on this than on
// the network.
//
// The answer changes only when the corpus does, so it is computed once and read
// back by primary key — 0.16s against 6s. RefreshCPEVendorRank rebuilds it, and
// the ingest runs it after each collector.
const migration5SQL = `
CREATE TABLE IF NOT EXISTS cpe_vendor_rank (
    product text NOT NULL,
    vendor  text NOT NULL,
    vulns   integer NOT NULL,
    PRIMARY KEY (product, vendor)
);
`

// migration6SQL converts vulnerabilities.doc from jsonb to bytea.
//
// Nothing queries inside it — every read is SELECT doc followed by
// json.Unmarshal in Go, there is no index on it, and the search tsvector is
// built separately from the record's fields. So it is an archive, and jsonb was
// costing a parse on every write plus a binary form larger than the text.
//
// USING rewrites the table, which needs as much free space as it occupies. The
// conversion therefore does not compress anything: it changes the type, and
// rows shrink as they are rewritten. decompressDoc reads the bare JSON that
// rows written before this still hold.
//
// Guarded on the column's current type for the same reason migration 4 is: a
// second run over a bytea column stores the hex spelling of every document.
const migration6SQL = `
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = 'vulnerabilities'::regclass
           AND a.attname = 'doc'
           AND NOT a.attisdropped
           AND format_type(a.atttypid, a.atttypmod) = 'jsonb'
    ) THEN
        ALTER TABLE vulnerabilities
            ALTER COLUMN doc TYPE bytea USING convert_to(doc::text, 'UTF8');
    END IF;
END $$;
`

// migration7SQL persists the default state of an affected statement.
//
// CVE 5.1 lets a CNA say "everything is affected except these versions" by
// putting defaultStatus: affected next to a list of unaffected ranges. Without
// the default, a statement that lists only unaffected windows reads as "nothing
// is affected", which is the opposite of what the CNA said. The parser has
// carried the field for a while; the store dropped it on the floor.
const migration7SQL = `
ALTER TABLE vuln_affected ADD COLUMN IF NOT EXISTS default_state text;
`

// migration8SQL indexes the purl lookup key the scanner actually uses.
//
// The previous index was on split_part(purl, '?', 1): qualifiers stripped, but
// the version, the subpath and the letter case kept. The scanner strips all
// four on its side, so a stored pkg:rpm/redhat/kernel@4.18.0-553.el8 — every
// CSAF purl carries its version — or pkg:golang/github.com/Masterminds/goutils
// was never found. Both sides now derive the key with purlKeyExpr and
// normalisePURL, which are kept identical by a test.
//
// The expression is spelled out rather than taken from purlKeyExpr because
// this is what version 8 created on every corpus that ran it, and a migration
// that changes its text after the fact is one whose recorded version no
// longer says what the schema looks like. Version 10 carries the corrected
// expression.
const migration8SQL = `
CREATE INDEX IF NOT EXISTS vuln_affected_purl_key_idx
    ON vuln_affected (lower(regexp_replace(split_part(split_part(purl, '?', 1), '#', 1), '@[^/]*$', ''))) WHERE purl IS NOT NULL;
DROP INDEX IF EXISTS vuln_affected_purl_base_idx;
`

// migration9SQL indexes the expression the state filter compares on. The filter
// upper-cases both sides so that ?state=published matches, but the index from
// migration 2 is on the bare column, which upper(state) cannot use.
const migration9SQL = `
CREATE INDEX IF NOT EXISTS vuln_state_upper_idx ON vulnerabilities (upper(state));
`

// migration10SQL rebuilds the purl key index on the corrected expression.
//
// Version 8's pattern '@[^/]*$' cut from the first '@' whose tail held no
// '/', while normalisePURL cuts at the last '@': for pkg:npm/a@b@c the index
// stored "pkg:npm/a" and the scanner asked for "pkg:npm/a@b", and the two
// never met. purlKeyExpr now cuts at the last '@' too. An expression index is
// only used for the exact expression it was built on, so the old one has to
// go and be built again; CREATE INDEX IF NOT EXISTS under the same name would
// have kept the old expression and silently returned to sequential scans.
const migration10SQL = `
DROP INDEX IF EXISTS vuln_affected_purl_key_idx;
CREATE INDEX vuln_affected_purl_key_idx
    ON vuln_affected (` + purlKeyExpr + `) WHERE purl IS NOT NULL;
`

var migrations = []struct {
	version int
	sql     string
}{
	{1, migrationSQL},
	{2, migration2SQL},
	{3, migration3SQL},
	{4, migration4SQL},
	{5, migration5SQL},
	{6, migration6SQL},
	{7, migration7SQL},
	{8, migration8SQL},
	{9, migration9SQL},
	{10, migration10SQL},
}

// migrationLockKey is the advisory lock every Migrate takes before it changes
// the schema. The deployment has one binary and no separate migration tool, so
// every subcommand used to migrate on start, and two of them starting together
// — the API container restarting while `make delta` opened a second process —
// both saw the same pending version and both ran it. For most migrations that
// is a wasted ALTER; for 4 and 6 it converted a corpus to hex.
const migrationLockKey int64 = 0x63766566656564 // "cvefeed"

const bootstrapSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migrate creates or updates the schema. It is safe to run on every start and
// from several processes at once: each step runs in one transaction that first
// takes migrationLockKey, re-reads which versions are applied, and records its
// own version before committing, so a step is either fully applied and
// recorded or not applied at all.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, bootstrapSQL); err != nil {
		return fmt.Errorf("store: migrate bootstrap: %w", err)
	}
	for _, m := range migrations {
		if err := s.applyMigration(ctx, m.version, m.sql); err != nil {
			return err
		}
	}
	return s.seedAttribution(ctx)
}

func (s *Store) applyMigration(ctx context.Context, version int, sql string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migrate to version %d: begin: %w", version, err)
	}
	defer tx.Rollback()

	// Transaction-scoped so that it cannot outlive a crashed process: a
	// session lock held by a backend whose client vanished would block every
	// later start until the backend was killed by hand.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("store: migrate to version %d: lock: %w", version, err)
	}
	// Re-read under the lock. Another process may have applied this version
	// between our first look and the lock being granted, and a DDL step that
	// is not idempotent must not run twice.
	applied, err := appliedVersions(ctx, tx)
	if err != nil {
		return err
	}
	if applied[version] {
		return nil
	}
	if _, err := tx.ExecContext(ctx, sql); err != nil {
		return fmt.Errorf("store: migrate to version %d: %w", version, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("store: record migration %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: migrate to version %d: commit: %w", version, err)
	}
	return nil
}

// querier is the subset of *sql.DB and *sql.Tx the read helpers need.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func appliedVersions(ctx context.Context, q querier) (map[int]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: scan migration row: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	return applied, nil
}

// CheckSchema reports whether the database is at the schema this binary
// expects, without changing anything. Read-only subcommands call it instead of
// Migrate: a `scan` run from the host must not start a table rewrite under a
// running API, and a query against a half-migrated schema fails in ways that
// look like missing data rather than a missing migration.
func (s *Store) CheckSchema(ctx context.Context) error {
	var initialised bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&initialised); err != nil {
		return fmt.Errorf("store: check schema: %w", err)
	}
	if !initialised {
		return errors.New("store: schema is not initialised: no schema_migrations table; run a subcommand that migrates (serve or ingest) once")
	}
	applied, err := appliedVersions(ctx, s.db)
	if err != nil {
		return err
	}
	var pending []int
	for _, m := range migrations {
		if !applied[m.version] {
			pending = append(pending, m.version)
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("store: schema is behind this binary: migrations %v are pending (%d of %d applied); run a subcommand that migrates (serve or ingest) once",
			pending, len(migrations)-len(pending), len(migrations))
	}
	return nil
}

// RawChanged reports whether an upstream document differs from what is already
// stored, without writing anything. The sink uses it to decide whether a record
// needs re-merging; the write itself happens only after the merge commits.
func (s *Store) RawChanged(ctx context.Context, source, recordID string, content []byte) (bool, error) {
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	var stored string
	err := s.db.QueryRowContext(ctx,
		`SELECT content_sha256 FROM raw_records WHERE source = $1 AND record_id = $2`,
		source, recordID).Scan(&stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("store: compare raw %s/%s: %w", source, recordID, err)
	}
	return stored != hexSum, nil
}

// SaveRaw stores an upstream document verbatim and reports whether the content
// actually changed. Unchanged documents skip the expensive merge path entirely,
// which is what makes re-ingesting a full bulk file cheap.
func (s *Store) SaveRaw(ctx context.Context, source, recordID string, content []byte) (bool, error) {
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	// ON CONFLICT ... RETURNING cannot see the pre-update row, so the update is
	// gated on the hash differing. No row comes back exactly when nothing
	// changed, which is the signal the caller wants.
	var one int
	packed, err := compressDoc(content)
	if err != nil {
		return false, err
	}
	err = s.db.QueryRowContext(ctx, `
        INSERT INTO raw_records (source, record_id, content, content_sha256, fetched_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (source, record_id) DO UPDATE
            SET content = EXCLUDED.content,
                content_sha256 = EXCLUDED.content_sha256,
                fetched_at = now()
            WHERE raw_records.content_sha256 IS DISTINCT FROM EXCLUDED.content_sha256
        RETURNING 1`,
		source, recordID, packed, hexSum).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: save raw %s/%s: %w", source, recordID, err)
	}
	return true, nil
}

// UpsertVulnerability merges one incoming record into the canonical store.
//
// The hard part is identity: the same flaw arrives as CVE-2024-1234 from the
// CVE List, GHSA-xxxx from GitHub and EUVD-2024-9999 from ENISA. Each carries
// the others in its alias list, so we resolve the whole alias set to any
// existing records, fold them into one canonical row, and merge field by field
// with source precedence.
func (s *Store) UpsertVulnerability(ctx context.Context, in *model.Vulnerability) (string, error) {
	ids := in.AllIdentifiers()
	if len(ids) == 0 {
		return "", errors.New("store: record has no identifiers")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '`+
		fmt.Sprint(lockTimeout.Milliseconds())+`ms'`); err != nil {
		return "", fmt.Errorf("store: set lock timeout: %w", err)
	}

	if err := lockIdentifiers(ctx, tx, ids); err != nil {
		return "", err
	}
	existing, err := resolveExisting(ctx, tx, ids)
	if err != nil {
		return "", err
	}

	canonical := model.PickCanonicalID(append(append([]string{}, ids...), existing...))
	if canonical == "" {
		canonical = ids[0]
	}

	var current *Document
	if len(existing) > 0 {
		// Read every previously separate document BEFORE folding: the fold
		// deletes the losing rows, and dropping their content on the floor
		// would silently discard everything those records contributed —
		// description, title, dates, the lot — until whichever source produced
		// them happens to re-emit.
		docs, err := loadDocs(ctx, tx, existing)
		if err != nil {
			return "", err
		}
		if err := foldRecords(ctx, tx, existing, canonical); err != nil {
			return "", err
		}
		current = mergeAll(docs, canonical)
	}

	merged := Merge(current, in)
	merged.ID = canonical
	merged.Aliases = normalizeIDs(append(merged.Aliases, ids...))
	merged.Aliases = removeString(merged.Aliases, canonical)

	if err := writeVuln(ctx, tx, merged, in.Source); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit %s: %w", canonical, err)
	}
	return canonical, nil
}

// lockIdentifiers serialises writers of the same vulnerability for the rest of
// the transaction.
//
// Rows lock themselves once they exist: loadDoc takes FOR UPDATE, and a second
// writer waits there. A record that does not exist yet has no row to lock, so
// two collectors delivering the first copy of one identifier at the same
// moment — the CVE List and OSV both publishing a new CVE within the same
// minute of ingest — both resolved it to nothing, both merged from nothing,
// and the second INSERT ... ON CONFLICT DO UPDATE replaced the first's
// document with one that had never seen it. The first source's contribution
// was gone until it happened to re-emit.
//
// A transaction-scoped advisory lock on each identifier closes the window:
// whichever writer takes it first finishes its merge before the other resolves,
// and the other then finds the row. The lock covers the record's own
// identifiers; a document reached through an alias edge already has a row and
// is covered by the row lock. Sorted, so that two records naming the same
// identifiers in a different order cannot each hold one and wait for the
// other's. hashtext folds the text onto the key space the lock functions take;
// a collision between two unrelated identifiers costs one of them a wait, not
// its correctness.
func lockIdentifiers(ctx context.Context, tx *sql.Tx, ids []string) error {
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, id); err != nil {
			return fmt.Errorf("store: lock %s: %w", id, err)
		}
	}
	return nil
}

func resolveExisting(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT DISTINCT vuln_id FROM vuln_aliases WHERE alias = ANY($1)
        UNION
        SELECT id FROM vulnerabilities WHERE id = ANY($1)
        ORDER BY 1`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("store: resolve aliases: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan alias: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// foldRecords repoints all children of the losing records at the canonical one
// and deletes the losers. Called when two identifiers that were previously
// tracked separately turn out to describe the same flaw.
func foldRecords(ctx context.Context, tx *sql.Tx, existing []string, canonical string) error {
	var losers []string
	for _, id := range existing {
		if id != canonical {
			losers = append(losers, id)
		}
	}
	if len(losers) == 0 {
		return nil
	}

	// The canonical row must exist before children can point at it.
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO vulnerabilities (id, doc)
        VALUES ($1, convert_to('{}', 'UTF8'))
        ON CONFLICT (id) DO NOTHING`, canonical); err != nil {
		return fmt.Errorf("store: ensure canonical %s: %w", canonical, err)
	}

	// Children are copied with INSERT ... ON CONFLICT rather than repointed
	// with UPDATE. An UPDATE hits the child primary key whenever the canonical
	// record already carries the same (type, provider, source) or URL — which
	// is the common case, not an edge case — and a unique violation aborts the
	// entire PostgreSQL transaction. Catching that error and continuing does
	// not undo the abort: every following statement fails with
	// "current transaction is aborted", the commit fails, and the record is
	// dropped on every retry because the inputs are identical. DISTINCT ON
	// additionally guards against two losers carrying the same key, which
	// ON CONFLICT rejects within a single statement.
	copies := []string{
		`INSERT INTO vuln_severity (vuln_id, type, provider, source, score, vector, rating)
         SELECT DISTINCT ON (type, provider, source) $2, type, provider, source, score, vector, rating
           FROM vuln_severity WHERE vuln_id = ANY($1)
         ON CONFLICT (vuln_id, type, provider, source) DO NOTHING`,
		`INSERT INTO vuln_reference (vuln_id, url, source, name, tags)
         SELECT DISTINCT ON (url, source) $2, url, source, name, tags
           FROM vuln_reference WHERE vuln_id = ANY($1)
         ON CONFLICT (vuln_id, url, source) DO NOTHING`,
		`INSERT INTO vuln_affected (vuln_id, fingerprint, vendor, product, ecosystem, purl, cpes, versions, ranges, status, default_state, source)
         SELECT DISTINCT ON (fingerprint) $2, fingerprint, vendor, product, ecosystem, purl, cpes, versions, ranges, status, default_state, source
           FROM vuln_affected WHERE vuln_id = ANY($1)
         ON CONFLICT (vuln_id, fingerprint) DO NOTHING`,
	}
	for _, q := range copies {
		if _, err := tx.ExecContext(ctx, q, pq.Array(losers), canonical); err != nil {
			return fmt.Errorf("store: fold children of %v into %s: %w", losers, canonical, err)
		}
	}
	for _, q := range []string{
		`DELETE FROM vuln_severity  WHERE vuln_id = ANY($1)`,
		`DELETE FROM vuln_reference WHERE vuln_id = ANY($1)`,
		`DELETE FROM vuln_affected  WHERE vuln_id = ANY($1)`,
	} {
		if _, err := tx.ExecContext(ctx, q, pq.Array(losers)); err != nil {
			return fmt.Errorf("store: prune folded children: %w", err)
		}
	}

	// History has no natural key, so it can simply be repointed.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vuln_history SET vuln_id = $2 WHERE vuln_id = ANY($1)`,
		pq.Array(losers), canonical); err != nil {
		return fmt.Errorf("store: fold history of %v into %s: %w", losers, canonical, err)
	}

	// Enrichment lives on the vulnerability row, so carry the losers' KEV and
	// EPSS flags across before their rows disappear.
	//
	// COALESCE is not defensive padding. A loser can be a name without a row —
	// resolveExisting reaches records through vuln_aliases, and an OSV record
	// listing a dozen CVE aliases usually has most of them unstored — and an
	// aggregate with no GROUP BY still returns one row when nothing matched,
	// with bool_or NULL. "false OR NULL" is NULL, which in_kev's NOT NULL
	// constraint rejects, and the whole upsert is lost.
	if _, err := tx.ExecContext(ctx, `
        UPDATE vulnerabilities c SET
            in_kev          = c.in_kev OR COALESCE(l.in_kev, false),
            kev_date_added  = COALESCE(c.kev_date_added, l.kev_date_added),
            epss_score      = COALESCE(c.epss_score, l.epss_score),
            epss_percentile = COALESCE(c.epss_percentile, l.epss_percentile),
            epss_date       = COALESCE(c.epss_date, l.epss_date)
          FROM (SELECT bool_or(in_kev) AS in_kev,
                       max(kev_date_added) AS kev_date_added,
                       max(epss_score) AS epss_score,
                       max(epss_percentile) AS epss_percentile,
                       max(epss_date) AS epss_date
                  FROM vulnerabilities WHERE id = ANY($1)) l
         WHERE c.id = $2`, pq.Array(losers), canonical); err != nil {
		return fmt.Errorf("store: carry enrichment of %v onto %s: %w", losers, canonical, err)
	}

	// Repoint any alias that still names a loser, then preserve the losing
	// identifiers themselves as aliases of the survivor.
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO vuln_aliases (alias, vuln_id, source)
        SELECT DISTINCT alias, $2, source FROM vuln_aliases WHERE vuln_id = ANY($1)
        ON CONFLICT (alias) DO UPDATE SET vuln_id = EXCLUDED.vuln_id`,
		pq.Array(losers), canonical); err != nil {
		return fmt.Errorf("store: repoint folded aliases: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO vuln_aliases (alias, vuln_id)
        SELECT unnest($1::text[]), $2
        ON CONFLICT (alias) DO UPDATE SET vuln_id = EXCLUDED.vuln_id`,
		pq.Array(losers), canonical); err != nil {
		return fmt.Errorf("store: alias folded ids: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM vulnerabilities WHERE id = ANY($1)`, pq.Array(losers)); err != nil {
		return fmt.Errorf("store: delete folded records: %w", err)
	}
	return nil
}

// loadDocs reads the stored documents for a set of identifiers, locking them
// for the duration of the transaction.
func loadDocs(ctx context.Context, tx *sql.Tx, ids []string) ([]*Document, error) {
	out := make([]*Document, 0, len(ids))
	for _, id := range ids {
		v, err := loadDoc(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if v != nil {
			out = append(out, v)
		}
	}
	return out, nil
}

// mergeAll folds several previously separate documents into one, most
// authoritative first so that source precedence resolves the same way it would
// have if they had always been a single record.
//
// Every document's own identifier goes into the aliases. A losing record that
// was reached through an alias edge — EUVD says GHSA-x, the CVE says EUVD —
// is not among the incoming record's identifiers, so nothing else would list
// it, and GET /v1/vulns/CVE-x would stop mentioning the GHSA it was folded
// from even though the id still resolves.
func mergeAll(docs []*Document, canonical string) *Document {
	if len(docs) == 0 {
		return nil
	}
	ordered := append([]*Document{}, docs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return rankOf(ordered[i].Source) < rankOf(ordered[j].Source)
	})
	out := merge(nil, ordered[0], true)
	for _, d := range ordered[1:] {
		out = merge(out, d, true)
	}
	for _, d := range ordered {
		if d.ID != "" {
			out.Aliases = append(out.Aliases, d.ID)
		}
	}
	out.Aliases = normalizeIDs(out.Aliases)
	out.ID = canonical
	return out
}

func loadDoc(ctx context.Context, tx *sql.Tx, id string) (*Document, error) {
	var doc []byte
	err := tx.QueryRowContext(ctx,
		`SELECT doc FROM vulnerabilities WHERE id = $1 FOR UPDATE`, id).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: load %s: %w", id, err)
	}
	if len(doc) == 0 || string(doc) == "{}" {
		return nil, nil
	}
	var v Document
	plain, err := decompressDoc(doc)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plain, &v); err != nil {
		return nil, fmt.Errorf("store: decode doc %s: %w", id, err)
	}
	return &v, nil
}

func writeVuln(ctx context.Context, tx *sql.Tx, v *Document, changeSource string) error {
	primary := PickPrimarySeverity(v.Severities)
	doc, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("store: encode doc %s: %w", v.ID, err)
	}
	// The change detector hashes the document with FetchedAt blanked. FetchedAt
	// is the time the collector saw the record, so it differs on every run
	// even when nothing upstream moved; hashing it made every re-ingest look
	// like a change, which wrote the child rows and a history row for every
	// record on every run and left the "nothing changed" guard below dead in
	// production. The stored document keeps the real FetchedAt.
	stable := *v
	stable.FetchedAt = time.Time{}
	hashDoc, err := json.Marshal(&stable)
	if err != nil {
		return fmt.Errorf("store: encode doc %s: %w", v.ID, err)
	}

	sources := collectSources(v)
	var ssvcJSON any
	if v.SSVC != nil {
		b, err := cleanJSON(json.Marshal(v.SSVC))
		if err != nil {
			return fmt.Errorf("store: encode ssvc %s: %w", v.ID, err)
		}
		ssvcJSON = string(b)
	}

	var (
		pType, pVector, pRating, pProvider any
		pScore                             any
	)
	if primary != nil {
		// Empty strings go in as NULL. A statement with a vector but no band
		// — every v4.0 vector this code cannot score — was stored with
		// primary_rating '' and counted under a rating of "" in the stats,
		// where a NULL is what "unscored" means everywhere else.
		pType = primary.Type
		pVector, pRating, pProvider = nullStr(cleanText(primary.Vector)), nullStr(cleanText(primary.Rating)), nullStr(cleanText(primary.Provider))
		if primary.Score > 0 {
			pScore = primary.Score
		}
	}

	packedDoc, err := compressDoc(doc)
	if err != nil {
		return err
	}
	searchText := cleanText(strings.Join([]string{v.ID, v.Title, v.Description, strings.Join(v.Aliases, " ")}, " "))
	docSum := sha256.Sum256(hashDoc)
	docHash := hex.EncodeToString(docSum[:])

	// The upsert reports whether the document actually changed. Child rows and
	// the change log are then written only when it did: re-ingesting a bulk
	// archive otherwise appends one history row per record per source per run,
	// which turns the change log into noise and costs more writes than the
	// merge itself.
	var one int
	err = tx.QueryRowContext(ctx, `
        INSERT INTO vulnerabilities (
            id, title, description, state, published, modified, withdrawn, assigner,
            cwes, primary_severity_type, primary_score, primary_vector, primary_rating,
            primary_provider, ssvc, sources, doc, search, enrichment_status, tags,
            doc_sha256, updated_at
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,
            to_tsvector('simple', $18), $19, $20, $21, now()
        )
        ON CONFLICT (id) DO UPDATE SET
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            state = EXCLUDED.state,
            published = EXCLUDED.published,
            modified = EXCLUDED.modified,
            withdrawn = EXCLUDED.withdrawn,
            assigner = EXCLUDED.assigner,
            cwes = EXCLUDED.cwes,
            primary_severity_type = EXCLUDED.primary_severity_type,
            primary_score = EXCLUDED.primary_score,
            primary_vector = EXCLUDED.primary_vector,
            primary_rating = EXCLUDED.primary_rating,
            primary_provider = EXCLUDED.primary_provider,
            ssvc = EXCLUDED.ssvc,
            sources = EXCLUDED.sources,
            doc = EXCLUDED.doc,
            search = EXCLUDED.search,
            enrichment_status = EXCLUDED.enrichment_status,
            tags = EXCLUDED.tags,
            doc_sha256 = EXCLUDED.doc_sha256,
            updated_at = now()
        WHERE vulnerabilities.doc_sha256 IS DISTINCT FROM EXCLUDED.doc_sha256
        RETURNING 1`,
		v.ID, nullStr(cleanText(v.Title)), nullStr(cleanText(v.Description)), nullStr(cleanText(v.State)),
		v.Published, v.Modified, v.Withdrawn, nullStr(cleanText(v.AssignerShortName)),
		strArray(cleanTexts(v.CWEs)), pType, pScore, pVector, pRating, pProvider,
		ssvcJSON, strArray(sources), packedDoc, searchText,
		nullStr(cleanText(v.EnrichmentStatus)), strArray(cleanTexts(v.Tags)), docHash).Scan(&one)
	changed := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The DO UPDATE guard matched: the stored document is byte-identical,
		// so there is nothing to re-derive and nothing to log.
		changed = false
	case err != nil:
		return fmt.Errorf("store: upsert %s: %w", v.ID, err)
	}

	// Alias edges record who asserted them. An incorrect merge is otherwise
	// impossible to attribute, and this graph is the one place where a single
	// bad upstream claim can silently collapse two real vulnerabilities.
	if len(v.Aliases) > 0 {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO vuln_aliases (alias, vuln_id, source)
            SELECT unnest($1::text[]), $2, $3
            ON CONFLICT (alias) DO UPDATE SET
                vuln_id = EXCLUDED.vuln_id,
                source  = COALESCE(EXCLUDED.source, vuln_aliases.source)`,
			strArray(v.Aliases), v.ID, nullStr(changeSource)); err != nil {
			return fmt.Errorf("store: write aliases %s: %w", v.ID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO vuln_aliases (alias, vuln_id, source) VALUES ($1, $1, $2)
        ON CONFLICT (alias) DO UPDATE SET vuln_id = EXCLUDED.vuln_id`,
		v.ID, nullStr(changeSource)); err != nil {
		return fmt.Errorf("store: self alias %s: %w", v.ID, err)
	}

	if !changed {
		return nil
	}

	// Child rows go in as one statement per table rather than one per row. A
	// CVE with forty references would otherwise cost forty round trips, and
	// that multiplier is what dominates a bulk ingest.
	if err := writeChildren(ctx, tx, v); err != nil {
		return err
	}

	change, err := json.Marshal(map[string]any{
		"modified":          v.Modified,
		"state":             v.State,
		"score":             pScore,
		"rating":            pRating,
		"enrichment_status": nullStr(v.EnrichmentStatus),
		"sources":           sources,
	})
	if err != nil {
		return fmt.Errorf("store: encode history %s: %w", v.ID, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO vuln_history (vuln_id, source, change) VALUES ($1,$2,$3::jsonb)`,
		v.ID, changeSource, string(change)); err != nil {
		return fmt.Errorf("store: write history %s: %w", v.ID, err)
	}
	return nil
}

func collectSources(v *Document) []string {
	set := []string{v.Source}
	// Every record that was merged is a source of the document, whether or
	// not it supplied a child row. Without this a source that contributed
	// only text — an OSV entry with a summary and aliases, then overtaken by
	// the CNA record — dropped out of the column the source filter and the
	// stats read, although its words were still in the document.
	for key := range v.Contributions {
		if src := keySource(key); src != "" {
			set = append(set, src)
		}
	}
	for _, s := range v.Severities {
		set = append(set, s.Source)
	}
	for _, r := range v.References {
		set = append(set, r.Source)
	}
	for _, a := range v.Affected {
		set = append(set, a.Source)
	}
	return model.DedupeStrings(set)
}

func affectedFingerprint(a model.Affected) string {
	// Status is part of the identity. A CSAF advisory routinely names the same
	// product under known_affected, fixed and known_not_affected; without the
	// status in the key those three collapse into one row and the VEX assertion
	// — the whole reason to collect CSAF — is lost.
	//
	// So are the ranges and the default state. A vulnerability fixed on three
	// release branches is three statements about one product that differ only
	// in their windows, and the Linux CNA emits a statement carrying a git
	// range next to one carrying only "unaffected" versions for the same
	// product. Keyed without the ranges, whichever was written last silently
	// replaced the others. The ranges go in as JSON rather than joined text so
	// that "introduced 1, fixed 2" and "introduced 1.2" cannot collide.
	var ranges string
	if len(a.Ranges) > 0 {
		b, err := json.Marshal(a.Ranges)
		if err == nil {
			ranges = string(b)
		}
	}
	key := strings.ToLower(strings.Join([]string{
		a.Source, a.Vendor, a.Product, a.Ecosystem, a.PURL, a.Status, a.DefaultState,
		strings.Join(a.CPEs, ","), strings.Join(a.Versions, ","), ranges,
	}, "|"))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// PickPrimarySeverity chooses which of the competing scores to surface.
//
// A statement that actually carries a number always beats one that does not.
// That ordering is not cosmetic: OSV and GHSA publish CVSS v4.0 as a vector
// with no number, and v4.0 cannot be recomputed from the vector without the
// official MacroVector table. Ranking purely by CVSS version therefore elected
// the unscored v4.0 statement and published score NULL / rating NONE for
// records that also carried a scored 9.8 v3.1 statement — which silently
// removed them from every `rating=CRITICAL` and `score_min=` query.
//
// Among statements that are equally scored (or equally unscored), the newer
// CVSS version wins, and among equal versions the more authoritative source
// wins. This is the query-time answer to NVD no longer scoring every CVE.
func PickPrimarySeverity(sevs []model.Severity) *model.Severity {
	best := -1
	for i := range sevs {
		if sevs[i].Score <= 0 && sevs[i].Vector == "" {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		bScored, cScored := sevs[best].Score > 0, sevs[i].Score > 0
		if bScored != cScored {
			if cScored {
				best = i
			}
			continue
		}
		bi, ci := severityTypeRank(sevs[best].Type), severityTypeRank(sevs[i].Type)
		switch {
		case ci < bi:
			best = i
		case ci == bi:
			if rankOf(sevs[i].Source) < rankOf(sevs[best].Source) {
				best = i
			}
		}
	}
	if best < 0 {
		return nil
	}
	out := sevs[best]
	return &out
}

// severityTypeRank orders scoring systems, newest CVSS first. A type this code
// does not know — SSVC, a vendor's own scale, a typo upstream — sorts below all
// of them: a map lookup's zero default would have tied it with CVSS v4.0, so an
// unrecognised statement could displace a real CVSS score as the primary.
func severityTypeRank(t string) int {
	switch t {
	case "CVSS_V4_0":
		return 0
	case "CVSS_V3_1":
		return 1
	case "CVSS_V3_0":
		return 2
	case "CVSS_V2":
		return 3
	case "OTHER":
		return 4
	default:
		return 5
	}
}

// Document is the stored form of a vulnerability: the canonical record plus
// the bookkeeping the merge needs and the model has no place for. It is what
// the doc column holds; readers that only want the record decode the same
// bytes into model.Vulnerability and never see the extra keys.
type Document struct {
	model.Vulnerability

	// Contributions is what the document remembers about each upstream record
	// that was merged into it, keyed by contributionKey: the newest Modified
	// seen from that record, and which child rows it supplied last time.
	//
	// The Modified is what the stale-snapshot guard compares an incoming
	// record against — not Vulnerability.Modified, which is the newest across
	// all sources. OSV refreshes its modified stamp so often that a CNA
	// update from March was thrown away as "older" than an OSV touch from
	// June, freezing the CNA view of the record. It is kept per record rather
	// than per source because CSAF publishes several advisories per CVE, each
	// with its own date, and an older advisory is not a stale copy of a newer
	// one.
	//
	// The child keys are what lets the statements a record no longer makes be
	// retired when it comes round again — NVD narrowing a CPE configuration
	// used to leave the old statement in place forever — without touching
	// what other records of the same source contributed.
	Contributions map[string]Contribution `json:"contributions,omitempty"`

	// WithdrawnBy is the contribution key (see contributionKey) of the upstream
	// record that set Withdrawn. Only that record can clear it again, by
	// coming round without the field, and only a source ranked at least as
	// high can replace it.
	//
	// It names a record rather than a source because one source feeds one
	// vulnerability through several records: OSV carries a withdrawn GHSA-x
	// beside a live PYSEC-y for the same CVE. Keyed on the source, PYSEC's
	// arrival cleared what GHSA had set and GHSA's set it again, so the value
	// flipped with ingest order and the document's hash — and its history —
	// moved on every run for a record nothing upstream had touched.
	WithdrawnBy string `json:"withdrawn_by,omitempty"`

	// WithdrawnSource is the field WithdrawnBy replaced: the source alone.
	// Documents written before the change still carry it. adoptLegacyWithdrawal
	// reads it as a source-only key — which record set it is unknown, so any
	// record of that source may clear it — and it is never written again.
	WithdrawnSource string `json:"withdrawn_source,omitempty"`
}

// Contribution is what one upstream record last supplied: when it was modified
// and the keys of the child rows it carried.
type Contribution struct {
	Modified   *time.Time `json:"modified,omitempty"`
	Severities []string   `json:"severities,omitempty"`
	References []string   `json:"references,omitempty"`
	Affected   []string   `json:"affected,omitempty"`
}

// contributionKey identifies an upstream record within the merged document.
// The record id is part of it because one source can feed one vulnerability
// through several records.
func contributionKey(v *model.Vulnerability) string {
	id := v.SourceRecordID
	if id == "" {
		id = v.ID
	}
	return v.Source + "\x00" + id
}

// sourceOnlyKey is the contribution key of a record whose id is not known: a
// legacy document's withdrawal is attributed to one, because the document
// recorded the source and nothing more.
func sourceOnlyKey(source string) string { return source + "\x00" }

// keySource is the source half of a contribution key.
func keySource(key string) string {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i]
	}
	return key
}

// recordMatchesKey reports whether in is the record key names. A source-only
// key names every record of that source: which one set the value was never
// recorded, and refusing them all would leave the value uncancellable.
func recordMatchesKey(key string, in *model.Vulnerability) bool {
	if key == "" || in.Source == "" {
		return false
	}
	if key == contributionKey(in) {
		return true
	}
	src := keySource(key)
	return key == sourceOnlyKey(src) && in.Source == src
}

func severityKey(s model.Severity) string   { return s.Type + "|" + s.Provider + "|" + s.Source }
func referenceKey(r model.Reference) string { return r.URL + "|" + r.Source }

func contributionOf(v *model.Vulnerability) Contribution {
	var c Contribution
	for _, s := range v.Severities {
		c.Severities = append(c.Severities, severityKey(s))
	}
	for _, r := range v.References {
		c.References = append(c.References, referenceKey(r))
	}
	for _, a := range v.Affected {
		c.Affected = append(c.Affected, affectedFingerprint(a))
	}
	return c
}

// Merge folds an incoming record into the existing document using source
// precedence. Exported so the merge rules can be unit-tested without a
// database; Merge(nil, in) is how a document is born.
func Merge(existing *Document, in *model.Vulnerability) *Document {
	return merge(existing, &Document{Vulnerability: *in}, false)
}

// merge is Merge for both callers. With fold set, in is a document that was
// until now a separate record of its own — the two are being collapsed because
// an alias edge tied them together — so nothing in it is a stale snapshot of
// anything in existing and nothing it says retires anything: both were live
// records a moment ago, and their children are unioned.
func merge(existing, in *Document, fold bool) *Document {
	if existing == nil {
		out := *in
		out.Severities = append([]model.Severity{}, in.Severities...)
		out.References = append([]model.Reference{}, in.References...)
		out.Affected = append([]model.Affected{}, in.Affected...)
		out.Aliases = normalizeIDs(in.Aliases)
		out.Related = normalizeIDs(in.Related)
		out.Contributions = copyContributions(in.Contributions)
		if out.Withdrawn != nil && out.WithdrawnBy == "" {
			out.WithdrawnBy = withdrawnKeyOf(in, fold)
		}
		out.WithdrawnSource = ""
		if !fold {
			out.noteRecord(in)
		}
		return &out
	}
	out := *existing
	// The map is mutated below; the caller's document must not be.
	out.Contributions = copyContributions(existing.Contributions)
	out.adoptLegacyWithdrawal()
	if !fold {
		out.adoptLegacyRecord(in)
	}
	inRank, exRank := rankOf(in.Source), rankOf(existing.Source)

	// Version guard. Re-ingesting an older snapshot of the SAME record must not
	// roll a record back: a bulk archive is a point-in-time copy, so a backfill
	// run after a delta run routinely carries staler content for the same
	// source. The comparison is against that upstream record's own last
	// Modified, never the cross-source newest. Cross-source merges are
	// unaffected — different upstreams legitimately carry different
	// modification times for the same flaw, and precedence, not recency,
	// decides those. A record the document has no entry for — one written
	// before contributions were tracked — was given one by adoptLegacyRecord
	// just above, carrying the document's own Modified when the record is of
	// the document's source, so the guard holds on the first re-merge too.
	if !fold && in.Source != "" && in.Modified != nil {
		prev, ok := out.Contributions[contributionKey(&in.Vulnerability)]
		if ok && prev.Modified != nil && in.Modified.Before(*prev.Modified) {
			out.Aliases = normalizeIDs(append(out.Aliases, in.Aliases...))
			out.Related = normalizeIDs(append(out.Related, in.Related...))
			if in.FetchedAt.After(out.FetchedAt) {
				out.FetchedAt = in.FetchedAt
			}
			return &out
		}
	}

	if !fold {
		out.retire(in)
	}

	// Scalar text fields: a more authoritative source overwrites, a less
	// authoritative one only fills gaps.
	if in.Title != "" && (out.Title == "" || inRank <= exRank) {
		out.Title = in.Title
	}
	if in.Description != "" && (out.Description == "" || inRank <= exRank) {
		out.Description = in.Description
	}
	if in.AssignerShortName != "" && (out.AssignerShortName == "" || inRank <= exRank) {
		out.AssignerShortName = in.AssignerShortName
	}
	if in.State != "" && (out.State == "" || inRank <= exRank) {
		out.State = in.State
	}
	if in.Source != "" && inRank < exRank {
		out.Source = in.Source
		out.SourceRecordID = in.SourceRecordID
	}

	// Dates: earliest publication, latest modification. Upstreams disagree on
	// publication date routinely; the earliest is the one that is defensible.
	if in.Published != nil && (out.Published == nil || in.Published.Before(*out.Published)) {
		out.Published = in.Published
	}
	if in.Modified != nil && (out.Modified == nil || in.Modified.After(*out.Modified)) {
		out.Modified = in.Modified
	}

	// Withdrawn is an assertion, and its absence is not one: the CVE List has
	// no such field, so a CNA update saying nothing about withdrawal must not
	// clear what OSV said. The record that set it can retract it by coming
	// round without the field — and only that record: another record of the
	// same source saying nothing is not a retraction, or OSV's live PYSEC
	// entry would cancel its withdrawn GHSA entry on every other run. A source
	// ranked at least as high can replace it; anyone can fill the gap.
	withdrawnBy := withdrawnKeyOf(in, fold)
	switch {
	case in.Withdrawn != nil:
		if out.Withdrawn == nil || rankOf(keySource(withdrawnBy)) <= rankOf(keySource(out.WithdrawnBy)) {
			out.Withdrawn = in.Withdrawn
			out.WithdrawnBy = withdrawnBy
		}
	case !fold && out.Withdrawn != nil && recordMatchesKey(out.WithdrawnBy, &in.Vulnerability):
		out.Withdrawn = nil
		out.WithdrawnBy = ""
	}

	out.Aliases = normalizeIDs(append(out.Aliases, in.Aliases...))
	out.Related = normalizeIDs(append(out.Related, in.Related...))
	out.CWEs = model.DedupeStrings(append(out.CWEs, in.CWEs...))
	out.Tags = model.DedupeStrings(append(out.Tags, in.Tags...))

	// Only NVD and its mirror have an enrichment status to report.
	if in.EnrichmentStatus != "" {
		out.EnrichmentStatus = in.EnrichmentStatus
	}

	out.Severities = mergeSeverities(out.Severities, in.Severities)
	out.References = mergeReferences(out.References, in.References)
	out.Affected = mergeAffected(out.Affected, in.Affected)

	if in.SSVC != nil && (out.SSVC == nil || inRank <= exRank) {
		out.SSVC = in.SSVC
	}
	if in.FetchedAt.After(out.FetchedAt) {
		out.FetchedAt = in.FetchedAt
	}
	if len(in.Raw) > 0 && inRank <= exRank {
		out.Raw = in.Raw
	}

	// Bookkeeping. A folded document brings its own map, which is unioned:
	// newest Modified per record, every contributed key kept. A fresh record
	// registers itself.
	for key, c := range in.Contributions {
		out.setContribution(key, unionContribution(out.Contributions[key], c))
	}
	if !fold {
		out.noteRecord(in)
	}
	return &out
}

// noteRecord registers an incoming record's Modified and the child rows it
// supplied, so the next arrival of the same record can be judged against them.
func (d *Document) noteRecord(in *Document) {
	if in.Source == "" {
		return
	}
	c := contributionOf(&in.Vulnerability)
	if in.Modified != nil {
		t := *in.Modified
		c.Modified = &t
	}
	d.setContribution(contributionKey(&in.Vulnerability), c)
}

// withdrawnKeyOf is the record an incoming document's withdrawal is attributed
// to. A fresh record is its own; a document being folded brings the key it
// already holds, or — written before keys existed — the source it recorded,
// which is all that is known about the record.
func withdrawnKeyOf(in *Document, fold bool) string {
	if in.WithdrawnBy != "" {
		return in.WithdrawnBy
	}
	if fold {
		if in.WithdrawnSource != "" {
			return sourceOnlyKey(in.WithdrawnSource)
		}
		return sourceOnlyKey(in.Source)
	}
	return contributionKey(&in.Vulnerability)
}

// adoptLegacyWithdrawal attributes a withdrawal that a document written before
// WithdrawnBy existed carries without saying who set it.
//
// The old field held the source alone; older documents still held nothing.
// Either way the record is unknown, so the withdrawal is attributed to a
// source-only key — the withdrawing source, or failing that the document's own
// — and any record of that source coming round without the field clears it.
// That is the most a legacy document can support: refusing to guess left such
// a withdrawal set forever, which is worse than letting the source that most
// plausibly set it retract it.
func (d *Document) adoptLegacyWithdrawal() {
	if d.Withdrawn != nil && d.WithdrawnBy == "" {
		src := d.WithdrawnSource
		if src == "" {
			src = d.Source
		}
		if src != "" {
			d.WithdrawnBy = sourceOnlyKey(src)
		}
	}
	d.WithdrawnSource = ""
}

// adoptLegacyRecord gives an incoming record a contribution entry when the
// document holds its source's children without any record of that source
// having been tracked, built from what the document already holds.
//
// A document written before contributions were tracked knows what it carries
// but not which record carried it. Treating the record as never seen had two
// costs on its first re-merge: the stale guard had nothing to compare against,
// so an older snapshot of the same source — a backfill after a delta —
// overwrote newer text while Modified stayed newer; and retire had nothing to
// retire, so every child the legacy document held for that source survived
// forever, however narrow the record had since become.
//
// The entry is built the way the document was: its Modified is the guard when
// the record is of the document's own source, which was the rule before
// contributions existed; and the record is held to have made every child of
// its source that no tracked contribution claims, so the ones it no longer
// makes retire with it. That attribution is a guess where a source publishes
// several records per vulnerability — CSAF's advisories — and the guess costs
// a sibling advisory's statements until it comes round again, which it does on
// every run; the alternative was a corpus in which nothing an old document
// held could ever be withdrawn.
//
// It applies only while the source is untracked. Once any record of the
// source has an entry, the document is no longer legacy for that source, and
// a further record of it is what it looks like: a new advisory, which owes
// nothing to the document's Modified and inherits nothing from its siblings.
func (d *Document) adoptLegacyRecord(in *Document) {
	if in.Source == "" {
		return
	}
	key := contributionKey(&in.Vulnerability)
	if _, ok := d.Contributions[key]; ok {
		return
	}
	for other := range d.Contributions {
		if keySource(other) == in.Source {
			return
		}
	}
	var c Contribution
	if in.Source == d.Source && d.Modified != nil {
		t := *d.Modified
		c.Modified = &t
	}
	claimed := d.claimedExcept(key)
	for _, s := range d.Severities {
		if k := severityKey(s); s.Source == in.Source && !claimed[k] {
			c.Severities = append(c.Severities, k)
		}
	}
	for _, r := range d.References {
		if k := referenceKey(r); r.Source == in.Source && !claimed[k] {
			c.References = append(c.References, k)
		}
	}
	for _, a := range d.Affected {
		if k := affectedFingerprint(a); a.Source == in.Source && !claimed[k] {
			c.Affected = append(c.Affected, k)
		}
	}
	d.setContribution(key, c)
}

// claimedExcept is every child key some contribution other than key still
// claims.
func (d *Document) claimedExcept(key string) map[string]bool {
	claimed := map[string]bool{}
	for other, c := range d.Contributions {
		if other == key {
			continue
		}
		for _, list := range [][]string{c.Severities, c.References, c.Affected} {
			for _, k := range list {
				claimed[k] = true
			}
		}
	}
	return claimed
}

// retire drops the children that the incoming upstream record supplied last
// time and that no other record still claims, so that what the record says now
// is all it says. A record never seen before has nothing to retire; a document
// written before contributions were tracked was given an entry for the record
// by adoptLegacyRecord before this runs.
func (d *Document) retire(in *Document) {
	key := contributionKey(&in.Vulnerability)
	prev, ok := d.Contributions[key]
	if !ok {
		return
	}
	claimed := d.claimedExcept(key)
	retired := func(keys []string) map[string]struct{} {
		set := make(map[string]struct{}, len(keys))
		for _, k := range keys {
			if !claimed[k] {
				set[k] = struct{}{}
			}
		}
		return set
	}
	if drop := retired(prev.Severities); len(drop) > 0 {
		kept := d.Severities[:0:0]
		for _, s := range d.Severities {
			if _, gone := drop[severityKey(s)]; !gone {
				kept = append(kept, s)
			}
		}
		d.Severities = kept
	}
	if drop := retired(prev.References); len(drop) > 0 {
		kept := d.References[:0:0]
		for _, r := range d.References {
			if _, gone := drop[referenceKey(r)]; !gone {
				kept = append(kept, r)
			}
		}
		d.References = kept
	}
	if drop := retired(prev.Affected); len(drop) > 0 {
		kept := d.Affected[:0:0]
		for _, a := range d.Affected {
			if _, gone := drop[affectedFingerprint(a)]; !gone {
				kept = append(kept, a)
			}
		}
		d.Affected = kept
	}
}

func (d *Document) setContribution(key string, c Contribution) {
	if d.Contributions == nil {
		d.Contributions = map[string]Contribution{}
	}
	d.Contributions[key] = c
}

func unionContribution(a, b Contribution) Contribution {
	modified := a.Modified
	if b.Modified != nil && (modified == nil || b.Modified.After(*modified)) {
		modified = b.Modified
	}
	return Contribution{
		Modified:   modified,
		Severities: model.DedupeStrings(append(append([]string{}, a.Severities...), b.Severities...)),
		References: model.DedupeStrings(append(append([]string{}, a.References...), b.References...)),
		Affected:   model.DedupeStrings(append(append([]string{}, a.Affected...), b.Affected...)),
	}
}

func copyContributions(m map[string]Contribution) map[string]Contribution {
	if m == nil {
		return nil
	}
	out := make(map[string]Contribution, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mergeSeverities(a, b []model.Severity) []model.Severity {
	idx := map[string]int{}
	out := make([]model.Severity, 0, len(a)+len(b))
	for _, list := range [][]model.Severity{a, b} {
		for _, s := range list {
			key := s.Type + "|" + s.Provider + "|" + s.Source
			if i, ok := idx[key]; ok {
				out[i] = s
				continue
			}
			idx[key] = len(out)
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rankOf(out[i].Source) < rankOf(out[j].Source) })
	return out
}

func mergeReferences(a, b []model.Reference) []model.Reference {
	idx := map[string]int{}
	out := make([]model.Reference, 0, len(a)+len(b))
	for _, list := range [][]model.Reference{a, b} {
		for _, r := range list {
			key := r.URL + "|" + r.Source
			if i, ok := idx[key]; ok {
				out[i] = r
				continue
			}
			idx[key] = len(out)
			out = append(out, r)
		}
	}
	return out
}

func mergeAffected(a, b []model.Affected) []model.Affected {
	idx := map[string]int{}
	out := make([]model.Affected, 0, len(a)+len(b))
	for _, list := range [][]model.Affected{a, b} {
		for _, af := range list {
			key := affectedFingerprint(af)
			if i, ok := idx[key]; ok {
				out[i] = af
				continue
			}
			idx[key] = len(out)
			out = append(out, af)
		}
	}
	return out
}

// normalizeIDs is DedupeStrings for identifier lists: every entry is spelled
// canonically first. Publishers do write "cve-2024-1234", and the resolver
// normalises what it looks up, so a document that kept the raw spelling next
// to the canonical one listed the same alias twice and wrote both spellings
// into vuln_aliases.
func normalizeIDs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, id := range in {
		out = append(out, model.NormalizeID(id))
	}
	return model.DedupeStrings(out)
}

func removeString(list []string, drop string) []string {
	out := list[:0]
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

// writeChildren makes the severity, reference and affected tables agree with
// the document: rows the document no longer carries are deleted, the rest are
// upserted using set-returning parameters. Each slice is already de-duplicated
// by its merge function, so no row can conflict with another row in the same
// batch — which ON CONFLICT would otherwise reject outright.
//
// The document is the truth and the tables are derived from it. Before the
// reconcile, a statement an upstream had withdrawn was retired from the
// document but its row stayed in vuln_affected, where the scanner reads, so a
// narrowed NVD configuration kept matching what it no longer named.
func writeChildren(ctx context.Context, tx *sql.Tx, v *Document) error {
	// Upstreams do repeat the same reference URL or metric inside a single
	// record, and a batched ON CONFLICT rejects a batch that touches one row
	// twice. Deduplicate on the conflict key here rather than trusting callers.
	severities := dedupeBy(v.Severities, severityKey)
	references := dedupeBy(v.References, referenceKey)
	affected := dedupeBy(v.Affected, affectedFingerprint)

	// Stale rows first, so that an empty slice below clears the table for this
	// record rather than leaving whatever was there. The key sets are matched
	// through a hashed subselect: `<> ALL(array)` compares every row against
	// every key, and NVD records carry thousands of statements.
	keep := contributionOf(&v.Vulnerability)
	for _, st := range []struct {
		what, sql string
		keys      []string
	}{
		{"severities", `DELETE FROM vuln_severity
		     WHERE vuln_id = $1 AND (type || '|' || provider || '|' || source) NOT IN (SELECT unnest($2::text[]))`, keep.Severities},
		{"references", `DELETE FROM vuln_reference
		     WHERE vuln_id = $1 AND (url || '|' || source) NOT IN (SELECT unnest($2::text[]))`, keep.References},
		{"affected", `DELETE FROM vuln_affected
		     WHERE vuln_id = $1 AND fingerprint NOT IN (SELECT unnest($2::text[]))`, keep.Affected},
	} {
		if _, err := tx.ExecContext(ctx, st.sql, v.ID, strArray(cleanTexts(st.keys))); err != nil {
			return fmt.Errorf("store: retire %s %s: %w", st.what, v.ID, err)
		}
	}

	if len(severities) > 0 {
		payload, err := cleanJSON(json.Marshal(severities))
		if err != nil {
			return fmt.Errorf("store: encode severities %s: %w", v.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO vuln_severity (vuln_id, type, provider, source, score, vector, rating)
            SELECT $1, r.type, COALESCE(r.provider,''), r.source,
                   NULLIF(r.score, 0), NULLIF(r.vector,''), NULLIF(r.rating,'')
              FROM jsonb_to_recordset($2::jsonb)
                AS r(type text, provider text, source text, score double precision, vector text, rating text)
            ON CONFLICT (vuln_id, type, provider, source) DO UPDATE
                SET score = EXCLUDED.score, vector = EXCLUDED.vector, rating = EXCLUDED.rating`,
			v.ID, string(payload)); err != nil {
			return fmt.Errorf("store: write severities %s: %w", v.ID, err)
		}
	}

	if len(references) > 0 {
		payload, err := cleanJSON(json.Marshal(references))
		if err != nil {
			return fmt.Errorf("store: encode references %s: %w", v.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO vuln_reference (vuln_id, url, source, name, tags)
            SELECT $1, r.url, r.source, NULLIF(r.name,''), COALESCE(r.tags, '{}')
              FROM jsonb_to_recordset($2::jsonb)
                AS r(url text, source text, name text, tags text[])
            ON CONFLICT (vuln_id, url, source) DO UPDATE
                SET name = EXCLUDED.name, tags = EXCLUDED.tags`,
			v.ID, string(payload)); err != nil {
			return fmt.Errorf("store: write references %s: %w", v.ID, err)
		}
	}

	if len(affected) > 0 {
		type affectedRow struct {
			model.Affected
			Fingerprint string `json:"fingerprint"`
		}
		rows := make([]affectedRow, 0, len(affected))
		for _, af := range affected {
			if af.CPEs == nil {
				af.CPEs = []string{}
			}
			if af.Versions == nil {
				af.Versions = []string{}
			}
			if af.Ranges == nil {
				af.Ranges = []model.VersionRange{}
			}
			rows = append(rows, affectedRow{Affected: af, Fingerprint: affectedFingerprint(af)})
		}
		payload, err := cleanJSON(json.Marshal(rows))
		if err != nil {
			return fmt.Errorf("store: encode affected %s: %w", v.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO vuln_affected (vuln_id, fingerprint, vendor, product, ecosystem, purl, cpes, versions, ranges, status, default_state, source)
            SELECT $1, r.fingerprint, NULLIF(r.vendor,''), NULLIF(r.product,''),
                   NULLIF(r.ecosystem,''), NULLIF(r.purl,''),
                   COALESCE(r.cpes,'{}'), COALESCE(r.versions,'{}'),
                   COALESCE(r.ranges,'[]'::jsonb), NULLIF(r.status,''), NULLIF(r.default_state,''), r.source
              FROM jsonb_to_recordset($2::jsonb)
                AS r(fingerprint text, vendor text, product text, ecosystem text,
                     purl text, cpes text[], versions text[], ranges jsonb, status text,
                     default_state text, source text)
            ON CONFLICT (vuln_id, fingerprint) DO UPDATE SET
                vendor = EXCLUDED.vendor, product = EXCLUDED.product,
                ecosystem = EXCLUDED.ecosystem, purl = EXCLUDED.purl,
                cpes = EXCLUDED.cpes, versions = EXCLUDED.versions,
                ranges = EXCLUDED.ranges, status = EXCLUDED.status,
                default_state = EXCLUDED.default_state, source = EXCLUDED.source`,
			v.ID, string(payload)); err != nil {
			return fmt.Errorf("store: write affected %s: %w", v.ID, err)
		}
	}
	return nil
}

// dedupeBy keeps the last occurrence of each key, matching the semantics of the
// DO UPDATE clause the batch would otherwise have applied row by row.
func dedupeBy[T any](in []T, key func(T) string) []T {
	if len(in) < 2 {
		return in
	}
	idx := make(map[string]int, len(in))
	out := make([]T, 0, len(in))
	for _, item := range in {
		k := key(item)
		if i, ok := idx[k]; ok {
			out[i] = item
			continue
		}
		idx[k] = len(out)
		out = append(out, item)
	}
	return out
}

// strArray guards every text[] parameter. A nil Go slice marshals to SQL NULL,
// which every one of these columns rejects as NOT NULL — and because the upsert
// is best-effort per record, that failure mode silently drops records rather
// than surfacing. Empty array is the correct representation of "none".
func strArray(in []string) any {
	if in == nil {
		return pq.Array([]string{})
	}
	return pq.Array(in)
}

// cleanText drops NUL bytes from a value bound for a text column. JSON
// carries "\u0000" happily and Go strings carry it too, but PostgreSQL's
// text type rejects the byte and jsonb rejects the escape, so one such
// character anywhere in a record failed the whole upsert — silently, because
// the sink is best-effort per record. The document itself is bytea and keeps
// the original; only the derived columns are scrubbed.
func cleanText(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func cleanTexts(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cleanText(s)
	}
	return out
}

// cleanJSON is cleanText for an encoded value bound for a jsonb column. It
// only re-encodes when the escape is present at all; the values that reach
// it are encoded structs, whose keys are field names, so nothing that must
// keep a NUL passes through here.
func cleanJSON(payload []byte, err error) ([]byte, error) {
	if err != nil || !bytes.Contains(payload, []byte(`\u0000`)) {
		return payload, err
	}
	var tree any
	if err := json.Unmarshal(payload, &tree); err != nil {
		return nil, err
	}
	return json.Marshal(stripNUL(tree))
}

func stripNUL(n any) any {
	switch x := n.(type) {
	case string:
		return cleanText(x)
	case []any:
		for i := range x {
			x[i] = stripNUL(x[i])
		}
		return x
	case map[string]any:
		for k, v := range x {
			x[k] = stripNUL(v)
		}
		return x
	}
	return n
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
