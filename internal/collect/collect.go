// Package collect holds the source adapters and the machinery that drives them.
//
// Every adapter implements Collector and reaches the network only through the
// httpx.Fetcher it is handed. That is what lets the identical adapter run on an
// internet-connected harvester and inside an isolated network against a bundle.
package collect

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/00gxd14g/cvefeed/internal/config"
	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// Mode selects between a full historical load and an incremental update.
type Mode string

const (
	// ModeBackfill loads the complete history from bulk artefacts.
	ModeBackfill Mode = "backfill"
	// ModeDelta loads only what changed since the persisted cursor.
	ModeDelta Mode = "delta"
)

// Sink receives normalised records.
type Sink interface {
	Vulnerability(ctx context.Context, v *model.Vulnerability) error
	// KEV adds or refreshes catalogue entries; rows it does not mention are
	// left alone. It is the right call for a partial view — EUVD's exploited
	// flags, a consolidated dump that mirrors other catalogues.
	KEV(ctx context.Context, entries []model.KEV) error
	// KEVCatalogue stores a complete catalogue: entries is everything the
	// upstream lists today, so an entry this load does not mention has been
	// withdrawn, and its row and the flag it put on the vulnerability go with
	// it. Only the collector that owns a catalogue may call this.
	KEVCatalogue(ctx context.Context, entries []model.KEV) error
	EPSS(ctx context.Context, scores []model.EPSS) error
}

// Run carries everything a collector needs for one execution.
type Run struct {
	Mode    Mode
	Fetcher httpx.Fetcher
	Sink    Sink
	Cfg     *config.Config
	Log     *slog.Logger

	// Cursor is the collector's persisted state. Adapters read and write it
	// freely; the runner persists safe progress after collector errors. If the
	// asynchronous store loses one of the records it accepted, the runner holds
	// the cursor at this run's starting point so the missing record is retried.
	Cursor map[string]string

	seen atomic.Int64
}

// Emit forwards a record to the sink and counts it.
func (r *Run) Emit(ctx context.Context, v *model.Vulnerability) error {
	if v == nil || v.ID == "" {
		return nil
	}
	if v.FetchedAt.IsZero() {
		v.FetchedAt = time.Now().UTC()
	}
	dropFutureTimestamps(v, v.FetchedAt, r.Log)
	if err := r.Sink.Vulnerability(ctx, v); err != nil {
		return err
	}
	r.seen.Add(1)
	return nil
}

// futureSlack is how far past this host's clock an upstream timestamp may sit
// before it is corrupt rather than skewed. Skew between two well-run clocks is
// seconds; a day also covers a feed that prints local time without a zone.
const futureSlack = 24 * time.Hour

// dropFutureTimestamps clears a record's timestamps that lie in the future.
//
// They are upstream typos, and they are not harmless ones. The PyPA advisory
// database published PYSEC-2025-19 with modified 2027-07-09; vulnerability-
// lookup republished it verbatim, the store folded it into CVE-2025-1889 and
// took it as the record's modified, and its per-record stale guard then
// rejected every genuine update of that record as older — for a year. A
// watermark derived from the data would have been pushed past everything
// that follows it. An absent timestamp is merely unknown; a future one is a
// claim that poisons whatever compares against it.
func dropFutureTimestamps(v *model.Vulnerability, now time.Time, log *slog.Logger) {
	limit := now.Add(futureSlack)
	for _, f := range []struct {
		name string
		at   **time.Time
	}{
		{"modified", &v.Modified},
		{"published", &v.Published},
		{"withdrawn", &v.Withdrawn},
	} {
		if *f.at == nil || !(*f.at).After(limit) {
			continue
		}
		if log != nil {
			log.Warn("upstream timestamp is in the future; dropped",
				"id", v.ID, "source", v.Source, "record", v.SourceRecordID,
				"field", f.name, "value", (*f.at).Format(time.RFC3339))
		}
		*f.at = nil
	}
}

// Seen reports how many records this run emitted.
func (r *Run) Seen() int64 { return r.seen.Load() }

// AddSeen records non-vulnerability emissions (KEV rows, EPSS scores).
func (r *Run) AddSeen(n int64) { r.seen.Add(n) }

// Collector is one upstream adapter.
type Collector interface {
	Name() string
	Run(ctx context.Context, r *Run) error
}

// Registry maps collector names to implementations.
type Registry map[string]Collector

// NewRegistry builds the full set of collectors.
func NewRegistry(cfg *config.Config) Registry {
	reg := Registry{}
	for _, c := range []Collector{
		&CVEListCollector{},
		&NVDCollector{},
		&FKIECollector{},
		&VulnrichmentCollector{},
		&OSVCollector{},
		&GHSACollector{},
		&EUVDCollector{},
		&GCVECollector{BaseURL: cfg.VulnLookupURL},
		&CSAFCollector{Providers: cfg.CSAFProviders},
		&KEVCollector{},
		&EPSSCollector{},
	} {
		reg[c.Name()] = c
	}
	return reg
}

// StoreSink persists collector output through a bounded worker pool.
//
// Each record costs a transaction with several round trips. Doing that serially
// caps ingest at a few hundred records a second regardless of how fast the
// upstream delivers, which is hopeless for a 300,000-record backfill. The work
// is embarrassingly parallel — separate rows, separate transactions — so a
// small pool turns database latency into throughput.
type StoreSink struct {
	Store   *store.Store
	Log     *slog.Logger
	Workers int // defaults to 8
	// QueueDepth bounds how many parsed records may wait for the database.
	// It is the backpressure valve between a fast bulk reader and a
	// transaction-bound writer; defaults to 2048.
	QueueDepth int

	// SkipUnchanged short-circuits the merge when the raw document is byte
	// identical to what is already stored. On a full bulk re-ingest this turns
	// hundreds of thousands of transactions into hundreds of cheap hash checks.
	SkipUnchanged bool

	Unchanged atomic.Int64
	Written   atomic.Int64
	Failed    atomic.Int64

	once     sync.Once
	queue    chan *model.Vulnerability
	inflight sync.WaitGroup
	workers  sync.WaitGroup

	// mu orders Close against Vulnerability. The closed flag and the in-flight
	// count used to be independent atomics, which left a window between "is
	// the sink closed?" and "count me as in flight" in which Close could see
	// zero in-flight sends, close the queue, and have the caller then send on
	// a closed channel — a panic that takes the whole ingest down with it.
	mu     sync.Mutex
	closed bool

	// persistFn is what a worker calls per record. It is persist unless a test
	// that has no database substitutes its own.
	persistFn func(ctx context.Context, v *model.Vulnerability)
}

func (s *StoreSink) start() {
	s.once.Do(func() {
		n := s.Workers
		if n <= 0 {
			n = 8
		}
		depth := s.QueueDepth
		if depth <= 0 {
			depth = 2048
		}
		if s.persistFn == nil {
			s.persistFn = s.persist
		}
		s.queue = make(chan *model.Vulnerability, depth)
		for i := 0; i < n; i++ {
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				for v := range s.queue {
					s.persistFn(context.Background(), v)
					s.inflight.Done()
				}
			}()
		}
	})
}

// persistAttempts bounds how often a lock-timed-out upsert is retried, and
// persistRetryDelay is the wait before the first retry (the next waits twice
// as long, and so on).
const (
	persistAttempts   = 4
	persistRetryDelay = 3 * time.Second
)

// persist writes one record. The raw document is stored only after the merge
// has committed: recording the content hash first would mark a record as
// "already ingested" even though its upsert failed, and SkipUnchanged would
// then skip it on every subsequent run — a transient database error would
// become permanent data loss.
func (s *StoreSink) persist(ctx context.Context, v *model.Vulnerability) {
	if len(v.Raw) > 0 && s.SkipUnchanged {
		changed, err := s.Store.RawChanged(ctx, v.Source, v.SourceRecordID, v.Raw)
		if err != nil {
			s.Failed.Add(1)
			s.Log.Warn("raw comparison failed", "id", v.ID, "source", v.Source, "error", err)
			return
		}
		if !changed {
			s.Unchanged.Add(1)
			return
		}
	}
	var err error
	for attempt := 1; ; attempt++ {
		_, err = s.Store.UpsertVulnerability(ctx, v)
		// A lock timeout is another writer holding the same identifiers, not
		// a fault in this record. Two of them in a five-hour OSV walk used to
		// fail the whole run and hold its cursor at the start, so the next
		// run re-read every record to reach the two. Wait and try again.
		if err == nil || !store.IsLockTimeout(err) || attempt >= persistAttempts || ctx.Err() != nil {
			break
		}
		s.Log.Warn("upsert waiting on a lock; retrying", "id", v.ID, "source", v.Source, "attempt", attempt)
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt) * persistRetryDelay):
		}
	}
	if err != nil {
		// One malformed record must not abort an ingest of 300,000. Log it,
		// count it and carry on. RunOne observes the failure after Drain and
		// holds the cursor so the record is offered again on the next run.
		s.Failed.Add(1)
		s.Log.Warn("upsert failed", "id", v.ID, "source", v.Source, "error", err)
		return
	}
	if len(v.Raw) > 0 {
		if _, err := s.Store.SaveRaw(ctx, v.Source, v.SourceRecordID, v.Raw); err != nil {
			s.Log.Warn("raw save failed", "id", v.ID, "source", v.Source, "error", err)
		}
	}
	s.Written.Add(1)
}

// Vulnerability enqueues a record for persistence.
func (s *StoreSink) Vulnerability(ctx context.Context, v *model.Vulnerability) error {
	// The closed check and the in-flight increment happen under one lock so
	// Close cannot slip between them; once inflight counts this send, Close
	// waits for it before closing the queue.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("collect: sink is closed")
	}
	s.start()
	s.inflight.Add(1)
	s.mu.Unlock()
	select {
	case s.queue <- v:
		return nil
	case <-ctx.Done():
		s.inflight.Done()
		return ctx.Err()
	}
}

// Drain blocks until every enqueued record has been persisted. The runner calls
// it before saving a cursor, so it can distinguish a completed queue from one
// containing writes that failed after they had been accepted asynchronously.
func (s *StoreSink) Drain() {
	s.mu.Lock()
	started := s.queue != nil
	s.mu.Unlock()
	if !started {
		return
	}
	s.inflight.Wait()
}

// FailureCount reports the cumulative number of asynchronous persistence
// failures. Runner snapshots it per source so a shared sink can safely be used
// by RunAll without attributing an earlier source's failure to a later one.
func (s *StoreSink) FailureCount() int64 { return s.Failed.Load() }

// Close drains the queue and stops the workers.
func (s *StoreSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	queue := s.queue
	s.mu.Unlock()
	if queue == nil {
		return nil
	}
	// Every send that was counted before closed flipped is drained here, and
	// no new one can be counted, so closing the channel is safe.
	s.inflight.Wait()
	close(queue)
	s.workers.Wait()
	return nil
}

// KEV stores catalogue entries without retiring any.
func (s *StoreSink) KEV(ctx context.Context, entries []model.KEV) error {
	return s.Store.UpsertKEV(ctx, entries)
}

// KEVCatalogue stores a complete catalogue and retires what left it.
func (s *StoreSink) KEVCatalogue(ctx context.Context, entries []model.KEV) error {
	return s.Store.ReplaceKEV(ctx, entries)
}

// EPSS stores exploit prediction scores.
func (s *StoreSink) EPSS(ctx context.Context, scores []model.EPSS) error {
	return s.Store.UpsertEPSS(ctx, scores)
}

// Runner executes collectors and persists their cursors.
type Runner struct {
	Registry Registry
	Store    *store.Store
	Fetcher  httpx.Fetcher
	Cfg      *config.Config
	Log      *slog.Logger
	Sink     Sink

	// ReplayFrom, when set, overrides every time-based cursor value for this
	// run. The research calls for a "replay-from" control because upstreams do
	// ask consumers to re-read a window — NVD did exactly that on 2025-03-11 —
	// and without it an operator has to edit the database by hand.
	ReplayFrom *time.Time
}

// RunOne executes a single named collector.
func (rn *Runner) RunOne(ctx context.Context, name string, mode Mode) error {
	c, ok := rn.Registry[name]
	if !ok {
		return fmt.Errorf("collect: unknown source %q", name)
	}

	rawCursor, err := rn.Store.LoadCursor(ctx, name)
	if err != nil {
		return err
	}
	cursor := map[string]string{}
	if len(rawCursor) > 0 {
		if err := json.Unmarshal(rawCursor, &cursor); err != nil {
			rn.Log.Warn("cursor unreadable, starting clean", "source", name, "error", err)
			cursor = map[string]string{}
		}
	}

	if rn.ReplayFrom != nil {
		replayCursor(cursor, *rn.ReplayFrom)
		rn.Log.Info("replaying from an explicit position",
			"source", name, "since", rn.ReplayFrom.Format(time.RFC3339))
	}

	// A collector mutates its cursor as it walks. Snapshot the effective start
	// after replay rewrites it: if an asynchronous database write later fails,
	// persisting the mutated cursor would permanently step over that record.
	cursorAtStart := cloneCursor(cursor)
	failedBefore := failureCount(rn.Sink)

	run := &Run{
		Mode:    mode,
		Fetcher: rn.Fetcher,
		Sink:    rn.Sink,
		Cfg:     rn.Cfg,
		Log:     rn.Log.With("source", name),
		Cursor:  cursor,
	}

	started := time.Now()
	runErr := c.Run(ctx, run)

	// The sink is asynchronous; everything it was handed must be on disk before
	// a cursor is saved. Queue acceptance is not persistence success, so compare
	// the sink's failure counter only after Drain has made the result final.
	if d, ok := rn.Sink.(interface{ Drain() }); ok {
		d.Drain()
	}
	persistenceFailures := failureCount(rn.Sink) - failedBefore
	if persistenceFailures > 0 {
		runErr = errors.Join(runErr, fmt.Errorf(
			"collect: %d record(s) failed to persist; cursor held for retry",
			persistenceFailures))
	}

	// Link whatever was just written to the KEV and EPSS tables. The
	// enrichment loaders skip their work when the upstream has not changed,
	// so without this a record ingested between two catalogue releases would
	// never pick up its exploitation flag or its EPSS score.
	if rn.Store != nil && run.Seen() > 0 {
		syncCtx, cancelSync := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		if err := rn.Store.SyncEnrichment(syncCtx); err != nil {
			rn.Log.Warn("enrichment sync failed", "source", name, "error", err)
		}
		cancelSync()

		// Recompute which CPE vendor the corpus files each product under. The
		// network scanner reads that ranking on every service it identifies,
		// and answering the question directly means unnesting an array across
		// nine million rows — two minutes, which has no business happening
		// while somebody waits for a report. It changes exactly when
		// vuln_affected does, which is here.
		rankCtx, cancelRank := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		if err := rn.Store.RefreshCPEVendorRank(rankCtx); err != nil {
			rn.Log.Warn("cpe vendor rank refresh failed", "source", name, "error", err)
		}
		cancelRank()
	}

	cursorToSave := run.Cursor
	if persistenceFailures > 0 {
		cursorToSave = cursorAtStart
	}
	encoded, encErr := json.Marshal(cursorToSave)
	if encErr != nil {
		encoded = []byte("{}")
	}
	// The cursor is progress that must outlive a cancelled run, so it is saved
	// on a context detached from the shutdown signal.
	saveCtx, cancelSave := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancelSave()
	if saveErr := rn.Store.SaveCursor(saveCtx, name, encoded, run.Seen(), runErr); saveErr != nil {
		rn.Log.Error("cursor not saved", "source", name, "error", saveErr)
	}

	level := slog.LevelInfo
	if runErr != nil {
		level = slog.LevelError
	}
	rn.Log.Log(ctx, level, "collector finished",
		"source", name, "mode", string(mode),
		"records", run.Seen(), "duration", time.Since(started).Round(time.Millisecond),
		"error", runErr)
	return runErr
}

// RunAll executes the named collectors in order, continuing past failures so a
// single unreachable upstream cannot stall the whole refresh.
func (rn *Runner) RunAll(ctx context.Context, names []string, mode Mode) error {
	var errs []error
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rn.RunOne(ctx, name, mode); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// ------------------------------------------------------------------ helpers

// failureCount returns the asynchronous persistence failure counter when the
// sink exposes one. Synchronous/test sinks do not need to implement it.
func failureCount(s Sink) int64 {
	if counter, ok := s.(interface{ FailureCount() int64 }); ok {
		return counter.FailureCount()
	}
	return 0
}

func cloneCursor(cursor map[string]string) map[string]string {
	cloned := make(map[string]string, len(cursor))
	for key, value := range cursor {
		cloned[key] = value
	}
	return cloned
}

// fetchJSON retrieves a URL and decodes it into out.
func fetchJSON(ctx context.Context, f httpx.Fetcher, url string, out any) error {
	return fetchJSONOpts(ctx, f, httpx.Request{URL: url}, out)
}

// fetchJSONOpts is fetchJSON with full control over the request.
func fetchJSONOpts(ctx context.Context, f httpx.Fetcher, req httpx.Request, out any) error {
	resp, err := f.Fetch(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("collect: decode %s: %w", req.URL, err)
	}
	// Decode stops at the closing brace and never reads the EOF that follows
	// it. Reading on lets a recording body see the end of the document on the
	// read path, where a recorder failure can still be reported, rather than
	// leaving it to the drain in Close.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("collect: read %s: %w", req.URL, err)
	}
	return nil
}

// fetchBytes retrieves a URL fully into memory. Use only for small documents.
func fetchBytes(ctx context.Context, f httpx.Fetcher, url string) ([]byte, error) {
	return fetchBytesOpts(ctx, f, httpx.Request{URL: url})
}

// fetchBytesOpts is fetchBytes with full control over the request.
func fetchBytesOpts(ctx context.Context, f httpx.Fetcher, req httpx.Request) ([]byte, error) {
	resp, err := f.Fetch(ctx, req)
	if err != nil {
		return nil, err
	}
	return httpx.ReadAllLimit(resp, 256<<20)
}

// fetchToTemp streams a URL to a temporary file and returns its path. Bulk
// archives run to hundreds of megabytes; buffering them in memory would make
// the ingester's footprint a function of upstream size.
func fetchToTemp(ctx context.Context, f httpx.Fetcher, url, pattern string) (string, error) {
	resp, err := f.Fetch(ctx, httpx.Request{URL: url})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("collect: temp file: %w", err)
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("collect: download %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("collect: close temp: %w", err)
	}
	return tmp.Name(), nil
}

// maxZipNesting bounds how deep walkZipJSON follows archives inside archives.
// The CVE List baseline is one level of nesting; anything deeper is a zip bomb.
const maxZipNesting = 3

// walkZipJSON calls fn for every JSON member of a zip archive whose path passes
// the accept predicate.
//
// Nested archives are descended into. This is not a nicety: the CVE List
// baseline release asset "YYYY-MM-DD_all_CVEs_at_midnight.zip.zip" is an outer
// zip whose only member is cves.zip, so a single-level walk silently ingests
// nothing at all from the most authoritative source in the pipeline.
//
// A member that cannot be read is logged by the caller through onErr and
// skipped. One corrupt entry in an 800,000-file archive must not forfeit the
// whole run.
func walkZipJSON(path string, accept func(name string) bool, fn func(name string, data []byte) error) error {
	return walkZipJSONErr(path, accept, fn, nil)
}

// walkZipJSONErr is walkZipJSON with an explicit per-member error sink.
func walkZipJSONErr(path string, accept func(name string) bool, fn func(name string, data []byte) error, onErr func(name string, err error)) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("collect: open zip %s: %w", path, err)
	}
	defer zr.Close()
	return walkZipEntries(&zr.Reader, path, 0, accept, fn, onErr)
}

func walkZipEntries(zr *zip.Reader, label string, depth int, accept func(name string) bool, fn func(name string, data []byte) error, onErr func(name string, err error)) error {
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		lower := strings.ToLower(f.Name)

		if strings.HasSuffix(lower, ".zip") {
			if depth >= maxZipNesting {
				continue
			}
			// Spilled to disk rather than buffered: the CVE List inner archive
			// is 640 MB, and archive/zip needs an io.ReaderAt anyway.
			inner, cleanup, err := spillZipMember(f)
			if err != nil {
				if onErr != nil {
					onErr(f.Name, err)
					continue
				}
				return fmt.Errorf("collect: extract nested zip %s: %w", f.Name, err)
			}
			err = walkZipEntries(&inner.Reader, label+"!"+f.Name, depth+1, accept, fn, onErr)
			cleanup()
			if err != nil {
				return err
			}
			continue
		}

		if !strings.HasSuffix(lower, ".json") {
			continue
		}
		if accept != nil && !accept(f.Name) {
			continue
		}
		data, err := readZipMember(f)
		if err != nil {
			if onErr != nil {
				onErr(f.Name, err)
				continue
			}
			return fmt.Errorf("collect: read zip member %s: %w", f.Name, err)
		}
		if err := fn(f.Name, data); err != nil {
			return err
		}
	}
	return nil
}

// spillZipMember copies a nested archive to a temporary file and opens it.
func spillZipMember(f *zip.File) (*zip.ReadCloser, func(), error) {
	rc, err := f.Open()
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "cvefeed-nested-*.zip")
	if err != nil {
		return nil, nil, err
	}
	path := tmp.Name()
	cleanup := func() { os.Remove(path) }

	n, err := io.Copy(tmp, io.LimitReader(rc, maxZipMemberBytes+1))
	if err == nil && n > maxZipMemberBytes {
		// A truncated archive is unreadable at best; refusing it makes the
		// caller log and skip it instead of failing on a mystery.
		err = fmt.Errorf("nested archive %s exceeds %d bytes", f.Name, int64(maxZipMemberBytes))
	}
	if err != nil {
		tmp.Close()
		cleanup()
		return nil, nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, nil, err
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return zr, func() { zr.Close(); cleanup() }, nil
}

func readZipMember(f *zip.File) ([]byte, error) {
	return readZipMemberLimit(f, maxJSONMemberBytes)
}

// readZipMemberLimit reads one member whole and refuses one larger than limit.
// A silently truncated document parses as garbage at best and as a plausible
// but wrong record at worst; an error makes the caller log and skip it.
func readZipMemberLimit(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("member %s exceeds %d bytes", f.Name, limit)
	}
	return data, nil
}

// maxZipMemberBytes caps a single archive member. The largest legitimate member
// in this pipeline is a nested archive, which is why this is generous.
const maxZipMemberBytes = 2 << 30

// maxJSONMemberBytes caps one JSON document read into memory. No upstream CVE,
// OSV or CSAF record comes close.
const maxJSONMemberBytes = 64 << 20

// cursorTime reads an RFC3339 timestamp from the cursor. The RFC3339 layout
// accepts a fractional second on input, so values written by setCursorTime
// with nanoseconds and older whole-second values both parse.
func cursorTime(cursor map[string]string, key string) *time.Time {
	raw, ok := cursor[key]
	if !ok || raw == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// setCursorTime stores t at full precision. Upstream timestamps carry
// milliseconds — NVD's lastModified, the CVE List's fetchTime — and a cursor
// rounded down to the second sits just before the last record it covers, so
// every run re-fetched that record and, for the CVE List, re-processed the
// whole last publication run.
func setCursorTime(cursor map[string]string, key string, t time.Time) {
	cursor[key] = t.UTC().Format(time.RFC3339Nano)
}

// replayCursor rewinds every timestamp-valued cursor entry to at. Conditional
// caching keys (ETags) are cleared too, or the upstream would answer 304 and
// the replay would fetch nothing.
func replayCursor(cursor map[string]string, at time.Time) {
	stamp := at.UTC().Format(time.RFC3339)
	for k, v := range cursor {
		if strings.HasPrefix(k, "etag") {
			delete(cursor, k)
			continue
		}
		if _, err := time.Parse(time.RFC3339, v); err == nil {
			cursor[k] = stamp
		}
	}
	// Sources whose cursor is a version marker rather than a timestamp need it
	// cleared so the next run does not short-circuit on "unchanged".
	delete(cursor, "catalog_version")
	// GCVE's resume state is a bare date (vl_since) and a page number, and
	// neither parses as a timestamp above. Rewriting only vl_started left the
	// next run resuming the old window at the old page, so `ingest -since`
	// could not rewind an open walk; the walk restarts from the replay instant.
	vlClearResume(cursor)
}
