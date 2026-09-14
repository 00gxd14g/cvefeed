package collect

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/00gxd14g/cvefeed/internal/config"
	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
)

// Live tests talk to the real upstreams. They are how you find out that an
// endpoint changed shape — which is the failure mode this pipeline is most
// exposed to, and the one unit tests cannot see.
//
//	CVEFEED_TEST_LIVE=1 go test ./internal/collect/ -run Live
//
// The CVE List baseline test additionally needs CVEFEED_TEST_LIVE_HEAVY=1
// because it downloads roughly 580 MB.
func liveClient(t *testing.T) *httpx.Client {
	t.Helper()
	if os.Getenv("CVEFEED_TEST_LIVE") == "" {
		t.Skip("CVEFEED_TEST_LIVE not set")
	}
	c := httpx.NewClient(httpx.ClientOptions{
		Timeout:    120 * time.Second,
		UserAgent:  "cvefeed/1.0 (+https://example.org/cvefeed; mailto=test@example.org)",
		MaxRetries: 3,
	})
	t.Cleanup(func() { c.Close() })
	return c
}

// countingSink records what a collector emits without needing a database.
type countingSink struct {
	vulns int64
	kev   int64
	epss  int64
}

func (s *countingSink) Vulnerability(ctx context.Context, v *model.Vulnerability) error {
	s.vulns++
	return nil
}
func (s *countingSink) KEVCatalogue(ctx context.Context, e []model.KEV) error {
	return s.KEV(ctx, e)
}

func (s *countingSink) KEV(ctx context.Context, e []model.KEV) error {
	s.kev += int64(len(e))
	return nil
}
func (s *countingSink) EPSS(ctx context.Context, e []model.EPSS) error {
	s.epss += int64(len(e))
	return nil
}

func liveRun(t *testing.T, mode Mode, cursor map[string]string) (*Run, *countingSink) {
	t.Helper()
	if cursor == nil {
		cursor = map[string]string{}
	}
	sink := &countingSink{}
	return &Run{
		Mode:    mode,
		Fetcher: liveClient(t),
		Sink:    sink,
		Cfg:     &config.Config{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cursor:  cursor,
	}, sink
}

// The CVE List baseline asset is a zip inside a zip. Reading only one level
// emits nothing while reporting success, which leaves the authoritative corpus
// permanently unloaded.
func TestLiveCVEListBaselineYieldsRecords(t *testing.T) {
	if os.Getenv("CVEFEED_TEST_LIVE_HEAVY") == "" {
		t.Skip("CVEFEED_TEST_LIVE_HEAVY not set (this downloads ~580 MB)")
	}
	r, sink := liveRun(t, ModeBackfill, nil)
	c := &CVEListCollector{}
	if err := c.Run(context.Background(), r); err != nil {
		t.Fatalf("cvelist backfill error = %v", err)
	}
	// The corpus passed 378,000 records in August 2026; anything in the low
	// hundreds of thousands means the archive was actually walked.
	if sink.vulns < 300000 {
		t.Fatalf("baseline emitted %d records, want the full corpus", sink.vulns)
	}
	if r.Cursor["last_delta"] == "" {
		t.Error("no delta cursor recorded after a successful baseline")
	}
	t.Logf("baseline emitted %d records, cursor %s", sink.vulns, r.Cursor["last_delta"])
}

func TestLiveCVEListDelta(t *testing.T) {
	// A recent cursor keeps this to the last hour of changes.
	cursor := map[string]string{}
	setCursorTime(cursor, "last_delta", time.Now().UTC().Add(-2*time.Hour))
	r, sink := liveRun(t, ModeDelta, cursor)

	c := &CVEListCollector{}
	if err := c.Run(context.Background(), r); err != nil {
		t.Fatalf("cvelist delta error = %v", err)
	}
	t.Logf("delta emitted %d records", sink.vulns)
}

func TestLiveKEVCatalogue(t *testing.T) {
	r, sink := liveRun(t, ModeDelta, nil)
	if err := (&KEVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("kev error = %v", err)
	}
	if sink.kev < 1000 {
		t.Fatalf("kev entries = %d, want the full catalogue", sink.kev)
	}
	if r.Cursor["catalog_version"] == "" {
		t.Error("catalogVersion not recorded; the change gate cannot work without it")
	}
}

func TestLiveEPSSScores(t *testing.T) {
	r, sink := liveRun(t, ModeDelta, nil)
	if err := (&EPSSCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("epss error = %v", err)
	}
	if sink.epss < 300000 {
		t.Fatalf("epss rows = %d, want the whole corpus", sink.epss)
	}
	if r.Cursor["model_version"] == "" {
		t.Error("model_version not recorded; scores are only comparable within one model")
	}
	if r.Cursor["score_date"] == "" {
		t.Error("score_date not recorded")
	}
}

func TestLiveEUVDSearch(t *testing.T) {
	cursor := map[string]string{}
	setCursorTime(cursor, "last_run", time.Now().UTC().Add(-24*time.Hour))
	r, sink := liveRun(t, ModeDelta, cursor)

	if err := (&EUVDCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("euvd error = %v", err)
	}
	if sink.vulns == 0 {
		t.Fatal("euvd emitted nothing for a 24-hour window")
	}
	t.Logf("euvd emitted %d records and %d exploited flags", sink.vulns, sink.kev)
}

// Vulnerability-Lookup answers with a bare JSON array; decoding straight into a
// struct made this collector silently ingest nothing at all.
func TestLiveVulnerabilityLookup(t *testing.T) {
	// A short window so the run finishes inside the page ceiling. CIRCL is
	// rate limited and its pages are large; a partial read is a legitimate
	// outcome that holds the cursor, so the assertion here is that records
	// arrive at all, not that the window closes.
	cursor := map[string]string{}
	setCursorTime(cursor, "last_run", time.Now().UTC().Add(-3*time.Hour))
	r, sink := liveRun(t, ModeDelta, cursor)

	err := (&GCVECollector{}).Run(context.Background(), r)
	if sink.vulns == 0 {
		t.Fatalf("vulnerability-lookup emitted nothing (error: %v)", err)
	}
	if r.Cursor["gna_index"] == "" {
		t.Error("GNA registry not recorded")
	}
	t.Logf("vulnerability-lookup emitted %d records (completion: %v)", sink.vulns, err)
}

func TestLiveOSVDelta(t *testing.T) {
	cursor := map[string]string{}
	setCursorTime(cursor, "last_modified", time.Now().UTC().Add(-20*time.Minute))
	r, sink := liveRun(t, ModeDelta, cursor)

	if err := (&OSVCollector{}).Run(context.Background(), r); err != nil {
		t.Fatalf("osv delta error = %v", err)
	}
	t.Logf("osv delta emitted %d records", sink.vulns)
}
