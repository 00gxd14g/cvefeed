package collect

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestStoreSinkFailureCountIsVisibleAfterDrain(t *testing.T) {
	sink := &StoreSink{
		Workers:    1,
		QueueDepth: 1,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	sink.persistFn = func(context.Context, *model.Vulnerability) {
		sink.Failed.Add(1)
	}

	if err := sink.Vulnerability(context.Background(), &model.Vulnerability{ID: "CVE-2026-1"}); err != nil {
		t.Fatalf("Vulnerability() error = %v", err)
	}
	sink.Drain()
	if got := sink.FailureCount(); got != 1 {
		t.Fatalf("FailureCount() = %d, want 1 after the queued write failed", got)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloneCursorProtectsTheRetryPoint(t *testing.T) {
	cursor := map[string]string{
		"last_modified": "2026-09-01T00:00:00Z",
		"page":          "12",
	}
	start := cloneCursor(cursor)

	cursor["last_modified"] = "2026-09-09T00:00:00Z"
	cursor["page"] = "99"
	cursor["etag"] = "new"

	if got := start["last_modified"]; got != "2026-09-01T00:00:00Z" {
		t.Fatalf("snapshot last_modified = %q, want the run's starting cursor", got)
	}
	if got := start["page"]; got != "12" {
		t.Fatalf("snapshot page = %q, want 12", got)
	}
	if _, ok := start["etag"]; ok {
		t.Fatal("mutating the live cursor also mutated the retry snapshot")
	}
}
