package collect

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/model"
)

// fakeFetcher answers requests from a handler and remembers every URL asked
// for, so a test can assert what a collector did and did not fetch.
type fakeFetcher struct {
	mu     sync.Mutex
	calls  []string
	handle func(req httpx.Request) (*httpx.Response, error)
}

func (f *fakeFetcher) Fetch(ctx context.Context, req httpx.Request) (*httpx.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.URL)
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.handle(req)
}

func (f *fakeFetcher) Close() error { return nil }

// count reports how many requests carried substr in their URL.
func (f *fakeFetcher) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, u := range f.calls {
		if strings.Contains(u, substr) {
			n++
		}
	}
	return n
}

func (f *fakeFetcher) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// textResponse is a 200 with the given body and headers.
func textResponse(req httpx.Request, body string, hdr http.Header) *httpx.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &httpx.Response{
		URL: req.URL, Status: http.StatusOK, Header: hdr,
		Body: io.NopCloser(strings.NewReader(body)),
		ETag: hdr.Get("ETag"), LastModified: hdr.Get("Last-Modified"),
	}
}

// bytesResponse is textResponse for binary payloads.
func bytesResponse(req httpx.Request, body []byte) *httpx.Response {
	return &httpx.Response{
		URL: req.URL, Status: http.StatusOK, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(string(body))),
	}
}

// unknownURL is what the fake answers for anything a test did not script,
// honouring AcceptNotFound the way the real client does.
func unknownURL(req httpx.Request) (*httpx.Response, error) {
	if req.AcceptNotFound {
		return nil, httpx.ErrNotFound
	}
	return nil, fmt.Errorf("%w: %s", httpx.ErrOffline, req.URL)
}

// idSink remembers what a collector emitted.
type idSink struct {
	mu       sync.Mutex
	ids      []string
	kev      []model.KEV
	kevCalls int
	// kevCatalogueCalls counts full-catalogue loads, which retire entries; a
	// collector that holds only a partial view must never make one.
	kevCatalogueCalls int
	kevErr            error // returned by KEV, so a test can make the store fail
}

func (s *idSink) Vulnerability(_ context.Context, v *model.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = append(s.ids, v.ID)
	return nil
}

func (s *idSink) KEVCatalogue(ctx context.Context, entries []model.KEV) error {
	s.mu.Lock()
	s.kevCatalogueCalls++
	s.mu.Unlock()
	return s.KEV(ctx, entries)
}

func (s *idSink) KEV(_ context.Context, entries []model.KEV) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kevCalls++
	if s.kevErr != nil {
		return s.kevErr
	}
	s.kev = append(s.kev, entries...)
	return nil
}

func (s *idSink) EPSS(context.Context, []model.EPSS) error { return nil }

func (s *idSink) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ids...)
}

// newTestRun builds a Run around a fake fetcher and an id-recording sink.
func newTestRun(t *testing.T, mode Mode, f httpx.Fetcher, cursor map[string]string) (*Run, *idSink) {
	t.Helper()
	if cursor == nil {
		cursor = map[string]string{}
	}
	sink := &idSink{}
	return &Run{
		Mode:    mode,
		Fetcher: f,
		Sink:    sink,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cursor:  cursor,
	}, sink
}
