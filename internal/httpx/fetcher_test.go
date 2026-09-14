package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, retries int) *Client {
	t.Helper()
	return NewClient(ClientOptions{Timeout: 5 * time.Second, UserAgent: "cvefeed-test", MaxRetries: retries})
}

func TestFetchSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "cvefeed-test" {
			t.Errorf("User-Agent = %q", got)
		}
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	c := newTestClient(t, 0)
	defer c.Close()
	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q", body)
	}
	if resp.ETag != `"abc"` {
		t.Errorf("ETag = %q", resp.ETag)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Fatalf("expected conditional request, got If-None-Match=%q", r.Header.Get("If-None-Match"))
	}))
	defer srv.Close()

	c := newTestClient(t, 0)
	defer c.Close()
	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL, IfNoneMatch: `"abc"`})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	if !resp.NotModified {
		t.Error("NotModified = false, want true")
	}
}

func TestFetchAcceptNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, 0)
	defer c.Close()
	_, err := c.Fetch(context.Background(), Request{URL: srv.URL, AcceptNotFound: true})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFetchRetriesOn503ThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, 3)
	c.SetHostRate(mustHost(t, srv.URL), 100, time.Millisecond) // don't let the rate limiter slow the test
	defer c.Close()

	// Backoff between attempts grows fast (1s, 2s, ...); cap the test's
	// patience instead of waiting on the real schedule.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Fetch(ctx, Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestFetchPermanentErrorDoesNotRetry(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	c := newTestClient(t, 3)
	defer c.Close()
	_, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 (400 must not be retried)", got)
	}
}

func TestFetchGivesUpAfterMaxRetries(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, 2)
	c.SetHostRate(mustHost(t, srv.URL), 100, time.Millisecond)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.Fetch(ctx, Request{URL: srv.URL})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if got := atomic.LoadInt32(&attempts); got != 3 { // initial + 2 retries
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestSetHostHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apiKey"); got != "secret" {
			t.Errorf("apiKey header = %q, want secret", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, 0)
	defer c.Close()
	c.SetHostHeader(mustHost(t, srv.URL), "apiKey", "secret")
	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	resp.Body.Close()
}

func TestParseRetryAfterSeconds(t *testing.T) {
	if got, ok := parseRetryAfter("5"); got != 5*time.Second || !ok {
		t.Errorf("parseRetryAfter(5) = %v/%v, want 5s/true", got, ok)
	}
	if got, ok := parseRetryAfter(""); got != 0 || ok {
		t.Errorf("parseRetryAfter(\"\") = %v/%v, want 0/false", got, ok)
	}
	if got, ok := parseRetryAfter("not-a-number-or-date"); got != 0 || ok {
		t.Errorf("parseRetryAfter(garbage) = %v/%v, want 0/false", got, ok)
	}
	if got, ok := parseRetryAfter("0"); got != 0 || !ok {
		t.Errorf("parseRetryAfter(0) = %v/%v, want 0/true (explicit zero)", got, ok)
	}
}

func TestBackoffCapsAt60Seconds(t *testing.T) {
	if got := backoff(1); got != 1*time.Second {
		t.Errorf("backoff(1) = %v, want 1s", got)
	}
	if got := backoff(10); got != 60*time.Second {
		t.Errorf("backoff(10) = %v, want capped at 60s", got)
	}
}

func TestReadAllLimitTruncates(t *testing.T) {
	resp := &Response{Body: io.NopCloser(bytes.NewReader([]byte("0123456789")))}
	b, err := ReadAllLimit(resp, 4)
	if err != nil {
		t.Fatalf("ReadAllLimit() error = %v", err)
	}
	if string(b) != "0123" {
		t.Errorf("ReadAllLimit truncated = %q, want %q", b, "0123")
	}
}

func TestLimiterEnforcesBurst(t *testing.T) {
	lim := newLimiter(2, 50*time.Millisecond, 0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := lim.wait(ctx); err != nil {
			t.Fatalf("wait() error = %v", err)
		}
	}
	// The third call must have blocked for roughly one window.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("elapsed = %v, want >= ~50ms (third token should wait for refill)", elapsed)
	}
}

func TestLimiterEnforcesMinInterval(t *testing.T) {
	// A burst large enough that only the spacing rule can slow this down.
	lim := newLimiter(10, time.Hour, 30*time.Millisecond)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := lim.wait(ctx); err != nil {
			t.Fatalf("wait() error = %v", err)
		}
	}
	// Two gaps of 30ms between three requests.
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("elapsed = %v, want >= ~60ms (requests must be spaced)", elapsed)
	}
}

func TestFetchRetriesOn403(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, 3)
	defer c.Close()
	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v; 403 must be retried as a rate-limit signal", err)
	}
	defer resp.Body.Close()
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestNoCacheHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	c := newTestClient(t, 0)
	defer c.Close()
	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL, NoCache: true})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	resp.Body.Close()
	if got.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got.Get("Cache-Control"))
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	h := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	return h
}

// A fixed-window limiter refills its whole allowance on a boundary, so 2×burst
// requests can land inside one rolling window and collect a 429 from an
// upstream whose published ceiling was never actually exceeded on paper.
func TestLimiterIsASlidingWindow(t *testing.T) {
	lim := newLimiter(2, 120*time.Millisecond, 0)
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := lim.wait(ctx); err != nil {
			t.Fatalf("wait() error = %v", err)
		}
	}
	// Four requests at two per 120ms cannot complete in less than one window.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("elapsed = %v; four requests slipped through a two-per-window limit", elapsed)
	}
}

// memRecorder keeps completed recordings in memory. A recording whose body
// arrives with an error is refused, exactly as the bundle recorder refuses it.
type memRecorder struct {
	mu      sync.Mutex
	entries map[string][]byte
	sizes   map[string]int64
}

func (m *memRecorder) Record(url string, _ http.Header, _ int, body io.Reader) error {
	n, err := io.Copy(io.Discard, io.TeeReader(body, &capture{m: m, url: url}))
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sizes == nil {
		m.sizes = map[string]int64{}
	}
	m.sizes[url] = n
	return nil
}

type capture struct {
	m   *memRecorder
	url string
}

func (c *capture) Write(p []byte) (int, error) {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	if c.m.entries == nil {
		c.m.entries = map[string][]byte{}
	}
	// Bounded so the drain-limit test can stream tens of megabytes through
	// without keeping them.
	if len(c.m.entries[c.url]) < 4096 {
		c.m.entries[c.url] = append(c.m.entries[c.url], p...)
	}
	return len(p), nil
}

func (m *memRecorder) recorded(url string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.sizes[url]
	if !ok {
		return nil, false
	}
	return m.entries[url][:min(int(n), len(m.entries[url]))], true
}

// splitEOFReader hands out its payload on one Read and io.EOF on the next,
// which is how HTTP/2 and chunked HTTP/1.1 bodies behave. An httptest server
// with a Content-Length returns (n, io.EOF) in a single call and cannot show
// the bug this guards against.
type splitEOFReader struct {
	data   []byte
	closed bool
}

func (r *splitEOFReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *splitEOFReader) Close() error {
	r.closed = true
	return nil
}

// json.Decoder stops at the closing brace and never issues the Read that
// would return EOF, and the collectors close the body right after Decode. A
// recording that waited for the consumer to see EOF therefore dropped every
// JSON response — release metadata, NVD pages, KEV, CSAF feeds — from the
// bundle while reporting nothing.
func TestRecordingBodyRecordsABodyClosedBeforeEOF(t *testing.T) {
	rec := &memRecorder{}
	const url = "https://example.org/release.json"
	src := &splitEOFReader{data: []byte(`{"tag_name":"cve_2026-08-18_1000Z"}`)}
	body := newRecordingBody(rec, url, http.Header{}, http.StatusOK, src)

	var out struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if out.Tag != "cve_2026-08-18_1000Z" {
		t.Fatalf("decoded tag = %q", out.Tag)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	got, ok := rec.recorded(url)
	if !ok {
		t.Fatal("the response was not recorded; a body closed before EOF must still be drained into the bundle")
	}
	if string(got) != `{"tag_name":"cve_2026-08-18_1000Z"}` {
		t.Fatalf("recorded body = %q, want the complete document", got)
	}
	if !src.closed {
		t.Error("the underlying body was not closed")
	}
}

// A consumer that stops reading with megabytes still on the wire is giving up
// on the transfer, not finishing it. The drain must not turn that into a
// download of the whole remainder on the recorder's behalf.
func TestRecordingBodyAbortsWhenTheUnreadRemainderIsTooLarge(t *testing.T) {
	rec := &memRecorder{}
	const url = "https://example.org/huge.bin"
	src := io.NopCloser(io.LimitReader(zeroReader{}, maxRecordDrain+4096))
	body := newRecordingBody(rec, url, http.Header{}, http.StatusOK, src)

	buf := make([]byte, 16)
	if _, err := body.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if err := body.Close(); err == nil {
		t.Fatal("Close() = nil, want the aborted recording reported")
	}
	if _, ok := rec.recorded(url); ok {
		t.Fatal("an over-long remainder was recorded as if it were the complete response")
	}
}

// A source that fails part-way delivers a truncated document, which must never
// be indexed as a complete one, whether the failure is seen by Read or by the
// drain in Close.
func TestRecordingBodyDropsATruncatedTransfer(t *testing.T) {
	rec := &memRecorder{}
	const url = "https://example.org/truncated.json"
	src := io.NopCloser(io.MultiReader(strings.NewReader(`{"partial":`), errReader{errors.New("connection reset")}))
	body := newRecordingBody(rec, url, http.Header{}, http.StatusOK, src)

	buf := make([]byte, 4)
	if _, err := body.Read(buf); err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if err := body.Close(); err == nil {
		t.Fatal("Close() = nil, want the read failure surfaced")
	}
	if _, ok := rec.recorded(url); ok {
		t.Fatal("a truncated transfer was recorded")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// Retry-After is the server stating how long it wants; adding the exponential
// backoff on top of it stacked a second wait on every rate-limited retry. Two
// 503s with Retry-After: 1 must ask for two waits of one second, not 1+1 and
// 1+2. The waits are recorded rather than slept: measured on the wall clock
// the assertion flaked on a loaded runner.
func TestRetryAfterReplacesTheBackoffRatherThanAddingToIt(t *testing.T) {
	var (
		mu    sync.Mutex
		waits []time.Duration
	)
	orig := sleep
	sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return ctx.Err()
	}
	t.Cleanup(func() { sleep = orig })

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, 3)
	c.SetHostRate(mustHost(t, srv.URL), 100, time.Millisecond)
	defer c.Close()

	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(waits) != 2 {
		t.Fatalf("waits = %v, want one wait before each of the two retries", waits)
	}
	// With the backoff stacked on top the waits are 1+1 s and 1+2 s.
	for i, w := range waits {
		if w < 900*time.Millisecond || w > 1100*time.Millisecond {
			t.Fatalf("wait %d = %v, want the Retry-After of 1 s alone; the exponential backoff was added on top", i+1, w)
		}
	}
}

// A body that is closed before a single byte was read was abandoned, not
// decoded: the download whose temp file could not be created, say. Draining it
// on the recorder's behalf held the caller for up to maxRecordDrain of a
// transfer it had just decided not to make.
func TestRecordingBodyClosedBeforeAnyReadDoesNotDrainTheSource(t *testing.T) {
	rec := &memRecorder{}
	const url = "https://example.org/huge.tar.gz"
	src := &stalledSource{release: make(chan struct{})}
	t.Cleanup(func() { close(src.release) })
	body := newRecordingBody(rec, url, http.Header{}, http.StatusOK, src)

	closed := make(chan error, 1)
	go func() { closed <- body.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v, want an abandoned response dropped quietly", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked draining a body nobody read")
	}
	if _, ok := rec.recorded(url); ok {
		t.Fatal("an abandoned response was recorded")
	}
	if !src.closed.Load() {
		t.Error("the underlying body was not closed")
	}
}

// stalledSource never delivers a byte until released, the way a slow origin
// behaves from the point of view of a drain.
type stalledSource struct {
	release chan struct{}
	closed  atomic.Bool
}

func (s *stalledSource) Read([]byte) (int, error) {
	<-s.release
	return 0, io.EOF
}

func (s *stalledSource) Close() error {
	s.closed.Store(true)
	return nil
}

// A cancelled wait must return promptly and leave no timer running.
func TestSleepCtxReturnsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := sleepCtx(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleepCtx() = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("sleepCtx did not return on cancellation")
	}
}
