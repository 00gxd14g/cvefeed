// Package httpx provides the single network abstraction used by every
// collector. Collectors never touch net/http directly; they talk to a Fetcher.
// That indirection is what makes the air-gapped mode possible: the offline
// bundle reader satisfies the same interface.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Request is a fetch request. Conditional headers are first-class because every
// bulk upstream in this domain supports ETag or Last-Modified, and honouring
// them is the difference between a 400 MB download and a 200-byte 304.
type Request struct {
	URL             string
	Header          http.Header
	IfNoneMatch     string
	IfModifiedSince string
	// AcceptNotFound suppresses the error for a 404 and returns Status 404
	// with an empty body. Used where a resource is legitimately optional.
	AcceptNotFound bool
	// NoCache asks intermediaries for a fresh copy. raw.githubusercontent.com
	// has served a stale cves/delta.json for hours (May 2026), which silently
	// stalls the CVE List delta, so every GitHub raw fetch sets this.
	NoCache bool
}

// Response is a fetch result. Body must always be closed by the caller.
type Response struct {
	URL          string
	Status       int
	Header       http.Header
	Body         io.ReadCloser
	NotModified  bool
	ETag         string
	LastModified string
	FromBundle   bool
}

// Fetcher retrieves bytes for a URL.
type Fetcher interface {
	Fetch(ctx context.Context, req Request) (*Response, error)
	Close() error
}

// ErrOffline is returned when a fetch is attempted with networking disabled and
// the resource is not present in the offline bundle.
var ErrOffline = errors.New("httpx: network disabled and resource not in bundle")

// ErrNotFound is returned for a 404 when the caller opted into AcceptNotFound.
var ErrNotFound = errors.New("httpx: resource not found")

// Recorder captures fetched responses so they can be replayed offline.
type Recorder interface {
	Record(url string, header http.Header, status int, body io.Reader) error
}

// Client is the online Fetcher.
type Client struct {
	hc          *http.Client
	idleTimeout time.Duration
	userAgent   string
	retries     int
	recorder    Recorder

	mu       sync.Mutex
	limiters map[string]*limiter
	rates    map[string]rateSpec

	// hostHeaders injects per-host headers, e.g. the NVD apiKey.
	hostHeaders map[string]http.Header
}

type rateSpec struct {
	burst  int
	window time.Duration
	// minInterval, when set, additionally paces requests so the burst is not
	// emitted back to back. Some upstreams police the spacing, not just the
	// count.
	minInterval time.Duration
}

// ClientOptions configures a Client.
type ClientOptions struct {
	Timeout time.Duration
	// IdleTimeout bounds how long a response body may deliver nothing before
	// the transfer is abandoned. It is not a deadline on the download: every
	// byte that arrives resets it, so an arbitrarily long transfer succeeds and
	// only a silent connection is cut. Zero disables the guard.
	IdleTimeout time.Duration
	UserAgent   string
	MaxRetries  int
	Recorder    Recorder
}

// NewClient builds an online Fetcher with sensible transport defaults.
func NewClient(opt ClientOptions) *Client {
	if opt.Timeout <= 0 {
		opt.Timeout = 120 * time.Second
	}
	if opt.MaxRetries < 0 {
		opt.MaxRetries = 0
	}
	if opt.IdleTimeout <= 0 {
		// Generous, because it is measuring silence rather than slowness: a
		// transfer moving at any rate at all never reaches it.
		opt.IdleTimeout = 5 * time.Minute
	}
	// The timeout is applied to the response *headers*, not to the whole
	// exchange. http.Client.Timeout is an end-to-end deadline that includes
	// reading the body, and the bulk artefacts here run to 1.4 GiB — a 120 s
	// end-to-end deadline would abort every backfill download that cannot
	// sustain ~12 MB/s. Cancellation of a slow body is the caller's context.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		ResponseHeaderTimeout: opt.Timeout,
		ForceAttemptHTTP2:     true,
	}
	c := &Client{
		hc:          &http.Client{Transport: transport},
		idleTimeout: opt.IdleTimeout,
		userAgent:   opt.UserAgent,
		retries:     opt.MaxRetries,
		recorder:    opt.Recorder,
		limiters:    map[string]*limiter{},
		hostHeaders: map[string]http.Header{},
		rates: map[string]rateSpec{
			// NVD enforces 5 requests per rolling 30 seconds without a key and
			// 50 with one. We stay one request below the ceiling on purpose,
			// and NIST additionally asks for ~6 s between requests — bursting
			// the whole allowance at once is what actually earns a 403.
			"services.nvd.nist.gov": {burst: 4, window: 30 * time.Second, minInterval: 6 * time.Second},
			// Unauthenticated GitHub is 60 requests an hour. A token raises it
			// to 5,000/h and main wires SetHostRate accordingly.
			"api.github.com":               {burst: 55, window: time.Hour},
			"api.first.org":                {burst: 10, window: 10 * time.Second},
			"euvdservices.enisa.europa.eu": {burst: 5, window: 10 * time.Second},
			"api.osv.dev":                  {burst: 20, window: 10 * time.Second},
			// CIRCL publishes 20 requests/minute anonymously. The margin is
			// deliberately wide: a retry is itself a request, so pacing right
			// at the ceiling means the first 429 spends the rest of the
			// allowance retrying into the same wall.
			"vulnerability.circl.lu": {burst: 10, window: time.Minute, minInterval: 5 * time.Second},
		},
	}
	return c
}

// SetHostRate overrides the token bucket for a host.
func (c *Client) SetHostRate(host string, burst int, window time.Duration) {
	c.SetHostRateInterval(host, burst, window, 0)
}

// SetHostRateInterval overrides the token bucket and the minimum spacing
// between two requests to the same host.
func (c *Client) SetHostRateInterval(host string, burst int, window, minInterval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rates[host] = rateSpec{burst: burst, window: window, minInterval: minInterval}
	delete(c.limiters, host)
}

// SetHostHeader registers a header injected on every request to host.
func (c *Client) SetHostHeader(host, key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.hostHeaders[host]
	if !ok {
		h = http.Header{}
		c.hostHeaders[host] = h
	}
	h.Set(key, value)
}

func (c *Client) limiterFor(host string) *limiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.limiters[host]; ok {
		return l
	}
	spec, ok := c.rates[host]
	if !ok {
		spec = rateSpec{burst: 10, window: 1 * time.Second}
	}
	l := newLimiter(spec.burst, spec.window, spec.minInterval)
	c.limiters[host] = l
	return l
}

// Fetch performs the request, retrying transient failures with exponential
// backoff and honouring Retry-After when the server supplies it.
func (c *Client) Fetch(ctx context.Context, req Request) (*Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("httpx: parse %q: %w", req.URL, err)
	}
	lim := c.limiterFor(u.Host)

	var lastErr error
	var delay time.Duration // the wait before the next attempt, decided by the last failure
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, delay); err != nil {
				return nil, err
			}
		}
		if err := lim.wait(ctx); err != nil {
			return nil, err
		}

		resp, retryAfter, err := c.do(ctx, u, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if errors.Is(err, ErrNotFound) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		var perm *permanentError
		if errors.As(err, &perm) {
			return nil, err
		}
		// A Retry-After replaces the exponential backoff rather than adding to
		// it. The server has stated exactly how long it wants, and stacking a
		// second wait on top turned NVD's 30 s floor into 31, 32, 34 … seconds
		// of dead time per retry.
		delay = backoff(attempt + 1)
		if retryAfter > 0 {
			delay = retryAfter
		}
	}
	return nil, fmt.Errorf("httpx: %s: giving up after %d attempts: %w", req.URL, c.retries+1, lastErr)
}

// sleep is the wait between two attempts of one fetch. It is a variable so a
// test can substitute a recorder and check the durations the retry loop asks
// for without waiting them out on the wall clock, where a loaded CI runner
// turns "about two seconds" into a flaky assertion.
var sleep = sleepCtx

// sleepCtx waits for d or until ctx is done. It uses an explicit timer that
// is stopped on the way out: time.After leaks its timer until it fires, and a
// retry loop that is cancelled mid-wait would otherwise leave a 60 s timer
// behind on every abandoned fetch.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type permanentError struct{ err error }

func (p *permanentError) Error() string { return p.err.Error() }
func (p *permanentError) Unwrap() error { return p.err }

func (c *Client) do(ctx context.Context, u *url.URL, req Request) (*Response, time.Duration, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, &permanentError{err}
	}
	// Accept-Encoding is intentionally left unset: Go's transport then adds and
	// transparently strips gzip, so recorded bundle bytes are always decoded.
	hr.Header.Set("User-Agent", c.userAgent)
	c.mu.Lock()
	if hh, ok := c.hostHeaders[u.Host]; ok {
		for k, vs := range hh {
			for _, v := range vs {
				hr.Header.Set(k, v)
			}
		}
	}
	c.mu.Unlock()
	for k, vs := range req.Header {
		for _, v := range vs {
			hr.Header.Set(k, v)
		}
	}
	if req.IfNoneMatch != "" {
		hr.Header.Set("If-None-Match", req.IfNoneMatch)
	}
	if req.IfModifiedSince != "" {
		hr.Header.Set("If-Modified-Since", req.IfModifiedSince)
	}
	if req.NoCache {
		hr.Header.Set("Cache-Control", "no-cache")
		hr.Header.Set("Pragma", "no-cache")
	}

	resp, err := c.hc.Do(hr)
	if err != nil {
		return nil, 0, err
	}

	switch {
	case resp.StatusCode == http.StatusNotModified:
		resp.Body.Close()
		return &Response{
			URL: req.URL, Status: resp.StatusCode, Header: resp.Header,
			Body: io.NopCloser(strings.NewReader("")), NotModified: true,
			ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
		}, 0, nil

	case resp.StatusCode == http.StatusNotFound && req.AcceptNotFound:
		resp.Body.Close()
		return nil, 0, ErrNotFound

	// 403 is a back-off signal, not a permanent failure. NVD has historically
	// answered rate limiting with 403 and announced the migration to 429 in
	// May 2026; both codes still occur in the wild, and GitHub uses 403 for
	// secondary rate limits too. Treating 403 as permanent aborted the whole
	// collector on what is a "wait and retry" condition.
	case resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		ra, stated := parseRetryAfter(resp.Header.Get("Retry-After"))
		if !stated && resp.StatusCode < 500 {
			// The documented floor for a rate-limit response with no header.
			ra = rateLimitBackoff
		}
		msg := resp.Header.Get("message") // NVD explains rate limiting here
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, ra, fmt.Errorf("httpx: %s: status %d%s%s", req.URL, resp.StatusCode,
			prefixed(": ", msg), prefixed(" ", errorBody(resp.Header.Get("Content-Type"), body)))

	case resp.StatusCode >= 400:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, 0, &permanentError{fmt.Errorf("httpx: %s: status %d: %s",
			req.URL, resp.StatusCode, errorBody(resp.Header.Get("Content-Type"), body))}
	}

	// Innermost, so everything layered above reads through the guard.
	body := newStallGuard(resp.Body, c.idleTimeout)
	if c.recorder != nil {
		body = newRecordingBody(c.recorder, req.URL, resp.Header, resp.StatusCode, body)
	}

	return &Response{
		URL: req.URL, Status: resp.StatusCode, Header: resp.Header, Body: body,
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
	}, 0, nil
}

// Close releases idle connections.
func (c *Client) Close() error {
	c.hc.CloseIdleConnections()
	return nil
}

// rateLimitBackoff is the wait applied to a 403/429 that carries no
// Retry-After, per the NVD guidance in the research report.
const rateLimitBackoff = 30 * time.Second

func prefixed(sep, s string) string {
	if s == "" {
		return ""
	}
	return sep + s
}

// parseRetryAfter reads a Retry-After header. The bool distinguishes "the
// server told us to wait zero seconds" from "the server said nothing", which is
// what decides whether the rate-limit floor applies.
func parseRetryAfter(v string) (time.Duration, bool) {
	if strings.TrimSpace(v) == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

// limiter enforces "at most burst requests in any window" as a genuine sliding
// window, plus an optional floor on the spacing between two consecutive
// requests.
//
// A fixed window is not good enough here. Refilling the whole allowance on a
// boundary lets 2×burst requests land inside one rolling window — burst at the
// end of one period and burst at the start of the next — which is exactly how a
// collector that is nominally within a published ceiling still collects a 429.
// The spacing floor is separate: NIST asks for roughly six seconds between NVD
// calls regardless of the count.
type limiter struct {
	mu          sync.Mutex
	burst       int
	window      time.Duration
	minInterval time.Duration
	// recent holds the timestamps of the last burst requests, oldest first.
	recent []time.Time
}

func newLimiter(burst int, window, minInterval time.Duration) *limiter {
	if burst < 1 {
		burst = 1
	}
	if window <= 0 {
		window = time.Second
	}
	return &limiter{
		burst:       burst,
		window:      window,
		minInterval: minInterval,
		recent:      make([]time.Time, 0, burst),
	}
}

func (l *limiter) wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()

		// Drop everything that has aged out of the window.
		cutoff := now.Add(-l.window)
		keep := l.recent[:0]
		for _, t := range l.recent {
			if t.After(cutoff) {
				keep = append(keep, t)
			}
		}
		l.recent = keep

		var sleep time.Duration
		switch {
		case len(l.recent) >= l.burst:
			sleep = l.recent[0].Add(l.window).Sub(now)
		case l.minInterval > 0 && len(l.recent) > 0 &&
			now.Sub(l.recent[len(l.recent)-1]) < l.minInterval:
			sleep = l.minInterval - now.Sub(l.recent[len(l.recent)-1])
		default:
			l.recent = append(l.recent, now)
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		if sleep <= 0 {
			sleep = time.Millisecond
		}
		if err := sleepCtx(ctx, sleep); err != nil {
			return err
		}
	}
}

// recordingBody tees the response into the recorder, finalising the bundle
// entry only when the body has been read to completion. A truncated read must
// not produce a bundle entry that would later replay as a corrupt document.
//
// "Read to completion" is decided by the source, not by the consumer. Nearly
// every consumer here closes the body before it has seen io.EOF: json.Decoder
// stops at the closing brace of the document and never issues the Read that
// would return EOF, and io.LimitReader reports EOF at its bound without
// touching the source again. On an HTTP/2 or chunked HTTP/1.1 body the last
// data read returns (n, nil) and EOF only arrives on a separate call, so a
// recording that needed the consumer to observe EOF captured nothing at all —
// every JSON response in the pipeline was missing from the bundle. Close
// therefore drains whatever the consumer left unread through the recorder,
// and only a source that errors or exceeds the drain bound aborts the entry.
type recordingBody struct {
	rec    Recorder
	url    string
	header http.Header
	status int
	src    io.ReadCloser
	pw     *io.PipeWriter
	done   chan error
	closed bool
	// read counts the bytes the consumer took, so Close can tell an abandoned
	// response from one that was decoded and closed a few bytes early.
	read int64
}

// maxRecordDrain bounds how much of an abandoned body Close reads on the
// recorder's behalf. A consumer that stops early because it has what it needs
// leaves at most a few bytes behind; a consumer that gave up on a 1.4 GiB
// archive must not have the whole thing downloaded for it.
const maxRecordDrain = 64 << 20

func newRecordingBody(rec Recorder, url string, header http.Header, status int, src io.ReadCloser) io.ReadCloser {
	pr, pw := io.Pipe()
	rb := &recordingBody{rec: rec, url: url, header: header, status: status, src: src, pw: pw, done: make(chan error, 1)}
	go func() {
		err := rec.Record(url, header, status, pr)
		io.Copy(io.Discard, pr)
		pr.Close()
		rb.done <- err
	}()
	return rb
}

func (rb *recordingBody) Read(p []byte) (int, error) {
	n, err := rb.src.Read(p)
	rb.read += int64(n)
	// A reader is allowed to call Read again after EOF; pw is nil by then.
	if n > 0 && rb.pw != nil {
		if _, werr := rb.pw.Write(p[:n]); werr != nil {
			return n, werr
		}
	}
	if err != nil && rb.pw != nil {
		if errors.Is(err, io.EOF) {
			if rerr := rb.finish(); rerr != nil {
				return n, rerr
			}
		} else {
			// The source failed part-way; what reached the recorder is a
			// truncated document and must not be indexed as a complete one.
			rb.abort(err)
		}
	}
	return n, err
}

// finish closes the recorder's side cleanly and reports the recorder's verdict.
func (rb *recordingBody) finish() error {
	rb.pw.Close()
	rb.pw = nil
	if rerr := <-rb.done; rerr != nil {
		return fmt.Errorf("httpx: record %s: %w", rb.url, rerr)
	}
	return nil
}

// abort cancels the recording so no partial entry lands, and hands the reason
// back so the caller can report why the bundle is missing this URL.
func (rb *recordingBody) abort(reason error) error {
	rb.pw.CloseWithError(reason)
	<-rb.done
	rb.pw = nil
	return fmt.Errorf("httpx: record %s: %w", rb.url, reason)
}

func (rb *recordingBody) Close() error {
	if rb.closed {
		return nil
	}
	rb.closed = true
	var recErr error
	switch {
	case rb.pw != nil && rb.read == 0:
		// Nothing was consumed, so there is no document worth completing on
		// the recorder's behalf: the caller abandoned the response before it
		// began — the path a 1.4 GiB archive takes when its temp file cannot
		// be created — and draining up to maxRecordDrain of it here would hold
		// the caller for the download it just decided not to make. The entry
		// is dropped, which is also not an error the caller can act on.
		rb.pw.CloseWithError(errors.New("body closed before any read"))
		<-rb.done
		rb.pw = nil
	case rb.pw != nil:
		// The consumer stopped before EOF. Read the remainder on its behalf so
		// the recorder sees the complete document; a source error or an
		// over-long remainder means the entry cannot be trusted and is dropped.
		n, err := io.Copy(rb.pw, io.LimitReader(rb.src, maxRecordDrain+1))
		switch {
		case err != nil:
			recErr = rb.abort(fmt.Errorf("body closed before EOF and the remainder could not be read: %w", err))
		case n > maxRecordDrain:
			recErr = rb.abort(fmt.Errorf("body closed with more than %d bytes unread; recording aborted", maxRecordDrain))
		default:
			recErr = rb.finish()
		}
	}
	if err := rb.src.Close(); err != nil && recErr == nil {
		return err
	}
	return recErr
}

// ReadAllLimit drains a response body up to max bytes, closing it afterwards.
func ReadAllLimit(resp *Response, max int64) ([]byte, error) {
	defer resp.Body.Close()
	if max <= 0 {
		max = 512 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil {
		return nil, fmt.Errorf("httpx: read %s: %w", resp.URL, err)
	}
	return b, nil
}

// errorBodyLimit bounds how much of an upstream error body reaches an error
// message. The message is stored as a source's last_error and served by
// /v1/sources, so it has to stay a sentence, not a page.
const errorBodyLimit = 200

// errorBody reduces an error response body to the part worth quoting. HTML
// error pages (a CDN's 503, a challenge interstitial) are stripped to their
// text; whitespace is collapsed; the result is cut at errorBodyLimit.
func errorBody(contentType string, body []byte) string {
	text := strings.TrimSpace(string(body))
	if strings.Contains(strings.ToLower(contentType), "html") || strings.HasPrefix(text, "<") {
		text = stripTags(text)
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > errorBodyLimit {
		cut := errorBodyLimit
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "…"
	}
	return text
}

// stripTags drops HTML tags and the contents of script and style elements,
// leaving the visible text separated by spaces.
func stripTags(s string) string {
	var b strings.Builder
	lower := strings.ToLower(s)
	i := 0
	for i < len(s) {
		if s[i] != '<' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			break
		}
		tag := lower[i+1 : i+end]
		i += end + 1
		for _, skip := range []string{"script", "style"} {
			if strings.HasPrefix(tag, skip) {
				if close := strings.Index(lower[i:], "</"+skip); close >= 0 {
					i += close
				} else {
					i = len(s)
				}
				break
			}
		}
		b.WriteByte(' ')
	}
	return b.String()
}
