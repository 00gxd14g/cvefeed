// Package api exposes the aggregated corpus over HTTP.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/00gxd14g/cvefeed/internal/config"
	"github.com/00gxd14g/cvefeed/internal/inventory"
	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/netscan"
	"github.com/00gxd14g/cvefeed/internal/scan"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// Server wires the HTTP handlers to the store.
type Server struct {
	store   *store.Store
	cfg     *config.Config
	log     *slog.Logger
	started time.Time
	version string

	// stream is the export's row source. Nil means the store's; tests set it to
	// a function that fails at a chosen row, which is the only way to exercise
	// the truncation path without a database that breaks on cue.
	stream streamFunc
}

// streamFunc has the shape of store.StreamVulnerabilities.
type streamFunc func(context.Context, store.ListFilter, func(*store.ExportRecord) error) error

func (s *Server) streamVulnerabilities() streamFunc {
	if s.stream != nil {
		return s.stream
	}
	return s.store.StreamVulnerabilities
}

// New builds a Server.
func New(st *store.Store, cfg *config.Config, log *slog.Logger) *Server {
	return &Server{store: st, cfg: cfg, log: log, started: time.Now()}
}

// WithVersion records the build version for /healthz and the Atom generator.
func (s *Server) WithVersion(v string) *Server {
	s.version = v
	return s
}

// Handler returns the fully configured HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/vulns", s.auth(s.handleList))
	mux.HandleFunc("GET /v1/vulns/{id}", s.auth(s.handleGet))
	mux.HandleFunc("GET /v1/vulns/{id}/history", s.auth(s.handleHistory))
	mux.HandleFunc("GET /v1/export", s.auth(s.handleExport))
	mux.HandleFunc("GET /v1/stats", s.auth(s.handleStats))
	mux.HandleFunc("GET /v1/sources", s.auth(s.handleSources))
	mux.HandleFunc("GET /v1/attribution", s.auth(s.handleAttribution))
	mux.HandleFunc("POST /v1/scan", s.auth(s.handleScan))
	mux.HandleFunc("POST /v1/scan/target", s.auth(s.handleScanTarget))
	mux.HandleFunc("GET /v1/feed.atom", s.auth(s.handleAtom))
	// Every /v1 path is behind the token, including ones that do not exist.
	// Without this, an unknown /v1/... URL fell through to the unauthenticated
	// catch-all and told an anonymous caller which endpoints are real.
	//
	// Both catch-alls are registered without a method: Go's mux refuses a
	// method-qualified general pattern alongside a method-free specific one,
	// and the method check belongs in the handler anyway.
	mux.HandleFunc("/v1/", s.auth(s.handleNotFound))
	mux.HandleFunc("/", s.handleIndex)

	return logging(s.log, mux)
}

// auth enforces the optional bearer token.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIToken == "" {
			next(w, r)
			return
		}
		got, ok := bearerToken(r.Header.Get("Authorization"))
		// Constant-time comparison: a byte-wise != leaks the token prefix
		// through response timing.
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.APIToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cvefeed"`)
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		next(w, r)
	}
}

// bearerToken extracts the credential from an Authorization header. RFC 7235
// makes the scheme case-insensitive, and a bare token with no scheme at all is
// not a bearer credential.
func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	return rest, rest != ""
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		// Deferred rather than sequenced after ServeHTTP: a handler that breaks
		// the connection on purpose does so by panicking with
		// http.ErrAbortHandler, and the export does exactly that when a stream
		// fails mid-way. Those are the requests most worth a log line, and a
		// plain call after ServeHTTP never ran for them. The panic continues
		// past the deferred call, so net/http still sees it.
		defer func() {
			log.Info("request",
				"method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration", time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(rec, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the wrapped writer so streaming endpoints keep working.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the writer underneath so http.ResponseController can reach
// it. The controller looks for SetReadDeadline and friends on the writer it is
// handed, and when that is this wrapper it finds nothing and reports
// ErrNotSupported — which made the body-read deadlines below silently
// inoperative behind the logging middleware.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// bodyReadTimeout bounds how long a handler waits for a request body to arrive
// in full. The server has no ReadTimeout — it would start at accept time and
// cut off long exports — so the bound lives with the two handlers that read a
// body. 64 MB at a few KB/s is many minutes; a client that slow is not
// uploading an inventory.
const bodyReadTimeout = 2 * time.Minute

// limitBodyRead arms the read deadline for the current request's body.
//
// The failure is deliberately not fatal: a ResponseWriter that cannot set one
// — httptest's recorder, or HTTP/2 on older toolchains — reports
// http.ErrNotSupported, and refusing to serve because a deadline could not be
// armed would be a worse outcome than serving without it.
func limitBodyRead(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))
}

// ------------------------------------------------------------------ handlers

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET is supported")
		return
	}
	if r.URL.Path != "/" {
		s.handleNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "cvefeed",
		"version": s.version,
		"endpoints": []string{
			"GET /healthz",
			"GET /readyz",
			"GET /v1/vulns",
			"GET /v1/vulns/{id}",
			"GET /v1/vulns/{id}/history",
			"GET /v1/export?format=ndjson|csv",
			"GET /v1/stats",
			"GET /v1/sources",
			"GET /v1/attribution",
			"POST /v1/scan",
			"POST /v1/scan/target",
			"GET /v1/feed.atom",
		},
		// Upstream terms of use require these notices to accompany the data.
		"notice":      store.NVDNotice,
		"attribution": "GET /v1/attribution",
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "no such endpoint")
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
		"uptime":  time.Since(s.started).Round(time.Second).String(),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.store.DB().PingContext(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.store.ListVulnerabilities(r.Context(), f)
	if err != nil {
		s.log.Error("list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": res.Total,
		// The limit actually applied, not the one requested: a client paging on
		// this value would otherwise never advance when it defaulted to zero.
		"limit":  res.Limit,
		"offset": res.Offset,
		"items":  res.Items,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := checkText("id", id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := s.store.GetVulnerability(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("%s not found", model.NormalizeID(id)))
		return
	}
	if err != nil {
		s.log.Error("get failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// maxHistoryLimit is the largest page the history endpoint serves. It mirrors
// the store's own ceiling; the store answers a larger request by quietly
// resetting to its default page, and a client paging on the number it asked
// for would then skip entries without noticing. The API's rule for every other
// limit is that an out-of-range value is a 400, not a silent clamp, so the
// same holds here.
const maxHistoryLimit = 500

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := checkText("id", id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > maxHistoryLimit {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be at most %d", maxHistoryLimit))
			return
		}
		limit = n
	}
	entries, err := s.store.History(r.Context(), id, limit)
	if err != nil {
		s.log.Error("history failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	// An empty change log is what the store returns for an identifier it has
	// never heard of, and also for one it knows whose history is empty. Only
	// the second is a 200: answering `{"entries": []}` for a typo tells the
	// caller the record exists and has never changed, which is the opposite of
	// the truth. The existence check runs only on the empty case, so the common
	// path costs one query as before.
	if len(entries) == 0 {
		if _, gerr := s.store.GetVulnerability(r.Context(), id); errors.Is(gerr, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("%s not found", model.NormalizeID(id)))
			return
		} else if gerr != nil {
			s.log.Error("history lookup failed", "id", id, "error", gerr)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": model.NormalizeID(id), "entries": entries})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		s.log.Error("stats failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	states, err := s.store.SourceStates(r.Context())
	if err != nil {
		s.log.Error("source states failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": states})
}

// handleAttribution serves the upstream licence notices. NIST asks every
// service using the NVD API to display its notice, MITRE's terms require the
// copyright and licence to travel with copies, FIRST requests EPSS attribution
// and GHSA is CC-BY — so a service redistributing all of them needs somewhere
// a consumer can actually read them.
func (s *Server) handleAttribution(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.Attributions(r.Context())
	if err != nil {
		s.log.Error("attribution failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"notice":       store.NVDNotice,
		"attributions": rows,
	})
}

// maxInventoryBytes bounds an uploaded inventory. A container SBOM runs to a
// few megabytes; anything past this is not an inventory.
const maxInventoryBytes = 64 << 20

// handleScan tests an uploaded inventory against the corpus.
//
// The body is an SBOM (CycloneDX or SPDX), a newline-separated list of package
// URLs, or a JSON array of package URL strings; the format is sniffed rather
// than declared, because the operator running this has a file, not a
// preference.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	limitBodyRead(w)
	components, err := inventory.Parse(io.LimitReader(r.Body, maxInventoryBytes))
	if err != nil {
		// inventory.Parse already prefixes its errors with "inventory:".
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(components) == 0 {
		writeError(w, http.StatusBadRequest, "inventory contains no components")
		return
	}

	opt, qerr := scanOptionsFromQueryErr(r.URL.Query())
	if err := qerr; err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	scanner := &scan.Scanner{Store: s.store}
	report, err := scanner.Scan(r.Context(), components, opt)
	if err != nil {
		s.log.Error("scan failed", "components", len(components), "error", err)
		writeError(w, http.StatusInternalServerError, "scan failed")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleExport streams the full result set. NDJSON is the default because a
// multi-hundred-thousand record JSON array is unusable for consumers and hostile
// to memory on both ends.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The export honours every documented filter, including limit, offset and
	// order_by; silently ignoring them made "give me the top 1000 by score" a
	// full-corpus download in an arbitrary order.

	// Rows are counted because the failure has two very different shapes. A
	// query that never returned a row has committed nothing to the wire — the
	// CSV header sits in the csv.Writer's buffer, the NDJSON encoder has not
	// been called — so a real 500 is still available and is what the client
	// gets. A stream that fails after rows have gone out has already sent a
	// 200, and the only honest thing left is to append a marker the client can
	// detect and then break the connection, so that a consumer who looks only
	// at "did the download finish cleanly" cannot mistake the output for
	// complete. Ending the response normally after the marker was the previous
	// behaviour, and curl reported success on every truncated export.
	rows := 0
	// The decision is made on bytes that reached net/http, not on rows
	// handed to an encoder. The csv.Writer sits on a 4 KB buffer, so "rows >
	// 0" was true for a stream that failed on its third row while the header
	// and every row were still in memory and the status line was still free;
	// those exports went out as a 200 with a marker on the end, for a client
	// that could have been told plainly.
	out := &countingWriter{ResponseWriter: w}
	// Flush is the csv.Writer's for CSV and the ResponseWriter's for NDJSON.
	// For CSV it must run before the marker: the csv.Writer buffers, and
	// writing the marker straight to w put it in front of the rows it was
	// meant to follow.
	var flush func()

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "ndjson", "csv":
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("format must be ndjson or csv, got %q", format))
		return
	}
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="cvefeed-export.csv"`)
		noSniff(w)
		cw := csv.NewWriter(out)
		flush = cw.Flush
		if err := cw.Write([]string{"id", "state", "published", "modified", "rating", "score",
			"vector", "epss", "kev", "cwes", "title"}); err != nil {
			return
		}
		err = s.streamVulnerabilities()(r.Context(), f, func(v *store.ExportRecord) error {
			sev := store.PickPrimarySeverity(v.Severities)
			score, vector, rating := "", "", ""
			if sev != nil {
				rating, vector = sev.Rating, sev.Vector
				if sev.Score > 0 {
					score = strconv.FormatFloat(sev.Score, 'f', 1, 64)
				}
			}
			rows++
			return cw.Write([]string{
				csvSafe(v.ID), csvSafe(v.State), fmtTime(v.Published), fmtTime(v.Modified),
				csvSafe(rating), score, csvSafe(vector),
				// The enrichment columns come from the record itself so the
				// header is not advertising data the rows never carry.
				fmtFloat(v.EPSSScore), fmtBool(v.InKEV),
				csvSafe(strings.Join(v.CWEs, " ")), csvSafe(v.Title),
			})
		})
	default:
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		noSniff(w)
		enc := json.NewEncoder(out)
		flusher, _ := w.(http.Flusher)
		flush = func() {
			if flusher != nil {
				flusher.Flush()
			}
		}
		err = s.streamVulnerabilities()(r.Context(), f, func(v *store.ExportRecord) error {
			if err := enc.Encode(v); err != nil {
				return err
			}
			if rows++; rows%500 == 0 {
				flush()
			}
			return nil
		})
	}

	if err == nil || errors.Is(err, context.Canceled) {
		// A client that went away gets nothing more; a client that stayed gets
		// whatever the csv.Writer still holds.
		flush()
		return
	}

	s.log.Error("export failed", "rows", rows, "bytes", out.written, "error", err)
	if out.written == 0 {
		// Nothing has reached the client, so the response can still say what
		// happened in the status line. The CSV header and any rows still in
		// the csv.Writer are dropped with its buffer, and the attachment
		// disposition goes with them: an error body should not arrive as a
		// download named cvefeed-export.csv.
		w.Header().Del("Content-Disposition")
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	flush()
	fmt.Fprintf(w, "\n{\"error\":\"export truncated: %s\"}\n", jsonEscape(err.Error()))
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	// net/http treats this panic as "close the connection without a clean
	// end": no terminating chunk, so the client's transfer errors instead of
	// completing. The logging middleware logs the request from a defer, so the
	// truncated export still appears in the access log.
	panic(http.ErrAbortHandler)
}

// countingWriter records how many bytes a handler has handed to net/http,
// which is the only measure of what a client may already have. It forwards
// Flush and exposes the writer underneath for the same reasons statusRecorder
// does: the export streams, and http.ResponseController looks past wrappers.
type countingWriter struct {
	http.ResponseWriter
	written int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.written += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// ----------------------------------------------------------------- atom feed

// maxAtomEntries and defaultAtomEntries bound the feed page.
const (
	maxAtomEntries     = 200
	defaultAtomEntries = 50
)

type atomFeed struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	Title     string   `xml:"title"`
	Updated   string   `xml:"updated"`
	ID        string   `xml:"id"`
	Generator string   `xml:"generator,omitempty"`
	Rights    string   `xml:"rights,omitempty"`
	Author    struct {
		Name string `xml:"name"`
	} `xml:"author"`
	SelfLink struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
		Type string `xml:"type,attr"`
	} `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title   string `xml:"title"`
	ID      string `xml:"id"`
	Updated string `xml:"updated"`
	Summary string `xml:"summary"`
	Link    struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
}

func (s *Server) handleAtom(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The feed's page is smaller than the query endpoint's because a reader
	// polls it on a schedule; 200 entries is already more than any reader
	// shows. Above that is a 400 like every other out-of-range limit, not a
	// quiet reset to 50 that left the caller believing they had asked for more.
	if f.Limit > maxAtomEntries {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be at most %d", maxAtomEntries))
		return
	}
	if f.Limit <= 0 {
		f.Limit = defaultAtomEntries
	}
	f.OrderBy = "modified"

	res, err := s.store.ListVulnerabilities(r.Context(), f)
	if err != nil {
		s.log.Error("atom failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	self := absoluteURL(r)
	feed := atomFeed{
		Title: "cvefeed aggregated vulnerabilities",
		// A feed id must be stable: deriving it from the query string gave
		// every filter combination a different feed identity, so readers could
		// never recognise two requests as the same feed.
		ID:        "urn:cvefeed:feed",
		Updated:   time.Now().UTC().Format(time.RFC3339),
		Generator: "cvefeed " + s.version,
		Rights:    store.NVDNotice,
	}
	feed.Author.Name = "cvefeed"
	feed.SelfLink.Rel = "self"
	feed.SelfLink.Type = "application/atom+xml"
	feed.SelfLink.Href = self

	for i := range res.Items {
		v := res.Items[i]
		title := v.ID
		if v.Title != "" {
			title = v.ID + " — " + v.Title
		}
		e := atomEntry{
			Title:   title,
			ID:      "urn:cvefeed:" + v.ID,
			Updated: fmtTime(v.Modified),
			Summary: truncate(v.Description, 800),
		}
		if e.Updated == "" {
			e.Updated = feed.Updated
		}
		e.Link.Rel = "alternate"
		e.Link.Href = canonicalURL(v.ID)
		feed.Entries = append(feed.Entries, e)
	}

	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	noSniff(w)
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		s.log.Error("atom encode failed", "error", err)
	}
}

// canonicalURL points at the upstream that owns the identifier. Sending every
// entry to cve.org produced a dead link for every GHSA, EUVD, GCVE, PYSEC and
// distribution advisory in the feed — which is most of the non-CVE coverage the
// service exists to provide.
func canonicalURL(id string) string {
	switch {
	case model.IsCVE(id):
		return "https://www.cve.org/CVERecord?id=" + id
	case model.IsGHSA(id):
		return "https://github.com/advisories/" + id
	case model.IsEUVD(id):
		return "https://euvd.enisa.europa.eu/vulnerability/" + id
	case model.IsGCVE(id):
		return "https://vulnerability.circl.lu/vuln/" + id
	default:
		return "https://osv.dev/vulnerability/" + id
	}
}

func absoluteURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// ------------------------------------------------------------------- helpers

// filterParams is every query parameter the list-shaped endpoints read.
// Anything else is refused rather than ignored: a caller who misspells a
// filter (severity=HIGH, published_from=...) would otherwise receive the
// whole unfiltered corpus with a 200, and read it as "nothing matched my
// filter" or, worse, as the filtered answer.
var filterParams = map[string]bool{
	"q": true, "cpe": true, "purl": true, "product": true, "vendor": true, "ecosystem": true,
	"order_by": true, "kev": true, "modified_since": true, "published_since": true,
	"score_min": true, "score_max": true, "epss_min": true, "rating": true, "state": true,
	"source": true, "cwe": true, "limit": true, "offset": true,
	// Read by the export handler only, but a query-string that names it on
	// the other list endpoints is an honest mistake, not a misspelling.
	"format": true,
}

// validState is the record states the parsers emit (CVE 5 cveMetadata.state,
// OSV withdrawn), which is what the store's state column can hold.
var validState = map[string]bool{
	"PUBLISHED": true, "REJECTED": true, "WITHDRAWN": true, "RESERVED": true,
}

// unknownParams names the query parameters a request carries that the
// endpoint does not read, in a stable order for the error message.
func unknownParams(q url.Values, known map[string]bool) []string {
	var out []string
	for k := range q {
		if !known[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// checkText refuses a parameter PostgreSQL cannot take. A NUL byte in a text
// operand is rejected by the server with an encoding error, which surfaced
// here as a 500 for a request that was malformed, not a query that failed.
func checkText(name, v string) error {
	if strings.IndexByte(v, 0) >= 0 {
		return fmt.Errorf("%s must not contain a NUL byte", name)
	}
	return nil
}

func parseFilter(r *http.Request) (store.ListFilter, error) {
	q := r.URL.Query()
	if bad := unknownParams(q, filterParams); len(bad) > 0 {
		return store.ListFilter{}, fmt.Errorf("unknown query parameter %q; the filters are %s",
			bad[0], strings.Join(sortedKeys(filterParams), ", "))
	}
	for k, vs := range q {
		for _, v := range vs {
			if err := checkText(k, v); err != nil {
				return store.ListFilter{}, err
			}
		}
	}
	f := store.ListFilter{
		Text:      strings.TrimSpace(q.Get("q")),
		CPE:       strings.TrimSpace(q.Get("cpe")),
		PURL:      strings.TrimSpace(q.Get("purl")),
		Product:   strings.TrimSpace(q.Get("product")),
		Vendor:    strings.TrimSpace(q.Get("vendor")),
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		OrderBy:   strings.TrimSpace(q.Get("order_by")),
	}

	if raw := q.Get("kev"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return f, fmt.Errorf("kev must be true or false, got %q", raw)
		}
		f.KEVOnly = b
	}
	if f.OrderBy != "" && !validOrderBy[f.OrderBy] {
		return f, fmt.Errorf("order_by must be one of modified, published, score, epss, id; got %q", f.OrderBy)
	}

	var err error
	if f.ModifiedSince, err = parseTimeParam(q.Get("modified_since")); err != nil {
		return f, fmt.Errorf("modified_since: %w", err)
	}
	if f.PublishedSince, err = parseTimeParam(q.Get("published_since")); err != nil {
		return f, fmt.Errorf("published_since: %w", err)
	}
	if f.ScoreMin, err = parseFloatParam(q.Get("score_min")); err != nil {
		return f, fmt.Errorf("score_min: %w", err)
	}
	if f.ScoreMax, err = parseFloatParam(q.Get("score_max")); err != nil {
		return f, fmt.Errorf("score_max: %w", err)
	}
	if f.EPSSMin, err = parseFloatParam(q.Get("epss_min")); err != nil {
		return f, fmt.Errorf("epss_min: %w", err)
	}
	// A threshold outside the scale is a typo, not a filter: score_min=99 or
	// epss_min=2 can only ever return nothing, and an empty page looks exactly
	// like a corpus with nothing that severe in it.
	if err := checkRange("score_min", f.ScoreMin, 0, 10); err != nil {
		return f, err
	}
	if err := checkRange("score_max", f.ScoreMax, 0, 10); err != nil {
		return f, err
	}
	if err := checkRange("epss_min", f.EPSSMin, 0, 1); err != nil {
		return f, err
	}
	if f.ScoreMin != nil && f.ScoreMax != nil && *f.ScoreMin > *f.ScoreMax {
		return f, fmt.Errorf("score_min (%g) is above score_max (%g)", *f.ScoreMin, *f.ScoreMax)
	}

	f.Ratings = splitCSV(q.Get("rating"))
	for _, rt := range f.Ratings {
		if !validRating[strings.ToUpper(rt)] {
			return f, fmt.Errorf("rating must be one of NONE, LOW, MEDIUM, HIGH, CRITICAL; got %q", rt)
		}
	}
	f.States = splitCSV(q.Get("state"))
	for _, st := range f.States {
		if !validState[strings.ToUpper(st)] {
			return f, fmt.Errorf("state must be one of %s; got %q", strings.Join(sortedKeys(validState), ", "), st)
		}
	}
	f.Sources = splitCSV(q.Get("source"))
	for _, src := range f.Sources {
		if !validSource[strings.ToLower(src)] {
			return f, fmt.Errorf("source must be one of %s; got %q", strings.Join(config.AllSources(), ", "), src)
		}
	}
	f.CWEs = splitCSV(q.Get("cwe"))

	if raw := q.Get("limit"); raw != "" {
		n, cerr := strconv.Atoi(raw)
		if cerr != nil || n < 1 {
			return f, fmt.Errorf("limit must be a positive integer")
		}
		if n > store.MaxPageSize {
			return f, fmt.Errorf("limit must be at most %d", store.MaxPageSize)
		}
		f.Limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, cerr := strconv.Atoi(raw)
		if cerr != nil || n < 0 {
			return f, fmt.Errorf("offset must be a non-negative integer")
		}
		f.Offset = n
	}
	return f, nil
}

var validOrderBy = map[string]bool{
	"modified": true, "published": true, "score": true, "epss": true, "id": true,
}

var validRating = map[string]bool{
	"NONE": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

// validSource is the collector names, which are the only values the sources
// column ever holds.
var validSource = func() map[string]bool {
	out := map[string]bool{}
	for _, name := range config.AllSources() {
		out[name] = true
	}
	return out
}()

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkRange refuses a stated threshold outside the scale it filters on.
func checkRange(name string, v *float64, lo, hi float64) error {
	if v == nil {
		return nil
	}
	if *v < lo || *v > hi {
		return fmt.Errorf("%s must be between %g and %g, got %g", name, lo, hi, *v)
	}
	return nil
}

func parseTimeParam(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if t := model.ParseTime(raw); t != nil {
		return t, nil
	}
	return nil, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", raw)
}

func parseFloatParam(raw string) (*float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil, fmt.Errorf("expected a number, got %q", raw)
	}
	return &f, nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func fmtFloat(f float64) string {
	if f <= 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', 5, 64)
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// csvSafe neutralises spreadsheet formula injection. Upstream titles and vendor
// strings are attacker-influenced text, and a cell starting with =, +, - or @
// is executed on open by Excel and LibreOffice.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// truncate cuts to at most max bytes without splitting a UTF-8 rune. Slicing
// blind produced invalid UTF-8 in the Atom summary of every non-ASCII record.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func jsonEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// noSniff disables content-type sniffing on a response. Every body this
// service writes carries upstream text — titles, descriptions, vendor strings —
// and without the header a browser can be talked into rendering a CSV, an
// NDJSON line or an Atom summary as HTML. It used to be set on JSON only, which
// left exactly the formats a person opens in a browser tab unprotected.
func noSniff(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	noSniff(w)
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		// The status line is already written; nothing useful remains to do.
		return
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// scanParams is every query parameter the scan endpoints read.
var scanParams = map[string]bool{"min_confidence": true, "undecidable": true}

// scanOptionsFromQueryErr reads the scan knobs off the query string.
//
// The floor defaults to scan.DefaultMinConfidence rather than to the zero
// value, so a caller who names no preference gets the same answer here as they
// would from `cvefeed scan`.
func scanOptionsFromQueryErr(q url.Values) (scan.Options, error) {
	opt := scan.Options{MinConfidence: scan.DefaultMinConfidence}
	if bad := unknownParams(q, scanParams); len(bad) > 0 {
		return opt, fmt.Errorf("unknown query parameter %q; the options are min_confidence and undecidable", bad[0])
	}
	if raw := strings.TrimSpace(q.Get("undecidable")); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return opt, fmt.Errorf("undecidable must be true or false, got %q", raw)
		}
		opt.IncludeUndecidable = b
	}
	if raw := strings.TrimSpace(q.Get("min_confidence")); raw != "" {
		c := match.Confidence(strings.ToLower(raw))
		switch c {
		case match.Confirmed, match.Probable, match.Possible:
			opt.MinConfidence = c
		default:
			return opt, errors.New("min_confidence must be one of confirmed, probable, possible")
		}
	}
	return opt, nil
}

// targetRequest is the body of POST /v1/scan/target.
type targetRequest struct {
	Host  string `json:"host"`
	Ports string `json:"ports,omitempty"`
	// TimeoutSeconds bounds each connection. It is capped rather than trusted:
	// a large value on a large port list holds a server worker for a long time.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Engine selects how the host is examined: auto, builtin, nmap or masscan.
	Engine string `json:"engine,omitempty"`
	// Rate is masscan's packets per second, capped below.
	Rate int `json:"rate,omitempty"`
}

// maxMasscanRate caps how fast a caller may make this service emit packets.
// masscan's own default is millions per second, which saturates a link and
// reads as an attack from the other end.
const maxMasscanRate = 20000

// maxTargetPorts bounds one request. A full 65,535-port sweep through a shared
// service is a different operation from a scan, and the caller who wants one
// should run the command against the host directly rather than borrow the
// server's network position to do it.
const maxTargetPorts = 1024

// maxTargetHosts bounds a range requested over HTTP. A /24 is a reasonable
// thing to ask a service for; a /16 is an hours-long operation that should be
// started deliberately from a command line, where it can be watched and stopped.
const maxTargetHosts = 256

// handleScanTarget probes a host and tests what answered against the corpus.
//
// Disabled unless the operator turned it on: it makes the service open
// connections to a host the caller names, which is a capability the rest of
// this API does not have and which reaches wherever the service reaches.
func (s *Server) handleScanTarget(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.TargetScanEnabled {
		writeError(w, http.StatusForbidden,
			"target scanning is disabled; set CVEFEED_TARGET_SCAN_ENABLED=true to enable it")
		return
	}
	limitBodyRead(w)
	var req targetRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object with a \"host\"")
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}

	// A range over the API is a different proposition from one on a command
	// line: the caller is borrowing this service's network position, and the
	// bill for a wide sweep is paid by whoever runs it. The cap is far tighter
	// than the command's for that reason.
	tg, err := netscan.ParseTargets(req.Host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if tg.Len() > maxTargetHosts {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%s names %d addresses; at most %d per request over the API — "+
				"run a wider sweep with the command instead", req.Host, tg.Len(), maxTargetHosts))
		return
	}

	ports := netscan.DefaultPorts()
	if req.Ports != "" {
		if ports, err = netscan.ParsePorts(req.Ports); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if len(ports) > maxTargetPorts {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("at most %d ports per request, got %d", maxTargetPorts, len(ports)))
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
	}

	opt, err := scanOptionsFromQueryErr(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	engine := netscan.Engine(strings.ToLower(strings.TrimSpace(req.Engine)))
	if engine == "" {
		engine = netscan.EngineAuto
	}
	if !netscan.ValidEngine(engine) {
		writeError(w, http.StatusBadRequest, "engine must be auto, builtin, nmap or masscan")
		return
	}
	rate := req.Rate
	if rate > maxMasscanRate {
		rate = maxMasscanRate
	}

	// Named in the log before the first packet, so a scan nobody meant to run
	// is visible while it is running rather than afterwards — and after the
	// last validation, so that a request refused for a bad engine does not
	// leave a line saying a scan was run against the host.
	s.log.Info("target scan requested", "host", req.Host, "ports", len(ports), "engine", string(engine))

	probe, err := netscan.New(netscan.Options{
		Timeout: timeout, Engine: engine, Rate: rate,
		Resolver: storeVendorResolver{s.store},
	}).Run(r.Context(), req.Host, ports)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("probe failed: %s", err))
		return
	}

	report, err := (&scan.Scanner{Store: s.store}).Scan(r.Context(), probe.Components(), opt)
	if err != nil {
		s.log.Error("target scan failed", "host", req.Host, "error", err)
		writeError(w, http.StatusInternalServerError, "scan failed")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		*scan.Report
		Probe *netscan.Sweep `json:"probe"`
	}{report, probe})
}

// storeVendorResolver lets the corpus overrule a scanner's CPE vendor.
type storeVendorResolver struct{ st *store.Store }

func (r storeVendorResolver) VendorsFor(ctx context.Context, product string) ([]string, error) {
	if r.st == nil {
		return nil, nil
	}
	return r.st.CPEVendorsFor(ctx, product)
}
