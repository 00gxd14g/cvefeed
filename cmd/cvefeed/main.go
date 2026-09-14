// Command cvefeed aggregates public vulnerability feeds into one queryable
// corpus and serves it over HTTP.
//
// Subcommands:
//
//	migrate                     create or update the database schema
//	ingest [flags]              run collectors once
//	serve                       run the API and the scheduler
//	scan [flags]                report which corpus records apply to a system
//	sources                     print collector state
//	bundle pack   <dir> <file>  wrap a recorded bundle for transport
//	bundle unpack <file> <dir>  expand a transported bundle
//	bundle info   <dir>         summarise a bundle
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/00gxd14g/cvefeed/internal/airgap"
	"github.com/00gxd14g/cvefeed/internal/api"
	"github.com/00gxd14g/cvefeed/internal/collect"
	"github.com/00gxd14g/cvefeed/internal/config"
	"github.com/00gxd14g/cvefeed/internal/httpx"
	"github.com/00gxd14g/cvefeed/internal/inventory"
	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/netscan"
	"github.com/00gxd14g/cvefeed/internal/progress"
	"github.com/00gxd14g/cvefeed/internal/scan"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// version is stamped at build time with -ldflags "-X main.version=...".
// Without this declaration the linker flag in the Makefile and Dockerfile was
// silently discarded and the binary reported nothing at all.
var version = "dev"

// Exit statuses. A pipeline gating on `scan` has to tell "the scan ran and
// found something" from "the scan could not run" — a database that was down
// must not read as a clean host, and a host with findings must not read as a
// broken tool — so the two get different codes.
//
// A sweep the auto engine declined to run (errDeclined) is "the scan could
// not run": nothing was examined, so there is no clean host to report, and no
// findings either. It exits 1 like any other failure to run, with a message
// that says the sweep was not attempted and why.
const (
	exitError    = 1 // the command failed, or `scan -target` was not attempted
	exitFindings = 2 // `scan` completed and at least one vulnerability applies
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cvefeed: %v\n", err)
		os.Exit(exitStatus(err))
	}
}

// exitStatus maps a failed run to its process status.
func exitStatus(err error) int {
	var found errFindings
	if errors.As(err, &found) {
		return exitFindings
	}
	return exitError
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no subcommand given")
	}

	// `scan` writes a report for a person to read; the others write a log for a
	// machine to collect. Emitting structured records around a report buries it
	// in the terminal — the reader has to pick the answer out of the
	// bookkeeping — so scan is quiet unless something went wrong, or -v asks.
	level := os.Getenv("CVEFEED_LOG_LEVEL")
	if level == "" && len(os.Args) > 1 && os.Args[1] == "scan" && !hasFlag(os.Args[2:], "-v") {
		level = "warn"
	}
	log := newLogger(level).With("version", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first Ctrl-C cancels the context and the command starts shutting
	// down: the server drains, a sweep stops handing out addresses. While the
	// signal is still being caught, a second Ctrl-C is swallowed the same way
	// and a shutdown that hangs — a scan blocked in a long read, a database
	// call that will not return — cannot be interrupted at all. Restoring the
	// default disposition the moment the context is cancelled makes the second
	// Ctrl-C do what it does everywhere else: kill the process.
	context.AfterFunc(ctx, stop)

	switch os.Args[1] {
	case "migrate":
		return cmdMigrate(ctx, log, os.Args[2:])
	case "ingest":
		return cmdIngest(ctx, log, os.Args[2:])
	case "serve":
		return cmdServe(ctx, log, os.Args[2:])
	case "sources":
		return cmdSources(ctx, log, os.Args[2:])
	case "scan":
		return cmdScan(ctx, log, os.Args[2:])
	case "bundle":
		return cmdBundle(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("cvefeed", version)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cvefeed — aggregated public vulnerability feed service

USAGE
  cvefeed migrate
  cvefeed ingest [-sources a,b,c] [-mode delta|backfill] [-record DIR] [-bundle DIR] [-since RFC3339|YYYY-MM-DD]
  cvefeed serve  [-addr :8080] [-no-schedule]
  cvefeed scan   [-sbom FILE | -purls FILE | -local | -target HOST] [-ports SPEC] [-engine auto|builtin|nmap|masscan]
                 [-min-confidence confirmed|probable|possible] [-undecidable] [-explain] [-format text|json] [-v]
                 (cvefeed scan -h lists the sweep tuning flags: -max-hosts, -host-concurrency, -probe-timeout, -rate)
  cvefeed sources
  cvefeed version
  cvefeed bundle pack   <dir> <file.tar.gz>
  cvefeed bundle unpack <file.tar.gz> <dir>
  cvefeed bundle info   <dir>

ENVIRONMENT
  CVEFEED_DATABASE_URL   postgres connection string
  CVEFEED_NVD_API_KEY    raises the NVD rate limit from 5 to 50 requests / 30s
  CVEFEED_GITHUB_TOKEN   raises the GitHub API rate limit
  CVEFEED_API_TOKEN      when set, /v1 requires this bearer token
  CVEFEED_CSAF_PROVIDERS comma separated CSAF provider base URLs
  CVEFEED_LOG_LEVEL      debug | info | warn | error

EXIT STATUS
  0  success; for scan, nothing in the corpus applies to the inventory
  1  the command failed (bad flags, unreachable database, unreadable input,
     or a -target sweep that examined nothing: the engine declined to run,
     or no address answered on any probed port)
  2  scan completed and at least one vulnerability applies, in every -format

See README.md for the full list.
`)
}

func newLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	// Diagnostics go to stderr because stdout is a data channel: `scan -format
	// json` and `export` write a document there, and a log line interleaved
	// with it makes the document unparseable. Found by piping a scan into jq.
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// openStore connects and, when migrate is set, brings the schema up to date.
//
// Only the commands that own the database migrate it: migrate, ingest and
// serve. A read-only command — scan, sources — checks the schema and refuses a
// stale one instead. Migrations take an exclusive lock and some of them run
// for tens of minutes; a `cvefeed scan` started from a shell while the API
// container is mid-upgrade should wait for nothing and change nothing.
func openStore(ctx context.Context, cfg *config.Config, migrate bool) (*store.Store, error) {
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, describeStoreFailure(cfg.DatabaseURL, err)
	}
	if migrate {
		err = st.Migrate(ctx)
	} else {
		err = st.CheckSchema(ctx)
	}
	if err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// buildFetcher decides between the online client and the offline bundle reader.
// Everything downstream is identical either way.
func buildFetcher(cfg *config.Config, log *slog.Logger) (httpx.Fetcher, func() error, error) {
	if cfg.BundlePath != "" {
		f, err := airgap.NewFetcher(cfg.BundlePath, true)
		if err != nil {
			return nil, nil, err
		}
		created, entries, bytes := f.Info()
		log.Info("running offline from bundle",
			"path", cfg.BundlePath, "captured_at", created.Format(time.RFC3339),
			"entries", entries, "bytes", bytes)
		return f, f.Close, nil
	}
	if cfg.OfflineOnly {
		return nil, nil, errors.New("offline mode requested but no bundle path set (CVEFEED_BUNDLE_PATH)")
	}

	var rec *airgap.Recorder
	opts := httpx.ClientOptions{
		Timeout:    cfg.HTTPTimeout,
		UserAgent:  cfg.UserAgent,
		MaxRetries: cfg.MaxRetries,
	}
	if cfg.RecordPath != "" {
		r, err := airgap.NewRecorder(cfg.RecordPath)
		if err != nil {
			return nil, nil, err
		}
		rec = r
		opts.Recorder = r
		log.Info("recording responses for air-gap transfer", "path", cfg.RecordPath)
	}

	client := httpx.NewClient(opts)
	if cfg.NVDAPIKey != "" {
		client.SetHostHeader("services.nvd.nist.gov", "apiKey", cfg.NVDAPIKey)
		// With a key the documented ceiling is 50 per 30 seconds; stay under it.
		// NIST still asks for ~6 s between calls, so keep the spacing floor —
		// the burst allowance is not the constraint that earns a 403.
		client.SetHostRateInterval("services.nvd.nist.gov", 45, 30*time.Second, 6*time.Second)
	}
	if cfg.GitHubToken != "" {
		client.SetHostHeader("api.github.com", "Authorization", "Bearer "+cfg.GitHubToken)
		// A token raises the GitHub ceiling from 60 to 5,000 requests an hour.
		client.SetHostRate("api.github.com", 4500, time.Hour)
	}
	if cfg.VulnCheckToken != "" {
		client.SetHostHeader("api.vulncheck.com", "Authorization", "Bearer "+cfg.VulnCheckToken)
	}

	closer := func() error {
		if rec != nil {
			if err := rec.Flush(); err != nil {
				return err
			}
			entries, bytes := rec.Stats()
			log.Info("bundle written", "path", cfg.RecordPath, "entries", entries, "bytes", bytes)
		}
		return client.Close()
	}
	return client, closer, nil
}

// noArguments refuses arguments to a command that takes none. `migrate -x`
// used to run the migration and drop the flag on the floor, so a typo for
// another command's flag looked as if it had been honoured.
func noArguments(name string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments or flags, got %q", name, strings.Join(args, " "))
	}
	return nil
}

func cmdMigrate(ctx context.Context, log *slog.Logger, args []string) error {
	if err := noArguments("migrate", args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg, true)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("schema is up to date")
	return nil
}

func cmdIngest(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	sources := fs.String("sources", "", "comma separated collector names (default: all)")
	mode := fs.String("mode", "delta", "delta or backfill")
	record := fs.String("record", "", "record every response into this bundle directory")
	bundle := fs.String("bundle", "", "serve every request from this bundle directory (offline)")
	skipUnchanged := fs.Bool("skip-unchanged", true, "skip records whose raw document is unchanged")
	since := fs.String("since", "", "replay from this instant (RFC3339 or YYYY-MM-DD) instead of the stored cursor")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var replayFrom *time.Time
	if strings.TrimSpace(*since) != "" {
		t := model.ParseTime(*since)
		if t == nil {
			return fmt.Errorf("-since: expected RFC3339 or YYYY-MM-DD, got %q", *since)
		}
		replayFrom = t
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *record != "" {
		cfg.RecordPath = *record
	}
	if *bundle != "" {
		cfg.BundlePath = *bundle
	}
	// A bundle replaces the network and a recording captures it, so the two
	// cannot both be meant. buildFetcher used to take the bundle and drop the
	// recording without a word, which bit anyone whose .env carried
	// CVEFEED_BUNDLE_PATH from the air-gapped side: `ingest -record DIR` ran,
	// reported success, and wrote nothing into DIR. Refusing is the only answer
	// that does not guess which of the two settings was the stale one.
	if cfg.RecordPath != "" && cfg.BundlePath != "" {
		return recordBundleConflict(*record != "", *bundle != "", cfg.RecordPath, cfg.BundlePath)
	}

	m := collect.Mode(strings.ToLower(*mode))
	if m != collect.ModeDelta && m != collect.ModeBackfill {
		return fmt.Errorf("mode must be delta or backfill, got %q", *mode)
	}

	names := config.AllSources()
	if strings.TrimSpace(*sources) != "" {
		names = nil
		for _, n := range strings.Split(*sources, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}

	st, err := openStore(ctx, cfg, true)
	if err != nil {
		return err
	}
	defer st.Close()

	fetcher, closeFetcher, err := buildFetcher(cfg, log)
	if err != nil {
		return err
	}
	// A failed bundle flush must not be reported as a successful harvest.
	defer func() {
		if cerr := closeFetcher(); cerr != nil {
			log.Error("fetcher shutdown failed", "error", cerr)
		}
	}()

	sink := &collect.StoreSink{
		Store: st, Log: log, SkipUnchanged: *skipUnchanged, QueueDepth: cfg.IngestBatchSize,
	}
	defer sink.Close()
	runner := &collect.Runner{
		Registry:   collect.NewRegistry(cfg),
		Store:      st,
		Fetcher:    fetcher,
		Cfg:        cfg,
		Log:        log,
		Sink:       sink,
		ReplayFrom: replayFrom,
	}

	start := time.Now()
	runErr := runner.RunAll(ctx, names, m)
	log.Info("ingest complete",
		"mode", string(m), "sources", strings.Join(names, ","),
		"written", sink.Written.Load(), "unchanged", sink.Unchanged.Load(),
		"failed", sink.Failed.Load(), "duration", time.Since(start).Round(time.Second))
	return runErr
}

func cmdServe(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "", "listen address (default from CVEFEED_LISTEN_ADDR)")
	noSchedule := fs.Bool("no-schedule", false, "serve the API without running collectors")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	if *noSchedule {
		cfg.ScheduleEnabled = false
	}

	st, err := openStore(ctx, cfg, true)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.New(st, cfg, log).WithVersion(version).Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		// No WriteTimeout: the export endpoint streams the full corpus and a
		// deadline here would truncate large downloads mid-flight.
		//
		// No ReadTimeout either, for the mirror-image reason: it would start
		// counting at accept time and cut off a long export the same way. The
		// two handlers that read a body (/v1/scan, /v1/scan/target) set their own
		// read deadline through http.ResponseController, so a client that opens
		// a 64 MB upload and then trickles it cannot hold a worker indefinitely.
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", cfg.ListenAddr, "auth", cfg.APIToken != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	schedulerDone := make(chan struct{})
	if cfg.ScheduleEnabled {
		go func() {
			defer close(schedulerDone)
			runScheduler(ctx, cfg, st, log)
		}()
	} else {
		close(schedulerDone)
		log.Info("scheduler disabled")
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		// The collectors hold the same *store.Store the deferred Close will
		// release. Returning while they are mid-transaction closes the pool
		// underneath them, which loses whatever the run had not yet committed
		// — including the cursor it was about to save.
		select {
		case <-schedulerDone:
		case <-time.After(45 * time.Second):
			log.Warn("scheduler did not stop in time; closing anyway")
		}
		return shutdownErr
	}
}

// runScheduler polls each source on its own cadence. Sources run sequentially
// inside one goroutine per source, but never concurrently with themselves, so
// a slow backfill cannot overlap its own next tick.
func runScheduler(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) {
	fetcher, closeFetcher, err := buildFetcher(cfg, log)
	if err != nil {
		log.Error("scheduler cannot start", "error", err)
		return
	}
	defer func() {
		if err := closeFetcher(); err != nil {
			log.Error("fetcher shutdown failed", "error", err)
		}
	}()

	var wg sync.WaitGroup
	sources := config.AllSources()
	for i, name := range sources {
		interval, ok := cfg.Intervals[name]
		if !ok || interval <= 0 {
			continue
		}
		wg.Add(1)
		go func(idx int, name string, interval time.Duration) {
			defer wg.Done()

			// Each source gets its own sink. A shared StoreSink means every
			// collector's Drain() waits for every other collector's queue, and
			// its sync.WaitGroup is then Add()ed concurrently with Wait() —
			// which panics and takes the whole service down.
			sink := &collect.StoreSink{
				Store: st, Log: log, SkipUnchanged: true, QueueDepth: cfg.IngestBatchSize,
			}
			defer sink.Close()
			runner := &collect.Runner{
				Registry: collect.NewRegistry(cfg),
				Store:    st,
				Fetcher:  fetcher,
				Cfg:      cfg,
				Log:      log,
				Sink:     sink,
			}

			// Stagger by position, not by name length: several collector names
			// are the same length, so the old scheme fired six of them at once.
			jitter := time.Duration(idx) * 20 * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter):
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				if err := runner.RunOne(ctx, name, collect.ModeDelta); err != nil {
					log.Warn("scheduled run failed", "source", name, "error", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}(i, name, interval)
	}

	wg.Wait()
}

// cmdScan compares an inventory of installed software against the corpus.
func cmdScan(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	sbom := fs.String("sbom", "", "inventory file: CycloneDX or SPDX JSON (- for stdin)")
	purls := fs.String("purls", "", "inventory file: one package URL per line (- for stdin)")
	local := fs.Bool("local", false, "inventory this host through dpkg, rpm and apk")
	target := fs.String("target", "",
		"inventory hosts over the network: an address, a hostname, or a CIDR block such as 10.0.0.0/24")
	maxHosts := fs.Int("max-hosts", defaultMaxHosts,
		"refuse a range larger than this without being told again; 0 removes the limit")
	hostConc := fs.Int("host-concurrency", 0, "addresses examined at once in a range (default 16)")
	ports := fs.String("ports", "",
		"ports to probe with -target: a list like \"22,80,443,8000-8100\", \"top:N\" for the N "+
			"most commonly open, or \"all\" (default: all where masscan is installed, top:1000 otherwise)")
	netTimeout := fs.Duration("probe-timeout", 5*time.Second, "per-connection timeout for -target")
	engine := fs.String("engine", "auto",
		"how to examine -target: auto, builtin, nmap, or masscan (auto uses whichever of nmap and masscan are installed)")
	rate := fs.Int("rate", 0, "masscan packets per second (default 1000)")
	minConf := fs.String("min-confidence", string(scan.DefaultMinConfidence),
		"report findings at least this strong: confirmed, probable or possible")
	undecidable := fs.Bool("undecidable", false,
		"also list the statements the corpus could not decide")
	format := fs.String("format", "text", "text or json")
	explain := fs.Bool("explain", false,
		"print why each finding matched: the identity, the ordering scheme, and the comparison")
	// Declared so it appears in -h and is accepted; the level it sets was
	// decided in run(), before the report's own output began.
	_ = fs.Bool("v", false, "log what the scan is doing as well as reporting what it found")
	if err := fs.Parse(args); err != nil {
		return err
	}

	source := ""
	for _, choice := range []struct {
		name string
		set  bool
	}{{"-sbom", *sbom != ""}, {"-purls", *purls != ""}, {"-local", *local}, {"-target", *target != ""}} {
		if !choice.set {
			continue
		}
		if source != "" {
			return fmt.Errorf("choose one inventory source, not %s and %s", source, choice.name)
		}
		source = choice.name
	}
	if source == "" {
		return errors.New("no inventory: pass -sbom, -purls, -local or -target")
	}
	if *target == "" {
		for name, set := range map[string]bool{
			"-ports": *ports != "", "-max-hosts": *maxHosts != defaultMaxHosts,
			"-host-concurrency": *hostConc != 0, "-rate": *rate != 0,
		} {
			if set {
				return fmt.Errorf("%s only means something with -target", name)
			}
		}
	}
	if !netscan.ValidEngine(netscan.Engine(*engine)) {
		return fmt.Errorf("-engine must be auto, builtin, nmap or masscan, got %q", *engine)
	}
	if !strings.EqualFold(*format, "text") && !strings.EqualFold(*format, "json") {
		// Refused rather than read as text: a pipeline that asked for
		// -format jsno and got a human report would try to parse it.
		return fmt.Errorf("-format must be text or json, got %q", *format)
	}
	// A negative probe timeout fails every connection before it is made and
	// the run then reports "nothing answered", which reads as a quiet host.
	if *netTimeout <= 0 {
		return fmt.Errorf("-probe-timeout must be positive, got %v", *netTimeout)
	}
	for name, v := range map[string]int{"-max-hosts": *maxHosts, "-host-concurrency": *hostConc, "-rate": *rate} {
		if v < 0 {
			return fmt.Errorf("%s must not be negative, got %d", name, v)
		}
	}

	conf := match.Confidence(strings.ToLower(*minConf))
	switch conf {
	case match.Confirmed, match.Probable, match.Possible:
	default:
		return fmt.Errorf("-min-confidence must be confirmed, probable or possible, got %q", *minConf)
	}

	var (
		sweep      *netscan.Sweep
		components []match.Component
		skipped    []inventory.Skip
		st         *store.Store
		err        error
	)
	// The store opens where each source needs it, not before both. A probe
	// consults the corpus while it runs — an external scanner's CPE vendor is
	// checked against what the corpus files the product under — so it needs the
	// database first. A file-based inventory does not, and opening the database
	// ahead of reading it would report an unreachable database when the real
	// problem is a malformed SBOM.
	openCorpus := func() error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		st, err = openStore(ctx, cfg, false)
		return err
	}

	if *target != "" {
		if err = openCorpus(); err != nil {
			return err
		}
		defer st.Close()
		sweep, err = probeTarget(ctx, log, st, *target, *ports,
			*netTimeout, netscan.Engine(*engine), *rate, *maxHosts, *hostConc)
		if err != nil {
			return err
		}
		if sweep.Declined {
			// Nothing was examined, so there is nothing to test against the
			// corpus: not "nothing answered", which is what falling through
			// used to report. The probe report still goes out, because the
			// plan note is where the reader learns why and what to do.
			return reportDeclined(os.Stdout, sweep, *format)
		}
		components = sweep.Components()
		skipped = netSkips(sweep)
	} else {
		if components, skipped, err = readInventory(ctx, *sbom, *purls, *local); err != nil {
			return err
		}
		// Logged here rather than after the database opens, so a run that reads
		// the inventory and then cannot reach the corpus still says what it
		// read. The two failures send a reader to different places.
		logInventory(log, components, skipped, source)
		if err = openCorpus(); err != nil {
			return err
		}
		defer st.Close()
	}
	// An empty inventory is an error for the file-based sources, where it means
	// the caller pointed at something that is not an inventory. It is not an
	// error for a probe: a host can be reachable, have open ports, and have
	// nothing on them that names its own version. Refusing to report then would
	// throw away the coverage gap at exactly the moment it was discovered.
	if len(components) == 0 {
		if sweep == nil {
			return errors.New("inventory contains no components")
		}
		if len(skipped) == 0 {
			return fmt.Errorf("%s: nothing answered on any probed port of any address", sweep.Target)
		}
	}
	if sweep != nil {
		logInventory(log, components, skipped, source)
	}

	scanner := &scan.Scanner{Store: st}
	report, err := scanner.Scan(ctx, components, scan.Options{
		MinConfidence:      conf,
		IncludeUndecidable: *undecidable,
	})
	if err != nil {
		return err
	}

	if strings.EqualFold(*format, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		var doc any = report
		if sweep != nil {
			// The probe's own result is part of the answer, not context for it:
			// which addresses answered, on which ports, and which of those
			// nothing could be said about. A caller consuming JSON needs all of
			// it, because a host that was never identified is not a host that
			// was found clean.
			doc = scanDocument{report, sweep}
		}
		if err := enc.Encode(doc); err != nil {
			return err
		}
	} else {
		if sweep != nil {
			printProbeReport(os.Stdout, sweep)
		}
		printScanReport(os.Stdout, report, *explain)
	}
	// A scan that found something exits non-zero so it can gate a pipeline.
	// This sits after both output paths on purpose: the JSON path used to return
	// straight from the encoder, so a pipeline that asked for machine-readable
	// output got exit 0 on the very report that listed the findings, and the
	// README's promise held only for the format nobody scripts against.
	return findingsStatus(report)
}

// recordBundleConflict names the two settings that collided and the pair of
// actions that resolve it. Each side can come from a flag or from the
// environment, and the remedy has to name the one actually in use: telling
// someone who set CVEFEED_RECORD_PATH to "drop -record" sends them to a flag
// they never passed, while the variable that is set goes unmentioned.
func recordBundleConflict(recordFlag, bundleFlag bool, recordPath, bundlePath string) error {
	recordVia, recordFix := "CVEFEED_RECORD_PATH", "unset CVEFEED_RECORD_PATH"
	if recordFlag {
		recordVia, recordFix = "-record", "drop -record"
	}
	bundleVia, bundleFix := "CVEFEED_BUNDLE_PATH", "unset CVEFEED_BUNDLE_PATH"
	if bundleFlag {
		bundleVia, bundleFix = "-bundle", "drop -bundle"
	}
	return fmt.Errorf("a recording into %s (%s) and a bundle at %s (%s) cannot be combined: "+
		"a bundle replaces the network the recording would capture (%s, or %s)",
		recordPath, recordVia, bundlePath, bundleVia, recordFix, bundleFix)
}

// scanDocument is the JSON shape of a `scan -target` run: the report's fields
// with the probe beside them.
type scanDocument struct {
	*scan.Report
	Probe *netscan.Sweep `json:"probe"`
}

// reportDeclined writes what a declined sweep has to say and returns the
// error that ends the run.
//
// The output keeps the shape of a completed run — the probe report in text,
// the "probe" member in JSON, with no report fields because there was no
// scan — so a consumer finds the plan note where it would look for one. The
// error is its own type so exitStatus can be sure of it, and it carries the
// note, because "the sweep was not attempted" on its own sends the reader
// back to the output to find out why.
func reportDeclined(w io.Writer, sweep *netscan.Sweep, format string) error {
	if strings.EqualFold(format, "json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(scanDocument{nil, sweep}); err != nil {
			return err
		}
	} else {
		printProbeReport(w, sweep)
	}
	note := ""
	if sweep.Plan != nil {
		note = sweep.Plan.Note
	}
	return errDeclined{note: note}
}

// errDeclined is a sweep the engine refused to run. It exits like any other
// failure to run — nothing was examined — but with a message that says so
// rather than one that could be read as a scanner fault.
type errDeclined struct{ note string }

func (e errDeclined) Error() string {
	if e.note == "" {
		return "the sweep was not attempted"
	}
	return "the sweep was not attempted: " + e.note
}

// findingsStatus is the exit-status decision for a completed scan, shared by
// both output formats so they cannot disagree about it.
func findingsStatus(report *scan.Report) error {
	if len(report.Findings) > 0 {
		return errFindings{n: len(report.Findings)}
	}
	return nil
}

// errFindings makes "the scan worked and found problems" distinguishable from
// "the scan failed", while still giving CI a non-zero status to act on.
type errFindings struct{ n int }

func (e errFindings) Error() string {
	return fmt.Sprintf("%d vulnerabilities apply to this inventory", e.n)
}

func readInventory(ctx context.Context, sbom, purls string, local bool) ([]match.Component, []inventory.Skip, error) {
	switch {
	case local:
		comps, err := inventory.CollectLocal(ctx)
		return comps, nil, err
	case sbom != "":
		return readInventoryFile(sbom, false)
	default:
		return readInventoryFile(purls, true)
	}
}

func readInventoryFile(path string, purlList bool) ([]match.Component, []inventory.Skip, error) {
	in := os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("inventory: %w", err)
		}
		defer f.Close()
		in = f
	}
	if purlList {
		comps, report, err := inventory.ParsePURLListWithReport(in)
		return comps, report.Skipped, err
	}
	comps, err := inventory.Parse(in)
	return comps, nil, err
}

// printScanReport writes the human-facing report.
//
// The shape is chosen so the answer survives being long. An earlier version
// printed each finding's full reasoning underneath it, which is exactly the
// right thing to have and the wrong thing to show by default: eighteen findings
// became eighteen paragraphs, and the reader had to reconstruct "one host, one
// vulnerable service, one of these is being exploited right now" out of a wall
// of prose. So the default is a table that fits on a screen, a summary that
// says what to do first, and -explain for the reasoning behind any of it.
func printScanReport(w io.Writer, report *scan.Report, explain bool) {
	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "No vulnerabilities matched %d component(s) at the requested confidence.\n",
			report.Components)
		printCoverage(w, report)
		return
	}

	fmt.Fprintf(w, "FINDINGS  %d across %d component(s), most urgent first\n\n",
		len(report.Findings), report.Components)
	fmt.Fprintf(w, "  %-9s %-6s %-8s %-18s %s\n", "SEVERITY", "SCORE", "EPSS", "VULNERABILITY", "COMPONENT")
	for _, f := range report.Findings {
		v := f.Vulnerability
		score := ""
		if v.Score > 0 {
			score = fmt.Sprintf("%.1f", v.Score)
		}
		epss := ""
		if v.EPSSScore > 0 {
			epss = strconv.FormatFloat(v.EPSSScore, 'f', 4, 64)
		}
		id := v.ID
		if v.InKEV {
			// The one distinction worth making in the identifier column:
			// somebody is using this today.
			id += " !"
		}
		name := f.Component.Name
		if f.Component.Version != "" {
			name += " " + f.Component.Version
		}
		if where := originLabel(f.Component.Origin); where != "" {
			name += "  on " + where
		}
		fmt.Fprintf(w, "  %-9s %-6s %-8s %-18s %s\n", v.Rating, score, epss, id, name)
		if explain {
			fmt.Fprintf(w, "%s\n\n", indent(f.Evidence.Reason, "      "))
		}
	}

	printSummary(w, report)
	printCoverage(w, report)
	if !explain {
		fmt.Fprintf(w, "\nRun again with -explain to see why each finding matched.\n")
	}
}

// printSummary says what the table means, because a list of eighteen rows does
// not on its own answer "what do I do first".
func printSummary(w io.Writer, report *scan.Report) {
	var kev, high int
	worst := ""
	for _, f := range report.Findings {
		if f.Vulnerability.InKEV {
			kev++
			if worst == "" {
				worst = f.Vulnerability.ID
			}
		}
		switch f.Vulnerability.Rating {
		case "CRITICAL", "HIGH":
			high++
		}
	}
	fmt.Fprintf(w, "\nSUMMARY\n")
	fmt.Fprintf(w, "  %d finding(s): %d confirmed, %d probable, %d possible\n",
		len(report.Findings),
		report.Counts[match.Confirmed], report.Counts[match.Probable], report.Counts[match.Possible])
	fmt.Fprintf(w, "  %d rated high or critical\n", high)
	if kev > 0 {
		fmt.Fprintf(w, "  %d known to be exploited in the wild (marked !) — start with %s\n", kev, worst)
	} else {
		fmt.Fprintf(w, "  none are known to be exploited in the wild\n")
	}
}

// printCoverage says what was not answered, which a report of findings alone
// silently presents as nothing.
func printCoverage(w io.Writer, report *scan.Report) {
	if n := len(report.Undecidable); n > 0 {
		fmt.Fprintf(w, "  %d statement(s) could not be decided and are not counted above\n", n)
	}
	if n := len(report.Suppressed); n > 0 {
		// A finding a vendor's negative statement retired is the one an
		// operator comparing this report with another scanner's will ask
		// about, so the statement that made the difference is named here
		// rather than left for the JSON to carry.
		fmt.Fprintf(w, "  %d finding(s) were retired by a vendor's negative statement and are not counted above:\n", n)
		for _, f := range report.Suppressed {
			name := f.Component.Name
			if f.Component.Version != "" {
				name += " " + f.Component.Version
			}
			by := "a negative statement"
			if r := f.RetiredBy; r != nil {
				by = r.Source + " " + r.Status
				if product := strings.TrimSpace(strings.TrimPrefix(r.Vendor+"/"+r.Product, "/")); product != "" {
					by += " for " + product
				}
			}
			fmt.Fprintf(w, "    %s on %s: retired by %s\n", f.Vulnerability.ID, name, by)
		}
	}
	if n := len(report.Truncated); n > 0 {
		// A component whose candidate set hit the store's limit was not fully
		// checked. Saying nothing would let "no findings" read as "clean".
		fmt.Fprintf(w, "  %d component(s) had more candidate statements than were examined: %s\n",
			n, strings.Join(report.Truncated, ", "))
	}
	fmt.Fprintf(w, "\n%s\n", report.Notice)
}

// originLabel turns an origin like "netscan:10.0.0.7:80" into the address and
// port a finding is about.
//
// The port is not decoration. A host can run the same software twice — OpenSSH
// on 22 and again on 2222, at different versions — and both can be vulnerable
// to the same CVE. Without the port those two findings print as one line
// repeated, and the reader cannot tell which service to go and fix.
func originLabel(origin string) string {
	rest, ok := strings.CutPrefix(origin, "netscan:")
	if !ok {
		return ""
	}
	return rest
}

// indent prefixes every line, wrapping the reasoning so it stays readable
// beside the table it explains.
func indent(text, prefix string) string {
	const width = 92
	var out strings.Builder
	for _, para := range strings.Split(text, "\n") {
		line := prefix
		for _, word := range strings.Fields(para) {
			if len(line)+len(word)+1 > width && len(line) > len(prefix) {
				out.WriteString(line + "\n")
				line = prefix
			}
			if len(line) > len(prefix) {
				line += " "
			}
			line += word
		}
		if len(line) > len(prefix) {
			out.WriteString(line)
		}
	}
	return out.String()
}

func cmdSources(ctx context.Context, log *slog.Logger, args []string) error {
	if err := noArguments("sources", args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg, false)
	if err != nil {
		return err
	}
	defer st.Close()

	states, err := st.SourceStates(ctx)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Println("no collector has run yet")
		return nil
	}

	fmt.Printf("%-14s %-22s %-10s %s\n", "SOURCE", "LAST SUCCESS", "RECORDS", "LAST ERROR")
	for _, s := range states {
		last := "never"
		if s.LastSuccessAt != nil {
			last = s.LastSuccessAt.UTC().Format(time.RFC3339)
		}
		fmt.Printf("%-14s %-22s %-10d %s\n", s.Name, last, s.RecordsSeen, s.LastError)
	}
	return nil
}

func cmdBundle(args []string) error {
	if len(args) == 0 {
		return errors.New("bundle needs a subcommand: pack, unpack or info")
	}
	switch args[0] {
	case "pack":
		if len(args) != 3 {
			return errors.New("usage: cvefeed bundle pack <dir> <file.tar.gz>")
		}
		if err := airgap.Pack(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("packed %s into %s\n", args[1], args[2])
		return nil

	case "unpack":
		if len(args) != 3 {
			return errors.New("usage: cvefeed bundle unpack <file.tar.gz> <dir>")
		}
		if err := airgap.Unpack(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("unpacked %s into %s\n", args[1], args[2])
		return nil

	case "info":
		if len(args) != 2 {
			return errors.New("usage: cvefeed bundle info <dir>")
		}
		f, err := airgap.NewFetcher(args[1], false)
		if err != nil {
			return err
		}
		created, entries, bytes := f.Info()
		fmt.Printf("bundle:   %s\ncaptured: %s\nentries:  %d\nbytes:    %d\n\n",
			args[1], created.UTC().Format(time.RFC3339), entries, bytes)
		for _, u := range f.URLs() {
			fmt.Println("  " + u)
		}
		return nil

	default:
		return fmt.Errorf("unknown bundle subcommand %q", args[0])
	}
}

// probeTarget inventories a host over the network.
//
// This is the one inventory source that touches a machine other than the one it
// runs on, so it says out loud what it is about to do and against whom. Scanning
// a host you are not responsible for is the operator's problem to avoid, and a
// log line naming the target is the least a tool can do to make an accident
// visible while it is still happening.
// defaultMaxHosts is how large a range may be before the caller has to say so
// again.
//
// A /16 is 65,534 addresses, which is a legitimate thing to scan and a long
// operation. A /8 is 16.7 million, which is almost always a typo for something
// smaller — and the cost of finding out the slow way is hours of traffic
// against a network someone else may be watching. The limit is a speed bump in
// front of the mistake, not a judgement about the range.
const defaultMaxHosts = 65536

func probeTarget(ctx context.Context, log *slog.Logger, st *store.Store, target, portSpec string,
	timeout time.Duration, engine netscan.Engine, rate, maxHosts, hostConc int) (*netscan.Sweep, error) {

	tg, err := netscan.ParseTargets(target)
	if err != nil {
		return nil, err
	}
	if maxHosts > 0 && tg.Len() > maxHosts {
		return nil, fmt.Errorf("%s names %d addresses, above the -max-hosts limit of %d; "+
			"raise it (or pass -max-hosts 0) if that is what you meant",
			target, tg.Len(), maxHosts)
	}

	// With masscan present the default is every port, because the ports worth
	// looking at are the ones something answers on and no list of guesses finds
	// those. Without it, a full range means connecting to 65,535 ports one at a
	// time, so the default falls back to the ranking.
	ports := netscan.DefaultPorts()
	switch {
	case portSpec != "":
		if ports, err = netscan.ParsePorts(portSpec); err != nil {
			return nil, err
		}
	case netscan.HasMasscan() && engine != netscan.EngineBuiltin && engine != netscan.EngineNmap:
		ports, _ = netscan.ParsePorts("all")
	}
	// Said out loud before the first packet, and against whom. A sweep nobody
	// meant to start is visible while it is running rather than afterwards.
	log.Info("probing target", "target", tg.String(), "hosts", tg.Len(), "ports", len(ports),
		"engine", string(engine), "nmap", netscan.HasNmap(), "masscan", netscan.HasMasscan())
	if tg.IsRange() && !netscan.HasMasscan() {
		log.Warn("scanning a range without masscan",
			"hosts", tg.Len(), "note", "every address will be connected to in turn")
	}

	bar := progress.New()
	bar.Tick(200 * time.Millisecond)
	defer bar.Done()

	s := netscan.New(netscan.Options{
		Timeout:         timeout,
		Engine:          engine,
		Rate:            rate,
		HostConcurrency: hostConc,
		Progress:        bar,
		// The corpus overrules an external scanner's vendor when the two
		// disagree, because a stale CPE dictionary does not fail loudly.
		Resolver: storeVendors{st},
	})
	sweep, err := s.Run(ctx, target, ports)
	bar.Done()
	if err != nil {
		return nil, fmt.Errorf("probe %s: %w", target, err)
	}
	log.Info("probe finished", "target", sweep.Target,
		"hosts_up", sweep.HostsUp, "hosts_total", sweep.HostsTotal,
		"discovery", sweep.Plan.Discovery, "identification", sweep.Plan.Identification)
	if sweep.Plan.Note != "" {
		// Not a warning: the commonest note is the standing caveat about how
		// stateless discovery works, which accompanies a scan that went
		// entirely to plan. Labelling that "fell back" told the reader
		// something had gone wrong when nothing had.
		log.Info("probe note", "target", sweep.Target, "note", sweep.Plan.Note)
	}
	return sweep, nil
}

// netSkips turns everything the probe could not use into the same skip report
// the file-based inventories produce, so one code path reports coverage gaps
// whatever the inventory came from.
func netSkips(sw *netscan.Sweep) []inventory.Skip {
	var out []inventory.Skip
	for _, h := range sw.Hosts {
		where := h.Addr
		if where == "" {
			where = h.Host
		}
		for _, u := range h.Unidentified {
			out = append(out, inventory.Skip{
				Text:   fmt.Sprintf("%s port %d: %s", where, u.Port, u.Banner),
				Reason: u.Reason,
			})
		}
		for _, s := range h.Open {
			if !s.Scannable() {
				out = append(out, inventory.Skip{
					Text:   fmt.Sprintf("%s port %d: %s", where, s.Port, s.Raw),
					Reason: s.Why(),
				})
			}
		}
	}
	return out
}

// storeVendors adapts the corpus to netscan's resolver.
type storeVendors struct{ st *store.Store }

func (s storeVendors) VendorsFor(ctx context.Context, product string) ([]string, error) {
	if s.st == nil {
		return nil, nil
	}
	return s.st.CPEVendorsFor(ctx, product)
}

// printProbeReport writes what the network probe saw, above the findings.
//
// Ports it could not identify are printed with the same weight as the ones it
// could, because they are the part of the target that was not tested. A report
// that lists findings and says nothing about the ports it could not read
// invites the reader to believe the host has been covered.
func printProbeReport(w io.Writer, sw *netscan.Sweep) {
	fmt.Fprintf(w, "SCAN  %s\n", sw.Target)
	fmt.Fprintf(w, "  %d of %d address(es) answered · %d port(s) each · %s, %s\n",
		sw.HostsUp, sw.HostsTotal, sw.Ports, sw.Plan.Discovery, sw.Plan.Identification)
	switch {
	case sw.Declined:
		// The port arithmetic below is about a sweep that ran. For one that
		// did not, "64,535 ports were not looked at" understates it.
		fmt.Fprintln(w, "  the sweep was not attempted — see the note below")
	case sw.Ports < 65535:
		// A scan that looked at 1,000 of 65,535 ports and found nothing is
		// not the same as a clean host, and the report is the only place that
		// difference can be made visible.
		fmt.Fprintf(w, "  %d port(s) per address were not looked at — use -ports all to cover them\n",
			65535-sw.Ports)
	}
	fmt.Fprintln(w)
	if sw.Plan != nil && sw.Plan.Note != "" {
		fmt.Fprintf(w, "%s\n\n", indent(sw.Plan.Note, "  note: "))
	}

	var untested int
	for _, h := range sw.Hosts {
		where := h.Addr
		if where == "" {
			where = h.Host
		} else if h.Host != "" && h.Host != h.Addr {
			where = fmt.Sprintf("%s (%s)", h.Addr, h.Host)
		}
		fmt.Fprintf(w, "  %s\n", where)
		for _, svc := range h.Open {
			name := svc.Vendor + " " + svc.Product
			state := ""
			if svc.Version != "" {
				name += " " + svc.Version
			} else {
				state = "no version reported — not tested"
				untested++
			}
			fmt.Fprintf(w, "    %-7d %-38s %s\n", svc.Port, name, state)
			if svc.VendorNote != "" {
				fmt.Fprintf(w, "%s\n", indent(svc.VendorNote, "            "))
			}
		}
		for _, u := range h.Unidentified {
			untested++
			what := u.Banner
			if what == "" {
				what = "said nothing"
			}
			fmt.Fprintf(w, "    %-7d %-38s %s\n", u.Port, "unidentified", truncateTo(what, 46))
		}
		fmt.Fprintln(w)
	}
	if untested > 0 {
		fmt.Fprintf(w, "  %d open port(s) were not tested against anything — see above.\n\n", untested)
	}
}

// truncateTo shortens a banner for a column without cutting a rune in half.
func truncateTo(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// logInventory records what an inventory source produced and what it could not
// use.
//
// Entries that never became components are entries that will never be reported
// on. Saying so is the difference between an incomplete answer and one that
// looks complete.
func logInventory(log *slog.Logger, components []match.Component, skipped []inventory.Skip, source string) {
	log.Info("inventory read", "components", len(components), "source", source, "skipped", len(skipped))
	// Info rather than Warn: the report prints the same gaps in the place a
	// reader is looking for them, and a warning that duplicates the answer sits
	// above it as noise. The record stays for anyone collecting logs.
	for _, sk := range skipped {
		if sk.Line > 0 {
			log.Info("inventory entry skipped", "line", sk.Line, "text", sk.Text, "reason", sk.Reason)
			continue
		}
		log.Info("inventory entry skipped", "text", sk.Text, "reason", sk.Reason)
	}
}

// describeStoreFailure turns a driver error into one a reader can act on.
//
// "password authentication failed" and "connection refused" are true and
// useless on their own: they do not say which database was tried, and they do
// not hint that a setting decided it. Someone who brought the stack up with the
// shipped .env and then ran the command outside it hits exactly this, and the
// gap between the compose password and the built-in default is invisible from
// the message alone.
func describeStoreFailure(dsn string, err error) error {
	return fmt.Errorf("%w\n  tried: %s\n  set CVEFEED_DATABASE_URL to change it "+
		"(the compose stack's password is POSTGRES_PASSWORD in .env)",
		err, redactDSN(dsn))
}

// redactDSN removes the password and leaves everything a reader needs to
// recognise which database was meant.
func redactDSN(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
			return u.String()
		}
		return dsn
	}
	// The key/value form, which url.Parse does not reject but does not
	// understand either.
	out := []string{}
	for _, f := range strings.Fields(dsn) {
		if strings.HasPrefix(f, "password=") {
			f = "password=xxxxx"
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

// hasFlag reports whether a bare flag appears in an argument list, before the
// flag package has had a chance to parse it.
//
// The flag package treats one dash and two as the same flag, so `scan --v` is
// accepted by fs.Parse and must be seen here too; comparing the raw argument
// against "-v" alone made the double-dash spelling parse cleanly and then log
// nothing, which is the worst of both.
func hasFlag(args []string, name string) bool {
	want := strings.TrimLeft(name, "-")
	for _, a := range args {
		if a == "--" {
			return false
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		got := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		if got == want || got == want+"=true" {
			return true
		}
	}
	return false
}
