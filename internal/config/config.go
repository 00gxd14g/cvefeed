// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	DatabaseURL string
	ListenAddr  string
	APIToken    string // when set, /v1 endpoints require "Authorization: Bearer <token>"

	NVDAPIKey       string
	GitHubToken     string
	VulnCheckToken  string
	UserAgent       string
	HTTPTimeout     time.Duration
	MaxRetries      int
	IngestBatchSize int

	// Offline / air-gap.
	BundlePath  string // when set, all fetches are served from this bundle
	RecordPath  string // when set, every online fetch is recorded into this bundle
	OfflineOnly bool

	// TargetScanEnabled opens POST /v1/scan/target.
	//
	// Default false, and deliberately so. The endpoint makes the service
	// connect to a host of the caller's choosing, which turns a read-only
	// mirror into something that can reach whatever the service can reach —
	// including hosts on its own network that the caller cannot. That is a
	// meaningful escalation for anyone who obtains the API token, and it should
	// be something an operator switched on rather than something they inherited.
	TargetScanEnabled bool

	// Logging.
	LogLevel string

	// Scheduler.
	ScheduleEnabled bool
	Intervals       map[string]time.Duration

	// CSAF vendor providers to walk (comma separated base URLs or full
	// provider-metadata.json URLs).
	CSAFProviders []string

	// Vulnerability-Lookup / GCVE instance base URL.
	VulnLookupURL string
}

// DefaultIntervals is the per-source polling cadence. These are chosen to match
// how often each upstream actually changes: polling faster only burns rate limit.
func DefaultIntervals() map[string]time.Duration {
	return map[string]time.Duration{
		"cvelist":      1 * time.Hour,  // hourly delta releases
		"nvd":          2 * time.Hour,  // rate limited, lastModStartDate window
		"fkie":         6 * time.Hour,  // bi-hourly upstream sync, yearly files
		"vulnrichment": 1 * time.Hour,  // ADP container updates, published hourly
		"kev":          1 * time.Hour,  // weekday business hours updates
		"epss":         24 * time.Hour, // one model run per day
		"euvd":         6 * time.Hour,  // KEV dump refreshes 07:00 UTC
		"osv":          6 * time.Hour,  // continuous export, modified_id.csv delta
		"ghsa":         6 * time.Hour,  // documented 1-6h band
		"gcve":         24 * time.Hour, // registry rarely changes
		"csaf":         12 * time.Hour, // vendor advisories
	}
}

// AllSources lists every registered collector name in ingestion order. Order
// matters: authoritative CVE records land before the enrichment layers that
// attach to them.
func AllSources() []string {
	return []string{
		"cvelist", "nvd", "fkie", "vulnrichment",
		"osv", "ghsa", "euvd", "gcve", "csaf",
		"kev", "epss",
	}
}

// Load reads configuration from the environment, applying defaults.
//
// A .env file at or above the working directory is read first, without
// displacing anything already in the environment. It is the same file the
// compose stack reads, and not reading it was the difference between `make up`
// succeeding and the command that follows it failing to authenticate against
// the database it just started.
func Load() (*Config, error) {
	dotenv := loadDotenvHere()
	// Whether the DSN was set for real has to be decided before the file is
	// applied, because the file sets it too — and the file's value is written
	// for inside the compose network, where the database answers to a name that
	// exists nowhere else. Reading it back after applying would skip the
	// redirection below and try to resolve "postgres" on this machine.
	// An empty value counts as unset. A compose file or a shell profile that
	// writes CVEFEED_DATABASE_URL= to "clear" it is not choosing an empty
	// DSN, which no driver accepts; it is choosing none, and the file or the
	// built-in default should apply as if the variable were absent.
	envDSN, envDSNSet := os.LookupEnv("CVEFEED_DATABASE_URL")
	envDSN = strings.TrimSpace(envDSN)
	if envDSN == "" {
		envDSNSet = false
	}
	applyDotenv(dotenv)

	databaseURL := envDSN
	if !envDSNSet {
		// The file holds POSTGRES_* rather than a DSN — that is what the
		// database container consumes — so the URL is composed from them, aimed
		// at this machine.
		databaseURL = dsnFromDotenv(dotenv)
		if databaseURL == "" {
			databaseURL = "postgres://cvefeed:cvefeed@localhost:5432/cvefeed?sslmode=disable"
		}
	}

	c := &Config{
		DatabaseURL:    databaseURL,
		ListenAddr:     env("CVEFEED_LISTEN_ADDR", ":8080"),
		APIToken:       env("CVEFEED_API_TOKEN", ""),
		LogLevel:       env("CVEFEED_LOG_LEVEL", "info"),
		NVDAPIKey:      env("CVEFEED_NVD_API_KEY", ""),
		GitHubToken:    env("CVEFEED_GITHUB_TOKEN", ""),
		VulnCheckToken: env("CVEFEED_VULNCHECK_TOKEN", ""),
		// Several upstreams filter on the User-Agent and at least one
		// (Packagist) rejects a request without a mailto contact. The default
		// is deliberately obvious placeholder text so an operator who has not
		// set it can tell from a request log that they have not set it.
		UserAgent: env("CVEFEED_USER_AGENT",
			"cvefeed/1.0 (+https://example.org/cvefeed; mailto=UNSET-set-CVEFEED_USER_AGENT@example.org)"),
		BundlePath:    env("CVEFEED_BUNDLE_PATH", ""),
		RecordPath:    env("CVEFEED_RECORD_PATH", ""),
		VulnLookupURL: strings.TrimRight(env("CVEFEED_VULNLOOKUP_URL", "https://vulnerability.circl.lu"), "/"),
		Intervals:     DefaultIntervals(),
	}

	// Every boolean goes through envBool, which refuses a value it cannot
	// read. Each one guards something that matters when it is wrong:
	// OFFLINE_ONLY keeps an air-gapped host from originating traffic, and
	// TARGET_SCAN_ENABLED opens an endpoint that makes the service connect to
	// hosts of the caller's choosing. A typo in either silently becoming the
	// default is the worst of both outcomes — the operator believes the
	// setting took, and it did not.
	var err error
	if c.ScheduleEnabled, err = envBool("CVEFEED_SCHEDULE_ENABLED", true); err != nil {
		return nil, err
	}
	if c.TargetScanEnabled, err = envBool("CVEFEED_TARGET_SCAN_ENABLED", false); err != nil {
		return nil, err
	}
	if c.OfflineOnly, err = envBool("CVEFEED_OFFLINE_ONLY", false); err != nil {
		return nil, err
	}
	if c.HTTPTimeout, err = envDuration("CVEFEED_HTTP_TIMEOUT", 120*time.Second); err != nil {
		return nil, err
	}
	if c.HTTPTimeout <= 0 {
		// A zero timeout is "no timeout" to net/http, and a negative one is
		// nonsense; neither is what anyone typing the variable meant.
		return nil, fmt.Errorf("CVEFEED_HTTP_TIMEOUT must be positive, got %v", c.HTTPTimeout)
	}
	if c.MaxRetries, err = envInt("CVEFEED_HTTP_MAX_RETRIES", 5); err != nil {
		return nil, err
	}
	if c.IngestBatchSize, err = envInt("CVEFEED_INGEST_BATCH_SIZE", 500); err != nil {
		return nil, err
	}
	if c.IngestBatchSize < 1 {
		return nil, fmt.Errorf("CVEFEED_INGEST_BATCH_SIZE must be >= 1")
	}
	if raw := env("CVEFEED_CSAF_PROVIDERS", ""); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.CSAFProviders = append(c.CSAFProviders, p)
			}
		}
	}

	// Per-source interval overrides: CVEFEED_INTERVAL_NVD=30m
	for name := range c.Intervals {
		key := "CVEFEED_INTERVAL_" + strings.ToUpper(name)
		if raw := env(key, ""); raw != "" {
			d, perr := time.ParseDuration(raw)
			if perr != nil {
				return nil, fmt.Errorf("%s: %w", key, perr)
			}
			if d <= 0 {
				return nil, fmt.Errorf("%s must be positive", key)
			}
			c.Intervals[name] = d
		}
	}

	return c, nil
}

// AllowNetwork reports whether the process may talk to upstreams: not when
// the operator said offline-only, and not when every fetch is served from a
// bundle. It is a method rather than a field computed at Load because the
// ingest command sets BundlePath after loading, and a value fixed at Load
// time would then be wrong for the one caller that cares.
func (c *Config) AllowNetwork() bool {
	return !c.OfflineOnly && c.BundlePath == ""
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) (int, error) {
	raw := env(key, "")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// envBool reports a boolean and refuses to guess. A typo in
// CVEFEED_OFFLINE_ONLY silently falling back to "false" re-enabled outbound
// traffic on a host whose entire purpose was never to originate any.
func envBool(key string, def bool) (bool, error) {
	raw := env(key, "")
	if raw == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean", key, raw)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw := env(key, "")
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// loadDotenvHere finds the .env relative to where the command was run.
func loadDotenvHere() map[string]string {
	dir, err := os.Getwd()
	if err != nil {
		return nil
	}
	return loadDotenv(dir)
}
