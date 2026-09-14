package config

import (
	"strings"
	"testing"
	"time"
)

// clearEnv resets every variable this package reads to the empty string so
// tests are isolated from whatever happens to be set in the ambient
// environment: env() treats an empty value the same as unset.
func clearEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"CVEFEED_DATABASE_URL", "CVEFEED_LISTEN_ADDR", "CVEFEED_API_TOKEN",
		"CVEFEED_NVD_API_KEY", "CVEFEED_GITHUB_TOKEN", "CVEFEED_VULNCHECK_TOKEN",
		"CVEFEED_USER_AGENT", "CVEFEED_BUNDLE_PATH", "CVEFEED_RECORD_PATH",
		"CVEFEED_VULNLOOKUP_URL", "CVEFEED_SCHEDULE_ENABLED", "CVEFEED_OFFLINE_ONLY",
		"CVEFEED_TARGET_SCAN_ENABLED",
		"CVEFEED_HTTP_TIMEOUT", "CVEFEED_HTTP_MAX_RETRIES", "CVEFEED_INGEST_BATCH_SIZE",
		"CVEFEED_CSAF_PROVIDERS",
	}
	for name := range DefaultIntervals() {
		keys = append(keys, "CVEFEED_INTERVAL_"+strings.ToUpper(name))
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", c.ListenAddr)
	}
	if c.HTTPTimeout != 120*time.Second {
		t.Errorf("HTTPTimeout = %v, want 120s", c.HTTPTimeout)
	}
	if c.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", c.MaxRetries)
	}
	if c.IngestBatchSize != 500 {
		t.Errorf("IngestBatchSize = %d, want 500", c.IngestBatchSize)
	}
	if !c.ScheduleEnabled {
		t.Error("ScheduleEnabled = false, want true")
	}
	if c.OfflineOnly {
		t.Error("OfflineOnly = true, want false")
	}
	if !c.AllowNetwork() {
		t.Error("AllowNetwork = false, want true when offline/bundle unset")
	}
	if len(c.Intervals) != len(DefaultIntervals()) {
		t.Errorf("Intervals has %d entries, want %d", len(c.Intervals), len(DefaultIntervals()))
	}
}

func TestLoadCSAFProviders(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_CSAF_PROVIDERS", "https://a.example/, , https://b.example/csaf/provider-metadata.json")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"https://a.example/", "https://b.example/csaf/provider-metadata.json"}
	if len(c.CSAFProviders) != len(want) {
		t.Fatalf("CSAFProviders = %v, want %v", c.CSAFProviders, want)
	}
	for i := range want {
		if c.CSAFProviders[i] != want[i] {
			t.Errorf("CSAFProviders[%d] = %q, want %q", i, c.CSAFProviders[i], want[i])
		}
	}
}

func TestLoadIntervalOverride(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_INTERVAL_NVD", "30m")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Intervals["nvd"] != 30*time.Minute {
		t.Errorf("Intervals[nvd] = %v, want 30m", c.Intervals["nvd"])
	}
	// Untouched sources keep their default.
	if c.Intervals["kev"] != 1*time.Hour {
		t.Errorf("Intervals[kev] = %v, want 1h (default)", c.Intervals["kev"])
	}
}

func TestLoadIntervalOverrideInvalid(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_INTERVAL_NVD", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with an invalid interval override should fail")
	}
}

func TestLoadIntervalOverrideNonPositive(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_INTERVAL_NVD", "0s")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with a non-positive interval override should fail")
	}
}

func TestLoadInvalidBatchSize(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_INGEST_BATCH_SIZE", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with batch size 0 should fail")
	}
}

func TestLoadInvalidTimeout(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_HTTP_TIMEOUT", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with an unparsable timeout should fail")
	}
}

func TestLoadOfflineOnlyDisablesNetwork(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_OFFLINE_ONLY", "true")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.AllowNetwork() {
		t.Error("AllowNetwork = true, want false when CVEFEED_OFFLINE_ONLY=true")
	}
}

func TestLoadBundlePathDisablesNetwork(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_BUNDLE_PATH", "/data/bundle")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.AllowNetwork() {
		t.Error("AllowNetwork = true, want false when a bundle path is set")
	}
}

func TestVulnLookupURLTrimsTrailingSlash(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_VULNLOOKUP_URL", "https://vulnerability.circl.lu/")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.VulnLookupURL != "https://vulnerability.circl.lu" {
		t.Errorf("VulnLookupURL = %q, want trailing slash trimmed", c.VulnLookupURL)
	}
}

func TestAllSourcesMatchesDefaultIntervals(t *testing.T) {
	all := AllSources()
	intervals := DefaultIntervals()
	if len(all) != len(intervals) {
		t.Fatalf("AllSources has %d entries, DefaultIntervals has %d", len(all), len(intervals))
	}
	for _, name := range all {
		if _, ok := intervals[name]; !ok {
			t.Errorf("source %q has no default interval", name)
		}
	}
}

// An empty CVEFEED_DATABASE_URL is a variable someone cleared, not a DSN
// someone chose. It used to reach the driver as an empty string.
func TestAnEmptyDatabaseURLCountsAsUnset(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_DATABASE_URL", "   ")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.DatabaseURL == "" || strings.TrimSpace(c.DatabaseURL) != c.DatabaseURL {
		t.Errorf("DatabaseURL = %q, want the default DSN rather than the empty value", c.DatabaseURL)
	}
}

// CVEFEED_TARGET_SCAN_ENABLED opens an endpoint that makes the service connect
// to hosts of the caller's choosing. A typo in it silently became "off", so an
// operator who thought they had enabled it — or one who thought they had
// spelled "false" — could not tell from the process that they had not.
func TestAnUnreadableTargetScanSettingIsAnError(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_TARGET_SCAN_ENABLED", "yes-please")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with an unparsable CVEFEED_TARGET_SCAN_ENABLED should fail")
	}
	t.Setenv("CVEFEED_TARGET_SCAN_ENABLED", "true")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !c.TargetScanEnabled {
		t.Error("TargetScanEnabled = false, want true")
	}
}

// A zero timeout is "no timeout" to net/http, and a negative one is nonsense.
func TestTheHTTPTimeoutMustBePositive(t *testing.T) {
	for _, v := range []string{"0s", "-5s"} {
		clearEnv(t)
		t.Setenv("CVEFEED_HTTP_TIMEOUT", v)
		if _, err := Load(); err == nil {
			t.Errorf("Load() with CVEFEED_HTTP_TIMEOUT=%s should fail", v)
		}
	}
}

func TestAnUnreadableScheduleSettingIsAnError(t *testing.T) {
	clearEnv(t)
	t.Setenv("CVEFEED_SCHEDULE_ENABLED", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with an unparsable CVEFEED_SCHEDULE_ENABLED should fail")
	}
}
