package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/netscan"
	"github.com/00gxd14g/cvefeed/internal/scan"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// stdout is a data channel: `scan -format json` and `export` write a document
// there. A log line on the same stream makes the document unparseable, which is
// only discovered by whoever pipes the output into a JSON reader.
//
// The scan is run without a reachable database on purpose. It logs the
// inventory it read before it ever opens the store, so the run exercises the
// logging path and then fails, which is all this test needs: it asserts on the
// stream the records landed on, not on the scan succeeding.
func TestDiagnosticsDoNotContaminateTheDataStream(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	binName := "cvefeed"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(t.TempDir(), binName)
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "scan", "-sbom", "../../testdata/target-system.cdx.json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(),
		"CVEFEED_LOG_LEVEL=debug",
		// Nothing listens here; the store open fails after the logging is done.
		"CVEFEED_DATABASE_URL=postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
	)
	_ = cmd.Run()

	if !strings.Contains(stderr.String(), "inventory read") {
		t.Fatalf("the run never reached the logging path, so this proves nothing.\nstdout: %s\nstderr: %s",
			stdout.String(), stderr.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var rec struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Level != "" && rec.Msg != "" {
			t.Fatalf("a log record reached stdout and would corrupt a JSON document there: %s", line)
		}
	}
}

// Someone who brings the stack up and then runs the command gets whatever
// database error the driver produced — "password authentication failed", or a
// refused connection — and no indication that a setting is involved at all. The
// message has to name the DSN it tried and the variable that changes it, and it
// must not print the password while doing so.
func TestAnUnreachableDatabaseSaysWhichOneAndHowToChangeIt(t *testing.T) {
	err := describeStoreFailure(
		"postgres://cvefeed:local-dev-password@localhost:5432/cvefeed?sslmode=disable",
		errors.New(`pq: password authentication failed for user "cvefeed"`))

	msg := err.Error()
	if strings.Contains(msg, "local-dev-password") {
		t.Fatalf("the password is in the error: %s", msg)
	}
	for _, want := range []string{
		"password authentication failed", // the original cause survives
		"postgres://cvefeed:", "localhost:5432/cvefeed",
		"CVEFEED_DATABASE_URL",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestRedactDSNKeepsEverythingButTheSecret(t *testing.T) {
	cases := map[string]string{
		"postgres://u:hunter2@host:5432/db?sslmode=disable": "postgres://u:xxxxx@host:5432/db?sslmode=disable",
		"postgres://u@host:5432/db":                         "postgres://u@host:5432/db",
		"host=localhost user=cvefeed password=hunter2":      "host=localhost user=cvefeed password=xxxxx",
		"not a dsn": "not a dsn",
	}
	for in, want := range cases {
		if got := redactDSN(in); got != want {
			t.Errorf("redactDSN(%q) = %q, want %q", in, got, want)
		}
	}
}

// A host can run the same software twice — OpenSSH on 22 and again on 2222,
// at different versions — and both are vulnerable to the same CVE. Printing the
// address without the port makes those two findings read as one duplicated
// line, and the reader cannot tell which service to go and fix.
func TestAFindingSaysWhichServiceItIsAbout(t *testing.T) {
	cases := map[string]string{
		"netscan:10.0.10.221:22":   "10.0.10.221:22",
		"netscan:10.0.10.221:2222": "10.0.10.221:2222",
		"netscan:example.org:443":  "example.org:443",
		// A bare address with no port is still worth naming.
		"netscan:10.0.10.221": "10.0.10.221",
		// Other inventory sources have no host at all.
		"cyclonedx": "",
		"spdx":      "",
		"":          "",
	}
	for origin, want := range cases {
		if got := originLabel(origin); got != want {
			t.Errorf("originLabel(%q) = %q, want %q", origin, got, want)
		}
	}
}

// A pipeline gating on the scan has to tell "the scan ran and found something"
// from "the scan could not run": a database that was down must not read as a
// clean host, and a host with findings must not read as a broken tool.
func TestScanExitStatusDistinguishesFindingsFromFailure(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"findings":         {errFindings{n: 3}, exitFindings},
		"wrapped findings": {fmt.Errorf("scan: %w", errFindings{n: 1}), exitFindings},
		"failure":          {errors.New("dial tcp: connection refused"), exitError},
	}
	for name, tc := range cases {
		if got := exitStatus(tc.err); got != tc.want {
			t.Errorf("%s: exitStatus = %d, want %d", name, got, tc.want)
		}
	}
}

// The README promises a non-zero status when anything is found. The JSON path
// used to return straight from the encoder, so the format a pipeline actually
// scripts against was the one that exited 0 on a report full of findings. Both
// output paths now end in the same decision.
func TestFindingsDecideTheStatusWhateverTheFormat(t *testing.T) {
	if err := findingsStatus(&scan.Report{}); err != nil {
		t.Errorf("a clean report returned %v, want nil", err)
	}
	err := findingsStatus(&scan.Report{Findings: make([]scan.Finding, 2)})
	var found errFindings
	if !errors.As(err, &found) || found.n != 2 {
		t.Fatalf("a report with findings returned %v, want errFindings{2}", err)
	}
	if exitStatus(err) != exitFindings {
		t.Errorf("exitStatus(%v) = %d, want %d", err, exitStatus(err), exitFindings)
	}
}

// The flag package accepts one dash or two, so `scan --v` parses cleanly; the
// pre-parse check that decides the log level has to agree with it, or the
// double-dash spelling is accepted and then logs nothing.
// A sweep the auto engine declined has no hosts, and so does a silent range.
// Reading the first as the second reported "nothing answered on any probed
// port of any address" for a target nothing was ever sent to, and the plan
// note — the only place that said so, and said what to do — was never
// printed. The declined sweep gets its report in both formats and an error
// that says it was not attempted, on the exit status of a scan that could
// not run.
func TestADeclinedSweepIsReportedAndEndsTheRunAsNotAttempted(t *testing.T) {
	sweep := &netscan.Sweep{
		Target: "10.0.0.0/16", HostsTotal: 65534, Ports: 1000, Declined: true,
		Plan: &netscan.Plan{
			Discovery: "direct", Identification: "not attempted",
			Note: "the built-in prober was the only engine left, and 10.0.0.0/16 at 1000 ports is " +
				"65534000 connections; nothing was examined. Install nmap or masscan",
		},
	}

	var text bytes.Buffer
	err := reportDeclined(&text, sweep, "text")
	var declined errDeclined
	if !errors.As(err, &declined) {
		t.Fatalf("reportDeclined returned %v, want errDeclined", err)
	}
	for _, want := range []string{"the sweep was not attempted", "nothing was examined", "Install nmap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if got := exitStatus(err); got != exitError {
		t.Errorf("exitStatus = %d, want %d: a sweep that did not run is a scan that could not run", got, exitError)
	}
	for _, want := range []string{"SCAN  10.0.0.0/16", "not attempted", "nothing was examined", "Install nmap"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report lacks %q:\n%s", want, text.String())
		}
	}
	if strings.Contains(text.String(), "were not looked at — use -ports all") {
		t.Errorf("text report offers -ports all for a sweep that did not run:\n%s", text.String())
	}

	var js bytes.Buffer
	if err := reportDeclined(&js, sweep, "json"); !errors.As(err, &declined) {
		t.Fatalf("reportDeclined(json) returned %v, want errDeclined", err)
	}
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
		Probe    struct {
			Declined bool `json:"declined"`
			Plan     struct {
				Note string `json:"note"`
			} `json:"plan"`
		} `json:"probe"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
		t.Fatalf("JSON output does not parse: %v\n%s", err, js.String())
	}
	if !doc.Probe.Declined || !strings.Contains(doc.Probe.Plan.Note, "nothing was examined") {
		t.Errorf("JSON probe = %+v, want declined with the note", doc.Probe)
	}
	if doc.Findings != nil {
		t.Errorf("JSON carries findings for a scan that never ran: %s", js.String())
	}
}

// The recording and the bundle can each come from a flag or from the
// environment, and the message used to name one fixed pair — "unset
// CVEFEED_BUNDLE_PATH or drop -record" — whichever pair was actually in play.
// Someone whose .env set CVEFEED_RECORD_PATH was told to drop a flag they had
// not passed.
func TestTheRecordBundleConflictNamesTheSettingsActuallyInUse(t *testing.T) {
	cases := []struct {
		name                   string
		recordFlag, bundleFlag bool
		want, wantNot          []string
	}{
		{"both flags", true, true,
			[]string{"-record", "-bundle", "drop -record", "drop -bundle"},
			[]string{"CVEFEED_RECORD_PATH", "CVEFEED_BUNDLE_PATH"}},
		{"record flag, bundle from the environment", true, false,
			[]string{"drop -record", "unset CVEFEED_BUNDLE_PATH"},
			[]string{"CVEFEED_RECORD_PATH", "-bundle"}},
		{"record from the environment, bundle flag", false, true,
			[]string{"unset CVEFEED_RECORD_PATH", "drop -bundle"},
			[]string{"-record", "CVEFEED_BUNDLE_PATH"}},
		{"both from the environment", false, false,
			[]string{"unset CVEFEED_RECORD_PATH", "unset CVEFEED_BUNDLE_PATH"},
			[]string{"-record", "-bundle"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := recordBundleConflict(tc.recordFlag, tc.bundleFlag, "/rec", "/bundle").Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("message does not mention %q: %s", w, msg)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(msg, w) {
					t.Errorf("message names %q, which is not in use: %s", w, msg)
				}
			}
			if !strings.Contains(msg, "/rec") || !strings.Contains(msg, "/bundle") {
				t.Errorf("message does not name both paths: %s", msg)
			}
		})
	}
}

func TestHasFlagAcceptsEitherDashSpelling(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-sbom", "bom.json", "-v"}, true},
		{[]string{"-sbom", "bom.json", "--v"}, true},
		{[]string{"--v=true"}, true},
		{[]string{"-v=true"}, true},
		{[]string{"-sbom", "bom.json"}, false},
		{[]string{"-sbom", "-v"}, true}, // a value that looks like the flag is still the flag to fs.Parse
		{[]string{"--", "-v"}, false},   // after the terminator nothing is a flag
		{[]string{"-verbose"}, false},   // a different flag, not a prefix match
		{[]string{"v"}, false},          // a bare word is a positional argument
	}
	for _, tc := range cases {
		if got := hasFlag(tc.args, "-v"); got != tc.want {
			t.Errorf("hasFlag(%q, -v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// The JSON report carries the suppressed findings; the text report used to
// drop them, so an operator comparing it with another scanner's output had no
// way to see that a CVE was missing on purpose, or whose statement said so.
func TestCoverageNamesTheStatementThatRetiredAFinding(t *testing.T) {
	report := &scan.Report{
		Findings: []scan.Finding{},
		Suppressed: []scan.Finding{{
			Component:     match.Component{Name: "marked", Version: "4.0.9"},
			Vulnerability: store.VulnSummary{ID: "CVE-2026-0030"},
			Statement:     scan.Statement{Source: "osv", PURL: "pkg:npm/marked"},
			RetiredBy:     &scan.Statement{Source: "csaf", Vendor: "acme", Product: "marked", Status: "known_not_affected"},
		}},
		Counts: map[match.Confidence]int{},
		Notice: "notice",
	}
	var out bytes.Buffer
	printCoverage(&out, report)
	text := out.String()
	for _, want := range []string{
		"1 finding(s) were retired",
		"CVE-2026-0030 on marked 4.0.9",
		"retired by csaf known_not_affected for acme/marked",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("coverage does not say %q:\n%s", want, text)
		}
	}

	// Nothing suppressed, nothing said: the line would be noise.
	out.Reset()
	printCoverage(&out, &scan.Report{Findings: []scan.Finding{}, Counts: map[match.Confidence]int{}, Notice: "notice"})
	if strings.Contains(out.String(), "retired") {
		t.Errorf("coverage mentions retired findings when there are none:\n%s", out.String())
	}
}

// Flag values that can only produce a misleading run are refused before any
// inventory is read or database opened: `-format jsno` used to print the text
// report, and a negative probe timeout reported every host as silent.
func TestScanRefusesFlagValuesThatWouldMisleadTheRun(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := map[string][]string{
		"bad format":           {"-sbom", "x", "-format", "xml"},
		"negative timeout":     {"-target", "127.0.0.1", "-probe-timeout", "-1s"},
		"zero timeout":         {"-target", "127.0.0.1", "-probe-timeout", "0"},
		"negative max-hosts":   {"-target", "127.0.0.1", "-max-hosts", "-1"},
		"negative concurrency": {"-target", "127.0.0.1", "-host-concurrency", "-2"},
		"negative rate":        {"-target", "127.0.0.1", "-rate", "-5"},
	}
	for name, args := range cases {
		err := cmdScan(context.Background(), log, args)
		if err == nil {
			t.Errorf("%s: cmdScan(%v) = nil, want a refusal", name, args)
			continue
		}
		if exitStatus(err) != exitError {
			t.Errorf("%s: exit status %d, want %d", name, exitStatus(err), exitError)
		}
	}
	if err := noArguments("migrate", []string{"-x"}); err == nil {
		t.Error("migrate -x was accepted")
	}
}
