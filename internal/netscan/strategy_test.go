package netscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEngineBuiltinNeedsNoToolsInstalled(t *testing.T) {
	port := listenBanner(t, "SSH-2.0-OpenSSH_8.4p1\r\n")

	s := New(Options{Timeout: 2 * time.Second, Engine: EngineBuiltin})
	sw, err := s.Run(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if sw.Plan.Identification != "builtin" {
		t.Errorf("identification = %q, want builtin", sw.Plan.Identification)
	}
	if sw.HostsUp != 1 {
		t.Fatalf("hosts up = %d, want 1", sw.HostsUp)
	}
	if len(sw.Hosts[0].Open) != 1 || sw.Hosts[0].Open[0].Product != "openssh" {
		t.Fatalf("services = %+v", sw.Hosts[0].Open)
	}
}

// Asking for a tool that is not there must fail rather than quietly scanning
// with something weaker: a caller who named an engine chose it for a reason.
func TestDemandingAMissingToolFailsRatherThanDowngrading(t *testing.T) {
	if HasNmap() && HasMasscan() {
		t.Skip("both tools are installed; nothing to be missing")
	}
	s := New(Options{Timeout: time.Second})
	for _, e := range []Engine{EngineNmap, EngineMasscan} {
		if (e == EngineNmap && HasNmap()) || (e == EngineMasscan && HasMasscan()) {
			continue
		}
		s.opt.Engine = e
		if _, err := s.Run(context.Background(), "127.0.0.1", []int{22}); err == nil {
			t.Errorf("-engine %s succeeded although the tool is not installed", e)
		}
	}
}

func TestRunRefusesATargetThatCouldBecomeAnOption(t *testing.T) {
	s := New(Options{Timeout: time.Second, Engine: EngineBuiltin})
	if _, err := s.Run(context.Background(), "--script=evil", []int{22}); err == nil {
		t.Fatal("a target beginning with a dash was accepted")
	}
}

// The corpus gets the last word on the vendor whichever engine identified the
// service, because the built-in table can go stale the same way nmap's does.
func TestBuiltinIdentificationIsAlsoReconciled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("SSH-2.0-OpenSSH_8.4p1\r\n"))
				time.Sleep(2 * time.Second)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	s := New(Options{
		Timeout: 2 * time.Second, Engine: EngineBuiltin,
		Resolver: resolverFunc(func(_ context.Context, product string) ([]string, error) {
			return []string{"somebody_else"}, nil
		}),
	})
	sw, err := s.Run(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if sw.HostsUp != 1 || len(sw.Hosts[0].Open) != 1 {
		t.Fatalf("sweep = %+v", sw)
	}
	svc := sw.Hosts[0].Open[0]
	if svc.Vendor != "somebody_else" {
		t.Errorf("vendor = %q, want the corpus's answer", svc.Vendor)
	}
	if !strings.Contains(svc.VendorNote, "openbsd") {
		t.Errorf("the substitution was not recorded: %q", svc.VendorNote)
	}
}

// masscan returning nothing for a whole sweep is not the same as a target with
// nothing open. It is stateless and drops replies, and it was observed
// returning zero ports for a host that nmap found 23 on moments later. Taking
// that at face value reports the host as silent, which is the failure this
// scanner exists to avoid.
func TestDiscoveryFindingNothingIsCheckedRatherThanBelieved(t *testing.T) {
	port := listenBanner(t, "SSH-2.0-OpenSSH_8.4p1\r\n")

	s := New(Options{Timeout: 2 * time.Second, Engine: EngineBuiltin})
	// A discovery pass that answered "nothing here" for a host that has
	// something. The builtin path does not use masscan, so this asserts the
	// property through the confirm step directly.
	confirmed, engine, sampled, err := s.confirmEmpty(context.Background(),
		mustTargets(t, "127.0.0.1"), []int{port})
	if err != nil {
		t.Fatalf("confirmEmpty: %v", err)
	}
	if len(confirmed) == 0 {
		t.Fatal("a host with an open port was confirmed as empty")
	}
	if engine == "" || sampled != 1 {
		t.Errorf("confirmEmpty reported engine %q over %d addresses, want a named engine over the one host", engine, sampled)
	}
}

// The confirmation is a second look at a target discovery called silent, and
// a discovery pass that dropped every reply dropped them for every address.
// Looking at all 65,534 addresses of a /16 at a thousand ports each is a full
// sweep by the slowest engine there is; a sample answers the same question.
func TestConfirmingASilentRangeChecksASampleNotEveryAddress(t *testing.T) {
	dc := &dialCounter{}
	s := New(Options{Timeout: time.Second, HostConcurrency: 4})
	s.dialer = dc.dial
	s.hasNmap = func() bool { return false }

	hosts, engine, sampled, err := s.confirmEmpty(context.Background(), mustTargets(t, "10.0.0.0/16"), []int{22, 80})
	if err != nil {
		t.Fatalf("confirmEmpty: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("found %d hosts on a network that refuses everything", len(hosts))
	}
	if sampled != confirmHosts || dc.hostCount() != confirmHosts {
		t.Errorf("confirmEmpty reported %d addresses and dialled %d, want %d of the 65534", sampled, dc.hostCount(), confirmHosts)
	}
	if engine != "builtin" {
		t.Errorf("engine = %q, want builtin: nmap was not available", engine)
	}
}

// The report labels its evidence by engine, and the check that follows an
// empty discovery pass falls back to the built-in prober when nmap is missing
// or fails. Labelling that evidence "nmap -sV" claims a version database that
// was never consulted.
func TestTheConfirmationLabelSaysWhichProberDidTheWork(t *testing.T) {
	port := listenBanner(t, "SSH-2.0-OpenSSH_8.4p1\r\n")
	s := New(Options{Timeout: 2 * time.Second})
	s.hasNmap = func() bool { return false }

	hosts, engine, _, err := s.confirmEmpty(context.Background(), mustTargets(t, "127.0.0.1"), []int{port})
	if err != nil {
		t.Fatalf("confirmEmpty: %v", err)
	}
	if len(hosts) != 1 || len(hosts[0].Open) != 1 {
		t.Fatalf("hosts = %+v, want the one service", hosts)
	}
	if engine != "builtin" {
		t.Errorf("engine = %q, want builtin: that is what identified the service", engine)
	}
}

// Auto runs out of engines on a machine with neither masscan nor nmap, and the
// built-in prober is what is left. Handed a /16 at the default ports it would
// open 65 million connections that nobody asked for; the sweep has to decline
// and say so, rather than start something that will be killed hours later
// with nothing to show.
func TestTheFallbackRefusesWorkItCannotFinish(t *testing.T) {
	s := New(Options{Timeout: time.Second})
	s.hasNmap = func() bool { return false }
	s.hasMasscan = func() bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dc := &dialCounter{}
	s.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cancel() // a sweep that started is the failure; stop it at once
		return dc.dial(ctx, network, addr)
	}

	sw, err := s.Run(ctx, "10.0.0.0/16", TopPorts(defaultTopN))
	if err != nil {
		t.Fatalf("Run: %v (the fallback started the sweep it should have refused)", err)
	}
	if n := dc.calls.Load(); n != 0 {
		t.Errorf("%d connections were opened; none should have been", n)
	}
	if sw.HostsUp != 0 || len(sw.Hosts) != 0 {
		t.Errorf("sweep reported %d hosts up", sw.HostsUp)
	}
	if sw.Plan.Identification == "builtin" {
		t.Error("the plan claims the built-in prober ran")
	}
	if !strings.Contains(sw.Plan.Note, "nothing was examined") || !strings.Contains(sw.Plan.Note, "-engine builtin") {
		t.Errorf("plan note = %q, want it to say nothing was examined and how to run it anyway", sw.Plan.Note)
	}
	// A declined sweep and a silent target both have no hosts. The caller has
	// to be able to tell them apart without reading the note, because the one
	// reads "nothing answered" and the other "nothing was asked".
	if !sw.Declined {
		t.Error("the sweep does not say it was declined; a caller will report the range as silent")
	}

	// A single host at the default ports is well within the bound, so the
	// same machine still gets scanned.
	dc2 := &dialCounter{}
	s2 := New(Options{Timeout: time.Second})
	s2.hasNmap, s2.hasMasscan = s.hasNmap, s.hasMasscan
	s2.dialer = dc2.dial
	sw2, err := s2.Run(context.Background(), "10.0.0.7", []int{22, 80, 443})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sw2.Plan.Identification != "builtin" || dc2.calls.Load() != 3 {
		t.Errorf("a small target was not scanned: plan %+v, %d dials", sw2.Plan, dc2.calls.Load())
	}
}

// nmap's budget follows the work the way masscan's does: thirty fixed minutes
// killed a /24 at a thousand ports part way through and let one host at ten
// ports hang for half an hour.
func TestNmapBudgetScalesWithTheWork(t *testing.T) {
	small := nmapBudget(1, 10)
	one := nmapBudget(1, defaultTopN)
	all := nmapBudget(1, 65535)
	wide := nmapBudget(254, defaultTopN)
	if !(small < one && one < all && all < wide) {
		t.Errorf("budgets do not grow with the work: %v, %v, %v, %v", small, one, all, wide)
	}
	if small < 5*time.Minute {
		t.Errorf("budget for one host at ten ports is %v; version probes need a floor", small)
	}
	if got := nmapBudget(65534, 65535); got != 6*time.Hour {
		t.Errorf("budget for a /16 at every port is %v, want the six-hour cap", got)
	}
	// Targets.Len saturates at maxInt for anything wider than a /8, and the
	// product with a port count must saturate too rather than wrap negative.
	if got := probeCount(maxInt, defaultTopN); got <= 0 {
		t.Errorf("probeCount(maxInt, 1000) = %d, want saturated and positive", got)
	}
	if got := masscanBudget(mustTargets(t, "10.0.0.0/16"), 65535, 1000); got != 6*time.Hour {
		t.Errorf("masscan budget for a /16 at every port is %v, want the six-hour cap", got)
	}
}

// masscan reporting nothing is checked on a sample of the addresses, and when
// the sample finds services the sweep used to report those and call every
// other address absent. A positive sample is proof that discovery dropped
// replies, and it dropped them for the whole range: the sixteen addresses it
// looked at are not the sixteen that happen to have something. So the whole
// target has to go to identification as if discovery had never run.
func TestAPositiveConfirmationCheckSendsTheWholeTargetToIdentification(t *testing.T) {
	// Four addresses answer on 22: one inside the sixteen the check samples
	// and three well beyond them.
	answering := map[string]bool{"10.0.0.1": true, "10.0.0.100": true, "10.0.0.200": true, "10.0.0.254": true}
	s := New(Options{Timeout: time.Second, HostConcurrency: 8})
	s.hasNmap = func() bool { return false }
	s.hasMasscan = func() bool { return true }
	// Installed, ran, and reported nothing — the shape of masscan's failure
	// that matters, observed against a host nmap found 23 ports on.
	s.masscan = func(context.Context, *Targets, []int) (map[string][]int, error) { return nil, nil }
	s.dialer = greetingDialer(answering, 22, "SSH-2.0-OpenSSH_8.4p1\r\n")

	sw, err := s.Run(context.Background(), "10.0.0.0/24", []int{22})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sw.Declined {
		t.Fatalf("a /24 at one port was declined: %s", sw.Plan.Note)
	}
	got := map[string]bool{}
	for _, h := range sw.Hosts {
		got[h.Host] = true
	}
	for ip := range answering {
		if !got[ip] {
			t.Errorf("%s answered on 22 and is missing from the sweep; hosts up = %d", ip, sw.HostsUp)
		}
	}
	if sw.HostsUp != len(answering) {
		t.Errorf("hosts up = %d, want %d", sw.HostsUp, len(answering))
	}
	if sw.Plan.Identification != "builtin" {
		t.Errorf("identification = %q, want builtin: that is what examined the whole range", sw.Plan.Identification)
	}
	if !strings.Contains(sw.Plan.Note, "found services") || !strings.Contains(sw.Plan.Note, "whole target") {
		t.Errorf("plan note = %q, want it to say the check found services and the whole target was examined", sw.Plan.Note)
	}
}

// When the whole target goes to the built-in prober after a positive check
// and is more work than the fallback takes on, the sweep declines like any
// other — but the check's findings are real and stay in the report, and the
// note must not claim that nothing was examined.
func TestARefusalAfterAPositiveCheckKeepsWhatTheCheckFound(t *testing.T) {
	s := New(Options{Timeout: time.Second, HostConcurrency: 8})
	s.hasNmap = func() bool { return false }
	s.hasMasscan = func() bool { return true }
	s.masscan = func(context.Context, *Targets, []int) (map[string][]int, error) { return nil, nil }
	s.dialer = greetingDialer(map[string]bool{"10.0.0.1": true}, 22, "SSH-2.0-OpenSSH_8.4p1\r\n")

	// A /16 at the default ports is 65 million connections: over the bound.
	sw, err := s.Run(context.Background(), "10.0.0.0/16", TopPorts(defaultTopN))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !sw.Declined {
		t.Fatal("the sweep was not declined")
	}
	if sw.HostsUp != 1 || len(sw.Hosts) != 1 || sw.Hosts[0].Host != "10.0.0.1" {
		t.Errorf("hosts = %+v, want the one the check found", sw.Hosts)
	}
	if strings.Contains(sw.Plan.Note, "nothing was examined") || !strings.Contains(sw.Plan.Note, "nothing beyond") {
		t.Errorf("plan note = %q, want it to say the check's addresses were examined and nothing beyond them", sw.Plan.Note)
	}
}

// greetingDialer stands in for a network on which the given addresses answer
// on one port with a greeting and everything else refuses the connection.
func greetingDialer(answering map[string]bool, port int, greeting string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, p, err := net.SplitHostPort(addr)
		if err != nil || !answering[host] || p != strconv.Itoa(port) {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.Write([]byte(greeting))
		}()
		return client, nil
	}
}

func mustTargets(t *testing.T, spec string) *Targets {
	t.Helper()
	tg, err := ParseTargets(spec)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// A tool's first line of stderr is usually its banner. Reporting that as the
// reason it failed sends the reader to look at a version string:
//
//	masscan was available but failed (netscan: masscan: Starting masscan 1.3.2
//	(http://bit.ly/14GZzcT) at 2026-08-25 09:48:43 GMT)
//
// The reason is further down, and it is what the note must carry.
func TestAToolsFailureNamesTheReasonNotItsBanner(t *testing.T) {
	cases := map[string]string{
		"Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2026-08-25 09:48:43 GMT\n" +
			"FAIL: failed to detect IP of interface\n": "FAIL: failed to detect IP of interface",

		"Starting masscan 1.3.2\n[-] FAIL: permission denied\n": "[-] FAIL: permission denied",

		"Starting Nmap 7.98 ( https://nmap.org )\n" +
			"Failed to resolve \"nosuchhost\".\n": "Failed to resolve \"nosuchhost\".",

		// Nothing that looks like a diagnosis: the last line beats the banner,
		// because a tool's parting words are closer to why it stopped.
		"Starting masscan 1.3.2\nwaiting 3 seconds\n": "waiting 3 seconds",

		"": "",
	}
	for in, want := range cases {
		if got := toolFailure(in); got != want {
			t.Errorf("toolFailure(%q) = %q, want %q", in, got, want)
		}
	}
}
