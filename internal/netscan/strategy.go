package netscan

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Engine names how a host is examined.
type Engine string

const (
	// EngineAuto uses the best tool present: masscan to narrow a wide port
	// range, nmap to confirm and to identify, and the built-in prober when
	// neither is installed.
	EngineAuto Engine = "auto"
	// EngineBuiltin uses only this package's own connect-and-read prober, which
	// needs nothing installed and no privileges.
	EngineBuiltin Engine = "builtin"
	// EngineNmap uses nmap for identification, skipping masscan.
	EngineNmap Engine = "nmap"
	// EngineMasscan insists on the masscan discovery pass, and fails rather than
	// quietly scanning without it.
	EngineMasscan Engine = "masscan"
)

// ValidEngine reports whether e names an engine.
func ValidEngine(e Engine) bool {
	switch e {
	case EngineAuto, EngineBuiltin, EngineNmap, EngineMasscan:
		return true
	}
	return false
}

// Plan is what a scan decided to do, so a report can say how its evidence was
// obtained rather than presenting every answer as equally grounded.
type Plan struct {
	Discovery      string `json:"discovery"`
	Identification string `json:"identification"`
	// Note qualifies the result: what the method cannot promise, and what it
	// had to do differently. It is not a failure report — a caveat about how
	// discovery works accompanies a scan that went entirely to plan.
	Note string `json:"note,omitempty"`
}

// accurateRate is the packet rate at which masscan finds what is there.
//
// It is not a throttle for politeness, it is the accuracy setting. masscan is
// stateless and drops replies it cannot keep up with, and the loss is silent.
// Measured against one real host over all 65,535 ports:
//
//	 1,000 pps   89s   23 ports   — the same 23 nmap -p- finds
//	 5,000 pps   21s   20 ports
//	20,000 pps    8s    7 ports
//
// Two thirds of the host disappears at the rate that makes a sweep feel fast,
// and nothing in the output says so. So this is the default, and raising it is
// something the report tells the reader about.
const accurateRate = 1000

// masscanCaveat is attached to any report whose discovery pass was masscan, so
// that a silent address is not read as an empty one.
const masscanCaveat = "discovery was a stateless sweep: it is fast enough to cross this range " +
	"but it drops replies, so an address listed as silent is not proven to be empty. " +
	"Re-run a narrower range with -engine nmap to be sure of one."

// Run examines a target — one host or a whole range — and reports what is
// listening.
//
// The division of labour is deliberate. masscan finds candidate ports fast and
// inaccurately, and takes a CIDR block natively, which is the only practical
// way to cross anything wider than a /24; nmap then confirms each candidate
// with a full handshake and identifies the software with its service-probe
// database. The built-in prober is the floor: it needs no tools and no
// privileges, and it reads only what a service volunteers.
func (s *Scanner) Run(ctx context.Context, target string, ports []int) (*Sweep, error) {
	tg, err := ParseTargets(target)
	if err != nil {
		return nil, err
	}
	engine := s.opt.Engine
	if engine == "" {
		engine = EngineAuto
	}

	sweep := &Sweep{
		Target: tg.String(), ScannedAt: time.Now().UTC(),
		HostsTotal: tg.Len(), Ports: len(ports),
	}
	plan := &Plan{}
	sweep.Plan = plan

	switch engine {
	case EngineMasscan:
		if !s.hasMasscan() {
			return nil, fmt.Errorf("netscan: -engine masscan was asked for but masscan is not installed")
		}
	case EngineNmap:
		if !s.hasNmap() {
			return nil, fmt.Errorf("netscan: -engine nmap was asked for but nmap is not installed")
		}
	}

	if engine == EngineBuiltin {
		s.report().Stage("probing " + tg.String())
		s.report().Total(tg.Len() * len(ports))
		plan.Discovery, plan.Identification = "builtin", "builtin"
		hosts, err := s.sweepBuiltin(ctx, tg, ports)
		if err != nil {
			return nil, err
		}
		if err := reconcileAll(ctx, hosts, s.opt.Resolver); err != nil {
			return nil, err
		}
		return finish(sweep, hosts), nil
	}

	// Discovery. For a range this is not an optimisation but the difference
	// between minutes and days: a /16 at 64 ports is four million probes, and
	// masscan is built to emit them while a connect scan is not.
	// Discovery first, whenever masscan can run: the ports worth looking at are
	// the ones something is listening on, and no list of guesses finds those.
	// On one real host the sixty-five well-known ports held 4 of 23 services —
	// httpd on 7011, 8011 and 30008, RabbitMQ on 30003, Syncthing on 8384 —
	// none of which any list would have contained.
	var found map[string][]int
	rate := s.opt.Rate
	if rate <= 0 {
		rate = accurateRate
	}
	// sampled is the part of the target a positive confirmation check covered,
	// kept for the refusal note below: a sweep declined after such a check has
	// examined that much and no more, and must not say it examined nothing.
	var sampled []*Result
	useMasscan := s.hasMasscan() && engine != EngineNmap
	if useMasscan {
		s.report().Stage("finding open ports with masscan")
		found, err = s.masscan(ctx, tg, ports)
		switch {
		case err != nil && engine == EngineMasscan:
			return nil, err
		case err != nil:
			plan.Note = "masscan was available but failed (" + err.Error() +
				"); every address was examined directly instead"
		default:
			plan.Discovery = "masscan"
			plan.Note = appendNote(plan.Note, masscanCaveat)
			if rate > accurateRate {
				plan.Note = appendNote(plan.Note, fmt.Sprintf(
					"at %d packets per second rather than %d, and masscan loses ports as it "+
						"speeds up: measured on one host, 23 ports found at %d and 7 at 20000",
					rate, accurateRate, accurateRate))
			}
			if len(found) == 0 {
				// Nothing at all, across every port of every address. That is
				// possible and it is also what a discovery pass looks like when
				// it drops every reply — observed returning zero for a host
				// nmap found 23 ports on moments later. Believing it reports
				// the target as silent, so it is checked instead.
				confirmPorts := TopPorts(defaultTopN)
				checked, via, n, cerr := s.confirmEmpty(ctx, tg, confirmPorts)
				if cerr != nil {
					return nil, cerr
				}
				where := sampleNote(n, tg.Len())
				if len(checked) == 0 {
					plan.Note = appendNote(plan.Note,
						"a direct check of the most common ports on "+where+" also found nothing")
					plan.Identification = "not needed: nothing answered"
					return finish(sweep, nil), nil
				}
				plan.Discovery = "masscan (found nothing), then direct"
				if n >= tg.Len() && samePorts(confirmPorts, ports) {
					// The check covered every address at every port asked
					// for, so it already is the examination the target needed
					// and running it again would only repeat it. The label
					// says which prober actually did the work: the check falls
					// back to the built-in one when nmap is missing or fails,
					// and "nmap -sV" over builtin evidence would claim a
					// version database that was never consulted.
					plan.Note = appendNote(plan.Note,
						"the sweep found nothing and was wrong: a direct check of the same "+
							"ports on "+where+" found services, so those are reported instead")
					plan.Identification = via
					if err := reconcileAll(ctx, checked, s.opt.Resolver); err != nil {
						return nil, err
					}
					return finish(sweep, checked), nil
				}
				// The check looked at a sample of the addresses, or at fewer
				// ports than were asked for, and it found something. That is
				// not a result to report: it is proof that discovery dropped
				// replies, and a pass that dropped them for these addresses
				// dropped them for the rest of the range too. Reporting the
				// sample and calling every other address absent turned the
				// one failure this scanner exists to catch into its own
				// output, sixteen addresses at a time. So discovery's answer
				// is set aside and the whole target goes to identification
				// as if there had been no discovery pass — nmap under its
				// budget, or the built-in prober under its bound, which may
				// decline and say so.
				sampled = checked
				plan.Note = appendNote(plan.Note,
					"the sweep found nothing and was wrong: a direct check of the "+
						"most common ports on "+where+" found services, so its answer was "+
						"set aside and the whole target is examined directly instead")
			}
		}
	}
	if plan.Discovery == "" {
		plan.Discovery = "direct"
		if !s.hasMasscan() && engine != EngineNmap {
			plan.Note = appendNote(plan.Note,
				"masscan is not installed, so only the ports named were looked at rather than "+
					"every port something is listening on; install it, or pass -ports all")
		}
	}

	if s.hasNmap() {
		if len(found) > 0 {
			s.report().Stage("identifying services with nmap")
			s.report().Total(len(found))
		} else {
			// One invocation covering the whole target: nothing to count, so
			// the stage shows its name and how long it has been running rather
			// than a percentage nobody measured.
			s.report().Stage("identifying services with nmap")
		}
		hosts, err := s.nmapSweep(ctx, tg, ports, found)
		if err == nil {
			s.enrichUnidentified(ctx, hosts)
			if err := reconcileAll(ctx, hosts, s.opt.Resolver); err != nil {
				return nil, err
			}
			plan.Identification = "nmap -sV"
			return finish(sweep, hosts), nil
		}
		if engine == EngineNmap || engine == EngineMasscan {
			return nil, err
		}
		plan.Note = appendNote(plan.Note, "nmap was available but failed ("+err.Error()+
			"); the built-in prober was used instead, which reads only what a service volunteers")
	}

	// The built-in prober is the last resort, and unlike the tools above it
	// has no idea how big a job it has been handed: it will open one
	// connection per address per port until it is done or killed. When
	// discovery narrowed the work it is bounded by what discovery found; when
	// there was no discovery it is the whole target, and a /16 at the
	// default ports is 65 million connections that nobody asked for — the
	// operator asked for auto, and auto has run out of engines. Refusing is
	// reported in the plan rather than as an error, because the sweep did
	// not fail: it declined, and the note says how to get it done.
	if len(found) == 0 {
		if work := probeCount(tg.Len(), len(ports)); work > maxBuiltinProbes {
			examined := "nothing was examined"
			if len(sampled) > 0 {
				// The confirmation check's findings are real evidence about
				// the addresses it reached, and they stay in the report; the
				// note says that the rest of the target was not looked at.
				examined = "nothing beyond the addresses the direct check reached was examined"
			}
			plan.Identification = "not attempted"
			plan.Note = appendNote(plan.Note, fmt.Sprintf(
				"the built-in prober was the only engine left, and %s at %d ports is %d "+
					"connections, more than the %d it takes on as a fallback; %s. "+
					"Install nmap or masscan, narrow the range or the port list, "+
					"or pass -engine builtin to run it regardless",
				tg.String(), len(ports), work, maxBuiltinProbes, examined))
			sweep.Declined = true
			if err := reconcileAll(ctx, sampled, s.opt.Resolver); err != nil {
				return nil, err
			}
			return finish(sweep, sampled), nil
		}
	}
	plan.Identification = "builtin"
	s.report().Stage("probing " + tg.String())
	s.report().Total(tg.Len() * len(ports))
	hosts, err := s.builtinFrom(ctx, tg, ports, found)
	if err != nil {
		return nil, err
	}
	if err := reconcileAll(ctx, hosts, s.opt.Resolver); err != nil {
		return nil, err
	}
	return finish(sweep, hosts), nil
}

// maxBuiltinProbes bounds the work the built-in prober takes on when it is
// the fallback rather than the engine asked for.
//
// A million connections is a /22 at the default thousand ports, or one host
// at every port sixteen times over. At the default concurrency (16 hosts by
// 16 ports) that is minutes against a network that refuses connections and
// most of a day against one that drops them, which is the far edge of what
// an operator who typed "auto" can be assumed to have meant. -engine builtin
// carries no such bound: naming the engine is accepting its cost.
const maxBuiltinProbes = 1 << 20

// probeCount is hosts × ports without overflowing: Targets.Len saturates at
// maxInt for anything wider than a /8, and multiplying that by a port count
// wrapped to a negative number that passed every "too much work" check.
func probeCount(hosts, ports int) int64 {
	if hosts <= 0 || ports <= 0 {
		return 0
	}
	h, p := int64(hosts), int64(ports)
	if h > math.MaxInt64/p {
		return math.MaxInt64
	}
	return h * p
}

// samePorts reports whether two port lists name the same ports. Both come
// from ParsePorts or TopPorts, which return them sorted and without repeats,
// so an element-wise comparison is enough.
func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sampleNote spells out how much of a target a direct check covered, so a
// note that says "found nothing" is read as "found nothing on the part that
// was looked at".
func sampleNote(sampled, total int) string {
	switch {
	case total <= 1:
		return "it"
	case sampled >= total:
		return fmt.Sprintf("all %d addresses", total)
	}
	return fmt.Sprintf("%d of its %d addresses", sampled, total)
}

// finish fills in the counts a reader needs to size the answer.
func finish(s *Sweep, hosts []*Result) *Sweep {
	sortHosts(hosts)
	s.Hosts = hosts
	s.HostsUp = len(hosts)
	return s
}

// reconcileAll lets the corpus overrule every host's vendors.
func reconcileAll(ctx context.Context, hosts []*Result, r VendorResolver) error {
	for _, h := range hosts {
		if err := h.reconcileVendors(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// builtinFrom probes with the built-in prober, using masscan's findings when
// there are any so that dead addresses are not connected to again.
func (s *Scanner) builtinFrom(ctx context.Context, tg *Targets, ports []int, found map[string][]int) ([]*Result, error) {
	if len(found) == 0 {
		return s.sweepBuiltin(ctx, tg, ports)
	}
	var (
		mu    sync.Mutex
		hosts []*Result
		fail  error
	)
	workers(ctx, min(s.hostConcurrency(), len(found)), eachFound(found), func(f foundHost) {
		res, err := s.Scan(ctx, f.ip, f.ports)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if fail == nil {
				fail = err
			}
			return
		}
		if len(res.Open) > 0 || len(res.Unidentified) > 0 {
			hosts = append(hosts, res)
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fail != nil {
		return nil, fail
	}
	sortHosts(hosts)
	return hosts, nil
}

// foundHost is one address discovery reported, with the ports it answered on.
type foundHost struct {
	ip    string
	ports []int
}

// eachFound turns a discovery map into a producer for workers.
func eachFound(found map[string][]int) func(yield func(foundHost) bool) {
	return func(yield func(foundHost) bool) {
		for ip, ps := range found {
			if !yield(foundHost{ip, ps}) {
				return
			}
		}
	}
}

// masscanSweep runs discovery over the whole target at once.
//
// The CIDR goes to masscan as written rather than expanded: it understands
// ranges, and handing it 65,534 arguments instead would be slower and would hit
// every limit an argument list has.
func (s *Scanner) masscanSweep(ctx context.Context, tg *Targets, ports []int) (map[string][]int, error) {
	rate := s.opt.Rate
	if rate <= 0 {
		rate = accurateRate
	}
	args := []string{
		"-p", portList(ports),
		"--rate", strconv.Itoa(rate),
		"-oJ", "-",
		"--wait", "3",
		tg.Spec(),
	}
	out, err := s.runTool(ctx, "masscan", args, masscanBudget(tg, len(ports), rate))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			return nil, fmt.Errorf("%w: masscan needs raw sockets (run it with CAP_NET_RAW, "+
				"e.g. docker run --cap-add=NET_RAW, or as root)", err)
		}
		return nil, err
	}
	return parseMasscanHosts(out)
}

// masscanBudget bounds the discovery pass by the work it was actually given.
// A fixed ten minutes is far too long for a /24 and far too short for a /16.
func masscanBudget(tg *Targets, ports, rate int) time.Duration {
	probes := probeCount(tg.Len(), ports)
	seconds := probes/int64(max(rate, 1)) + 60
	return capBudget(seconds)
}

// nmapBudget bounds an identification pass the same way. The thirty fixed
// minutes it replaces were sized for one host at the default ports and are
// wrong in both directions elsewhere: a /24 at a thousand ports is killed
// part way through with nothing to show for it, and one host at ten ports is
// allowed to hang for half an hour on a dropped packet.
//
// nmap -sV gets through closed ports at hundreds a second and then spends
// seconds on version probes against each open one, so the estimate is a
// twentieth of a second per probe plus five minutes for the open ones,
// whatever the count — a floor that keeps one host at one port from timing
// out on a slow version probe.
func nmapBudget(hosts, ports int) time.Duration {
	probes := probeCount(hosts, ports)
	return capBudget(probes/20 + 300)
}

// capBudget turns an estimate in seconds into a bounded duration. Six hours
// is the point past which an unattended scan is better restarted narrower.
func capBudget(seconds int64) time.Duration {
	const limit = 6 * time.Hour
	if seconds > int64(limit/time.Second) {
		return limit
	}
	return time.Duration(seconds) * time.Second
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// nmapSweep identifies what discovery found, or the whole target when there was
// no discovery pass.
func (s *Scanner) nmapSweep(ctx context.Context, tg *Targets, ports []int, found map[string][]int) ([]*Result, error) {
	if len(found) == 0 {
		return s.nmapRun(ctx, tg.Spec(), tg.Len(), ports)
	}
	// One invocation per host, because the hosts have different open ports and
	// giving nmap the union would re-probe every closed one on every address.
	var (
		mu    sync.Mutex
		hosts []*Result
		fail  error
	)
	workers(ctx, min(s.hostConcurrency(), len(found)), eachFound(found), func(f foundHost) {
		rs, err := s.nmapRun(ctx, f.ip, 1, f.ports)
		s.report().Add(1)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if fail == nil {
				fail = err
			}
			return
		}
		hosts = append(hosts, rs...)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fail != nil {
		return nil, fail
	}
	return hosts, nil
}

// enrichUnidentified gives the ports nmap could not name a second chance
// through their TLS certificate.
//
// nmap reports "ssl/blackice-icecap?" for a port it knows is TLS and cannot
// place — the name is a guess from the port number, and the question mark is
// nmap saying so. The certificate behind it is evidence nobody had looked at.
func (s *Scanner) enrichUnidentified(ctx context.Context, hosts []*Result) {
	for _, h := range hosts {
		host := h.Addr
		if host == "" {
			host = h.Host
		}
		if host == "" {
			continue
		}
		kept := h.Unidentified[:0]
		for _, u := range h.Unidentified {
			_, subject, err := s.probeTLS(ctx, host, u.Port)
			if err != nil || subject == "" {
				kept = append(kept, u)
				continue
			}
			if svc := IdentifyTLS(u.Port, subject); svc != nil {
				h.Open = append(h.Open, *svc)
				continue
			}
			// Still unnamed, but the certificate is worth carrying: it is what
			// an operator identifying this by hand would look at first.
			u.Banner = strings.TrimSpace(u.Banner + " · tls: " + subject)
			kept = append(kept, u)
		}
		h.Unidentified = kept
		sort.Slice(h.Open, func(i, j int) bool { return h.Open[i].Port < h.Open[j].Port })
	}
}

// nmapRun executes one identification pass over a target of hosts addresses.
//
// -Pn because the caller named the target and a ping sweep only adds a way to
// conclude wrongly that it is down. --open because a closed port is not
// evidence about what is running.
func (s *Scanner) nmapRun(ctx context.Context, target string, hosts int, ports []int) ([]*Result, error) {
	args := []string{
		"-sV", "-Pn", "-n",
		"-p", portList(ports),
		"--open",
		"-oX", "-",
		target,
	}
	out, err := s.runTool(ctx, "nmap", args, nmapBudget(hosts, len(ports)))
	if err != nil {
		return nil, err
	}
	return parseNmapXML(out)
}

func appendNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// nmap runs the identification pass.
//
// -Pn because the host is already known to be worth looking at — the caller
// named it — and a ping sweep only adds a way to conclude wrongly that it is
// down. --version-intensity is left at nmap's default: turning it up sends more
// probes to every port, and this is a scan of software rather than a hunt for
// something hiding.

// runTool executes an external scanner with an explicit argument vector and no
// shell. The target reached validateTarget before any of this, so nothing on
// the command line can become an option.
//
// stderr is watched rather than merely collected, because masscan reports its
// completion there while it runs and that figure is the only real measurement
// of a sweep's progress.
func (s *Scanner) runTool(ctx context.Context, name string, args []string, max time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, max)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr := &progressWatcher{report: s.report()}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		msg := toolFailure(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("netscan: %s: %s", name, msg)
	}
	return stdout.Bytes(), nil
}

// progressWatcher collects a tool's stderr and forwards any completion figure
// it finds. masscan rewrites one status line with a carriage return rather than
// printing lines, so the split has to treat both as separators.
type progressWatcher struct {
	report  Reporter
	buf     bytes.Buffer
	partial []byte
	pct     float64
}

func (w *progressWatcher) Write(p []byte) (int, error) {
	w.buf.Write(p)
	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexAny(w.partial, "\r\n")
		if i < 0 {
			break
		}
		line := string(w.partial[:i])
		w.partial = w.partial[i+1:]
		if pct, ok := masscanPercent(line); ok && pct != w.pct {
			w.pct = pct
			// Reported in hundredths so the bar has something to divide: the
			// tool gives a percentage, not a tally of anything countable.
			w.report.Total(10000)
			w.report.Add(0)
			if r, ok := w.report.(interface{ Set(int) }); ok {
				r.Set(int(pct * 100))
			}
		}
	}
	return len(p), nil
}

func (w *progressWatcher) String() string { return w.buf.String() }

// toolFailure picks the line of a tool's stderr that says why it stopped.
//
// The first line is almost always a banner — "Starting masscan 1.3.2
// (http://bit.ly/14GZzcT)" — and reporting that as the reason sends the reader
// to look at a version string. A line that names a failure wins; failing that,
// the last line, because a tool's parting words are nearer to why it stopped
// than its greeting is.
func toolFailure(stderr string) string {
	var lines []string
	for _, raw := range strings.Split(stderr, "\n") {
		if t := strings.TrimSpace(raw); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	for _, l := range lines {
		low := strings.ToLower(l)
		for _, marker := range []string{"fail", "error", "denied", "cannot", "could not", "unable", "refused", "no route", "unknown"} {
			if strings.Contains(low, marker) {
				return l
			}
		}
	}
	return lines[len(lines)-1]
}

// confirmHosts is how many addresses confirmEmpty looks at.
//
// The check exists to catch a discovery pass that dropped every reply, and a
// pass that did that dropped them for every address alike — so a handful of
// addresses answers the question, and answering it for all 65,534 addresses
// of a /16 at a thousand ports each is a second full sweep, this time by the
// slowest engine available, on a target discovery already said was silent.
const confirmHosts = 16

// confirmEmpty asks directly whether a target really has nothing open, on a
// sample of its addresses. It reports which engine did the asking, because
// the report labels its evidence by engine, and how many addresses it covered,
// because "nothing found" on sixteen addresses of a /16 is not "the /16 is
// empty".
//
// It runs only when discovery reported nothing, so its cost is paid exactly
// when the alternative is announcing a silent target on the word of a tool that
// drops replies for a living.
func (s *Scanner) confirmEmpty(ctx context.Context, tg *Targets, ports []int) (hosts []*Result, engine string, sampled int, err error) {
	sample := sampleHosts(tg, confirmHosts)
	found := make(map[string][]int, len(sample))
	for _, ip := range sample {
		found[ip] = ports
	}
	if s.hasNmap() {
		hosts, err := s.nmapSweep(ctx, tg, ports, found)
		if err == nil {
			return hosts, "nmap -sV", len(sample), nil
		}
		if ctx.Err() != nil {
			return nil, "", len(sample), err // not a failure of nmap's; nothing else will fare better
		}
	}
	hosts, err = s.builtinFrom(ctx, tg, ports, found)
	return hosts, "builtin", len(sample), err
}

// sampleHosts takes the first n addresses of a target, or all of them when
// there are fewer. The first addresses rather than a spread because the walk
// is lazy and the point is to stop early; a discovery pass that dropped
// everything did so regardless of which addresses these are.
func sampleHosts(tg *Targets, n int) []string {
	var out []string
	tg.Each(func(ip string) bool {
		out = append(out, ip)
		return len(out) < n
	})
	return out
}
