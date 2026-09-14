package netscan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// Options configures a scan.
type Options struct {
	// Timeout bounds each individual connection: the dial, the handshake and
	// the read. It is not a budget for the whole scan, which the caller's
	// context governs.
	Timeout time.Duration
	// Concurrency bounds simultaneous connections to one host. The default is
	// deliberately modest: a scanner that opens hundreds of sockets at once
	// looks like an attack to anything watching, and gets throttled or blocked
	// for it.
	Concurrency int
	// HostConcurrency bounds how many addresses are examined at once when the
	// target is a range. It multiplies with Concurrency: their product is what
	// the network actually sees, and the default pair is chosen to stay well
	// under what an intrusion-detection system treats as a flood.
	HostConcurrency int
	// Engine selects how the host is examined. Empty means EngineAuto.
	Engine Engine
	// Rate is masscan's packets per second. Left at zero it is 1000, which is
	// slow for masscan and fast enough to be worth the process.
	Rate int
	// Progress receives what stage the scan is in and how far through it is, so
	// a caller can show something during the minutes a range takes. Optional.
	Progress Reporter
	// Resolver lets the corpus overrule a vendor an external scanner reported.
	// Optional; without it the scanner's own vendor is used unchanged, which is
	// how the CPE for a product like nginx ends up matching nothing.
	Resolver VendorResolver
}

// Reporter is told what a scan is doing. It exists so netscan does not depend
// on a terminal, and so a caller with no interest in progress passes nothing.
type Reporter interface {
	// Stage names the step now beginning and resets any count.
	Stage(name string)
	// Total declares how many units the current stage has, or zero when the
	// step cannot be counted — which must not be reported as a percentage.
	Total(n int)
	// Add records completed units.
	Add(n int)
}

// Scanner probes a host's ports and reports what answered.
type Scanner struct {
	opt Options
	// dialer, hasNmap and hasMasscan are what the scanner asks about the
	// world: open a connection, and are the tools installed. They are fields
	// rather than calls so a test can stand in a network that answers
	// instantly and a machine with nothing on PATH — the alternative is a
	// suite whose outcome depends on which scanner the build host has, or
	// one that runs nmap against a /16 to prove the /16 was refused.
	dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	hasNmap    func() bool
	hasMasscan func() bool
	// masscan is the discovery pass, normally masscanSweep. A field for the
	// same reason as the three above: a test has to be able to stand in a
	// masscan that is installed and reports nothing, which is the shape of
	// its failure that matters most and cannot be produced on request.
	masscan func(ctx context.Context, tg *Targets, ports []int) (map[string][]int, error)
}

// report is the nil-safe accessor: most callers pass no Reporter.
func (s *Scanner) report() Reporter {
	if s.opt.Progress == nil {
		return nopReporter{}
	}
	return s.opt.Progress
}

type nopReporter struct{}

func (nopReporter) Stage(string) {}
func (nopReporter) Total(int)    {}
func (nopReporter) Add(int)      {}

// New builds a Scanner, filling in defaults.
func New(opt Options) *Scanner {
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 16
	}
	d := &net.Dialer{Timeout: opt.Timeout}
	s := &Scanner{
		opt:        opt,
		dialer:     d.DialContext,
		hasNmap:    HasNmap,
		hasMasscan: HasMasscan,
	}
	s.masscan = s.masscanSweep
	return s
}

// Unidentified is an open port whose software could not be named.
//
// It is reported rather than dropped. A port that is open and unrecognised is
// the most interesting thing a scan can find — it is the part of the host that
// was not tested — and hiding it makes the report read as though the host were
// fully covered.
type Unidentified struct {
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
	Reason string `json:"reason"`
}

// Result is one host's scan.
type Result struct {
	Host         string         `json:"host"`
	Addr         string         `json:"addr,omitempty"`
	ScannedAt    time.Time      `json:"scanned_at"`
	Scanned      int            `json:"ports_scanned"`
	Open         []Service      `json:"services"`
	Unidentified []Unidentified `json:"unidentified,omitempty"`
}

// Components turns identified services into inventory the matcher can test.
//
// Only services that stated a version are included. The rest are not silently
// discarded — they are in Result.Unidentified or carry an empty version — but
// they cannot be compared against a range, and a component with no version
// satisfies every unbounded window in the corpus.
func (r *Result) Components() []match.Component {
	var out []match.Component
	for _, s := range r.Open {
		if !s.Scannable() {
			continue
		}
		out = append(out, match.Component{
			Name:    s.Product,
			Version: s.Version,
			Vendor:  s.Vendor,
			CPE:     s.CPE(),
			Origin:  "netscan:" + strconv.Itoa(s.Port),
		})
	}
	return out
}

// Scan probes every port in the list and reports what answered.
func (s *Scanner) Scan(ctx context.Context, host string, ports []int) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res := &Result{Host: host, ScannedAt: time.Now().UTC(), Scanned: len(ports)}
	if ip, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil && len(ip) > 0 {
		res.Addr = ip[0].String()
	}

	// A port that refuses the connection is a result, not a failure, so there is
	// no error to accumulate here: probe() reporting one means "nothing is
	// listening", and the scan carries on.
	//
	// The ports are fed to a fixed pool rather than each given a goroutine
	// that waits its turn: the second shape held 65,535 goroutines for
	// "-ports all" before the first one had connected. See workers.
	var mu sync.Mutex
	workers(ctx, min(s.opt.Concurrency, len(ports)), func(yield func(int) bool) {
		for _, port := range ports {
			if !yield(port) {
				return
			}
		}
	}, func(port int) {
		banner, tlsSubject, err := s.probe(ctx, host, port)
		s.report().Add(1)
		if err != nil {
			return // closed, filtered, or nothing to say
		}
		mu.Lock()
		defer mu.Unlock()
		// Every product the banner names, not only the first: an HTTP answer
		// carrying both "Server: nginx/1.18.0" and "X-Powered-By: PHP/7.4.3"
		// is two pieces of software on one port, and the second used to be
		// dropped because the first rule to match ended the search.
		if svcs := IdentifyAll(port, banner); len(svcs) > 0 {
			for _, svc := range svcs {
				svc.TLS = tlsSubject
				res.Open = append(res.Open, *svc)
			}
			return
		}
		// The response said nothing recognisable, but a TLS service always
		// presents a certificate and that often names the product.
		if svc := IdentifyTLS(port, tlsSubject); svc != nil {
			res.Open = append(res.Open, *svc)
			return
		}
		shown := truncateBanner(banner)
		if tlsSubject != "" {
			// Still unnamed, but the certificate is worth carrying: it is
			// what an operator identifying this by hand would look at first.
			shown = strings.TrimSpace(shown + " · tls: " + tlsSubject)
		}
		res.Unidentified = append(res.Unidentified, Unidentified{
			Port:   port,
			Banner: shown,
			Reason: "the port is open but nothing in its response names known software",
		})
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(res.Open, func(i, j int) bool { return res.Open[i].Port < res.Open[j].Port })
	sort.Slice(res.Unidentified, func(i, j int) bool {
		return res.Unidentified[i].Port < res.Unidentified[j].Port
	})
	return res, nil
}

// probe opens a connection and reads whatever the service volunteers.
//
// Two kinds of service exist and they need opposite treatment: SSH, FTP and
// SMTP greet the client, while HTTP says nothing until asked. Waiting on the
// second kind finds an open port and no software; asking the first kind is
// harmless because it has already spoken. So it listens briefly, then asks.
//
// And a third kind says nothing that means anything in clear, because it is
// expecting TLS. That is not confined to the ports a list remembers: on one
// real host it was a Docker API on 2376, a Syncthing relay on 22000, and seven
// services between 7010 and 8085. So TLS is decided by what the port does
// rather than by its number — a plain read that yields nothing usable is
// retried through a handshake.
func (s *Scanner) probe(ctx context.Context, host string, port int) (string, string, error) {
	if tlsFirst(port) {
		banner, subject, err := s.probeTLS(ctx, host, port)
		if err == nil {
			return banner, subject, nil
		}
		if !isConnectFailure(err) {
			// The port is open and simply not TLS; fall through and read it in
			// clear rather than reporting nothing.
			return s.probePlain(ctx, host, port)
		}
		return "", "", err
	}

	banner, _, err := s.probePlain(ctx, host, port)
	if err != nil {
		return "", "", err
	}
	if Identify(port, banner) != nil {
		return banner, "", nil
	}
	// Open, and nothing in the answer names software. Very often that is a TLS
	// handshake being read as text.
	//
	// A completed handshake is a result even when the service behind it then
	// says nothing — which is what a Docker daemon, a Syncthing relay or a
	// Kubernetes API does to an unauthenticated GET. The certificate it
	// presented is the only evidence there is about such a port, and it was
	// being thrown away because the banner was empty. So the subject is kept
	// whenever the handshake succeeded and anything at all was learned; the
	// plain-text banner stays only when TLS produced nothing to replace it.
	if tlsBanner, subject, tlsErr := s.probeTLS(ctx, host, port); tlsErr == nil && (tlsBanner != "" || subject != "") {
		if tlsBanner == "" {
			return banner, subject, nil
		}
		return tlsBanner, subject, nil
	}
	return banner, "", nil
}

// probePlain reads a service in the clear.
func (s *Scanner) probePlain(ctx context.Context, host string, port int) (string, string, error) {
	conn, err := s.dial(ctx, host, port)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	return s.converse(conn, host, port), "", nil
}

// probeTLS completes a handshake and reads the service behind it, keeping the
// certificate subject as evidence about the host.
func (s *Scanner) probeTLS(ctx context.Context, host string, port int) (string, string, error) {
	conn, err := s.dial(ctx, host, port)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{
		ServerName: host,
		// The certificate is read as evidence, not trusted for anything.
		// Refusing to look at a host because it uses a self-signed certificate
		// would exclude exactly the hosts most worth scanning.
		InsecureSkipVerify: true,
	})
	hctx, cancel := context.WithTimeout(ctx, s.opt.Timeout)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return "", "", err
	}
	var subject string
	if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
		subject = st.PeerCertificates[0].Subject.String()
	}
	return s.converse(tc, host, port), subject, nil
}

func (s *Scanner) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return s.dialer(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// isConnectFailure distinguishes "nothing is listening" from "something is
// listening and did not do what was expected". Only the first means the port is
// closed.
func isConnectFailure(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		return oe.Op == "dial"
	}
	return false
}

// converse listens for a greeting and, if none comes, asks an HTTP question.
func (s *Scanner) converse(conn net.Conn, host string, port int) string {
	// A service that speaks first usually does so at once. This window is short
	// because it is pure latency on every silent port.
	if b := readSome(conn, minDuration(s.opt.Timeout, greetWindow)); b != "" {
		return b
	}
	// Nothing volunteered. Ask for the root document; the answer's Server header
	// is what names the software. This is the only thing this package ever
	// sends.
	conn.SetWriteDeadline(time.Now().Add(s.opt.Timeout))
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: cvefeed-netscan/1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		net.JoinHostPort(host, strconv.Itoa(port)))
	if _, err := io.WriteString(conn, req); err != nil {
		return ""
	}
	return readSome(conn, s.opt.Timeout)
}

// greetWindow is how long to wait for a service to introduce itself before
// concluding that it is waiting for us.
const greetWindow = 1500 * time.Millisecond

// maxRead bounds one response. Some services answer a bare GET with a whole
// application, and none of it past the headers says anything about the version.
const maxRead = 8 << 10

// readIdle is how long to wait for more of a response once some of it has
// arrived. It separates "this service has stopped talking" from "this service
// never started", and the two deserve very different waits.
const readIdle = 150 * time.Millisecond

// readSome reads a response, waiting `first` for it to begin and only readIdle
// for it to continue.
//
// Reading to a fixed size instead — io.ReadFull into an 8 KiB buffer — waits for
// the deadline on every service whose answer is shorter than the buffer, which
// is nearly all of them: a 25-byte SSH greeting cost the full 1.5s window,
// making a 64-port scan take six seconds against a host that answered instantly.
func readSome(conn net.Conn, first time.Duration) string {
	buf := make([]byte, maxRead)
	n := 0
	if err := conn.SetReadDeadline(time.Now().Add(first)); err != nil {
		return ""
	}
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
		if m > 0 {
			// Something is coming; wait only for the gap that means it is done.
			if err := conn.SetReadDeadline(time.Now().Add(readIdle)); err != nil {
				break
			}
		}
	}
	return string(buf[:n])
}

// tlsFirst reports whether to try TLS before reading in clear. It is an
// ordering hint rather than a rule: any port that says nothing usable in clear
// is retried through a handshake anyway, so a port missing from this list costs
// one extra connection rather than an identification.
func tlsFirst(p int) bool {
	switch p {
	case 443, 465, 636, 989, 990, 993, 995, 1443, 2376, 4443, 5986, 8443, 9443, 10443:
		return true
	}
	return false
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
