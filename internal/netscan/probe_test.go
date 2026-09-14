package netscan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// listenBanner starts a server that speaks first, the way SSH, FTP and SMTP do.
func listenBanner(t *testing.T, greeting string) int {
	t.Helper()
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
				fmt.Fprint(c, greeting)
				// Hold the connection so the probe's read deadline, and not the
				// close, is what ends the read.
				time.Sleep(2 * time.Second)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestProbeReadsAServiceThatSpeaksFirst(t *testing.T) {
	port := listenBanner(t, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")

	s := New(Options{Timeout: 2 * time.Second})
	res, err := s.Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Open) != 1 {
		t.Fatalf("open ports = %d, want 1", len(res.Open))
	}
	got := res.Open[0]
	if got.Product != "openssh" || got.Version != "8.4p1" {
		t.Fatalf("identified %+v, want openssh 8.4p1", got)
	}
}

// Most HTTP servers say nothing until asked. A probe that only listens finds an
// open port and no software at all.
func TestProbeAsksHTTPServersThatWaitForTheClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(strings.TrimPrefix(srv.URL, "http://127.0.0.1:"))

	s := New(Options{Timeout: 2 * time.Second})
	res, err := s.Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Open) != 1 {
		t.Fatalf("open ports = %d, want 1", len(res.Open))
	}
	if res.Open[0].Product != "http_server" || res.Open[0].Version != "2.4.49" {
		t.Fatalf("identified %+v, want apache http_server 2.4.49", res.Open[0])
	}
}

func TestProbeReportsAnOpenPortItCouldNotIdentify(t *testing.T) {
	port := listenBanner(t, "welcome to the thing\r\n")

	s := New(Options{Timeout: 2 * time.Second})
	res, err := s.Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Open) != 0 {
		t.Fatalf("identified %+v from a banner that names nothing", res.Open)
	}
	if len(res.Unidentified) != 1 {
		t.Fatalf("unidentified = %d, want the open port to still be reported", len(res.Unidentified))
	}
	if res.Unidentified[0].Port != port {
		t.Errorf("unidentified port = %d, want %d", res.Unidentified[0].Port, port)
	}
	if res.Unidentified[0].Banner == "" {
		t.Error("the banner was not carried through; an operator needs it to identify the service by hand")
	}
}

func TestClosedPortsAreNotReportedAsAnything(t *testing.T) {
	// Bind and immediately release, so the port is almost certainly closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := New(Options{Timeout: time.Second})
	res, err := s.Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Open)+len(res.Unidentified) != 0 {
		t.Fatalf("a closed port produced %d open and %d unidentified",
			len(res.Open), len(res.Unidentified))
	}
	if res.Scanned != 1 {
		t.Errorf("scanned = %d, want 1", res.Scanned)
	}
}

// The scan must stop when its caller stops caring, not run to completion in the
// background against a host nobody is waiting on any more.
func TestScanStopsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New(Options{Timeout: 2 * time.Second})
	_, err := s.Scan(ctx, "127.0.0.1", []int{1, 2, 3, 4, 5})
	if err == nil {
		t.Fatal("a cancelled scan returned success")
	}
}

func TestComponentsCarryTheCPEAndTheOriginPort(t *testing.T) {
	res := &Result{Open: []Service{
		{Port: 443, Vendor: "apache", Product: "http_server", Version: "2.4.49"},
		{Port: 8080, Vendor: "nginx", Product: "nginx"}, // no version
	}}
	comps := res.Components()
	if len(comps) != 1 {
		t.Fatalf("components = %d, want only the one that states a version", len(comps))
	}
	c := comps[0]
	if c.CPE != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q", c.CPE)
	}
	if c.Version != "2.4.49" || c.Name != "http_server" || c.Vendor != "apache" {
		t.Errorf("component = %+v", c)
	}
	if !strings.Contains(c.Origin, "443") {
		t.Errorf("origin = %q, want it to name the port the evidence came from", c.Origin)
	}
}

// TLS is not confined to the ports a list remembers. On one real host nmap
// reported ssl/ on 2376, 8081, 8082, 8084, 8085, 22000 and 7010–8012 — a Docker
// API, a Syncthing relay, and several services on ports no fixed list contains.
// A prober that only tries TLS where it expects it reads an encrypted greeting
// as line noise and reports the port unidentified.
func TestTLSIsTriedOnAnyPortThatSaysNothingInClear(t *testing.T) {
	cert, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
				// Speaks only after the handshake, and only when asked.
				buf := make([]byte, 512)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Read(buf); err != nil {
					return
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
			}(c)
		}
	}()
	// A port with no conventional TLS meaning at all.
	port := ln.Addr().(*net.TCPAddr).Port

	s := New(Options{Timeout: 3 * time.Second, Engine: EngineBuiltin})
	sw, err := s.Run(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sw.HostsUp != 1 || len(sw.Hosts[0].Open) != 1 {
		t.Fatalf("nothing identified behind TLS: %+v", sw.Hosts)
	}
	svc := sw.Hosts[0].Open[0]
	if svc.Product != "nginx" || svc.Version != "1.18.0" {
		t.Errorf("identified %s %s, want nginx 1.18.0", svc.Product, svc.Version)
	}
	if svc.TLS == "" {
		t.Error("the certificate subject was not recorded")
	}
}

func selfSigned() (tls.Certificate, error) { return selfSignedFor("probe-test.example") }

func selfSignedFor(cn string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// A TLS service that completes the handshake and then says nothing has still
// said something: which certificate it holds. Docker's daemon, a Syncthing
// relay and a Kubernetes API all answer an unauthenticated GET with silence or
// a close, and the certificate is the only evidence about the port — it was
// being dropped because the banner was empty.
func TestTheCertificateSubjectSurvivesASilentTLSService(t *testing.T) {
	cert, err := selfSignedFor("syncthing")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
				// Handshake, read whatever the client asks, answer nothing.
				buf := make([]byte, 512)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				c.Read(buf)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	s := New(Options{Timeout: 700 * time.Millisecond})
	res, err := s.Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Open) != 1 {
		t.Fatalf("a silent TLS service with a telling certificate was not identified: open=%+v unidentified=%+v",
			res.Open, res.Unidentified)
	}
	if got := res.Open[0]; got.Product != "syncthing" || got.TLS == "" {
		t.Errorf("identified %+v, want syncthing with the certificate subject recorded", got)
	}
}

// dialCounter stands in for a network on which nothing listens and every
// connection is refused after a moment. It records how many dials were in
// flight at once and which addresses were tried, which is what the bounds
// below are about; the delay is what makes "at once" observable.
type dialCounter struct {
	delay    time.Duration
	inflight atomic.Int32
	peak     atomic.Int32
	calls    atomic.Int32
	mu       sync.Mutex
	hosts    map[string]bool
}

func (d *dialCounter) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	n := d.inflight.Add(1)
	defer d.inflight.Add(-1)
	for {
		p := d.peak.Load()
		if n <= p || d.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		d.mu.Lock()
		if d.hosts == nil {
			d.hosts = map[string]bool{}
		}
		d.hosts[host] = true
		d.mu.Unlock()
	}
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
}

func (d *dialCounter) hostCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.hosts)
}

// watchGoroutines samples the goroutine count until done closes and reports
// the highest it saw.
func watchGoroutines(done <-chan struct{}) int {
	peak := 0
	for {
		if g := runtime.NumGoroutine(); g > peak {
			peak = g
		}
		select {
		case <-done:
			return peak
		case <-time.After(200 * time.Microsecond):
		}
	}
}

// Concurrency bounds how many connections are open at once, and it has to
// bound the goroutines too. Starting one per port and letting them queue on a
// semaphore looked bounded and was not: "-ports all" was 65,535 goroutines
// created before the first connection, and each one is stack that stays
// allocated until its turn comes.
func TestScanRunsOnABoundedNumberOfGoroutines(t *testing.T) {
	const nports = 3000
	ports := make([]int, nports)
	for i := range ports {
		ports[i] = 10000 + i
	}
	dc := &dialCounter{delay: time.Millisecond}
	s := New(Options{Timeout: time.Second, Concurrency: 8})
	s.dialer = dc.dial

	before := runtime.NumGoroutine()
	done := make(chan struct{})
	var res *Result
	var err error
	go func() {
		defer close(done)
		res, err = s.Scan(context.Background(), "127.0.0.1", ports)
	}()
	peak := watchGoroutines(done)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Scanned != nports || dc.calls.Load() != nports {
		t.Errorf("scanned %d ports with %d dials, want %d of each", res.Scanned, dc.calls.Load(), nports)
	}
	if p := dc.peak.Load(); p > 8 {
		t.Errorf("%d connections in flight at once, want at most the concurrency of 8", p)
	}
	// The pool, the scan itself, and a little for the runtime and the test.
	if limit := before + 8 + 16; peak > limit {
		t.Errorf("goroutines peaked at %d for a %d-port scan at concurrency 8, want under %d: "+
			"the goroutine count is following the port count", peak, nports, limit)
	}
}

// The same for addresses: a /20 at one port must not become four thousand
// goroutines waiting their turn, because a /8 would be sixteen million.
func TestASweepRunsOnABoundedNumberOfGoroutines(t *testing.T) {
	dc := &dialCounter{delay: time.Millisecond}
	s := New(Options{Timeout: time.Second, Concurrency: 1, HostConcurrency: 4, Engine: EngineBuiltin})
	s.dialer = dc.dial

	before := runtime.NumGoroutine()
	done := make(chan struct{})
	var sw *Sweep
	var err error
	go func() {
		defer close(done)
		sw, err = s.Run(context.Background(), "10.0.0.0/20", []int{22})
	}()
	peak := watchGoroutines(done)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sw.HostsTotal != 4094 || dc.hostCount() != 4094 {
		t.Errorf("swept %d of %d addresses", dc.hostCount(), sw.HostsTotal)
	}
	if p := dc.peak.Load(); p > 4 {
		t.Errorf("%d connections in flight at once, want at most 4 hosts × 1 port", p)
	}
	if limit := before + 4 + 4 + 16; peak > limit {
		t.Errorf("goroutines peaked at %d sweeping 4094 addresses at host concurrency 4, want under %d: "+
			"the goroutine count is following the address count", peak, limit)
	}
}
