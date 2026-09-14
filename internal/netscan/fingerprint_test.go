package netscan

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Every banner below was copied from a real service. The point of the table is
// not breadth but the distinction the whole scanner rests on: a banner that
// states a version yields a component, and a banner that does not must not be
// turned into one.
func TestBannerYieldsAComponentOnlyWhenItStatesAVersion(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		banner  string
		want    *Service // nil means: identified nothing usable
		wantCPE string
	}{
		{
			name:   "openssh states its version",
			port:   22,
			banner: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
			want: &Service{
				Vendor: "openbsd", Product: "openssh", Version: "8.4p1",
			},
			wantCPE: "cpe:2.3:a:openbsd:openssh:8.4p1:*:*:*:*:*:*:*",
		},
		{
			name:   "apache states its version in the Server header",
			port:   80,
			banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\n\r\n",
			want: &Service{
				Vendor: "apache", Product: "http_server", Version: "2.4.49",
			},
			wantCPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
		{
			name:   "nginx states its version",
			port:   80,
			banner: "HTTP/1.1 404 Not Found\r\nServer: nginx/1.18.0\r\n\r\n",
			want:   &Service{Vendor: "f5", Product: "nginx", Version: "1.18.0"},
		},
		{
			name:   "vsftpd states its version",
			port:   21,
			banner: "220 (vsFTPd 3.0.3)\r\n",
			want:   &Service{Vendor: "vsftpd_project", Product: "vsftpd", Version: "3.0.3"},
		},
		{
			name:   "postfix names itself with no version at all",
			port:   25,
			banner: "220 mail.example.org ESMTP Postfix\r\n",
			// Identified, but there is nothing to compare against a range.
			want: &Service{Vendor: "postfix", Product: "postfix"},
		},
		{
			name:   "a hardened nginx suppresses its version",
			port:   80,
			banner: "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
			want:   &Service{Vendor: "f5", Product: "nginx"},
		},
		{
			name:   "a bare greeting identifies nothing",
			port:   9999,
			banner: "hello\r\n",
			want:   nil,
		},
		{
			name:   "an empty banner identifies nothing",
			port:   9999,
			banner: "",
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Identify(tc.port, tc.banner)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("identified %+v from a banner that names no software", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("identified nothing from %q", tc.banner)
			}
			if got.Product != tc.want.Product || got.Vendor != tc.want.Vendor {
				t.Errorf("vendor/product = %q/%q, want %q/%q",
					got.Vendor, got.Product, tc.want.Vendor, tc.want.Product)
			}
			if got.Version != tc.want.Version {
				t.Errorf("version = %q, want %q; a version that was not stated must stay empty",
					got.Version, tc.want.Version)
			}
			if tc.wantCPE != "" && got.CPE() != tc.wantCPE {
				t.Errorf("cpe = %q, want %q", got.CPE(), tc.wantCPE)
			}
		})
	}
}

// A service identified without a version still has to reach the operator. It
// cannot produce a finding, and silently dropping it is how a scan reports a
// host as clean when it never tested half of it.
func TestAVersionlessServiceIsReportedRatherThanDropped(t *testing.T) {
	s := Identify(80, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	if s == nil {
		t.Fatal("nginx without a version was discarded entirely")
	}
	if s.Scannable() {
		t.Error("a service with no version claims to be scannable; it cannot match any range")
	}
	if s.Why() == "" {
		t.Error("no reason recorded for why it cannot be scanned")
	}
}

// A TLS service that says nothing recognisable in its response has still said
// something: the certificate it presented. Syncthing puts its own name in the
// common name, Docker's daemon certificate is issued for the daemon, and a
// self-signed appliance certificate usually names the product. It is weaker
// evidence than a version banner and it is not nothing, which is what those
// ports were being reported as.
func TestACertificateNamesSoftwareWhenTheResponseDoesNot(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		want    string
	}{
		{"syncthing", "CN=syncthing,O=Syncthing", "syncthing"},
		{"docker daemon", "CN=docker,O=Docker Inc", "docker"},
		{"nothing recognisable", "CN=localhost", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IdentifyTLS(443, tc.subject)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("identified %+v from %q", got, tc.subject)
				}
				return
			}
			if got == nil {
				t.Fatalf("identified nothing from %q", tc.subject)
			}
			if got.Product != tc.want {
				t.Errorf("product = %q, want %q", got.Product, tc.want)
			}
			// A certificate names software, never a version. It must not
			// become a finding.
			if got.Version != "" {
				t.Errorf("version = %q; a certificate does not state one", got.Version)
			}
			if got.Scannable() {
				t.Error("a certificate-only identification claims to be scannable")
			}
		})
	}
}

// A version capture that took whatever followed the product name turned
// "OpenSSH_for_Windows_8.1" into version "for_Windows_8.1" and built a CPE for
// a build that does not exist. A version begins with a digit; anything else
// identifies the software and states nothing.
func TestAVersionThatDoesNotBeginWithADigitIsNotAVersion(t *testing.T) {
	cases := []struct {
		banner  string
		product string
		version string
	}{
		{"SSH-2.0-OpenSSH_for_Windows_8.1\r\n", "openssh", ""},
		{"SSH-2.0-OpenSSH_8.1\r\n", "openssh", "8.1"},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", "openssh", "9.2p1"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", "openssh", "8.9p1"},
		{"SSH-2.0-dropbear_2022.83\r\n", "dropbear_ssh", "2022.83"},
	}
	for _, tc := range cases {
		got := Identify(22, tc.banner)
		if got == nil {
			t.Errorf("Identify(%q) = nil, want %s", tc.banner, tc.product)
			continue
		}
		if got.Product != tc.product || got.Version != tc.version {
			t.Errorf("Identify(%q) = %s %q, want %s %q", tc.banner, got.Product, got.Version, tc.product, tc.version)
		}
		if tc.version == "" && got.CPE() != "" {
			t.Errorf("Identify(%q) built CPE %q out of no version", tc.banner, got.CPE())
		}
	}
}

// One HTTP answer routinely names two pieces of software: the server in its
// Server header and the runtime behind it in X-Powered-By. The first rule to
// match used to end the search, so a host running nginx in front of PHP was
// inventoried as nginx alone and the PHP version — a stated version, the most
// useful thing a banner offers — was thrown away.
func TestABannerNamingTwoProductsReportsBoth(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4.3\r\n\r\n"
	all := IdentifyAll(80, banner)
	if len(all) != 2 {
		t.Fatalf("IdentifyAll found %d products, want nginx and php: %+v", len(all), all)
	}
	if all[0].Product != "nginx" || all[0].Version != "1.18.0" {
		t.Errorf("first = %s %q, want nginx 1.18.0: the server is the primary identification", all[0].Product, all[0].Version)
	}
	if all[1].Vendor != "php" || all[1].Product != "php" || all[1].Version != "7.4.3" {
		t.Errorf("second = %s:%s %q, want php:php 7.4.3", all[1].Vendor, all[1].Product, all[1].Version)
	}
	if got := Identify(80, banner); got == nil || got.Product != "nginx" {
		t.Errorf("Identify = %+v, want the primary, nginx", got)
	}
	// Two rules for one product — the versioned SSH pattern and its
	// version-less fallback — are one product, not two.
	if all := IdentifyAll(22, "SSH-2.0-OpenSSH_8.4p1\r\n"); len(all) != 1 {
		t.Errorf("IdentifyAll reported OpenSSH %d times: %+v", len(all), all)
	}

	// And both reach the scan's result, which is where the inventory is read.
	port := listenBanner(t, banner)
	res, err := New(Options{Timeout: 2 * time.Second}).Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatal(err)
	}
	products := map[string]string{}
	for _, svc := range res.Open {
		products[svc.Product] = svc.Version
	}
	if products["nginx"] != "1.18.0" || products["php"] != "7.4.3" {
		t.Errorf("scan reported %v, want nginx 1.18.0 and php 7.4.3 on the one port", products)
	}
}

// "Apache-Coyote/1.1" is Tomcat's HTTP connector. A word boundary after
// "Apache" matches before the hyphen, and every Tomcat on the network was
// being reported as Apache httpd of no particular version.
func TestApacheCoyoteIsNotApacheHTTPServer(t *testing.T) {
	if got := Identify(8080, "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n"); got != nil {
		t.Fatalf("identified %s:%s from a Tomcat connector header", got.Vendor, got.Product)
	}
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Apache (Ubuntu)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)\r\n\r\n",
	} {
		got := Identify(80, banner)
		if got == nil || got.Product != "http_server" {
			t.Errorf("Identify(%q) = %+v, want apache http_server", banner, got)
		}
	}
}

// A product name inside another word is not that product. "multiplex" is
// not Plex and a "dockerhub-proxy" is not the Docker daemon; the certificate
// has to name the software as a word of its own.
func TestACertificateNeedleMatchesWholeTokensOnly(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"CN=multiplex.example.com", ""},
		{"CN=dockerhub-proxy.example.com", ""},
		{"CN=complexity.example.com", ""},
		{"CN=*.plex.direct", "plex_media_server"},
		{"CN=docker,O=Docker Inc", "docker"},
		{"CN=pfSense-fw1.lan", "pfsense"},
		{"CN=rabbitmq-node1", "rabbitmq"},
	}
	for _, tc := range cases {
		got := IdentifyTLS(443, tc.subject)
		switch {
		case tc.want == "" && got != nil:
			t.Errorf("IdentifyTLS(%q) = %s, want nothing", tc.subject, got.Product)
		case tc.want != "" && got == nil:
			t.Errorf("IdentifyTLS(%q) = nil, want %s", tc.subject, tc.want)
		case tc.want != "" && got.Product != tc.want:
			t.Errorf("IdentifyTLS(%q) = %s, want %s", tc.subject, got.Product, tc.want)
		}
	}
}

// The banner limit is in bytes, and a byte limit cut through the middle of a
// multi-byte character, leaving a string no JSON encoder or terminal could
// render as anything but a replacement mark.
func TestTruncatingABannerDoesNotSplitACharacter(t *testing.T) {
	banner := strings.Repeat("a", maxBannerBytes-1) + "é" + strings.Repeat("b", 10)
	got := truncateBanner(banner)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated banner is not valid UTF-8: ends %q", got[len(got)-8:])
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated banner does not say it was truncated: %q", got[len(got)-8:])
	}
	if len(got) > maxBannerBytes+len("…") {
		t.Errorf("truncated banner is %d bytes, want at most %d plus the mark", len(got), maxBannerBytes)
	}
}
