// Package netscan identifies the software listening on a target host's ports
// and hands it to the matcher as an inventory.
//
// It reads what a service volunteers about itself and nothing more: connect,
// take the greeting, and for HTTP ask once for the root document so the Server
// header arrives. It never sends anything a service could act on beyond that
// request, and it never tries a vulnerability to see whether it works. What it
// produces is an inventory, exactly like an SBOM, and the same matcher decides
// what applies to it.
//
// The rule the rest of this package exists to keep is the project's own: a
// banner that does not state a version must not be turned into one. Banners are
// self-reported and often deliberately trimmed, so the honest outcome for
// "Server: nginx" is "nginx is here, I cannot tell which build" — reported to
// the operator, never quietly compared against a range.
package netscan

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Service is one identified listener.
type Service struct {
	Port int    `json:"port"`
	Raw  string `json:"banner,omitempty"`
	// Vendor and Product are CPE attributes, because that is the identity a
	// network service can be recognised by: no purl describes "the httpd
	// answering on port 80".
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	// TLS carries the certificate subject when the port spoke TLS, which is
	// evidence about the host rather than about the software.
	TLS string `json:"tls,omitempty"`
	// VendorNote records a vendor the corpus supplied in place of one the
	// scanner reported, so an adjusted identity is never a silent one.
	VendorNote string `json:"vendor_note,omitempty"`
}

// CPE renders the identity as a CPE 2.3 name, or "" when there is no version to
// put in it. A CPE whose version attribute is a wildcard matches every build
// ever shipped, so emitting one would turn "I could not tell" into "all of
// them".
func (s *Service) CPE() string {
	if s == nil || s.Vendor == "" || s.Product == "" || s.Version == "" {
		return ""
	}
	return "cpe:2.3:a:" + cpeAttr(s.Vendor) + ":" + cpeAttr(s.Product) + ":" +
		cpeAttr(s.Version) + ":*:*:*:*:*:*:*"
}

// Scannable reports whether this service can be tested against a version range
// at all.
func (s *Service) Scannable() bool { return s != nil && s.Version != "" }

// Why explains a service that cannot be scanned, for the operator who has to
// decide what to do about it.
func (s *Service) Why() string {
	switch {
	case s == nil:
		return "nothing on this port identified itself"
	case s.Product == "":
		return "the banner names no software"
	case s.Version == "":
		return "the banner names " + s.Product + " but states no version, so no range can be tested against it"
	}
	return ""
}

// cpeAttr escapes a CPE 2.3 attribute value.
func cpeAttr(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		switch r {
		case ':', '/', '?', '*', '!', '"', ';', '<', '>', '=', '[', ']', '(', ')', '{', '}', '~', '#', '$', '%', '^', '&', '+', ',', '@', '`', '|', '\\', '\'':
			b.WriteByte('\\')
		case ' ':
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// rule matches one product family in a banner.
//
// Each carries the CPE vendor the NVD files that product under, which is rarely
// the obvious word and is not guessable: OpenSSH is filed under "openbsd",
// vsftpd under "vsftpd_project", Apache httpd is "http_server" not "httpd", and
// nginx is under "f5" — 684 statements against 2 for the obvious "nginx".
// Getting this wrong does not fail loudly; it silently downgrades every finding
// to a bare-name match, which the default confidence floor then hides. Every
// pair here was checked against the loaded corpus rather than recalled, and
// TestFingerprintVendorsExistInTheCorpus keeps checking.
type rule struct {
	re      *regexp.Regexp
	vendor  string
	product string
	// version names the capture group holding the version, when the pattern has
	// one. A rule with no version group identifies the software and says so.
	version int
}

var rules = []rule{
	// SSH transport greeting, RFC 4253 §4.2: SSH-<protoversion>-<softwareversion>
	//
	// The version capture has to begin with a digit. Microsoft's port announces
	// itself as "OpenSSH_for_Windows_8.1", and a capture that took whatever
	// followed the underscore reported version "for_Windows_8.1" and built a
	// CPE out of it — a claim about a build that does not exist. A greeting
	// like that identifies OpenSSH through the version-less rule below and
	// states no version, which is the truth.
	{regexp.MustCompile(`(?i)^SSH-[\d.]+-OpenSSH[_-](\d[\w.]*?)(?:[\s-]|$)`), "openbsd", "openssh", 1},
	{regexp.MustCompile(`(?i)^SSH-[\d.]+-dropbear[_-](\d[\w.]*)`), "dropbear_ssh_project", "dropbear_ssh", 1},
	{regexp.MustCompile(`(?i)^SSH-[\d.]+-OpenSSH`), "openbsd", "openssh", 0},

	// HTTP Server header. The bare "Apache" is anchored to what can follow the
	// product name in a real header — a slash, a space or the end of the line —
	// because \b also matches before a hyphen, and "Apache-Coyote/1.1" is
	// Tomcat's connector, not httpd.
	{regexp.MustCompile(`(?im)^Server:\s*Apache/([\d.]+[\w.]*)`), "apache", "http_server", 1},
	{regexp.MustCompile(`(?im)^Server:\s*Apache(?:/|\s|$)`), "apache", "http_server", 0},
	{regexp.MustCompile(`(?im)^Server:\s*nginx/([\d.]+)`), "f5", "nginx", 1},
	{regexp.MustCompile(`(?im)^Server:\s*nginx\b`), "f5", "nginx", 0},
	{regexp.MustCompile(`(?im)^Server:\s*Microsoft-IIS/([\d.]+)`), "microsoft", "internet_information_services", 1},
	{regexp.MustCompile(`(?im)^Server:\s*lighttpd/([\d.]+)`), "lighttpd", "lighttpd", 1},
	{regexp.MustCompile(`(?im)^Server:\s*openresty/([\d.]+)`), "openresty", "openresty", 1},
	{regexp.MustCompile(`(?im)^Server:\s*Jetty\(([\d.]+[\w.]*)\)`), "eclipse", "jetty", 1},
	{regexp.MustCompile(`(?im)^X-Powered-By:\s*PHP/([\d.]+)`), "php", "php", 1},

	// FTP.
	{regexp.MustCompile(`(?i)^220[\s-].*vsFTPd\s+([\d.]+)`), "vsftpd_project", "vsftpd", 1},
	{regexp.MustCompile(`(?i)^220[\s-].*ProFTPD\s+([\d.]+\w*)`), "proftpd", "proftpd", 1},
	{regexp.MustCompile(`(?i)^220[\s-].*Pure-FTPd`), "pureftpd", "pure-ftpd", 0},
	{regexp.MustCompile(`(?i)^220[\s-].*FileZilla Server\s+([\d.]+)`), "filezilla-project", "filezilla_server", 1},

	// SMTP.
	{regexp.MustCompile(`(?i)^220[\s-].*Postfix`), "postfix", "postfix", 0},
	{regexp.MustCompile(`(?i)^220[\s-].*Exim\s+([\d.]+)`), "exim", "exim", 1},
	{regexp.MustCompile(`(?i)^220[\s-].*Sendmail\s+([\d.]+[\w.\-]*)`), "sendmail", "sendmail", 1},

	// Databases and caches, which announce themselves on connect or on error.
	{regexp.MustCompile(`(?i)([\d]+\.[\d]+\.[\d]+)[\w.\-]*\x00.*mysql_native_password`), "oracle", "mysql", 1},
	{regexp.MustCompile(`(?i)^\+OK\b.*Dovecot`), "dovecot", "dovecot", 0},
	{regexp.MustCompile(`(?i)redis_version:([\d.]+)`), "redis", "redis", 1},
	{regexp.MustCompile(`(?i)^\* OK .*Cyrus IMAP\s+([\d.]+)`), "cyrus", "imap", 1},
}

// Identify reads a banner and reports the software it names.
//
// It returns nil when the banner names nothing recognisable — which is the
// common case for a bespoke service, and is not an error. The port is taken
// only as context; identification comes from the bytes, because a service on a
// non-standard port is still that service and a port number on its own is not
// evidence of anything.
//
// A banner can name more than one product; this reports the first, which the
// rule order makes the most specific. IdentifyAll reports the rest as well.
func Identify(port int, banner string) *Service {
	all := IdentifyAll(port, banner)
	if len(all) == 0 {
		return nil
	}
	return all[0]
}

// IdentifyAll reads a banner and reports every product it names, one Service
// per distinct product in rule order.
//
// One banner routinely names two pieces of software: an HTTP response carries
// "Server: nginx/1.18.0" and "X-Powered-By: PHP/7.4.3" together, and both are
// things the corpus has advisories about. Stopping at the first rule to match
// reported the web server and threw the PHP version away — a stated version,
// which is the rarest and most useful thing a banner offers.
//
// Two rules for the same product both matching is not two products: the SSH
// rules pair a versioned pattern with a version-less one so that a greeting
// whose version does not look like one still identifies the software. The
// rules are ordered most specific first, so the first match for a product is
// the one kept.
func IdentifyAll(port int, banner string) []*Service {
	b := strings.TrimSpace(banner)
	if b == "" {
		return nil
	}
	var out []*Service
	seen := map[[2]string]bool{}
	for _, r := range rules {
		m := r.re.FindStringSubmatch(b)
		if m == nil {
			continue
		}
		key := [2]string{r.vendor, r.product}
		if seen[key] {
			continue
		}
		seen[key] = true
		s := &Service{Port: port, Raw: truncateBanner(b), Vendor: r.vendor, Product: r.product}
		if r.version > 0 && r.version < len(m) {
			// The same shape check nmap's version attribute gets: one token
			// that begins with a digit. The patterns above already enforce it,
			// and this keeps a future pattern from loosening it by accident —
			// the product is still identified, the version simply stays
			// unstated rather than becoming something that is not one.
			if v := strings.TrimSpace(m[r.version]); looksLikeVersion(v) {
				s.Version = v
			}
		}
		out = append(out, s)
	}
	return out
}

// maxBannerBytes bounds what is carried into a report. A banner is remote input
// and some services answer with a whole page.
const maxBannerBytes = 512

func truncateBanner(b string) string {
	b = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, b)
	b = strings.Join(strings.Fields(b), " ")
	if len(b) > maxBannerBytes {
		// Cut on a rune boundary. The limit is in bytes because that is what
		// a report's size is measured in, but a banner is text, and slicing a
		// multi-byte sequence in half leaves an invalid string that a JSON
		// encoder replaces with U+FFFD and a terminal renders as noise.
		cut := maxBannerBytes
		for cut > 0 && !utf8.RuneStart(b[cut]) {
			cut--
		}
		return b[:cut] + "…"
	}
	return b
}

// certRules match a product name in a TLS certificate subject.
//
// The certificate is the one thing a TLS service always volunteers, and for a
// service whose protocol nothing here speaks it is the only thing. It names
// software and never a version, so what it produces is "this is here, I cannot
// tell which build" — reported, and never compared against a range.
var certRules = []struct {
	needle  string
	vendor  string
	product string
}{
	{"syncthing", "syncthing", "syncthing"},
	{"docker", "docker", "docker"},
	{"kubernetes", "kubernetes", "kubernetes"},
	{"elasticsearch", "elastic", "elasticsearch"},
	{"rabbitmq", "pivotal_software", "rabbitmq"},
	{"grafana", "grafana", "grafana"},
	{"jenkins", "jenkins", "jenkins"},
	{"vmware", "vmware", "vmware"},
	{"ubiquiti", "ui", "unifi"},
	{"pfsense", "netgate", "pfsense"},
	{"synology", "synology", "diskstation_manager"},
	{"qnap", "qnap", "qts"},
	{"plex", "plex", "plex_media_server"},
	{"minio", "minio", "minio"},
}

// IdentifyTLS reads a certificate subject for the name of the software behind
// it, for the ports where the protocol itself gave nothing away.
//
// A needle has to match a whole token of the subject, not a substring of one.
// "multiplex.example.com" contains "plex" and is not a Plex server, and a
// certificate for "dockerhub-proxy" is not the Docker daemon; a substring
// match turned both into products. Tokens are the runs of letters and digits,
// so "CN=docker,O=Docker Inc", "plex.direct" and "pfSense-fw1" still match.
func IdentifyTLS(port int, subject string) *Service {
	if strings.TrimSpace(subject) == "" {
		return nil
	}
	tokens := map[string]bool{}
	for _, tok := range strings.FieldsFunc(strings.ToLower(subject), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		tokens[tok] = true
	}
	for _, r := range certRules {
		if !tokens[r.needle] {
			continue
		}
		return &Service{
			Port: port, Vendor: r.vendor, Product: r.product,
			TLS: subject,
			Raw: truncateBanner("tls certificate: " + subject),
		}
	}
	return nil
}
