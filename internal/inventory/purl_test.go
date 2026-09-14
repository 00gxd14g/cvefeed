package inventory

import "testing"

func TestParsePURLSplitsFromTheRight(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantType  string
		wantNS    string
		wantName  string
		wantVer   string
		wantSub   string
		qualifier map[string]string
	}{
		{
			name:      "debian package with an epoch-free version and two qualifiers",
			in:        "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",
			wantType:  "deb",
			wantNS:    "debian",
			wantName:  "openssl",
			wantVer:   "3.0.11-1~deb12u2",
			qualifier: map[string]string{"arch": "amd64", "distro": "debian-12"},
		},
		{
			name:     "go module whose namespace contains slashes and whose subpath does too",
			in:       "pkg:golang/github.com/gin-gonic/gin@v1.9.1#internal/json",
			wantType: "golang",
			wantNS:   "github.com/gin-gonic",
			wantName: "gin",
			wantVer:  "v1.9.1",
			wantSub:  "internal/json",
		},
		{
			name:     "npm scope arrives percent-encoded",
			in:       "pkg:npm/%40angular/animation@12.3.1",
			wantType: "npm",
			wantNS:   "@angular",
			wantName: "animation",
			wantVer:  "12.3.1",
		},
		{
			name:     "rpm version carries an epoch colon",
			in:       "pkg:rpm/redhat/openssl@1:3.0.7-27.el9_5?arch=x86_64",
			wantType: "rpm",
			wantNS:   "redhat",
			wantName: "openssl",
			wantVer:  "1:3.0.7-27.el9_5",
		},
		{
			name:     "type is lowercased",
			in:       "pkg:NPM/lodash@4.17.20",
			wantType: "npm",
			wantName: "lodash",
			wantVer:  "4.17.20",
		},
		{
			name:     "no version at all",
			in:       "pkg:pypi/django",
			wantType: "pypi",
			wantName: "django",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parsePURL(tt.in)
			if !ok {
				t.Fatalf("parsePURL(%q) refused a valid package URL", tt.in)
			}
			if p.Type != tt.wantType || p.Namespace != tt.wantNS || p.Name != tt.wantName {
				t.Errorf("got type=%q namespace=%q name=%q, want %q/%q/%q",
					p.Type, p.Namespace, p.Name, tt.wantType, tt.wantNS, tt.wantName)
			}
			if p.Version != tt.wantVer {
				t.Errorf("version = %q, want %q", p.Version, tt.wantVer)
			}
			if p.Subpath != tt.wantSub {
				t.Errorf("subpath = %q, want %q", p.Subpath, tt.wantSub)
			}
			for k, want := range tt.qualifier {
				if got := p.Qualifiers[k]; got != want {
					t.Errorf("qualifier %s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestParsePURLRefusesWhatIsNotAPURL(t *testing.T) {
	for _, in := range []string{"", "openssl@3.0.11", "pkg:", "pkg:npm", "pkg:/", "http://example.test/pkg:npm/lodash"} {
		if _, ok := parsePURL(in); ok {
			t.Errorf("parsePURL(%q) accepted something that is not a package URL", in)
		}
	}
}

func TestNormalisePURLTouchesNothingButTheType(t *testing.T) {
	const in = "pkg:DEB/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"
	const want = "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"
	if got := normalisePURL(in); got != want {
		t.Errorf("normalisePURL(%q) = %q, want %q", in, got, want)
	}
	if got := normalisePURL("not a purl"); got != "" {
		t.Errorf("normalisePURL of a non-purl = %q, want the empty string", got)
	}
}

func TestPackageNameUsesTheEcosystemSpelling(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "org.apache.logging.log4j:log4j-core"},
		{"pkg:npm/%40angular/animation@12.3.1", "@angular/animation"},
		{"pkg:composer/laravel/framework@9.1.0", "laravel/framework"},
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.1", "github.com/gin-gonic/gin"},
		{"pkg:deb/debian/openssl@3.0.11-1", "openssl"},
		{"pkg:apk/alpine/musl@1.2.4-r2", "musl"},
		{"pkg:rpm/redhat/openssl@3.0.7-27.el9_5", "openssl"},
	}
	for _, tt := range tests {
		p, ok := parsePURL(tt.in)
		if !ok {
			t.Fatalf("parsePURL(%q) failed", tt.in)
		}
		if got := packageName(p); got != tt.want {
			t.Errorf("packageName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestVendorIsNotTakenFromADistroNamespace(t *testing.T) {
	// "debian" is the distribution that built the package, not the vendor an
	// advisory names, and offering it as one invites a vendor+product match
	// against rows that mean the upstream project.
	p, _ := parsePURL("pkg:deb/debian/openssl@3.0.11-1")
	if got := vendorFromPURL(p); got != "" {
		t.Errorf("vendorFromPURL = %q, want empty for a deb namespace", got)
	}
	p, _ = parsePURL("pkg:maven/org.slf4j/slf4j-api@1.7.36")
	if got := vendorFromPURL(p); got != "org.slf4j" {
		t.Errorf("vendorFromPURL = %q, want the Maven group", got)
	}
}

func TestEcosystemForPURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"pkg:npm/lodash@4.17.20", "npm"},
		{"pkg:pypi/requests@2.31.0", "PyPI"},
		{"pkg:cargo/openssl-src@111.22.0", "crates.io"},
		{"pkg:githubactions/actions/checkout@4", "GitHub Actions"},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "Debian:12"},
		// A codename cannot be turned into a release number without a table
		// that goes stale, and a stale entry is a silent false negative.
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-bookworm", "Debian"},
		// The qualifier does not say whether an Ubuntu release is an LTS, and
		// half of Canonical's ecosystem tokens carry that suffix.
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04", "Ubuntu"},
		{"pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19.1", "Alpine:v3.19"},
		{"pkg:apk/wolfi/openssl@3.1.4-r5", "Wolfi"},
		{"pkg:rpm/redhat/openssl@3.0.7-27.el9_5?distro=rhel-9.4", "Red Hat:rhel_9"},
		{"pkg:rpm/rocky/openssl@3.0.7-27?distro=rocky-9.3", "Rocky Linux:9"},
		// No OSV ecosystem publishes for CentOS or for generic purls, and
		// claiming one would have the matcher reject every row it sees.
		{"pkg:rpm/centos/openssl@3.0.7-27?distro=centos-9", ""},
		{"pkg:generic/curl@8.4.0", ""},
	}
	for _, tt := range tests {
		p, ok := parsePURL(tt.in)
		if !ok {
			t.Fatalf("parsePURL(%q) failed", tt.in)
		}
		if got := ecosystemForPURL(p); got != tt.want {
			t.Errorf("ecosystemForPURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBuildPURLLeavesVersionPunctuationAlone(t *testing.T) {
	// '~', '+' and ':' are ordinary characters in Debian and RPM versions and
	// no producer encodes them; encoding one side of an equality test loses the
	// match.
	got := buildPURL("deb", "debian", "openssl", "1:3.0.11-1~deb12u2+b1", map[string]string{
		"arch":   "amd64",
		"distro": "debian-bookworm",
	})
	const want = "pkg:deb/debian/openssl@1:3.0.11-1~deb12u2+b1?arch=amd64&distro=debian-bookworm"
	if got != want {
		t.Errorf("buildPURL = %q, want %q", got, want)
	}
}

func TestBuildPURLOrdersQualifiersAndDropsEmptyOnes(t *testing.T) {
	got := buildPURL("rpm", "redhat", "openssl", "3.0.7-27.el9_5", map[string]string{
		"epoch":  "1",
		"arch":   "",
		"distro": "rhel-9.4",
	})
	const want = "pkg:rpm/redhat/openssl@3.0.7-27.el9_5?distro=rhel-9.4&epoch=1"
	if got != want {
		t.Errorf("buildPURL = %q, want %q", got, want)
	}
}

func TestCPE22URIRebindsToTheFormattedString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"cpe:/a:apache:tomcat:9.0.75", "cpe:2.3:a:apache:tomcat:9.0.75:*:*:*:*:*:*:*"},
		{"cpe:/o:debian:debian_linux:12", "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"},
		// The packed edition carries four attributes 2.2 has no field for.
		// Leaving them packed asserts a condition nothing can satisfy.
		{"cpe:/a:acme:libfoo:1.2::~~~wordpress~~", "cpe:2.3:a:acme:libfoo:1.2:*:*:*:*:wordpress:*:*"},
		// Percent-encoding is undone before the formatted string re-escapes it,
		// so a colon inside an attribute survives as an escaped literal.
		{"cpe:/a:vendor:pro%3aduct:1.0", `cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`},
	}
	for _, tt := range tests {
		if got := cpe23(tt.in); got != tt.want {
			t.Errorf("cpe23(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCPE23StringIsPassedThroughUntouched(t *testing.T) {
	// Its attributes carry backslash escapes that a naive split on ':' would
	// mangle, and nothing here needs to look inside.
	const in = `cpe:2.3:a:libssl3:libssl3:3.0.11-1\~deb12u2:*:*:*:*:*:*:*`
	if got := cpe23(in); got != in {
		t.Errorf("cpe23 rewrote a 2.3 string: %q", got)
	}
	if got := cpe23("libssl3 3.0.11"); got != "" {
		t.Errorf("cpe23 of a non-CPE = %q, want the empty string", got)
	}
}
