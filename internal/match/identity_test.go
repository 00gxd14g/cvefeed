package match

import "testing"

func TestPURLCanonicalisationFoldsOnlyWhatTheEcosystemItselfFolds(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		valid bool
	}{
		{"type is case-insensitive and PyPI names are PEP 503 normalised",
			"pkg:PyPI/Django@4.0", "pkg:pypi/django", true},
		{"PyPI collapses runs of dots, dashes and underscores",
			"pkg:pypi/Flask__Login.Ext", "pkg:pypi/flask-login-ext", true},
		{"an npm scope survives percent-decoding",
			"pkg:npm/%40angular/core@13.0.0", "pkg:npm/@angular/core", true},
		{"an unencoded npm scope with no version is still a purl",
			"pkg:npm/@angular/core", "pkg:npm/@angular/core", true},
		{"an unencoded npm scope with a version",
			"pkg:npm/@angular/core@13.0.0", "pkg:npm/@angular/core", true},
		{"crates.io keeps dash and underscore apart because the registry does",
			"pkg:cargo/foo_bar", "pkg:cargo/foo_bar", true},
		{"Maven coordinates stay case-sensitive",
			"pkg:maven/org.apache.Commons/Commons-Lang3@3.12", "pkg:maven/org.apache.Commons/Commons-Lang3", true},
		{"only the host of a Go module path is a DNS name",
			"pkg:golang/GitHub.com/Foo/Bar@v1.2.3", "pkg:golang/github.com/Foo/Bar", true},
		{"build qualifiers and the subpath are not identity",
			"pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12#usr/lib", "pkg:deb/debian/openssl", true},
		{"the namespace is part of the name",
			"pkg:deb/ubuntu/openssl@3.0.11-1", "pkg:deb/ubuntu/openssl", true},
		{"a bare product name is not a purl", "openssl", "", false},
		{"a purl needs a type and a name", "pkg:npm", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := parsePURL(tc.in)
			if ok != tc.valid {
				t.Fatalf("parsePURL(%q) ok = %v, want %v", tc.in, ok, tc.valid)
			}
			if ok && p.Canonical != tc.want {
				t.Fatalf("canonical = %q, want %q", p.Canonical, tc.want)
			}
		})
	}
}

func TestPURLQualifiersTheVersionTestStillNeedsAreKept(t *testing.T) {
	p, ok := parsePURL("pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64&epoch=1&distro=rhel-9")
	if !ok {
		t.Fatal("parsePURL failed on a Red Hat VEX purl")
	}
	// Epoch is dropped from identity but is part of RPM version ordering, and
	// distro is dropped from identity but is the release constraint.
	if p.Epoch != "1" || p.Distro != "rhel-9" || p.Version != "3.0.7-27.el9" {
		t.Fatalf("epoch=%q distro=%q version=%q", p.Epoch, p.Distro, p.Version)
	}
	if fam, rel := purlEcosystem(p); fam != "redhat" || rel != "9" {
		t.Fatalf("ecosystem = %q/%q, want redhat/9", fam, rel)
	}
}

func TestCPEAttributeRelations(t *testing.T) {
	tests := []struct {
		name string
		row  string
		comp string
		want cpeRelation
	}{
		{"ANY on the row admits anything", "*", "wordpress", cpeSatisfied},
		{"NA matches only NA", "-", "-", cpeSatisfied},
		{"NA against a literal is a contradiction", "-", "wordpress", cpeDisjoint},
		{"equal literals match case-insensitively", "WordPress", "wordpress", cpeSatisfied},
		{"different literals are disjoint", "wordpress", "drupal", cpeDisjoint},
		{"a literal the component does not know is unproven, not satisfied", "wordpress", "*", cpeUnproven},
		{"a wildcarded literal globs", "libfoo*", "libfoo_extra", cpeSatisfied},
		{"a glob that does not match is disjoint", "libfoo*", "libbar", cpeDisjoint},
		{"'?' matches exactly one character", "libfoo?", "libfoo1", cpeSatisfied},
		{"'?' does not match two", "libfoo?", "libfoo12", cpeDisjoint},
		{"an escaped wildcard is a literal", `libfoo\*`, "libfoo*", cpeSatisfied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cpeAttrRelation(tc.row, tc.comp); got != tc.want {
				t.Fatalf("cpeAttrRelation(%q, %q) = %v, want %v", tc.row, tc.comp, got, tc.want)
			}
		})
	}
}

func TestCPE22URIUnpacksThePackedEditionField(t *testing.T) {
	a, ok := parseCPE("cpe:/a:acme:libfoo:1.2.3::~~~wordpress~~")
	if !ok {
		t.Fatal("parseCPE rejected a CPE 2.2 URI")
	}
	if a.part != "a" || a.vendor != "acme" || a.product != "libfoo" || a.version != "1.2.3" {
		t.Fatalf("identity attributes = %+v", a)
	}
	if a.targetSW != "wordpress" {
		t.Fatalf("target_sw = %q, want wordpress; leaving the edition packed compares ~~~wordpress~~ against a target_sw", a.targetSW)
	}
	if a.update != "*" {
		t.Fatalf("update = %q, want ANY for an omitted URI attribute", a.update)
	}
}

func TestMalformedCPEIsRejectedRatherThanGuessedAt(t *testing.T) {
	for _, in := range []string{"", "libfoo", "cpe:2.3:a:acme:libfoo", "cpe:2.3:a:acme:libfoo:1.0:*:*:*:*:*:*:*:extra"} {
		if _, ok := parseCPE(in); ok {
			t.Errorf("parseCPE(%q) accepted a name it cannot have read correctly", in)
		}
	}
}

func TestVendorFoldStripsLegalEntityNoiseAndNothingElse(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Acme Inc.", "acme"},
		{"ACME Corporation", "acme"},
		{"The Apache Software Foundation", "apache-software"},
		{"Open Build Service", "open-build-service"},
		{"xfree86", "xfree86"},
		{"Red_Hat", "red-hat"},
		{"Inc", "inc"},
	}
	for _, tc := range tests {
		if got := foldVendor(tc.in); got != tc.want {
			t.Errorf("foldVendor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNameFoldDoesNotInventEqualities(t *testing.T) {
	// Separator and case differences only. Nothing here may merge two products
	// that the upstream spells differently on purpose.
	if foldName("remote-login-service") != foldName("Remote Login Service") {
		t.Error("separator and case differences must fold")
	}
	if foldName("libssl3") == foldName("libssl") {
		t.Error("a trailing version-like token is part of the name, not noise")
	}
	if foldName("marked") == foldName("markdown") {
		t.Error("no fuzzy matching is permitted in the identity test")
	}
}

func TestEcosystemSplitHandlesTheReleaseSpellingsUpstreamsUse(t *testing.T) {
	tests := []struct {
		in      string
		family  string
		release string
	}{
		{"Debian:12", "debian", "12"},
		{"Ubuntu:22.04:LTS", "ubuntu", "22.04"},
		{"Alpine:v3.19", "alpine", "3.19"},
		{"Red Hat:rhel_9", "redhat", "9"},
		{"Red Hat:rhel-9", "redhat", "9"},
		{"Red Hat:9", "redhat", "9"},
		{"crates.io", "cargo", ""},
		{"PyPI", "pypi", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		fam, rel := splitEcosystem(tc.in)
		if fam != tc.family || rel != tc.release {
			t.Errorf("splitEcosystem(%q) = %q/%q, want %q/%q", tc.in, fam, rel, tc.family, tc.release)
		}
	}
}

// BenchmarkIdentify pins the cost of the identity test, which runs once per
// (component, candidate row) pair and is capped at 2,000 candidates per
// component: work repeated here is repeated a hundred million times per scan.
func BenchmarkIdentify(b *testing.B) {
	comp := Component{
		Name: "libssl3", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12",
		PURL:   "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12",
		Origin: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=source&distro=debian-12",
	}
	rows := []Affected{
		{Product: "openssl", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/openssl", Source: "osv"},
		{Product: "zlib", Ecosystem: "Debian:12", PURL: "pkg:deb/debian/zlib", Source: "osv"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		identify(comp, rows[i%len(rows)])
	}
}

func TestOnlyAnAtSignAfterTheLastSlashSeparatesTheVersion(t *testing.T) {
	// Producers write npm scopes unencoded. On a version-less scoped purl the
	// last '@' is the scope's, and taking it as the separator left "npm" as the
	// whole path and rejected the purl.
	p, ok := parsePURL("pkg:npm/@angular/core")
	if !ok || p.Version != "" || p.Namespace != "@angular" || p.Name != "core" {
		t.Fatalf("parsePURL(pkg:npm/@angular/core) = %+v, %v", p, ok)
	}
	p, ok = parsePURL("pkg:npm/@angular/core@13.0.0")
	if !ok || p.Version != "13.0.0" || p.Namespace != "@angular" || p.Name != "core" {
		t.Fatalf("parsePURL(pkg:npm/@angular/core@13.0.0) = %+v, %v", p, ok)
	}
}

func TestDerivativeDistributionsFoldOntoTheParentFamily(t *testing.T) {
	// Mint ships Ubuntu's packages and Raspbian ships Debian's; the advisories
	// are filed under the parent. pkg:github is the purl type for actions.
	tests := []struct {
		name    string
		in      string
		family  string
		release string
	}{
		{"Linux Mint is Ubuntu, on Mint's own release numbers", "Linux Mint:21.2", "ubuntu", ""},
		{"linuxmint spelled as an id", "linuxmint:21", "ubuntu", ""},
		{"Raspbian is Debian, on Debian's numbers", "Raspbian:12", "debian", "12"},
		{"GitHub Actions itself", "GitHub Actions", "github actions", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if fam, rel := splitEcosystem(tc.in); fam != tc.family || rel != tc.release {
				t.Fatalf("splitEcosystem(%q) = %q/%q, want %q/%q", tc.in, fam, rel, tc.family, tc.release)
			}
		})
	}
	purls := []struct {
		name    string
		in      string
		family  string
		release string
	}{
		{"pkg:github is the actions ecosystem", "pkg:github/actions/checkout@v4", "github actions", ""},
		{"a Mint package is an Ubuntu package with an unknown release", "pkg:deb/linuxmint/libfoo@1.0?distro=linuxmint-21.2", "ubuntu", ""},
		{"a Raspbian package is a Debian package on the same release", "pkg:deb/raspbian/libfoo@1.0?distro=raspbian-12", "debian", "12"},
	}
	for _, tc := range purls {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := parsePURL(tc.in)
			if !ok {
				t.Fatalf("parsePURL(%q) failed", tc.in)
			}
			if fam, rel := purlEcosystem(p); fam != tc.family || rel != tc.release {
				t.Fatalf("purlEcosystem(%q) = %q/%q, want %q/%q", tc.in, fam, rel, tc.family, tc.release)
			}
		})
	}
	// Both tables must agree, or a family folded here spells back as something
	// that folds elsewhere.
	for _, family := range []string{"linuxmint", "raspbian"} {
		if losslessEcosystems[family] || osvNames[family] != "" {
			t.Errorf("%q still has entries of its own; nothing folds to it any more", family)
		}
	}
}

func TestPURLDistroReleaseIsReducedToTheOSVSpelling(t *testing.T) {
	// The qualifier carries os-release VERSION_ID verbatim, and the corpus
	// spells releases per major (Debian:12) or major.minor (Alpine:v3.18).
	// internal/inventory reduces the same way, and a host must not be in
	// release conflict with its own advisories.
	tests := []struct {
		in      string
		family  string
		release string
	}{
		{"pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.18.4", "alpine", "3.18"},
		{"pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.18", "alpine", "3.18"},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12.4", "debian", "12"},
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-bookworm", "debian", "bookworm"},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04", "ubuntu", "22.04"},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04.3", "ubuntu", "22.04"},
		{"pkg:rpm/redhat/openssl@3.0.7-27.el9?distro=rhel-9.2", "redhat", "9"},
		{"pkg:rpm/rocky/openssl@3.0.7-27.el9?distro=rocky-9.3", "rocky", "9"},
	}
	for _, tc := range tests {
		p, ok := parsePURL(tc.in)
		if !ok {
			t.Fatalf("parsePURL(%q) failed", tc.in)
		}
		if fam, rel := purlEcosystem(p); fam != tc.family || rel != tc.release {
			t.Errorf("purlEcosystem(%q) = %q/%q, want %q/%q", tc.in, fam, rel, tc.family, tc.release)
		}
	}
}
