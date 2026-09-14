package inventory

import (
	"strings"
	"testing"
)

// purlListFixture is a host inventory exported as package URLs: comments, blank
// lines, a subpath, a version-less entry and one line that is not a purl at all.
const purlListFixture = `# host inventory exported 2026-08-17
pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12
pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12
pkg:golang/github.com/gin-gonic/gin@v1.9.1#internal/json
pkg:npm/%40angular/animation@12.3.1
pkg:npm/lodash@4.17.20
pkg:pypi/requests@2.31.0
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
pkg:cargo/openssl-src@111.22.0
pkg:gem/rack@2.2.6.4
pkg:composer/laravel/framework@9.1.0
pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1
pkg:rpm/redhat/openssl@3.0.7-27.el9_5?arch=x86_64&distro=rhel-9.4&epoch=1

   # an indented comment
pkg:pypi/django
pkg:
`

func TestPURLListSkipsUnreadableLinesButKeepsTheRest(t *testing.T) {
	comps, err := ParsePURLList(strings.NewReader(purlListFixture))
	if err != nil {
		t.Fatalf("ParsePURLList: %v", err)
	}
	if len(comps) != 13 {
		t.Fatalf("got %d components, want the 13 readable entries: %+v", len(comps), comps)
	}
	for _, c := range comps {
		if c.Name == "" {
			t.Errorf("component with no name got through: %+v", c)
		}
	}
}

func TestPURLListHashIsASubpathNotAComment(t *testing.T) {
	comps, err := ParsePURLList(strings.NewReader(purlListFixture))
	if err != nil {
		t.Fatalf("ParsePURLList: %v", err)
	}
	// Cutting the line at '#' would turn this into pkg:golang/github.com/gin-gonic/gin,
	// which is a different package URL and, with a subpath, a different package.
	got := componentByName(t, comps, "github.com/gin-gonic/gin")
	if !strings.HasSuffix(got.PURL, "#internal/json") {
		t.Errorf("purl = %q, want the subpath kept", got.PURL)
	}
	if got.Version != "v1.9.1" {
		t.Errorf("version = %q, want v1.9.1", got.Version)
	}
}

func TestPURLListVersionlessEntryKeepsAnEmptyVersion(t *testing.T) {
	comps, err := ParsePURLList(strings.NewReader(purlListFixture))
	if err != nil {
		t.Fatalf("ParsePURLList: %v", err)
	}
	if got := componentByName(t, comps, "django"); got.Version != "" {
		t.Errorf("version = %q, want it left empty rather than invented", got.Version)
	}
}

func TestPURLListDeduplicatesOnIdentityNotOnQualifiers(t *testing.T) {
	const doc = `pkg:npm/lodash@4.17.20
pkg:npm/lodash@4.17.20?repository_url=https://registry.example.test
`
	comps, err := ParsePURLList(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParsePURLList: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1: a private mirror of lodash is still lodash", len(comps))
	}
}

func TestPURLListRejectsAFileThatIsMostlyNotPURLs(t *testing.T) {
	const doc = `pkg:npm/lodash@4.17.20
pkg:not
pkg:also-not
`
	_, err := ParsePURLList(strings.NewReader(doc))
	if err == nil {
		t.Fatal("a file that is two thirds unreadable parsed as an inventory")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error = %v, want it to name the first unreadable line", err)
	}
}

func TestPURLListEcosystemComesFromThePURLAlone(t *testing.T) {
	comps, err := ParsePURLList(strings.NewReader(purlListFixture))
	if err != nil {
		t.Fatalf("ParsePURLList: %v", err)
	}
	tests := []struct {
		name string
		want string
	}{
		{"openssl", "Debian:12"},
		{"@angular/animation", "npm"},
		{"requests", "PyPI"},
		{"org.apache.logging.log4j:log4j-core", "Maven"},
		{"openssl-src", "crates.io"},
		{"rack", "RubyGems"},
		{"laravel/framework", "Packagist"},
		{"musl", "Alpine:v3.19"},
		{"github.com/gin-gonic/gin", "Go"},
	}
	for _, tt := range tests {
		if got := componentByName(t, comps, tt.name).Ecosystem; got != tt.want {
			t.Errorf("%s ecosystem = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// A tenth of a three-line list is less than one line, so the ratio alone
// refused a short inventory for one misspelt entry. One unreadable line is a
// typo whatever the length of the file; it is in the report, which is where a
// typo belongs.
func TestPURLListForgivesASingleTypoInAShortList(t *testing.T) {
	const doc = `pkg:npm/lodash@4.17.20
pkg:pypi/requests@2.31.0
pgk:gem/rack@2.2.6.4
`
	comps, report, err := ParsePURLListWithReport(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParsePURLList: %v; one typo in three lines is still an inventory", err)
	}
	if len(comps) != 2 {
		t.Fatalf("got %d components, want the two readable entries", len(comps))
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Line != 3 {
		t.Errorf("report = %+v, want the typo on line 3 recorded", report)
	}
}
