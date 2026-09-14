package match

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// A distribution tracker's "affected, no fix" claim is probable: the export
// gives the same shape to packages it has confirmed and to packages it has
// not triaged. A released fix the build predates is confirmed.
func TestDistroOpenEndedClaimIsProbableAndReleasedFixIsConfirmed(t *testing.T) {
	deb := Component{
		Name: "sqlite3", Version: "3.46.1-9ubuntu0.2", Ecosystem: "Ubuntu:26.04:LTS",
		PURL: "pkg:deb/ubuntu/sqlite3@3.46.1-9ubuntu0.2?arch=source&distro=resolute", Origin: "dpkg-source",
	}
	open := Affected{
		VulnID: "UBUNTU-CVE-2026-51302", Product: "sqlite3", Ecosystem: "Ubuntu:26.04:LTS", Source: "osv",
		PURL:     "pkg:deb/ubuntu/sqlite3?arch=source&distro=resolute",
		Ranges:   []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0"}},
		Versions: []string{"3.46.1-9ubuntu0.1", "3.46.1-9ubuntu0.2"},
	}
	got, ev := Evaluate(deb, open)
	if got != Match || ev.Confidence != Probable {
		t.Fatalf("open claim: Evaluate = %v/%s, want Match/probable (reason: %s)", got, ev.Confidence, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "no fixed version") {
		t.Errorf("reason does not explain the cap: %s", ev.Reason)
	}

	released := open
	released.Ranges = []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "3.46.1-9ubuntu0.3"}}
	if got, ev := Evaluate(deb, released); got != Match || ev.Confidence != Confirmed {
		t.Fatalf("released fix: Evaluate = %v/%s, want Match/confirmed (reason: %s)", got, ev.Confidence, ev.Reason)
	}

	// An upstream advisory's open range (a fix simply does not exist yet) is
	// not a tracker shape and keeps its grade.
	lib := Component{Name: "marked", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/marked@2.0.0"}
	row := Affected{
		VulnID: "GHSA-x", Product: "marked", Ecosystem: "npm", PURL: "pkg:npm/marked", Source: "ghsa",
		Ranges: []model.VersionRange{{Type: "SEMVER", Introduced: "1.0.0"}},
	}
	if got, ev := Evaluate(lib, row); got != Match || ev.Confidence != Confirmed {
		t.Fatalf("npm open range: Evaluate = %v/%s, want Match/confirmed (reason: %s)", got, ev.Confidence, ev.Reason)
	}
}
