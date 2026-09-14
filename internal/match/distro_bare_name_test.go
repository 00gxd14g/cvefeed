package match

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// An upstream statement that names only a product must not become a finding
// against a distribution package that merely shares the name: the version is
// a distro build, and the name collides across ecosystems.
func TestDistroPackageMatchedByBareNameIsUndecidable(t *testing.T) {
	row := Affected{
		VulnID: "CVE-2015-7309", Vendor: "bolt", Product: "bolt", Source: "nvd",
		Ranges: []model.VersionRange{{Type: "CUSTOM", LastAffected: "2.2.0"}},
	}
	deb := Component{
		Name: "bolt", Version: "0.9.10-1", Ecosystem: "Ubuntu:26.04:LTS",
		PURL: "pkg:deb/ubuntu/bolt@0.9.10-1?arch=amd64&distro=ubuntu-26.04", Origin: "dpkg",
	}
	got, ev := Evaluate(deb, row)
	if got != Undecidable {
		t.Fatalf("Evaluate = %v, want Undecidable (reason: %s)", got, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "distro_package_upstream_statement") || !strings.Contains(ev.Reason, "Ubuntu") {
		t.Errorf("reason does not explain the distribution rule: %s", ev.Reason)
	}

	// Outside the range the answer needs no backport knowledge: NoMatch, as
	// before, so -undecidable lists questions rather than every row.
	newer := deb
	newer.Version = "3.0.0-1"
	if got, ev := Evaluate(newer, row); got != NoMatch {
		t.Fatalf("out-of-range deb: Evaluate = %v, want NoMatch (reason: %s)", got, ev.Reason)
	}

	// The same statement against an artefact with no ecosystem at all is still
	// the question it always was: a possible finding for an operator to read.
	bare := Component{Name: "bolt", Version: "0.9.10"}
	if got, ev := Evaluate(bare, row); got != Match || ev.Confidence != Possible {
		t.Fatalf("bare component: Evaluate = %v/%s, want Match/possible (reason: %s)", got, ev.Confidence, ev.Reason)
	}

	// And the distribution's own advisory still decides: ecosystem and name
	// agree, so the deb version is ordered under its own scheme.
	usn := Affected{
		VulnID: "CVE-2026-0002", Product: "bolt", Ecosystem: "Ubuntu:26.04:LTS", Source: "osv",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "0", Fixed: "0.9.10-1ubuntu0.1"}},
	}
	if got, ev := Evaluate(deb, usn); got != Match {
		t.Fatalf("USN row: Evaluate = %v, want Match (reason: %s)", got, ev.Reason)
	}
}
