package store

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// A vulnerability that was fixed on several release branches has one statement
// per branch, and they differ only in their ranges. Deduplicating on identity
// alone therefore keeps whichever arrived first and discards the rest, which
// silently drops every branch but one.
//
// The rows below are the three real OSV statements for CVE-2021-45105 on
// log4j-core, copied out of vuln_affected. Collapsing them leaves the 2.4.0–
// 2.12.3 window as the only survivor, and an installed 2.14.1 — which the
// 2.13.0–2.17.0 window covers — is then reported clean.
func TestDedupeKeepsStatementsThatDifferOnlyInTheirRanges(t *testing.T) {
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core"
	row := func(fingerprint, introduced, fixed string) AffectedStatement {
		return AffectedStatement{
			VulnID: "CVE-2021-45105", Source: "osv", Status: "affected",
			Product: "org.apache.logging.log4j:log4j-core", Ecosystem: "Maven", PURL: purl,
			Fingerprint: fingerprint,
			Ranges:      []model.VersionRange{{Type: "ECOSYSTEM", Introduced: introduced, Fixed: fixed}},
		}
	}
	rows := []AffectedStatement{
		row("fp-a", "2.4.0", "2.12.3"),
		row("fp-b", "0", "2.3.1"),
		row("fp-c", "2.13.0", "2.17.0"),
	}

	got := dedupeStatements(append([]AffectedStatement(nil), rows...))
	if len(got) != 3 {
		t.Fatalf("kept %d of %d statements; each names a different affected window", len(got), len(rows))
	}
	var covers2141 bool
	for _, st := range got {
		for _, r := range st.Ranges {
			if r.Introduced == "2.13.0" && r.Fixed == "2.17.0" {
				covers2141 = true
			}
		}
	}
	if !covers2141 {
		t.Error("the 2.13.0–2.17.0 window was dropped, so an installed 2.14.1 reports clean")
	}
}

// The reason the function exists: one row reached through two candidate
// lookups — matched by purl and again by ecosystem and product — must be
// tested once, not twice.
func TestDedupeStillCollapsesOneRowArrivingTwice(t *testing.T) {
	st := AffectedStatement{
		VulnID: "CVE-2021-45105", Source: "osv", Status: "affected",
		Product: "log4j-core", Ecosystem: "Maven", Fingerprint: "fp-a",
		Ranges: []model.VersionRange{{Type: "ECOSYSTEM", Introduced: "2.4.0", Fixed: "2.12.3"}},
	}
	got := dedupeStatements([]AffectedStatement{st, st})
	if len(got) != 1 {
		t.Fatalf("kept %d copies of one row, want 1", len(got))
	}
}
