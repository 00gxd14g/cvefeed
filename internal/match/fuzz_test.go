package match

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// Evaluate decides whether a vulnerability applies to an installed component.
// Both sides are outside data — one from a target, one from an advisory — and
// the verdict must always be one of the three, with evidence attached.
func FuzzEvaluate(f *testing.F) {
	f.Add("log4j-core", "2.14.1", "Maven", "pkg:maven/org.apache.logging.log4j/log4j-core",
		"org.apache.logging.log4j:log4j-core", "2.0-beta9", "2.15.0", "ECOSYSTEM", "affected")
	f.Add("openssl", "3.0.7-1", "Debian", "pkg:deb/debian/openssl",
		"openssl", "0", "3.0.15", "DEBIAN", "affected")
	f.Add("widget", "1.2.3", "", "", "widget", "0", "Upgrade to the latest version.", "CUSTOM", "affected")
	f.Add("x", "", "", "", "x", "", "", "", "")

	f.Fuzz(func(t *testing.T, name, ver, eco, purl, product, introduced, fixed, rtype, status string) {
		c := Component{Name: name, Version: ver, Ecosystem: eco, PURL: purl, Origin: "fuzz"}
		a := Affected{
			VulnID: "CVE-0000-0000", Product: product, Ecosystem: eco, Source: "fuzz",
			Status: status,
			Ranges: []model.VersionRange{{Introduced: introduced, Fixed: fixed, Type: rtype}},
		}
		result, ev := Evaluate(c, a)

		switch result {
		case Match, NoMatch, Undecidable:
		default:
			t.Fatalf("verdict %v is none of the three", result)
		}
		if result == Match {
			// A match a caller cannot audit is a match nobody will act on, and
			// a grade is what decides whether it is reported at all.
			if ev.Reason == "" {
				t.Fatalf("match with no reason: %+v vs %+v", c, a)
			}
			switch ev.Confidence {
			case Confirmed, Probable, Possible:
			default:
				t.Fatalf("match graded %q, which is not a confidence level", ev.Confidence)
			}
			// A component with no stated version cannot be inside any range.
			if ver == "" {
				t.Fatalf("matched a component with no version against %q..%q", introduced, fixed)
			}
		}
	})
}
