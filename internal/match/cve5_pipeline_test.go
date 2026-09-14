package match_test

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/parse"
)

func TestCVE5StatusChangesKeepReviewWithinDeclaredInterval(t *testing.T) {
	raw := []byte(`{
		"cveMetadata":{"cveId":"CVE-2026-9004","state":"PUBLISHED"},
		"containers":{"cna":{"affected":[{
			"vendor":"acme","product":"widget","packageURL":"pkg:npm/widget",
			"defaultStatus":"unaffected",
			"versions":[{"version":"1.0.0","lessThan":"4.0.0","versionType":"semver",
				"status":"affected","changes":[
					{"at":"2.0.0","status":"unknown"},
					{"at":"3.0.0","status":"affected"}
				]}]
		}]}}
	}`)
	for _, source := range []string{"cvelist", "vulnrichment", "fkie"} {
		v, err := parse.CVE5ToModel(raw, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			installed string
			want      match.Result
		}{{"0.5.0", match.NoMatch}, {"1.0.0", match.Match}, {"2.0.0", match.Undecidable},
			{"2.5.0", match.Undecidable}, {"3.0.0", match.Match}, {"4.0.0", match.NoMatch}} {
			c := match.Component{Name: "widget", PURL: "pkg:npm/widget", Version: tt.installed}
			got := match.NoMatch
			for _, a := range v.Affected {
				result, _ := match.Evaluate(c, match.Affected{
					Product: a.Product, Vendor: a.Vendor, PURL: a.PURL, Source: a.Source,
					Status: a.Status, DefaultState: a.DefaultState, Versions: a.Versions, Ranges: a.Ranges,
				})
				if result != match.NoMatch {
					if got != match.NoMatch {
						t.Errorf("source=%s installed=%s: disjoint status intervals produced multiple applicable rows", source, tt.installed)
					}
					got = result
				}
			}
			if got != tt.want {
				t.Errorf("source=%s installed=%s: got %v, want %v", source, tt.installed, got, tt.want)
			}
		}
	}
}
