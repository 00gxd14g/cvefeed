package parse

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestCVE5VersionChangesSplitStatusIntervals(t *testing.T) {
	raw := []byte(`{
	  "dataType":"CVE_RECORD","dataVersion":"5.2",
	  "cveMetadata":{"cveId":"CVE-2026-9001","state":"PUBLISHED"},
	  "containers":{"cna":{"affected":[{
	    "vendor":"acme","product":"widget","defaultStatus":"unaffected",
	    "versions":[{
	      "version":"1.0","status":"affected","lessThan":"4.0","versionType":"semver",
	      "changes":[
	        {"at":"2.0","status":"unaffected"},
	        {"at":"3.0","status":"affected"}
	      ]
	    }]
	  }]}}
	}`)

	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}

	var affected, unaffected *model.Affected
	for i := range v.Affected {
		switch v.Affected[i].Status {
		case model.StatusAffected:
			affected = &v.Affected[i]
		case model.StatusNotAffected:
			unaffected = &v.Affected[i]
		}
	}
	if affected == nil || unaffected == nil {
		t.Fatalf("affected rows = %#v, want both affected and not_affected", v.Affected)
	}
	if got := len(affected.Ranges); got != 2 {
		t.Fatalf("affected ranges = %d, want 2: %#v", got, affected.Ranges)
	}
	if affected.Ranges[0].Introduced != "1.0" || affected.Ranges[0].Fixed != "2.0" {
		t.Errorf("first affected interval = %#v, want [1.0,2.0)", affected.Ranges[0])
	}
	if affected.Ranges[1].Introduced != "3.0" || affected.Ranges[1].Fixed != "4.0" {
		t.Errorf("second affected interval = %#v, want [3.0,4.0)", affected.Ranges[1])
	}
	if got := len(unaffected.Ranges); got != 1 {
		t.Fatalf("not_affected ranges = %d, want 1: %#v", got, unaffected.Ranges)
	}
	if unaffected.Ranges[0].Introduced != "2.0" || unaffected.Ranges[0].Fixed != "3.0" {
		t.Errorf("not_affected interval = %#v, want [2.0,3.0)", unaffected.Ranges[0])
	}
	if affected.DefaultState != "unaffected" {
		t.Errorf("affected default_state = %q, want unaffected", affected.DefaultState)
	}
	if unaffected.DefaultState != "" {
		t.Errorf("exception row inherited default_state %q; want empty", unaffected.DefaultState)
	}
}

func TestCVE5DefaultAffectedSurvivesExceptionOnlyVersionList(t *testing.T) {
	raw := []byte(`{
	  "dataType":"CVE_RECORD","dataVersion":"5.2",
	  "cveMetadata":{"cveId":"CVE-2026-9003","state":"PUBLISHED"},
	  "containers":{"cna":{"affected":[{
	    "vendor":"acme","product":"widget","defaultStatus":"affected",
	    "versions":[
	      {"version":"2.0","status":"unaffected","lessThan":"2.1","versionType":"semver"},
	      {"version":"3.0","status":"fixed","lessThan":"3.1","versionType":"semver"}
	    ]
	  }]}}
	}`)

	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}

	var affected, unaffected, fixed *model.Affected
	for i := range v.Affected {
		switch v.Affected[i].Status {
		case model.StatusAffected:
			affected = &v.Affected[i]
		case model.StatusNotAffected:
			unaffected = &v.Affected[i]
		case model.StatusFixed:
			fixed = &v.Affected[i]
		}
	}
	if affected == nil {
		t.Fatalf("default affected row disappeared: %#v", v.Affected)
	}
	if affected.DefaultState != "affected" || len(affected.Ranges) != 0 || len(affected.Versions) != 0 {
		t.Fatalf("default affected row = %#v, want unbounded default coverage", affected)
	}
	if unaffected == nil || len(unaffected.Ranges) != 1 || unaffected.Ranges[0].Introduced != "2.0" || unaffected.Ranges[0].Fixed != "2.1" {
		t.Fatalf("not_affected exception = %#v, want [2.0,2.1)", unaffected)
	}
	if fixed == nil || len(fixed.Ranges) != 1 || fixed.Ranges[0].Introduced != "3.0" || fixed.Ranges[0].Fixed != "3.1" {
		t.Fatalf("fixed exception = %#v, want [3.0,3.1)", fixed)
	}
}

func TestCVE5UnknownStatusStaysUndecidable(t *testing.T) {
	raw := []byte(`{
	  "cveMetadata":{"cveId":"CVE-2026-9002","state":"PUBLISHED"},
	  "containers":{"cna":{"affected":[{
	    "vendor":"acme","product":"widget",
	    "versions":[{"version":"1.0","status":"unknown"}]
	  }]}}
	}`)

	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}
	if len(v.Affected) != 1 || v.Affected[0].Status != model.StatusUnderInvestigation {
		t.Fatalf("affected = %#v, want one under_investigation row", v.Affected)
	}
}
