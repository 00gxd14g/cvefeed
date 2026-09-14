package parse

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// The parser emits one affected row per product status, and it used to decide
// which rows to emit from a list written out by hand. A status the list did not
// mention was built and then dropped on the way out — and a dropped
// affectedness statement is indistinguishable from a record that never made
// one. Every value the canonical vocabulary can hold must survive the parser.
func TestEveryCanonicalStatusSurvivesTheParser(t *testing.T) {
	for _, status := range model.Statuses() {
		t.Run(status, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
              "cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED"},
              "containers": {"cna": {"affected": [{
                "vendor": "acme", "product": "widget",
                "versions": [{"version": "1.0.0", "status": %s, "lessThan": "2.0.0", "versionType": "semver"}]
              }]}}
            }`, mustQuote(status)))

			v, err := CVE5ToModel(raw, "cvelist")
			if err != nil {
				t.Fatalf("CVE5ToModel: %v", err)
			}
			for _, a := range v.Affected {
				if a.Status == status {
					return
				}
			}
			t.Fatalf("status %q was parsed and then dropped; rows = %#v", status, v.Affected)
		})
	}
}

func mustQuote(s string) string {
	q, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(q)
}
