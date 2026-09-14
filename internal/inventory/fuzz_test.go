package inventory

import (
	"strings"
	"testing"
)

// Parse is reachable from POST /v1/scan with a body the caller controls, so a
// panic in it is a denial of service against a shared server. It has one
// contract under fuzzing: return components or an error, never panic, whatever
// the bytes are.
func FuzzParse(f *testing.F) {
	f.Add(cycloneDXFixture)
	f.Add(spdxFixture)
	f.Add("pkg:npm/lodash@4.17.20\n")
	f.Add("[]")
	f.Add("{}")
	f.Add("")
	f.Add("<xml/>")
	f.Add(`{"bomFormat":"CycloneDX","components":[{"name":"x","version":1}]}`)
	f.Add(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"x"}]}`)
	f.Add("pkg:")
	f.Add("pkg:npm/@scope/name@1.0.0")

	f.Fuzz(func(t *testing.T, in string) {
		comps, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		// A component that reached the scanner with no name cannot be looked up
		// and cannot be reported on; it would become a silent row in the report.
		for _, c := range comps {
			if c.Name == "" {
				t.Fatalf("parsed a component with no name from %q: %+v", in, c)
			}
		}
	})
}
