package inventory

import (
	"strings"
	"testing"
)

// An npm scope starts with '@' and is part of the namespace, not a version
// marker. Reading it as one dropped every scoped package in the inventory.
func TestParsePURLKeepsScopedNamesWithoutAVersion(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantNS   string
		wantVer  string
	}{
		{"pkg:npm/@babel/core", "core", "@babel", ""},
		{"pkg:npm/@babel/core@7.0.0", "core", "@babel", "7.0.0"},
		{"pkg:npm/lodash@4.17.20", "lodash", "", "4.17.20"},
		{"pkg:golang/github.com/x/y@v1.0.0", "y", "github.com/x", "v1.0.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core", "org.apache.logging.log4j", "2.14.1"},
		{"pkg:deb/debian/curl@7.88.1-10?arch=amd64", "curl", "debian", "7.88.1-10"},
	}
	for _, tc := range cases {
		got, ok := parsePURL(tc.in)
		if !ok {
			t.Errorf("parsePURL(%q) rejected the purl", tc.in)
			continue
		}
		if got.Name != tc.wantName || got.Namespace != tc.wantNS || got.Version != tc.wantVer {
			t.Errorf("parsePURL(%q) = name %q ns %q ver %q, want %q / %q / %q",
				tc.in, got.Name, got.Namespace, got.Version, tc.wantName, tc.wantNS, tc.wantVer)
		}
	}
}

// encoding/json fills in every well-typed field before returning a type error,
// so a component whose publisher is a number still has its name, its purl and
// its nested children. Discarding it threw away a scannable component; it is
// now kept whenever what survived is still enough to compare a version with.
// (A numeric version is no longer a type error at all — it is read as written,
// see TestCycloneDXANumericVersionIsReadAsWritten — so the malformed field
// here is one this reader has no way to recover.)
func TestSBOMKeepsPartiallyDecodedComponents(t *testing.T) {
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"outer","publisher":404,
	   "purl":"pkg:npm/outer@1.0.0",
	   "components":[{"type":"library","name":"inner","version":"2.0.0","purl":"pkg:npm/inner@2.0.0"}]},
	  {"type":"library","name":"fine","version":"3.0.0","purl":"pkg:npm/fine@3.0.0"}]}`

	got, err := ParseCycloneDX(strings.NewReader(cdx))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}
	names := map[string]string{}
	for _, c := range got {
		names[c.Name] = c.Version
	}
	for _, want := range []string{"outer", "inner", "fine"} {
		if _, ok := names[want]; !ok {
			t.Errorf("component %q was discarded; parsed %v", want, names)
		}
	}
	// The purl carries the version the component itself did not state.
	if names["outer"] != "1.0.0" {
		t.Errorf("outer version = %q, want 1.0.0 recovered from the purl", names["outer"])
	}
}

func TestSPDXKeepsPartiallyDecodedPackages(t *testing.T) {
	doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"t","packages":[
	  {"SPDXID":"SPDXRef-a","name":"broken","versionInfo":7,
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	                    "referenceLocator":"pkg:npm/broken@1.2.3"}]},
	  {"SPDXID":"SPDXRef-b","name":"ok","versionInfo":"2.0.0"}]}`

	got, err := ParseSPDX(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseSPDX() error = %v", err)
	}
	names := map[string]string{}
	for _, c := range got {
		names[c.Name] = c.Version
	}
	if _, ok := names["broken"]; !ok {
		t.Errorf("a package with a numeric versionInfo but a usable purl was discarded; parsed %v", names)
	}
	if _, ok := names["ok"]; !ok {
		t.Errorf("a well-formed package went missing; parsed %v", names)
	}
}
