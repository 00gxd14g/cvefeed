package inventory

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// cycloneDXFixture is a CycloneDX 1.5 document in the shape syft emits for a
// container image, with three deliberate hazards folded in: a component whose
// version is a JSON number, a component with no version at all, and a component
// whose only package URL lives in evidence.identity.
const cycloneDXFixture = `{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:0d3b1b0e-6a4a-4d0e-9c3f-9d2a1b2c3d4e",
  "version": 1,
  "metadata": {
    "timestamp": "2026-08-17T09:12:44Z",
    "tools": {
      "components": [
        {"type": "application", "author": "anchore", "name": "syft", "version": "1.18.1"}
      ]
    },
    "component": {
      "bom-ref": "e8f0a1b2c3d4e5f6",
      "type": "container",
      "name": "debian",
      "version": "12.5"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&package-id=6e6f6c",
      "type": "library",
      "publisher": "Debian OpenSSL Team",
      "name": "libssl3",
      "version": "3.0.11-1~deb12u2",
      "licenses": [{"license": {"name": "Apache-2.0"}}],
      "cpe": "cpe:2.3:a:libssl3:libssl3:3.0.11-1\\~deb12u2:*:*:*:*:*:*:*",
      "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
      "properties": [{"name": "syft:package:type", "value": "deb"}]
    },
    {
      "bom-ref": "pkg:npm/%40angular/animation@12.3.1",
      "type": "library",
      "group": "@angular",
      "name": "animation",
      "version": "12.3.1",
      "purl": "pkg:npm/%40angular/animation@12.3.1"
    },
    {
      "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "type": "library",
      "group": "org.apache.logging.log4j",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "components": [
        {
          "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1",
          "type": "library",
          "group": "org.apache.logging.log4j",
          "name": "log4j-api",
          "version": "2.14.1",
          "purl": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"
        }
      ]
    },
    {
      "bom-ref": "malformed",
      "type": "library",
      "name": "busybox",
      "version": 1.36
    },
    {
      "bom-ref": "no-version",
      "type": "library",
      "name": "zlib"
    },
    {
      "bom-ref": "evidence-only",
      "type": "library",
      "name": "curl",
      "version": "8.4.0",
      "evidence": {
        "identity": {
          "field": "purl",
          "confidence": 0.9,
          "concludedValue": "pkg:generic/curl@8.4.0",
          "methods": [{"technique": "filename", "confidence": 0.9, "value": "curl-8.4.0"}]
        }
      }
    }
  ],
  "dependencies": [
    {"ref": "e8f0a1b2c3d4e5f6", "dependsOn": ["pkg:npm/%40angular/animation@12.3.1"]}
  ]
}`

func componentByName(t *testing.T, comps []match.Component, name string) match.Component {
	t.Helper()
	for _, c := range comps {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component named %q in %d components", name, len(comps))
	return match.Component{}
}

func TestCycloneDXMapsEveryComponentToItsEcosystemSpelling(t *testing.T) {
	comps, err := ParseCycloneDX(strings.NewReader(cycloneDXFixture))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}

	want := []match.Component{
		{Name: "debian", Version: "12.5", Origin: "cyclonedx"},
		{
			Name:      "libssl3",
			Version:   "3.0.11-1~deb12u2",
			Vendor:    "Debian OpenSSL Team",
			Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
			CPE:       `cpe:2.3:a:libssl3:libssl3:3.0.11-1\~deb12u2:*:*:*:*:*:*:*`,
			Origin:    "cyclonedx",
		},
		{
			Name:    "@angular/animation",
			Version: "12.3.1",
			// The group is the purl namespace by another name and is spelled
			// the same way: the scope without its "@".
			Vendor:    "angular",
			Ecosystem: "npm",
			PURL:      "pkg:npm/%40angular/animation@12.3.1",
			Origin:    "cyclonedx",
		},
		{
			Name:      "org.apache.logging.log4j:log4j-core",
			Version:   "2.14.1",
			Vendor:    "org.apache.logging.log4j",
			Ecosystem: "Maven",
			PURL:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			Origin:    "cyclonedx",
		},
		{
			Name:      "org.apache.logging.log4j:log4j-api",
			Version:   "2.14.1",
			Vendor:    "org.apache.logging.log4j",
			Ecosystem: "Maven",
			PURL:      "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1",
			Origin:    "cyclonedx",
		},
		// busybox wrote its version as a JSON number; the document stated it
		// and it is read as written.
		{Name: "busybox", Version: "1.36", Origin: "cyclonedx"},
		{Name: "zlib", Origin: "cyclonedx"},
		{
			Name:    "curl",
			Version: "8.4.0",
			PURL:    "pkg:generic/curl@8.4.0",
			Origin:  "cyclonedx",
		},
	}

	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for i, w := range want {
		if comps[i] != w {
			t.Errorf("component %d:\n got %+v\nwant %+v", i, comps[i], w)
		}
	}
}

// Producers write "version": 1.36 as often as "version": "1.36", and a string
// field rejected the number — dropping a component the document did state a
// version for. It is read as written: 1.10 is not 1.1.
func TestCycloneDXANumericVersionIsReadAsWritten(t *testing.T) {
	const doc = `{"bomFormat":"CycloneDX","components":[
	  {"type":"library","name":"busybox","version":1.36},
	  {"type":"library","name":"foo","version":1.10},
	  {"type":"library","name":"bar","version":3},
	  {"type":"library","name":"baz","version":null},
	  {"type":"library","name":"qux","version":{"major":1}}
	]}`
	comps, err := ParseCycloneDX(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	want := map[string]string{"busybox": "1.36", "foo": "1.10", "bar": "3", "baz": "", "qux": ""}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for _, c := range comps {
		if v, ok := want[c.Name]; !ok || c.Version != v {
			t.Errorf("%s version = %q, want %q", c.Name, c.Version, v)
		}
	}
}

func TestCycloneDXMalformedComponentDoesNotDiscardTheDocument(t *testing.T) {
	// A purl written as a number is a type error in a field this reads; the
	// component keeps whatever decoded — here a name and no version, which
	// is nothing to scan with — and its siblings are unaffected.
	const doc = `{"bomFormat":"CycloneDX","components":[
	  {"type":"library","name":"broken","purl":12345},
	  {"type":"library","name":"zlib","version":"1.3"}
	]}`
	comps, err := ParseCycloneDX(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	if len(comps) != 1 || comps[0].Name != "zlib" {
		t.Fatalf("got %+v, want zlib alone: the broken entry has nothing to scan and must not cost its siblings", comps)
	}
}

func TestCycloneDXNestedComponentIsInstalledToo(t *testing.T) {
	comps, err := ParseCycloneDX(strings.NewReader(cycloneDXFixture))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	nested := componentByName(t, comps, "org.apache.logging.log4j:log4j-api")
	if nested.Version != "2.14.1" {
		t.Errorf("nested component version = %q, want 2.14.1", nested.Version)
	}
}

func TestCycloneDXMetadataComponentIsEmitted(t *testing.T) {
	comps, err := ParseCycloneDX(strings.NewReader(cycloneDXFixture))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	// The image itself is what every operating-system advisory is about.
	if got := componentByName(t, comps, "debian"); got.Version != "12.5" {
		t.Errorf("metadata component = %+v, want version 12.5", got)
	}
}

func TestCycloneDXVersionlessComponentKeepsAnEmptyVersion(t *testing.T) {
	comps, err := ParseCycloneDX(strings.NewReader(cycloneDXFixture))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	if got := componentByName(t, comps, "zlib"); got.Version != "" {
		t.Errorf("zlib version = %q, want it left empty rather than invented", got.Version)
	}
}

func TestCycloneDX16IdentityArrayIsReadLikeThe15Object(t *testing.T) {
	const doc = `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "components": [
        {
          "type": "library",
          "name": "log4j-core",
          "version": "2.14.1",
          "evidence": {
            "identity": [
              {"field": "purl", "confidence": 0.8, "concludedValue": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
              {"field": "cpe", "confidence": 0.5, "concludedValue": "cpe:/a:apache:log4j:2.14.1"}
            ]
          }
        }
      ]
    }`
	comps, err := ParseCycloneDX(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseCycloneDX: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	got := comps[0]
	if got.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("purl = %q, want the concluded purl", got.PURL)
	}
	if got.CPE != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q, want the concluded 2.2 URI rebound as 2.3", got.CPE)
	}
	if got.Ecosystem != "Maven" {
		t.Errorf("ecosystem = %q, want Maven", got.Ecosystem)
	}
}

func TestCycloneDXXMLIsRefusedRatherThanReadAsEmpty(t *testing.T) {
	const doc = `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`
	if _, err := ParseCycloneDX(strings.NewReader(doc)); err == nil {
		t.Fatal("an XML BOM parsed without error, which reports the host as clean")
	}
}

func TestCycloneDXRefusesADocumentThatSaysItIsSomethingElse(t *testing.T) {
	// Reading an SPDX document with the CycloneDX parser finds no components
	// and no error, which is indistinguishable from a host with nothing
	// installed on it.
	_, err := ParseCycloneDX(strings.NewReader(spdxFixture))
	if err == nil {
		t.Fatal("an SPDX document parsed as a CycloneDX BOM without error")
	}
	if !strings.Contains(err.Error(), "SPDX-2.3") {
		t.Errorf("error = %v, want it to name the document it was actually given", err)
	}
}
