package inventory

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// spdxFixture is an SPDX 2.3 document in the shape syft emits for an Alpine
// image. It carries the two external-reference category spellings that are both
// in service, a 2.2-era CPE, a NOASSERTION version rescued from the purl, a
// display name that is really a path, and one unreadable package.
const spdxFixture = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "alpine-3.19.1",
  "documentNamespace": "https://anchore.com/syft/image/alpine-3.19.1-7c1b4f6e",
  "creationInfo": {
    "licenseListVersion": "3.21",
    "creators": ["Organization: Anchore, Inc", "Tool: syft-1.18.1"],
    "created": "2026-08-17T09:20:11Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-apk-openssl-1a2b3c4d",
      "name": "openssl",
      "versionInfo": "3.1.4-r5",
      "supplier": "Organization: Alpine Linux",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "Apache-2.0",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:openssl:openssl:3.1.4-r5:*:*:*:*:*:*:*"
        },
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-python-requests-9f8e7d",
      "name": "/usr/lib/python3.11/site-packages/requests",
      "versionInfo": "NOASSERTION",
      "supplier": "NOASSERTION",
      "originator": "Person: Kenneth Reitz",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:pypi/requests@2.31.0"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-tomcat",
      "name": "tomcat",
      "versionInfo": "9.0.75",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe22Type",
          "referenceLocator": "cpe:/a:apache:tomcat:9.0.75::~~~~~"
        },
        {
          "referenceCategory": "SECURITY",
          "referenceType": "advisory",
          "referenceLocator": "https://tomcat.apache.org/security-9.html"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-malformed",
      "name": "busybox",
      "versionInfo": 1.36
    },
    {
      "SPDXID": "SPDXRef-Package-musl",
      "name": "musl",
      "versionInfo": "1.2.4-r2",
      "supplier": "NOASSERTION",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false
    }
  ],
  "files": [
    {
      "SPDXID": "SPDXRef-File-bin-busybox",
      "fileName": "/bin/busybox",
      "checksums": [{"algorithm": "SHA256", "checksumValue": "6f1a"}]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-apk-openssl-1a2b3c4d",
      "relationshipType": "DESCRIBES"
    }
  ]
}`

func TestSPDXReadsPackagesAndTheirExternalRefs(t *testing.T) {
	comps, err := ParseSPDX(strings.NewReader(spdxFixture))
	if err != nil {
		t.Fatalf("ParseSPDX: %v", err)
	}

	want := []match.Component{
		{
			Name:      "openssl",
			Version:   "3.1.4-r5",
			Vendor:    "Alpine Linux",
			Ecosystem: "Alpine:v3.19",
			PURL:      "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1",
			CPE:       "cpe:2.3:a:openssl:openssl:3.1.4-r5:*:*:*:*:*:*:*",
			Origin:    "spdx",
		},
		{
			// The SPDX name is a path; the purl carries the package name.
			Name:      "requests",
			Version:   "2.31.0",
			Vendor:    "Kenneth Reitz",
			Ecosystem: "PyPI",
			PURL:      "pkg:pypi/requests@2.31.0",
			Origin:    "spdx",
		},
		{
			Name:    "tomcat",
			Version: "9.0.75",
			CPE:     "cpe:2.3:a:apache:tomcat:9.0.75:*:*:*:*:*:*:*",
			Origin:  "spdx",
		},
		{
			Name:    "musl",
			Version: "1.2.4-r2",
			Origin:  "spdx",
		},
	}

	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for i, w := range want {
		if comps[i] != w {
			t.Errorf("package %d:\n got %+v\nwant %+v", i, comps[i], w)
		}
	}
}

func TestSPDXMalformedPackageDoesNotDiscardTheDocument(t *testing.T) {
	comps, err := ParseSPDX(strings.NewReader(spdxFixture))
	if err != nil {
		t.Fatalf("ParseSPDX: %v", err)
	}
	for _, c := range comps {
		if c.Name == "busybox" {
			t.Fatalf("the package with a numeric versionInfo was read anyway: %+v", c)
		}
	}
	if len(comps) != 4 {
		t.Fatalf("got %d components, want the 4 readable ones", len(comps))
	}
}

func TestSPDXNoAssertionIsAbsenceNotAValue(t *testing.T) {
	comps, err := ParseSPDX(strings.NewReader(spdxFixture))
	if err != nil {
		t.Fatalf("ParseSPDX: %v", err)
	}
	requests := componentByName(t, comps, "requests")
	if requests.Version != "2.31.0" {
		t.Errorf("version = %q, want the purl's version once versionInfo said NOASSERTION", requests.Version)
	}
	musl := componentByName(t, comps, "musl")
	if musl.Vendor != "" {
		t.Errorf("vendor = %q, want empty rather than a supplier named NOASSERTION", musl.Vendor)
	}
}

func TestSPDXFilesAreNotComponents(t *testing.T) {
	comps, err := ParseSPDX(strings.NewReader(spdxFixture))
	if err != nil {
		t.Fatalf("ParseSPDX: %v", err)
	}
	for _, c := range comps {
		if strings.HasPrefix(c.Name, "/bin/") {
			t.Fatalf("a file entered the inventory as a component: %+v", c)
		}
	}
}

func TestSPDX3IsRefusedRatherThanReadAsEmpty(t *testing.T) {
	const doc = `{
      "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
      "@graph": [{"type": "SpdxDocument", "spdxId": "urn:spdx"}]
    }`
	_, err := ParseSPDX(strings.NewReader(doc))
	if err == nil {
		t.Fatal("an SPDX 3.x document parsed without error, which reports the host as clean")
	}
	if !strings.Contains(err.Error(), "SPDX 3.x") {
		t.Errorf("error = %v, want it to name the version it refused", err)
	}
}

func TestSPDX21IsRefusedWithItsVersionNamed(t *testing.T) {
	const doc = `{"spdxVersion": "SPDX-2.1", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}`
	_, err := ParseSPDX(strings.NewReader(doc))
	if err == nil {
		t.Fatal("SPDX-2.1 parsed without error")
	}
	if !strings.Contains(err.Error(), "SPDX-2.1") {
		t.Errorf("error = %v, want it to name the version it refused", err)
	}
}

func TestSPDXWithoutVersionHeaderIsStillReadWhenItIsUnambiguous(t *testing.T) {
	const doc = `{
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "sbom",
      "packages": [
        {"SPDXID": "SPDXRef-a", "name": "curl", "versionInfo": "8.4.0"}
      ]
    }`
	comps, err := ParseSPDX(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseSPDX: %v", err)
	}
	if len(comps) != 1 || comps[0].Name != "curl" {
		t.Fatalf("got %+v, want the one package the document describes", comps)
	}
}

func TestSPDXRefusesADocumentThatSaysItIsSomethingElse(t *testing.T) {
	_, err := ParseSPDX(strings.NewReader(cycloneDXFixture))
	if err == nil {
		t.Fatal("a CycloneDX BOM parsed as SPDX without error, reporting no components at all")
	}
}
