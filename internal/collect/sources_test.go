package collect

import (
	"encoding/json"
	"testing"
)

// Vulnerability-Lookup 5.x answers with a bare JSON array while its own
// documentation describes {metadata, data}. Decoding straight into a struct
// failed on the array and the collector treated that as "nothing to do", so it
// ingested zero records indefinitely.
func TestDecodeVLPageAcceptsBothShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"bare array", `[{"id":"PYSEC-2025-19"},{"id":"PYSEC-2024-115"}]`, 2},
		{"documented envelope", `{"metadata":{"total":2},"data":[{"id":"a"},{"id":"b"}]}`, 2},
		{"vulnerabilities key", `{"vulnerabilities":[{"id":"a"}]}`, 1},
		{"empty array", `[]`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeVLPage([]byte(tc.body))
			if err != nil {
				t.Fatalf("decodeVLPage() error = %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("decoded %d records, want %d", len(got), tc.want)
			}
		})
	}
}

func TestDecodeVLPageRejectsGarbage(t *testing.T) {
	if _, err := decodeVLPage([]byte(`not json`)); err == nil {
		t.Fatal("decodeVLPage(garbage) = nil error, want a failure the caller can surface")
	}
}

// A Vulnerability-Lookup page mixes native upstream schemas: mostly CSAF, some
// OSV, some CVE 5.x. Probing only for a flat {id, aliases} object dropped
// nearly all of them.
func TestGCVEToModelDispatchesOnDocumentShape(t *testing.T) {
	c := &GCVECollector{}
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"osv",
			`{"id":"PYSEC-2025-19","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"x"}}]}`,
			"PYSEC-2025-19",
		},
		{
			"cve 5.x",
			`{"cveMetadata":{"cveId":"CVE-2026-1234","state":"PUBLISHED"},"containers":{"cna":{}}}`,
			"CVE-2026-1234",
		},
		{
			"csaf",
			`{"document":{"title":"RHSA","tracking":{"id":"RHSA-2026:1","version":"1"}},
			  "vulnerabilities":[{"cve":"CVE-2026-25639"}]}`,
			"CVE-2026-25639",
		},
		{
			"flat gcve",
			`{"gcve_id":"GCVE-0-2023-40224","summary":"s"}`,
			"GCVE-0-2023-40224",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := c.toModel([]byte(tc.body))
			if v == nil {
				t.Fatalf("toModel() = nil for a %s document", tc.name)
			}
			if v.ID != tc.want {
				t.Fatalf("id = %q, want %q", v.ID, tc.want)
			}
			if v.Source != "gcve" {
				t.Errorf("source = %q, want gcve", v.Source)
			}
		})
	}
}

func TestGCVEEmitsGNAZeroAlias(t *testing.T) {
	c := &GCVECollector{}
	v := c.toModel([]byte(`{"gcve_id":"GCVE-0-2023-40224","summary":"s"}`))
	if v == nil {
		t.Fatal("toModel() = nil")
	}
	found := false
	for _, a := range v.Aliases {
		if a == "CVE-2023-40224" {
			found = true
		}
	}
	if !found {
		t.Fatalf("aliases = %v, want the equivalent CVE so the two collapse into one record", v.Aliases)
	}
}

// EUVD names the field `exploitedSince` and gives it a date, not a boolean.
func TestEUVDToModelReadsExploitedSince(t *testing.T) {
	c := &EUVDCollector{}
	raw := json.RawMessage(`{
	  "id":"EUVD-2025-199754",
	  "description":"d",
	  "datePublished":"Jun 24, 2025, 2:10:07 PM",
	  "dateUpdated":"Aug 18, 2026, 9:31:23 AM",
	  "aliases":"CVE-2025-62593\nGHSA-q279-jhrf-cc6v\n",
	  "exploitedSince":"Aug 17, 2026, 12:00:00 AM",
	  "baseScore":9.8,"baseScoreVersion":"3.1",
	  "baseScoreVector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	  "enisaIdProduct":[{"product":{"name":"widget","vendor":{"name":"acme"}},"product_version":"1.0"}],
	  "enisaIdVendor":[{"vendor":{"name":"other"}}]
	}`)

	v, kev := c.toModel(raw)
	if v == nil {
		t.Fatal("toModel() = nil")
	}
	if kev == nil {
		t.Fatal("exploitedSince set but no KEV entry produced")
	}
	if kev.CVEID != "CVE-2025-62593" {
		t.Errorf("kev keyed on %q, want the CVE alias", kev.CVEID)
	}
	if kev.DateAdded == nil {
		t.Error("kev.DateAdded = nil, want the exploitedSince instant")
	}
	if v.Published == nil || v.Published.Format("2006-01-02") != "2025-06-24" {
		t.Errorf("published = %v, want the ENISA date spelling parsed", v.Published)
	}
	// The raw document must be the upstream's bytes, not a re-serialisation.
	if string(v.Raw) != string(raw) {
		t.Error("raw document was rewritten; the raw layer must stay verbatim")
	}
	if len(v.Affected) != 1 || v.Affected[0].Vendor != "acme" {
		t.Errorf("affected = %+v, want the product's own vendor rather than the first in the record", v.Affected)
	}
}

// CSAF advisories without a CVE are exactly the vendor-only and OT coverage the
// collector exists for; they must not be dropped.
func TestParseCSAFKeepsAdvisoriesWithoutACVE(t *testing.T) {
	raw := []byte(`{
	  "document":{
	    "title":"SSA-123456",
	    "publisher":{"name":"Siemens"},
	    "tracking":{"id":"SSA-123456","version":"2","initial_release_date":"2026-01-01T00:00:00Z",
	                "current_release_date":"2026-02-01T00:00:00Z"}
	  },
	  "product_tree":{"branches":[{"category":"vendor","name":"Siemens","branches":[
	     {"category":"product_name","name":"SIMATIC S7","product":{"product_id":"P1","name":"SIMATIC S7-1500"}}]}]},
	  "vulnerabilities":[{
	     "title":"Improper access control",
	     "ids":[{"system_name":"Siemens","text":"SSA-123456-1"}],
	     "notes":[{"category":"description","text":"detail"}],
	     "scores":[{"cvss_v2":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}],
	     "product_status":{"known_affected":["P1"],"fixed":["P1"],"known_not_affected":["P1"]}
	  }]
	}`)

	out := parseCSAF(raw, "csaf", "")
	if len(out) != 1 {
		t.Fatalf("parseCSAF() produced %d records, want 1", len(out))
	}
	v := out[0]
	if v.ID != "SSA-123456" {
		t.Errorf("id = %q, want the advisory tracking id", v.ID)
	}
	if v.SourceRecordID != "SSA-123456@2#SSA-123456" {
		t.Errorf("source record id = %q, want tracking id plus version", v.SourceRecordID)
	}
	// Branch-based product trees must resolve, or every product id stays raw.
	var names []string
	statuses := map[string]bool{}
	for _, a := range v.Affected {
		names = append(names, a.Product)
		statuses[a.Status] = true
	}
	for _, n := range names {
		if n != "SIMATIC S7-1500" {
			t.Errorf("product = %q, want the name resolved from the branch tree", n)
		}
	}
	for _, want := range []string{"affected", "fixed", "not_affected"} {
		if !statuses[want] {
			t.Errorf("product status %q missing; VEX statuses are the reason to collect CSAF", want)
		}
	}
	if len(v.Severities) != 1 || v.Severities[0].Type != "CVSS_V2" {
		t.Errorf("severities = %+v, want the CVSS v2 statement kept", v.Severities)
	}
}

func TestParseCSAFUsesCVEWhenPresent(t *testing.T) {
	raw := []byte(`{
	  "document":{"title":"RHSA","publisher":{"name":"Red Hat"},
	              "tracking":{"id":"RHSA-2026:1","version":"3"}},
	  "vulnerabilities":[{"cve":"cve-2026-25639"}]
	}`)
	out := parseCSAF(raw, "csaf", "")
	if len(out) != 1 || out[0].ID != "CVE-2026-25639" {
		t.Fatalf("parseCSAF() = %+v, want the normalised CVE id", out)
	}
}
