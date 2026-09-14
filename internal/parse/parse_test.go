package parse

import (
	"math"
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestCVSSBaseScore(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		// Log4Shell, the canonical 10.0.
		{"log4shell v3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"scope unchanged high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"local low impact", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8},
		{"no impact is zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"v3.0 same inputs", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"v2 partial availability", "AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0},
		{"v2 complete", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"v4 is not recomputed", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0.0},
		{"garbage", "not-a-vector", 0.0},
		{"empty", "", 0.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CVSSBaseScore(tc.vector)
			if math.Abs(got-tc.want) > 0.05 {
				t.Fatalf("CVSSBaseScore(%q) = %v, want %v", tc.vector, got, tc.want)
			}
		})
	}
}

func TestCVE5ToModel(t *testing.T) {
	raw := []byte(`{
      "dataType":"CVE_RECORD","dataVersion":"5.1",
      "cveMetadata":{"cveId":"cve-2024-12345","state":"PUBLISHED",
        "assignerShortName":"acme","datePublished":"2024-03-01T10:00:00.000Z",
        "dateUpdated":"2024-06-02T08:30:00.000Z"},
      "containers":{
        "cna":{
          "providerMetadata":{"shortName":"acme"},
          "title":"Heap overflow in widget parser",
          "descriptions":[{"lang":"en","value":"A heap overflow exists."}],
          "problemTypes":[{"descriptions":[{"cweId":"CWE-122","lang":"en"}]}],
          "references":[{"url":"https://acme.example/advisory","tags":["vendor-advisory"]}],
          "affected":[{"vendor":"Acme","product":"Widget","versions":[
            {"version":"1.0","status":"affected","lessThan":"1.4","versionType":"semver"}]}],
          "metrics":[{"cvssV3_1":{"baseScore":9.8,
            "vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseSeverity":"CRITICAL"}}]
        },
        "adp":[{
          "providerMetadata":{"shortName":"CISA-ADP"},
          "metrics":[{"other":{"type":"ssvc","content":{"version":"2.0.3",
            "options":[{"Exploitation":"active"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}]
        }]
      }}`)

	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "CVE-2024-12345" {
		t.Errorf("id = %q, want normalised CVE-2024-12345", v.ID)
	}
	if v.Title != "Heap overflow in widget parser" {
		t.Errorf("title = %q", v.Title)
	}
	if len(v.CWEs) != 1 || v.CWEs[0] != "CWE-122" {
		t.Errorf("cwes = %v", v.CWEs)
	}
	if len(v.Severities) != 1 || v.Severities[0].Score != 9.8 || v.Severities[0].Type != "CVSS_V3_1" {
		t.Errorf("severities = %+v", v.Severities)
	}
	if v.SSVC == nil {
		t.Fatal("SSVC from the ADP container was dropped")
	}
	if v.SSVC.Exploitation != "active" || v.SSVC.Automatable != "yes" || v.SSVC.TechnicalImpact != "total" {
		t.Errorf("ssvc = %+v", v.SSVC)
	}
	if len(v.Affected) != 1 || len(v.Affected[0].Ranges) != 1 || v.Affected[0].Ranges[0].Fixed != "1.4" {
		t.Errorf("affected = %+v", v.Affected)
	}
	if v.Published == nil || v.Published.Year() != 2024 {
		t.Errorf("published = %v", v.Published)
	}
}

func TestOSVToModel(t *testing.T) {
	raw := []byte(`{
      "schema_version":"1.6.0","id":"GHSA-jfh8-c2jp-5v3q",
      "aliases":["CVE-2021-44228"],
      "modified":"2024-01-02T03:04:05Z","published":"2021-12-10T00:00:00Z",
      "summary":"Remote code execution in Log4j",
      "details":"JNDI features do not protect against attacker controlled LDAP.",
      "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
      "affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core",
        "purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}],
      "references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
      "database_specific":{"cwe_ids":["CWE-502","CWE-917"],"severity":"CRITICAL"}}`)

	v, err := OSVToModel(raw, "ghsa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("id = %q", v.ID)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2021-44228" {
		t.Errorf("aliases = %v", v.Aliases)
	}
	if len(v.Severities) != 1 {
		t.Fatalf("severities = %+v", v.Severities)
	}
	// The vector says 10.0; OSV carries no number, so it must be recomputed.
	if math.Abs(v.Severities[0].Score-10.0) > 0.05 {
		t.Errorf("recomputed score = %v, want 10.0", v.Severities[0].Score)
	}
	if len(v.Affected) != 1 || v.Affected[0].Ecosystem != "Maven" {
		t.Errorf("affected = %+v", v.Affected)
	}
	if len(v.CWEs) != 2 {
		t.Errorf("cwes = %v", v.CWEs)
	}
}

func TestNVDToModel(t *testing.T) {
	raw := []byte(`{
      "id":"CVE-1999-0001","sourceIdentifier":"cve@mitre.org",
      "published":"1999-12-30T05:00:00.000","lastModified":"2024-11-20T23:27:50.057",
      "vulnStatus":"Modified",
      "descriptions":[{"lang":"en","value":"ip_input.c allows remote attackers to cause a denial of service."},
                      {"lang":"es","value":"ignorado"}],
      "metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary",
        "cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:N/I:N/A:P","baseScore":5.0},
        "baseSeverity":"MEDIUM"}]},
      "weaknesses":[{"source":"nvd@nist.gov","description":[{"lang":"en","value":"CWE-20"}]}],
      "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
        {"vulnerable":true,"criteria":"cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*"},
        {"vulnerable":true,"criteria":"cpe:2.3:o:freebsd:freebsd:1.1:*:*:*:*:*:*:*"},
        {"vulnerable":false,"criteria":"cpe:2.3:o:ignored:ignored:1.0:*:*:*:*:*:*:*"}]}]}],
      "references":[{"url":"http://www.openbsd.org/errata23.html","source":"cve@mitre.org"}]}`)

	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Description == "" || v.Description[:11] != "ip_input.c " {
		t.Errorf("english description not selected: %q", v.Description)
	}
	if len(v.Severities) != 1 || v.Severities[0].Type != "CVSS_V2" || v.Severities[0].Rating != "MEDIUM" {
		t.Errorf("severities = %+v", v.Severities)
	}
	if len(v.Affected) != 1 {
		t.Fatalf("expected CPEs grouped into one vendor/product entry, got %+v", v.Affected)
	}
	if v.Affected[0].Vendor != "freebsd" || v.Affected[0].Product != "freebsd" {
		t.Errorf("vendor/product = %q/%q", v.Affected[0].Vendor, v.Affected[0].Product)
	}
	if len(v.Affected[0].CPEs) != 2 {
		t.Errorf("non-vulnerable CPE should be dropped, got %v", v.Affected[0].CPEs)
	}
	if !model.IsCVE(v.ID) {
		t.Errorf("id = %q", v.ID)
	}
}

// OSV `related` means "related but not equivalent". Feeding it into the alias
// list made the store fold genuinely distinct vulnerabilities into one record
// and delete the losers.
func TestOSVRelatedIsNotAnAlias(t *testing.T) {
	raw := []byte(`{
	  "id":"DSA-1234-1","modified":"2026-01-01T00:00:00Z",
	  "aliases":["CVE-2026-1111"],
	  "related":["CVE-2026-2222","CVE-2026-3333"],
	  "upstream":["CVE-2026-4444"]
	}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	for _, a := range v.Aliases {
		if a == "CVE-2026-2222" || a == "CVE-2026-3333" {
			t.Fatalf("aliases = %v, must not contain a `related` identifier", v.Aliases)
		}
	}
	if len(v.Related) != 3 {
		t.Errorf("related = %v, want `related` and `upstream` both preserved outside the alias graph", v.Related)
	}
	// `upstream` belongs with `related` rather than with `aliases`. It records
	// derivation — the package build this advisory rebuilt — and the hardened
	// image producers republish one upstream CVE per rebuild in their tens of
	// thousands. See TestUpstreamIsADerivationNotAnIdentity.
	for _, a := range v.Aliases {
		if a == "CVE-2026-4444" {
			t.Errorf("aliases = %v, must not contain an `upstream` identifier", v.Aliases)
		}
	}
}

// CVSS v4.0 cannot be recomputed from its vector without the official
// MacroVector table. Deriving a rating from the resulting zero published
// "NONE" for critical vulnerabilities.
func TestOSVUnscorableVectorIsLeftUnrated(t *testing.T) {
	raw := []byte(`{
	  "id":"GHSA-aaaa-bbbb-cccc","modified":"2026-01-01T00:00:00Z",
	  "severity":[
	    {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	    {"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
	  ]}`)
	v, err := OSVToModel(raw, "ghsa")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	for _, s := range v.Severities {
		if s.Type == "CVSS_V4_0" {
			if s.Score != 0 {
				t.Errorf("v4.0 score = %v, want 0 (not recomputed)", s.Score)
			}
			if s.Rating != "" {
				t.Errorf("v4.0 rating = %q, want empty rather than a fabricated NONE", s.Rating)
			}
		}
		if s.Type == "CVSS_V3_1" && s.Rating != "CRITICAL" {
			t.Errorf("v3.1 rating = %q, want CRITICAL", s.Rating)
		}
	}
}

func TestOSVRangeEventsArePaired(t *testing.T) {
	raw := []byte(`{
	  "id":"PYSEC-1","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},
	    "ranges":[{"type":"ECOSYSTEM","events":[
	      {"introduced":"0"},{"fixed":"1.2.3"},
	      {"introduced":"2.0"},{"last_affected":"2.5"}]}]}]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Affected) != 1 {
		t.Fatalf("affected = %+v, want one package", v.Affected)
	}
	rs := v.Affected[0].Ranges
	if len(rs) != 2 {
		t.Fatalf("ranges = %+v, want two closed windows", rs)
	}
	if rs[0].Introduced != "0" || rs[0].Fixed != "1.2.3" {
		t.Errorf("first range = %+v, want 0 -> 1.2.3", rs[0])
	}
	if rs[1].Introduced != "2.0" || rs[1].LastAffected != "2.5" {
		t.Errorf("second range = %+v, want 2.0 -> 2.5", rs[1])
	}
}

func TestOSVPerPackageSeveritiesStayAttributable(t *testing.T) {
	raw := []byte(`{
	  "id":"OSV-1","modified":"2026-01-01T00:00:00Z",
	  "affected":[
	    {"package":{"ecosystem":"npm","name":"a"},
	     "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
	    {"package":{"ecosystem":"npm","name":"b"},
	     "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]}
	  ]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Severities) != 2 {
		t.Fatalf("severities = %+v, want one per package", v.Severities)
	}
	if v.Severities[0].Provider == v.Severities[1].Provider {
		t.Fatalf("both severities carry provider %q; they would collapse on merge",
			v.Severities[0].Provider)
	}
}

func TestNVDKeepsEnrichmentStatusAndSSVC(t *testing.T) {
	raw := []byte(`{
	  "id":"CVE-2026-1234","vulnStatus":"Deferred","lastModified":"2026-01-01T00:00:00.000",
	  "cveTags":["disputed"],
	  "metrics":{"ssvcV203":[{"source":"cisa","options":[
	     {"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"partial"}]}]},
	  "affected":[{"source":"cna","affectedData":[
	     {"vendor":"acme","product":"widget","versions":[{"version":"1.0","status":"affected"}]}]}]
	}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	if v.State != "PUBLISHED" {
		t.Errorf("state = %q, want PUBLISHED (Deferred is an enrichment state)", v.State)
	}
	if v.EnrichmentStatus != "Deferred" {
		t.Errorf("enrichment status = %q, want Deferred", v.EnrichmentStatus)
	}
	if v.SSVC == nil || v.SSVC.Exploitation != "none" || v.SSVC.TechnicalImpact != "partial" {
		t.Errorf("ssvc = %+v, want the ssvcV203 decision points", v.SSVC)
	}
	if len(v.Tags) != 1 || v.Tags[0] != "disputed" {
		t.Errorf("tags = %v, want the cveTags preserved", v.Tags)
	}
	if len(v.Affected) != 1 || v.Affected[0].Product != "widget" {
		t.Errorf("affected = %+v, want the CNA product view NVD republishes", v.Affected)
	}
}

func TestNVDKeepsEveryVersionWindowForARepeatedCPE(t *testing.T) {
	raw := []byte(`{
	  "id":"CVE-2026-2222",
	  "configurations":[{"nodes":[
	    {"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
	                  "versionEndExcluding":"1.5"}]},
	    {"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
	                  "versionStartIncluding":"3.0","versionEndExcluding":"3.4"}]}
	  ]}]}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	if len(v.Affected) != 1 {
		t.Fatalf("affected = %+v, want one vendor/product entry", v.Affected)
	}
	if len(v.Affected[0].Ranges) != 2 {
		t.Fatalf("ranges = %+v, want both version windows", v.Affected[0].Ranges)
	}
}

func TestNVDIgnoresNegatedNodes(t *testing.T) {
	raw := []byte(`{
	  "id":"CVE-2026-3333",
	  "configurations":[{"nodes":[
	    {"negate":true,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:safe:*:*:*:*:*:*:*:*"}]}
	  ]}]}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	if len(v.Affected) != 0 {
		t.Fatalf("affected = %+v, want nothing: a negated node asserts NOT vulnerable", v.Affected)
	}
}

func TestCVE5ParsesPackageURLTagsAndUnaffectedVersions(t *testing.T) {
	raw := []byte(`{
	  "cveMetadata":{"cveId":"CVE-2026-4444","state":"PUBLISHED"},
	  "containers":{"cna":{
	    "tags":["disputed"],
	    "affected":[{"vendor":"acme","product":"widget","packageURL":"pkg:npm/widget",
	      "defaultStatus":"affected",
	      "versions":[{"version":"1.0","status":"affected"},
	                  {"version":"2.0","status":"unaffected"}]}],
	    "metrics":[{"cvssV3_1":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	                "cvssV2_0":{"baseScore":10.0,"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]
	  }}}`)
	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}
	if len(v.Tags) != 1 || v.Tags[0] != "disputed" {
		t.Errorf("tags = %v, want the CNA tag preserved", v.Tags)
	}
	var affected, unaffected bool
	for _, a := range v.Affected {
		if a.PURL != "pkg:npm/widget" {
			t.Errorf("purl = %q, want the CVE 5.2.0 packageURL", a.PURL)
		}
		switch a.Status {
		case model.StatusAffected:
			affected = true
		case model.StatusNotAffected:
			unaffected = true
		}
	}
	if !affected || !unaffected {
		t.Errorf("affected entries = %+v, want both the affected and unaffected windows", v.Affected)
	}
	if len(v.Severities) != 2 {
		t.Errorf("severities = %+v, want every CVSS version in the metrics element", v.Severities)
	}
}

// Every cpeMatch window of one vendor/product lands in the same Ranges slice,
// so a window stated for target_sw=wordpress lost that constraint and applied
// to the drupal build as well. The criteria has to travel with its window.
func TestNVDRangesCarryTheCriteriaTheyCameFrom(t *testing.T) {
	raw := []byte(`{
	  "id":"CVE-2026-5555",
	  "configurations":[{"nodes":[{"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:a:acme:libfoo:*:*:*:*:*:wordpress:*:*","versionEndExcluding":"2.0"},
	    {"vulnerable":true,"criteria":"cpe:2.3:a:acme:libfoo:*:*:*:*:*:drupal:*:*","versionStartIncluding":"3.0","versionEndExcluding":"3.1"}
	  ]}]}]}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	if len(v.Affected) != 1 || len(v.Affected[0].Ranges) != 2 {
		t.Fatalf("affected = %+v, want one entry with two windows", v.Affected)
	}
	byFixed := map[string]string{}
	for _, r := range v.Affected[0].Ranges {
		byFixed[r.Fixed] = r.CPE
	}
	if byFixed["2.0"] != "cpe:2.3:a:acme:libfoo:*:*:*:*:*:wordpress:*:*" {
		t.Errorf("window <2.0 carries CPE %q, want the wordpress criteria", byFixed["2.0"])
	}
	if byFixed["3.1"] != "cpe:2.3:a:acme:libfoo:*:*:*:*:*:drupal:*:*" {
		t.Errorf("window <3.1 carries CPE %q, want the drupal criteria", byFixed["3.1"])
	}
}

// The NVD API 2.0 schema spells cveTags as objects; the reconstructed feeds
// spell it as strings. Refusing the object form skipped exactly the disputed
// records the tags exist to flag.
func TestNVDCVETagsAcceptBothTheStringAndTheObjectShape(t *testing.T) {
	cases := map[string]string{
		"string array": `["disputed","unsupported-when-assigned"]`,
		"object array": `[{"sourceIdentifier":"cve@mitre.org","tags":["disputed"]},
		                  {"sourceIdentifier":"nvd@nist.gov","tags":["unsupported-when-assigned"]}]`,
		"mixed": `["disputed",{"sourceIdentifier":"nvd@nist.gov","tags":["unsupported-when-assigned"]}]`,
	}
	for name, tags := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"id":"CVE-2026-6666","cveTags":` + tags + `}`)
			v, err := NVDToModel(raw, "nvd")
			if err != nil {
				t.Fatalf("NVDToModel() error = %v", err)
			}
			if len(v.Tags) != 2 || v.Tags[0] != "disputed" || v.Tags[1] != "unsupported-when-assigned" {
				t.Errorf("tags = %v, want both tags flattened", v.Tags)
			}
		})
	}
	raw := []byte(`{"id":"CVE-2026-6667","cveTags":null}`)
	if v, err := NVDToModel(raw, "nvd"); err != nil || len(v.Tags) != 0 {
		t.Errorf("null cveTags: v.Tags = %v, err = %v; want no tags and no error", v, err)
	}
}

// A record that fails to decode is skipped by the collector, and the only
// trace it leaves is the error text. Without the identifier in it nobody can
// tell which record was lost.
func TestAParseErrorNamesTheRecord(t *testing.T) {
	cases := []struct {
		name  string
		parse func([]byte, string) (*model.Vulnerability, error)
		raw   string
		want  string
	}{
		{"nvd", NVDToModel, `{"id":"CVE-2026-7777","descriptions":"not-an-array"}`, "CVE-2026-7777"},
		{"cve5", CVE5ToModel, `{"cveMetadata":{"cveId":"CVE-2026-7778"},"containers":{"cna":{"affected":"nope"}}}`, "CVE-2026-7778"},
		{"osv", OSVToModel, `{"id":"GHSA-1234-5678-9abc","affected":{"not":"an array"}}`, "GHSA-1234-5678-9abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.parse([]byte(tc.raw), tc.name)
			if err == nil {
				t.Fatal("expected a decode error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the record %s", err, tc.want)
			}
		})
	}
}

// Since NVD narrowed its enrichment, the CISA ADP's cpeApplicability in the
// CVE 5.1 record is the only CPE tree most records get. It was not read at all.
func TestCVE5ReadsCPEApplicabilityFromTheADPContainer(t *testing.T) {
	raw := []byte(`{
	  "cveMetadata":{"cveId":"CVE-2026-8888","state":"PUBLISHED"},
	  "containers":{
	    "cna":{"affected":[{"vendor":"acme","product":"widget","versions":[{"version":"1.0","status":"affected"}]}]},
	    "adp":[{
	      "providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP"},
	      "title":"CISA ADP Vulnrichment",
	      "cpeApplicability":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
	        {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
	         "versionStartIncluding":"1.0","versionEndExcluding":"1.4"},
	        {"vulnerable":false,"criteria":"cpe:2.3:o:acme:widget_os:*:*:*:*:*:*:*:*"}
	      ]}]}]
	    }]
	  }}`)
	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}
	var cpeEntry *model.Affected
	for i := range v.Affected {
		if len(v.Affected[i].CPEs) > 0 {
			cpeEntry = &v.Affected[i]
		}
	}
	if cpeEntry == nil {
		t.Fatalf("affected = %+v, want an entry derived from the ADP cpeApplicability", v.Affected)
	}
	if len(cpeEntry.CPEs) != 1 || cpeEntry.CPEs[0] != "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*" {
		t.Errorf("cpes = %v, want the vulnerable criteria only", cpeEntry.CPEs)
	}
	if cpeEntry.Vendor != "acme" || cpeEntry.Product != "widget" {
		t.Errorf("vendor/product = %q/%q, want acme/widget from the CPE", cpeEntry.Vendor, cpeEntry.Product)
	}
	if len(cpeEntry.Ranges) != 1 || cpeEntry.Ranges[0].Introduced != "1.0" || cpeEntry.Ranges[0].Fixed != "1.4" {
		t.Fatalf("ranges = %+v, want the 1.0 -> 1.4 window", cpeEntry.Ranges)
	}
	if cpeEntry.Ranges[0].CPE != "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*" {
		t.Errorf("range CPE = %q, want the criteria the window came from", cpeEntry.Ranges[0].CPE)
	}
}

// CVSS v2 has three bands and no Critical. Every parser put a v2 10.0 in the
// v3 table and published CRITICAL, a band the metric does not have.
func TestCVSSV2IsNeverRatedCritical(t *testing.T) {
	check := func(t *testing.T, sevs []model.Severity) {
		t.Helper()
		found := false
		for _, s := range sevs {
			if s.Type != "CVSS_V2" {
				continue
			}
			found = true
			if s.Rating != "HIGH" {
				t.Errorf("v2 rating = %q, want HIGH for a 10.0", s.Rating)
			}
		}
		if !found {
			t.Fatalf("severities = %+v, want a CVSS_V2 statement", sevs)
		}
	}
	t.Run("cve5", func(t *testing.T) {
		v, err := CVE5ToModel([]byte(`{"cveMetadata":{"cveId":"CVE-2026-9001"},"containers":{"cna":{
		  "metrics":[{"cvssV2_0":{"baseScore":10.0,"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]}}}`), "cvelist")
		if err != nil {
			t.Fatal(err)
		}
		check(t, v.Severities)
	})
	t.Run("nvd", func(t *testing.T) {
		v, err := NVDToModel([]byte(`{"id":"CVE-2026-9002","metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov",
		  "cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C","baseScore":10.0}}]}}`), "nvd")
		if err != nil {
			t.Fatal(err)
		}
		check(t, v.Severities)
	})
	t.Run("osv", func(t *testing.T) {
		v, err := OSVToModel([]byte(`{"id":"OSV-9003","severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}`), "osv")
		if err != nil {
			t.Fatal(err)
		}
		check(t, v.Severities)
	})
}

// Ubuntu's OSV export rates with a word, not a vector. That word is a rating
// and belongs in Rating; putting it in Vector published "Medium" as a CVSS
// vector and left the record unrated.
func TestOSVQualitativeSeverityGoesIntoRatingNotVector(t *testing.T) {
	raw := []byte(`{"id":"UBUNTU-CVE-2026-1","modified":"2026-01-01T00:00:00Z",
	  "severity":[{"type":"Ubuntu","score":"Medium"}]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Severities) != 1 {
		t.Fatalf("severities = %+v, want one", v.Severities)
	}
	s := v.Severities[0]
	if s.Rating != "MEDIUM" {
		t.Errorf("rating = %q, want MEDIUM", s.Rating)
	}
	if s.Vector != "" {
		t.Errorf("vector = %q, want empty: a word is not a vector", s.Vector)
	}
	if s.Type != "OTHER" {
		t.Errorf("type = %q, want OTHER", s.Type)
	}
}

// An OSV limit says where the publisher stopped describing a GIT range, not
// that the flaw is fixed there. Presenting it as Fixed claimed a fix that was
// never made; leaving the window open-ended would claim every later commit.
func TestOSVLimitIsBoundedButNotPresentedAsFixed(t *testing.T) {
	raw := []byte(`{"id":"OSV-LIMIT-1","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"GIT","name":"widget"},
	    "ranges":[{"type":"GIT","repo":"https://git.example/widget",
	      "events":[{"introduced":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	                {"limit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}]}]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	if len(v.Affected) != 1 || len(v.Affected[0].Ranges) != 1 {
		t.Fatalf("affected = %+v, want one window", v.Affected)
	}
	r := v.Affected[0].Ranges[0]
	if r.Fixed != "" {
		t.Errorf("fixed = %q, want empty: a limit is not a fix", r.Fixed)
	}
	if r.Limit != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("limit = %q, want the limit kept verbatim", r.Limit)
	}
	if r.LastAffected == "" {
		t.Error("last_affected is empty: the window would be read as open-ended and claim every later commit")
	}
	if r.Repo != "https://git.example/widget" {
		t.Errorf("repo = %q, want the range's repository", r.Repo)
	}
}

// The schema puts introduced first; some publishers write the pair the other
// way round, which paired reads as an open-ended window plus a bare bound.
func TestOSVAReversedEventPairIsRepaired(t *testing.T) {
	raw := []byte(`{"id":"OSV-ORDER-1","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.2"},{"introduced":"0"}]}]}]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	rs := v.Affected[0].Ranges
	if len(rs) != 1 || rs[0].Introduced != "0" || rs[0].Fixed != "1.2" {
		t.Fatalf("ranges = %+v, want the single window 0 -> 1.2", rs)
	}
	// A well-formed multi-window stream must be left exactly as written.
	raw = []byte(`{"id":"OSV-ORDER-2","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"},{"introduced":"2"},{"fixed":"3"}]}]}]}`)
	v, err = OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	rs = v.Affected[0].Ranges
	if len(rs) != 2 || rs[0].Fixed != "1" || rs[1].Introduced != "2" || rs[1].Fixed != "3" {
		t.Fatalf("ranges = %+v, want 0->1 and 2->3 untouched", rs)
	}
}

// The repair of a reversed pair used to apply to any closing event that
// arrived with no window open and an "introduced" behind it. That is also the
// shape of a legitimate stream: a "limit" closes one window and the next
// window opens right after it, and the swap moved the limit into the next
// window, so c and d ended up bounding something the publisher never said.
// Only the two-event reversed pair is repaired; everything longer is paired
// in the publisher's order.
func TestOSVOnlyATwoEventReversedPairIsRepaired(t *testing.T) {
	// A limit closing the first window, then a second window. In the
	// publisher's order this pairs as {a→b}, a bare limit c, {d→e}.
	raw := []byte(`{"id":"OSV-ORDER-3","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},
	    "ranges":[{"type":"ECOSYSTEM","events":[
	      {"introduced":"a"},{"fixed":"b"},{"limit":"c"},{"introduced":"d"},{"fixed":"e"}]}]}]}`)
	v, err := OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	rs := v.Affected[0].Ranges
	if len(rs) != 3 {
		t.Fatalf("ranges = %+v, want three: a->b, the bare limit c, d->e", rs)
	}
	if rs[0].Introduced != "a" || rs[0].Fixed != "b" {
		t.Errorf("first range = %+v, want a -> b", rs[0])
	}
	if rs[1].Introduced != "" || rs[1].Limit != "c" {
		t.Errorf("second range = %+v, want the bare limit c as the publisher wrote it", rs[1])
	}
	if rs[2].Introduced != "d" || rs[2].Fixed != "e" || rs[2].Limit != "" || rs[2].LastAffected != "" {
		t.Errorf("third range = %+v, want d -> e with no limit moved into it", rs[2])
	}

	// A last_affected after a fixed, then a new window: the swap produced
	// {2, <=1.5}, a window whose upper bound is below its lower one.
	raw = []byte(`{"id":"OSV-ORDER-4","modified":"2026-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},
	    "ranges":[{"type":"ECOSYSTEM","events":[
	      {"introduced":"0"},{"fixed":"1"},{"last_affected":"1.5"},{"introduced":"2"}]}]}]}`)
	v, err = OSVToModel(raw, "osv")
	if err != nil {
		t.Fatalf("OSVToModel() error = %v", err)
	}
	rs = v.Affected[0].Ranges
	if len(rs) != 3 {
		t.Fatalf("ranges = %+v, want three: 0->1, the bare last_affected 1.5, the open window from 2", rs)
	}
	if rs[1].Introduced != "" || rs[1].LastAffected != "1.5" {
		t.Errorf("second range = %+v, want the bare last_affected 1.5", rs[1])
	}
	if rs[2].Introduced != "2" || rs[2].LastAffected != "" || rs[2].Fixed != "" {
		t.Errorf("third range = %+v, want the open window from 2, not an inverted one", rs[2])
	}

	// The two-event pair itself is still repaired.
	if got := orderedEvents([]osvEvent{{Fixed: "1.2"}, {Introduced: "0"}}); got[0].Introduced != "0" || got[1].Fixed != "1.2" {
		t.Errorf("orderedEvents on the reversed pair = %+v, want it swapped", got)
	}
}

// A record's identifier is quoted in the parse error, and the error is
// logged. An identifier is untrusted input: one that is a hundred kilobytes
// long puts all of it in the log line, and one carrying control characters
// rewrites the line around it.
func TestAParseErrorQuotesOnlyABoundedCleanIdentifier(t *testing.T) {
	huge := strings.Repeat("A", 100<<10)
	doc := `{"id":"` + huge + `","descriptions":"not-an-array"}`
	_, err := NVDToModel([]byte(doc), "nvd")
	if err == nil {
		t.Fatal("expected a decode error")
	}
	if len(err.Error()) > 512 {
		t.Errorf("error is %d bytes long; the identifier was quoted in full", len(err.Error()))
	}
	if !strings.Contains(err.Error(), strings.Repeat("A", 64)+"…") {
		t.Errorf("error %q does not carry the capped identifier", truncateForLog(err.Error()))
	}

	doc = `{"id":"CVE-2026-1\r\n\u001b[2Kfake line\u0007","descriptions":"not-an-array"}`
	_, err = NVDToModel([]byte(doc), "nvd")
	if err == nil {
		t.Fatal("expected a decode error")
	}
	if strings.ContainsAny(err.Error(), "\r\n\x1b\x07") {
		t.Errorf("error %q carries control characters into the log", err.Error())
	}
	if !strings.Contains(err.Error(), "CVE-2026-1[2Kfake line") {
		t.Errorf("error %q lost the printable part of the identifier", err.Error())
	}
}

func truncateForLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// The 2.3 binding writes a colon inside an attribute as "\:", and a plain
// split on ':' read everything after it as the following attributes.
func TestCPEVendorProductHonoursEscapedColons(t *testing.T) {
	cases := []struct {
		cpe             string
		vendor, product string
	}{
		{"cpe:2.3:a:acme:libfoo:1.0:*:*:*:*:*:*:*", "acme", "libfoo"},
		{`cpe:2.3:a:acme\:corp:lib\:foo:1.0:*:*:*:*:*:*:*`, `acme\:corp`, `lib\:foo`},
		// A backslash that is itself escaped does not escape the colon after it.
		{`cpe:2.3:a:acme\\:libfoo:1.0:*:*:*:*:*:*:*`, `acme\\`, "libfoo"},
		{"cpe:2.3:a", "", ""},
	}
	for _, tc := range cases {
		v, p := cpeVendorProduct(tc.cpe)
		if v != tc.vendor || p != tc.product {
			t.Errorf("cpeVendorProduct(%q) = %q, %q; want %q, %q", tc.cpe, v, p, tc.vendor, tc.product)
		}
	}
}

// The NVD copy of the CNA affected view lists unaffected versions the same way
// the CVE 5.1 record does; dropping them turned "everything except these"
// into "everything".
func TestNVDKeepsUnaffectedVersionsAsNotAffectedRows(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-9100",
	  "affected":[{"source":"cna","affectedData":[{"vendor":"acme","product":"widget","versions":[
	    {"version":"0","status":"affected","lessThan":"3.0"},
	    {"version":"2.9.1","status":"unaffected"}]}]}]}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	var notAffected *model.Affected
	for i := range v.Affected {
		if v.Affected[i].Status == model.StatusNotAffected {
			notAffected = &v.Affected[i]
		}
	}
	if notAffected == nil {
		t.Fatalf("affected = %+v, want a not_affected row for 2.9.1", v.Affected)
	}
	if len(notAffected.Versions) != 1 || notAffected.Versions[0] != "2.9.1" {
		t.Errorf("not_affected versions = %v, want [2.9.1]", notAffected.Versions)
	}
}

// The same SSVC decision reaches us through NVD and through the CVE List; its
// provenance should be spelled the same way from both.
func TestNVDSSVCSourceIsSpelledLikeCVE5(t *testing.T) {
	raw := []byte(`{"id":"CVE-2026-9200","metrics":{"ssvcV203":[{"source":"CISA-ADP","options":[{"Exploitation":"poc"}]}]}}`)
	v, err := NVDToModel(raw, "nvd")
	if err != nil {
		t.Fatalf("NVDToModel() error = %v", err)
	}
	if v.SSVC == nil || v.SSVC.Source != "nvd/CISA-ADP" {
		t.Errorf("ssvc = %+v, want Source nvd/CISA-ADP (collector/provider, as cve5 spells it)", v.SSVC)
	}
}

// Some CNAs publish the base score without the vector. Requiring the vector
// threw away the only score those records carried.
func TestCVE5KeepsAMetricWithAScoreButNoVector(t *testing.T) {
	raw := []byte(`{"cveMetadata":{"cveId":"CVE-2026-9300"},"containers":{"cna":{
	  "metrics":[{"cvssV3_1":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}`)
	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatalf("CVE5ToModel() error = %v", err)
	}
	if len(v.Severities) != 1 || v.Severities[0].Score != 7.5 || v.Severities[0].Rating != "HIGH" {
		t.Fatalf("severities = %+v, want the 7.5 HIGH statement kept", v.Severities)
	}
}
