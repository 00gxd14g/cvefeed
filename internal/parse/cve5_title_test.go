package parse

import "testing"

// An ADP container's title is the container's label, not the vulnerability's
// name; a record whose CNA gives no title must stay untitled rather than be
// called "CVE Program Container".
func TestCVE5ADPTitleIsNotTheVulnerabilityTitle(t *testing.T) {
	raw := []byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2014-6271", "state": "PUBLISHED", "datePublished": "2014-09-24T00:00:00"},
	  "containers": {
	    "cna": {"descriptions": [{"lang": "en", "value": "GNU Bash processes trailing strings after function definitions."}]},
	    "adp": [
	      {"title": "CVE Program Container", "providerMetadata": {"shortName": "CVE"}},
	      {"title": "CISA ADP Vulnrichment", "providerMetadata": {"shortName": "CISA-ADP"}}
	    ]
	  }
	}`)
	v, err := CVE5ToModel(raw, "cvelist")
	if err != nil {
		t.Fatal(err)
	}
	if v.Title != "" {
		t.Errorf("title = %q, want empty", v.Title)
	}
	if v.Description == "" {
		t.Error("description lost")
	}
}
