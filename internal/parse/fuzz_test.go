package parse

import "testing"

// Feed documents are written by hundreds of independent publishers and arrive
// unvalidated. A panic here takes down an ingest run mid-corpus.
func FuzzOSVToModel(f *testing.F) {
	f.Add(`{"id":"GHSA-x","aliases":["CVE-2021-44228"],"modified":"2026-01-01T00:00:00Z"}`)
	f.Add(`{"id":"MINI-a","upstream":["CVE-1","GHSA-2"],"modified":"2026-01-01T00:00:00Z"}`)
	f.Add(`{"id":"x","affected":[{"package":{"ecosystem":"Maven","name":"a:b"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`)
	f.Add(`{}`)
	f.Add(``)
	f.Add(`{"id":"x","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`)

	f.Fuzz(func(t *testing.T, doc string) {
		v, err := OSVToModel([]byte(doc), "osv")
		if err != nil {
			return
		}
		if v.ID == "" {
			t.Fatalf("accepted a record with no identifier: %q", doc)
		}
		// The alias graph is destructive — a merge deletes the losing rows — so
		// a record must never claim itself as an alias of itself, which would
		// make it its own loser.
		for _, a := range v.Aliases {
			if a == v.ID {
				t.Fatalf("record %q lists itself as an alias", v.ID)
			}
		}
	})
}

func FuzzCVE5ToModel(f *testing.F) {
	f.Add(`{"cveMetadata":{"cveId":"CVE-2021-44228","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"a","product":"b","versions":[{"version":"1","status":"affected"}]}]}}}`)
	f.Add(`{"cveMetadata":{"cveId":"CVE-2021-1","state":"REJECTED"}}`)
	f.Add(`{}`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, doc string) {
		v, err := CVE5ToModel([]byte(doc), "cvelist")
		if err != nil {
			return
		}
		if v.ID == "" {
			t.Fatalf("accepted a record with no identifier: %q", doc)
		}
		for _, a := range v.Aliases {
			if a == v.ID {
				t.Fatalf("record %q lists itself as an alias", v.ID)
			}
		}
	})
}
