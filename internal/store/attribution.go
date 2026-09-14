package store

import (
	"context"
	"fmt"
)

// Attribution is one upstream's licence and the notice that must travel with
// its data.
//
// This is not decoration. The NVD terms of use ask every service that uses the
// API to display a specific sentence; MITRE's CVE Terms of Use require the
// copyright notice and licence text to accompany copies; FIRST requests
// attribution for EPSS; GHSA, Red Hat, SUSE and the Ubuntu-derived OSV feeds
// are CC-BY or CC-BY-SA, which makes credit a licence condition rather than a
// courtesy. A service that redistributes all of them has to say so somewhere a
// consumer can actually see, which is why this is served from the API and not
// buried in a README.
type Attribution struct {
	Source   string `json:"source"`
	Upstream string `json:"upstream"`
	Licence  string `json:"licence"`
	Notice   string `json:"notice"`
	URL      string `json:"url,omitempty"`
	Required bool   `json:"required"`
}

// NVDNotice is the sentence NIST asks consumers of the NVD API to display.
const NVDNotice = "This product uses the NVD API but is not endorsed or certified by the NVD."

// DefaultAttributions is the notice set for the eleven collectors this service
// runs. Sources whose licence asks for nothing are still listed, because "no
// attribution required" is itself an answer an operator needs.
func DefaultAttributions() []Attribution {
	return []Attribution{
		{
			Source:   "cvelist",
			Upstream: "CVE Program / MITRE — CVE List v5",
			Licence:  "CVE Terms of Use (SPDX: cve-tou)",
			Notice: "CVE® is a registered trademark of The MITRE Corporation. CVE Records are " +
				"reproduced under the CVE Program Terms of Use; the data is provided \"AS IS\".",
			URL:      "https://www.cve.org/Legal/TermsOfUse",
			Required: true,
		},
		{
			Source:   "nvd",
			Upstream: "NIST National Vulnerability Database — CVE API 2.0",
			Licence:  "US Government work, public domain",
			Notice:   NVDNotice,
			URL:      "https://nvd.nist.gov/developers/terms-of-use",
			Required: true,
		},
		{
			Source:   "fkie",
			Upstream: "Fraunhofer FKIE — reconstructed NVD feeds",
			Licence:  "NVD data, public domain; mirror carries no separate licence",
			Notice:   NVDNotice + " The yearly files are a community reconstruction, neither endorsed nor certified by the NVD.",
			URL:      "https://github.com/fkie-cad/nvd-json-data-feeds",
			Required: true,
		},
		{
			Source:   "vulnrichment",
			Upstream: "CISA Vulnrichment (CISA-ADP)",
			Licence:  "CC0-1.0",
			Notice:   "CISA Vulnrichment data is released under CC0-1.0; no attribution is required.",
			URL:      "https://github.com/cisagov/vulnrichment",
		},
		{
			Source:   "kev",
			Upstream: "CISA Known Exploited Vulnerabilities catalogue",
			Licence:  "CC0-1.0",
			Notice:   "The CISA KEV catalogue is released under CC0-1.0; no attribution is required.",
			URL:      "https://github.com/cisagov/kev-data",
		},
		{
			Source:   "epss",
			Upstream: "FIRST Exploit Prediction Scoring System",
			Licence:  "Free to use; attribution requested",
			Notice: "EPSS scores are provided by FIRST (https://www.first.org/epss). Attribution is " +
				"requested when EPSS data is used in publications or products.",
			URL:      "https://www.first.org/epss/",
			Required: true,
		},
		{
			Source:   "osv",
			Upstream: "OSV.dev (Google / OpenSSF)",
			Licence:  "Per upstream source: CC-BY-4.0, CC-BY-SA-4.0 (Ubuntu, Alpine), CC0, MIT, BSD, Apache-2.0",
			Notice: "Records aggregated from OSV.dev retain their originating database's licence. " +
				"Ubuntu- and Alpine-derived records are CC-BY-SA-4.0, which is share-alike.",
			URL:      "https://google.github.io/osv.dev/data/",
			Required: true,
		},
		{
			Source:   "ghsa",
			Upstream: "GitHub Advisory Database",
			Licence:  "CC-BY-4.0",
			Notice:   "Contains information from the GitHub Advisory Database, licensed under CC-BY-4.0.",
			URL:      "https://github.com/github/advisory-database",
			Required: true,
		},
		{
			Source:   "euvd",
			Upstream: "ENISA EU Vulnerability Database",
			Licence:  "ENISA legal notice: reproduction authorised provided the source is acknowledged",
			Notice:   "Contains information from the ENISA EU Vulnerability Database (EUVD).",
			URL:      "https://euvd.enisa.europa.eu/",
			Required: true,
		},
		{
			Source:   "gcve",
			Upstream: "GCVE registry and CIRCL Vulnerability-Lookup",
			Licence:  "Registry open (CIRCL); aggregated records inherit their upstream licences",
			Notice:   "Contains information from the GCVE registry and CIRCL Vulnerability-Lookup; records retain their originating source's licence.",
			URL:      "https://gcve.eu/",
			Required: true,
		},
		{
			Source:   "csaf",
			Upstream: "Vendor CSAF 2.0 providers",
			Licence:  "Per vendor; commonly TLP:WHITE, Red Hat and SUSE are CC-BY-4.0",
			Notice:   "Contains vendor CSAF advisories reproduced under each publisher's terms.",
			Required: true,
		},
	}
}

// seedAttribution writes the built-in notices, leaving operator edits to the
// non-notice columns alone but keeping the notice text itself authoritative.
func (s *Store) seedAttribution(ctx context.Context) error {
	for _, a := range DefaultAttributions() {
		if _, err := s.db.ExecContext(ctx, `
            INSERT INTO attribution (source, upstream, licence, notice, url, required, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6, now())
            ON CONFLICT (source) DO UPDATE SET
                upstream = EXCLUDED.upstream,
                licence  = EXCLUDED.licence,
                notice   = EXCLUDED.notice,
                url      = EXCLUDED.url,
                required = EXCLUDED.required,
                updated_at = now()`,
			a.Source, a.Upstream, a.Licence, a.Notice, nullStr(a.URL), a.Required); err != nil {
			return fmt.Errorf("store: seed attribution %s: %w", a.Source, err)
		}
	}
	return nil
}

// Attributions returns every recorded notice, most binding first.
func (s *Store) Attributions(ctx context.Context) ([]Attribution, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT source, upstream, licence, notice, COALESCE(url,''), required
          FROM attribution ORDER BY required DESC, source`)
	if err != nil {
		return nil, fmt.Errorf("store: attributions: %w", err)
	}
	defer rows.Close()

	out := []Attribution{}
	for rows.Next() {
		var a Attribution
		if err := rows.Scan(&a.Source, &a.Upstream, &a.Licence, &a.Notice, &a.URL, &a.Required); err != nil {
			return nil, fmt.Errorf("store: scan attribution: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
