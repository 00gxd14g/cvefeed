// Package parse turns upstream documents into canonical model records.
package parse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// CVE5 mirrors the parts of CVE Record Format 5.1 we consume. Fields we do not
// model are still preserved: the untouched document is stored as Raw.
type CVE5 struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CVEMetadata struct {
		CVEID             string `json:"cveId"`
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		State             string `json:"state"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
		DateReserved      string `json:"dateReserved"`
		DateRejected      string `json:"dateRejected"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
}

type cve5Container struct {
	ProviderMetadata struct {
		OrgID       string `json:"orgId"`
		ShortName   string `json:"shortName"`
		DateUpdated string `json:"dateUpdated"`
	} `json:"providerMetadata"`
	Title           string          `json:"title"`
	Tags            []string        `json:"tags"`
	Descriptions    []cve5LangValue `json:"descriptions"`
	RejectedReasons []cve5LangValue `json:"rejectedReasons"`
	Affected        []cve5Affected  `json:"affected"`
	References      []cve5Reference `json:"references"`
	ProblemTypes    []struct {
		Descriptions []struct {
			CWEID       string `json:"cweId"`
			Description string `json:"description"`
			Lang        string `json:"lang"`
			Type        string `json:"type"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Metrics  []cve5Metric `json:"metrics"`
	Timeline []struct {
		Time  string `json:"time"`
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"timeline"`
	// CPEApplicability is the CPE tree CVE Record Format 5.1 added, in the
	// same shape as NVD's configurations. Since NVD narrowed what it enriches
	// the CISA ADP container's copy of this is the only CPE data most records
	// ever get, so the CNA's and every ADP's are read.
	CPEApplicability []cpeConfiguration `json:"cpeApplicability"`
}

type cve5LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cve5Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type cve5Affected struct {
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	PackageName   string   `json:"packageName"`
	CollectionURL string   `json:"collectionURL"`
	Repo          string   `json:"repo"`
	CPEs          []string `json:"cpes"`
	// packageURL arrived with CVE Record Format 5.2.0 (October 2025) and is the
	// only PURL the authoritative CNA record carries.
	PackageURL    string `json:"packageURL"`
	DefaultStatus string `json:"defaultStatus"`
	Versions      []struct {
		Version         string `json:"version"`
		Status          string `json:"status"`
		LessThan        string `json:"lessThan"`
		LessThanOrEqual string `json:"lessThanOrEqual"`
		VersionType     string `json:"versionType"`
		// Changes split one version interval into status intervals. For example,
		// affected from 1.0, fixed at 1.5 is not an exact-version statement: it
		// is [1.0,1.5) affected and [1.5,...] fixed. Dropping changes therefore
		// turns patched builds into findings.
		Changes []struct {
			At     string `json:"at"`
			Status string `json:"status"`
		} `json:"changes"`
	} `json:"versions"`
}

// cve5Metric holds the several CVSS spellings plus CISA's SSVC block. Every
// version has a differently named key, which is why this is one struct with
// many optional members rather than a discriminated union.
type cve5Metric struct {
	Format   string `json:"format"`
	CVSSv4_0 *struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssV4_0"`
	CVSSv3_1 *struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssV3_1"`
	CVSSv3_0 *struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssV3_0"`
	CVSSv2_0 *struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssV2_0"`
	Other *struct {
		Type    string `json:"type"`
		Content struct {
			ID      string              `json:"id"`
			Options []map[string]string `json:"options"`
			Role    string              `json:"role"`
			Version string              `json:"version"`
			Time    string              `json:"timestamp"`
		} `json:"content"`
	} `json:"other"`
}

// CVE5ToModel converts one CVE 5.x record. source names the collector so that
// every derived statement stays attributable.
func CVE5ToModel(raw []byte, source string) (*model.Vulnerability, error) {
	var rec CVE5
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("parse: cve5%s: %w", idSuffix(raw, "cveMetadata.cveId"), err)
	}
	id := model.NormalizeID(rec.CVEMetadata.CVEID)
	if id == "" {
		return nil, fmt.Errorf("parse: cve5: record has no cveId")
	}

	v := &model.Vulnerability{
		ID:                id,
		State:             strings.ToUpper(rec.CVEMetadata.State),
		Published:         model.ParseTime(rec.CVEMetadata.DatePublished),
		Modified:          model.ParseTime(rec.CVEMetadata.DateUpdated),
		AssignerShortName: rec.CVEMetadata.AssignerShortName,
		Source:            source,
		SourceRecordID:    id,
		Raw:               json.RawMessage(raw),
	}
	if v.State == "REJECTED" {
		v.Withdrawn = model.ParseTime(rec.CVEMetadata.DateRejected)
		// The CNA explains WHY in rejectedReasons; that text is the only useful
		// content a rejected record has left, so it becomes the description.
		for _, d := range rec.Containers.CNA.RejectedReasons {
			if strings.HasPrefix(strings.ToLower(d.Lang), "en") && d.Value != "" {
				v.Description = d.Value
				break
			}
		}
	}

	containers := append([]cve5Container{rec.Containers.CNA}, rec.Containers.ADP...)
	for i, c := range containers {
		provider := c.ProviderMetadata.ShortName
		if provider == "" {
			if i == 0 {
				provider = rec.CVEMetadata.AssignerShortName
			} else {
				provider = "adp"
			}
		}
		applyContainer(v, c, provider, source, i == 0)
	}

	v.Aliases = model.DedupeStrings(v.Aliases)
	v.CWEs = model.DedupeStrings(v.CWEs)
	v.Tags = model.DedupeStrings(v.Tags)
	return v, nil
}

func applyContainer(v *model.Vulnerability, c cve5Container, provider, source string, isCNA bool) {
	// "disputed" and "unsupported-when-assigned" change how a record should be
	// read; dropping them loses the caveat entirely.
	v.Tags = append(v.Tags, c.Tags...)
	// Only the CNA names the vulnerability. In an ADP container `title` is
	// the container's own label ("CVE Program Container", "CISA ADP
	// Vulnrichment"), and falling back to it gave every record without a CNA
	// title the same meaningless heading.
	if isCNA {
		v.Title = c.Title
	}
	for _, d := range c.Descriptions {
		if !strings.EqualFold(d.Lang, "en") && !strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			continue
		}
		if v.Description == "" || isCNA {
			v.Description = d.Value
		}
		break
	}

	for _, pt := range c.ProblemTypes {
		for _, d := range pt.Descriptions {
			if d.CWEID != "" {
				v.CWEs = append(v.CWEs, d.CWEID)
			}
		}
	}

	for _, r := range c.References {
		if r.URL == "" {
			continue
		}
		v.References = append(v.References, model.Reference{
			URL: r.URL, Name: r.Name, Tags: r.Tags, Source: source,
		})
	}

	for _, a := range c.Affected {
		product := a.Product
		if product == "" {
			product = a.PackageName
		}
		identity := model.Affected{
			Vendor: a.Vendor, Product: product, PURL: a.PackageURL,
			CPEs: model.DedupeStrings(a.CPEs), Source: source,
		}
		rows := map[string]*model.Affected{}
		rowFor := func(rawStatus string) *model.Affected {
			status := model.NormalizeStatus(rawStatus)
			if strings.TrimSpace(rawStatus) == "" {
				status = model.StatusAffected
			}
			if status == "" {
				status = model.StatusUnderInvestigation
			}
			if row := rows[status]; row != nil {
				return row
			}
			row := identity
			row.Status = status
			// defaultStatus describes the product as a whole and belongs only on
			// the positive/default row. Copying "affected" onto an exception row
			// makes an unlisted negative version look positive again in matching.
			if status == model.StatusAffected {
				row.DefaultState = a.DefaultStatus
			}
			rows[status] = &row
			return &row
		}

		appendInterval := func(row *model.Affected, start, endExclusive, endInclusive, typ string) {
			start = strings.TrimSpace(start)
			endExclusive = strings.TrimSpace(endExclusive)
			endInclusive = strings.TrimSpace(endInclusive)
			if start == "" && endExclusive == "" && endInclusive == "" {
				return
			}
			row.Ranges = append(row.Ranges, model.VersionRange{
				Introduced: start, Fixed: endExclusive, LastAffected: endInclusive,
				Type: strings.ToUpper(typ),
			})
		}

		for _, ver := range a.Versions {
			if len(ver.Changes) == 0 {
				row := rowFor(ver.Status)
				switch {
				case ver.LessThan != "":
					appendInterval(row, ver.Version, ver.LessThan, "", ver.VersionType)
				case ver.LessThanOrEqual != "":
					appendInterval(row, ver.Version, "", ver.LessThanOrEqual, ver.VersionType)
				case ver.Version != "":
					row.Versions = append(row.Versions, ver.Version)
				}
				continue
			}

			// `changes` is a state machine over one declared interval. Every
			// change boundary closes the previous status exclusively and starts
			// the next at that exact version. The final status inherits the outer
			// lessThan/lessThanOrEqual bound, if the CNA supplied one.
			start := ver.Version
			status := ver.Status
			for _, change := range ver.Changes {
				if strings.TrimSpace(change.At) == "" {
					continue
				}
				appendInterval(rowFor(status), start, change.At, "", ver.VersionType)
				start = change.At
				status = change.Status
			}
			appendInterval(rowFor(status), start, ver.LessThan, ver.LessThanOrEqual, ver.VersionType)
		}

		// defaultStatus is a statement about every build not covered by an
		// explicit exception. In particular, defaultStatus:"affected" plus a
		// list containing only unaffected/fixed versions means "everything
		// except these". Keep an unbounded positive row even when no explicit
		// affected version appeared, or those records turn into false negatives.
		if len(a.Versions) == 0 || model.NormalizeStatus(a.DefaultStatus) == model.StatusAffected {
			rowFor(model.StatusAffected)
		}
		for _, status := range model.Statuses() {
			row := rows[status]
			if row == nil {
				continue
			}
			if status != model.StatusAffected && len(row.Ranges) == 0 && len(row.Versions) == 0 {
				continue
			}
			if row.Vendor != "" || row.Product != "" || len(row.CPEs) > 0 || row.PURL != "" {
				v.Affected = append(v.Affected, *row)
			}
		}
	}

	v.Affected = append(v.Affected, cpeAffected(c.CPEApplicability, source)...)

	for _, m := range c.Metrics {
		v.Severities = append(v.Severities, metricsToSeverities(m, provider, source)...)
		if ssvc := metricToSSVC(m, provider, source); ssvc != nil && v.SSVC == nil {
			v.SSVC = ssvc
		}
	}
}

// metricsToSeverities returns every CVSS statement a metrics element carries.
// One element may legitimately hold several versions at once, and returning
// only the highest discarded the rest — including the v3.1 score that is the
// one most consumers can actually use, whenever a v4.0 vector sat beside it.
//
// A statement is kept when it has a vector or a score. Some CNAs publish the
// number without the vector, and requiring the vector threw away the only
// score those records had.
func metricsToSeverities(m cve5Metric, provider, source string) []model.Severity {
	var out []model.Severity
	if m.CVSSv4_0 != nil && (m.CVSSv4_0.VectorString != "" || m.CVSSv4_0.BaseScore > 0) {
		out = append(out, model.Severity{Type: "CVSS_V4_0", Score: m.CVSSv4_0.BaseScore,
			Vector: m.CVSSv4_0.VectorString, Rating: rating(m.CVSSv4_0.BaseSeverity, m.CVSSv4_0.BaseScore),
			Provider: provider, Source: source})
	}
	if m.CVSSv3_1 != nil && (m.CVSSv3_1.VectorString != "" || m.CVSSv3_1.BaseScore > 0) {
		out = append(out, model.Severity{Type: "CVSS_V3_1", Score: m.CVSSv3_1.BaseScore,
			Vector: m.CVSSv3_1.VectorString, Rating: rating(m.CVSSv3_1.BaseSeverity, m.CVSSv3_1.BaseScore),
			Provider: provider, Source: source})
	}
	if m.CVSSv3_0 != nil && (m.CVSSv3_0.VectorString != "" || m.CVSSv3_0.BaseScore > 0) {
		out = append(out, model.Severity{Type: "CVSS_V3_0", Score: m.CVSSv3_0.BaseScore,
			Vector: m.CVSSv3_0.VectorString, Rating: rating(m.CVSSv3_0.BaseSeverity, m.CVSSv3_0.BaseScore),
			Provider: provider, Source: source})
	}
	if m.CVSSv2_0 != nil && (m.CVSSv2_0.VectorString != "" || m.CVSSv2_0.BaseScore > 0) {
		// CVSS v2 carries no baseSeverity in the record format and has its
		// own three-band table, so the band is always derived and never
		// CRITICAL.
		out = append(out, model.Severity{Type: "CVSS_V2", Score: m.CVSSv2_0.BaseScore,
			Vector: m.CVSSv2_0.VectorString, Rating: model.RatingFromScoreV2(m.CVSSv2_0.BaseScore),
			Provider: provider, Source: source})
	}
	return out
}

// metricToSSVC extracts CISA's SSVC decision points. They arrive inside the
// generic "other" metric with type "ssvc" and an options array of single-key
// maps, which is why this needs a loop rather than a struct field.
func metricToSSVC(m cve5Metric, provider, source string) *model.SSVC {
	if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
		return nil
	}
	// Source names the collector, Provider the asserting organisation (CISA-ADP
	// in practice). Both matter: the collector says where we got it, the
	// provider says who decided it.
	s := &model.SSVC{Version: m.Other.Content.Version, Timestamp: m.Other.Content.Time, Source: source}
	if provider != "" {
		s.Source = source + "/" + provider
	}
	for _, opt := range m.Other.Content.Options {
		for k, val := range opt {
			switch strings.ToLower(k) {
			case "exploitation":
				s.Exploitation = strings.ToLower(val)
			case "automatable":
				s.Automatable = strings.ToLower(val)
			case "technical impact", "technicalimpact":
				s.TechnicalImpact = strings.ToLower(val)
			}
		}
	}
	if s.Exploitation == "" && s.Automatable == "" && s.TechnicalImpact == "" {
		return nil
	}
	return s
}

func rating(given string, score float64) string {
	if given != "" {
		return strings.ToUpper(given)
	}
	return model.RatingFromScore(score)
}
