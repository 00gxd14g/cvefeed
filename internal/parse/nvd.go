package parse

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// NVDCVE is one record of the NVD CVE API 2.0 response. The Fraunhofer FKIE
// reconstructed feeds use the identical object shape inside their yearly files,
// so this single parser serves both the live API and the bulk backfill path.
//
// The field set tracks schema 2.2.4: NVD added `affected` and
// `metrics.ssvcV203` on 2026-06-17, and the CISA KEV block and `cveTags`
// before that. They are parsed rather than left in the raw document because
// they are exactly the enrichment NVD still produces after the April 2026
// policy change narrowed what it scores.
type NVDCVE struct {
	ID                    string     `json:"id"`
	SourceIdentifier      string     `json:"sourceIdentifier"`
	Published             string     `json:"published"`
	LastModified          string     `json:"lastModified"`
	VulnStatus            string     `json:"vulnStatus"`
	CVETags               nvdCVETags `json:"cveTags"`
	CISAExploitAdd        string     `json:"cisaExploitAdd"`
	CISAActionDue         string     `json:"cisaActionDue"`
	CISARequiredAction    string     `json:"cisaRequiredAction"`
	CISAVulnerabilityName string     `json:"cisaVulnerabilityName"`
	Descriptions          []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
		CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
		CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
		SSVCv203      []struct {
			Source  string `json:"source"`
			Type    string `json:"type"`
			Options []struct {
				Exploitation    string `json:"Exploitation"`
				Automatable     string `json:"Automatable"`
				TechnicalImpact string `json:"Technical Impact"`
			} `json:"options"`
			Version   string `json:"version"`
			Timestamp string `json:"timestamp"`
		} `json:"ssvcV203"`
	} `json:"metrics"`
	Weaknesses []struct {
		Source      string `json:"source"`
		Type        string `json:"type"`
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	// Affected is the CNA-supplied vendor/product/version view NVD started
	// republishing in June 2026. It is the only product key on records that
	// have no CPE applicability statement at all.
	Affected []struct {
		Source       string `json:"source"`
		AffectedData []struct {
			Vendor      string `json:"vendor"`
			Product     string `json:"product"`
			PackageName string `json:"packageName"`
			Versions    []struct {
				Version         string `json:"version"`
				Status          string `json:"status"`
				LessThan        string `json:"lessThan"`
				LessThanOrEqual string `json:"lessThanOrEqual"`
			} `json:"versions"`
		} `json:"affectedData"`
	} `json:"affected"`
	Configurations []cpeConfiguration `json:"configurations"`
	References     []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
}

// nvdCVETags accepts both spellings of the NVD cveTags member. The API 2.0
// schema defines it as an array of {sourceIdentifier, tags[]} objects, one per
// organisation that tagged the record; the reconstructed feeds and the earlier
// parser assumed a flat array of strings. Decoding only the flat form made the
// object form a hard unmarshal error, and the records it appears on are the
// disputed and unsupported-when-assigned ones — exactly the records whose
// caveat matters most, and which were then silently skipped.
//
// Both shapes flatten to the tag strings; who applied the tag is not modelled.
type nvdCVETags []string

func (t *nvdCVETags) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*t = nil
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("cveTags: %w", err)
	}
	var out []string
	for _, item := range items {
		var tag string
		if err := json.Unmarshal(item, &tag); err == nil {
			out = append(out, tag)
			continue
		}
		var obj struct {
			SourceIdentifier string   `json:"sourceIdentifier"`
			Tags             []string `json:"tags"`
		}
		if err := json.Unmarshal(item, &obj); err != nil {
			return fmt.Errorf("cveTags: element is neither a string nor a {sourceIdentifier, tags} object: %w", err)
		}
		out = append(out, obj.Tags...)
	}
	*t = out
	return nil
}

// cpeConfiguration, cpeNode and cpeMatch are the CPE applicability tree. NVD
// publishes it as configurations[] and CVE Record Format 5.1 as
// cpeApplicability[] with the identical member names, so one set of types and
// one flattening routine serve both parsers.
type cpeConfiguration struct {
	Operator string    `json:"operator"`
	Negate   bool      `json:"negate"`
	Nodes    []cpeNode `json:"nodes"`
}

type cpeNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// NVDToModel converts one NVD 2.0 CVE object.
func NVDToModel(raw []byte, source string) (*model.Vulnerability, error) {
	var rec NVDCVE
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("parse: nvd%s: %w", idSuffix(raw, "id"), err)
	}
	id := model.NormalizeID(rec.ID)
	if id == "" {
		return nil, fmt.Errorf("parse: nvd: record has no id")
	}

	v := &model.Vulnerability{
		ID:    id,
		State: nvdState(rec.VulnStatus),
		// vulnStatus is kept verbatim as well. Since April 2026 most records
		// are marked "Deferred"/not scheduled and will never be enriched, so
		// "NVD has no score for this" and "NVD has not looked at this yet" are
		// different answers and a consumer has to be able to tell them apart.
		EnrichmentStatus: strings.TrimSpace(rec.VulnStatus),
		Tags:             model.DedupeStrings(rec.CVETags),
		Published:        model.ParseTime(rec.Published),
		Modified:         model.ParseTime(rec.LastModified),
		Source:           source,
		SourceRecordID:   id,
		Raw:              json.RawMessage(raw),
	}
	for _, d := range rec.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			v.Description = d.Value
			break
		}
	}

	for _, w := range rec.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				v.CWEs = append(v.CWEs, d.Value)
			}
		}
	}

	appendMetrics := func(list []nvdMetric, typ string) {
		for _, m := range list {
			if m.CVSSData.VectorString == "" {
				continue
			}
			sev := model.Severity{
				Type:     typ,
				Score:    m.CVSSData.BaseScore,
				Vector:   m.CVSSData.VectorString,
				Provider: m.Source,
				Source:   source,
			}
			switch {
			case m.CVSSData.BaseSeverity != "":
				sev.Rating = strings.ToUpper(m.CVSSData.BaseSeverity)
			case m.BaseSeverity != "":
				sev.Rating = strings.ToUpper(m.BaseSeverity)
			case sev.Score > 0:
				sev.Rating = ratingFor(typ, sev.Score)
			}
			v.Severities = append(v.Severities, sev)
		}
	}
	appendMetrics(rec.Metrics.CVSSMetricV40, "CVSS_V4_0")
	appendMetrics(rec.Metrics.CVSSMetricV31, "CVSS_V3_1")
	appendMetrics(rec.Metrics.CVSSMetricV30, "CVSS_V3_0")
	appendMetrics(rec.Metrics.CVSSMetricV2, "CVSS_V2")

	// SSVC arrives from CISA's ADP container by way of NVD since 2026-06-17.
	for _, s := range rec.Metrics.SSVCv203 {
		for _, o := range s.Options {
			if o.Exploitation == "" && o.Automatable == "" && o.TechnicalImpact == "" {
				continue
			}
			if v.SSVC == nil {
				// Spelled the way cve5.go spells it — collector, then the
				// organisation that made the decision — so that the same SSVC
				// statement reached through NVD and through the CVE List does
				// not look like two different provenances.
				v.SSVC = &model.SSVC{Version: s.Version, Timestamp: s.Timestamp, Source: source}
				if s.Source != "" {
					v.SSVC.Source = source + "/" + s.Source
				}
			}
			if o.Exploitation != "" {
				v.SSVC.Exploitation = strings.ToLower(o.Exploitation)
			}
			if o.Automatable != "" {
				v.SSVC.Automatable = strings.ToLower(o.Automatable)
			}
			if o.TechnicalImpact != "" {
				v.SSVC.TechnicalImpact = strings.ToLower(o.TechnicalImpact)
			}
		}
	}

	for _, r := range rec.References {
		if r.URL == "" {
			continue
		}
		v.References = append(v.References, model.Reference{URL: r.URL, Tags: r.Tags, Source: source})
	}

	v.Affected = append(v.Affected, cpeAffected(rec.Configurations, source)...)
	v.Affected = append(v.Affected, nvdCNAAffected(rec, source)...)

	v.CWEs = model.DedupeStrings(v.CWEs)
	return v, nil
}

// cpeAffected flattens a CPE applicability tree into affected entries while
// preserving whether the evidence came from a cross-component AND expression.
// A single-component inventory cannot prove "this application AND this OS";
// flattening that into an ordinary affected row creates a false positive.
// Conditional and unconditional evidence therefore use separate rows so a
// version range cannot inherit another range's stronger applicability status.
func cpeAffected(configs []cpeConfiguration, source string) []model.Affected {
	type key struct {
		vendor      string
		product     string
		conditional bool
	}
	var order []key
	cpesFor := map[key][]string{}
	rangesFor := map[key][]model.VersionRange{}

	for _, cfg := range configs {
		// A negated configuration or node asserts the opposite: those CPEs
		// are explicitly NOT vulnerable, so recording them as affected inverts
		// the claim.
		if cfg.Negate {
			continue
		}
		configAND := strings.EqualFold(strings.TrimSpace(cfg.Operator), "AND") && len(cfg.Nodes) > 1
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			nodeAND := strings.EqualFold(strings.TrimSpace(node.Operator), "AND") && len(node.CPEMatch) > 1
			conditional := configAND || nodeAND
			for _, m := range node.CPEMatch {
				if !m.Vulnerable || m.Criteria == "" {
					continue
				}
				vendor, product := cpeVendorProduct(m.Criteria)
				k := key{vendor: vendor, product: product, conditional: conditional}
				if _, seen := cpesFor[k]; !seen {
					order = append(order, k)
				}
				cpesFor[k] = append(cpesFor[k], m.Criteria)

				// The window keeps the criteria it came from. Every cpeMatch
				// of one vendor/product and one applicability class lands in the
				// same Ranges slice, so target_sw and AND evidence cannot leak to
				// a sibling range.
				vr := model.VersionRange{Type: "CPE", CPE: m.Criteria}
				switch {
				case m.VersionStartIncluding != "":
					vr.Introduced = m.VersionStartIncluding
				case m.VersionStartExcluding != "":
					// Exclusive lower bounds have no representation in the OSV
					// range vocabulary; mark it so the boundary is not silently
					// read as inclusive.
					vr.Introduced = m.VersionStartExcluding + " (exclusive)"
				}
				switch {
				case m.VersionEndExcluding != "":
					vr.Fixed = m.VersionEndExcluding
				case m.VersionEndIncluding != "":
					vr.LastAffected = m.VersionEndIncluding
				}
				if vr.Introduced != "" || vr.Fixed != "" || vr.LastAffected != "" {
					rangesFor[k] = append(rangesFor[k], vr)
				}
			}
		}
	}

	// Deterministic output: the canonical document is hashed to decide whether
	// anything changed, so map iteration order would make every re-ingest look
	// like a modification. Put the ordinary row before its conditional sibling.
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].vendor != order[j].vendor {
			return order[i].vendor < order[j].vendor
		}
		if order[i].product != order[j].product {
			return order[i].product < order[j].product
		}
		return !order[i].conditional && order[j].conditional
	})

	out := make([]model.Affected, 0, len(order))
	for _, k := range order {
		status := ""
		if k.conditional {
			status = model.StatusConditional
		}
		out = append(out, model.Affected{
			Vendor:  k.vendor,
			Product: k.product,
			CPEs:    model.DedupeStrings(cpesFor[k]),
			Ranges:  dedupeRanges(rangesFor[k]),
			Status:  status,
			Source:  source,
		})
	}
	return out
}

// nvdCNAAffected reads the vendor/product view NVD republishes from the CNA
// record. Records that were never CPE-analysed — the majority since the 2026
// enrichment policy change — carry product information only here.
func nvdCNAAffected(rec NVDCVE, source string) []model.Affected {
	var out []model.Affected
	for _, a := range rec.Affected {
		for _, d := range a.AffectedData {
			product := d.Product
			if product == "" {
				product = d.PackageName
			}
			if strings.EqualFold(product, "n/a") {
				product = ""
			}
			vendor := d.Vendor
			if strings.EqualFold(vendor, "n/a") {
				vendor = ""
			}
			if vendor == "" && product == "" {
				continue
			}
			af := model.Affected{Vendor: vendor, Product: product, Source: source}
			// The unaffected versions are kept as their own not_affected
			// entry, as cve5.go does for the same CNA data: a CNA that lists
			// them against defaultStatus "affected" is saying "everything
			// except these", and dropping them turns that into "everything".
			unaffected := model.Affected{
				Vendor: vendor, Product: product, Status: model.StatusNotAffected, Source: source,
			}
			for _, ver := range d.Versions {
				target := &af
				switch {
				case ver.Status == "" || strings.EqualFold(ver.Status, "affected"):
				case strings.EqualFold(ver.Status, "unaffected"):
					target = &unaffected
				default:
					continue
				}
				switch {
				case ver.LessThan != "":
					target.Ranges = append(target.Ranges, model.VersionRange{Introduced: ver.Version, Fixed: ver.LessThan})
				case ver.LessThanOrEqual != "":
					target.Ranges = append(target.Ranges, model.VersionRange{Introduced: ver.Version, LastAffected: ver.LessThanOrEqual})
				case ver.Version != "" && !strings.EqualFold(ver.Version, "n/a"):
					target.Versions = append(target.Versions, ver.Version)
				}
			}
			out = append(out, af)
			if len(unaffected.Ranges) > 0 || len(unaffected.Versions) > 0 {
				out = append(out, unaffected)
			}
		}
	}
	return out
}

func dedupeRanges(in []model.VersionRange) []model.VersionRange {
	if len(in) < 2 {
		return in
	}
	seen := map[model.VersionRange]struct{}{}
	out := make([]model.VersionRange, 0, len(in))
	for _, r := range in {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// ratingFor derives the qualitative band for a CVSS statement of the given
// canonical type. CVSS v2 has its own three-band table and no Critical, so it
// cannot share the v3/v4 mapping.
func ratingFor(typ string, score float64) string {
	if typ == "CVSS_V2" {
		return model.RatingFromScoreV2(score)
	}
	return model.RatingFromScore(score)
}

// idSuffix recovers the record identifier from a document the full decode has
// just rejected, so that the error names the record. A type mismatch deep in
// one member fails the whole Unmarshal, but a decode that asks for the
// identifier alone skips every other member, so the id is usually still
// readable. Only a syntactically broken document yields nothing, and then the
// error already says where in the bytes it broke.
//
// path is the dotted path to the identifier: "id" for NVD and OSV,
// "cveMetadata.cveId" for CVE 5.x.
func idSuffix(raw []byte, path string) string {
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return ""
	}
	for _, key := range strings.Split(path, ".") {
		obj, ok := node.(map[string]any)
		if !ok {
			return ""
		}
		node = obj[key]
	}
	id, _ := node.(string)
	if id = strings.TrimSpace(id); id == "" {
		return ""
	}
	// The identifier is untrusted input going into an error message, and the
	// message goes into a log line. A real identifier is a few dozen bytes;
	// a document whose "id" is a hundred kilobytes of whatever the publisher
	// put there would have all of it in the log, and one carrying a carriage
	// return or an escape sequence would rewrite the line around it.
	id = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, id)
	if runes := []rune(id); len(runes) > maxIDInError {
		id = string(runes[:maxIDInError]) + "…"
	}
	return " " + id
}

// maxIDInError bounds an identifier quoted in an error. The longest real
// ones — GHSA, PYSEC, distribution advisories — fit in twenty characters.
const maxIDInError = 64

// cpeVendorProduct pulls the vendor and product out of a CPE 2.3 URI.
// Format: cpe:2.3:part:vendor:product:version:...
//
// The split honours backslash escapes. A colon inside an attribute is written
// "\:" by the 2.3 binding, and a plain split on ':' read everything after it
// as the following attributes — vendor "foo\" and product "bar" for a vendor
// of "foo:bar". A backslash escapes whatever follows it, so "\\" is a literal
// backslash and does not escape the colon after it.
func cpeVendorProduct(cpe string) (string, string) {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(cpe); i++ {
		switch c := cpe[i]; {
		case c == '\\' && i+1 < len(cpe):
			cur.WriteByte(c)
			i++
			cur.WriteByte(cpe[i])
		case c == ':':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	if len(parts) < 5 {
		return "", ""
	}
	return parts[3], parts[4]
}

// nvdState maps NVD's vulnStatus onto the canonical record state. Only
// "Rejected" changes what the record IS; every other status describes how far
// NVD has got with enrichment and is preserved separately in EnrichmentStatus.
func nvdState(status string) string {
	if strings.EqualFold(strings.TrimSpace(status), "rejected") {
		return "REJECTED"
	}
	return "PUBLISHED"
}
