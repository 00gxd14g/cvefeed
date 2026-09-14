// Package model defines the canonical vulnerability representation that every
// collector normalises into. It is deliberately a superset of CVE Record Format
// 5.1 and the OSV schema so that no upstream field has to be discarded.
package model

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Severity carries one scoring statement about a vulnerability. A vulnerability
// routinely has several: the CNA's own score, CISA's ADP score, NVD's score and
// so on. We keep all of them and pick a primary at query time, because since the
// April 2026 NVD policy change no single provider scores every CVE.
type Severity struct {
	Type     string  `json:"type"`               // CVSS_V2 | CVSS_V3_0 | CVSS_V3_1 | CVSS_V4_0 | OTHER (SSVC is not a score; see Vulnerability.SSVC)
	Score    float64 `json:"score"`              // 0.0 - 10.0
	Vector   string  `json:"vector,omitempty"`   // CVSS:3.1/AV:N/...
	Rating   string  `json:"rating,omitempty"`   // NONE | LOW | MEDIUM | HIGH | CRITICAL
	Provider string  `json:"provider,omitempty"` // e.g. "cisa-adp", "redhat", "nvd@nist.gov"
	Source   string  `json:"source"`             // collector that produced this statement
}

// Reference is an external link attached to a vulnerability.
type Reference struct {
	URL    string   `json:"url"`
	Name   string   `json:"name,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	Source string   `json:"source"`
}

// VersionRange expresses an affected version window in OSV terms.
type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Type         string `json:"type,omitempty"` // SEMVER | ECOSYSTEM | GIT
	// CPE is the applicability criteria that carried this window, when the
	// source states ranges per CPE (NVD configurations, CVE 5.1
	// cpeApplicability). A window travels with the constraints of the CPE it
	// came from — target_sw, sw_edition and the rest — so the matcher can
	// keep those constraints attached to the range rather than to the whole
	// statement.
	CPE string `json:"cpe,omitempty"`
	// Limit is the OSV `limit` event: the point past which the publisher
	// stops describing the range, stated for GIT ranges whose walk would
	// otherwise continue down every descendant branch. It is informational.
	// It carries no claim that the flaw is fixed there, which is why it is not
	// Fixed, and the matcher does not read it. A limit-bounded window is still
	// bounded for matching: the parser copies the value into LastAffected as
	// well, because a window with only Introduced set is read as open-ended
	// and would report every later version affected. LastAffected is
	// inclusive where limit is exclusive, so the one version at the boundary
	// is over-claimed rather than every version beyond it.
	Limit string `json:"limit,omitempty"`
	// Repo is the repository a GIT range's commits belong to (OSV
	// ranges[].repo). A commit hash means nothing without it, so it travels
	// with the window it bounds.
	Repo string `json:"repo,omitempty"`
}

// The product-status vocabulary. It is CSAF's, because CSAF is the only upstream
// that defines one normatively and every other source maps onto it cleanly.
// Sources must go through NormalizeStatus rather than inventing a spelling: a
// scanner that treats "unaffected" and "not_affected" as different assertions
// reports patched software as vulnerable.
const (
	StatusAffected           = "affected"
	StatusNotAffected        = "not_affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"

	// StatusConditional is the one value here that no upstream publishes. It
	// marks applicability an upstream stated as a cross-component condition —
	// NVD's "this application AND that platform" — where the condition names a
	// component a package inventory does not describe. It is decided exactly
	// like under_investigation, and exists only so a report can say which of
	// the two a reader is looking at: "the vendor is still deciding" and "the
	// vendor decided, but on a question this inventory cannot answer" are
	// different sentences, and printing the first for the second is a lie
	// about who is uncertain.
	StatusConditional = "conditional"
)

// Statuses lists the canonical vocabulary in a fixed order.
//
// Anything that enumerates statuses reads it from here. A parser that emits one
// row per status used to carry its own hand-written list, so adding a value to
// the vocabulary dropped every row carrying it — silently, because a dropped
// affectedness statement looks exactly like a record that never made one.
func Statuses() []string {
	return []string{
		StatusAffected,
		StatusNotAffected,
		StatusFixed,
		StatusUnderInvestigation,
		StatusConditional,
	}
}

// NormalizeStatus maps an upstream product status onto the canonical
// vocabulary. An unrecognised value is returned empty rather than guessed at,
// because "we do not know what this vendor meant" and "this product is
// affected" are not the same claim.
func NormalizeStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "_"))) {
	case "affected", "known_affected", "vulnerable":
		return StatusAffected
	case "not_affected", "unaffected", "known_not_affected", "not_vulnerable":
		return StatusNotAffected
	case "fixed", "first_fixed", "patched", "resolved":
		return StatusFixed
	case "under_investigation", "investigating", "unknown":
		return StatusUnderInvestigation
	case "conditional":
		return StatusConditional
	default:
		return ""
	}
}

// Affected describes one impacted product.
type Affected struct {
	Vendor       string         `json:"vendor,omitempty"`
	Product      string         `json:"product,omitempty"`
	Ecosystem    string         `json:"ecosystem,omitempty"`
	PURL         string         `json:"purl,omitempty"`
	CPEs         []string       `json:"cpes,omitempty"`
	Versions     []string       `json:"versions,omitempty"`
	Ranges       []VersionRange `json:"ranges,omitempty"`
	DefaultState string         `json:"default_state,omitempty"`
	// Status is the per-product assertion a VEX-bearing source makes about this
	// package: affected, fixed, not_affected or under_investigation. It is the
	// whole point of collecting CSAF, so it is a first-class field rather than
	// something buried in the raw document.
	Status string `json:"status,omitempty"`
	Source string `json:"source"`
}

// SSVC holds CISA's stakeholder-specific vulnerability categorisation, which is
// the enrichment CISA publishes through its Authorized Data Publisher container.
type SSVC struct {
	Exploitation    string `json:"exploitation,omitempty"`     // none | poc | active
	Automatable     string `json:"automatable,omitempty"`      // yes | no
	TechnicalImpact string `json:"technical_impact,omitempty"` // partial | total
	Version         string `json:"version,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
	Source          string `json:"source"`
}

// KEV mirrors an entry of CISA's Known Exploited Vulnerabilities catalogue.
type KEV struct {
	CVEID             string     `json:"cve_id"`
	CatalogVersion    string     `json:"catalog_version,omitempty"`
	DateReleased      *time.Time `json:"date_released,omitempty"`
	CWEs              []string   `json:"cwes,omitempty"`
	RansomwareUse     string     `json:"ransomware_use,omitempty"` // Known | Unknown
	VendorProject     string     `json:"vendor_project,omitempty"`
	Product           string     `json:"product,omitempty"`
	VulnerabilityName string     `json:"vulnerability_name,omitempty"`
	ShortDescription  string     `json:"short_description,omitempty"`
	RequiredAction    string     `json:"required_action,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	DateAdded         *time.Time `json:"date_added,omitempty"`
	DueDate           *time.Time `json:"due_date,omitempty"`
	KnownRansomware   bool       `json:"known_ransomware"`
	Sources           []string   `json:"sources,omitempty"` // cisa_kev, eu_kev, ...
	Source            string     `json:"source"`
}

// EPSS is one daily exploit-prediction score. ModelVersion is carried because
// FIRST rescores the whole corpus on every model release, and a score is only
// comparable against others produced by the same model.
type EPSS struct {
	CVEID        string    `json:"cve_id"`
	Score        float64   `json:"score"`
	Percentile   float64   `json:"percentile"`
	ScoreDate    time.Time `json:"score_date"`
	ModelVersion string    `json:"model_version,omitempty"`
	Source       string    `json:"source"`
}

// Vulnerability is the canonical record. One row per real-world vulnerability,
// not one row per upstream identifier: GHSA/EUVD/GCVE identifiers for the same
// flaw collapse into a single record through the alias graph.
type Vulnerability struct {
	ID          string     `json:"id"` // canonical identifier
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	State       string     `json:"state,omitempty"` // PUBLISHED | REJECTED | DISPUTED | WITHDRAWN
	Published   *time.Time `json:"published,omitempty"`
	Modified    *time.Time `json:"modified,omitempty"`
	Withdrawn   *time.Time `json:"withdrawn,omitempty"`

	// Aliases are identifiers for the SAME flaw; they drive the alias graph and
	// therefore record identity. Related is deliberately separate: the OSV
	// schema defines it as "related but not equivalent", and feeding it into
	// the alias graph merges distinct vulnerabilities into one record.
	Aliases    []string    `json:"aliases,omitempty"`
	Related    []string    `json:"related,omitempty"`
	CWEs       []string    `json:"cwes,omitempty"`
	Severities []Severity  `json:"severities,omitempty"`
	References []Reference `json:"references,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
	SSVC       *SSVC       `json:"ssvc,omitempty"`

	AssignerShortName string `json:"assigner_short_name,omitempty"`

	// EnrichmentStatus is NVD's vulnStatus verbatim (Analyzed, Awaiting
	// Analysis, Deferred, Modified, Received, Rejected, Undergoing Analysis).
	// Since April 2026 most records are never scheduled for enrichment, so
	// "NVD has no score" and "NVD has not looked yet" are different answers and
	// have to be distinguishable.
	EnrichmentStatus string `json:"enrichment_status,omitempty"`
	// Tags carries upstream record tags such as "disputed" or
	// "unsupported-when-assigned".
	Tags []string `json:"tags,omitempty"`

	Source         string          `json:"source"`           // collector name
	SourceRecordID string          `json:"source_record_id"` // upstream primary key
	Raw            json.RawMessage `json:"-"`                // untouched upstream document
	FetchedAt      time.Time       `json:"fetched_at"`
}

var (
	cveRe  = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	ghsaRe = regexp.MustCompile(`(?i)^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	euvdRe = regexp.MustCompile(`(?i)^EUVD-\d{4}-\d+$`)
	gcveRe = regexp.MustCompile(`(?i)^GCVE-\d+-\d{4}-\d+$`)
)

// IsCVE reports whether id is a well-formed CVE identifier.
func IsCVE(id string) bool { return cveRe.MatchString(strings.TrimSpace(id)) }

// IsGHSA reports whether id is a well-formed GitHub Security Advisory identifier.
func IsGHSA(id string) bool { return ghsaRe.MatchString(strings.TrimSpace(id)) }

// IsEUVD reports whether id is a well-formed ENISA EUVD identifier.
func IsEUVD(id string) bool { return euvdRe.MatchString(strings.TrimSpace(id)) }

// IsGCVE reports whether id is a well-formed GCVE identifier.
func IsGCVE(id string) bool { return gcveRe.MatchString(strings.TrimSpace(id)) }

// NormalizeID canonicalises an identifier's spelling. Identifier namespaces in
// this domain are case-insensitive in practice but case-sensitive in storage,
// so every entry point funnels through here.
func NormalizeID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	upper := strings.ToUpper(id)
	switch {
	case cveRe.MatchString(id), euvdRe.MatchString(id), gcveRe.MatchString(id):
		return upper
	case ghsaRe.MatchString(id):
		// GHSA identifiers are lowercase after the prefix by specification.
		return "GHSA-" + strings.ToLower(strings.TrimPrefix(upper, "GHSA-"))
	}
	return id
}

// IdentifierRank orders identifier namespaces for canonical-ID selection. Lower
// wins. CVE is preferred because it is the identifier every downstream tool
// understands; GCVE-0-* is by definition a CVE restatement and never wins.
func IdentifierRank(id string) int {
	switch {
	case IsCVE(id):
		return 0
	case IsGHSA(id):
		return 1
	case IsEUVD(id):
		return 2
	case IsGCVE(id):
		return 3
	default:
		return 4
	}
}

// PickCanonicalID chooses the identifier a merged record should be filed under.
func PickCanonicalID(ids []string) string {
	best := ""
	bestRank := 1 << 30
	for _, raw := range ids {
		id := NormalizeID(raw)
		if id == "" {
			continue
		}
		r := IdentifierRank(id)
		if r < bestRank || (r == bestRank && id < best) {
			best, bestRank = id, r
		}
	}
	return best
}

// AllIdentifiers returns the record's own ID plus its aliases, normalised and
// de-duplicated. This is the input to the alias-graph resolution in the store.
func (v *Vulnerability) AllIdentifiers() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(v.Aliases)+1)
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		n := NormalizeID(id)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RatingFromScore maps a CVSS base score onto the qualitative band. Upstreams
// are inconsistent about supplying the band, so we derive it when it is absent.
func RatingFromScore(score float64) string {
	switch {
	case score <= 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// RatingFromScoreV2 maps a CVSS v2 base score onto its qualitative band. CVSS
// v2 defines three bands only — Low 0.0-3.9, Medium 4.0-6.9, High 7.0-10.0 —
// and has no Critical. Applying the v3 table to a v2 score labelled every
// 9.0+ v2 record CRITICAL, a band the metric never produced.
//
// A score that is absent or zero is reported as NONE for the same reason as
// in RatingFromScore: labelling a missing score LOW would fabricate a band.
func RatingFromScoreV2(score float64) string {
	switch {
	case score <= 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	default:
		return "HIGH"
	}
}

// CVSSTypeFromVector infers the severity type from a CVSS vector string.
func CVSSTypeFromVector(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return "CVSS_V4_0"
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "CVSS_V3_1"
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return "CVSS_V3_0"
	case vector != "" && strings.HasPrefix(vector, "AV:"):
		return "CVSS_V2"
	default:
		return "OTHER"
	}
}

// ParseTime accepts the several timestamp spellings found across upstreams and
// returns nil rather than an error for unparseable input, because a bad
// timestamp must never cost us an otherwise good vulnerability record.
func ParseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"Jan 2, 2006, 3:04:05 PM", // ENISA EUVD spelling
		"Jan 2, 2006",
		// No slash-separated layout. "01/02/2006" used to be here, and no
		// collector's upstream emits it: it is the US month/day order, which
		// reads "03/04/2026" as March 4th where half the world writes April
		// 3rd, and a date that parses to the wrong day is worse than one that
		// does not parse.
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// DedupeStrings returns a sorted, de-duplicated copy with empties removed.
func DedupeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
