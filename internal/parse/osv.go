package parse

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// OSV mirrors the OSV schema (https://ossf.github.io/osv-schema/). It is the
// lingua franca for GitHub advisories, Debian, Ubuntu, SUSE, Alpine, Rocky,
// PyPI, npm, Go and Rust data, so one parser covers a large share of sources.
type OSV struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	Related       []string `json:"related"`
	Upstream      []string `json:"upstream"`
	Modified      string   `json:"modified"`
	Published     string   `json:"published"`
	Withdrawn     string   `json:"withdrawn"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details"`
	Severity      []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Repo   string     `json:"repo"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
		Versions          []string        `json:"versions"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
		DatabaseSpecific  struct {
			// NVD-converted GIT records carry no affected[].package at all;
			// database_specific.cpe is the only product key they have.
			CPE  string   `json:"cpe"`
			CPEs []string `json:"cpes"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		CWEIDs   []string `json:"cwe_ids"`
		Severity string   `json:"severity"`
	} `json:"database_specific"`
}

// osvEvent is one entry of an OSV ranges[].events stream.
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// opens reports whether the event starts a window; the other three kinds
// close one.
func (e osvEvent) opens() bool { return e.Introduced != "" }

// OSVToModel converts one OSV document.
func OSVToModel(raw []byte, source string) (*model.Vulnerability, error) {
	var o OSV
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("parse: osv%s: %w", idSuffix(raw, "id"), err)
	}
	if strings.TrimSpace(o.ID) == "" {
		return nil, fmt.Errorf("parse: osv: record has no id")
	}

	v := &model.Vulnerability{
		ID:             model.NormalizeID(o.ID),
		Title:          o.Summary,
		Description:    o.Details,
		Published:      model.ParseTime(o.Published),
		Modified:       model.ParseTime(o.Modified),
		Withdrawn:      model.ParseTime(o.Withdrawn),
		CWEs:           o.DatabaseSpecific.CWEIDs,
		Source:         source,
		SourceRecordID: o.ID,
		Raw:            json.RawMessage(raw),
	}
	v.State = "PUBLISHED"
	if v.Withdrawn != nil {
		v.State = "WITHDRAWN"
	}

	// Only `aliases` and `upstream` assert identity. The OSV schema defines
	// `related` as "related but not equivalent" — a multi-CVE distro advisory
	// lists its siblings there — so feeding it into the alias graph collapses
	// genuinely distinct vulnerabilities into a single record. Keep it, but
	// keep it out of identity resolution.
	// `upstream` is a derivation edge, not an identity one: it says where this
	// record came from, not what it is. The hardened image producers — MinimOS,
	// Chainguard, CleanStart, Echo, BellSoft, TuxCare, Root — republish upstream
	// CVEs against their own package builds, which the research report names as
	// high volume and low novelty; MinimOS alone ships about 117k of them. Every
	// one of those rebuilds carries the CVE it was built against in `upstream`,
	// so reading it as identity folds the lot into that CVE. Observed live:
	// CVE-2018-1099 had absorbed 18,240 aliases, 15,902 of them MinimOS records.
	claimed := model.DedupeStrings(o.Aliases)
	related := model.DedupeStrings(append(append([]string{}, o.Related...), o.Upstream...))

	// `aliases` collapses records the same way when the record is an aggregate.
	// An Android bulletin, a CleanStart or Azure Linux advisory, a Bitnami
	// rollup — each names every CVE its package build fixed, and it names them
	// in `aliases` rather than `related`. Two distinct CVE ids cannot both be
	// the identity of one flaw, so a set holding more than one is a bundle, and
	// the non-CVE ids in it are bundled just as much: ASB-A-258759189 lists the
	// sibling bulletins ASB-A-258759192 and A-258759192 alongside the five CVEs
	// they each stand for.
	//
	// Two ids do sometimes name one flaw, when one was assigned in error and
	// rejected as its duplicate, and this rule refuses those merges too. That
	// is the right way to be wrong. An unmerged pair is two records where one
	// would do, and stays fixable; a wrong merge destroys both identities and
	// everything folded in afterwards. Observed before this rule: one CVE had
	// absorbed 10,088 aliases and 3,257 applicability statements, putting
	// log4j-core and lodash on the same record.
	// A record's own identifier is not an alias of itself. Publishers repeat it
	// in the list routinely, and letting it through puts a self-edge in a graph
	// whose entire job is to connect identifiers that differ — and adds to the
	// CVE count that decides, just below, whether this set is a bundle.
	claimed = removeSelf(claimed, v.ID)
	related = removeSelf(related, v.ID)

	if countCVEs(claimed) > 1 {
		related = model.DedupeStrings(append(related, claimed...))
		claimed = nil
	}
	v.Aliases = claimed
	v.Related = related

	band := qualitativeBand(o.DatabaseSpecific.Severity)
	for _, s := range o.Severity {
		if sev := osvSeverity(s.Type, s.Score, source); sev != nil {
			// A statement this code cannot score — every CVSS v4.0 vector —
			// would otherwise carry no band at all, and when it is the only
			// statement the record has it becomes the primary with an empty
			// rating: observed live as 3,494 GHSA records, all rated "".
			// The publisher's own band is the honest fallback: GitHub sets
			// database_specific.severity from the very v4.0 score it does
			// not export, so it is the band that vector has upstream. Only
			// the gap is filled; a band derived from a real number is kept.
			if sev.Score == 0 && sev.Rating == "" && band != "" {
				sev.Rating = band
			}
			v.Severities = append(v.Severities, *sev)
		}
	}
	if len(v.Severities) == 0 && band != "" {
		v.Severities = append(v.Severities, model.Severity{Type: "OTHER", Rating: band, Source: source})
	}

	for _, r := range o.References {
		if r.URL == "" {
			continue
		}
		var tags []string
		if r.Type != "" {
			tags = []string{strings.ToLower(r.Type)}
		}
		v.References = append(v.References, model.Reference{URL: r.URL, Tags: tags, Source: source})
	}

	for _, a := range o.Affected {
		af := model.Affected{
			Ecosystem: a.Package.Ecosystem,
			Product:   a.Package.Name,
			PURL:      a.Package.PURL,
			Versions:  a.Versions,
			CPEs:      model.DedupeStrings(append(append([]string{}, a.DatabaseSpecific.CPEs...), a.DatabaseSpecific.CPE)),
			Source:    source,
		}
		for _, rg := range a.Ranges {
			af.Ranges = append(af.Ranges, osvRanges(rg.Type, rg.Repo, rg.Events)...)
		}
		// A per-package severity has to stay attributable to its package.
		// Without that the provider key is empty for all of them and the merge
		// keeps only whichever package happened to be parsed last.
		provider := a.Package.Name
		for _, sv := range a.Severity {
			if sev := osvSeverity(sv.Type, sv.Score, source); sev != nil {
				sev.Provider = provider
				v.Severities = append(v.Severities, *sev)
			}
		}
		v.Affected = append(v.Affected, af)
	}

	v.CWEs = model.DedupeStrings(v.CWEs)
	return v, nil
}

// osvRanges turns an OSV event stream into closed version ranges.
//
// OSV events are an ordered stream, not independent facts: "introduced 0",
// "fixed 1.2.3", "introduced 2.0", "last_affected 2.5" describes two windows.
// Emitting one range per event loses the pairing entirely and turns
// "introduced: 0" — the overwhelmingly common case — into no version data at
// all, because a bare zero lower bound was being skipped.
//
// repo is the repository the commits of a GIT range belong to; it is kept on
// every window of the range because a commit hash means nothing without it.
func osvRanges(rangeType, repo string, events []osvEvent) []model.VersionRange {
	typ := strings.ToUpper(rangeType)
	var (
		out     []model.VersionRange
		current *model.VersionRange
		open    bool
	)
	flush := func() {
		if current != nil {
			out = append(out, *current)
			current = nil
		}
		open = false
	}
	for _, ev := range orderedEvents(events) {
		switch {
		case ev.Introduced != "":
			flush()
			current = &model.VersionRange{Type: typ, Repo: repo, Introduced: ev.Introduced}
			open = true
		case ev.Fixed != "":
			if !open {
				current = &model.VersionRange{Type: typ, Repo: repo}
			}
			current.Fixed = ev.Fixed
			flush()
		case ev.LastAffected != "":
			if !open {
				current = &model.VersionRange{Type: typ, Repo: repo}
			}
			current.LastAffected = ev.LastAffected
			flush()
		case ev.Limit != "":
			if !open {
				current = &model.VersionRange{Type: typ, Repo: repo}
			}
			// A limit says where the publisher stopped describing the range,
			// not that the flaw is fixed there, so it must not be presented
			// as Fixed: the matcher reports a Fixed bound as "the version the
			// fix landed in". It cannot be left out of the bounds either. A
			// window with only Introduced set is read as open-ended and
			// reports every later version affected, which for a GIT range
			// walked to a branch point is every commit on every branch since.
			// LastAffected keeps the window bounded and asserts no fix; it is
			// inclusive where limit is exclusive, so the boundary version
			// itself is over-claimed, which is the safe direction. The limit
			// is kept verbatim in its own field so the original claim stays
			// readable. See model.VersionRange.Limit.
			current.Limit = ev.Limit
			current.LastAffected = ev.Limit
			flush()
		}
	}
	flush()
	return out
}

// orderedEvents repairs the one ordering fault publishers actually commit.
//
// The schema requires an "introduced" event before the event that closes its
// window, and the pairing above depends on it. Some publishers write the pair
// the other way round — [{fixed}, {introduced}] — which paired reads as an
// open window preceded by a bare upper bound: two windows where one was
// meant, one of them open-ended. A stream that is exactly that pair, a
// closing event first and an opening one second, is swapped.
//
// Nothing longer is touched. An earlier version swapped any closing event
// that arrived while no window was open and was followed by an opening one,
// and that re-paired legitimate streams: a "limit" closing one window is
// followed by the "introduced" opening the next, and the swap moved the limit
// into the next window — [a, b, limit c, d, e] became {a→b}, {d, ≤c}, {fixed
// e}, where c and d no longer bound anything the publisher said. A closing
// event that stands alone is a bare bound, which is what the publisher wrote;
// a swapped one is a window nobody wrote. Only the two-event pair has a
// reading that is unambiguous.
func orderedEvents(events []osvEvent) []osvEvent {
	if len(events) != 2 || events[0].opens() || !events[1].opens() {
		return events
	}
	return []osvEvent{events[1], events[0]}
}

// osvSeverity turns an OSV severity entry into a canonical one. OSV carries the
// vector string in Score rather than a numeric value, so the base score has to
// be read back out of the vector where the type does not encode it.
//
// When the score cannot be derived — every CVSS v4.0 vector, because its
// scoring needs the official MacroVector table — the statement is kept for its
// vector but left explicitly unscored. Deriving a rating from a zero it does
// not have would publish "NONE" for a 9.8 vulnerability.
//
// A type that is not CVSS at all — {"type":"Ubuntu","score":"Medium"} is the
// common one — carries a qualitative band, not a vector. It goes into Rating,
// upper-cased to match the CVSS bands; putting it in Vector published
// "Medium" as a vector string and left the rating, the thing it actually was,
// empty.
func osvSeverity(typ, score, source string) *model.Severity {
	score = strings.TrimSpace(score)
	if score == "" {
		return nil
	}
	t := model.CVSSTypeFromVector(score)
	if t == "OTHER" {
		switch strings.ToUpper(typ) {
		case "CVSS_V4":
			t = "CVSS_V4_0"
		case "CVSS_V3":
			t = "CVSS_V3_1"
		case "CVSS_V2":
			t = "CVSS_V2"
		default:
			sev := &model.Severity{Type: "OTHER", Source: source, Provider: strings.TrimSpace(typ)}
			if n, err := strconv.ParseFloat(score, 64); err == nil {
				sev.Score = n
				sev.Rating = model.RatingFromScore(n)
			} else {
				sev.Rating = strings.ToUpper(score)
			}
			return sev
		}
	}
	sev := &model.Severity{Type: t, Vector: score, Source: source}
	// A computed 0.0 is a score, not a missing one: CVSS:3.1/.../C:N/I:N/A:N
	// scores 0.0 by the formula and its band is NONE. Only a vector the
	// calculator could not read is left unrated.
	if s, ok := cvssBaseScore(score); ok {
		sev.Score = s
		sev.Rating = ratingFor(t, s)
	}
	return sev
}

// qualitativeBand maps a publisher's qualitative severity onto the CVSS
// band vocabulary the rating filter and the stats endpoint speak. GitHub
// spells the middle band "moderate"; anything outside the vocabulary is
// dropped rather than published as a rating nothing can query for.
func qualitativeBand(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NONE":
		return "NONE"
	case "LOW":
		return "LOW"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "HIGH":
		return "HIGH"
	case "CRITICAL":
		return "CRITICAL"
	}
	return ""
}

// countCVEs reports how many distinct CVE identifiers a set names.
func countCVEs(ids []string) int {
	n := 0
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			n++
		}
	}
	return n
}

// removeSelf drops a record's own identifier from a list of other identifiers.
func removeSelf(ids []string, self string) []string {
	if self == "" {
		return ids
	}
	out := ids[:0]
	for _, id := range ids {
		if !strings.EqualFold(id, self) {
			out = append(out, id)
		}
	}
	return out
}
