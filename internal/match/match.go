// Package match decides whether one installed component is affected by one
// stored applicability statement.
//
// Most of the corpus cannot answer that question. Of 348,339 stored rows,
// 127,515 declare range type CUSTOM, which is the CNA saying that no ordering
// scheme applies, and 52,770 carry commit hashes where a version belongs.
// Comparing those anyway yields an answer that is confident and meaningless,
// and a scanner that cries wolf is worse than no scanner at all. So a test has
// three outcomes rather than two, and Undecidable is never quietly folded into
// either of the others.
//
// A decision is two independent tests that must both succeed: identity, which
// asks whether the row is even about this component, and version, which asks
// whether the component's version falls inside what the row claims. Confidence
// is a function of both and never of either alone, because an exact purl match
// says nothing about whether the version comparison was possible, and a clean
// version comparison says nothing about whether the two parties meant the same
// package.
package match

import (
	"sort"
	"strconv"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/version"
)

// Component is one installed piece of software under test.
//
// Every field beyond Name is optional and an absent one stays empty rather than
// being guessed at, because identity is graded by the strength of the field
// that matched: inventing an ecosystem or a vendor promotes a guess into a
// confident finding.
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
	CPE       string `json:"cpe,omitempty"`
	// Origin is where the inventory found the component. When it holds a
	// package URL it is used as a second identity: dpkg, rpm and apk all ship
	// binary packages built from a differently named source package, and distro
	// advisories are filed against the source, so an installed libssl3 has to
	// be tested as openssl too or every openssl advisory is missed.
	Origin string `json:"origin,omitempty"`
}

// Confidence is what the report tells an operator about one finding.
type Confidence string

const (
	// Confirmed: the identifier matched exactly and the version comparison used
	// the ordering the ecosystem itself defines. If you disagree with a
	// confirmed finding, the data is wrong, not the scanner.
	Confirmed Confidence = "confirmed"
	// Probable: the identifier matched well and the comparison is sound, but it
	// used either a weaker identity or an ordering that was inferred rather
	// than declared.
	Probable Confidence = "probable"
	// Possible: something matched, but at least one link in the chain is a
	// name, an assumption or an unproven constraint. Read the evidence before
	// acting.
	Possible Confidence = "possible"
)

// Evidence explains one decision well enough for a human to audit it.
type Evidence struct {
	MatchedOn  string         `json:"matched_on"`
	Confidence Confidence     `json:"confidence"`
	Scheme     version.Scheme `json:"scheme"`
	Reason     string         `json:"reason"`
}

// Affected is one stored applicability statement.
type Affected struct {
	VulnID    string
	Vendor    string
	Product   string
	Ecosystem string
	PURL      string
	CPEs      []string
	Versions  []string
	Ranges    []model.VersionRange
	// DefaultState is what the source says about every version the statement
	// does not name: CVE-5's defaultStatus. It decides what absence from
	// Versions[] means, and the two readings are opposites. Under "unaffected"
	// the list is closed and an unlisted version is safe; under "affected" the
	// list is the CNA's examples and an unlisted version is affected too.
	// Empty means the source stated no default, and the source's habits decide.
	DefaultState string
	Status       string
	Source       string
}

// Result is the outcome of testing one component against one statement.
type Result int

const (
	// NoMatch: the statement is not about this component, or its version is
	// provably outside what the statement claims.
	NoMatch Result = iota
	// Match: the statement applies. Evidence.Confidence grades how firmly.
	Match
	// Undecidable: the statement may or may not apply and the data cannot
	// settle it. This is a distinct answer, not a soft no and not a soft yes;
	// collapsing it into either one is how a scanner misrepresents its own
	// coverage.
	Undecidable
	// Suppressed: the statement is a negative assertion (not_affected or fixed)
	// that covers this build. It is kept apart from NoMatch because it carries
	// information NoMatch does not: a vendor has looked at this vulnerability on
	// this product and said no. That answer outranks a positive from another
	// source about the same vulnerability, which a plain "this row is not about
	// you" never could.
	Suppressed
)

// String names the result the way the tests and the reports spell it, so a
// failure message or a log line says "Suppressed" rather than "3".
func (r Result) String() string {
	switch r {
	case NoMatch:
		return "NoMatch"
	case Match:
		return "Match"
	case Undecidable:
		return "Undecidable"
	case Suppressed:
		return "Suppressed"
	}
	return "Result(" + strconv.Itoa(int(r)) + ")"
}

// Evaluate decides whether c is affected by a.
func Evaluate(c Component, a Affected) (Result, Evidence) {
	id := identify(c, a)
	if id.grade == idNone {
		return NoMatch, Evidence{Reason: id.reason}
	}

	// A component with no version can never produce a Match, at any confidence.
	// One version-less SBOM entry named "openssl" otherwise matches every
	// OpenSSL advisory ever published, which is the most common way
	// SBOM-driven scanners produce garbage.
	if !statedVersion(c.Version) {
		return Undecidable, Evidence{
			MatchedOn: id.channel,
			Reason: "no_component_version: " + id.reason +
				", but the inventory recorded " + describeMissingVersion(c.Version) +
				", and a statement that no version can be tested against matches every version",
		}
	}

	// Status "fixed" and VersionRange.Fixed share a word and mean unrelated
	// things: the first asserts that these product builds carry the fix, the
	// second is an exclusive upper bound on an affected interval. They are kept
	// apart by name here because conflating them inverts the verdict.
	status := normalizeStatus(a.Status)
	vt := versionTest(c, a, id)
	if status == model.StatusUnderInvestigation || status == model.StatusConditional {
		if vt.verdict == vNotInRange {
			return NoMatch, Evidence{
				MatchedOn: id.channel, Scheme: vt.scheme,
				Reason: joinParts(undecidedLabel(status)+" statement does not cover this build", vt.reason, id.reason),
			}
		}
		if status == model.StatusConditional {
			// Not "the source reports under_investigation": the source
			// reported an applicability condition, and it is this inventory
			// that cannot answer it. Say which.
			return Undecidable, Evidence{
				MatchedOn: id.channel,
				Reason: "conditional_applicability: " + id.reason +
					", and " + sourceLabel(a) + " states it only applies in combination with a further" +
					" component that a package inventory does not describe, so the condition can be" +
					" neither confirmed nor ruled out here",
			}
		}
		return Undecidable, Evidence{
			MatchedOn: id.channel,
			Reason: "status_under_investigation: " + id.reason +
				", and " + sourceLabel(a) + " reports status " + quote(a.Status) +
				", which neither affirms nor denies that this component is affected",
		}
	}

	ev := Evidence{MatchedOn: id.channel, Scheme: vt.scheme}

	if status == model.StatusNotAffected || status == model.StatusFixed {
		switch vt.verdict {
		case vInRange:
			// The negative statement covers this build. That is a first-class
			// result, not an absence of one: "we checked, the vendor says you
			// are not affected, here is the statement".
			//
			// It is graded exactly as a Match would be, because a negative is
			// weighed against positives about the same vulnerability and the
			// two have to be measured on one scale. A CSAF row that names
			// only a vendor and a product, matched on the bare name, is not
			// the vendor saying "not you" to a component identified by an
			// exact purl; ungraded, it read as if it were, and one weak row
			// silenced a confirmed finding.
			level, caps, demotions := confidenceFor(id, vt)
			ev.Confidence = level
			ev.Reason = joinParts("suppressed: "+sourceLabel(a)+" asserts "+string(status)+" for "+productLabel(a)+
				", and that assertion covers the installed "+c.Version, vt.reason, id.reason,
				"version evidence: "+vt.grade.String(), capText(caps), demotionText(demotions), noteText(vt.notes))
			return Suppressed, ev
		case vNotInRange:
			ev.Reason = joinParts("the "+string(status)+" assertion by "+sourceLabel(a)+" does not cover the installed "+c.Version+
				", so it carries no information about this component", vt.reason, id.reason)
			return NoMatch, ev
		default:
			ev.Reason = joinParts(vt.review+": "+vt.reason, id.reason, noteText(vt.notes))
			return Undecidable, ev
		}
	}

	switch vt.verdict {
	case vInRange:
		// A distribution package matched on nothing but its name against an
		// upstream statement that names no ecosystem. The installed version
		// is a distribution build: 3.5.5-1ubuntu3.5 says which upstream
		// release it started from and nothing about the fixes backported
		// since, and the name itself is shared across ecosystems (the Debian
		// package "bolt" is a Thunderbolt daemon, the product "bolt" a CMS).
		// Every positive this pair produced on a real host was one or the
		// other, so it is a question for the distribution's own advisories,
		// which match on ecosystem and name, not a finding. A version
		// outside the range is still a clean NoMatch: that answer needs no
		// backport knowledge.
		if id.grade == idWeak && distroFamilies[id.componentFamily] {
			ev.Reason = "distro_package_upstream_statement: " + joinParts(vt.reason, id.reason) +
				", but the component is a " + osvEcosystemName(id.componentFamily) + " package build " + quote(c.Version) +
				" whose version does not say which upstream fixes the distribution backported, and the name alone" +
				" does not say the two are the same software; the distribution's own advisories decide this"
			return Undecidable, ev
		}
		level, caps, demotions := confidenceFor(id, vt)
		// A distribution tracker's open-ended claim. Ubuntu and Debian export
		// "needs-triage", "needed", "pending", "deferred" and "ignored" alike
		// as introduced 0 with no upper bound, and the triage state itself is
		// not in the record: the same shape covers a package the distribution
		// has confirmed and one it has not looked at yet, and the tracker's
		// web view can already say not-affected while the export still says
		// this. Confirmed is reserved for the claim that can be checked from
		// the outside: the distribution released a fix and this build predates
		// it. The open claim is still reported, one level down.
		if level == Confirmed && distroFamilies[id.rowFamily] && openEndedClaim(a) {
			level = Probable
			caps = append(caps, "the "+osvEcosystemName(id.rowFamily)+" tracker lists the package as affected with no fixed version, a shape it also uses for packages it has not triaged")
		}
		ev.Confidence = level
		ev.Reason = joinParts(vt.reason, id.reason,
			"version evidence: "+vt.grade.String(), capText(caps), demotionText(demotions), noteText(vt.notes))
		return Match, ev
	case vNotInRange:
		ev.Reason = joinParts(vt.reason, id.reason, noteText(vt.notes))
		return NoMatch, ev
	default:
		ev.Reason = joinParts(vt.review+": "+vt.reason, id.reason, noteText(vt.notes))
		return Undecidable, ev
	}
}

// openEndedClaim reports whether every range on the statement is bounded
// below only: no fixed version and no last affected version anywhere. Such a
// statement says "affected, and no fix" and nothing about how that was
// established.
func openEndedClaim(a Affected) bool {
	if len(a.Ranges) == 0 {
		return false
	}
	for _, r := range a.Ranges {
		if strings.TrimSpace(r.Fixed) != "" || strings.TrimSpace(r.LastAffected) != "" {
			return false
		}
	}
	return true
}

// statedVersion reports whether the inventory actually gave a version.
//
// The trap is that a producer who does not know one rarely leaves the field
// empty: SBOM tools write "unknown", "n/a", "NOASSERTION" or "*", and those
// arrive here as ordinary strings that compare like versions and match every
// unbounded window in the corpus. Testing only for the empty string implements
// the letter of the version-less rule and none of its purpose.
//
// "0" is deliberately not in the set. It is a sentinel in a range bound, where
// it spells the beginning of time, but a component version is an installed
// build and packages genuinely versioned 0 exist; refusing them would drop real
// findings to guard against a spelling that never occurs on this side.
func statedVersion(v string) bool {
	switch version.ClassifySentinel(v) {
	case version.SentinelEmpty, version.SentinelAll, version.SentinelUnknown:
		return false
	}
	// SPDX spells a declined field NOASSERTION, which no sentinel table outside
	// that format has a reason to know about.
	return !strings.EqualFold(strings.TrimSpace(v), "NOASSERTION")
}

// describeMissingVersion says which spelling of "no version" was found, since
// an empty field and the word "unknown" send a reviewer to different places.
func describeMissingVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "no version"
	}
	return "the placeholder " + quote(strings.TrimSpace(v)) + " where a version belongs"
}

// normalizeStatus folds the several spellings the collectors emit onto the
// canonical vocabulary. osv.go and nvd.go emit no status at all, cve5.go emits
// "unaffected" and eu_sources.go emits "not_affected" for the same assertion.
func normalizeStatus(raw string) string {
	if strings.TrimSpace(raw) == "" {
		// An entry in an affected[] array is an affectedness claim by
		// construction; that is what the array is.
		return model.StatusAffected
	}
	if s := model.NormalizeStatus(raw); s != "" {
		return s
	}
	// A vocabulary nobody recognises is a request for a human to look, never an
	// assertion that the component is affected.
	return model.StatusUnderInvestigation
}

// confidenceFor combines the identity grade and the version grade.
//
// The two are separate axes and the combination is a floor, not a sum: an exact
// purl with a comparison nobody could make is not a confirmed finding, and a
// flawless dpkg comparison against a product matched by bare name is not one
// either.
func confidenceFor(id identity, vt elementResult) (Confidence, []string, []string) {
	level := Possible
	switch {
	case id.grade == idExact && vt.grade == vgOrdered:
		level = Confirmed
	case id.grade == idExact && vt.grade == vgGeneric,
		id.grade == idStrong && vt.grade == vgOrdered:
		// A GENERIC decision is only ever issued when the numeric prefixes
		// differ, which every plausible ordering scheme agrees on. Dropping the
		// 127,515 CUSTOM rows into the bottom tier would train operators to
		// ignore the bottom tier, which defeats having tiers at all.
		level = Probable
	}

	var caps []string
	if id.grade == idWeak {
		caps = append(caps, "identity is a bare product name")
	}
	// The conditions the identity test could not prove and the conditions
	// attached to the evidence that decided the version test are one set here.
	// They are gathered separately because they come from different places: a
	// row lists several vulnerable configurations, and the one that supplies the
	// matching version is often not the one that establishes identity. Grading
	// the finding on identity's conditions alone lets an unconstrained
	// configuration answer for a constrained one.
	for _, u := range mergeUnproven(id.unproven, vt.unproven) {
		caps = append(caps, "unproven "+u)
	}
	switch vt.grade {
	case vgUnbounded:
		caps = append(caps, "the statement bounds nothing and claims every version")
	case vgLiteral:
		caps = append(caps, "byte equality only, because no ordering scheme applies to these operands")
	case vgPattern:
		caps = append(caps, "the configuration names a version pattern rather than a version, so only the pattern's shape was matched")
	}
	if len(caps) > 0 {
		level = Possible
	}

	// A demotion lowers one level rather than capping, because it says the
	// answer is weaker than it looks, not that a link in the chain is missing.
	// At possible there is nowhere further to fall, so it becomes a caveat.
	var demotions []string
	if vt.heuristic {
		demotions = append(demotions, "the ordering was reached by convention rather than by the scheme's own rules")
	}
	if vt.epochElided {
		demotions = append(demotions, "only one side stated a package epoch, so both were compared without one and the discarded epoch could have moved the version across the bound")
	}
	for range demotions {
		switch level {
		case Confirmed:
			level = Probable
		case Probable:
			level = Possible
		}
	}
	return level, caps, demotions
}

// mergeUnproven unions two condition sets into a stable, deduplicated order. A
// condition named twice is one question for the operator, not two.
func mergeUnproven(sets ...[]string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, set := range sets {
		for _, u := range set {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

func demotionText(demotions []string) string {
	if len(demotions) == 0 {
		return ""
	}
	return "demoted: " + strings.Join(demotions, "; ")
}

func capText(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	return "capped at possible: " + strings.Join(caps, "; ")
}

func noteText(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return "notes: " + strings.Join(notes, ", ")
}

func joinParts(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

func sourceLabel(a Affected) string {
	if s := strings.TrimSpace(a.Source); s != "" {
		return s
	}
	return "the statement"
}

func quote(s string) string { return "\"" + s + "\"" }

// undecidedLabel names the undecided status in prose, so a NoMatch explanation
// says which kind of statement was found not to cover the installed build.
func undecidedLabel(status string) string {
	if status == model.StatusConditional {
		return "the conditional applicability"
	}
	return "the under_investigation"
}
