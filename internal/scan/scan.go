// Package scan turns an inventory of installed software into a prioritised
// list of vulnerabilities that apply to it.
//
// It is the top of the stack and owns none of the hard parts: identity and
// version reasoning live in internal/match, ordering in internal/version,
// inventory parsing in internal/inventory, and candidate retrieval in
// internal/store. What is left here is the orchestration, and one editorial
// decision — what a caller is shown by default.
//
// That decision is the whole product. Of the 348,339 applicability statements
// in a fully loaded corpus, the plurality declare no ordering scheme and a
// further 52,770 carry commit hashes where a version belongs, so a scan
// produces far more questions than answers. Reporting the questions as answers
// is how a scanner becomes something operators learn to ignore. The default is
// therefore to report only what was proven, and to keep everything else in a
// separate channel the caller has to ask for.
package scan

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/00gxd14g/cvefeed/internal/match"
	"github.com/00gxd14g/cvefeed/internal/store"
)

// Finding is one vulnerability that applies to one installed component.
type Finding struct {
	Component     match.Component   `json:"component"`
	Vulnerability store.VulnSummary `json:"vulnerability"`
	Evidence      match.Evidence    `json:"evidence"`
	Statement     Statement         `json:"statement"`
	// RetiredBy is set only on a suppressed finding: the negative statement
	// that outweighed Statement. It is kept as a statement rather than only as
	// a sentence in the reason, so a report can say which vendor's assertion
	// retired which vulnerability without parsing prose.
	RetiredBy *Statement `json:"retired_by,omitempty"`
}

// Statement records which stored applicability claim produced a finding, so an
// operator disputing it can go and read the original.
type Statement struct {
	Source    string `json:"source"`
	Vendor    string `json:"vendor,omitempty"`
	Product   string `json:"product,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Status    string `json:"status,omitempty"`
}

// DefaultMinConfidence is the floor a caller gets when they express no
// preference, and it is deliberately not the weakest one. Every entry point
// must use it rather than its own literal, so the command line and the HTTP API
// cannot drift into answering the same question differently: on this project's
// own fixture the difference between this floor and `possible` is 65 findings
// against 321, the extra 256 resting on nothing stronger than a shared product
// name.
const DefaultMinConfidence = match.Probable

// Options tunes what a scan reports.
type Options struct {
	// MinConfidence drops findings weaker than this level. Empty means
	// DefaultMinConfidence.
	MinConfidence match.Confidence
	// IncludeUndecidable adds the statements that could not be decided at all.
	// They are not findings and are never counted as such, but an operator
	// auditing coverage needs to see what the corpus could not answer.
	IncludeUndecidable bool
}

// Report is the result of one scan.
type Report struct {
	ScannedAt   time.Time `json:"scanned_at"`
	Components  int       `json:"components"`
	Findings    []Finding `json:"findings"`
	Undecidable []Finding `json:"undecidable,omitempty"`
	// Suppressed lists the findings a vendor's negative statement retired: a
	// Match from one source about a vulnerability that a not_affected or fixed
	// statement from another covers for the same component. They are not
	// findings, but they do not vanish either, because an operator who sees a
	// CVE in one scanner's report and not in this one needs to be shown the
	// statement that made the difference.
	Suppressed []Finding `json:"suppressed,omitempty"`
	// Truncated names the components whose candidate statements hit the
	// store's per-key limit, so some of what the corpus says about them was
	// never examined. A bare name like "linux" or "core" can carry tens of
	// thousands of statements; the ones that were not read cannot produce a
	// finding, and a report that stayed silent about that would let "nothing
	// found" pass for "nothing there".
	Truncated []string `json:"truncated,omitempty"`
	// Counts summarises the findings by confidence so a caller can see at a
	// glance how much of the answer rests on weak identity.
	Counts map[match.Confidence]int `json:"counts"`
	// Notice carries the upstream attribution the corpus licences require.
	Notice string `json:"notice"`
}

// Scanner evaluates inventories against the corpus.
type Scanner struct {
	Store *store.Store
}

// Scan tests every component against every applicability statement that could
// describe it.
func (s *Scanner) Scan(ctx context.Context, components []match.Component, opt Options) (*Report, error) {
	report := &Report{
		ScannedAt:  time.Now().UTC(),
		Components: len(components),
		Findings:   []Finding{},
		Counts:     map[match.Confidence]int{},
		Notice:     store.NVDNotice,
	}
	if len(components) == 0 {
		return report, nil
	}

	queries := make([]store.CandidateQuery, len(components))
	for i, c := range components {
		queries[i] = store.CandidateQuery{
			PURL:      c.PURL,
			Name:      c.Name,
			Vendor:    c.Vendor,
			Ecosystem: c.Ecosystem,
		}
	}
	found, err := s.Store.FindAffectedCandidates(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("scan: candidates: %w", err)
	}
	candidates := found.Statements
	for i, c := range components {
		if found.Truncated[i] {
			report.Truncated = append(report.Truncated, componentLabel(c))
		}
	}

	minimum := opt.MinConfidence
	if minimum == "" {
		minimum = DefaultMinConfidence
	}

	var (
		matched     []Finding
		undecided   []Finding
		suppressed  []Finding
		wantedVulns = map[string]struct{}{}
	)
	for i, c := range components {
		v := evaluateComponent(c, candidates[i], minimum, opt.IncludeUndecidable)
		matched = append(matched, v.matched...)
		undecided = append(undecided, v.undecided...)
		suppressed = append(suppressed, v.suppressed...)
	}
	for _, list := range [][]Finding{matched, undecided, suppressed} {
		for _, f := range list {
			wantedVulns[f.Vulnerability.ID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(wantedVulns))
	for id := range wantedVulns {
		ids = append(ids, id)
	}
	summaries, err := s.Store.VulnSummaries(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("scan: summaries: %w", err)
	}
	for _, list := range [][]Finding{matched, undecided, suppressed} {
		for i := range list {
			if vs, ok := summaries[list[i].Vulnerability.ID]; ok {
				list[i].Vulnerability = vs
			}
		}
	}

	sortFindings(matched)
	sortFindings(undecided)
	sortFindings(suppressed)
	for _, f := range matched {
		report.Counts[f.Evidence.Confidence]++
	}
	report.Findings = matched
	report.Undecidable = undecided
	report.Suppressed = suppressed
	return report, nil
}

// verdicts is what one component's candidate statements amounted to.
type verdicts struct {
	matched, undecided, suppressed []Finding
}

// evaluateComponent tests one component against every statement that could
// describe it and reduces the answers to one per vulnerability.
//
// One vulnerability can be described by several statements about the same
// component — a CVE List entry and an OSV entry for one package. The strongest
// positive evidence wins; reporting both would inflate the count and bury the
// reason. A negative statement outranks a positive one: a CSAF
// known_not_affected or fixed entry is the vendor saying they looked at this
// vulnerability on this product and it does not apply to this build, and that
// is exactly the VEX assertion the format exists to carry. Keeping the Match
// from another source beside it would report a vulnerability the vendor has
// retired, which is the reading of VEX that makes collecting it pointless.
//
// But only when the negative is at least as well founded as the positive it
// retires. Both are graded on the same scale — identity strength and version
// strength combined — and a negative that matched a purl-identified component
// on nothing but a shared product name is not the vendor speaking about this
// component; it is a row about some product also called "marked". Letting it
// silence a confirmed purl match turned every vendor's habit of naming
// products loosely into a blanket exemption. So the strongest negative about
// a vulnerability vetoes the best positive when its confidence is at least
// the positive's; a weaker one is recorded on the finding's reason and the
// finding stands.
//
// The retired finding is kept on the suppressed list, with the statement that
// retired it, so the decision can be audited rather than merely trusted. The
// undecidable statements about the same vulnerability are retired with it:
// they were questions, and the vendor answered.
func evaluateComponent(c match.Component, candidates []store.AffectedStatement, minimum match.Confidence, includeUndecidable bool) verdicts {
	best := map[string]Finding{}
	var undecided []Finding
	vetoed := map[string]Finding{}
	for _, st := range candidates {
		result, evidence := match.Evaluate(c, toAffected(st))
		f := Finding{
			Component: c,
			Evidence:  evidence,
			Statement: Statement{
				Source: st.Source, Vendor: st.Vendor, Product: st.Product,
				Ecosystem: st.Ecosystem, PURL: st.PURL, Status: st.Status,
			},
			Vulnerability: store.VulnSummary{ID: st.VulnID},
		}
		switch result {
		case match.Match:
			if !atLeast(evidence.Confidence, minimum) {
				continue
			}
			if prev, ok := best[st.VulnID]; !ok || stronger(evidence.Confidence, prev.Evidence.Confidence) {
				best[st.VulnID] = f
			}
		case match.Undecidable:
			if includeUndecidable {
				undecided = append(undecided, f)
			}
		case match.Suppressed:
			// The strongest negative is the one weighed against the positive,
			// for the same reason the strongest positive is the one reported.
			if prev, ok := vetoed[st.VulnID]; !ok || stronger(evidence.Confidence, prev.Evidence.Confidence) {
				vetoed[st.VulnID] = f
			}
		}
	}

	var out verdicts
	for id, f := range best {
		if veto, ok := vetoed[id]; ok {
			if atLeast(veto.Evidence.Confidence, f.Evidence.Confidence) {
				retiredBy := veto.Statement
				f.RetiredBy = &retiredBy
				f.Evidence.Reason = "suppressed by a " + string(veto.Evidence.Confidence) + " negative statement from " + veto.Statement.Source +
					" (" + veto.Evidence.Reason + "); the retired finding read: " + f.Evidence.Reason
				out.suppressed = append(out.suppressed, f)
				continue
			}
			f.Evidence.Reason += "; note: a " + string(veto.Evidence.Confidence) + " negative statement from " + veto.Statement.Source +
				" was not taken over this " + string(f.Evidence.Confidence) + " finding, because it rests on weaker evidence (" +
				veto.Evidence.Reason + ")"
		}
		out.matched = append(out.matched, f)
	}
	for _, f := range undecided {
		if _, ok := vetoed[f.Vulnerability.ID]; ok {
			continue
		}
		out.undecided = append(out.undecided, f)
	}
	return out
}

func toAffected(st store.AffectedStatement) match.Affected {
	return match.Affected{
		VulnID:    st.VulnID,
		Vendor:    st.Vendor,
		Product:   st.Product,
		Ecosystem: st.Ecosystem,
		PURL:      st.PURL,
		CPEs:      st.CPEs,
		Versions:  st.Versions,
		Ranges:    st.Ranges,
		// DefaultState is what decides whether absence from Versions[] proves
		// safety or proves the opposite; without it the matcher has to guess
		// from the source.
		DefaultState: st.DefaultState,
		Status:       st.Status,
		Source:       st.Source,
	}
}

// confidenceRank orders the levels, strongest first.
func confidenceRank(c match.Confidence) int {
	switch c {
	case match.Confirmed:
		return 0
	case match.Probable:
		return 1
	case match.Possible:
		return 2
	default:
		return 3
	}
}

func stronger(a, b match.Confidence) bool { return confidenceRank(a) < confidenceRank(b) }
func atLeast(got, min match.Confidence) bool {
	return confidenceRank(got) <= confidenceRank(min)
}

// sortFindings orders by what an operator has to act on first: confirmed
// in-the-wild exploitation, then the probability that exploitation is coming,
// then severity. Alphabetical order by identifier is the tie-break so two runs
// over an unchanged system produce an identical report.
func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Vulnerability.InKEV != b.Vulnerability.InKEV {
			return a.Vulnerability.InKEV
		}
		if ra, rb := confidenceRank(a.Evidence.Confidence), confidenceRank(b.Evidence.Confidence); ra != rb {
			return ra < rb
		}
		if a.Vulnerability.EPSSScore != b.Vulnerability.EPSSScore {
			return a.Vulnerability.EPSSScore > b.Vulnerability.EPSSScore
		}
		if a.Vulnerability.Score != b.Vulnerability.Score {
			return a.Vulnerability.Score > b.Vulnerability.Score
		}
		if a.Vulnerability.ID != b.Vulnerability.ID {
			return a.Vulnerability.ID < b.Vulnerability.ID
		}
		return a.Component.Name < b.Component.Name
	})
}

// componentLabel is how a component is named in the report's truncation list:
// the name, and the version when there is one, which is enough to find it in
// the inventory again.
func componentLabel(c match.Component) string {
	if c.Version != "" {
		return c.Name + " " + c.Version
	}
	return c.Name
}
