package match

import (
	"fmt"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/model"
	"github.com/00gxd14g/cvefeed/internal/version"
)

// exclusiveMarker is how internal/parse/nvd.go writes NVD's
// versionStartExcluding: the OSV range vocabulary has no exclusive lower bound,
// so the words are appended to the bound itself. Comparing the marked string as
// if it were a version puts every component below the bound and reports nothing.
const exclusiveMarker = "(exclusive)"

// versionVerdict is what one window or version list says about the component.
type versionVerdict int

const (
	vNotInRange versionVerdict = iota
	vInRange
	vUndecided
)

// versionGrade records what the comparison actually proved. It is the second
// axis of confidence; ordering matters, because the union of several windows
// keeps the strongest positive.
type versionGrade int

const (
	vgUndecidable versionGrade = iota
	vgUnbounded
	// vgPattern: a wildcarded CPE version (2.*) admitted the installed version.
	// It sits below literal because a glob says even less than byte equality:
	// "2.*" admits 2.1 without stating that 2.1 was ever examined.
	vgPattern
	vgLiteral
	vgGeneric
	vgOrdered
)

func (g versionGrade) String() string {
	switch g {
	case vgOrdered:
		return "ordered"
	case vgGeneric:
		return "generic"
	case vgLiteral:
		return "literal"
	case vgPattern:
		return "pattern"
	case vgUnbounded:
		return "unbounded"
	}
	return "undecidable"
}

// elementResult is the outcome of one window, one version list, or the union
// of them all.
type elementResult struct {
	verdict versionVerdict
	grade   versionGrade
	scheme  version.Scheme
	// heuristic records that the deciding comparison was reached by convention
	// rather than by the scheme's own rules, which costs the finding a level.
	heuristic bool
	// epochElided records that only one operand stated an epoch and both were
	// therefore compared without one. The answer is the honest reading of
	// advisory data that omits epochs, but the elision is exactly what could
	// have moved the version across the bound, so it costs a level too.
	epochElided bool
	reason      string
	// review is the machine-readable reason an undecidable result went to
	// review, so the bucket can be triaged and the scanner's own blind spots
	// can be counted.
	review string
	notes  []string
	// unproven names the conditions attached to the configuration that decided
	// this element, when the evidence came from one configuration among several
	// the row lists. They cap confidence the same way identity's do.
	unproven []string
}

// discreteVersion is one enumerated affected version together with any
// conditions the configuration that named it attaches.
//
// The pair is what keeps a caveat with its evidence. A row commonly lists one
// unconstrained CPE and several constrained ones; if the version that fires
// came from "only under WordPress" then the finding is conditional, whatever
// the unconstrained sibling says about identity.
type discreteVersion struct {
	value    string
	unproven []string
}

func discreteValues(items []discreteVersion) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.value)
	}
	return out
}

// plainVersions wraps a CNA's Versions[] list, which attaches no conditions.
func plainVersions(in []string) []discreteVersion {
	out := make([]discreteVersion, 0, len(in))
	for _, v := range in {
		out = append(out, discreteVersion{value: v})
	}
	return out
}

// splitCommitEntries separates the commit hashes in an enumerated list from
// the releases, keeping each entry's conditions with it.
func splitCommitEntries(items []discreteVersion) (releases, commits []discreteVersion) {
	for _, it := range items {
		if version.LooksLikeCommit(it.value) {
			commits = append(commits, it)
		} else {
			releases = append(releases, it)
		}
	}
	return releases, commits
}

// ecosystemOrdering names the families whose packages carry an ordering the
// ecosystem itself defines and publishes, so that the ordering is a property of
// the package rather than of the record describing it.
//
// Membership is what licenses overriding the declared range type. Everything
// left out is either an ecosystem with no ordering of its own (Linux, Android,
// GSD, UVI, OSS-Fuzz) or a re-issuer that rebuilds someone else's packages
// without saying whose (Bitnami, MinimOS, Echo, Root, CleanStart), where the
// producer's declared type is the better evidence of the two.
// The table is keyed by the family the published ecosystem name folds back to,
// which is why Linux Mint and Raspbian are absent: identity resolves them to
// Ubuntu and Debian before a scheme is ever asked for.
var ecosystemOrdering = map[string]bool{
	"debian": true, "ubuntu": true,
	"redhat": true, "fedora": true, "centos": true, "rocky": true,
	"almalinux": true, "suse": true, "opensuse": true, "azurelinux": true,
	"openeuler": true, "mageia": true, "photon": true,
	"alpine": true, "wolfi": true, "chainguard": true, "alpaquita": true,
	"bellsoft": true,
	"npm":      true, "pypi": true, "maven": true, "go": true, "cargo": true,
	"rubygems": true, "nuget": true, "packagist": true, "hex": true, "pub": true,
	"cran": true, "hackage": true, "swifturl": true, "opam": true, "julia": true,
	"github actions": true,
}

// resolveScheme picks the ordering for one window and names where it came from.
//
// The ecosystem override is the highest-yield rule available, because it turns
// the CUSTOM-typed slice of distro rows from undecidable into decidable, and it
// is sound in the other direction too: a CNA writing SEMVER in a versionType
// field does not change how dpkg orders 2.15.0-1, which sorts ABOVE 2.15.0
// where SemVer sorts it below. Reading the declaration first is therefore not a
// neutral choice of tie-break; on a Debian row it inverts the verdict and
// reports a patched host as confirmed vulnerable.
//
// It is also the most dangerous rule to apply blindly: handing a 40-character
// commit hash to dpkg ordering produces a total order over nonsense.
// Commit-bearing ranges are therefore forced to OPAQUE first, before either the
// ecosystem or the declared type is consulted.
func resolveScheme(rangeType, ecosystem string, operands ...string) (version.Scheme, string) {
	switch strings.ToUpper(strings.TrimSpace(rangeType)) {
	case "GIT", "ORIGINAL_COMMIT_FOR_FIX":
		return version.Opaque, ""
	}
	for _, op := range operands {
		if version.LooksLikeCommit(op) {
			return version.Opaque, ""
		}
	}
	family, _ := splitEcosystem(ecosystem)
	if ecosystemOrdering[family] {
		s := version.SchemeFor("", ecosystem)
		if declared := version.SchemeFor(rangeType, ecosystem); declared != s {
			return s, "scheme_source:ecosystem_override:" + declaredTypeName(rangeType)
		}
		return s, ""
	}
	return version.SchemeFor(rangeType, ecosystem), ""
}

// declaredTypeName spells the raw range type for evidence. An empty type is the
// CNA declaring nothing, which the corpus spells CUSTOM 127,515 times.
func declaredTypeName(rangeType string) string {
	if t := strings.ToUpper(strings.TrimSpace(rangeType)); t != "" {
		return t
	}
	return "CUSTOM"
}

// compareVersions orders two operands and applies this package's policy on
// answers the scheme reached by convention rather than by rule.
//
// version.CompareCertain grades every answer, and a heuristic one is the best
// reading of the data rather than a proof. Under an ordered scheme that is a
// repaired operand or an elided epoch: the answer stands and the finding is
// demoted. Under GENERIC it is the boundary the whole design turns on. Given
// the bound 2.15.0 and the installed 2.15.0-1ubuntu2, SemVer puts the installed
// version below the fix and dpkg puts it above; a CUSTOM range has not said
// which applies, so picking one is guessing about whether to alarm a user, or
// worse, whether to tell them they are already patched.
func compareVersions(s version.Scheme, a, b string) (int, comparison, error) {
	a, b, elided := elideEpochs(s, a, b)
	n, certainty, err := version.CompareCertain(s, a, b)
	if err != nil {
		return 0, comparison{}, fmt.Errorf("match: compare %q and %q under %s: %w", a, b, s, err)
	}
	c := comparison{heuristic: certainty != version.Exact, epochElided: elided}
	if c.heuristic && s == version.Generic {
		return 0, c, fmt.Errorf("match: compare %q and %q under %s: decided only by convention: %w",
			a, b, s, version.ErrNotComparable)
	}
	return n, c, nil
}

// comparison records what had to be assumed to reach an ordering. Both fields
// cost the finding a level, and both have to travel with the answer, because an
// assumption that is not reported is indistinguishable from a proof.
type comparison struct {
	heuristic   bool
	epochElided bool
}

// elideEpochs compares like with like when only one operand states an epoch.
//
// internal/inventory reads an epoch-bearing EVR off the rpm database
// (openssl-1:3.0.7-1.el9) while advisory bounds routinely omit the epoch
// altogether (3.0.7-2.el9). Both rpm and dpkg define an absent epoch as 0, and
// applying that definition here puts every epoch-bearing installed package
// above every epoch-less bound, which reports an unpatched RHEL host as fixed:
// a systematic false negative across the whole RHEL, SUSE, Rocky and Alma
// corpus, and one that looks exactly like a correct all-clear.
//
// So the epoch is dropped from whichever side stated it and the remainders are
// compared. That is the reading the advisory intended, and it is recorded and
// demoted because the discarded epoch is precisely what could have moved the
// version across the bound. When both sides state an epoch there is no
// asymmetry to repair and the scheme's own rules apply unchanged.
func elideEpochs(s version.Scheme, a, b string) (string, string, bool) {
	if s != version.RPM && s != version.Debian {
		return a, b, false
	}
	ra, oka := stripEpoch(a)
	rb, okb := stripEpoch(b)
	if oka == okb {
		return a, b, false
	}
	if oka {
		return ra, b, true
	}
	return a, rb, true
}

// stripEpoch removes a leading "<digits>:" epoch. Only digits qualify: a bound
// written "see: the vendor advisory" states no epoch, and a version with an
// empty remainder states nothing at all.
func stripEpoch(s string) (string, bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(s) || s[i] != ':' || i+1 == len(s) {
		return s, false
	}
	return s[i+1:], true
}

// versionsEqual is scheme-aware equality. Byte equality is the fallback of last
// resort, not the definition: under SEMVER 1.0 and 1.0.0 are the same release,
// and under RPM an elided epoch does not make two builds different.
func versionsEqual(s version.Scheme, a, b string) (bool, comparison, error) {
	if s == version.Opaque {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)), comparison{}, nil
	}
	n, c, err := compareVersions(s, a, b)
	return n == 0, c, err
}

func gradeOf(s version.Scheme) versionGrade {
	switch {
	case s == version.Opaque:
		return vgUndecidable
	case s == version.Generic:
		return vgGeneric
	case version.Ordered(s):
		return vgOrdered
	default:
		// A scheme that does not claim a total order decides only what every
		// plausible ordering agrees on, which is what generic means here.
		return vgGeneric
	}
}

func discreteGrade(s version.Scheme) versionGrade {
	switch {
	case s == version.Opaque:
		return vgLiteral
	case s == version.Generic:
		return vgGeneric
	case version.Ordered(s):
		return vgOrdered
	}
	return vgGeneric
}

// A placeholder means different things in different fields, which is why
// version.ClassifySentinel only classifies and leaves the reading to here.
//
// unboundedLower says every placeholder in Introduced means the window opens at
// the beginning of time, including "0", which is the OSV spelling for that and
// not the version zero.
func unboundedLower(s string) bool {
	return version.ClassifySentinel(s) != version.NotSentinel
}

// sentinelUpper says an upper bound that states no version leaves the top of
// the window unknown.
//
// This is the asymmetry that keeps the scanner honest. A missing lower bound
// widens the window downwards, which the row already intended; a missing upper
// bound widens it to infinity, which it did not, so it is never read as "no
// upper bound". Doing that would report versions released years after the fix.
func sentinelUpper(s string) bool {
	switch version.ClassifySentinel(s) {
	case version.SentinelAll, version.SentinelUnknown:
		return true
	}
	return false
}

// usableVersions filters a Versions[] list. internal/parse/cve5.go does not
// sanitise it the way nvd.go does, so n/a, unspecified and all reach storage.
func usableVersions(in []string) (listed []string, claimsAll bool) {
	for _, raw := range in {
		switch version.ClassifySentinel(raw) {
		case version.SentinelAll:
			claimsAll = true
		case version.SentinelEmpty, version.SentinelUnknown:
			// Asserts nothing.
		case version.SentinelZero:
			// A package genuinely versioned 0 exists, so this entry may be
			// real. It is dropped anyway: in a CNA version list "0" is a
			// placeholder far more often than a release, and the cost of
			// dropping it is one missed match rather than one invented finding.
		default:
			listed = append(listed, strings.TrimSpace(raw))
		}
	}
	return listed, claimsAll
}

// evalRange applies one window to the component version.
func evalRange(s version.Scheme, v string, r model.VersionRange) elementResult {
	res := elementResult{scheme: s}

	lower := strings.TrimSpace(r.Introduced)
	lowerExclusive := false
	if trimmed, ok := strings.CutSuffix(lower, exclusiveMarker); ok {
		lower, lowerExclusive = strings.TrimSpace(trimmed), true
	}
	hasLower := lower != "" && (lowerExclusive || !unboundedLower(lower))

	fixed := strings.TrimSpace(r.Fixed)
	last := strings.TrimSpace(r.LastAffected)
	if sentinelUpper(fixed) || sentinelUpper(last) {
		// Name the field that actually tripped the check and print the pair.
		// firstNonEmpty returns whichever bound is present, which on a row
		// carrying Fixed=2.0.0 and LastAffected=unspecified quotes "2.0.0" as
		// the value that "names no version" and sends the reviewer to the one
		// operand that was fine.
		field, value := "Fixed", fixed
		if !sentinelUpper(fixed) {
			field, value = "LastAffected", last
		}
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "sentinel_upper_bound"
		res.reason = fmt.Sprintf("the window's %s bound is %q, which names no version, so the top of the affected range is unknown (the window states Fixed=%q and LastAffected=%q)",
			field, value, fixed, last)
		return res
	}
	if fixed != "" && last != "" {
		// Should not occur, but does. Applying both bounds is exactly the
		// smaller of the two affected sets and needs no guess about which the
		// upstream meant.
		res.notes = append(res.notes, "conflicting_upper_bounds")
	}

	if !hasLower && fixed == "" && last == "" {
		// An all-versions claim is still a claim about versions, so it can only
		// be asserted against something that is one. No comparison runs on this
		// path, so nothing else would ever look at the operand: a component
		// whose recorded version is "trunk" or a commit hash would be reported
		// affected by every unbounded row in the corpus, on the strength of a
		// string the scheme cannot read.
		if s == version.Opaque {
			res.verdict, res.grade = vUndecided, vgUndecidable
			res.review = "opaque_scheme:" + declaredTypeName(r.Type)
			res.reason = fmt.Sprintf("the window bounds nothing and range type %s defines no ordering, so there is no sense in which %q is inside it", declaredTypeName(r.Type), v)
			return res
		}
		if !statesAVersion(v) {
			res.verdict, res.grade = vUndecided, vgUndecidable
			res.review = "unparseable_version:component"
			res.reason = fmt.Sprintf("the window claims every version, but the installed %q is not a version any scheme can read, so it cannot be placed inside or outside the claim", v)
			return res
		}
		res.verdict, res.grade = vInRange, vgUnbounded
		res.reason = fmt.Sprintf("%s is affected because the window gives neither a lower nor an upper bound, so it claims every version that has ever existed", v)
		return res
	}

	if hasLower {
		n, c, err := compareVersions(s, v, lower)
		if err != nil {
			return undecidableRange(s, v, lower, r, err)
		}
		res.note(c)
		if n < 0 || (n == 0 && lowerExclusive) {
			res.verdict, res.grade = vNotInRange, gradeOf(s)
			res.reason = fmt.Sprintf("%s is below the window: the flaw was introduced %s %s", v, boundWord(lowerExclusive), lower)
			return res
		}
	}
	if fixed != "" {
		n, c, err := compareVersions(s, v, fixed)
		if err != nil {
			return undecidableRange(s, v, fixed, r, err)
		}
		res.note(c)
		if n >= 0 {
			res.verdict, res.grade = vNotInRange, gradeOf(s)
			// Fixed is exclusive. Reading it as inclusive reports every patched
			// system as vulnerable, which is the one bug that would discredit
			// the scanner for exactly the users who acted on it.
			res.reason = fmt.Sprintf("%s >= %s, the version the fix landed in; Fixed is an exclusive bound, so the fix version itself is not affected", v, fixed)
			return res
		}
	}
	if last != "" {
		n, c, err := compareVersions(s, v, last)
		if err != nil {
			return undecidableRange(s, v, last, r, err)
		}
		res.note(c)
		if n > 0 {
			res.verdict, res.grade = vNotInRange, gradeOf(s)
			res.reason = fmt.Sprintf("%s > %s, the last affected version, which is an inclusive bound", v, last)
			return res
		}
	}

	res.verdict, res.grade = vInRange, gradeOf(s)
	res.reason = affectedSentence(s, v, lower, hasLower, lowerExclusive, fixed, last)
	return res
}

// undecidableRange turns a refused comparison into a reviewable statement. The
// reason names both operands and why no ordering could be applied, because a
// reviewer without database access has to be able to re-derive the verdict.
func undecidableRange(s version.Scheme, v, bound string, r model.VersionRange, err error) elementResult {
	declared := strings.ToUpper(strings.TrimSpace(r.Type))
	if declared == "" {
		declared = "CUSTOM"
	}
	res := elementResult{verdict: vUndecided, grade: vgUndecidable, scheme: s}
	switch s {
	case version.Opaque:
		res.review = "opaque_scheme:" + declared
		// Name the operand that actually looked like a hash. The scheme goes
		// opaque when either side does, and a reviewer sent to "the bound" when
		// it is the inventory that recorded a commit where a version belongs
		// looks at the one operand that was fine.
		switch {
		case version.LooksLikeCommit(v) && version.LooksLikeCommit(bound):
			res.reason = fmt.Sprintf("range type %s: the installed version %q and the bound %q are both commit hashes, which have no order relation to each other", declared, v, bound)
		case version.LooksLikeCommit(v):
			res.reason = fmt.Sprintf("range type %s: the installed version %q is a commit hash and has no order relation to the bound %q", declared, v, bound)
		case version.LooksLikeCommit(bound):
			res.reason = fmt.Sprintf("range type %s: the bound %q is a commit hash and has no order relation to the installed version %q", declared, bound, v)
		default:
			res.reason = fmt.Sprintf("range type %s defines no ordering, so the installed version %q cannot be placed against the bound %q", declared, v, bound)
		}
	case version.Generic:
		if !startsWithVersionNumber(v) || !startsWithVersionNumber(bound) {
			res.review = "unparseable_version:bound"
			res.reason = fmt.Sprintf("installed %q and the bound %q cannot be ordered: one of them does not begin with a version number, and the range declared type %s, which defines no ordering to fall back on", v, bound, declared)
			return res
		}
		res.review = "generic_refused_tie"
		res.reason = fmt.Sprintf("installed %q and the bound %q cannot be ordered by any rule both would obey; the range declared type %s, which defines none, and the mainstream schemes disagree at exactly this point: SemVer places a suffixed version below the bare one, dpkg above it", v, bound, declared)
	default:
		res.review = "unparseable_version:bound"
		res.reason = fmt.Sprintf("the %s ordering could not read one of the operands: %v", s, err)
	}
	return res
}

// note folds one comparison's assumptions into the window's result. Both are
// sticky: a window decided by three comparisons is only as strong as the
// weakest of them.
func (r *elementResult) note(c comparison) {
	r.heuristic = r.heuristic || c.heuristic
	if c.epochElided && !r.epochElided {
		r.epochElided = true
		r.notes = append(r.notes, "epoch_elided")
	}
}

// statesAVersion reports whether an operand is something a scheme could read.
//
// It is deliberately only consulted where no comparison runs, since every
// comparator already refuses what it cannot parse. A leading digit, after an
// optional "v", is what every ordered scheme in this corpus requires; a commit
// hash passes that test when it happens to start with a digit, so it is
// excluded by name.
func statesAVersion(v string) bool {
	return startsWithVersionNumber(v) && !version.LooksLikeCommit(v)
}

// startsWithVersionNumber separates the two ways a GENERIC comparison can fail:
// a boundary tie the scheme deliberately refuses, and an operand that was never
// a version at all. They need different review queues, so they get different
// reasons.
func startsWithVersionNumber(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

func boundWord(exclusive bool) string {
	if exclusive {
		return "after (exclusive of)"
	}
	return "in"
}

// affectedSentence states the containment with both operands, the operator and
// each bound's inclusivity. A template that omits a number cannot be audited.
func affectedSentence(s version.Scheme, v, lower string, hasLower, lowerExclusive bool, fixed, last string) string {
	var clauses []string
	if hasLower {
		if lowerExclusive {
			clauses = append(clauses, fmt.Sprintf("%s > %s (affected from above %s, exclusive: the NVD versionStartExcluding encoding)", v, lower, lower))
		} else {
			clauses = append(clauses, fmt.Sprintf("%s >= %s (introduced in %s, inclusive)", v, lower, lower))
		}
	}
	if fixed != "" {
		clauses = append(clauses, fmt.Sprintf("%s < %s (fixed in %s; the fix version itself is not affected)", v, fixed, fixed))
	}
	if last != "" {
		clauses = append(clauses, fmt.Sprintf("%s <= %s (last affected %s, inclusive)", v, last, last))
	}
	if !hasLower {
		clauses = append(clauses, "no lower bound was given, so every earlier version is affected too")
	}
	if fixed == "" && last == "" {
		clauses = append(clauses, "no fixed version has been published, so the window is open-ended")
	}
	return strings.Join(clauses, " and ") + ", compared under " + string(s) + " ordering"
}

// evalDiscrete applies a version list.
//
// A list can prove affected; it can only prove not-affected under a closed
// world. Ranges are a claim about an interval, but a version list is often just
// the versions the reporter happened to test, so absence from an open list is
// not evidence of safety.
func evalDiscrete(s version.Scheme, v string, listed []discreteVersion, claimsAll, closed bool, kind string) elementResult {
	res := elementResult{scheme: s}
	refused := false
	for _, item := range listed {
		eq, c, err := versionsEqual(s, v, item.value)
		if err != nil {
			refused = true
			continue
		}
		if eq {
			res.verdict, res.grade = vInRange, discreteGrade(s)
			res.note(c)
			// The conditions travel with the entry that fired, not with the
			// list. One row can enumerate an unconditional configuration and a
			// conditional one, and only the one that matched has any bearing on
			// what this component's finding means.
			res.unproven = item.unproven
			if strings.EqualFold(v, item.value) {
				res.reason = fmt.Sprintf("installed %s is listed verbatim among the %s the statement names as affected", v, kind)
			} else {
				res.reason = fmt.Sprintf("installed %s is the same release as %s, which the statement names as affected, under %s ordering", v, item.value, s)
			}
			if len(item.unproven) > 0 {
				res.reason += ", in the configuration that also requires " + strings.Join(item.unproven, " and ")
			}
			return res
		}
	}
	// Checked after the listed versions, because an explicit hit is a decision
	// and this is not: "every release that has ever existed is affected" is
	// unfalsifiable against any inventory, so it can only ask for review.
	if claimsAll {
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "unbounded_default_affected"
		res.reason = "the statement claims all versions rather than naming any, which cannot be checked against an inventory"
		return res
	}
	values := strings.Join(discreteValues(listed), ", ")
	if refused {
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "unparseable_version:bound"
		res.reason = fmt.Sprintf("installed %s could not be compared with the %s the statement lists (%s), so membership of the list is unknown", v, kind, values)
		return res
	}
	if closed {
		res.verdict, res.grade = vNotInRange, discreteGrade(s)
		res.reason = fmt.Sprintf("installed %s is not among the %s the statement enumerates (%s), and the enumeration is complete", v, kind, values)
		return res
	}
	res.verdict, res.grade = vUndecided, vgUndecidable
	res.review = "open_version_enumeration"
	res.reason = fmt.Sprintf("installed %s is not among the %s the statement lists (%s), but the list is not declared complete, so absence from it proves nothing", v, kind, values)
	return res
}

// versionTest runs every window and version list on the row and unions them.
func versionTest(c Component, a Affected, id identity) elementResult {
	eco := id.ecosystem
	declared := commonRangeType(a.Ranges)

	var elems []elementResult
	var notes []string

	for _, r := range a.Ranges {
		if strings.EqualFold(strings.TrimSpace(r.Type), "ORIGINAL_COMMIT_FOR_FIX") {
			// Not a bound at all: it names the commit that fixed the flaw.
			// Counting it as an undecidable window would pin all 8,518 rows
			// that carry one to review even when a sibling window could decide
			// them, so it is removed from the set and kept as a pointer.
			notes = append(notes, "fix_commit:"+firstNonEmpty(r.Fixed, r.LastAffected, r.Introduced))
			continue
		}
		if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
			// An entirely empty window asserts nothing. This is not the same as
			// introduced:"0", where somebody deliberately wrote "all versions".
			continue
		}
		s, schemeNote := resolveScheme(r.Type, eco, c.Version, r.Introduced, r.Fixed, r.LastAffected)
		if schemeNote != "" {
			notes = appendOnce(notes, schemeNote)
		}

		// Alpine secdb publishes fixed-in versions only and uses "0" as the
		// pseudo-version meaning the package was never affected. Read as a
		// window that is [0, 0), which is empty, and an empty window is a
		// silent false negative indistinguishable from a correct suppression.
		//
		// It is one window's verdict and not the row's. Returning here instead
		// would discard every sibling window already evaluated, so a row that
		// carries both a real fixed-in bound and a not-affected marker for some
		// other branch would retract a proven positive — the union rule run
		// backwards, and a suppressed true finding that reads exactly like a
		// correct all-clear.
		if s == version.Alpine && strings.TrimSpace(r.Fixed) == "0" {
			elems = append(elems, elementResult{
				verdict: vNotInRange,
				grade:   vgOrdered,
				scheme:  s,
				notes:   []string{"alpine_fixed_zero"},
				reason:  fmt.Sprintf("the Alpine-family statement records fixed version \"0\", the pseudo-version meaning this package was never affected, so %s is not affected", c.Version),
			})
			continue
		}
		elems = append(elems, evalCarriedRange(s, c, r))
	}

	if listed, claimsAll := usableVersions(a.Versions); claimsAll || len(listed) > 0 {
		more, schemeNote := evalVersionList(declared, eco, c.Version, plainVersions(listed), claimsAll, closedEnumeration(a), "versions")
		if schemeNote != "" {
			notes = appendOnce(notes, schemeNote)
		}
		elems = append(elems, more...)
	}

	// A literal version attribute on a matched CPE is a discrete affected
	// version, not identity.
	if len(id.cpeVersions) > 0 {
		more, schemeNote := evalVersionList(declared, eco, c.Version, id.cpeVersions, false, closedCPEConfigurations(a), "vulnerable configurations")
		if schemeNote != "" {
			notes = appendOnce(notes, schemeNote)
		}
		elems = append(elems, more...)
	}
	if len(id.cpePatterns) > 0 {
		elems = append(elems, evalPatterns(c.Version, id.cpePatterns, closedCPEConfigurations(a)))
	}

	if affectedByDefault(a) {
		s, schemeNote := resolveScheme(declared, eco, c.Version)
		if schemeNote != "" {
			notes = appendOnce(notes, schemeNote)
		}
		elems = append(elems, evalDefaultAffected(s, c.Version, a))
	}

	if len(elems) == 0 {
		return elementResult{
			verdict: vUndecided,
			grade:   vgUndecidable,
			review:  "no_version_data",
			notes:   notes,
			reason: fmt.Sprintf("the statement names %s but carries no version range and no version list, so there is nothing to test %s against",
				productLabel(a), c.Version),
		}
	}

	res := unionOf(elems)
	if res.verdict == vNotInRange && unknownByDefault(a) {
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "unknown_default_status"
		res.reason = fmt.Sprintf("%s is outside the stated version scope, but %s gives no affirmative default affected or unaffected status, so absence from that scope does not establish safety", c.Version, sourceLabel(a))
	}
	res.notes = append(notes, res.notes...)
	return res
}

// evalCarriedRange applies one window together with the conditions of the CPE
// that carried it.
//
// A source that states its windows per applicability criteria (NVD
// configurations, CVE 5.1 cpeApplicability) writes each one against a CPE, and
// that CPE's target_sw, sw_edition and the rest are what the window is
// conditional on: "libfoo below 2.0 under WordPress" is not "libfoo below
// 2.0". Evaluating the windows as one flat slice lost the carrier, and a row
// listing that window beside an unconditional libfoo:3.1 reported a
// Drupal-hosted libfoo 1.5 as affected outright, on the strength of a bound
// that never applied to it. The conditions travel with the window here exactly
// as they travel with a literal version: one the inventory has not established
// is unproven and caps the finding, and one the inventory contradicts takes
// the window out of the set, because a window about another configuration
// says nothing about this build.
func evalCarriedRange(s version.Scheme, c Component, r model.VersionRange) elementResult {
	res := evalRange(s, c.Version, r)
	if strings.TrimSpace(r.CPE) == "" {
		return res
	}
	unproven, disjoint, ok := carrierConstraints(r.CPE, c.CPE)
	if !ok {
		return res
	}
	if disjoint != "" {
		return elementResult{
			verdict: vNotInRange,
			grade:   gradeOf(s),
			scheme:  s,
			reason: fmt.Sprintf("the window (Introduced=%q, Fixed=%q, LastAffected=%q) is carried by the configuration %s, which requires %s, and the component's %s contradicts that, so the window is about a different configuration and says nothing about the installed %s",
				r.Introduced, r.Fixed, r.LastAffected, r.CPE, disjoint, c.CPE, c.Version),
		}
	}
	if len(unproven) > 0 {
		res.unproven = unproven
		if res.verdict == vInRange {
			res.reason += ", in the configuration that also requires " + strings.Join(unproven, " and ")
		}
	}
	return res
}

// evalVersionList applies one enumerated list, with the commit hashes in it
// taken out and judged on their own.
//
// The scheme is resolved from the installed version and the declared type
// alone. Resolving it from the whole list let one entry decide for all of
// them: the kernel CNA and others mix versionType git entries with real
// releases in one versions[] array, and a single hash among them forced the
// entire list to byte-literal comparison, under which installed 1.0 is not the
// listed 1.0.0 and a closed CNA enumeration reported the host safe. The hashes
// are still never handed to an ordering: they are compared literally, as the
// separate list they are, and under the same closed-world rule, because a CNA
// that enumerates its affected builds enumerates them however they are spelled.
func evalVersionList(declared, eco, v string, listed []discreteVersion, claimsAll, closed bool, kind string) ([]elementResult, string) {
	releases, commits := splitCommitEntries(listed)
	var out []elementResult
	schemeNote := ""
	if claimsAll || len(releases) > 0 {
		var s version.Scheme
		s, schemeNote = resolveScheme(declared, eco, v)
		out = append(out, evalDiscrete(s, v, releases, claimsAll, closed, kind))
	}
	if len(commits) > 0 {
		out = append(out, evalDiscrete(version.Opaque, v, commits, false, closed, "commit hashes"))
	}
	return out, schemeNote
}

// evalPatterns applies the wildcarded version attributes of the matched CPEs.
//
// NVD writes cpe:2.3:a:acme:libfoo:2.*:... to mean every 2.x build. The
// pattern is globbed against the installed version, as the CPE specification
// globs every other wildcarded attribute, and a hit is graded as a pattern
// match rather than an ordering: "2.*" admits 2.1 without saying where 2.1
// sits or that it was ever examined. Absence proves safety under the same
// closed-world rule as a literal configuration list, since a pattern is one
// more entry in the enumeration.
func evalPatterns(v string, patterns []discreteVersion, closed bool) elementResult {
	res := elementResult{scheme: version.Opaque}
	installed := strings.TrimSpace(v)
	for _, p := range patterns {
		if !globMatch(p.value, installed) {
			continue
		}
		res.verdict, res.grade = vInRange, vgPattern
		res.unproven = p.unproven
		res.reason = fmt.Sprintf("installed %s matches the version pattern %s of a vulnerable configuration the statement lists", v, p.value)
		if len(p.unproven) > 0 {
			res.reason += ", in the configuration that also requires " + strings.Join(p.unproven, " and ")
		}
		return res
	}
	values := strings.Join(discreteValues(patterns), ", ")
	if closed {
		res.verdict, res.grade = vNotInRange, vgPattern
		res.reason = fmt.Sprintf("installed %s matches none of the version patterns the statement's vulnerable configurations name (%s), and the enumeration is complete", v, values)
		return res
	}
	res.verdict, res.grade = vUndecided, vgUndecidable
	res.review = "open_version_enumeration"
	res.reason = fmt.Sprintf("installed %s matches none of the version patterns the statement's vulnerable configurations name (%s), but the list is not declared complete, so absence from it proves nothing", v, values)
	return res
}

// evalDefaultAffected applies a CVE-5 defaultStatus of affected: every version
// the statement does not name is affected.
//
// It is graded unbounded, the same as a window with no bounds, because it is
// the same claim: nothing was compared, and the finding rests on the CNA's
// blanket assertion rather than on any examination of this version. The
// guards are the unbounded window's too. The claim is about versions, so it
// can only be asserted against something a scheme can read; a component whose
// recorded version is a commit hash or "trunk" would otherwise be reported
// affected by every default-affected row in the corpus.
func evalDefaultAffected(s version.Scheme, v string, a Affected) elementResult {
	res := elementResult{scheme: s}
	if s == version.Opaque {
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "opaque_scheme:" + declaredTypeName(commonRangeType(a.Ranges))
		res.reason = fmt.Sprintf("the statement declares every unlisted version affected by default, but no ordering can read %q, so there is no sense in which it is a version the default covers", v)
		return res
	}
	if !statesAVersion(v) {
		res.verdict, res.grade = vUndecided, vgUndecidable
		res.review = "unparseable_version:component"
		res.reason = fmt.Sprintf("the statement declares every unlisted version affected by default, but the installed %q is not a version any scheme can read, so it cannot be placed inside or outside the claim", v)
		return res
	}
	res.verdict, res.grade = vInRange, vgUnbounded
	res.reason = fmt.Sprintf("%s is affected by default: %s declares defaultStatus affected, so every version the statement does not name as an exception is affected, and the exceptions travel on the statement's own not_affected row", v, sourceLabel(a))
	return res
}

// unionOf combines the per-window verdicts.
//
// A positive from any window is a positive, and an undecidable sibling cannot
// retract it. A negative needs every window to be provably clear: one window we
// could not decide is enough to deny a clean bill of health.
func unionOf(elems []elementResult) elementResult {
	var positive, undecided, clear []elementResult
	for _, e := range elems {
		switch e.verdict {
		case vInRange:
			positive = append(positive, e)
		case vUndecided:
			undecided = append(undecided, e)
		default:
			clear = append(clear, e)
		}
	}
	if len(positive) > 0 {
		best := positive[0]
		for _, e := range positive[1:] {
			if strongerPositive(e, best) {
				best = e
			}
		}
		return best
	}
	if len(undecided) > 0 {
		return undecided[0]
	}
	return clear[0]
}

// strongerPositive orders two positive verdicts for the union. Grade first;
// at equal grade a proof beats a convention; and at equal strength the window
// with fewer conditions attached wins, because an unconditional positive is
// the stronger claim and reporting the conditional sibling's caveat in its
// place would cap a finding the row never capped.
func strongerPositive(e, best elementResult) bool {
	if e.grade != best.grade {
		return e.grade > best.grade
	}
	if e.heuristic != best.heuristic {
		return !e.heuristic
	}
	return len(e.unproven) < len(best.unproven)
}

// cve5Shaped reports whether the statement was read from a CVE Record Format 5
// document, where Versions[] is the CNA's enumeration and DefaultState is the
// record's defaultStatus. Only those sources give the two fields those
// meanings: the CSAF collector copies the product status into DefaultState,
// and a product-level known_affected is a statement about the builds it
// names, not a default for the ones it does not.
func cve5Shaped(a Affected) bool {
	switch strings.ToLower(strings.TrimSpace(a.Source)) {
	case "cvelist", "vulnrichment", "fkie":
		return true
	}
	return false
}

// closedEnumeration reports whether absence from the row's version list proves
// the component is unaffected.
//
// A CVE-5 record enumerates the affected versions, and cve5.go already splits
// the CNA's exceptions into their own row. The positive list is closed only
// under defaultStatus unaffected. Under defaultStatus affected the
// listed versions are examples and an unlisted one is affected too, which
// affectedByDefault reports. An unknown or omitted default proves nothing
// about an unlisted version, as specified by the CVE version-status algorithm. The
// exceptions row itself is always closed: it lists every exception the CNA
// named, and the record's default is a statement about the other row.
func closedEnumeration(a Affected) bool {
	if !cve5Shaped(a) {
		return false
	}
	if normalizeStatus(a.Status) != model.StatusAffected {
		return true
	}
	return model.NormalizeStatus(a.DefaultState) == model.StatusNotAffected
}

// unknownByDefault keeps the CVE default separate from an interval endpoint:
// a lessThan bound closes this statement, but does not assert a fix outside it.
func unknownByDefault(a Affected) bool {
	if normalizeStatus(a.Status) != model.StatusAffected || !cve5Shaped(a) {
		return false
	}
	status := model.NormalizeStatus(a.DefaultState)
	return status != model.StatusAffected && status != model.StatusNotAffected
}

// affectedByDefault reports whether the statement claims every version it
// does not name.
//
// Only an affirmative CVE-5 row can: defaultStatus affected is the CNA saying
// "affected unless I say otherwise", and the "otherwise" lives on the
// not_affected row cve5.go splits off. A negative row never claims a default
// whatever DefaultState says, because its list is the exceptions themselves,
// and reading a default into it would make the vendor's "these builds are
// safe" cover builds it never named.
func affectedByDefault(a Affected) bool {
	if normalizeStatus(a.Status) != model.StatusAffected || !cve5Shaped(a) {
		return false
	}
	return model.NormalizeStatus(a.DefaultState) == model.StatusAffected
}

// closedCPEConfigurations reports whether absence from the row's CPE
// configuration list proves the component is unaffected.
//
// NVD's configuration list is an enumeration: nvd.go writes every vulnerable
// build the analyst matched, so a version that is not in it is a version NVD
// says is not vulnerable. A vendor CSAF advisory is not. It names the products
// the vendor chose to mention, and reading it as exhaustive turns "Siemens
// names firmware 4.5" into "Siemens asserts 4.5.1 is safe" — a silent negative
// on an OT device, manufactured from a row that never mentioned 4.5.1. The
// specification routes exactly that case to human review instead.
func closedCPEConfigurations(a Affected) bool {
	if strings.EqualFold(strings.TrimSpace(a.Source), "nvd") {
		return true
	}
	return closedEnumeration(a)
}

// appendOnce keeps the evidence notes a set. Every window on a row resolves its
// own scheme, and repeating one note per window says nothing extra.
func appendOnce(notes []string, note string) []string {
	for _, n := range notes {
		if n == note {
			return notes
		}
	}
	return append(notes, note)
}

// commonRangeType is the declared type to use for data that has no type of its
// own, namely the version list. It is only used when every window agrees, since
// a row with mixed types has each window evaluated under its own scheme.
func commonRangeType(ranges []model.VersionRange) string {
	out := ""
	for _, r := range ranges {
		t := strings.ToUpper(strings.TrimSpace(r.Type))
		if t == "" || t == "ORIGINAL_COMMIT_FOR_FIX" {
			continue
		}
		if out == "" {
			out = t
			continue
		}
		if out != t {
			return ""
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func productLabel(a Affected) string {
	if s := firstNonEmpty(a.PURL, a.Product); s != "" {
		if a.Vendor != "" && s == a.Product {
			return a.Vendor + " " + s
		}
		return s
	}
	if len(a.CPEs) > 0 {
		return a.CPEs[0]
	}
	return "an unnamed product"
}
