package match

import "strings"

// cpeAttrs is a CPE 2.3 well-formed name: the eleven attributes, each holding
// ANY ("*"), NA ("-") or a quoted literal that may itself contain the wildcards
// '*' and '?'.
type cpeAttrs struct {
	part      string
	vendor    string
	product   string
	version   string
	update    string
	edition   string
	language  string
	swEdition string
	targetSW  string
	targetHW  string
	other     string
}

// parseCPE accepts the two bindings producers actually emit: the CPE 2.3
// formatted string and the CPE 2.2 URI. The URI form is converted rather than
// rejected because several SBOM tools still write it, and rejecting it would
// silently drop the strongest identity those tools supply.
func parseCPE(s string) (cpeAttrs, bool) {
	s = strings.TrimSpace(s)
	switch {
	case len(s) >= 8 && strings.EqualFold(s[:8], "cpe:2.3:"):
		f := splitEscaped(s, ':')
		if len(f) != 13 {
			return cpeAttrs{}, false
		}
		return cpeAttrs{
			part: f[2], vendor: f[3], product: f[4], version: f[5], update: f[6],
			edition: f[7], language: f[8], swEdition: f[9], targetSW: f[10],
			targetHW: f[11], other: f[12],
		}.normalized(), true

	case len(s) >= 5 && strings.EqualFold(s[:5], "cpe:/"):
		f := strings.Split(s[5:], ":")
		for len(f) < 7 {
			f = append(f, "")
		}
		a := cpeAttrs{
			part: f[0], vendor: f[1], product: f[2], version: f[3], update: f[4],
			edition: f[5], language: f[6],
		}
		// CPE 2.2 packs the four attributes it has no field for into edition as
		// ~edition~sw_edition~target_sw~target_hw~other. Leaving them packed
		// would compare the literal "~~~wordpress~~" against a target_sw.
		if strings.HasPrefix(a.edition, "~") {
			p := strings.Split(a.edition, "~")
			for len(p) < 6 {
				p = append(p, "")
			}
			a.edition, a.swEdition, a.targetSW, a.targetHW, a.other = p[1], p[2], p[3], p[4], p[5]
		}
		for _, v := range []*string{&a.part, &a.vendor, &a.product, &a.version, &a.update,
			&a.edition, &a.language, &a.swEdition, &a.targetSW, &a.targetHW, &a.other} {
			*v = unescape(*v)
		}
		return a.normalized(), true
	}
	return cpeAttrs{}, false
}

// normalized turns the several spellings of "unspecified" into ANY. In the URI
// binding an omitted attribute is empty; in the formatted string it is "*".
func (a cpeAttrs) normalized() cpeAttrs {
	for _, v := range []*string{&a.part, &a.vendor, &a.product, &a.version, &a.update,
		&a.edition, &a.language, &a.swEdition, &a.targetSW, &a.targetHW, &a.other} {
		*v = strings.TrimSpace(*v)
		if *v == "" {
			*v = "*"
		}
	}
	return a
}

// cpeRelation is how one stored attribute relates to the component's.
type cpeRelation int

const (
	// cpeSatisfied: the stored attribute admits the component's value.
	cpeSatisfied cpeRelation = iota
	// cpeDisjoint: the two cannot describe the same thing. This is positive
	// evidence of non-applicability, not an absence of evidence.
	cpeDisjoint
	// cpeUnproven: the row constrains an attribute the inventory does not know.
	// The claim is neither established nor refuted, so it caps confidence.
	cpeUnproven
)

// cpeAttrRelation compares one stored attribute (row) against the component's.
func cpeAttrRelation(row, comp string) cpeRelation {
	switch {
	case row == "*":
		return cpeSatisfied
	case row == "-":
		if comp == "-" {
			return cpeSatisfied
		}
		return cpeDisjoint
	case comp == "*":
		return cpeUnproven
	case comp == "-":
		return cpeDisjoint
	}
	if hasWildcard(row) {
		if globMatch(row, unquoteCPE(comp)) {
			return cpeSatisfied
		}
		return cpeDisjoint
	}
	if strings.EqualFold(unquoteCPE(row), unquoteCPE(comp)) {
		return cpeSatisfied
	}
	return cpeDisjoint
}

// cpeChannel is the verdict of the whole CPE channel over a row's CPE list.
type cpeChannel struct {
	relation cpeRelation
	// unproven is the constraint set of the best configuration that matched,
	// which is what the identity question asks: is any listed configuration
	// wholly satisfied by this component?
	unproven []string
	// versions are the literal version attributes of the CPEs that matched,
	// each carrying its own configuration's constraints. NVD's configuration
	// list enumerates the vulnerable builds, so these are a discrete
	// affected-version set rather than part of identity — and the constraints
	// have to stay attached to the entry, because the entry that decides the
	// version test is rarely the one that decides identity.
	versions []discreteVersion
	// patterns are the wildcarded version attributes of the CPEs that matched:
	// libfoo:2.* names every 2.x build. A pattern is not a version and is kept
	// out of versions, because a comparator handed "2.*" reads the release 2
	// followed by something it cannot parse, and under a closed NVD
	// configuration list that made an installed 2.1 provably safe. Patterns
	// are globbed against the installed version instead, as the CPE
	// specification globs every other wildcarded attribute.
	patterns []discreteVersion
}

// matchCPEs runs the CPE channel: the component's CPE against every CPE the row
// stores.
//
// A row whose CPE names product "*" or vendor "*" contributes nothing to
// identity, however specific the rest of it looks. cpe:2.3:a:microsoft:*:*:...
// means "every Microsoft application"; reading it as identity flags every
// Microsoft product for every Microsoft CVE. Such CPEs are indeterminate, which
// lets a weaker channel decide instead of the row being rejected outright.
func matchCPEs(componentCPE string, rowCPEs []string) cpeChannel {
	comp, ok := parseCPE(componentCPE)
	if !ok {
		return cpeChannel{relation: cpeUnproven}
	}
	out := cpeChannel{relation: cpeUnproven}
	determinate := false
	matched := false

	for _, raw := range rowCPEs {
		row, ok := parseCPE(raw)
		if !ok {
			continue
		}
		if row.product == "*" || row.vendor == "*" {
			continue
		}
		// part, vendor and product carry identity. A disjoint one is evidence
		// the row is about something else; an unproven one (the component's own
		// CPE left the attribute ANY) proves nothing either way, so the row is
		// passed over without condemning the whole channel.
		skip := false
		for _, rel := range []cpeRelation{
			cpeAttrRelation(row.part, comp.part),
			cpeAttrRelation(row.vendor, comp.vendor),
			cpeAttrRelation(row.product, comp.product),
		} {
			switch rel {
			case cpeDisjoint:
				determinate = true
				skip = true
			case cpeUnproven:
				skip = true
			}
		}
		if skip {
			continue
		}
		determinate = true

		// The row's version attribute is a discrete affected version, not an
		// identity attribute, and it is folded with update because
		// version=2.14.0 update=rc1 is the single version 2.14.0-rc1. A
		// wildcard anywhere in the pair makes it a pattern rather than a
		// version, and the two are kept apart so that no comparator is ever
		// asked to order "2.*".
		literalVersion, pattern := "", ""
		versionStated := row.version != "*" && row.version != "-"
		if versionStated {
			stated := row.version
			if row.update != "*" && row.update != "-" {
				stated += "-" + row.update
			}
			if hasWildcard(stated) {
				pattern = stated
			} else {
				literalVersion = unquoteCPE(stated)
			}
		}

		unproven, disjoint := cpeConstraints(row, comp, !versionStated)
		if disjoint != "" {
			continue
		}

		// The version and the constraints come from the same CPE and must leave
		// together. Keeping only the smallest constraint set across the whole
		// row decouples them: an ANY-version CPE whose bounds live in Ranges
		// carries no constraints, and it would silently clear the "only under
		// WordPress" condition attached to the sibling CPE whose version
		// literal is the thing that actually matched the component. That turns
		// a conditional possible into an unconditional confirmed, on evidence
		// the row never gave.
		if literalVersion != "" {
			out.versions = append(out.versions, discreteVersion{value: literalVersion, unproven: unproven})
		}
		if pattern != "" {
			out.patterns = append(out.patterns, discreteVersion{value: pattern, unproven: unproven})
		}
		if !matched || len(unproven) < len(out.unproven) {
			out.unproven = unproven
		}
		matched = true
	}

	switch {
	case matched:
		out.relation = cpeSatisfied
	case determinate:
		out.relation = cpeDisjoint
	}
	return out
}

// cpeConstraints relates the configuration attributes of one stored CPE to
// the component's: everything but part, vendor, product and version, which
// carry identity and the affected version and are judged elsewhere.
//
// disjoint names the first attribute the component contradicts, spelled the
// way unproven spells a condition, so a reason can quote it; it is empty when
// nothing is contradicted. withUpdate adds update to the set. It is left out
// when the row states a version, because version=2.14.0 update=rc1 is the
// single version 2.14.0-rc1 and the update has already been folded into it.
func cpeConstraints(row, comp cpeAttrs, withUpdate bool) (unproven []string, disjoint string) {
	constraints := []struct{ name, value string }{
		{"edition", row.edition}, {"language", row.language},
		{"sw_edition", row.swEdition}, {"target_sw", row.targetSW},
		{"target_hw", row.targetHW}, {"other", row.other},
	}
	if withUpdate {
		constraints = append(constraints, struct{ name, value string }{"update", row.update})
	}
	for _, c := range constraints {
		switch cpeAttrRelation(c.value, cpeAttrOf(comp, c.name)) {
		case cpeDisjoint:
			if disjoint == "" {
				disjoint = c.name + "=" + unquoteCPE(c.value)
			}
		case cpeUnproven:
			unproven = append(unproven, c.name+"="+unquoteCPE(c.value))
		}
	}
	return unproven, disjoint
}

// carrierConstraints relates the configuration attributes of the CPE that
// carried a version window to the component, for a source that states its
// windows per applicability criteria.
//
// The carrier's identity attributes are not consulted: the parser grouped the
// window under this row's vendor and product from the same criteria string,
// and identity has already been decided by whichever channel had data. Only
// the configuration attributes matter, because they are what the window is
// conditional on. A component that states no CPE leaves every attribute ANY,
// so every condition the carrier names is unproven, exactly as it would be
// for a literal version listed by the same CPE. ok is false when the carrier
// is not a CPE at all, in which case the window is unconditional.
func carrierConstraints(carrier, componentCPE string) (unproven []string, disjoint string, ok bool) {
	row, ok := parseCPE(carrier)
	if !ok {
		return nil, "", false
	}
	comp, ok := parseCPE(componentCPE)
	if !ok {
		comp = cpeAttrs{}.normalized()
	}
	versionStated := row.version != "*" && row.version != "-"
	unproven, disjoint = cpeConstraints(row, comp, !versionStated)
	return unproven, disjoint, true
}

func cpeAttrOf(a cpeAttrs, name string) string {
	switch name {
	case "update":
		return a.update
	case "edition":
		return a.edition
	case "language":
		return a.language
	case "sw_edition":
		return a.swEdition
	case "target_sw":
		return a.targetSW
	case "target_hw":
		return a.targetHW
	case "other":
		return a.other
	}
	return "*"
}

// splitEscaped splits on sep while honouring the CPE backslash quoting, so that
// a product literal containing an escaped colon does not split into two fields.
func splitEscaped(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			i++
			cur.WriteByte(s[i])
		case s[i] == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}

// unquoteCPE removes the CPE quoting so that literals compare by their meaning.
func unquoteCPE(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

type globToken struct {
	r    rune
	kind int // 0 literal, 1 single, 2 run
}

// globMatch matches a quoted CPE literal containing '*' and '?' against a value.
func globMatch(pattern, value string) bool {
	var toks []globToken
	esc := false
	for _, r := range strings.ToLower(pattern) {
		switch {
		case esc:
			toks = append(toks, globToken{r: r})
			esc = false
		case r == '\\':
			esc = true
		case r == '?':
			toks = append(toks, globToken{kind: 1})
		case r == '*':
			toks = append(toks, globToken{kind: 2})
		default:
			toks = append(toks, globToken{r: r})
		}
	}
	return globAt(toks, []rune(strings.ToLower(value)))
}

func globAt(toks []globToken, s []rune) bool {
	for len(toks) > 0 {
		switch toks[0].kind {
		case 2:
			for i := 0; i <= len(s); i++ {
				if globAt(toks[1:], s[i:]) {
					return true
				}
			}
			return false
		case 1:
			if len(s) == 0 {
				return false
			}
		default:
			if len(s) == 0 || s[0] != toks[0].r {
				return false
			}
		}
		toks, s = toks[1:], s[1:]
	}
	return len(s) == 0
}
