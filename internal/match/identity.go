package match

import (
	"fmt"
	"sort"
	"strings"
)

// identityGrade records how strongly the row was tied to the component. It is
// one of the two axes confidence is built from; the other is how much the
// version comparison actually proved.
type identityGrade int

const (
	idNone identityGrade = iota
	idWeak
	idModerate
	idStrong
	idExact
)

func (g identityGrade) String() string {
	switch g {
	case idExact:
		return "exact"
	case idStrong:
		return "strong"
	case idModerate:
		return "moderate"
	case idWeak:
		return "weak"
	}
	return "none"
}

// identity is the outcome of the identity test.
type identity struct {
	grade   identityGrade
	channel string
	reason  string
	// unproven names the conditions the row attaches that the inventory has not
	// established: a CPE target_sw, an unknown distro release. Each caps the
	// finding at possible, because an unproven condition is a question for an
	// operator rather than a verdict.
	unproven []string
	// componentFamily is the component's own ecosystem family token, kept so
	// Evaluate can tell a distribution build from an upstream artefact.
	componentFamily string
	// ecosystem is the published ecosystem name handed to version.SchemeFor.
	// Knowing it is what turns a CUSTOM-typed distro range from undecidable
	// into decidable: a CNA writing CUSTOM does not change how dpkg orders
	// 1.1.1n-0+deb11u5.
	ecosystem string
	// cpeVersions are literal version attributes of the row CPEs that matched,
	// each still carrying the constraints of the configuration that named it.
	cpeVersions []discreteVersion
	// cpePatterns are the wildcarded version attributes of the row CPEs that
	// matched (2.*), carried the same way and globbed rather than compared.
	cpePatterns []discreteVersion
}

// identify runs the channel ladder of the identity test.
//
// The channels are ordered by strength and only the strongest channel on which
// both sides carry data is evaluated. A mismatch there ends the test: if both
// parties named the package precisely and the names differ, that is positive
// evidence of non-applicability, and letting a weaker channel rescue it puts
// pkg:npm/marked and pkg:pypi/marked back together under Product "marked".
func identify(c Component, a Affected) identity {
	// Parsed once and threaded through. identify runs for every candidate row
	// of every component, and the ecosystem derivation needs exactly the purls
	// the purl channel needs; re-deriving them two lines later was a third of
	// this function's allocations for no answer that was not already known.
	compPURLs := componentPURLs(c)
	rowP, rowHasPURL := parsePURL(a.PURL)

	compFam, compRel := componentEcosystem(c, compPURLs)
	rowFam, rowRel := rowEcosystem(a, rowP, rowHasPURL)

	// Ecosystem conflict is a rejection, not a demotion. It is the largest
	// single false-positive control available here: roughly 350,000 rows come
	// from distro and hardened-image vendors re-issuing upstream CVEs for their
	// own builds, and those rebuilds are not each other's software.
	if compFam != "" && rowFam != "" && compFam != rowFam {
		return identity{reason: fmt.Sprintf(
			"ecosystem conflict: the component is a %s package and the statement is about %s, which is a different ecosystem",
			osvEcosystemName(compFam), osvEcosystemName(rowFam))}
	}

	releaseUnknown := false
	if compFam != "" && compFam == rowFam && rowRel != "" {
		switch {
		case compRel == rowRel:
		case compRel == "" || !comparableRelease(compRel, rowRel):
			releaseUnknown = true
		default:
			return identity{reason: fmt.Sprintf(
				"release conflict: the statement is about %s %s and the component comes from %s %s; packages are rebased between releases and their version strings are not comparable across them",
				osvEcosystemName(rowFam), rowRel, osvEcosystemName(compFam), compRel)}
		}
	}

	eco := osvEcosystemName(rowFam)
	if rowFam == "" {
		eco = osvEcosystemName(compFam)
	}

	settle := func(id identity) identity {
		id.ecosystem = eco
		id.componentFamily = compFam
		if releaseUnknown {
			if id.grade > idWeak {
				id.grade--
			}
			id.unproven = append(id.unproven, "distro_release")
		}
		sort.Strings(id.unproven)
		if len(id.unproven) > 0 {
			id.reason += ", with " + strings.Join(id.unproven, " and ") + " unproven"
		}
		id.reason += " (" + id.grade.String() + " identity)"
		return id
	}

	// Channel 1: purl. The only channel with no known systematic collision
	// mode, because one token fixes the ecosystem, the namespace and the name.
	if rowHasPURL && len(compPURLs) > 0 {
		for _, cp := range compPURLs {
			if cp.Canonical == rowP.Canonical {
				return settle(identity{
					grade:   idExact,
					channel: "purl",
					reason:  fmt.Sprintf("identity: purl %s equals the statement's %s", cp.Canonical, rowP.Canonical),
				})
			}
		}
		return identity{reason: fmt.Sprintf(
			"purl mismatch: the component is %s and the statement is about %s",
			compPURLs[0].Canonical, rowP.Canonical)}
	}

	// Channel 2: CPE.
	if strings.TrimSpace(c.CPE) != "" && len(a.CPEs) > 0 {
		ch := matchCPEs(c.CPE, a.CPEs)
		switch ch.relation {
		case cpeSatisfied:
			grade := idExact
			if len(ch.unproven) > 0 {
				grade = idStrong
			}
			return settle(identity{
				grade:       grade,
				channel:     "cpe",
				unproven:    ch.unproven,
				cpeVersions: ch.versions,
				cpePatterns: ch.patterns,
				reason:      fmt.Sprintf("identity: the component's %s matches a vulnerable configuration listed on the statement", c.CPE),
			})
		case cpeDisjoint:
			return identity{reason: fmt.Sprintf(
				"cpe mismatch: none of the %d vulnerable configurations on the statement admit %s",
				len(a.CPEs), c.CPE)}
		}
		// Indeterminate: every stored CPE named product or vendor ANY, so the
		// channel carries no identity at all and a weaker one may decide.
	}

	// Channel 3: ecosystem + name.
	if compFam != "" && rowFam != "" && c.Name != "" && a.Product != "" {
		left, right := ecosystemName(compFam, c.Name), ecosystemName(rowFam, a.Product)
		if left == right {
			grade := idStrong
			if losslessEcosystems[rowFam] {
				grade = idExact
			}
			return settle(identity{
				grade:   grade,
				channel: "ecosystem_name",
				reason:  fmt.Sprintf("identity: %s package %q is the statement's %s package %q", osvEcosystemName(compFam), c.Name, osvEcosystemName(rowFam), a.Product),
			})
		}
		return identity{reason: fmt.Sprintf(
			"name mismatch within %s: the component is %q and the statement is about %q",
			osvEcosystemName(rowFam), left, right)}
	}

	// Channel 4: vendor + product.
	if c.Vendor != "" && a.Vendor != "" && c.Name != "" && a.Product != "" {
		if foldVendor(c.Vendor) == foldVendor(a.Vendor) && foldName(c.Name) == foldName(a.Product) {
			return settle(identity{
				grade:   idModerate,
				channel: "vendor_product",
				reason:  fmt.Sprintf("identity: vendor %q product %q matches the statement's vendor %q product %q", c.Vendor, c.Name, a.Vendor, a.Product),
			})
		}
		return identity{reason: fmt.Sprintf(
			"vendor/product mismatch: %q/%q is not %q/%q", c.Vendor, c.Name, a.Vendor, a.Product)}
	}

	// Channel 5: bare name. Reliable enough to raise a question, never enough
	// to answer one, so it is capped at possible in every case.
	if c.Name != "" && a.Product != "" {
		if foldName(c.Name) == foldName(a.Product) {
			return settle(identity{
				grade:   idWeak,
				channel: "name",
				reason:  fmt.Sprintf("identity: product name %q only, with no ecosystem, purl, cpe or vendor on either side to confirm it", c.Name),
			})
		}
		return identity{reason: fmt.Sprintf("name mismatch: %q is not %q", c.Name, a.Product)}
	}

	return identity{reason: "no identity channel carried data on both sides"}
}

// componentPURLs returns every purl the component can be known by.
//
// Origin is included when it holds one: dpkg, rpm and apk each ship binary
// packages built from a differently named source package, and distro advisories
// are filed against the source. Testing only the binary name misses every
// advisory filed against openssl for an installed libssl3.
func componentPURLs(c Component) []purl {
	var out []purl
	for _, s := range []string{c.PURL, c.Origin} {
		if p, ok := parsePURL(s); ok {
			out = append(out, p)
		}
	}
	return out
}

func componentEcosystem(c Component, purls []purl) (family, release string) {
	family, release = splitEcosystem(c.Ecosystem)
	if family == "" {
		for _, p := range purls {
			if f, r := purlEcosystem(p); f != "" {
				return f, r
			}
		}
		return "", ""
	}
	if release == "" {
		for _, p := range purls {
			if f, r := purlEcosystem(p); f == family && r != "" {
				return family, r
			}
		}
	}
	return family, release
}

func rowEcosystem(a Affected, p purl, hasPURL bool) (family, release string) {
	family, release = splitEcosystem(a.Ecosystem)
	if family == "" && hasPURL {
		family, release = purlEcosystem(p)
	}
	// GIT is not an ecosystem. NVD-converted OSV records carry it in place of
	// one, with no package and only commit ranges, so treating it as a family
	// would put it in conflict with every real ecosystem and suppress the CPE
	// channel that is their only usable identity.
	if family == "git" {
		return "", ""
	}
	return family, release
}

// comparableRelease reports whether two release identifiers can be declared
// different.
//
// Debian is "12" in OSV and "bookworm" in os-release. Without a codename table
// those cannot be shown to disagree, and rejecting the row over a spelling
// difference would hide real findings. An unresolvable pair is therefore
// treated as an unknown release: the row still matches, one grade lower and
// capped at possible with distro_release named as unproven.
func comparableRelease(a, b string) bool {
	digit := func(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }
	return digit(a) && digit(b)
}

// corporateSuffixes are stripped from a vendor before comparison. They are
// legal-entity noise: "Acme" and "Acme Inc." are one vendor.
var corporateSuffixes = map[string]bool{
	"inc": true, "corp": true, "corporation": true, "ltd": true, "llc": true,
	"gmbh": true, "ag": true, "sa": true, "bv": true, "co": true, "company": true,
	"foundation": true, "project": true,
}

// foldName folds case and separators, and nothing else.
//
// NFKC normalisation belongs here per the specification but is not in the
// standard library, and hand-rolled transliteration would fold characters that
// name different products. It is left undone deliberately: the cost is a missed
// match, never an invented one. Stemming, singularisation and dropping
// version-like tokens are forbidden for the same reason, and no fuzzy matching
// of any kind is permitted in the identity test.
func foldName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	sep := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch r {
		case ' ', '\t', '_', '.', '/', '-':
			sep = true
		default:
			if sep && b.Len() > 0 {
				b.WriteByte('-')
			}
			sep = false
			b.WriteRune(r)
		}
	}
	return b.String()
}

func foldVendor(s string) string {
	tokens := strings.Split(foldName(s), "-")
	for len(tokens) > 1 && tokens[0] == "the" {
		tokens = tokens[1:]
	}
	for len(tokens) > 1 && corporateSuffixes[tokens[len(tokens)-1]] {
		tokens = tokens[:len(tokens)-1]
	}
	return strings.Join(tokens, "-")
}
