package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// ParseSPDX reads an SPDX 2.2 or 2.3 JSON document.
//
// SPDX 3.x is refused rather than attempted. Its serialisation is structurally
// different, so a 2.x reader finds almost nothing in it and reports an empty
// inventory, which reads exactly like a clean scan.
func ParseSPDX(r io.Reader) ([]match.Component, error) {
	doc, err := readDocument(r, 0)
	if err != nil {
		return nil, err
	}
	if err := rejectXML(doc); err != nil {
		return nil, err
	}

	var d struct {
		SPDXVersion string            `json:"spdxVersion"`
		SPDXID      string            `json:"SPDXID"`
		Context     json.RawMessage   `json:"@context"`
		Packages    []json.RawMessage `json:"packages"`
		Files       []json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("inventory: spdx: decode document: %w", err)
	}

	switch {
	case len(d.Context) > 0, strings.HasPrefix(d.SPDXVersion, "SPDX-3"):
		return nil, errors.New("inventory: SPDX 3.x is not supported by scan/1; its serialisation is structurally different and a 2.x reader would silently find almost nothing in it. Re-export as SPDX 2.3 JSON")
	case spdxOldRe.MatchString(d.SPDXVersion):
		return nil, fmt.Errorf("inventory: %s is not supported by scan/1; re-export as SPDX 2.3 JSON", d.SPDXVersion)
	case d.SPDXVersion == "":
		// Tools do omit it. packages[] and SPDXID together are enough to know
		// what this is, so read it as 2.3 rather than refusing an inventory
		// over a missing header field.
		if len(d.Packages) == 0 || d.SPDXID == "" {
			return nil, errors.New("inventory: spdx: no spdxVersion and no packages[]; this is not an SPDX 2.x document")
		}
	case !spdx2xRe.MatchString(d.SPDXVersion):
		return nil, fmt.Errorf("inventory: spdx: unsupported version %q; scan/1 reads SPDX-2.2 and SPDX-2.3", d.SPDXVersion)
	}

	out := make([]match.Component, 0, len(d.Packages))
	for _, raw := range d.Packages {
		var p spdxPackage
		// A type error still leaves every well-typed field populated, so a
		// package whose versionInfo is a number keeps its name and its
		// externalRefs — which is where the purl and CPE identity live.
		// Discarding it outright loses a scannable component; keeping it
		// unconditionally adds a nameless, versionless row that can never
		// produce a finding. So it is kept only when what survived is still
		// enough to scan with.
		if err := json.Unmarshal(raw, &p); err != nil {
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) || !p.scannable() {
				continue
			}
		}
		if c, ok := p.component(); ok {
			out = append(out, c)
		}
	}
	// files[] are not components here. File-level matching needs hash-based
	// identity, which scan/1 does not have, so a file-only document yields an
	// empty inventory rather than a name-matched one.
	return dedupe(out), nil
}

type spdxPackage struct {
	SPDXID       string            `json:"SPDXID"`
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	Supplier     string            `json:"supplier"`
	Originator   string            `json:"originator"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

// scannable reports whether enough of a partially decoded package survived to
// be worth testing: a version to compare, or an identity strong enough that the
// version can be recovered from it.
func (p spdxPackage) scannable() bool {
	if strings.TrimSpace(p.VersionInfo) != "" {
		return true
	}
	for _, ref := range p.ExternalRefs {
		if strings.TrimSpace(ref.Locator) != "" {
			return true
		}
	}
	return false
}

func (p spdxPackage) component() (match.Component, bool) {
	purlString := p.purl()
	parsed, havePURL := parsePURL(purlString)

	name := strings.TrimSpace(p.Name)
	if havePURL {
		// SPDX name is whatever the producer chose to display, and for several
		// of them that is a file path or an image tag. The purl carries the
		// package name its own ecosystem uses.
		name = packageName(parsed)
	}
	if name == "" {
		return match.Component{}, false
	}

	version := strings.TrimSpace(p.VersionInfo)
	if noAssertion(version) {
		version = ""
	}
	if version == "" && havePURL {
		version = parsed.Version
	}

	return match.Component{
		Name:      name,
		Version:   version,
		Vendor:    firstNonEmpty(spdxActor(p.Supplier), spdxActor(p.Originator), vendorFromPURL(parsed)),
		Ecosystem: ecosystemForPURL(parsed),
		PURL:      purlString,
		CPE:       p.cpe(),
		Origin:    "spdx",
	}, true
}

// purl returns the package's package URL.
//
// The category is spelled PACKAGE-MANAGER by 2.3 and PACKAGE_MANAGER by the
// 2.2-era tools that are still in service, and some producers file the purl
// under no recognisable category at all. All three are read, because a purl is
// the strongest identity in the document and losing it to a spelling costs the
// only channel with no known collision mode.
func (p spdxPackage) purl() string {
	fallback := ""
	for _, ref := range p.ExternalRefs {
		if !strings.EqualFold(strings.TrimSpace(ref.Type), "purl") {
			continue
		}
		normalised := normalisePURL(ref.Locator)
		if normalised == "" {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(ref.Category)) {
		case "PACKAGE-MANAGER", "PACKAGE_MANAGER":
			return normalised
		}
		if fallback == "" {
			fallback = normalised
		}
	}
	return fallback
}

// cpe returns the package's CPE, preferring a 2.3 string over a 2.2 URI that
// has to be rebound.
func (p spdxPackage) cpe() string {
	converted := ""
	for _, ref := range p.ExternalRefs {
		if !strings.EqualFold(strings.TrimSpace(ref.Category), "SECURITY") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(ref.Type)) {
		case "cpe23type":
			if c := cpe23(ref.Locator); c != "" {
				return c
			}
		case "cpe22type":
			if converted == "" {
				converted = cpe23(ref.Locator)
			}
		}
		// referenceType advisory, fix, url and swid also live under SECURITY.
		// They point at documents about the package, not at the package, so
		// they carry no identity.
	}
	return converted
}

// spdxActor strips the "Organization: " or "Person: " prefix SPDX requires on
// an actor, and reads NOASSERTION as the absence of a supplier rather than as a
// supplier named NOASSERTION.
func spdxActor(s string) string {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"Organization:", "Person:", "Tool:"} {
		if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			s = strings.TrimSpace(s[len(prefix):])
			break
		}
	}
	if noAssertion(s) {
		return ""
	}
	return s
}

func noAssertion(s string) bool {
	return strings.EqualFold(s, "NOASSERTION") || strings.EqualFold(s, "NONE")
}
