package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// maxNesting bounds component containment. Real BOMs nest three or four deep;
// a thousand is a hand-written document trying to exhaust the stack.
const maxNesting = 64

// ParseCycloneDX reads a CycloneDX JSON BOM.
//
// 1.4, 1.5 and 1.6 are the dialects this understands; 1.2 and 1.3 parse because
// their components[] shape is compatible, and a later specVersion parses on the
// same assumption. The XML serialisation is refused rather than ignored.
func ParseCycloneDX(r io.Reader) ([]match.Component, error) {
	doc, err := readDocument(r, 0)
	if err != nil {
		return nil, err
	}
	if err := rejectXML(doc); err != nil {
		return nil, err
	}

	// Metadata and components are decoded separately from the envelope so that
	// an unreadable metadata block cannot cost us the component list.
	var bom struct {
		BOMFormat   string            `json:"bomFormat"`
		SPDXVersion string            `json:"spdxVersion"`
		Metadata    json.RawMessage   `json:"metadata"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		return nil, fmt.Errorf("inventory: cyclonedx: decode document: %w", err)
	}
	// A document that says it is something else would otherwise parse to zero
	// components and no error, which reads exactly like a clean host.
	switch {
	case bom.SPDXVersion != "":
		return nil, fmt.Errorf("inventory: cyclonedx: this is an %s document, not a CycloneDX BOM", bom.SPDXVersion)
	case bom.BOMFormat != "" && !strings.EqualFold(bom.BOMFormat, "CycloneDX"):
		return nil, fmt.Errorf("inventory: cyclonedx: bomFormat is %q, not \"CycloneDX\"", bom.BOMFormat)
	}

	var out []match.Component
	// metadata.component is the subject of the BOM: the image, the application
	// or the operating system. Dropping it is how an image scan misses every
	// OS-level advisory about the image itself.
	var metadata struct {
		Component json.RawMessage `json:"component"`
	}
	if json.Unmarshal(bom.Metadata, &metadata) == nil && len(metadata.Component) > 0 {
		out = appendCycloneDXComponent(out, metadata.Component, 0)
	}
	for _, raw := range bom.Components {
		out = appendCycloneDXComponent(out, raw, 0)
	}
	return dedupe(out), nil
}

type cdxComponent struct {
	Type  string `json:"type"`
	Group string `json:"group"`
	Name  string `json:"name"`
	// Version is kept raw because producers write it as a number as often as
	// a string — "version": 1.36 for busybox — and a string field rejects the
	// number, dropping a component the document did state a version for.
	// cdxVersion reads either.
	Version    json.RawMessage   `json:"version"`
	PURL       string            `json:"purl"`
	CPE        string            `json:"cpe"`
	Publisher  string            `json:"publisher"`
	Author     string            `json:"author"`
	Authors    []json.RawMessage `json:"authors"`
	Supplier   json.RawMessage   `json:"supplier"`
	Evidence   json.RawMessage   `json:"evidence"`
	Components []json.RawMessage `json:"components"`
}

// appendCycloneDXComponent adds one component and everything nested inside it.
//
// Nesting in CycloneDX means containment, not dependency: a nested component is
// installed just as much as its parent, so it is emitted in its own right.
func appendCycloneDXComponent(out []match.Component, raw json.RawMessage, depth int) []match.Component {
	if depth > maxNesting {
		return out
	}
	var c cdxComponent
	// A type error is not a reason to discard the entry. encoding/json fills in
	// every well-typed field before it returns UnmarshalTypeError, so a
	// component that wrote its version as a number still has its name, its purl
	// and its nested children — and the purl carries the version anyway. The
	// only unrecoverable case is a document that is not an object at all.
	partial := false
	if err := json.Unmarshal(raw, &c); err != nil {
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) {
			return out
		}
		partial = true
	}
	// A partially decoded component is kept only when what survived is still
	// enough to scan with — a version to compare, or a purl or CPE the version
	// can be recovered from. Dropping it outright loses a real component;
	// keeping it unconditionally adds a row that can never produce a finding.
	if comp, ok := c.component(); ok && (!partial || c.scannable()) {
		out = append(out, comp)
	}
	// Children are visited whatever happened to the parent: nesting is
	// containment, and a malformed wrapper says nothing about what it contains.
	for _, child := range c.Components {
		out = appendCycloneDXComponent(out, child, depth+1)
	}
	return out
}

func (c cdxComponent) scannable() bool {
	return c.version() != "" ||
		strings.TrimSpace(c.PURL) != "" ||
		strings.TrimSpace(c.CPE) != ""
}

// version reads the version whether it was written as a JSON string or as a
// JSON number. A number is taken exactly as written — json.Number rather than
// float64 — because 1.10 and 1.1 are different releases and a float would
// make them the same one.
func (c cdxComponent) version() string {
	raw := bytes.TrimSpace(c.Version)
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return "" // an object, an array, null: nothing a version can be read from
	}
	return n.String()
}

func (c cdxComponent) component() (match.Component, bool) {
	purlString := normalisePURL(c.PURL)
	cpe := cpe23(c.CPE)
	for _, id := range c.identities() {
		switch strings.ToLower(strings.TrimSpace(id.Field)) {
		case "purl":
			if purlString == "" {
				purlString = normalisePURL(id.ConcludedValue)
			}
		case "cpe":
			if cpe == "" {
				cpe = cpe23(id.ConcludedValue)
			}
		}
	}

	p, havePURL := parsePURL(purlString)
	name := strings.TrimSpace(c.Name)
	if havePURL {
		// The purl spells the name the way its ecosystem does, which is the
		// spelling an advisory's product field carries: org.slf4j:slf4j-api,
		// not the artifact id alone.
		name = packageName(p)
	}
	if name == "" {
		return match.Component{}, false
	}

	version := c.version()
	if version == "" && havePURL {
		// Not a guess: the same document stated the version inside the purl.
		version = p.Version
	}

	// The group is the purl namespace by another name, and is spelled the way
	// vendorFromPURL spells it: an npm scope loses its "@", so that a BOM
	// with a group and one with only a purl name the same vendor for the same
	// package rather than "@angular" for one and "angular" for the other.
	group := strings.TrimPrefix(strings.TrimSpace(c.Group), "@")

	return match.Component{
		Name:      name,
		Version:   version,
		Vendor:    firstNonEmpty(group, c.supplierName(), c.Publisher, c.authorName(), vendorFromPURL(p)),
		Ecosystem: ecosystemForPURL(p),
		PURL:      purlString,
		CPE:       cpe,
		Origin:    "cyclonedx",
	}, true
}

// supplierName reads metadata.supplier.name, tolerating the producers that
// write the field as a bare string.
func (c cdxComponent) supplierName() string {
	var obj struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(c.Supplier, &obj) == nil {
		return obj.Name
	}
	var s string
	if json.Unmarshal(c.Supplier, &s) == nil {
		return s
	}
	return ""
}

// authorName reads the first author, which 1.6 models as objects and earlier
// versions as strings.
func (c cdxComponent) authorName() string {
	for _, raw := range c.Authors {
		var obj struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.Name != "" {
			return obj.Name
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return c.Author
}

type cdxIdentity struct {
	Field          string `json:"field"`
	ConcludedValue string `json:"concludedValue"`
}

// identities reads evidence.identity, which 1.5 defines as one object and 1.6
// as an array of them.
//
// Only concludedValue is read. evidence.occurrences and evidence.callstack
// record where a thing was seen rather than what it is, and a file path is not
// an identity.
func (c cdxComponent) identities() []cdxIdentity {
	var ev struct {
		Identity json.RawMessage `json:"identity"`
	}
	if json.Unmarshal(c.Evidence, &ev) != nil || len(ev.Identity) == 0 {
		return nil
	}
	var many []cdxIdentity
	if json.Unmarshal(ev.Identity, &many) == nil {
		return many
	}
	var one cdxIdentity
	if json.Unmarshal(ev.Identity, &one) == nil {
		return []cdxIdentity{one}
	}
	return nil
}
