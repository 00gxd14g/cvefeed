package collect

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// csafProduct is one leaf of a CSAF product tree, kept with the identity the
// document supplied rather than only the name it displays.
//
// The distinction is the difference between a statement that can match and one
// that cannot. Red Hat's advisories name a leaf
//
//	glibc-langpack-kok-0:2.34-28.el9_0.6.s390x as a component of
//	Red Hat Enterprise Linux AppStream EUS (v.9.0)
//
// and put beside it
//
//	pkg:rpm/redhat/glibc-langpack-kok@2.34-28.el9_0.6?arch=s390x
//
// The first is a package, an epoch, a version, a release, an architecture and a
// parent product flattened into one string: nothing reports a component by that
// name, and the version that a range would be tested against is inside it
// rather than in a version field. The second is exactly what the matcher wants.
// Keeping only the first produced 13.6 million statements — more than half the
// table — that could never produce a finding.
type csafProduct struct {
	Name    string
	Vendor  string
	Product string
	Version string
	PURL    string
	CPE     string
}

// productTreeDoc is the shape parseProductTree reads.
type productTreeDoc struct {
	Branches      []productBranch   `json:"branches"`
	Relationships []productRelation `json:"relationships"`
	FullProducts  []productLeaf     `json:"full_product_names"`
}

// productRelation is CSAF's way of saying "this package, inside that platform".
// Red Hat's product_status refers to these composite ids rather than to the
// branch leaves, and the leaf they point at through product_reference is where
// the purl lives.
type productRelation struct {
	FullProductName productLeaf `json:"full_product_name"`
	ProductRef      string      `json:"product_reference"`
	RelatesTo       string      `json:"relates_to_product_reference"`
}

type productBranch struct {
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  *productLeaf    `json:"product"`
	Branches []productBranch `json:"branches"`
}

type productLeaf struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    *struct {
		PURL string `json:"purl"`
		CPE  string `json:"cpe"`
	} `json:"product_identification_helper"`
}

// parseProductTree walks the branches and returns every leaf by product id.
//
// The categories are the structure: vendor, product_family, product_name,
// product_version and architecture each say what their name means, so the path
// to a leaf carries the decomposition that its display name has thrown away.
func parseProductTree(raw []byte) map[string]csafProduct {
	var doc productTreeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := map[string]csafProduct{}
	var walk func(branches []productBranch, path map[string]string)
	walk = func(branches []productBranch, path map[string]string) {
		for _, b := range branches {
			// A copy per branch: siblings must not inherit each other's names.
			next := make(map[string]string, len(path)+1)
			for k, v := range path {
				next[k] = v
			}
			if b.Category != "" {
				next[b.Category] = b.Name
			}
			if b.Product != nil && b.Product.ProductID != "" {
				out[b.Product.ProductID] = leafFrom(*b.Product, next)
			}
			walk(b.Branches, next)
		}
	}
	walk(doc.Branches, map[string]string{})

	for _, p := range doc.FullProducts {
		if p.ProductID != "" {
			out[p.ProductID] = leafFrom(p, map[string]string{})
		}
	}

	// A relationship inherits the identity of the component it names. Its own
	// full_product_name is prose — "X as a component of Y" — and carries no
	// identifiers, so without this every relationship id resolves to that
	// string and matches nothing.
	for _, rel := range doc.Relationships {
		id := rel.FullProductName.ProductID
		if id == "" {
			continue
		}
		// The relationship's own full_product_name is prose — "X as a component
		// of Y" — and carries no identifiers. X is the component and Y is the
		// platform it sits in, and only X is this statement's identity.
		//
		// In order of what can be matched against: the component leaf's own
		// identity where the tree has one, then the NEVRA that
		// product_reference spells out for an RPM, then that reference as it
		// stands, which for a container advisory is an image digest and for
		// anything else is at least the id the advisory uses. The prose is kept
		// as the name a reader sees and is never the product.
		p := csafProduct{Name: rel.FullProductName.Name}
		component, known := out[rel.ProductRef]
		switch name, version, isNEVRA := splitNEVRA(rel.ProductRef); {
		case known && component.PURL != "":
			// The purl is the one identity that is already split into a
			// package and a version; only it earns the component precedence.
			prose := p.Name
			p = component
			if prose != "" {
				p.Name = prose
			}
		case isNEVRA:
			p.Product, p.Version = name, version
			if known {
				p.Vendor, p.CPE = component.Vendor, component.CPE
			}
		case known:
			prose := p.Name
			p = component
			if prose != "" {
				p.Name = prose
			}
		case rel.ProductRef != "":
			p.Product = rel.ProductRef
		}
		if p.Product == "" {
			p.Product = id
		}
		out[id] = p
	}
	return out
}

// leafFrom builds a product from its identifiers, preferring what a machine can
// read over what a person can.
func leafFrom(leaf productLeaf, path map[string]string) csafProduct {
	p := csafProduct{
		Name:    leaf.Name,
		Vendor:  path["vendor"],
		Version: path["product_version"],
	}
	if leaf.Helper != nil {
		p.PURL = leaf.Helper.PURL
		p.CPE = leaf.Helper.CPE
	}

	// A purl names the package and its version apart from each other, which no
	// display name does. It wins wherever the advisory supplied one, which for
	// Red Hat is 85 leaves of 86 — and those are exactly the leaves whose names
	// are an unusable NEVRA-plus-parent-product string.
	if name, version, ok := splitPURL(p.PURL); ok {
		p.Product = name
		p.Version = version
		return p
	}

	// Without a purl, a Red Hat leaf still names itself by NEVRA — the
	// product_version branch is called ceph-mds-debuginfo-2:17.2.6-216.el8cp
	// .x86_64 and so is the leaf — which put that whole string in both the
	// product and the version. The epoch's colon makes it splittable.
	for _, candidate := range []string{leaf.Name, path["product_version"]} {
		if name, version, ok := splitNEVRA(candidate); ok {
			p.Product, p.Version = name, version
			return p
		}
	}

	// Otherwise the leaf's own name, which for a vendor advisory is the product
	// as its publisher writes it — Siemens names a leaf "SIMATIC S7-1500" under
	// a branch called "SIMATIC S7", and the leaf is the specific one.
	switch {
	case leaf.Name != "":
		p.Product = leaf.Name
	default:
		p.Product = path["product_name"]
	}
	return p
}

// splitPURL pulls the package name and version out of a package URL.
func splitPURL(raw string) (name, version string, ok bool) {
	if !strings.HasPrefix(raw, "pkg:") {
		return "", "", false
	}
	body := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return "", "", false
	}
	version, err := url.PathUnescape(body[at+1:])
	if err != nil {
		version = body[at+1:]
	}
	path := body[:at]
	slash := strings.LastIndex(path, "/")
	if slash < 0 {
		return "", "", false
	}
	name, err = url.PathUnescape(path[slash+1:])
	if err != nil {
		name = path[slash+1:]
	}
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// nevra matches an RPM package reference: name-epoch:version-release.arch.
//
// The epoch's colon is what makes this parseable at all. A package name may
// contain any number of hyphens — glibc-langpack-kok — so nothing else in the
// string says where the name ends and the version begins.
var nevra = regexp.MustCompile(`^(.+)-(\d+):([^-\s]+)-(.+)\.([a-z0-9_]+)$`)

// splitNEVRA pulls the package name and its version-release out of an RPM
// reference, dropping the epoch and the architecture.
//
// The epoch is dropped because internal/match elides epochs when only one side
// states one, and the architecture because it is not part of what a version
// range compares — a statement about x86_64 and one about aarch64 are the same
// statement about the same build.
func splitNEVRA(s string) (name, version string, ok bool) {
	m := nevra.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", false
	}
	return m[1], m[3] + "-" + m[4], true
}
