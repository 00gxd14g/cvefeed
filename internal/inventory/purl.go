package inventory

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// purl is a decomposed package URL (https://github.com/package-url/purl-spec).
type purl struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// parsePURL decomposes a package URL, reporting whether it is one at all.
//
// The separators are split right to left, in the order the specification
// prescribes, because they are ambiguous read the other way: a namespace
// contains slashes (pkg:golang/github.com/x/y), a version contains almost
// anything (pkg:deb/debian/openssl@3.0.11-1~deb12u2), and a subpath contains
// both.
func parsePURL(s string) (purl, bool) {
	s = strings.TrimSpace(s)
	if len(s) < len("pkg:") || !strings.EqualFold(s[:4], "pkg:") {
		return purl{}, false
	}
	rest := s[4:]

	var p purl
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		p.Subpath = strings.Trim(rest[i+1:], "/")
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "?"); i >= 0 {
		p.Qualifiers = parseQualifiers(rest[i+1:])
		rest = rest[:i]
	}
	rest = strings.TrimLeft(rest, "/")

	i := strings.Index(rest, "/")
	if i < 0 {
		return purl{}, false
	}
	p.Type = strings.ToLower(rest[:i])
	rest = rest[i+1:]

	// The version separator is the '@' that follows the last '/', not simply
	// the last '@'. An npm scope is part of the namespace and starts with one:
	// pkg:npm/@babel/core has no version at all, and treating its scope marker
	// as the separator left the component with no name, no purl and no
	// ecosystem — silently dropping every scoped package in the inventory.
	if slash := strings.LastIndex(rest, "/"); true {
		if j := strings.LastIndex(rest, "@"); j > slash {
			p.Version = decodePURL(rest[j+1:])
			rest = rest[:j]
		}
	}
	rest = strings.Trim(rest, "/")
	if j := strings.LastIndex(rest, "/"); j >= 0 {
		p.Namespace = decodePURLPath(rest[:j])
		p.Name = decodePURL(rest[j+1:])
	} else {
		p.Name = decodePURL(rest)
	}
	if p.Type == "" || p.Name == "" {
		return purl{}, false
	}
	return p, true
}

func parseQualifiers(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, "&") {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" || v == "" {
			continue
		}
		out[k] = decodePURL(v)
	}
	return out
}

// decodePURL percent-decodes one purl segment. A segment that is not valid
// percent-encoding is kept verbatim: a stray '%' in a package name is a reason
// to read the name literally, not to drop the component from the scan.
func decodePURL(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

func decodePURLPath(s string) string {
	parts := strings.Split(s, "/")
	for i, part := range parts {
		parts[i] = decodePURL(part)
	}
	return strings.Join(parts, "/")
}

// normalisePURL lowercases the scheme and the type and leaves every other byte
// exactly as upstream wrote it. An input that is not a package URL yields "".
//
// This is deliberately not the canonicalisation of the matching spec. That one
// lowercases names per ecosystem, drops qualifiers and strips the version;
// internal/match applies it to both sides of a comparison at once. Applying
// half of it here, to the inventory side only, would break equality with the
// very rows it exists to match.
func normalisePURL(s string) string {
	s = strings.TrimSpace(s)
	p, ok := parsePURL(s)
	if !ok {
		return ""
	}
	rest := strings.TrimLeft(s[4:], "/")
	return "pkg:" + p.Type + rest[strings.Index(rest, "/"):]
}

// buildPURL assembles a package URL from parts already known to be correct.
// Qualifiers are emitted in key order, which is what the specification calls
// canonical and what makes two collectors of the same host agree byte for byte.
func buildPURL(typ, namespace, name, version string, qualifiers map[string]string) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(strings.ToLower(typ))
	b.WriteString("/")
	if namespace != "" {
		b.WriteString(escapePURL(strings.ToLower(namespace)))
		b.WriteString("/")
	}
	b.WriteString(escapePURL(name))
	if version != "" {
		b.WriteString("@")
		b.WriteString(escapePURL(version))
	}
	keys := make([]string, 0, len(qualifiers))
	for k, v := range qualifiers {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			b.WriteString("?")
		} else {
			b.WriteString("&")
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(escapePURL(qualifiers[k]))
	}
	return b.String()
}

// escapePURL encodes only the characters that would otherwise be read as purl
// syntax.
//
// It deliberately leaves '+', '~' and ':' alone. Those occur in real Debian and
// RPM versions (1.2.3-1+b2, 3.0.11-1~deb12u2, 1:3.0.7-27.el9_5), no producer in
// the field encodes them, and percent-encoding one side of an equality test is
// how a match is lost.
func escapePURL(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', '?', '#', '@', '%', ' ', '&':
			fmt.Fprintf(&b, "%%%02X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// packageName reconstructs the name the ecosystem itself uses, which is the
// string an advisory's product field carries. Only the purl knows how the two
// halves join: Maven writes group:artifact, npm writes @scope/name, and a
// Debian namespace is the distribution rather than part of the name at all.
func packageName(p purl) string {
	if p.Namespace == "" {
		return p.Name
	}
	switch p.Type {
	case "maven":
		return p.Namespace + ":" + p.Name
	case "npm":
		return "@" + strings.TrimPrefix(p.Namespace, "@") + "/" + p.Name
	case "deb", "rpm", "apk", "alpm", "generic", "docker", "oci", "conan":
		return p.Name
	default:
		return p.Namespace + "/" + p.Name
	}
}

// vendorFromPURL reads the namespace as a supplier, which it is for a Maven
// group or an npm scope and is not for a Debian or Alpine namespace: those name
// the distribution, and offering "debian" as the upstream vendor invites a
// vendor+product match against rows whose vendor means the upstream project.
func vendorFromPURL(p purl) string {
	switch p.Type {
	case "deb", "rpm", "apk", "alpm", "generic", "docker", "oci":
		return ""
	}
	return strings.TrimPrefix(p.Namespace, "@")
}

// purlEcosystem maps a purl type onto the OSV ecosystem that publishes
// advisories for it. Types whose ecosystem depends on the namespace as well —
// deb, rpm, apk — are resolved by distroEcosystem instead.
var purlEcosystem = map[string]string{
	"npm":            "npm",
	"pypi":           "PyPI",
	"maven":          "Maven",
	"golang":         "Go",
	"cargo":          "crates.io",
	"gem":            "RubyGems",
	"nuget":          "NuGet",
	"composer":       "Packagist",
	"hex":            "Hex",
	"pub":            "Pub",
	"cran":           "CRAN",
	"hackage":        "Hackage",
	"swift":          "SwiftURL",
	"opam":           "opam",
	"julia":          "Julia",
	"githubactions":  "GitHub Actions",
	"github-actions": "GitHub Actions",
}

// ecosystemForPURL derives the OSV ecosystem family, and where it can be spelled
// with confidence the release too.
//
// A type with no OSV ecosystem yields "". That is not a loss: an ecosystem the
// corpus never uses makes the matcher's ecosystem-conflict rule reject every
// row it is compared against, so an unknown ecosystem is safer than a guessed
// one.
func ecosystemForPURL(p purl) string {
	if eco, ok := purlEcosystem[p.Type]; ok {
		return eco
	}
	switch p.Type {
	case "deb", "rpm", "apk":
		return distroEcosystem(p.Namespace, p.Qualifiers["distro"])
	}
	return ""
}

// componentFromPURL builds the component a bare package URL describes. The purl
// is the only evidence available, so every field is derived from it or left
// empty; nothing here is inferred.
func componentFromPURL(p purl, normalised, origin string) match.Component {
	return match.Component{
		Name:      packageName(p),
		Version:   p.Version,
		Vendor:    vendorFromPURL(p),
		Ecosystem: ecosystemForPURL(p),
		PURL:      normalised,
		Origin:    origin,
	}
}
