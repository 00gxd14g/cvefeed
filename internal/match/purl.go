package match

import (
	"net/url"
	"strings"
)

// purl is a Package URL split into the parts the scanner needs.
//
// Only Canonical takes part in the identity test. It carries no version and no
// qualifiers at all: arch, distro, epoch and repository_url describe a build,
// not a package, so an amd64 build and an arm64 build of one source package
// must compare equal, and an unknown qualifier must never break equality that
// would otherwise hold. The dropped-but-load-bearing values are kept in their
// own fields because the version test needs the epoch and the release
// constraint needs the distro.
type purl struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	Epoch     string
	Distro    string
	Canonical string
}

// parsePURL parses and canonicalises a package URL. It reports false rather
// than an error for anything it cannot read: a component may legitimately carry
// no purl, and a malformed one must simply not establish identity.
func parsePURL(s string) (purl, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return purl{}, false
	}
	rest := strings.TrimLeft(s[4:], "/")

	// The subpath is stripped before anything else. '#' is a purl component,
	// not a comment introducer, and pkg:golang/github.com/x/y#subpkg names the
	// module github.com/x/y.
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	var quals string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, quals = rest[:i], rest[i+1:]
	}
	// Only an '@' after the last '/' separates the version. The specification
	// requires an npm scope to be percent-encoded, but producers write
	// pkg:npm/@angular/core anyway, and on a version-less purl the last '@' is
	// then the scope's: taking it as the separator leaves "npm" as the whole
	// name path and rejects the purl, which drops the strongest identity the
	// SBOM supplied for every unversioned scoped package.
	var version string
	if i := strings.LastIndexByte(rest, '@'); i > strings.LastIndexByte(rest, '/') {
		version = unescape(rest[i+1:])
		rest = rest[:i]
	}

	var segs []string
	for _, seg := range strings.Split(rest, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	if len(segs) < 2 {
		return purl{}, false
	}

	p := purl{Type: strings.ToLower(segs[0]), Version: version}
	p.Name = unescape(segs[len(segs)-1])
	if len(segs) > 2 {
		parts := make([]string, 0, len(segs)-2)
		for _, seg := range segs[1 : len(segs)-1] {
			parts = append(parts, unescape(seg))
		}
		p.Namespace = strings.Join(parts, "/")
	}
	if p.Name == "" {
		return purl{}, false
	}

	for _, q := range strings.Split(quals, "&") {
		k, v, ok := strings.Cut(q, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "epoch":
			p.Epoch = unescape(v)
		case "distro":
			p.Distro = unescape(v)
		}
	}

	p.Namespace, p.Name = canonicalPURLName(p.Type, p.Namespace, p.Name)
	p.Canonical = "pkg:" + p.Type
	if p.Namespace != "" {
		p.Canonical += "/" + p.Namespace
	}
	p.Canonical += "/" + p.Name
	return p, true
}

func unescape(s string) string {
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	return s
}

// canonicalPURLName applies the name rules each ecosystem defines for itself.
//
// These are lossless canonicalisations published by the registry, not
// heuristics: PyPI really does resolve Foo.Bar and foo-bar to one project. The
// rule that governs the whole table is that a distinction the ecosystem treats
// as significant is never normalised away, which is why crates.io keeps '-' and
// '_' apart and Maven stays case-sensitive.
func canonicalPURLName(typ, namespace, name string) (string, string) {
	switch typ {
	case "pypi":
		return strings.ToLower(namespace), pep503(name)
	case "npm", "composer", "hex", "pub", "opam", "githubactions", "nuget",
		"deb", "rpm", "apk", "alpm", "generic", "docker", "oci", "conan", "bitnami":
		return strings.ToLower(namespace), strings.ToLower(name)
	case "golang":
		// A Go module path is case-sensitive except for the host, which is a
		// DNS name. Lowercasing the whole path would merge two distinct modules
		// on any case-sensitive forge.
		host, tail, ok := strings.Cut(namespace, "/")
		ns := strings.ToLower(host)
		if ok {
			ns += "/" + tail
		}
		return ns, name
	default:
		// maven, cargo, gem, cran, hackage, swift, julia and everything
		// unrecognised: compared exactly. Guessing a folding rule for an
		// ecosystem whose rules we do not know invents equalities.
		return namespace, name
	}
}

// pep503 is PyPI's normalised project name: lower(re.sub(r"[-_.]+", "-", name)).
func pep503(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	dash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			dash = true
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		b.WriteRune(r)
	}
	if dash {
		b.WriteByte('-')
	}
	return b.String()
}
