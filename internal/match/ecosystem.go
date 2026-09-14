package match

import "strings"

// ecosystemAliases folds the several spellings of one ecosystem onto a single
// token, so that an OSV ecosystem name, a purl type and an os-release ID can be
// compared with ==. The comparison has to be exact once folded, because
// ecosystem conflict is a hard identity failure: roughly 350,000 corpus rows
// belong to distro and hardened-image ecosystems that rebuild the same
// upstreams, and a Chainguard row is not a statement about a Debian host.
var ecosystemAliases = map[string]string{
	"npm":            "npm",
	"pypi":           "pypi",
	"maven":          "maven",
	"go":             "go",
	"golang":         "go",
	"cargo":          "cargo",
	"crates.io":      "cargo",
	"crates":         "cargo",
	"gem":            "rubygems",
	"rubygems":       "rubygems",
	"nuget":          "nuget",
	"composer":       "packagist",
	"packagist":      "packagist",
	"hex":            "hex",
	"pub":            "pub",
	"cran":           "cran",
	"hackage":        "hackage",
	"swift":          "swifturl",
	"swifturl":       "swifturl",
	"opam":           "opam",
	"julia":          "julia",
	"githubactions":  "github actions",
	"github actions": "github actions",
	// pkg:github is the purl type OSV and GHSA use for actions, and is what
	// the version tables already map to that ecosystem; left unfolded it
	// conflicted with every "GitHub Actions" row it was meant to match.
	"github":  "github actions",
	"bitnami": "bitnami",

	"debian": "debian",
	"ubuntu": "ubuntu",
	// Mint and Raspbian ship Ubuntu's and Debian's packages; the advisories
	// that describe them are filed under the parent, and a family token of
	// their own put every such host in ecosystem conflict with its own
	// advisories. Mint numbers its releases on its own scale, though: see
	// ownReleaseNumbering.
	"linuxmint":                    "ubuntu",
	"linux mint":                   "ubuntu",
	"raspbian":                     "debian",
	"red hat":                      "redhat",
	"redhat":                       "redhat",
	"rhel":                         "redhat",
	"fedora":                       "fedora",
	"centos":                       "centos",
	"rocky linux":                  "rocky",
	"rocky":                        "rocky",
	"almalinux":                    "almalinux",
	"alma":                         "almalinux",
	"suse":                         "suse",
	"sles":                         "suse",
	"opensuse":                     "opensuse",
	"opensuse-leap":                "opensuse",
	"opensuse leap":                "opensuse",
	"opensuse tumbleweed":          "opensuse",
	"azure linux":                  "azurelinux",
	"azurelinux":                   "azurelinux",
	"mariner":                      "azurelinux",
	"cbl-mariner":                  "azurelinux",
	"openeuler":                    "openeuler",
	"mageia":                       "mageia",
	"photon os":                    "photon",
	"photon":                       "photon",
	"alpine":                       "alpine",
	"wolfi":                        "wolfi",
	"chainguard":                   "chainguard",
	"minimos":                      "minimos",
	"alpaquita":                    "alpaquita",
	"echo":                         "echo",
	"root":                         "root",
	"cleanstart":                   "cleanstart",
	"bellsoft hardened containers": "bellsoft",

	"linux":     "linux",
	"oss-fuzz":  "oss-fuzz",
	"android":   "android",
	"gsd":       "gsd",
	"uvi":       "uvi",
	"vscode":    "vscode",
	"maven.org": "maven",
}

// distroFamilies are the ecosystems whose packages are distribution builds:
// the version string carries an epoch, a packaging revision and often a
// backported fix that the upstream version number does not show. An upstream
// statement that names only a product cannot be ordered against such a
// version with any reliability, which is why Evaluate hands those pairs to
// the distribution's own advisories instead of guessing.
var distroFamilies = map[string]bool{
	"debian": true, "ubuntu": true,
	"redhat": true, "fedora": true, "centos": true, "rocky": true, "almalinux": true,
	"suse": true, "opensuse": true, "azurelinux": true, "openeuler": true,
	"mageia": true, "photon": true,
	"alpine": true, "wolfi": true, "chainguard": true, "minimos": true,
	"alpaquita": true, "echo": true, "root": true, "cleanstart": true, "bellsoft": true,
}

// losslessEcosystems are the ones where (ecosystem, name) reconstructs a purl
// with nothing lost, which makes an ecosystem+name match the same statement as
// a purl match written another way. Everything else matches at one grade lower.
var losslessEcosystems = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "go": true, "cargo": true,
	"rubygems": true, "nuget": true, "packagist": true, "hex": true, "pub": true,
	"cran": true, "hackage": true, "swifturl": true, "opam": true, "julia": true,
	"github actions": true,
	"debian":         true, "ubuntu": true,
	"redhat": true, "fedora": true, "centos": true, "rocky": true, "almalinux": true,
	"suse": true, "opensuse": true, "azurelinux": true, "openeuler": true,
	"mageia": true, "photon": true,
	"alpine": true, "wolfi": true, "chainguard": true, "minimos": true,
	"alpaquita": true, "echo": true, "root": true, "cleanstart": true, "bellsoft": true,
}

// osvNames spells a family back the way OSV writes it. internal/version keys
// its ecosystem override off the published ecosystem names, so it is handed
// those rather than this package's internal tokens.
var osvNames = map[string]string{
	"npm": "npm", "pypi": "PyPI", "maven": "Maven", "go": "Go", "cargo": "crates.io",
	"rubygems": "RubyGems", "nuget": "NuGet", "packagist": "Packagist", "hex": "Hex",
	"pub": "Pub", "cran": "CRAN", "hackage": "Hackage", "swifturl": "SwiftURL",
	"opam": "opam", "julia": "Julia", "github actions": "GitHub Actions",
	"bitnami": "Bitnami",
	"debian":  "Debian", "ubuntu": "Ubuntu",
	"redhat": "Red Hat", "fedora": "Fedora", "centos": "CentOS", "rocky": "Rocky Linux",
	"almalinux": "AlmaLinux", "suse": "SUSE", "opensuse": "openSUSE",
	"azurelinux": "Azure Linux", "openeuler": "openEuler", "mageia": "Mageia",
	"photon": "Photon",
	"alpine": "Alpine", "wolfi": "Wolfi", "chainguard": "Chainguard",
	"minimos": "MinimOS", "alpaquita": "Alpaquita", "echo": "Echo", "root": "Root",
	"cleanstart": "CleanStart", "bellsoft": "BellSoft Hardened Containers",
	"linux": "Linux", "android": "Android", "oss-fuzz": "OSS-Fuzz",
	"gsd": "GSD", "uvi": "UVI", "vscode": "VSCode",
}

// splitEcosystem splits an OSV ecosystem string into a folded family token and
// a release. The release matters on its own: Debian:11 and Debian:12 are the
// same family with incomparable version strings, because the packages are
// rebased between suites.
func splitEcosystem(s string) (family, release string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	head, tail, _ := strings.Cut(s, ":")
	family = foldEcosystem(head)
	// Ubuntu writes "Ubuntu:22.04:LTS"; the support-tier segment is not part of
	// the release identity.
	release, _, _ = strings.Cut(tail, ":")
	if ownReleaseNumbering(head) {
		release = ""
	}
	release = normalizeRelease(release)
	// Red Hat's OSV feeds spell the same major release as `rhel_9`, while rpm
	// purl distro qualifiers and local inventory commonly spell it as `rhel-9`
	// or simply `9`. Keeping the prefix made a RHEL 9 host conflict with a RHEL
	// 9 advisory. Strip only the Red Hat namespace marker; the family already
	// carries the information that would otherwise be lost.
	if family == "redhat" {
		for _, prefix := range []string{"rhel_", "rhel-"} {
			if strings.HasPrefix(release, prefix) {
				release = strings.TrimPrefix(release, prefix)
				break
			}
		}
	}
	return family, release
}

// ownReleaseNumbering reports whether a distribution folds onto a parent
// family but numbers its releases on a scale of its own. Linux Mint 21 is built
// on Ubuntu 22.04: folding the family and keeping the number would put a Mint
// host in release conflict with the very Ubuntu rows it should match, so the
// release is dropped and the row matches one grade lower with distro_release
// unproven, which is the honest reading. Raspbian is not here because its
// releases track Debian's numbers.
func ownReleaseNumbering(id string) bool {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "linuxmint", "linux mint":
		return true
	}
	return false
}

// osvRelease reduces a release to the precision the family's OSV ecosystem
// spells: Debian, Rocky, Alma and Red Hat publish per major (Debian:12),
// Alpine and Ubuntu per major.minor (Alpine:v3.18, Ubuntu:22.04).
//
// A purl distro qualifier carries whatever os-release VERSION_ID said, which
// is often finer than that (alpine-3.18.4, debian-12.4), and comparing the
// fine spelling against the coarse one reported a release conflict between a
// host and its own advisories. internal/inventory applies the same reduction
// when it spells the host's ecosystem, and the two have to agree, or one
// component's purl and ecosystem field would name different releases.
// Codenames are left alone: they are not numbers, and comparableRelease
// already declines to compare them.
func osvRelease(family, release string) string {
	if release == "" || release[0] < '0' || release[0] > '9' {
		return release
	}
	parts := strings.Split(release, ".")
	switch family {
	case "debian", "rocky", "almalinux", "redhat":
		return parts[0]
	case "alpine", "ubuntu":
		if len(parts) > 2 {
			return parts[0] + "." + parts[1]
		}
	}
	return release
}

// foldEcosystem maps one spelling onto the canonical token. An unrecognised
// name folds to itself rather than to a wildcard, so two rows from the same
// unknown ecosystem still match while two different unknowns still conflict.
func foldEcosystem(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if canon, ok := ecosystemAliases[s]; ok {
		return canon
	}
	return s
}

func normalizeRelease(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// Alpine writes its releases as v3.19 and its purls as 3.19.
	if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		s = s[1:]
	}
	return s
}

// purlEcosystem derives the ecosystem family and release from a purl.
//
// For deb, rpm and apk the type is not the family: the namespace is. That is
// the whole point of the namespace, and it is what keeps a MinimOS record off
// an Alpine host even though both are pkg:apk.
func purlEcosystem(p purl) (family, release string) {
	ownNumbering := false
	switch p.Type {
	case "deb", "rpm", "apk", "alpm":
		family = foldEcosystem(p.Namespace)
		ownNumbering = ownReleaseNumbering(p.Namespace)
	default:
		family = foldEcosystem(p.Type)
	}
	if p.Distro != "" {
		// distro qualifiers are written "<id>-<release>": debian-12,
		// alpine-3.19, rhel-9.
		rest := p.Distro
		if i := strings.LastIndexByte(rest, '-'); i >= 0 {
			if fam := foldEcosystem(rest[:i]); fam != "" && fam == family {
				ownNumbering = ownNumbering || ownReleaseNumbering(rest[:i])
				rest = rest[i+1:]
			}
		}
		release = osvRelease(family, normalizeRelease(rest))
	}
	if ownNumbering {
		release = ""
	}
	return family, release
}

// ecosystemName applies an ecosystem's own name rules before comparison. It is
// the same table as the purl name rules, reached from the other direction.
func ecosystemName(family, name string) string {
	name = strings.TrimSpace(name)
	switch family {
	case "pypi":
		return pep503(name)
	case "npm", "packagist", "hex", "pub", "opam", "nuget", "github actions", "bitnami",
		"debian", "ubuntu", "redhat", "fedora", "centos",
		"rocky", "almalinux", "suse", "opensuse", "azurelinux", "openeuler", "mageia",
		"photon", "alpine", "wolfi", "chainguard", "minimos", "alpaquita", "echo",
		"root", "cleanstart", "bellsoft":
		return strings.ToLower(name)
	default:
		return name
	}
}

// osvEcosystemName spells a family the way the published ecosystem lists do.
func osvEcosystemName(family string) string {
	if name, ok := osvNames[family]; ok {
		return name
	}
	return family
}
