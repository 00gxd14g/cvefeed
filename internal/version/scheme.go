package version

import "strings"

// rangeTypeSchemes maps the versionType an upstream declares onto an ordering.
//
// The commit types are in here rather than in a separate step because they must
// beat the ecosystem: a GIT range inside the Linux ecosystem is still a range of
// commits, and 44,252 stored ranges say so. Everything else in the table is the
// producer explicitly naming a scheme, which also outranks the ecosystem; the
// only cost is honouring a producer's mistake, and each comparator contains that
// by falling back to the generic ordering when its own grammar rejects the input.
var rangeTypeSchemes = map[string]Scheme{
	"SEMVER": Semver,
	"NPM":    Semver,
	"NODE":   Semver,
	"CARGO":  Semver,
	"NUGET":  Semver,

	"DEBIAN": Debian,
	"DEB":    Debian,
	"DPKG":   Debian,

	"RPM":   RPM,
	"NEVRA": RPM,
	"EVR":   RPM,

	"APK":    Alpine,
	"ALPINE": Alpine,

	"MAVEN": Maven,

	"PYTHON": Python,
	"PYPI":   Python,
	"PEP440": Python,

	"GO":     Go,
	"GOLANG": Go,

	"GIT":                     Opaque,
	"ORIGINAL_COMMIT_FOR_FIX": Opaque,
	"COMMIT":                  Opaque,
	"SHA":                     Opaque,
	"REVISION_ID":             Opaque,
}

// ecosystemSchemes maps a case folded OSV ecosystem head name onto an ordering.
// It covers OSV's 45 published ecosystems, GHSA's REST enum and the distro
// names the corpus carries outside OSV.
var ecosystemSchemes = map[string]Scheme{
	// Debian's ordering, tilde and all. opam is here because the OCaml opam
	// manual defines its version ordering on Debian's model.
	"debian": Debian,
	"ubuntu": Debian,
	"opam":   Debian,

	"red hat":      RPM,
	"redhat":       RPM,
	"rhel":         RPM,
	"rocky linux":  RPM,
	"rocky":        RPM,
	"almalinux":    RPM,
	"alma":         RPM,
	"suse":         RPM,
	"opensuse":     RPM,
	"sles":         RPM,
	"mageia":       RPM,
	"openeuler":    RPM,
	"azure linux":  RPM,
	"mariner":      RPM,
	"cbl-mariner":  RPM,
	"oracle linux": RPM,
	"centos":       RPM,
	"fedora":       RPM,
	"amazon linux": RPM,
	"photon":       RPM,
	"openanolis":   RPM,
	"anolis":       RPM,

	// All five ship apk packages with -rN revisions.
	"alpine":                       Alpine,
	"wolfi":                        Alpine,
	"chainguard":                   Alpine,
	"alpaquita":                    Alpine,
	"bellsoft hardened containers": Alpine,

	"npm":            Semver,
	"crates.io":      Semver,
	"cratesio":       Semver,
	"rust":           Semver,
	"nuget":          Semver,
	"pub":            Semver,
	"hex":            Semver,
	"erlang":         Semver,
	"swifturl":       Semver,
	"swift":          Semver,
	"github actions": Semver,
	"actions":        Semver,
	"julia":          Semver,
	"vscode":         Semver,
	// Composer's own comparator is PHP version_compare with stability flags,
	// not semver; GHSA normalises Packagist ranges into semver-shaped strings,
	// so lenient semver is an approximation that fits the data we actually get.
	"packagist": Semver,
	"composer":  Semver,
	// Gem::Version puts a pre-release behind a dot (1.0.0.rc1). parseSemver
	// rewrites that shape, which reproduces Gem semantics for gem-shaped
	// versions and grades itself Heuristic for saying so.
	"rubygems": Semver,
	// Kernel bounds that are not commits are dotted numeric (5.15.32, the
	// historical 2.6.32.71, and 6.1-rc1). Commit ranges never reach here: the
	// GIT range type is resolved before the ecosystem is consulted.
	"linux": Semver,

	"maven": Maven,

	"pypi": Python,
	"pip":  Python,

	"go":     Go,
	"golang": Go,

	// Strictly dotted integers (R's package_version, Haskell's PVP): the
	// generic ordering decides all of them exactly.
	"cran":    Generic,
	"hackage": Generic,
	"ghc":     Generic,
	// Android bounds are security patch levels (2023-06-01) and build ids. The
	// patch levels chunk into numbers and compare exactly; the build ids come
	// back undecidable, which is the correct answer for them.
	"android": Generic,
	"gsd":     Generic,
	"uvi":     Generic,
	// The hardened-image re-issuers rebuild other people's packages, and the
	// ecosystem name alone does not say whose. Generic is the placeholder until
	// the base distro is confirmed by sampling; guessing Alpine or RPM from a
	// vendor's marketing would be the kind of assumption this package exists to
	// avoid.
	"bitnami":    Generic,
	"minimos":    Generic,
	"echo":       Generic,
	"root":       Generic,
	"cleanstart": Generic,
	"tuxcare":    Generic,

	"git":      Opaque,
	"oss-fuzz": Opaque,
}

// reissuers are the ecosystems that republish someone else's packages and spell
// the real ecosystem after a colon, as in TuxCare:Maven.
var reissuers = map[string]bool{
	"tuxcare":    true,
	"root":       true,
	"bitnami":    true,
	"minimos":    true,
	"echo":       true,
	"cleanstart": true,
}

// SchemeFor maps an upstream range type and OSV ecosystem onto an ordering.
//
// The range type is consulted first, then the ecosystem. A type that names no
// ordering (CUSTOM, PATCH, RELEASE, DATE, OTP, OTHER, ECOSYSTEM, the empty
// string) and a type never seen before are the same question once the type is
// known to say nothing, so they share the fallthrough.
//
// The last resort is Generic, not Opaque. Refusing outright would discard every
// CVE List row, which carries no ecosystem and declares CUSTOM 127,515 times,
// and would leave the scanner useless for the data it has most of. Generic is
// safe to default to only because it answers what dotted-numeric comparison
// proves and grades or refuses the rest.
func SchemeFor(rangeType, ecosystem string) Scheme {
	if s, ok := rangeTypeSchemes[strings.ToUpper(strings.TrimSpace(rangeType))]; ok {
		return s
	}
	if s, ok := ecosystemSchemes[ecosystemKey(ecosystem)]; ok {
		return s
	}
	return Generic
}

// ecosystemKey reduces an OSV ecosystem to the name the tables are keyed by.
//
// OSV qualifies an ecosystem after a colon: the release ("Debian:11",
// "Alpine:v3.16"), a repository ("Maven:https://repo1.maven.org"), or, for the
// re-issuers, the ecosystem that actually owns the versions ("TuxCare:Maven").
// Only the last case may override the head, and only when the suffix names a
// known ecosystem, which is why a repository URL cannot be mistaken for one.
func ecosystemKey(ecosystem string) string {
	head, tail, _ := strings.Cut(ecosystem, ":")
	key := strings.ToLower(strings.TrimSpace(head))
	_, known := ecosystemSchemes[key]
	if known && !reissuers[key] {
		return key
	}
	first, _, _ := strings.Cut(tail, ":")
	if alt := strings.ToLower(strings.TrimSpace(first)); alt != "" {
		if _, ok := ecosystemSchemes[alt]; ok {
			return alt
		}
	}
	return key
}

// purlTypeEcosystems names the OSV ecosystem a package URL type implies.
//
// SchemeFor takes an ecosystem, and 3,797 stored statements carry a purl with
// no ecosystem beside it. Deriving one here keeps that derivation in a single
// place, and the caller should record that the scheme came from a purl rather
// than from the producer: it is a different confidence story.
//
// pkg:rpm carries the distro in its namespace (pkg:rpm/redhat, pkg:rpm/opensuse)
// and every one of them orders as RPM, so the namespace is not consulted.
var purlTypeEcosystems = map[string]string{
	"deb":      "Debian",
	"rpm":      "Red Hat",
	"apk":      "Alpine",
	"npm":      "npm",
	"maven":    "Maven",
	"pypi":     "PyPI",
	"golang":   "Go",
	"gem":      "RubyGems",
	"cargo":    "crates.io",
	"nuget":    "NuGet",
	"composer": "Packagist",
	"hex":      "Hex",
	"pub":      "Pub",
	"cran":     "CRAN",
	"swift":    "SwiftURL",
	"hackage":  "Hackage",
	"github":   "GitHub Actions",
}

// EcosystemForPURLType returns the ecosystem name a package URL type implies,
// or the empty string when the type implies none.
func EcosystemForPURLType(purlType string) string {
	return purlTypeEcosystems[strings.ToLower(strings.TrimSpace(purlType))]
}
