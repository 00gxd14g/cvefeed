package inventory

import "strings"

// osvEcosystemFamily maps an os-release ID, or the namespace of a deb/rpm/apk
// package URL, onto the OSV ecosystem family that publishes advisories for it.
//
// An identifier with no OSV ecosystem yields "". Claiming a family the corpus
// does not use would be worse than claiming none: the matcher treats a differing
// ecosystem family as a hard identity failure, so an invented family silences
// every row rather than only the wrong ones.
func osvEcosystemFamily(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "debian":
		return "Debian"
	case "ubuntu":
		return "Ubuntu"
	case "alpine":
		return "Alpine"
	case "wolfi":
		return "Wolfi"
	case "chainguard":
		return "Chainguard"
	case "minimos":
		return "MinimOS"
	case "alpaquita":
		return "Alpaquita"
	case "echo":
		return "Echo"
	case "cleanstart":
		return "CleanStart"
	case "root":
		return "Root"
	case "rocky":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "rhel", "redhat":
		return "Red Hat"
	case "sles", "sled", "suse":
		return "SUSE"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "openSUSE"
	case "azurelinux", "mariner":
		return "Azure Linux"
	case "openeuler":
		return "openEuler"
	case "mageia":
		return "Mageia"
	}
	return ""
}

// releaseForFamily spells a release the way its OSV ecosystem spells it:
// Debian:12, Alpine:v3.19, Rocky Linux:9, Red Hat:rhel_9, SUSE:sle15.5.
//
// A version this function cannot spell yields "", leaving the bare family. The
// asymmetry is deliberate. An unknown release costs one confidence level,
// because the matcher caps a finding whose distro release it could not check;
// a release spelled differently from the corpus costs the whole row, because
// the matcher reads a differing release as a hard non-match. Silence is the
// more expensive mistake, so this table only speaks where it is sure.
func releaseForFamily(family, versionID string) string {
	versionID = strings.TrimSpace(versionID)
	if versionID == "" {
		return ""
	}
	switch family {
	case "Debian", "Rocky Linux", "AlmaLinux":
		return majorOf(versionID)
	case "Red Hat":
		return "rhel_" + majorOf(versionID)
	case "Alpine":
		return "v" + majorMinorOf(versionID)
	case "SUSE":
		return "sle" + versionID
	}
	return ""
}

// ubuntuRelease spells an Ubuntu release. Canonical's OSV export distinguishes
// long-term releases (Ubuntu:22.04:LTS) from interim ones (Ubuntu:23.10), and
// the only place that distinction is recorded on a host is the VERSION string.
func ubuntuRelease(versionID string, lts bool) string {
	versionID = strings.TrimSpace(versionID)
	if versionID == "" {
		return ""
	}
	if lts {
		return versionID + ":LTS"
	}
	return versionID
}

// distroEcosystem resolves the ecosystem of an OS-package purl from its
// namespace and its distro qualifier (distro=debian-12, distro=alpine-3.19.1).
//
// A qualifier naming a codename rather than a number (distro=debian-bookworm)
// contributes no release: mapping codenames to numbers needs a table that goes
// stale, and a stale entry here is a silent false negative.
func distroEcosystem(namespace, distro string) string {
	family := osvEcosystemFamily(namespace)
	if family == "" {
		return ""
	}
	if family == "Ubuntu" {
		// A purl qualifier does not say whether the release is an LTS, and
		// half of Canonical's ecosystem tokens carry that suffix.
		return family
	}
	return joinEcosystem(family, releaseForFamily(family, distroVersionID(distro)))
}

// distroVersionID pulls the version out of a distro qualifier, whose form is
// <id>-<version or codename>.
func distroVersionID(distro string) string {
	_, tail, ok := strings.Cut(strings.TrimSpace(distro), "-")
	if !ok || tail == "" || tail[0] < '0' || tail[0] > '9' {
		return ""
	}
	return tail
}

func joinEcosystem(family, release string) string {
	if family == "" || release == "" {
		return family
	}
	return family + ":" + release
}

func majorOf(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

func majorMinorOf(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}
