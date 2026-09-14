package inventory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// CollectLocal reads the packages installed on the host this runs on.
//
// It degrades rather than failing. A machine with none of dpkg, rpm or apk
// yields an empty inventory and no error, because "there is no package database
// here I can read" is a fact about the machine, not a failure of the scan; the
// caller reports zero components rather than an error it cannot act on.
func CollectLocal(ctx context.Context) ([]match.Component, error) {
	return collectLocal(ctx, hostSystem{})
}

// system is the seam between the collectors and the machine: read a file, run a
// query, ask whether a binary exists. Tests supply their own so the suite
// proves the parsing on a host that has none of the three package managers.
type system interface {
	readFile(name string) ([]byte, error)
	run(ctx context.Context, name string, args ...string) ([]byte, error)
	lookPath(name string) (string, error)
}

type hostSystem struct{}

func (hostSystem) readFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (hostSystem) lookPath(name string) (string, error) { return exec.LookPath(name) }

// run executes a package-manager query with an explicit argument vector and no
// shell. A package name is third-party data on a machine whose whole purpose is
// installing third-party software, and "sh -c" would turn one into code.
func (hostSystem) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("inventory: run %s: %w", name, err)
	}
	return out, nil
}

func collectLocal(ctx context.Context, sys system) ([]match.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("inventory: collect local: %w", err)
	}
	host := readOSRelease(sys)

	var out []match.Component
	if c, ok := host.component(); ok {
		out = append(out, c)
	}
	out = append(out, collectDpkg(ctx, sys, host)...)
	out = append(out, collectRPM(ctx, sys, host)...)
	out = append(out, collectAPK(ctx, sys, host)...)
	return dedupe(out), nil
}

// osRelease is the host's own identity. Without it the distro namespace and
// release cannot be filled in, and a Debian 11 advisory becomes indistinguishable
// from a statement about a Debian 13 host.
type osRelease struct {
	ID        string
	VersionID string
	Codename  string
	Version   string
	CPEName   string
}

func readOSRelease(sys system) osRelease {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := sys.readFile(path); err == nil {
			return parseOSRelease(string(b))
		}
	}
	return osRelease{}
}

func parseOSRelease(text string) osRelease {
	var o osRelease
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "ID":
			o.ID = strings.ToLower(value)
		case "VERSION_ID":
			o.VersionID = value
		case "VERSION_CODENAME":
			o.Codename = strings.ToLower(value)
		case "VERSION":
			o.Version = value
		case "CPE_NAME":
			o.CPEName = value
		}
	}
	return o
}

// ecosystem spells the host's OSV ecosystem, release included where that
// release can be spelled the way the corpus spells it.
func (o osRelease) ecosystem() string {
	family := osvEcosystemFamily(o.ID)
	switch family {
	case "":
		return ""
	case "Ubuntu":
		return joinEcosystem(family, ubuntuRelease(o.VersionID, strings.Contains(strings.ToUpper(o.Version), "LTS")))
	}
	return joinEcosystem(family, releaseForFamily(family, o.VersionID))
}

// distroTag is the value of the purl distro qualifier. dpkg-based systems are
// keyed by codename in the security data that matters (bookworm, jammy), so the
// codename is preferred where the host states one.
func (o osRelease) distroTag() string {
	if o.ID == "" {
		return ""
	}
	release := firstNonEmpty(o.Codename, o.VersionID)
	if release == "" {
		return o.ID
	}
	return o.ID + "-" + release
}

func (o osRelease) numericDistroTag() string {
	if o.ID == "" {
		return ""
	}
	if o.VersionID == "" {
		return o.ID
	}
	return o.ID + "-" + o.VersionID
}

// osCPEIdentity maps an os-release ID onto the vendor and product the NVD files
// that operating system under.
//
// Neither is the ID. Ubuntu is published by "canonical", Alpine by
// "alpinelinux", Fedora by "fedoraproject", and building the CPE as
// "<id>:<id>_linux" produced "ubuntu:ubuntu_linux" — a name that appears in no
// NVD configuration, so every OS-level advisory about the host silently failed
// to match. An ID that is not in the table gets no CPE at all: a guessed CPE
// matches nothing and looks exactly like a host with no advisories.
var osCPEIdentity = map[string]struct{ vendor, product string }{
	"debian":              {"debian", "debian_linux"},
	"ubuntu":              {"canonical", "ubuntu_linux"},
	"alpine":              {"alpinelinux", "alpine_linux"},
	"rhel":                {"redhat", "enterprise_linux"},
	"fedora":              {"fedoraproject", "fedora"},
	"sles":                {"suse", "linux_enterprise_server"},
	"sled":                {"suse", "linux_enterprise_desktop"},
	"opensuse-leap":       {"opensuse", "leap"},
	"opensuse-tumbleweed": {"opensuse", "tumbleweed"},
	"rocky":               {"rocky", "rocky_linux"},
	"almalinux":           {"almalinux", "almalinux"},
	"centos":              {"centos", "centos"},
	"ol":                  {"oracle", "linux"},
	// Arch has no VERSION_ID — it is rolling, and os-release carries a
	// BUILD_ID instead — so this row only ever applies to a host that states
	// one. It is here so the vendor is not guessed when one does.
	"arch": {"archlinux", "arch_linux"},
	// Amazon Linux ("amzn") is deliberately absent: the NVD files it under
	// both "amazon:linux" and "amazon:linux_2", and a row that picks the
	// wrong one matches nothing while looking like a host with no advisories.
}

// component emits the operating system itself. Container and OS-level
// advisories are about this component, and nothing else in the inventory
// carries the release.
//
// A CPE_NAME the host states wins over the table: the vendor knows what it
// publishes under better than a table does, and Red Hat's carries the edition.
func (o osRelease) component() (match.Component, bool) {
	if o.ID == "" {
		return match.Component{}, false
	}
	cpe := cpe23(o.CPEName)
	if cpe == "" && o.VersionID != "" {
		if id, ok := osCPEIdentity[o.ID]; ok {
			cpe = fmt.Sprintf("cpe:2.3:o:%s:%s:%s:*:*:*:*:*:*:*", id.vendor, id.product, cpeAttribute(o.VersionID))
		}
	}
	return match.Component{
		Name:      o.ID,
		Version:   o.VersionID,
		Ecosystem: o.ecosystem(),
		CPE:       cpe,
		Origin:    "os-release",
	}, true
}

// dpkgQueryFormat asks for the six fields the deb identity needs. ${Package} is
// the bare name; ${binary:Package} would append ":amd64" on a multi-arch system
// and no advisory names a package that way.
const dpkgQueryFormat = "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"

func collectDpkg(ctx context.Context, sys system, host osRelease) []match.Component {
	if _, err := sys.lookPath("dpkg-query"); err == nil {
		if out, err := sys.run(ctx, "dpkg-query", "-W", "-f", dpkgQueryFormat); err == nil {
			if comps := parseDpkgQuery(string(out), host); len(comps) > 0 {
				return comps
			}
		}
	}
	// The offline path, which is also the path for an unpacked container image
	// where dpkg-query cannot be invoked at all.
	b, err := sys.readFile("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	return parseDpkgStatus(string(b), host)
}

func parseDpkgQuery(out string, host osRelease) []match.Component {
	var comps []match.Component
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 || !dpkgAbbrevInstalled(f[0]) {
			continue
		}
		comps = append(comps, debComponents(host,
			strings.TrimSpace(f[1]), strings.TrimSpace(f[2]), strings.TrimSpace(f[3]),
			field(f, 4), field(f, 5))...)
	}
	return comps
}

// dpkgAbbrevInstalled reads db:Status-Abbrev, whose three characters are the
// desired action, the current status and the error flag, in that order.
//
// Only the second says whether the files are on disk. "rc" is a package that
// was removed with its configuration left behind: the binary is gone, and
// reporting its old version as installed software is a false positive that no
// version comparison was even involved in. "iU", "iF" and "iH" are unpacked or
// half-configured, where what is on disk is indeterminate, so they are left out
// too rather than reported as present.
//
// "W" (triggers-awaited) and "T" (triggers-pending) are installed. The package
// is fully unpacked and configured; what is pending is another package's
// trigger — a man-db index rebuild, an ldconfig run — and its files are on
// disk and running. Both states are common in the middle of an apt upgrade and
// linger on a container image built from one, and treating them as absent
// dropped exactly the packages that had just been updated.
func dpkgAbbrevInstalled(abbrev string) bool {
	if len(abbrev) < 2 {
		return false
	}
	switch abbrev[1] {
	case 'i', 'W', 'T', 't':
		// dpkg's own header spells triggers-pending with a capital T; older
		// releases printed it lowercase.
		return true
	}
	return false
}

// dpkgStatusInstalled reads the last word of a Status field for the same
// states dpkgAbbrevInstalled accepts.
func dpkgStatusInstalled(state string) bool {
	switch state {
	case "installed", "triggers-awaited", "triggers-pending":
		return true
	}
	return false
}

// parseDpkgStatus reads /var/lib/dpkg/status, whose RFC-822 stanzas are what
// dpkg-query itself queries.
func parseDpkgStatus(text string, host osRelease) []match.Component {
	var comps []match.Component
	for _, stanza := range splitStanzas(text) {
		f := stanzaFields(stanza)
		// The Status field spells the same three states in a different order
		// from db:Status-Abbrev: desired action, error flag, current status.
		// Reading the second word here would accept "install ok deinstall".
		status := strings.Fields(f["Status"])
		if len(status) < 3 || !dpkgStatusInstalled(status[2]) {
			continue
		}
		srcName, srcVersion := parseDpkgSource(f["Source"])
		comps = append(comps, debComponents(host, f["Package"], f["Version"], f["Architecture"], srcName, srcVersion)...)
	}
	return comps
}

// parseDpkgSource splits a Source field, which is either "openssl" or
// "openssl (1.1.1n-0+deb11u5)" when the source version differs from the binary's.
func parseDpkgSource(value string) (name, version string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	name, rest, ok := strings.Cut(value, "(")
	if !ok {
		return strings.TrimSpace(value), ""
	}
	return strings.TrimSpace(name), strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ")"))
}

func debComponents(host osRelease, name, version, arch, srcName, srcVersion string) []match.Component {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	version = strings.TrimSpace(version)
	// dpkg prints an empty source version when it equals the binary's, and an
	// empty source name when it equals the binary's name.
	srcName = firstNonEmpty(srcName, name)
	srcVersion = firstNonEmpty(srcVersion, version)

	ecosystem := host.ecosystem()
	// The vendor is left empty on purpose: a dpkg Maintainer is the person who
	// packaged the software, not the upstream vendor an advisory names.
	comps := []match.Component{{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		PURL:      debPURL(host, name, version, arch),
		Origin:    "dpkg",
	}}

	// Debian and Ubuntu security data — the tracker JSON, USN and DSA, and the
	// OSV Debian and Ubuntu ecosystems — is keyed by source package. Matching
	// only the binary libssl3 against advisories filed under openssl misses
	// them entirely, so the source package is a component in its own right.
	//
	// When the source name and version are the binary's, the two purls differ
	// only by the arch qualifier, which identity drops: that is the same
	// component twice, not two components.
	if srcName != name || srcVersion != version {
		comps = append(comps, match.Component{
			Name:      srcName,
			Version:   srcVersion,
			Ecosystem: ecosystem,
			PURL:      debPURL(host, srcName, srcVersion, "source"),
			Origin:    "dpkg-source",
		})
	}
	return comps
}

func debPURL(host osRelease, name, version, arch string) string {
	if host.ID == "" {
		// Without an os-release ID there is no namespace, and a namespace-less
		// purl would claim a package identity the host cannot support.
		return ""
	}
	return buildPURL("deb", host.ID, name, version, map[string]string{
		"arch":   arch,
		"distro": host.distroTag(),
	})
}

// rpmQueryFormat spells EPOCH through rpm's conditional syntax. A bare
// %{EPOCH} prints the literal string "(none)" when the tag is unset, which then
// parses as a version and corrupts every comparison it takes part in.
const rpmQueryFormat = "%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%|ARCH?{%{ARCH}}:{none}|\t%{SOURCERPM}\n"

func collectRPM(ctx context.Context, sys system, host osRelease) []match.Component {
	if _, err := sys.lookPath("rpm"); err != nil {
		return nil
	}
	out, err := sys.run(ctx, "rpm", "-qa", "--qf", rpmQueryFormat)
	if err != nil {
		return nil
	}
	return parseRPMQuery(string(out), host)
}

func parseRPMQuery(out string, host osRelease) []match.Component {
	var comps []match.Component
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		name := strings.TrimSpace(f[0])
		// gpg-pubkey rows are keyring entries dressed as packages.
		if name == "" || name == "gpg-pubkey" {
			continue
		}
		epoch, version, release := strings.TrimSpace(f[1]), strings.TrimSpace(f[2]), strings.TrimSpace(f[3])
		arch := field(f, 4)
		if arch == "none" {
			arch = ""
		}
		comps = append(comps, rpmComponents(host, name, epoch, version, release, arch, field(f, 5))...)
	}
	return comps
}

func rpmComponents(host osRelease, name, epoch, version, release, arch, sourceRPM string) []match.Component {
	vr := version
	if release != "" {
		vr = version + "-" + release
	}
	// The epoch is printed only when it is set to something. An explicit "0:"
	// on every package would put an epoch on one side of comparisons whose
	// advisory bounds carry none, which is the elision case the matcher then
	// has to work around on every single row.
	evr := vr
	if epoch != "" && epoch != "0" {
		evr = epoch + ":" + vr
	}

	ecosystem := host.ecosystem()
	comps := []match.Component{{
		Name:      name,
		Version:   evr,
		Ecosystem: ecosystem,
		PURL:      rpmPURL(host, name, vr, arch, epoch),
		Origin:    "rpm",
	}}

	// Red Hat and SUSE file advisories against the source package as often as
	// against the binary one, exactly as Debian does.
	if src := sourceRPMName(sourceRPM); src != "" && src != name {
		comps = append(comps, match.Component{
			Name:      src,
			Version:   evr,
			Ecosystem: ecosystem,
			PURL:      rpmPURL(host, src, vr, "src", epoch),
			Origin:    "rpm-source",
		})
	}
	return comps
}

func rpmPURL(host osRelease, name, vr, arch, epoch string) string {
	if host.ID == "" {
		return ""
	}
	qualifiers := map[string]string{
		"arch":   arch,
		"distro": host.numericDistroTag(),
	}
	if epoch != "" && epoch != "0" {
		// Kept as a qualifier as well as folded into the version: the purl
		// spec puts it here, and an epoch dropped rather than carried inverts
		// comparisons across an epoch bump.
		qualifiers["epoch"] = epoch
	}
	return buildPURL("rpm", rpmNamespace(host.ID), name, vr, qualifiers)
}

// rpmNamespace maps an os-release ID onto the namespace the purl specification
// uses for RPM distributions. Only the documented renamings are applied;
// anything else is passed through, because inventing a namespace would put the
// component in an ecosystem the corpus never writes.
func rpmNamespace(id string) string {
	switch id {
	case "rhel":
		return "redhat"
	case "sles", "sled":
		return "suse"
	case "opensuse-leap", "opensuse-tumbleweed":
		return "opensuse"
	}
	return id
}

// sourceRPMName recovers the source package name from a SOURCERPM value such as
// "openssl-3.0.7-27.el9_5.src.rpm".
//
// The last two hyphen-separated fields are the source version and release.
// Package names contain hyphens themselves (python3-libs, java-17-openjdk), so
// counting from the right is the only split that works.
func sourceRPMName(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, ".src.rpm"):
		s = strings.TrimSuffix(s, ".src.rpm")
	case strings.HasSuffix(s, ".nosrc.rpm"):
		s = strings.TrimSuffix(s, ".nosrc.rpm")
	default:
		return ""
	}
	for i := 0; i < 2; i++ {
		j := strings.LastIndex(s, "-")
		if j <= 0 {
			return ""
		}
		s = s[:j]
	}
	return s
}

// apkInstalledDB is the authoritative list on an apk system. Reading it is
// preferred over "apk info -v", whose output cannot be split unambiguously.
const apkInstalledDB = "/lib/apk/db/installed"

func collectAPK(ctx context.Context, sys system, host osRelease) []match.Component {
	if b, err := sys.readFile(apkInstalledDB); err == nil {
		if comps := parseAPKInstalled(string(b), host); len(comps) > 0 {
			return comps
		}
	}
	if _, err := sys.lookPath("apk"); err != nil {
		return nil
	}
	out, err := sys.run(ctx, "apk", "info", "-v")
	if err != nil {
		return nil
	}
	return parseAPKInfo(string(out), host)
}

// parseAPKInstalled reads the installed database, whose stanzas carry one
// letter-keyed field per line: P for the package, V for the version, A for the
// architecture and o for the origin, which is apk's name for the source package.
func parseAPKInstalled(text string, host osRelease) []match.Component {
	var comps []match.Component
	for _, stanza := range splitStanzas(text) {
		f := stanzaFields(stanza)
		comps = append(comps, apkComponents(host, f["P"], f["V"], f["A"], f["o"])...)
	}
	return comps
}

var apkRevisionRe = regexp.MustCompile(`^r\d+$`)

// parseAPKInfo reads "apk info -v" output, which is genuinely ambiguous:
// package names contain hyphens (py3-cryptography) and so do versions
// (42.0.5-r0). A line that does not split cleanly is dropped rather than
// guessed at, since a misplaced split invents both a package and a version.
func parseAPKInfo(out string, host osRelease) []match.Component {
	var comps []match.Component
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, ok := splitAPKInfoLine(line)
		if !ok {
			continue
		}
		comps = append(comps, apkComponents(host, name, version, "", "")...)
	}
	return comps
}

func splitAPKInfoLine(line string) (name, version string, ok bool) {
	i := strings.LastIndex(line, "-")
	if i < 0 {
		return "", "", false
	}
	revision := line[i+1:]
	if !apkRevisionRe.MatchString(revision) {
		return "", "", false
	}
	rest := line[:i]
	j := strings.LastIndex(rest, "-")
	if j <= 0 {
		return "", "", false
	}
	upstream := rest[j+1:]
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return "", "", false
	}
	return rest[:j], upstream + "-" + revision, true
}

func apkComponents(host osRelease, name, version, arch, origin string) []match.Component {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	version = strings.TrimSpace(version)
	ecosystem := host.ecosystem()
	comps := []match.Component{{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		PURL:      apkPURL(host, name, version, arch),
		Origin:    "apk",
	}}
	if origin = strings.TrimSpace(origin); origin != "" && origin != name {
		comps = append(comps, match.Component{
			Name:      origin,
			Version:   version,
			Ecosystem: ecosystem,
			PURL:      apkPURL(host, origin, version, "src"),
			Origin:    "apk-source",
		})
	}
	return comps
}

// apkPURL builds the apk identity. The namespace is what keeps the 117k MinimOS
// and 19k Root records off an Alpine host and the Alpine records off theirs:
// those ecosystems rebuild the same upstreams, so the package name alone says
// nothing about which of them a fixed version describes.
func apkPURL(host osRelease, name, version, arch string) string {
	if host.ID == "" {
		return ""
	}
	return buildPURL("apk", host.ID, name, version, map[string]string{
		"arch":   arch,
		"distro": host.numericDistroTag(),
	})
}

// splitStanzas breaks an RFC-822-style database into blank-line separated
// records.
func splitStanzas(text string) []string {
	var out []string
	var current []string
	flush := func() {
		if len(current) > 0 {
			out = append(out, strings.Join(current, "\n"))
			current = nil
		}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()
	return out
}

// stanzaFields reads the single-line fields of one stanza. Continuation lines,
// which begin with whitespace, belong to multi-line fields such as Description
// and are skipped: nothing here needs them, and treating one as a field name
// would invent packages out of prose.
func stanzaFields(stanza string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(stanza, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, seen := fields[key]; seen {
			continue
		}
		fields[key] = strings.TrimSpace(value)
	}
	return fields
}

func field(f []string, i int) string {
	if i < len(f) {
		return strings.TrimSpace(f[i])
	}
	return ""
}
