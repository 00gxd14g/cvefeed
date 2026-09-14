package inventory

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// fakeSystem stands in for the host, so the suite proves the package-manager
// parsing on a machine that has none of dpkg, rpm or apk installed.
type fakeSystem struct {
	files    map[string]string
	commands map[string]string
}

func (f fakeSystem) readFile(name string) ([]byte, error) {
	if v, ok := f.files[name]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("open %s: %w", name, fs.ErrNotExist)
}

func (f fakeSystem) lookPath(name string) (string, error) {
	if _, ok := f.commands[name]; ok {
		return "/usr/bin/" + name, nil
	}
	return "", fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

func (f fakeSystem) run(_ context.Context, name string, _ ...string) ([]byte, error) {
	if v, ok := f.commands[name]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

const debianOSRelease = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
`

const rhelOSRelease = `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"
`

const alpineOSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
`

// dpkgQueryOutput is what dpkg-query prints for dpkgQueryFormat: the status
// abbreviation, the binary name and version, the architecture, and the source
// package the binary was built from.
const dpkgQueryOutput = "ii \topenssl\t3.0.11-1~deb12u2\tamd64\topenssl\t3.0.11-1~deb12u2\n" +
	"ii \tlibssl3\t3.0.11-1~deb12u2\tamd64\topenssl\t3.0.11-1~deb12u2\n" +
	"rc \tlibfoo1\t1.2.3-1\tamd64\tlibfoo\t1.2.3-1\n" +
	"iU \tlibhalf1\t2.0-1\tamd64\tlibhalf\t2.0-1\n" +
	"ii \tzlib1g\t1:1.2.13.dfsg-1\tamd64\tzlib\t1:1.2.13.dfsg-1\n"

const rpmQueryOutput = "openssl\t1\t3.0.7\t27.el9_5\tx86_64\topenssl-3.0.7-27.el9_5.src.rpm\n" +
	"kernel\t0\t5.14.0\t427.42.1.el9_4\tx86_64\tkernel-5.14.0-427.42.1.el9_4.src.rpm\n" +
	"gpg-pubkey\t0\t18b8e74c\t62f2920f\tnone\t(none)\n" +
	"python3-libs\t0\t3.9.18\t1.el9_4\tx86_64\tpython3-3.9.18-1.el9_4.src.rpm\n"

const apkInstalledDBFixture = `C:Q1eVpkS5AF7ZuZs0YQNlUJ3rVXOTA=
P:openssl
V:3.1.4-r5
A:x86_64
S:213412
I:2588672
T:Toolkit for Transport Layer Security (TLS)
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1706182861
c:9c0f5e5c1c07f0b9b0d9b0f6a0a1f2b3c4d5e6f7
D:so:libc.musl-x86_64.so.1
p:so:libcrypto.so.3=3

C:Q1YQbkZ8H0m3sWvJq4mFq0Zx3M9dA=
P:libcrypto3
V:3.1.4-r5
A:x86_64
o:openssl
L:Apache-2.0

C:Q1XmVoNwqE0cS9x0fA2jK4pQ1nD3E=
P:py3-cryptography
V:42.0.5-r0
A:x86_64
o:py3-cryptography
L:Apache-2.0
`

func TestCollectLocalOnAHostWithNoPackageManagerReturnsNothingAndNoError(t *testing.T) {
	comps, err := collectLocal(context.Background(), fakeSystem{})
	if err != nil {
		t.Fatalf("collectLocal: %v, want no error: an absent package database is a fact about the host", err)
	}
	if len(comps) != 0 {
		t.Fatalf("got %d components on a bare host, want none: %+v", len(comps), comps)
	}
}

func TestCollectLocalEmitsTheOperatingSystemItself(t *testing.T) {
	sys := fakeSystem{files: map[string]string{"/etc/os-release": debianOSRelease}}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	want := match.Component{
		Name:      "debian",
		Version:   "12",
		Ecosystem: "Debian:12",
		CPE:       "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
		Origin:    "os-release",
	}
	if len(comps) != 1 || comps[0] != want {
		t.Fatalf("got %+v, want [%+v]", comps, want)
	}
}

func TestCollectLocalUsesTheCPENameTheHostStates(t *testing.T) {
	sys := fakeSystem{files: map[string]string{"/etc/os-release": rhelOSRelease}}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	if got, want := comps[0].CPE, "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"; got != want {
		t.Errorf("CPE = %q, want the stated CPE_NAME rebound as 2.3 (%q)", got, want)
	}
	if got, want := comps[0].Ecosystem, "Red Hat:rhel_9"; got != want {
		t.Errorf("ecosystem = %q, want %q", got, want)
	}
}

func TestDpkgEmitsBothTheBinaryAndTheSourcePackage(t *testing.T) {
	sys := fakeSystem{
		files:    map[string]string{"/etc/os-release": debianOSRelease},
		commands: map[string]string{"dpkg-query": dpkgQueryOutput},
	}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}

	want := []match.Component{
		{Name: "debian", Version: "12", Ecosystem: "Debian:12", CPE: "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", Origin: "os-release"},
		{
			Name:      "openssl",
			Version:   "3.0.11-1~deb12u2",
			Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-bookworm",
			Origin:    "dpkg",
		},
		{
			Name:      "libssl3",
			Version:   "3.0.11-1~deb12u2",
			Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-bookworm",
			Origin:    "dpkg",
		},
		{
			Name:      "zlib1g",
			Version:   "1:1.2.13.dfsg-1",
			Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-bookworm",
			Origin:    "dpkg",
		},
		{
			// Debian and Ubuntu file advisories against the source package, so
			// zlib1g has to be looked up as zlib as well.
			Name:      "zlib",
			Version:   "1:1.2.13.dfsg-1",
			Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/zlib@1:1.2.13.dfsg-1?arch=source&distro=debian-bookworm",
			Origin:    "dpkg-source",
		},
	}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for i, w := range want {
		if comps[i] != w {
			t.Errorf("component %d:\n got %+v\nwant %+v", i, comps[i], w)
		}
	}
}

func TestDpkgSkipsPackagesWhoseFilesAreNotOnDisk(t *testing.T) {
	sys := fakeSystem{
		files:    map[string]string{"/etc/os-release": debianOSRelease},
		commands: map[string]string{"dpkg-query": dpkgQueryOutput},
	}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	for _, c := range comps {
		switch c.Name {
		case "libfoo1", "libfoo":
			t.Errorf("an rc package (removed, configuration left behind) was reported as installed: %+v", c)
		case "libhalf1", "libhalf":
			t.Errorf("an unpacked but unconfigured package was reported as installed: %+v", c)
		}
	}
}

func TestDpkgStatusFileIsTheOfflinePath(t *testing.T) {
	const status = `Package: openssl
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 This package is part of the OpenSSL project's implementation.

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.11-1~deb12u2)
Version: 3.0.11-1~deb12u2

Package: libfoo1
Status: deinstall ok config-files
Architecture: amd64
Version: 1.2.3-1
`
	sys := fakeSystem{files: map[string]string{
		"/etc/os-release":      debianOSRelease,
		"/var/lib/dpkg/status": status,
	}}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	names := map[string]string{}
	for _, c := range comps {
		names[c.Name] = c.Version
	}
	if _, ok := names["libfoo1"]; ok {
		t.Error("a config-files package was read as installed; the Status field's third word is the state")
	}
	if names["libssl3"] != "3.0.11-1~deb12u2" || names["openssl"] != "3.0.11-1~deb12u2" {
		t.Errorf("got %v, want both the binary and its source package", names)
	}
	if len(comps) != 3 {
		t.Errorf("got %d components, want the OS plus openssl and libssl3: %+v", len(comps), comps)
	}
}

func TestRPMFoldsTheEpochIntoTheVersionAndSkipsKeyringEntries(t *testing.T) {
	sys := fakeSystem{
		files:    map[string]string{"/etc/os-release": rhelOSRelease},
		commands: map[string]string{"rpm": rpmQueryOutput},
	}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}

	want := []match.Component{
		{Name: "rhel", Version: "9.4", Ecosystem: "Red Hat:rhel_9", CPE: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*", Origin: "os-release"},
		{
			Name:      "openssl",
			Version:   "1:3.0.7-27.el9_5",
			Ecosystem: "Red Hat:rhel_9",
			PURL:      "pkg:rpm/redhat/openssl@3.0.7-27.el9_5?arch=x86_64&distro=rhel-9.4&epoch=1",
			Origin:    "rpm",
		},
		{
			Name:      "kernel",
			Version:   "5.14.0-427.42.1.el9_4",
			Ecosystem: "Red Hat:rhel_9",
			PURL:      "pkg:rpm/redhat/kernel@5.14.0-427.42.1.el9_4?arch=x86_64&distro=rhel-9.4",
			Origin:    "rpm",
		},
		{
			Name:      "python3-libs",
			Version:   "3.9.18-1.el9_4",
			Ecosystem: "Red Hat:rhel_9",
			PURL:      "pkg:rpm/redhat/python3-libs@3.9.18-1.el9_4?arch=x86_64&distro=rhel-9.4",
			Origin:    "rpm",
		},
		{
			Name:      "python3",
			Version:   "3.9.18-1.el9_4",
			Ecosystem: "Red Hat:rhel_9",
			PURL:      "pkg:rpm/redhat/python3@3.9.18-1.el9_4?arch=src&distro=rhel-9.4",
			Origin:    "rpm-source",
		},
	}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for i, w := range want {
		if comps[i] != w {
			t.Errorf("component %d:\n got %+v\nwant %+v", i, comps[i], w)
		}
	}
}

func TestSourceRPMNameCountsFromTheRight(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"openssl-3.0.7-27.el9_5.src.rpm", "openssl"},
		// The name contains hyphens itself, so only counting from the right
		// finds the boundary.
		{"python3-libs-3.9.18-1.el9_4.src.rpm", "python3-libs"},
		{"java-17-openjdk-17.0.9.0.9-2.el9.src.rpm", "java-17-openjdk"},
		{"(none)", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := sourceRPMName(tt.in); got != tt.want {
			t.Errorf("sourceRPMName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAPKReadsTheInstalledDatabaseIncludingTheOriginPackage(t *testing.T) {
	sys := fakeSystem{files: map[string]string{
		"/etc/os-release":       alpineOSRelease,
		"/lib/apk/db/installed": apkInstalledDBFixture,
	}}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}

	want := []match.Component{
		{Name: "alpine", Version: "3.19.1", Ecosystem: "Alpine:v3.19", CPE: "cpe:2.3:o:alpinelinux:alpine_linux:3.19.1:*:*:*:*:*:*:*", Origin: "os-release"},
		{
			Name:      "openssl",
			Version:   "3.1.4-r5",
			Ecosystem: "Alpine:v3.19",
			PURL:      "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1",
			Origin:    "apk",
		},
		{
			Name:      "libcrypto3",
			Version:   "3.1.4-r5",
			Ecosystem: "Alpine:v3.19",
			PURL:      "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1",
			Origin:    "apk",
		},
		{
			Name:      "py3-cryptography",
			Version:   "42.0.5-r0",
			Ecosystem: "Alpine:v3.19",
			PURL:      "pkg:apk/alpine/py3-cryptography@42.0.5-r0?arch=x86_64&distro=alpine-3.19.1",
			Origin:    "apk",
		},
	}
	if len(comps) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(comps), len(want), comps)
	}
	for i, w := range want {
		if comps[i] != w {
			t.Errorf("component %d:\n got %+v\nwant %+v", i, comps[i], w)
		}
	}
}

func TestAPKInfoLineRefusesToGuessWhereTheVersionStarts(t *testing.T) {
	tests := []struct {
		line        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"openssl-3.1.4-r5", "openssl", "3.1.4-r5", true},
		{"py3-cryptography-42.0.5-r0", "py3-cryptography", "42.0.5-r0", true},
		{"zlib-1.3-r0", "zlib", "1.3-r0", true},
		// No build revision: the split point is unknowable.
		{"openssl-3.1.4", "", "", false},
		{"some-package-without-a-version", "", "", false},
		{"openssl", "", "", false},
	}
	for _, tt := range tests {
		name, version, ok := splitAPKInfoLine(tt.line)
		if ok != tt.wantOK || name != tt.wantName || version != tt.wantVersion {
			t.Errorf("splitAPKInfoLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.line, name, version, ok, tt.wantName, tt.wantVersion, tt.wantOK)
		}
	}
}

func TestAPKInfoIsTheFallbackWhenTheDatabaseCannotBeRead(t *testing.T) {
	sys := fakeSystem{
		files:    map[string]string{"/etc/os-release": alpineOSRelease},
		commands: map[string]string{"apk": "openssl-3.1.4-r5\nmusl-1.2.4-r2\nnot a package\n"},
	}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("got %d components, want the OS plus the two readable lines: %+v", len(comps), comps)
	}
	if comps[1].PURL != "pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.19.1" {
		t.Errorf("purl = %q, want no arch qualifier: apk info -v does not state one", comps[1].PURL)
	}
}

func TestOSReleaseEcosystemIsSpelledTheWayTheCorpusSpellsIt(t *testing.T) {
	tests := []struct {
		name string
		os   osRelease
		want string
	}{
		{"debian names a major release only", osRelease{ID: "debian", VersionID: "12"}, "Debian:12"},
		{"an ubuntu lts carries the suffix canonical publishes", osRelease{ID: "ubuntu", VersionID: "22.04", Version: "22.04.5 LTS (Jammy Jellyfish)"}, "Ubuntu:22.04:LTS"},
		{"an interim ubuntu does not", osRelease{ID: "ubuntu", VersionID: "23.10", Version: "23.10 (Mantic Minotaur)"}, "Ubuntu:23.10"},
		{"alpine takes a v prefix and two components", osRelease{ID: "alpine", VersionID: "3.19.1"}, "Alpine:v3.19"},
		{"red hat spells its release rhel_N", osRelease{ID: "rhel", VersionID: "9.4"}, "Red Hat:rhel_9"},
		{"rocky and alma take the major", osRelease{ID: "rocky", VersionID: "9.3"}, "Rocky Linux:9"},
		{"suse spells its release sleN", osRelease{ID: "sles", VersionID: "15.5"}, "SUSE:sle15.5"},
		// A rolling ecosystem has no release to compare, and inventing one
		// would have the matcher reject every row from it.
		{"a rolling hardened image has no release", osRelease{ID: "chainguard", VersionID: "20230214"}, "Chainguard"},
		{"a distribution with no osv ecosystem claims none", osRelease{ID: "fedora", VersionID: "40"}, ""},
		{"an unknown release leaves the bare family", osRelease{ID: "debian", VersionID: ""}, "Debian"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.os.ecosystem(); got != tt.want {
				t.Errorf("ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseOSReleaseStripsQuotes(t *testing.T) {
	got := parseOSRelease(debianOSRelease)
	want := osRelease{ID: "debian", VersionID: "12", Codename: "bookworm", Version: "12 (bookworm)"}
	if got != want {
		t.Errorf("parseOSRelease = %+v, want %+v", got, want)
	}
}

func TestCollectLocalOnThisHostDoesNotFail(t *testing.T) {
	// Whatever this machine is, and whether or not it has a package manager at
	// all, collecting must not be an error.
	if _, err := CollectLocal(context.Background()); err != nil {
		t.Fatalf("CollectLocal: %v", err)
	}
}

// The NVD files an operating system under its publisher, and the publisher is
// rarely the os-release ID: Ubuntu is "canonical", Alpine is "alpinelinux",
// Fedora is "fedoraproject". A CPE built as "<id>:<id>_linux" named nothing in
// any NVD configuration, so every OS-level advisory about an Ubuntu host was
// silently missed. An ID the table does not know gets no CPE: a guessed one
// matches nothing and reads exactly like a host with no advisories.
func TestOSCPEVendorIsTheOneTheNVDUses(t *testing.T) {
	tests := []struct {
		name string
		os   osRelease
		want string
	}{
		{"ubuntu is published by canonical", osRelease{ID: "ubuntu", VersionID: "22.04"}, "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"},
		{"debian is its own publisher", osRelease{ID: "debian", VersionID: "12"}, "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"},
		{"alpine is alpinelinux", osRelease{ID: "alpine", VersionID: "3.19.1"}, "cpe:2.3:o:alpinelinux:alpine_linux:3.19.1:*:*:*:*:*:*:*"},
		{"rhel is redhat enterprise_linux", osRelease{ID: "rhel", VersionID: "9.4"}, "cpe:2.3:o:redhat:enterprise_linux:9.4:*:*:*:*:*:*:*"},
		{"fedora is fedoraproject", osRelease{ID: "fedora", VersionID: "40"}, "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*"},
		{"sles is suse", osRelease{ID: "sles", VersionID: "15.5"}, "cpe:2.3:o:suse:linux_enterprise_server:15.5:*:*:*:*:*:*:*"},
		{"rocky", osRelease{ID: "rocky", VersionID: "9.3"}, "cpe:2.3:o:rocky:rocky_linux:9.3:*:*:*:*:*:*:*"},
		{"almalinux", osRelease{ID: "almalinux", VersionID: "9.3"}, "cpe:2.3:o:almalinux:almalinux:9.3:*:*:*:*:*:*:*"},
		{"centos is its own publisher", osRelease{ID: "centos", VersionID: "7"}, "cpe:2.3:o:centos:centos:7:*:*:*:*:*:*:*"},
		{"oracle linux is oracle:linux, not ol", osRelease{ID: "ol", VersionID: "8.9"}, "cpe:2.3:o:oracle:linux:8.9:*:*:*:*:*:*:*"},
		{"arch is archlinux:arch_linux", osRelease{ID: "arch", VersionID: "20260101"}, "cpe:2.3:o:archlinux:arch_linux:20260101:*:*:*:*:*:*:*"},
		{"amazon linux has two NVD spellings and gets no guess", osRelease{ID: "amzn", VersionID: "2023"}, ""},
		{"an unknown distribution gets no cpe rather than a guessed one", osRelease{ID: "chainguard", VersionID: "20230214"}, ""},
		{"a stated CPE_NAME wins over the table", osRelease{ID: "ubuntu", VersionID: "22.04", CPEName: "cpe:/o:canonical:ubuntu_linux:22.04:-:lts"}, "cpe:2.3:o:canonical:ubuntu_linux:22.04:-:lts:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := tt.os.component()
			if !ok {
				t.Fatal("no component for a host with an ID")
			}
			if c.CPE != tt.want {
				t.Errorf("CPE = %q, want %q", c.CPE, tt.want)
			}
		})
	}
}

// A package whose triggers are pending is installed: it is unpacked and
// configured, and what is outstanding is another package's trigger — a man-db
// index, an ldconfig run. Both states are what an interrupted apt upgrade
// leaves behind and what a container image built from one carries, and
// treating them as absent dropped exactly the packages that had just been
// updated.
func TestDpkgPackagesAwaitingTriggersAreInstalled(t *testing.T) {
	const query = "ii \topenssl\t3.0.11-1~deb12u2\tamd64\topenssl\t3.0.11-1~deb12u2\n" +
		"iW \tlibc6\t2.36-9+deb12u7\tamd64\tglibc\t2.36-9+deb12u7\n" +
		"iT \tman-db\t2.11.2-2\tamd64\tman-db\t2.11.2-2\n" +
		"rc \tlibfoo1\t1.2.3-1\tamd64\tlibfoo\t1.2.3-1\n"
	sys := fakeSystem{
		files:    map[string]string{"/etc/os-release": debianOSRelease},
		commands: map[string]string{"dpkg-query": query},
	}
	comps, err := collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	names := map[string]bool{}
	for _, c := range comps {
		names[c.Name] = true
	}
	for _, want := range []string{"libc6", "glibc", "man-db"} {
		if !names[want] {
			t.Errorf("%s is installed with triggers outstanding and was not reported: %v", want, names)
		}
	}
	if names["libfoo1"] {
		t.Error("a removed package was reported as installed")
	}

	// The same states spelled out in the status file.
	const status = `Package: libc6
Status: install ok triggers-awaited
Architecture: amd64
Version: 2.36-9+deb12u7

Package: man-db
Status: install ok triggers-pending
Architecture: amd64
Version: 2.11.2-2

Package: libhalf1
Status: install ok half-configured
Architecture: amd64
Version: 2.0-1
`
	sys = fakeSystem{files: map[string]string{
		"/etc/os-release":      debianOSRelease,
		"/var/lib/dpkg/status": status,
	}}
	comps, err = collectLocal(context.Background(), sys)
	if err != nil {
		t.Fatalf("collectLocal: %v", err)
	}
	names = map[string]bool{}
	for _, c := range comps {
		names[c.Name] = true
	}
	if !names["libc6"] || !names["man-db"] {
		t.Errorf("triggers-awaited and triggers-pending packages were not read from the status file: %v", names)
	}
	if names["libhalf1"] {
		t.Error("a half-configured package was reported as installed")
	}
}
