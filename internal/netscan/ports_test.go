package netscan

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// useEmbeddedRanking makes TopPorts answer as it would on a machine with no
// nmap-services file, whatever this machine has. The two tests that check the
// default's breadth used to pass or fail by whether nmap happened to be
// installed on the build host, which is a statement about the host and not
// about the product; what the product promises is the breadth without nmap.
func useEmbeddedRanking(t *testing.T) {
	t.Helper()
	saved := servicesFiles
	servicesFiles = []string{filepath.Join(t.TempDir(), "no-such-nmap-services")}
	resetRanking()
	t.Cleanup(func() {
		servicesFiles = saved
		resetRanking()
	})
}

// useServicesFile points the ranking at one nmap-services file.
func useServicesFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nmap-services")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := servicesFiles
	servicesFiles = []string{path}
	resetRanking()
	t.Cleanup(func() {
		servicesFiles = saved
		resetRanking()
	})
	return path
}

func resetRanking() {
	topOnce = sync.Once{}
	topRanked, topSource = nil, ""
}

func TestParsePortsAcceptsListsAndRanges(t *testing.T) {
	got, err := ParsePorts("22,80,443,8000-8003")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []int{22, 80, 443, 8000, 8001, 8002, 8003}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePortsRejectsWhatIsNotAPort(t *testing.T) {
	for _, in := range []string{"0", "65536", "-1", "80-79", "http", "", "22,,80"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) was accepted", in)
		}
	}
}

func TestParsePortsDeduplicatesAndSorts(t *testing.T) {
	got, err := ParsePorts("443,22,443,80,22")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 22 || got[1] != 80 || got[2] != 443 {
		t.Fatalf("got %v, want [22 80 443]", got)
	}
}

// The default is what a caller who names no ports gets, and it has to be wide
// enough to be worth running. The 65-port hand-written list it replaced found 4
// open ports on a real host where a full scan found 23 — the missed services
// were on 7011, 8011, 8384, 30003 and 30008, none of them near a port anyone
// would think to list.
//
// Still bounded: a default that swept all 65,535 would take four times as long
// and should be asked for, not inherited.
func TestDefaultPortsAreBroadButBounded(t *testing.T) {
	useEmbeddedRanking(t)
	n := len(DefaultPorts())
	if n < 500 {
		t.Fatalf("DefaultPorts() has %d entries; too narrow to find services on high ports", n)
	}
	if n >= 65535 {
		t.Fatalf("DefaultPorts() has %d entries; the default must not be a full sweep", n)
	}
	seen := map[int]bool{}
	for _, p := range DefaultPorts() {
		if p < 1 || p > 65535 {
			t.Fatalf("port %d out of range", p)
		}
		if seen[p] {
			t.Fatalf("port %d listed twice", p)
		}
		seen[p] = true
	}
	for _, must := range []int{22, 80, 443} {
		if !seen[must] {
			t.Errorf("default list omits %d", must)
		}
	}
}

// The hand-written default list was the single biggest source of missed
// findings. Against one real host it found 4 open ports where a full scan found
// 23, and the ones it missed carried versions: Apache httpd 2.4.63 on 7011 and
// 8011, httpd 2.4.28 on 30008, RabbitMQ 3.7.17 on 30003, Syncthing 2.1.2 on
// 8384. None of those are near a well-known port.
func TestPortSpecUnderstandsAllAndTop(t *testing.T) {
	useEmbeddedRanking(t)
	all, err := ParsePorts("all")
	if err != nil {
		t.Fatalf("ParsePorts(all): %v", err)
	}
	if len(all) != 65535 || all[0] != 1 || all[len(all)-1] != 65535 {
		t.Fatalf("all = %d ports, %d..%d", len(all), all[0], all[len(all)-1])
	}

	top, err := ParsePorts("top:1000")
	if err != nil {
		t.Fatalf("ParsePorts(top:1000): %v", err)
	}
	if len(top) != 1000 {
		t.Fatalf("top:1000 = %d ports", len(top))
	}
	// nmap's own frequency data decides the order, so the obvious ones are in.
	for _, must := range []int{22, 80, 443, 3306} {
		if !containsPort(top, must) {
			t.Errorf("top:1000 omits %d", must)
		}
	}
}

// The embedded ranking is an excerpt of nmap's measured data, and it has to be
// presented as one: the same "most common" a caller with nmap installed gets,
// not a remembered list dressed up as a measurement.
func TestTheEmbeddedRankingIsAMeasuredOne(t *testing.T) {
	useEmbeddedRanking(t)
	if !HasPortFrequencies() {
		t.Fatal("HasPortFrequencies() = false with the embedded ranking in use; it is derived from nmap's frequency data")
	}
	if got := PortRankingSource(); got != embeddedSource {
		t.Errorf("PortRankingSource() = %q, want %q", got, embeddedSource)
	}
	if len(topPortsEmbedded) != 1000 {
		t.Fatalf("embedded ranking holds %d ports, want 1000", len(topPortsEmbedded))
	}
	seen := map[int]bool{}
	for _, p := range topPortsEmbedded {
		if p < 1 || p > 65535 {
			t.Fatalf("embedded port %d out of range", p)
		}
		if seen[p] {
			t.Fatalf("embedded port %d listed twice", p)
		}
		seen[p] = true
	}
	// nmap's data has had the same head for years: http, telnet, https.
	if topPortsEmbedded[0] != 80 || topPortsEmbedded[1] != 23 || topPortsEmbedded[2] != 443 {
		t.Errorf("embedded ranking begins %v, want 80, 23, 443 — is it in frequency order?", topPortsEmbedded[:3])
	}
	// Asking for more than the excerpt holds gets the excerpt, not an error
	// and not a padded list.
	if got := TopPorts(5000); len(got) != 1000 {
		t.Errorf("TopPorts(5000) = %d ports without nmap-services, want the 1000 that are ranked", len(got))
	}
}

// Where this machine has nmap's file, the excerpt must agree with it — the one
// check that catches a list generated from the wrong column or the wrong
// order. Only the head is compared: the tail of the ranking shifts a little
// between nmap releases, and this is not a test of which release is installed.
func TestTheEmbeddedRankingAgreesWithAnInstalledNmapServices(t *testing.T) {
	var fromFile []int
	for _, path := range []string{
		"/usr/share/nmap/nmap-services",
		"/usr/local/share/nmap/nmap-services",
		"/opt/homebrew/share/nmap/nmap-services",
	} {
		if fromFile = parseServices(path); len(fromFile) > 0 {
			break
		}
	}
	if len(fromFile) < 100 {
		t.Skip("no nmap-services file on this machine to compare against")
	}
	for i := 0; i < 100; i++ {
		if fromFile[i] != topPortsEmbedded[i] {
			t.Fatalf("rank %d: embedded %d, nmap-services %d; regenerate the embedded list", i+1, topPortsEmbedded[i], fromFile[i])
		}
	}
}

// An installed nmap-services is newer than anything compiled in and covers
// every port, so it wins when present.
func TestAnInstalledNmapServicesFileOutranksTheEmbeddedList(t *testing.T) {
	path := useServicesFile(t, "# a made-up ranking\n"+
		"a\t40001/tcp\t0.5\n"+
		"b\t40002/tcp\t0.9\n"+
		"c\t40003/udp\t0.95\n"+ // udp: not this scanner's business
		"d\t40004/tcp\t0.1\n")
	got := TopPorts(2)
	if len(got) != 2 || got[0] != 40001 || got[1] != 40002 {
		t.Fatalf("TopPorts(2) = %v, want [40001 40002] from the file rather than the embedded list", got)
	}
	if !HasPortFrequencies() {
		t.Error("HasPortFrequencies() = false with a frequency file loaded")
	}
	if src := PortRankingSource(); src != "nmap-services at "+path {
		t.Errorf("PortRankingSource() = %q, want it to name the file", src)
	}
}

func TestTopIsBoundedByWhatExists(t *testing.T) {
	got, err := ParsePorts("top:99999")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	if len(got) > 65535 {
		t.Fatalf("top:99999 produced %d ports", len(got))
	}
}

func TestPortSpecRejectsNonsenseTop(t *testing.T) {
	for _, in := range []string{"top:", "top:0", "top:-5", "top:x"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) was accepted", in)
		}
	}
}

func containsPort(ps []int, p int) bool {
	for _, v := range ps {
		if v == p {
			return true
		}
	}
	return false
}

// Ports go to nmap and masscan as a command-line argument. Enumerating every
// one of them turns a full scan into a 380 KB argument string, and nmap spends
// longer parsing it than scanning: -ports all took over ten minutes rendered as
// a list against two minutes rendered as a range.
func TestPortsRenderAsRangesRatherThanAsAList(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{[]int{22, 80, 443}, "22,80,443"},
		{[]int{1, 2, 3, 4, 5}, "1-5"},
		{[]int{22, 80, 81, 82, 443, 8000, 8001}, "22,80-82,443,8000-8001"},
		{[]int{1}, "1"},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := portList(tc.in); got != tc.want {
			t.Errorf("portList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}

	full, err := ParsePorts("all")
	if err != nil {
		t.Fatal(err)
	}
	if got := portList(full); got != "1-65535" {
		t.Errorf("the whole range rendered as %d characters, want \"1-65535\"", len(got))
	}
}
