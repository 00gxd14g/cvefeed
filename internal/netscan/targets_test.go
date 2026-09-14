package netscan

import (
	"strings"
	"testing"
)

func TestParseTargetsExpandsCIDR(t *testing.T) {
	cases := []struct {
		in    string
		hosts int
		first string
		last  string
	}{
		// A /24 excludes the network and broadcast addresses, which no host
		// answers on.
		{"192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"},
		{"10.0.0.0/30", 2, "10.0.0.1", "10.0.0.2"},
		// A /31 is a point-to-point link: both addresses are usable (RFC 3021).
		{"10.0.0.0/31", 2, "10.0.0.0", "10.0.0.1"},
		{"10.0.0.5/32", 1, "10.0.0.5", "10.0.0.5"},
		{"10.0.0.7", 1, "10.0.0.7", "10.0.0.7"},
		{"192.168.1.0/16", 65534, "192.168.0.1", "192.168.255.254"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			tg, err := ParseTargets(tc.in)
			if err != nil {
				t.Fatalf("ParseTargets(%q): %v", tc.in, err)
			}
			if got := tg.Len(); got != tc.hosts {
				t.Fatalf("hosts = %d, want %d", got, tc.hosts)
			}
			var first, last string
			n := 0
			tg.Each(func(ip string) bool {
				if n == 0 {
					first = ip
				}
				last = ip
				n++
				return true
			})
			if n != tc.hosts {
				t.Fatalf("iterated %d hosts, want %d", n, tc.hosts)
			}
			if first != tc.first || last != tc.last {
				t.Errorf("range = %s..%s, want %s..%s", first, last, tc.first, tc.last)
			}
		})
	}
}

// A /8 is 16.7 million addresses. It has to be describable and iterable without
// ever building that list, or naming one exhausts memory before a packet moves.
func TestASlashEightIsCountedWithoutBeingMaterialised(t *testing.T) {
	tg, err := ParseTargets("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if got := tg.Len(); got != 16777214 {
		t.Fatalf("hosts = %d, want 16777214", got)
	}
	// Stop after a handful: Each must be lazy, not an iteration over a slice
	// that was already built.
	n := 0
	tg.Each(func(string) bool { n++; return n < 5 })
	if n != 5 {
		t.Fatalf("Each ran %d times after being told to stop at 5", n)
	}
}

func TestParseTargetsRefusesWhatIsNotATarget(t *testing.T) {
	for _, in := range []string{"", "-oN/tmp/x", "10.0.0.0/33", "10.0.0.0/-1", "not a host", "10.0.0.0/24/24"} {
		if _, err := ParseTargets(in); err == nil {
			t.Errorf("ParseTargets(%q) was accepted", in)
		}
	}
}

// masscan takes CIDR natively and is the only sane way to cross a large range,
// so the spec has to survive the round trip rather than being expanded into
// sixty-five thousand arguments.
func TestTargetsRenderBackToASpecForExternalTools(t *testing.T) {
	tg, err := ParseTargets("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.Spec(); got != "10.0.0.0/16" {
		t.Errorf("Spec() = %q, want the CIDR unchanged", got)
	}
	if !strings.Contains(tg.String(), "65534") {
		t.Errorf("String() = %q, want it to say how many hosts that is", tg.String())
	}
}

// A /8 is 16.7 million addresses. Typing one when a /24 was meant is an easy
// mistake with a very expensive outcome, so the size has to be something a
// caller can check before starting.
func TestARangeCanBeSizedBeforeItIsScanned(t *testing.T) {
	cases := map[string]int{
		"10.0.0.7":    1,
		"10.0.0.0/24": 254,
		"10.0.0.0/16": 65534,
		"10.0.0.0/8":  16777214,
		"10.0.0.0/32": 1,
	}
	for spec, want := range cases {
		tg, err := ParseTargets(spec)
		if err != nil {
			t.Fatalf("ParseTargets(%q): %v", spec, err)
		}
		if got := tg.Len(); got != want {
			t.Errorf("%s: %d hosts, want %d", spec, got, want)
		}
		if want > 1 && !tg.IsRange() {
			t.Errorf("%s: IsRange() false", spec)
		}
	}
}
