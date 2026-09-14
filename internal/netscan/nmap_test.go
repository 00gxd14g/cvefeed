package netscan

import (
	"context"
	"strings"
	"testing"
)

// Real output from `nmap -sV -Pn -p 80,443 -oX -`, trimmed to the elements this
// parser reads. Two things in it matter beyond the parsing: nmap reports a
// closed port alongside the open one, and the CPE it volunteers for nginx names
// a vendor the corpus does not use.
const nmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.98">
<host starttime="1787234963"><status state="up" reason="arp-response"/>
<address addr="172.19.0.4" addrtype="ipv4"/>
<hostnames><hostname name="web.example.org" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.4p1 Debian 5+deb11u1" extrainfo="protocol 2.0" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.4p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0" method="probed" conf="10">
<cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/>
<service name="https" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
<service name="http-alt" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>`

func TestNmapXMLYieldsOnlyOpenPorts(t *testing.T) {
	hosts, err := parseNmapXML([]byte(nmapXML))
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	res := hosts[0]
	if res.Addr != "172.19.0.4" {
		t.Errorf("addr = %q", res.Addr)
	}
	for _, s := range res.Open {
		if s.Port == 443 {
			t.Errorf("a closed port was reported as a service: %+v", s)
		}
	}
	for _, u := range res.Unidentified {
		if u.Port == 443 {
			t.Errorf("a closed port was reported as unidentified: %+v", u)
		}
	}
}

func TestNmapVersionDetectionBeatsBannerGuessing(t *testing.T) {
	hosts, err := parseNmapXML([]byte(nmapXML))
	if err != nil {
		t.Fatal(err)
	}
	res := hosts[0]
	byPort := map[int]Service{}
	for _, s := range res.Open {
		byPort[s.Port] = s
	}

	ssh, ok := byPort[22]
	if !ok {
		t.Fatal("port 22 was not identified")
	}
	// nmap's version string carries the distribution's packaging after the
	// upstream version; the CPE has the part that can be compared.
	if ssh.Version != "8.4p1" {
		t.Errorf("ssh version = %q, want 8.4p1 taken from the cpe rather than the version string", ssh.Version)
	}
	if ssh.Vendor != "openbsd" || ssh.Product != "openssh" {
		t.Errorf("ssh identity = %s:%s, want openbsd:openssh", ssh.Vendor, ssh.Product)
	}

	nginx, ok := byPort[80]
	if !ok {
		t.Fatal("port 80 was not identified")
	}
	if nginx.Product != "nginx" || nginx.Version != "1.18.0" {
		t.Errorf("nginx identity = %s %s", nginx.Product, nginx.Version)
	}
}

// An open port nmap could not name is still an open port. It has to reach the
// operator, because it is the part of the host nothing was tested against.
func TestNmapOpenPortWithNoProductIsReportedAsUnidentified(t *testing.T) {
	hosts, err := parseNmapXML([]byte(nmapXML))
	if err != nil {
		t.Fatal(err)
	}
	res := hosts[0]
	var found bool
	for _, u := range res.Unidentified {
		if u.Port == 8080 {
			found = true
			if u.Reason == "" {
				t.Error("no reason recorded")
			}
		}
	}
	if !found {
		t.Errorf("port 8080 is open and unnamed but was not reported: %+v", res.Unidentified)
	}
}

// The target is the one piece of this command line that comes from outside. It
// must never be able to become an nmap option.
func TestATargetThatLooksLikeAFlagIsRefused(t *testing.T) {
	for _, bad := range []string{"-oN/tmp/x", "--script=evil", "-", ""} {
		if err := validateTarget(bad); err == nil {
			t.Errorf("validateTarget(%q) was accepted", bad)
		}
	}
	for _, ok := range []string{"10.0.0.7", "example.org", "2001:db8::1", "host-1.internal"} {
		if err := validateTarget(ok); err != nil {
			t.Errorf("validateTarget(%q) = %v, want accepted", ok, err)
		}
	}
}

// The whole point of asking the corpus: nmap's CPE dictionary and the corpus
// disagree about who publishes nginx, and taking nmap's word silently produces
// a CPE that matches nothing.
func TestTheCorpusOverrulesNmapsVendorWhenItNamesNothing(t *testing.T) {
	hosts, err := parseNmapXML([]byte(nmapXML))
	if err != nil {
		t.Fatal(err)
	}
	res := hosts[0]
	resolver := resolverFunc(func(_ context.Context, product string) ([]string, error) {
		if product == "nginx" {
			return []string{"f5"}, nil // what the corpus actually files it under
		}
		return []string{"openbsd"}, nil
	})
	if err := res.reconcileVendors(context.Background(), resolver); err != nil {
		t.Fatalf("reconcileVendors: %v", err)
	}

	for _, s := range res.Open {
		switch s.Port {
		case 80:
			if s.Vendor != "f5" {
				t.Errorf("nginx vendor = %q, want the corpus's f5 rather than nmap's igor_sysoev", s.Vendor)
			}
			if !strings.Contains(s.VendorNote, "igor_sysoev") {
				t.Errorf("the substitution was not recorded: %q", s.VendorNote)
			}
		case 22:
			if s.Vendor != "openbsd" {
				t.Errorf("ssh vendor = %q, want nmap's openbsd kept when the corpus agrees", s.Vendor)
			}
			if s.VendorNote != "" {
				t.Errorf("an agreeing vendor was annotated anyway: %q", s.VendorNote)
			}
		}
	}
}

// nmap's version attribute is not always a version. Where its probe can only
// bound the answer it writes prose — "9.6.0 or later" — and the CPE it emits
// carries no version at all. That absence is nmap saying it does not know, and
// reading the prose as a version turns it into a claim nobody made.
//
// The document below is real output against a PostgreSQL 16.15. Taking "9.6.0"
// from it would report every flaw fixed between 9.6 and 16.15 against a host
// that has none of them.
func TestAVersionNmapCouldOnlyBoundIsNotAVersion(t *testing.T) {
	const xml = `<nmaprun><host><address addr="10.0.0.3" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="5432"><state state="open"/>
<service name="postgresql" product="PostgreSQL DB" version="9.6.0 or later" method="probed" conf="10">
<cpe>cpe:/a:postgresql:postgresql</cpe></service></port>
</ports></host></nmaprun>`

	hosts, err := parseNmapXML([]byte(xml))
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if len(hosts) != 1 || len(hosts[0].Open) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
	svc := hosts[0].Open[0]
	if svc.Product != "postgresql" {
		t.Errorf("product = %q", svc.Product)
	}
	if svc.Version != "" {
		t.Errorf("version = %q; nmap said \"9.6.0 or later\" and put no version in its cpe, "+
			"which is it saying it cannot tell", svc.Version)
	}
	if svc.Scannable() {
		t.Error("a service with a bounded-only version claims to be scannable")
	}
	if svc.Why() == "" {
		t.Error("no reason recorded for why it cannot be scanned")
	}
	if svc.CPE() != "" {
		t.Errorf("cpe = %q; a CPE with no version matches every build ever shipped", svc.CPE())
	}
}

// The ordinary case must keep working: nmap puts the version in the CPE when it
// knows it, even where the version attribute carries the distribution's
// packaging as well.
func TestAVersionNmapPutInTheCPEIsTrusted(t *testing.T) {
	const xml = `<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.4p1 Debian 5+deb11u1" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.4p1</cpe></service></port>
</ports></host></nmaprun>`

	hosts, err := parseNmapXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	svc := hosts[0].Open[0]
	if svc.Version != "8.4p1" {
		t.Errorf("version = %q, want 8.4p1", svc.Version)
	}
}

// And a bare version with no CPE at all is still usable, as long as it is a
// version rather than a sentence.
func TestABareVersionWithNoCPEIsStillAVersion(t *testing.T) {
	const xml = `<nmaprun><host><address addr="10.0.0.2" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="lighttpd" version="1.4.55" method="probed" conf="10"/></port>
<port protocol="tcp" portid="81"><state state="open"/>
<service name="http" product="Some Server" version="probably 2 or 3" method="probed" conf="10"/></port>
</ports></host></nmaprun>`

	hosts, err := parseNmapXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	byPort := map[int]Service{}
	for _, s := range hosts[0].Open {
		byPort[s.Port] = s
	}
	if got := byPort[80].Version; got != "1.4.55" {
		t.Errorf("lighttpd version = %q, want 1.4.55", got)
	}
	if got := byPort[81].Version; got != "" {
		t.Errorf("version = %q, want empty: %q is not a version", got, "probably 2 or 3")
	}
}

// nmap's own target grammar accepts octet ranges and lists. "10.0.0.1-50"
// passed through as a single hostname — one address as far as -max-hosts was
// concerned — and nmap scanned fifty. A target with no letters in it is
// either an address or an nmap range, and only the first is a host.
func TestATargetThatNmapWouldReadAsARangeIsRefused(t *testing.T) {
	for _, bad := range []string{"10.0.0.1-50", "10.0.0.0-255", "10.0.0.1,5", "10.0.0-5.1", "192.168.1-2.1", "1-50"} {
		if err := validateTarget(bad); err == nil {
			t.Errorf("validateTarget(%q) was accepted; nmap reads it as more than one host", bad)
		}
		if _, err := ParseTargets(bad); err == nil {
			t.Errorf("ParseTargets(%q) was accepted", bad)
		}
	}
	// Hostnames with numeric labels are still hostnames.
	for _, ok := range []string{"1.example.com", "3com.example.net", "host-1.internal", "10.0.0.7", "2001:db8::1"} {
		if err := validateTarget(ok); err != nil {
			t.Errorf("validateTarget(%q) = %v, want accepted", ok, err)
		}
	}
}
