package netscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// VendorResolver reports the CPE vendors a corpus files a product under.
//
// It exists because nmap's CPE dictionary and the vulnerability corpus do not
// always agree, and the disagreement is silent: nmap calls nginx
// "igor_sysoev:nginx", which matches nothing in a current corpus where the same
// product is filed under "f5" by 684 statements to 2. A CPE that matches nothing
// does not fail — it quietly demotes every finding for that service to a
// bare-name match, which the default confidence floor then hides.
//
// So the corpus gets the last word on the vendor, and the substitution is
// recorded rather than performed invisibly.
type VendorResolver interface {
	VendorsFor(ctx context.Context, product string) ([]string, error)
}

type resolverFunc func(ctx context.Context, product string) ([]string, error)

func (f resolverFunc) VendorsFor(ctx context.Context, p string) ([]string, error) { return f(ctx, p) }

// HasNmap reports whether nmap is on PATH.
func HasNmap() bool { _, err := exec.LookPath("nmap"); return err == nil }

// nmapRun is the subset of nmap's XML this reads. Everything else nmap reports —
// timing, host scripts, traceroute — is about the scan rather than about what
// is installed.
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string   `xml:"name,attr"`
				Product   string   `xml:"product,attr"`
				Version   string   `xml:"version,attr"`
				ExtraInfo string   `xml:"extrainfo,attr"`
				Tunnel    string   `xml:"tunnel,attr"`
				Method    string   `xml:"method,attr"`
				Conf      int      `xml:"conf,attr"`
				CPEs      []string `xml:"cpe"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// parseNmapXML turns one nmap run into a Result per host.
//
// A run can cover a whole range, so the hosts are kept apart: merging them
// would attribute one machine's services to another, which is the one mistake a
// sweep must not make.
func parseNmapXML(b []byte) ([]*Result, error) {
	var run nmapRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, fmt.Errorf("netscan: parse nmap xml: %w", err)
	}
	var out []*Result
	for _, h := range run.Hosts {
		res := &Result{}
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				res.Addr = a.Addr
				break
			}
		}
		if len(h.Hostnames) > 0 && res.Host == "" {
			res.Host = h.Hostnames[0].Name
		}
		for _, p := range h.Ports {
			res.Scanned++
			// Only open ports are evidence. nmap reports closed and filtered
			// ones too, and carrying them forward would put ports nothing is
			// listening on into a report about what is running.
			if p.State.State != "open" {
				continue
			}
			svc := serviceFromNmap(p.PortID, p.Service.Product, p.Service.Version,
				p.Service.CPEs, p.Service.Name, p.Service.ExtraInfo)
			if svc == nil {
				res.Unidentified = append(res.Unidentified, Unidentified{
					Port:   p.PortID,
					Banner: strings.TrimSpace(p.Service.Name + " " + p.Service.ExtraInfo),
					Reason: "nmap found the port open but could not name the software on it",
				})
				continue
			}
			res.Open = append(res.Open, *svc)
		}
		if res.Addr == "" && res.Host == "" {
			continue // a host element with no address is not about any machine
		}
		if res.Host == "" {
			res.Host = res.Addr
		}
		sort.Slice(res.Open, func(i, j int) bool { return res.Open[i].Port < res.Open[j].Port })
		sort.Slice(res.Unidentified, func(i, j int) bool {
			return res.Unidentified[i].Port < res.Unidentified[j].Port
		})
		out = append(out, res)
	}
	return out, nil
}

// serviceFromNmap builds a Service out of one <service> element.
//
// Where nmap knows a version it puts it in the CPE, and that is the only place
// this trusts. The version attribute is written for a human and says whatever
// the probe could establish, which is often less than a version: PostgreSQL
// reports "9.6.0 or later" with a CPE carrying no version at all. That absence
// is nmap saying it cannot tell, and reading "9.6.0" out of the prose turns it
// into a claim nobody made — against a host actually running 16.15, it would
// report every flaw fixed in the seven major versions between.
//
// Without any CPE, a version attribute is accepted only if it is a version
// rather than a sentence: one token, beginning with a digit. OpenSSH's "8.4p1
// Debian 5+deb11u1" is not a problem here because its CPE carries "8.4p1".
func serviceFromNmap(port int, product, version string, cpes []string, name, extra string) *Service {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil
	}
	version = strings.TrimSpace(version)
	s := &Service{
		Port:    port,
		Product: cpeAttr(product),
		Raw:     truncateBanner(strings.TrimSpace(product + " " + version + " " + extra)),
	}
	haveCPE := false
	for _, raw := range cpes {
		vendor, prod, ver, ok := splitCPE22(raw)
		if !ok {
			// cpe:/o:... describes the operating system, which is a different
			// inventory question from what is listening on this port.
			continue
		}
		haveCPE = true
		s.Vendor, s.Product = vendor, prod
		s.Version = ver
		break
	}
	if !haveCPE && looksLikeVersion(version) {
		s.Version = version
	}
	return s
}

// looksLikeVersion reports whether a string is a version rather than a sentence
// about one. Anything with a space in it is prose: nmap writes "9.6.0 or later",
// "probably 2 or 3", "1.4 - 1.6".
func looksLikeVersion(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t") {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

// splitCPE22 reads the application entries of nmap's CPE 2.2 URIs
// ("cpe:/a:vendor:product:version"). Operating-system and hardware entries are
// skipped: they answer a different question than "what is listening here".
func splitCPE22(raw string) (vendor, product, version string, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "cpe:/a:") {
		return "", "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "cpe:/a:"), ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if len(parts) > 2 {
		version = parts[2]
	}
	return parts[0], parts[1], version, true
}

// reconcileVendors replaces a vendor the corpus does not use with one it does.
//
// Leaving nmap's vendor in place when the corpus has never heard of it produces
// a CPE that matches nothing, and the failure is invisible: the finding degrades
// to a bare-name match and the default floor hides it. When a substitution is
// made it is written into VendorNote so the report can say the identity was
// adjusted and on whose authority.
func (r *Result) reconcileVendors(ctx context.Context, res VendorResolver) error {
	if res == nil {
		return nil
	}
	cache := map[string][]string{}
	for i := range r.Open {
		s := &r.Open[i]
		if s.Product == "" {
			continue
		}
		vendors, ok := cache[s.Product]
		if !ok {
			var err error
			if vendors, err = res.VendorsFor(ctx, s.Product); err != nil {
				return err
			}
			cache[s.Product] = vendors
		}
		if len(vendors) == 0 {
			continue // the corpus knows this product under no vendor; leave nmap's
		}
		agreed := false
		for _, v := range vendors {
			if v == s.Vendor {
				agreed = true
				break
			}
		}
		if agreed {
			continue
		}
		if s.Vendor != "" {
			s.VendorNote = fmt.Sprintf("nmap reported vendor %q, which names nothing in this corpus; using %q, which the corpus uses for %s",
				s.Vendor, vendors[0], s.Product)
		}
		s.Vendor = vendors[0]
	}
	return nil
}

// validateTarget refuses anything that could become an option rather than a
// host. The target is the one part of the command line that comes from outside,
// and nmap has options that write files and run scripts.
//
// It also refuses anything that nmap would read as more than one host. nmap's
// own target grammar accepts octet ranges and lists — "10.0.0.1-50",
// "10.0.0.1,5" — and a target like that passed through here as a single
// hostname: ParseTargets counted it as one address, the caller's -max-hosts
// check let it by, and nmap scanned fifty. So a comma is never accepted, and a
// target with no letter in it at all is accepted only if it parses as an
// address — a hostname has letters somewhere, and a string of digits, dots and
// hyphens that is not an address is an nmap range.
func validateTarget(t string) error {
	t = strings.TrimSpace(t)
	if t == "" {
		return fmt.Errorf("netscan: no target given")
	}
	if strings.HasPrefix(t, "-") {
		return fmt.Errorf("netscan: %q begins with a dash and would be read as an option", t)
	}
	if strings.ContainsAny(t, " \t\n\r\x00;|&$`'\"\\<>(){}[]*?!,") {
		return fmt.Errorf("netscan: %q is not a hostname or address", t)
	}
	if net.ParseIP(t) != nil {
		return nil
	}
	hasLetter := false
	for _, label := range strings.Split(t, ".") {
		if label == "" {
			return fmt.Errorf("netscan: %q is not a hostname or address", t)
		}
		for _, r := range label {
			switch {
			case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
				hasLetter = true
			case r == '-' || r == '_' || (r >= '0' && r <= '9'):
			default:
				return fmt.Errorf("netscan: %q is not a hostname or address", t)
			}
		}
	}
	if !hasLetter {
		return fmt.Errorf("netscan: %q is neither an address nor a hostname; a range must be written as a CIDR block", t)
	}
	return nil
}

// portList renders a port set as an nmap or masscan -p argument, collapsing
// runs into ranges.
//
// Both tools take a range, and enumerating instead turns a full scan into a
// 380 KB argument string that nmap spends longer parsing than scanning: -ports
// all took over ten minutes as a list against two minutes as "1-65535".
func portList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)

	var b strings.Builder
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(sorted[i]))
		if j > i {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(sorted[j]))
		}
		i = j + 1
	}
	return b.String()
}
