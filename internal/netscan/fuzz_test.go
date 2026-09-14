package netscan

import (
	"strings"
	"testing"
)

// A banner is written entirely by whatever is listening on the far end, which
// on a scan of an untrusted host is an adversary. Identify must survive any
// bytes, and must never manufacture an identity out of them.
func FuzzIdentify(f *testing.F) {
	f.Add(22, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")
	f.Add(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n")
	f.Add(80, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	f.Add(21, "220 (vsFTPd 3.0.3)\r\n")
	f.Add(9999, "")
	f.Add(80, "Server: Apache/"+strings.Repeat("9", 4096))
	f.Add(22, "SSH-2.0-OpenSSH_"+strings.Repeat(".", 2048))

	f.Fuzz(func(t *testing.T, port int, banner string) {
		s := Identify(port, banner)
		if s == nil {
			return
		}
		// Whatever it decided, it must be internally consistent: a product with
		// no vendor, or a CPE built from neither, would be an identity nothing
		// can be checked against.
		if s.Product == "" {
			t.Fatalf("identified a service with no product from %q", banner)
		}
		if cpe := s.CPE(); cpe != "" {
			if s.Version == "" {
				t.Fatalf("built a CPE %q with no version; it would match every build ever shipped", cpe)
			}
			// A CPE 2.3 name has exactly 13 colon-separated fields, and an
			// unescaped colon inside one silently shifts every field after it.
			n := 0
			for i := 0; i < len(cpe); i++ {
				if cpe[i] == ':' && (i == 0 || cpe[i-1] != '\\') {
					n++
				}
			}
			if n != 12 {
				t.Fatalf("cpe %q has %d unescaped separators, want 12", cpe, n)
			}
		}
		// The banner carried into a report must not smuggle control characters
		// into a terminal.
		for _, r := range s.Raw {
			if r < 32 && r != ' ' {
				t.Fatalf("raw banner kept control byte %q from %q", r, banner)
			}
		}
	})
}
