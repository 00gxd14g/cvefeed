package inventory

import (
	"net/url"
	"strings"
)

// cpe23 returns a CPE 2.3 formatted string, converting the CPE 2.2 URI binding
// on the way. Anything else yields "": a value that is not a CPE must not be
// offered to the matcher as one.
//
// A 2.3 string is passed through untouched. Its attributes carry backslash
// escapes (3.0.11-1\~deb12u2) that a split on ':' would mangle, and nothing
// here needs to look inside it.
func cpe23(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(strings.ToLower(s), "cpe:2.3:"):
		return s
	case strings.HasPrefix(strings.ToLower(s), "cpe:/"):
		return cpe23FromURI(s[len("cpe:/"):])
	}
	return ""
}

// cpe23FromURI rebinds a CPE 2.2 URI as a 2.3 formatted string. Several SBOM
// producers still emit the 2.2 form, and refusing it would throw away the only
// identity many operating-system components carry.
func cpe23FromURI(body string) string {
	fields := strings.Split(body, ":")
	at := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return ""
	}

	// 2.2 packs the four attributes it has no field for into edition, prefixed
	// with '~'. Unpacking them is not optional: an unpacked "~~~wordpress~~"
	// left in edition asserts a condition nothing can ever satisfy.
	edition, swEdition, targetSW, targetHW, other := at(5), "", "", "", ""
	if strings.HasPrefix(edition, "~") {
		packed := strings.Split(edition, "~")
		part := func(i int) string {
			if i < len(packed) {
				return packed[i]
			}
			return ""
		}
		edition, swEdition, targetSW, targetHW, other = part(1), part(2), part(3), part(4), part(5)
	}

	attrs := []string{
		at(0), at(1), at(2), at(3), at(4),
		edition, at(6), swEdition, targetSW, targetHW, other,
	}
	var b strings.Builder
	b.WriteString("cpe:2.3")
	for _, a := range attrs {
		b.WriteString(":")
		b.WriteString(cpeAttribute(a))
	}
	return b.String()
}

// cpeAttribute converts one URI-bound attribute to its formatted-string form:
// percent-decoded, lowercased, with the punctuation the binding reserves
// backslash-escaped. An empty attribute becomes ANY rather than the empty
// string, which is not a legal value.
func cpeAttribute(v string) string {
	if v == "" {
		return "*"
	}
	if d, err := url.PathUnescape(v); err == nil {
		v = d
	}
	if v == "-" || v == "*" {
		return v
	}
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_', r == '*', r == '?':
			// Printed unquoted by the formatted-string binding.
			b.WriteRune(r)
		default:
			b.WriteRune('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}
