package inventory

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// maxPURLLine bounds one line. A purl is a few hundred bytes; a megabyte on one
// line means the input is not a purl list at all.
const maxPURLLine = 1 << 20

type purlLine struct {
	number int
	text   string
}

// ParsePURLList reads a plain list of package URLs, one per line.
//
// '#' introduces a comment only as the first non-space character of a line.
// purl spends '#' on its own subpath component, so stripping everything after
// the first '#' anywhere on the line silently turns
// pkg:golang/github.com/x/y#subpkg into a statement about a different package.
func ParsePURLList(r io.Reader) ([]match.Component, error) {
	comps, _, err := parsePURLListReport(r)
	return comps, err
}

// ParsePURLListWithReport is ParsePURLList plus the entries it could not use.
func ParsePURLListWithReport(r io.Reader) ([]match.Component, Report, error) {
	return parsePURLListReport(r)
}

func parsePURLListReport(r io.Reader) ([]match.Component, Report, error) {
	doc, err := readDocument(r, 0)
	if err != nil {
		return nil, Report{}, err
	}
	var lines []purlLine
	sc := bufio.NewScanner(bytes.NewReader(doc))
	sc.Buffer(make([]byte, 0, 64<<10), maxPURLLine)
	for n := 1; sc.Scan(); n++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		lines = append(lines, purlLine{number: n, text: text})
	}
	if err := sc.Err(); err != nil {
		return nil, Report{}, fmt.Errorf("inventory: read purl list: %w", err)
	}
	return purlComponents(lines)
}

// purlComponents converts already-isolated entries, skipping the ones that are
// not package URLs.
func purlComponents(lines []purlLine) ([]match.Component, Report, error) {
	out := make([]match.Component, 0, len(lines))
	var report Report
	bad := 0
	var firstBad purlLine
	for _, line := range lines {
		p, ok := parsePURL(line.text)
		if !ok {
			if bad == 0 {
				firstBad = line
			}
			bad++
			// Recorded rather than merely counted: a line that is not a package
			// URL is a component that will never be scanned, and the operator
			// is entitled to know which one.
			report.add(line.number, line.text, "not a package URL")
			continue
		}
		out = append(out, componentFromPURL(p, normalisePURL(line.text), "purl-list"))
	}
	// One unreadable line is a typo and the rest of the file is still an
	// inventory. A tenth of them unreadable means this is not a purl list, and
	// reporting on the remainder would understate how much was never scanned.
	//
	// The single typo is exempt from the ratio outright. A tenth of a short
	// list is less than one line, so the ratio alone refused a three-line file
	// for one misspelt entry — and that entry is already in the report, which
	// is the right place for it.
	if bad > 1 && bad*10 > len(lines) {
		return nil, report, fmt.Errorf("inventory: purl list: %d of %d entries are not package URLs (first at line %d: %q)",
			bad, len(lines), firstBad.number, firstBad.text)
	}
	return dedupe(out), report, nil
}

// looksLikePURLList decides whether a text input is a purl list at all, before
// the tolerant per-line parse runs. A file where some lines are not purls is
// some other format being read by the wrong parser, so it is named and refused
// rather than silently reduced to the lines that happened to parse.
func looksLikePURLList(doc []byte) error {
	entries := 0
	sc := bufio.NewScanner(bytes.NewReader(doc))
	sc.Buffer(make([]byte, 0, 64<<10), maxPURLLine)
	for n := 1; sc.Scan(); n++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if !strings.HasPrefix(text, "pkg:") {
			return fmt.Errorf("inventory: input is not a supported format; it is not JSON and line %d is %q, which does not begin with \"pkg:\"", n, truncate(text, 80))
		}
		entries++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("inventory: read input: %w", err)
	}
	if entries == 0 {
		return fmt.Errorf("inventory: input contains no package URLs and no recognisable SBOM")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
