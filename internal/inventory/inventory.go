// Package inventory turns a description of what is installed on a target into
// the component list the matcher tests against the corpus.
//
// Four inputs are supported: CycloneDX JSON, SPDX 2.2/2.3 JSON, a plain list of
// package URLs, and the package databases of the host this runs on. All four
// produce match.Component values and nothing else, so a scan is reproducible
// from the component list alone.
//
// Three rules run through every parser here.
//
// A field upstream did not supply stays empty rather than being guessed at. A
// component with no version can never produce a finding, which is the whole
// defence against one version-less SBOM entry named "openssl" matching every
// OpenSSL advisory ever published; inventing a version to fill the hole defeats
// it.
//
// A malformed entry is skipped, not fatal. An SBOM with one unreadable
// component still describes the other nine hundred, and refusing the document
// would tell the operator nothing at all about them.
//
// Some things the specification asks for cannot be carried through
// match.Component and are deliberately left out rather than approximated: the
// dependency graph and per-entry locators, which the contract has no field for,
// and the candidates that may only ever produce a review item — a derivative
// distribution's parent namespace (Linux Mint against Ubuntu) and a crates.io
// hyphen/underscore variant. Emitting those as ordinary components would turn
// "a human should look at this" into a finding, which is the opposite of what
// they are for.
//
// A format that cannot be read is refused loudly, naming the format found and,
// where one exists, the command that produces a supported one. A scanner that
// accepts a document it cannot really parse and then reports zero findings has
// told the user they are safe, which is the one failure worse than a false
// positive.
package inventory

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/ulikunitz/xz"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// maxDocument bounds what one input may expand to. The limit is there for the
// compressed paths, where a few kilobytes can name terabytes.
const maxDocument = 512 << 20

// maxDecompress bounds nesting. One layer is a compressed SBOM, two is a
// double-compressed one, three is someone probing for a decompression bomb.
const maxDecompress = 2

var (
	gzipMagic = []byte{0x1f, 0x8b}
	xzMagic   = []byte{0xfd, '7', 'z', 'X', 'Z'}
)

var (
	spdx2xRe  = regexp.MustCompile(`^SPDX-2\.[23]$`)
	spdxOldRe = regexp.MustCompile(`^SPDX-2\.[01]$`)
)

// Parse sniffs the format and returns the components it describes.
//
// The format is decided from the content and never from a file name. An SBOM
// arrives on a pipe as often as in a file, and producers name their output
// .json, .sbom, .cdx.json and .spdx.json interchangeably, so trusting the
// extension turns a readable document into "0 findings".
func Parse(r io.Reader) ([]match.Component, error) {
	doc, err := readDocument(r, 0)
	if err != nil {
		return nil, err
	}
	body := bytes.TrimLeft(doc, " \t\r\n")
	if len(body) == 0 {
		return nil, errors.New("inventory: input is empty")
	}
	switch body[0] {
	case '{':
		return parseJSONObject(doc)
	case '[':
		return parseJSONArray(doc)
	case '<':
		return nil, errors.New("inventory: XML SBOMs (CycloneDX XML, SPDX RDF or tag-value) are not supported by scan/1; re-export the document as JSON")
	}
	if err := looksLikePURLList(doc); err != nil {
		return nil, err
	}
	return ParsePURLList(bytes.NewReader(doc))
}

// readDocument reads the whole input, transparently decompressing gzip and xz.
func readDocument(r io.Reader, depth int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxDocument+1))
	if err != nil {
		return nil, fmt.Errorf("inventory: read input: %w", err)
	}
	if len(buf) > maxDocument {
		return nil, fmt.Errorf("inventory: input exceeds the %d byte limit", maxDocument)
	}
	switch {
	case bytes.HasPrefix(buf, gzipMagic):
		if depth >= maxDecompress {
			return nil, fmt.Errorf("inventory: input is compressed more than %d times", maxDecompress)
		}
		zr, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("inventory: gzip reader: %w", err)
		}
		defer zr.Close()
		return readDocument(zr, depth+1)
	case bytes.HasPrefix(buf, xzMagic):
		if depth >= maxDecompress {
			return nil, fmt.Errorf("inventory: input is compressed more than %d times", maxDecompress)
		}
		xr, err := xz.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("inventory: xz reader: %w", err)
		}
		return readDocument(xr, depth+1)
	}
	return buf, nil
}

// parseJSONObject decides which JSON document this is from its top-level keys,
// and refuses the ones a scanner is regularly handed by mistake.
func parseJSONObject(doc []byte) ([]match.Component, error) {
	keys, err := topLevelKeys(doc)
	if err != nil {
		return nil, err
	}
	spdxVersion := keys.values["spdxVersion"]
	switch {
	case strings.EqualFold(keys.values["bomFormat"], "CycloneDX"):
		return ParseCycloneDX(bytes.NewReader(doc))
	case spdx2xRe.MatchString(spdxVersion):
		return ParseSPDX(bytes.NewReader(doc))
	case spdxOldRe.MatchString(spdxVersion):
		return nil, fmt.Errorf("inventory: %s is not supported by scan/1; re-export as SPDX 2.3 JSON", spdxVersion)
	case strings.HasPrefix(spdxVersion, "SPDX-3"), keys.present["@context"]:
		return nil, errors.New("inventory: SPDX 3.x is not supported by scan/1; its serialisation is structurally different and a 2.x reader would silently find almost nothing in it. Re-export as SPDX 2.3 JSON")
	case keys.present["components"] && keys.values["specVersion"] != "":
		// A CycloneDX document missing the bomFormat key its own schema has
		// required since 1.2. Still unambiguous, so read it.
		return ParseCycloneDX(bytes.NewReader(doc))
	case keys.present["packages"] && keys.present["SPDXID"]:
		return ParseSPDX(bytes.NewReader(doc))
	case keys.present["artifacts"] && strings.EqualFold(keys.descriptor, "syft"):
		return nil, errors.New("inventory: this is native syft JSON, which carries no version ranges; re-run with `syft <target> -o cyclonedx-json`")
	case keys.present["Results"] && keys.present["SchemaVersion"]:
		return nil, errors.New("inventory: this is native Trivy JSON, which is a scan result rather than an inventory; re-run with `trivy --format cyclonedx`")
	}
	return nil, fmt.Errorf("inventory: unrecognised JSON document; its top-level keys are %s", strings.Join(quoteAll(keys.names), ", "))
}

// parseJSONArray handles the one array form that is an inventory: a list of
// package URL strings.
func parseJSONArray(doc []byte) ([]match.Component, error) {
	var entries []string
	if err := json.Unmarshal(doc, &entries); err != nil {
		return nil, fmt.Errorf("inventory: a JSON array input is only read as a list of package URL strings: %w", err)
	}
	lines := make([]purlLine, 0, len(entries))
	for i, e := range entries {
		e = strings.TrimSpace(e)
		if !strings.HasPrefix(e, "pkg:") {
			return nil, fmt.Errorf("inventory: JSON array element %d is %q, which is not a package URL", i, e)
		}
		lines = append(lines, purlLine{number: i + 1, text: e})
	}
	comps, _, err := purlComponents(lines)
	return comps, err
}

type jsonKeys struct {
	names      []string
	present    map[string]bool
	values     map[string]string
	descriptor string
}

// topLevelKeys reads the outermost object's keys, and the string values of the
// handful of them that identify a format. Nothing deeper is decoded, so a
// hundred-megabyte SBOM is classified without being modelled twice.
func topLevelKeys(doc []byte) (jsonKeys, error) {
	k := jsonKeys{present: map[string]bool{}, values: map[string]string{}}
	dec := json.NewDecoder(bytes.NewReader(doc))
	if _, err := dec.Token(); err != nil {
		return k, fmt.Errorf("inventory: read JSON document: %w", err)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return k, fmt.Errorf("inventory: read JSON key: %w", err)
		}
		name, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return k, fmt.Errorf("inventory: read the value of %q: %w", name, err)
		}
		k.names = append(k.names, name)
		k.present[name] = true
		var s string
		if json.Unmarshal(raw, &s) == nil {
			k.values[name] = s
		}
		if name == "descriptor" {
			var d struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(raw, &d) == nil {
				k.descriptor = d.Name
			}
		}
	}
	return k, nil
}

// rejectXML refuses an XML document handed to a JSON parser, because the
// alternative is an empty component list and a clean bill of health.
func rejectXML(doc []byte) error {
	if bytes.HasPrefix(bytes.TrimLeft(doc, " \t\r\n"), []byte("<")) {
		return errors.New("inventory: this is XML; CycloneDX XML and SPDX RDF or tag-value are not supported by scan/1, re-export the document as JSON")
	}
	return nil
}

// dedupe collapses entries that describe the same installed thing, keeping the
// first. Producers repeat a package once per file it appears in, and the same
// identity reported twice is the same finding twice.
//
// Qualifiers are left out of the key because identity drops them: a binary
// package and the source package it was built from carry the same name and
// version and differ only in arch, and reporting both would double every
// finding about them.
func dedupe(in []match.Component) []match.Component {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, c := range in {
		purlKey := c.PURL
		if i := strings.IndexAny(purlKey, "?#"); i >= 0 {
			purlKey = purlKey[:i]
		}
		k := strings.Join([]string{purlKey, c.Name, c.Version, c.Ecosystem, c.CPE, c.Vendor}, "\x00")
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	return out
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
