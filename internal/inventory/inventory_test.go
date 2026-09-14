package inventory

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestParseIdentifiesTheFormatFromTheContentAlone(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantFirst string
		wantCount int
	}{
		{
			name:      "cyclonedx by its bomFormat key",
			input:     cycloneDXFixture,
			wantFirst: "debian",
			wantCount: 8,
		},
		{
			name:      "spdx by its spdxVersion key",
			input:     spdxFixture,
			wantFirst: "openssl",
			wantCount: 4,
		},
		{
			name:      "a purl list by its lines",
			input:     purlListFixture,
			wantFirst: "openssl",
			wantCount: 13,
		},
		{
			name:      "a json array of purl strings",
			input:     `["pkg:npm/lodash@4.17.20", "pkg:pypi/requests@2.31.0"]`,
			wantFirst: "lodash",
			wantCount: 2,
		},
		{
			// The schema has required bomFormat since 1.2 and producers still
			// omit it; specVersion plus components is unambiguous enough.
			name:      "cyclonedx without its bomFormat key",
			input:     `{"specVersion":"1.5","components":[{"type":"library","name":"curl","version":"8.4.0"}]}`,
			wantFirst: "curl",
			wantCount: 1,
		},
		{
			name:      "spdx without its spdxVersion key",
			input:     `{"SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-a","name":"curl","versionInfo":"8.4.0"}]}`,
			wantFirst: "curl",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, err := Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(comps) != tt.wantCount {
				t.Fatalf("got %d components, want %d: %+v", len(comps), tt.wantCount, comps)
			}
			if comps[0].Name != tt.wantFirst {
				t.Errorf("first component = %q, want %q", comps[0].Name, tt.wantFirst)
			}
		})
	}
}

func TestParseDecompressesACompressedSBOM(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(cycloneDXFixture)); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	comps, err := Parse(&buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(comps) != 8 {
		t.Fatalf("got %d components from the gzipped BOM, want 8", len(comps))
	}
}

func TestParseNamesWhatItRefusedAndWhy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "cyclonedx xml",
			input: `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`,
			want:  "XML",
		},
		{
			name:  "native syft json names the command that fixes it",
			input: `{"artifacts":[{"id":"a"}],"artifactRelationships":[],"source":{"type":"image"},"descriptor":{"name":"syft","version":"1.18.1"}}`,
			want:  "syft <target> -o cyclonedx-json",
		},
		{
			name:  "native trivy json names the command that fixes it",
			input: `{"SchemaVersion":2,"ArtifactName":"alpine:3.19","Results":[{"Target":"alpine:3.19"}]}`,
			want:  "trivy --format cyclonedx",
		},
		{
			name:  "spdx 3.x",
			input: `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`,
			want:  "SPDX 3.x",
		},
		{
			name:  "spdx 2.1",
			input: `{"spdxVersion":"SPDX-2.1","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`,
			want:  "SPDX-2.1",
		},
		{
			name:  "some other json says which keys it found",
			input: `{"vulnerabilities":[],"scanned_at":"2026-08-17"}`,
			want:  `"vulnerabilities", "scanned_at"`,
		},
		{
			name:  "text that is not a purl list quotes the offending line",
			input: "# installed\nopenssl 3.0.11\nzlib 1.2.13\n",
			want:  `line 2 is "openssl 3.0.11"`,
		},
		{
			name:  "an empty input",
			input: "   \n\n",
			want:  "empty",
		},
		{
			name:  "a json array of something else",
			input: `[{"name":"openssl","version":"3.0.11"}]`,
			want:  "package URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input))
			if err == nil {
				t.Fatal("parsed without error; reporting zero findings for a document we cannot read tells the user they are safe")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v\nwant it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseKeepsTheOriginOfEveryComponent(t *testing.T) {
	// A finding has to be traceable back to the inventory entry that produced
	// it, whichever document that was.
	tests := []struct {
		input string
		want  string
	}{
		{cycloneDXFixture, "cyclonedx"},
		{spdxFixture, "spdx"},
		{purlListFixture, "purl-list"},
	}
	for _, tt := range tests {
		comps, err := Parse(strings.NewReader(tt.input))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		for _, c := range comps {
			if c.Origin != tt.want {
				t.Errorf("component %q has origin %q, want %q", c.Name, c.Origin, tt.want)
			}
		}
	}
}
