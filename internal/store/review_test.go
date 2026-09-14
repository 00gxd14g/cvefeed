package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// Publishers do spell identifiers in lower case. The resolver normalises what
// it looks up, so a document that kept the raw spelling beside the canonical
// one listed the same alias twice and wrote both spellings into vuln_aliases.
func TestMergeNormalisesAliasSpelling(t *testing.T) {
	in := &model.Vulnerability{
		ID: "CVE-2026-0001", Source: "osv",
		Aliases: []string{"ghsa-JFH8-C2JP-5v3q", " cve-2026-0002"},
		Related: []string{"cve-2026-0003"},
	}
	doc := Merge(nil, in)
	if want := []string{"CVE-2026-0002", "GHSA-jfh8-c2jp-5v3q"}; !reflect.DeepEqual(doc.Aliases, want) {
		t.Errorf("aliases = %v, want %v", doc.Aliases, want)
	}
	if want := []string{"CVE-2026-0003"}; !reflect.DeepEqual(doc.Related, want) {
		t.Errorf("related = %v, want %v", doc.Related, want)
	}

	// The canonical spelling arriving later adds nothing.
	later := &model.Vulnerability{ID: "CVE-2026-0001", Source: "cvelist", Aliases: []string{"CVE-2026-0002"}}
	doc = Merge(doc, later)
	if want := []string{"CVE-2026-0002", "GHSA-jfh8-c2jp-5v3q"}; !reflect.DeepEqual(doc.Aliases, want) {
		t.Errorf("aliases after re-merge = %v, want %v", doc.Aliases, want)
	}
}

// A source that contributed only text is still a source of the document. It
// dropped out of the sources column — the one the source filter and the stats
// read — as soon as a higher-ranked record took over the text fields, because
// only child rows were counted.
func TestCollectSourcesKeepsATextOnlyContributor(t *testing.T) {
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	osv := &model.Vulnerability{ID: "CVE-2026-0010", Title: "from osv", Source: "osv",
		SourceRecordID: "GHSA-aaaa-bbbb-cccc", Modified: &when}
	cna := &model.Vulnerability{ID: "CVE-2026-0010", Description: "from the cna", Source: "cvelist",
		SourceRecordID: "CVE-2026-0010", Modified: &when,
		References: []model.Reference{{URL: "https://example.org", Source: "cvelist"}}}
	doc := Merge(Merge(nil, osv), cna)
	if doc.Source != "cvelist" {
		t.Fatalf("document source = %q, want cvelist", doc.Source)
	}
	if got, want := collectSources(doc), []string{"cvelist", "osv"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources = %v, want %v", got, want)
	}
}

func TestCleanJSONStripsNULButLeavesAnEscapedBackslashAlone(t *testing.T) {
	// A backslash followed by u0000 is six characters of text a publisher
	// literally wrote; it must survive untouched.
	in := []model.Reference{{URL: "https://example.org/\x00x", Name: `literal \u0000`, Source: "osv"}}
	payload, err := cleanJSON(jsonMarshal(in))
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Reference
	if err := jsonUnmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if out[0].URL != "https://example.org/x" {
		t.Errorf("url = %q, want the NUL removed", out[0].URL)
	}
	if out[0].Name != `literal \u0000` {
		t.Errorf("name = %q, want the literal text kept", out[0].Name)
	}
	if cleanText("plain") != "plain" {
		t.Error("cleanText changed a string with nothing to remove")
	}
}
