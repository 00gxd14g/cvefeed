package store

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// raw_records keeps every upstream document verbatim so normalisation can be
// re-derived without re-fetching. Nothing reads the column — only its hash is
// queried — so it is stored the way an archive is stored rather than the way a
// queryable value is, and jsonb was the wrong choice twice over: it parses on
// write, it is larger than the text it came from, and PostgreSQL's own pglz
// brought the pair back to roughly the size of the original.
//
// Measured over 2,000 real records: 8.25 MB of text, 861 KB gzipped, 487 KB
// with xz. The table was 4.1 KB per record stored against 4.1 KB per record
// raw, which is to say it was not being compressed at all.
func TestRawContentRoundTripsThroughCompression(t *testing.T) {
	doc := []byte(`{"id":"CVE-2021-44228","aliases":["GHSA-jfh8-c2jp-5v3q"],` +
		strings.Repeat(`"filler":"the quick brown fox jumps over the lazy dog",`, 50) +
		`"end":true}`)

	packed, err := compressDoc(doc)
	if err != nil {
		t.Fatalf("compressRaw: %v", err)
	}
	if len(packed) >= len(doc) {
		t.Errorf("compressed to %d bytes from %d; repetitive JSON must get smaller",
			len(packed), len(doc))
	}

	back, err := decompressDoc(packed)
	if err != nil {
		t.Fatalf("decompressRaw: %v", err)
	}
	if !bytes.Equal(back, doc) {
		t.Error("the document did not survive the round trip")
	}
}

func TestEmptyAndTinyDocumentsRoundTrip(t *testing.T) {
	for _, doc := range [][]byte{[]byte(""), []byte("{}"), []byte("null"), []byte(`{"a":1}`)} {
		packed, err := compressDoc(doc)
		if err != nil {
			t.Fatalf("compressDoc(%q): %v", doc, err)
		}
		back, err := decompressDoc(packed)
		if err != nil {
			t.Fatalf("decompressDoc(%q): %v", doc, err)
		}
		if !bytes.Equal(back, doc) {
			t.Errorf("%q became %q", doc, back)
		}
	}
}

// Rows written before the column changed are plain JSON with no container
// around them. They have to keep reading, because a migration that rewrites 1.6
// million rows needs as much free space as the table already occupies — which
// is the thing that ran out.
func TestUncompressedRowsAreStillReadable(t *testing.T) {
	plain := []byte(`{"id":"CVE-2021-44228"}`)
	back, err := decompressDoc(plain)
	if err != nil {
		t.Fatalf("decompressRaw: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Errorf("a legacy row became %q", back)
	}
}

// The point of the change is a number, so the number is asserted. A real CVE
// record stored through SaveRaw must occupy materially less than the document
// it came from — the previous jsonb column stored 4.1 KB per record for 4.1 KB
// of input, which is to say it was not compressing at all.
func TestAStoredDocumentIsMateriallySmallerThanTheDocument(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Shaped like the records the corpus is made of: repeated keys, long URLs,
	// prose descriptions.
	var b strings.Builder
	b.WriteString(`{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{`)
	b.WriteString(`"descriptions":[{"lang":"en","value":"A flaw was found in the way the component handled input. ` +
		strings.Repeat("An attacker able to reach the service could use this to cause a denial of service. ", 12) + `"}],`)
	b.WriteString(`"references":[`)
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"url":"https://lists.example.org/archives/list/security@example.org/thread/ABCDEF%04d/"}`, i)
	}
	b.WriteString(`]}}}`)
	doc := []byte(b.String())

	if _, err := st.SaveRaw(ctx, "cvelist", "CVE-2026-0001", doc); err != nil {
		t.Fatalf("SaveRaw: %v", err)
	}

	var stored int
	if err := st.db.QueryRowContext(ctx,
		`SELECT octet_length(content) FROM raw_records WHERE source = $1 AND record_id = $2`,
		"cvelist", "CVE-2026-0001").Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	ratio := float64(len(doc)) / float64(stored)
	t.Logf("%d bytes stored as %d (%.1fx)", len(doc), stored, ratio)
	if ratio < 4 {
		t.Errorf("stored %d bytes for a %d byte document (%.1fx); "+
			"the column exists to be an archive and this is barely smaller than the original",
			stored, len(doc), ratio)
	}

	// And it has to come back byte-identical, or the archive is worthless.
	var raw []byte
	if err := st.db.QueryRowContext(ctx,
		`SELECT content FROM raw_records WHERE source = $1 AND record_id = $2`,
		"cvelist", "CVE-2026-0001").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	back, err := decompressDoc(raw)
	if err != nil {
		t.Fatalf("decompressRaw: %v", err)
	}
	if !bytes.Equal(back, doc) {
		t.Error("the stored document did not come back identical")
	}
}
