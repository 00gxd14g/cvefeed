package store

import (
	"bytes"
	"strings"
	"testing"
)

// Both jsonb columns are archives of whole documents: nothing queries inside
// them, they are read back and unmarshalled in Go. Storing them compressed is
// worth several gigabytes, and which compressor is right is a measurement
// rather than a preference.
//
// Per document, over 500 real records averaging 6.8 KB:
//
//	xz     5.2x   6352 µs to compress   1280 µs to read
//	gzip   5.4x    269 µs               43 µs
//
// gzip wins on both axes because these are small inputs: xz's advantage comes
// from a large window over a large stream, and on one document its setup cost
// dominates and buys nothing. The first version of this used xz and was 24×
// slower to write for a slightly worse ratio.
func TestCompressRoundTripsAndShrinks(t *testing.T) {
	doc := []byte(`{"id":"CVE-2021-44228","references":[` +
		strings.Repeat(`{"url":"https://lists.example.org/archives/thread/ABCDEF/"},`, 60) +
		`{"url":"https://example.org/"}]}`)

	packed, err := compressDoc(doc)
	if err != nil {
		t.Fatalf("compressDoc: %v", err)
	}
	if len(packed) >= len(doc)/2 {
		t.Errorf("compressed to %d from %d; repetitive JSON must halve at least", len(packed), len(doc))
	}
	back, err := decompressDoc(packed)
	if err != nil {
		t.Fatalf("decompressDoc: %v", err)
	}
	if !bytes.Equal(back, doc) {
		t.Error("the document did not survive the round trip")
	}
}

// Three shapes have to read: gzip, the xz an earlier version wrote into
// raw_records, and the bare JSON of rows written before any of this. A
// migration that rewrites every row needs as much free space as the tables
// occupy, and that was the resource that ran out in the first place.
func TestEveryStoredShapeStillReads(t *testing.T) {
	doc := []byte(`{"id":"CVE-2021-44228","a":1}`)

	gzipped, err := compressDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	xzed, err := compressRawXZ(doc)
	if err != nil {
		t.Fatal(err)
	}

	for name, stored := range map[string][]byte{
		"gzip":       gzipped,
		"xz (older)": xzed,
		"bare json":  doc,
	} {
		back, err := decompressDoc(stored)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(back, doc) {
			t.Errorf("%s: came back as %q", name, back)
		}
	}
}

func TestTinyDocumentsAreStoredWhole(t *testing.T) {
	for _, doc := range [][]byte{[]byte(""), []byte("{}"), []byte(`{"a":1}`)} {
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
