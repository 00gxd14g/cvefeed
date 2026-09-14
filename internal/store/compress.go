package store

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
)

// Two columns hold whole documents that nothing queries inside: raw_records
// .content, the upstream document kept verbatim, and vulnerabilities.doc, the
// merged record. Both are read back and unmarshalled in Go, so both are
// archives rather than values, and storing them as jsonb spent PostgreSQL's
// effort parsing a structure no query uses while its binary form came out
// larger than the text it came from.
//
// Which compressor is right was measured rather than assumed. Per document,
// over 500 real records averaging 6.8 KB:
//
//	xz     5.2x   6352 µs to compress   1280 µs to read
//	gzip   5.4x    269 µs                 43 µs
//
// gzip on both axes, because these are small inputs: xz's advantage comes from
// a large window over a large stream, and on a single document its setup cost
// dominates and buys nothing. An earlier version of this used xz on the strength
// of a ratio measured over three thousand documents concatenated — a shared
// dictionary no row ever gets — and was 24× slower to write for slightly worse
// compression.
//
// The difference matters because doc is on the read path. /v1/export streams
// the whole corpus: at xz's rate that is twenty-three minutes of decompression,
// and at gzip's it is forty-seven seconds.

// gzipMagic and xzMagic identify a stored value's shape.
//
// Three shapes have to read: gzip, the xz an earlier version wrote into
// raw_records, and the bare JSON of every row written before either. Converting
// them all needs as much free space as the tables occupy, which is the resource
// that ran out and started this — so rows convert as they are rewritten, and
// until then they are read where they are.
var (
	gzipMagic = []byte{0x1F, 0x8B}
	xzMagic   = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
)

// compressDoc packs a document for storage.
func compressDoc(doc []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(doc); err != nil {
		return nil, fmt.Errorf("store: compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("store: compress: %w", err)
	}
	// A short document comes out larger than it went in — the header alone is
	// eighteen bytes. Storing it whole costs nothing to read back, because the
	// magic bytes say which shape it is.
	if buf.Len() >= len(doc) {
		return doc, nil
	}
	return buf.Bytes(), nil
}

// decompressDoc reads a stored document back, in whichever shape it was written.
func decompressDoc(stored []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(stored, gzipMagic):
		r, err := gzip.NewReader(bytes.NewReader(stored))
		if err != nil {
			return nil, fmt.Errorf("store: decompress: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("store: decompress: %w", err)
		}
		return out, nil

	case bytes.HasPrefix(stored, xzMagic):
		r, err := xz.NewReader(bytes.NewReader(stored))
		if err != nil {
			return nil, fmt.Errorf("store: decompress xz: %w", err)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("store: decompress xz: %w", err)
		}
		return out, nil
	}
	return stored, nil
}

// compressRawXZ is kept only so a test can produce the older shape and prove it
// still reads. Nothing writes xz any more.
func compressRawXZ(doc []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(doc); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
