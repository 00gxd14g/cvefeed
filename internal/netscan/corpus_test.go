package netscan

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
)

// The CPE vendor a product is filed under is not guessable and not stable
// across intuition: nginx is "f5", OpenSSH is "openbsd", vsftpd is "beasts",
// sendmail is "sendmail" and not "proofpoint" who now own it. Getting one wrong
// does not fail loudly — the CPE simply never matches anything, every finding
// for that service degrades to a bare-name match, and the default confidence
// floor hides it. The scan then reports a vulnerable host as clean.
//
// So this checks the table against a loaded corpus rather than against memory.
// It skips without one, because it is asking a question only real data answers.
//
//	CVEFEED_TEST_DATABASE_URL='postgres://…' go test ./internal/netscan/
func TestFingerprintVendorsExistInTheCorpus(t *testing.T) {
	dsn := os.Getenv("CVEFEED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CVEFEED_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("no corpus reachable: %v", err)
	}

	var total int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM vuln_affected`).Scan(&total); err != nil {
		t.Skipf("no corpus: %v", err)
	}
	if total == 0 {
		t.Skip("corpus is empty; nothing to check the table against")
	}

	products := map[string]bool{}
	for _, r := range rules {
		products[r.product] = true
	}
	list := make([]string, 0, len(products))
	for p := range products {
		list = append(list, p)
	}

	// Read from cpe_vendor_rank, the ranking the scanner itself consults.
	// Asking vuln_affected directly means unnesting an array across nine
	// million rows, which took two minutes here and is why the table exists.
	var ranked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cpe_vendor_rank`).Scan(&ranked); err != nil {
		t.Skipf("no cpe_vendor_rank: %v", err)
	}
	if ranked == 0 {
		t.Skip("cpe_vendor_rank is empty; run an ingest, which refreshes it")
	}

	rows, err := db.QueryContext(ctx, `
        SELECT product, vendor, vulns FROM (
            SELECT product, vendor, vulns,
                   row_number() OVER (PARTITION BY product ORDER BY vulns DESC, vendor) AS rank
              FROM cpe_vendor_rank WHERE product = ANY($1)
        ) r WHERE rank = 1`, pq.Array(list))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	best := map[string]struct {
		vendor string
		n      int
	}{}
	for rows.Next() {
		var product, vendor string
		var n int
		if err := rows.Scan(&product, &vendor, &n); err != nil {
			t.Fatal(err)
		}
		best[product] = struct {
			vendor string
			n      int
		}{vendor, n}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Counted by distinct vulnerabilities rather than by rows. NVD enumerates
	// every affected build as its own CPE, so a single verbose record outranks
	// several terse ones: vsftpd's "redhat" has 31 rows carrying one CVE from
	// 2008, while "vsftpd_project" has 5 rows carrying five separate ones.
	seen := map[string]bool{}
	for _, r := range rules {
		key := r.vendor + ":" + r.product
		if seen[key] {
			continue
		}
		seen[key] = true

		b, ok := best[r.product]
		switch {
		case !ok:
			t.Errorf("%s matches no CPE in the corpus, so every finding for this service "+
				"degrades to a bare-name match and the default floor hides it", key)
		case b.vendor != r.vendor:
			t.Errorf("the corpus files %s under %q, covering %d vulnerabilities, not under %q. "+
				"The resolver corrects this at runtime; the table should start from the better "+
				"answer for the case where no corpus is reachable.",
				r.product, b.vendor, b.n, r.vendor)
		}
	}
}
