package parse

import "testing"

// An aggregate advisory lists every CVE its package build fixed, and it lists
// them in `aliases`. Reading that as an equivalence class merges vulnerabilities
// that have nothing to do with each other.
//
// Both documents below are real OSV records, trimmed. The Android bulletin
// bundles five distinct CVEs; the CleanStart advisory bundles fifteen Python
// ones. Observed live: one CVE absorbed 10,088 aliases and 3,257 applicability
// statements, so that log4j-core and lodash ended up on the same record.
func TestAliasesThatBundleSeveralCVEsAreNotAnIdentityClaim(t *testing.T) {
	const androidBulletin = `{
      "id": "ASB-A-258759189",
      "aliases": ["A-258759189", "A-258759192", "ASB-A-258759192",
                  "CVE-2022-44434", "CVE-2022-44435", "CVE-2022-44436",
                  "CVE-2022-44437", "CVE-2022-44438", "U-2064988"],
      "modified": "2026-01-01T00:00:00Z"
    }`

	v, err := OSVToModel([]byte(androidBulletin), "osv")
	if err != nil {
		t.Fatalf("OSVToModel: %v", err)
	}
	if len(v.Aliases) != 0 {
		t.Errorf("aliases = %v; five distinct CVEs cannot all name one flaw, so none of the set is an identity claim",
			v.Aliases)
	}
	// The information must not be thrown away either: it is how an operator
	// gets from the bulletin to the individual advisories.
	for _, want := range []string{"CVE-2022-44434", "CVE-2022-44438", "ASB-A-258759192"} {
		if !contains(v.Related, want) {
			t.Errorf("related = %v, want it to keep %s", v.Related, want)
		}
	}
}

// The rule must not fire on the ordinary case, which is the whole point of the
// alias graph: one flaw carrying one CVE plus the ecosystem's own identifiers.
func TestASingleCVEAmongAliasesStillAssertsIdentity(t *testing.T) {
	const ghsa = `{
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "modified": "2026-01-01T00:00:00Z"
    }`

	v, err := OSVToModel([]byte(ghsa), "osv")
	if err != nil {
		t.Fatalf("OSVToModel: %v", err)
	}
	if !contains(v.Aliases, "CVE-2021-44228") {
		t.Fatalf("aliases = %v, want the CVE: this is exactly the merge the graph exists to make", v.Aliases)
	}
}

// Two CVE ids can legitimately name one flaw when one was assigned in error and
// rejected as a duplicate. Refusing that merge leaves two records where one
// would do, which is a cost worth paying: an unmerged pair stays fixable, while
// a wrong merge destroys both records' identities and everything folded after.
func TestADuplicateCVEAssignmentIsRefusedRatherThanGuessed(t *testing.T) {
	const dup = `{
      "id": "GHSA-j7hp-h8jx-5ppr",
      "aliases": ["CVE-2023-4863", "CVE-2023-5129"],
      "modified": "2026-01-01T00:00:00Z"
    }`

	v, err := OSVToModel([]byte(dup), "osv")
	if err != nil {
		t.Fatalf("OSVToModel: %v", err)
	}
	if len(v.Aliases) != 0 {
		t.Errorf("aliases = %v; the pair is indistinguishable from a bundle at this layer", v.Aliases)
	}
	if !contains(v.Related, "CVE-2023-5129") {
		t.Errorf("related = %v, want the pairing preserved", v.Related)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// `upstream` says where a record was derived from, not what it is. The hardened
// image producers — MinimOS, Chainguard, CleanStart, Echo, BellSoft, TuxCare,
// Root — republish upstream CVEs against their own package builds, which the
// research report calls out by name as high volume and low novelty. MinimOS
// alone ships about 117k such records.
//
// Treating that derivation as identity folds every rebuild into the CVE it was
// built from. Observed live: CVE-2018-1099 had absorbed 18,240 aliases, 15,902
// of them MINI records.
//
// The document below is a real MinimOS record, trimmed.
func TestUpstreamIsADerivationNotAnIdentity(t *testing.T) {
	const rebuild = `{
      "id": "MINI-mr8c-7qjg-8hmp",
      "upstream": ["CVE-2026-42500", "GHSA-m6fh-wvw4-4629", "GO-2026-5031"],
      "modified": "2026-01-01T00:00:00Z"
    }`

	v, err := OSVToModel([]byte(rebuild), "osv")
	if err != nil {
		t.Fatalf("OSVToModel: %v", err)
	}
	if len(v.Aliases) != 0 {
		t.Errorf("aliases = %v; a rebuild of a package is not the vulnerability it was rebuilt against",
			v.Aliases)
	}
	for _, want := range []string{"CVE-2026-42500", "GO-2026-5031"} {
		if !contains(v.Related, want) {
			t.Errorf("related = %v, want it to record the derivation %s", v.Related, want)
		}
	}
}

// Publishers routinely repeat a record's own identifier inside its alias list.
// It is not an alias — it is the identity — and letting it through puts a
// self-edge in a graph whose whole job is to connect *different* identifiers,
// and adds to the CVE count that decides whether an alias set is a bundle.
//
// Found by fuzzing, which reached it in under five seconds.
func TestARecordIsNotItsOwnAlias(t *testing.T) {
	for _, doc := range []string{
		`{"id":"CVE-2021-44228","aliases":["CVE-2021-44228","GHSA-jfh8-c2jp-5v3q"],"modified":"2026-01-01T00:00:00Z"}`,
		`{"id":"GHSA-a","upstream":["GHSA-a"],"modified":"2026-01-01T00:00:00Z"}`,
		`{"id":"DSA-1","related":["DSA-1"],"modified":"2026-01-01T00:00:00Z"}`,
	} {
		v, err := OSVToModel([]byte(doc), "osv")
		if err != nil {
			t.Fatalf("OSVToModel(%s): %v", doc, err)
		}
		for _, a := range v.Aliases {
			if a == v.ID {
				t.Errorf("%s: aliases = %v, must not contain the record's own id", doc, v.Aliases)
			}
		}
		for _, r := range v.Related {
			if r == v.ID {
				t.Errorf("%s: related = %v, must not contain the record's own id", doc, v.Related)
			}
		}
	}
	// The alias that is not the record's own id must survive the filter.
	v, err := OSVToModel([]byte(`{"id":"CVE-2021-44228","aliases":["CVE-2021-44228","GHSA-jfh8-c2jp-5v3q"],"modified":"2026-01-01T00:00:00Z"}`), "osv")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(v.Aliases, "GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("aliases = %v, want the GHSA kept", v.Aliases)
	}
}
