package collect

import (
	"strings"
	"testing"
)

// A CSAF product tree carries machine-readable identifiers next to every leaf,
// and the collector was keeping only the display name. Red Hat's advisories put
// a purl on 85 of 86 leaves; the name beside it reads
//
//	glibc-langpack-kok-0:2.34-28.el9_0.6.s390x as a component of
//	Red Hat Enterprise Linux AppStream EUS (v.9.0)
//
// which is a package, an epoch, a version, a release, an architecture and a
// parent product flattened into one string. Nothing will ever report a
// component by that name, and the version that should be compared is inside it
// rather than in the version field — so those statements could never match
// anything. There were 13.6 million of them, more than half the table.
func TestCSAFProductsKeepTheirMachineReadableIdentity(t *testing.T) {
	const tree = `{
      "branches": [{
        "category": "vendor", "name": "Red Hat",
        "branches": [{
          "category": "product_family", "name": "Red Hat Enterprise Linux",
          "branches": [{
            "category": "product_name",
            "name": "Red Hat Enterprise Linux AppStream EUS (v.8.6)",
            "product": {
              "product_id": "AppStream-8.6.0.Z.EUS",
              "name": "Red Hat Enterprise Linux AppStream EUS (v.8.6)",
              "product_identification_helper": {"cpe": "cpe:/a:redhat:rhel_eus:8.6::appstream"}
            }
          }]
        }, {
          "category": "architecture", "name": "src",
          "branches": [{
            "category": "product_version",
            "name": "httpd-0:2.4.37-47.el8.6.src",
            "product": {
              "product_id": "httpd-0:2.4.37-47.el8.6.src",
              "name": "httpd-0:2.4.37-47.el8.6.src",
              "product_identification_helper": {
                "purl": "pkg:rpm/redhat/httpd@2.4.37-47.el8.6?arch=src&epoch=0"
              }
            }
          }]
        }]
      }]
    }`

	products := parseProductTree([]byte(tree))

	rpm, ok := products["httpd-0:2.4.37-47.el8.6.src"]
	if !ok {
		t.Fatalf("the rpm leaf was not collected: %+v", products)
	}
	if rpm.PURL != "pkg:rpm/redhat/httpd@2.4.37-47.el8.6?arch=src&epoch=0" {
		t.Errorf("purl = %q, want the one the document supplied", rpm.PURL)
	}
	// The purl names the package and the version separately, which is what a
	// range can be tested against.
	if rpm.Product != "httpd" {
		t.Errorf("product = %q, want httpd", rpm.Product)
	}
	if rpm.Version != "2.4.37-47.el8.6" {
		t.Errorf("version = %q, want 2.4.37-47.el8.6", rpm.Version)
	}

	plat, ok := products["AppStream-8.6.0.Z.EUS"]
	if !ok {
		t.Fatal("the platform leaf was not collected")
	}
	if plat.CPE != "cpe:/a:redhat:rhel_eus:8.6::appstream" {
		t.Errorf("cpe = %q", plat.CPE)
	}
	if plat.Vendor != "Red Hat" {
		t.Errorf("vendor = %q, want the one the branch path names", plat.Vendor)
	}
}

// Without a purl the leaf name is the product as its publisher writes it, and
// the branch path still supplies what the name leaves out — the vendor, and the
// version the categories separate.
func TestCSAFFallsBackToTheBranchPathRatherThanTheFlatName(t *testing.T) {
	const tree = `{
      "branches": [{
        "category": "vendor", "name": "Example Corp",
        "branches": [{
          "category": "product_name", "name": "Widget Server",
          "branches": [{
            "category": "product_version", "name": "3.1.4",
            "product": {"product_id": "widget-3.1.4", "name": "Widget Server 3.1.4 on Linux"}
          }]
        }]
      }]
    }`

	p, ok := parseProductTree([]byte(tree))["widget-3.1.4"]
	if !ok {
		t.Fatal("leaf not collected")
	}
	if p.Vendor != "Example Corp" || p.Product != "Widget Server 3.1.4 on Linux" || p.Version != "3.1.4" {
		t.Errorf("got vendor=%q product=%q version=%q", p.Vendor, p.Product, p.Version)
	}
	// The branch path supplies the version the leaf name does not separate out.
	if p.Version != "3.1.4" {
		t.Errorf("version = %q, want the product_version branch", p.Version)
	}
}

// Red Hat's product_status refers to relationship ids — "platform:package" —
// not to the branch leaves. The relationship points back at the leaf through
// product_reference, and that leaf is where the purl lives. Resolving only the
// branch tree leaves every one of those ids unmatched and falls back to the
// composite id itself, which is what produced 13.6 million statements whose
// product was a string like
//
//	AppStream-8.6.0.Z.EUS:httpd-0:2.4.37-47.module+el8.6.0+19809+6e655c60.7.aarch64::httpd:2.4
func TestCSAFRelationshipsInheritTheirComponentsIdentity(t *testing.T) {
	const tree = `{
      "branches": [{
        "category": "vendor", "name": "Red Hat",
        "branches": [{
          "category": "architecture", "name": "aarch64",
          "branches": [{
            "category": "product_version", "name": "httpd-0:2.4.37-47.el8.6.aarch64",
            "product": {
              "product_id": "httpd-0:2.4.37-47.el8.6.aarch64",
              "name": "httpd-0:2.4.37-47.el8.6.aarch64",
              "product_identification_helper": {
                "purl": "pkg:rpm/redhat/httpd@2.4.37-47.el8.6?arch=aarch64&epoch=0"
              }
            }
          }]
        }]
      }],
      "relationships": [{
        "category": "default_component_of",
        "full_product_name": {
          "product_id": "AppStream-8.6.0.Z.EUS:httpd-0:2.4.37-47.el8.6.aarch64",
          "name": "httpd-0:2.4.37-47.el8.6.aarch64 as a component of Red Hat Enterprise Linux AppStream EUS (v.8.6)"
        },
        "product_reference": "httpd-0:2.4.37-47.el8.6.aarch64",
        "relates_to_product_reference": "AppStream-8.6.0.Z.EUS"
      }]
    }`

	products := parseProductTree([]byte(tree))
	p, ok := products["AppStream-8.6.0.Z.EUS:httpd-0:2.4.37-47.el8.6.aarch64"]
	if !ok {
		t.Fatalf("the relationship id was not resolved: %v", keysOf(products))
	}
	if p.PURL != "pkg:rpm/redhat/httpd@2.4.37-47.el8.6?arch=aarch64&epoch=0" {
		t.Errorf("purl = %q, want the component's", p.PURL)
	}
	if p.Product != "httpd" || p.Version != "2.4.37-47.el8.6" {
		t.Errorf("product/version = %q/%q, want httpd/2.4.37-47.el8.6", p.Product, p.Version)
	}
}

func keysOf(m map[string]csafProduct) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Not every Red Hat advisory attaches a purl. Where it does not, the
// relationship still names its component precisely — product_reference is the
// NEVRA itself — while full_product_name.name is prose:
//
//	ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64 as a component of
//	Red Hat Ceph Storage 6.1 Tools
//
// Keeping the prose produced 78,398 statements with product names up to 203
// characters, none of which any inventory reports.
func TestCSAFFallsBackToTheNEVRARatherThanTheProse(t *testing.T) {
	const tree = `{
      "branches": [],
      "relationships": [{
        "category": "default_component_of",
        "full_product_name": {
          "product_id": "8Base-RHCEPH-6.1-Tools:ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
          "name": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64 as a component of Red Hat Ceph Storage 6.1 Tools"
        },
        "product_reference": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
        "relates_to_product_reference": "8Base-RHCEPH-6.1-Tools"
      }]
    }`

	p, ok := parseProductTree([]byte(tree))["8Base-RHCEPH-6.1-Tools:ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64"]
	if !ok {
		t.Fatal("relationship not resolved")
	}
	if p.Product != "ceph-mds-debuginfo" {
		t.Errorf("product = %q, want ceph-mds-debuginfo", p.Product)
	}
	if p.Version != "17.2.6-216.el8cp" {
		t.Errorf("version = %q, want 17.2.6-216.el8cp", p.Version)
	}
}

func TestNEVRASplitting(t *testing.T) {
	cases := map[string][2]string{
		"ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64":              {"ceph-mds-debuginfo", "17.2.6-216.el8cp"},
		"httpd-0:2.4.37-47.module+el8.6.0+19809+6e655c60.7.aarch64": {"httpd", "2.4.37-47.module+el8.6.0+19809+6e655c60.7"},
		"glibc-langpack-kok-0:2.34-28.el9_0.6.s390x":                {"glibc-langpack-kok", "2.34-28.el9_0.6"},
		"kernel-0:4.18.0-513.5.1.el8_9.src":                         {"kernel", "4.18.0-513.5.1.el8_9"},
		"not a nevra at all":                                        {"", ""},
		"Red Hat Enterprise Linux AppStream EUS (v.8.6)":            {"", ""},
	}
	for in, want := range cases {
		name, version, ok := splitNEVRA(in)
		if want[0] == "" {
			if ok {
				t.Errorf("splitNEVRA(%q) = %q/%q, want refusal", in, name, version)
			}
			continue
		}
		if !ok || name != want[0] || version != want[1] {
			t.Errorf("splitNEVRA(%q) = %q/%q, want %q/%q", in, name, version, want[0], want[1])
		}
	}
}

// Red Hat's container advisories carry neither a purl nor a NEVRA: the
// component is an image reference, and the relationship's name appends the
// platform to it —
//
//	registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2…_ppc64le
//	  as a component of Red Hat OpenShift AI
//
// The image reference is a real identity and the suffix is not part of it. Of
// 285,358 statements in one re-ingest, 170,191 still carried that suffix
// because the prose name was taken whenever the component could not be reduced
// further.
func TestCSAFPrefersTheComponentReferenceOverProse(t *testing.T) {
	const tree = `{
      "branches": [],
      "relationships": [{
        "category": "default_component_of",
        "full_product_name": {
          "product_id": "RHOAI:registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2_ppc64le",
          "name": "registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2_ppc64le as a component of Red Hat OpenShift AI"
        },
        "product_reference": "registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2_ppc64le",
        "relates_to_product_reference": "RHOAI"
      }]
    }`

	p, ok := parseProductTree([]byte(tree))["RHOAI:registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2_ppc64le"]
	if !ok {
		t.Fatal("relationship not resolved")
	}
	if strings.Contains(p.Product, "as a component of") {
		t.Errorf("product = %q; the platform suffix is not part of the component's identity", p.Product)
	}
	if p.Product != "registry.redhat.io/rhoai/odh-rhel9-operator@sha256:66e2_ppc64le" {
		t.Errorf("product = %q, want the component reference", p.Product)
	}
	// The prose is still the name a reader of the advisory sees.
	if !strings.Contains(p.Name, "as a component of") {
		t.Errorf("name = %q, want the advisory's own wording kept", p.Name)
	}
}

// Red Hat advisories without a purl still shape the tree the same way: the
// leaf sits under an architecture branch, in a product_version branch whose
// name is the NEVRA, and the leaf's own name is that NEVRA again. The
// product_version branch name was taken as the version and the leaf name as
// the product, so both were the whole string and splitNEVRA never ran; the
// relationship then preferred that component because it "had a version".
func TestCSAFLeavesWithoutAPurlSplitTheirNEVRA(t *testing.T) {
	const tree = `{
      "branches": [{
        "category": "vendor", "name": "Red Hat",
        "branches": [{
          "category": "product_family", "name": "Red Hat Ceph Storage",
          "branches": [{
            "category": "product_name", "name": "Red Hat Ceph Storage 6.1 Tools",
            "product": {
              "product_id": "8Base-RHCEPH-6.1-Tools",
              "name": "Red Hat Ceph Storage 6.1 Tools",
              "product_identification_helper": {"cpe": "cpe:/a:redhat:ceph_storage:6.1::el8"}
            }
          }]
        }, {
          "category": "architecture", "name": "x86_64",
          "branches": [{
            "category": "product_version", "name": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
            "product": {
              "product_id": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
              "name": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64"
            }
          }]
        }]
      }],
      "relationships": [{
        "category": "default_component_of",
        "full_product_name": {
          "product_id": "8Base-RHCEPH-6.1-Tools:ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
          "name": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64 as a component of Red Hat Ceph Storage 6.1 Tools"
        },
        "product_reference": "ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64",
        "relates_to_product_reference": "8Base-RHCEPH-6.1-Tools"
      }]
    }`

	products := parseProductTree([]byte(tree))
	leaf, ok := products["ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64"]
	if !ok {
		t.Fatalf("leaf not collected: %v", keysOf(products))
	}
	if leaf.Product != "ceph-mds-debuginfo" || leaf.Version != "17.2.6-216.el8cp" {
		t.Errorf("leaf product/version = %q/%q, want ceph-mds-debuginfo/17.2.6-216.el8cp", leaf.Product, leaf.Version)
	}
	if leaf.Vendor != "Red Hat" {
		t.Errorf("leaf vendor = %q, want the vendor branch", leaf.Vendor)
	}

	rel, ok := products["8Base-RHCEPH-6.1-Tools:ceph-mds-debuginfo-2:17.2.6-216.el8cp.x86_64"]
	if !ok {
		t.Fatalf("relationship not resolved: %v", keysOf(products))
	}
	if rel.Product != "ceph-mds-debuginfo" || rel.Version != "17.2.6-216.el8cp" {
		t.Errorf("relationship product/version = %q/%q, want ceph-mds-debuginfo/17.2.6-216.el8cp", rel.Product, rel.Version)
	}
	if !strings.Contains(rel.Name, "as a component of") {
		t.Errorf("name = %q, want the advisory's own wording kept", rel.Name)
	}
}

// A component without a purl or a NEVRA — a vendor product under a plain
// product_version branch — still lends the relationship its identity rather
// than the raw reference id.
func TestCSAFRelationshipsFallBackToTheComponentTreeIdentity(t *testing.T) {
	const tree = `{
      "branches": [{
        "category": "vendor", "name": "Example Corp",
        "branches": [{
          "category": "product_name", "name": "Widget Server",
          "branches": [{
            "category": "product_version", "name": "3.1.4",
            "product": {"product_id": "widget-3.1.4", "name": "Widget Server 3.1.4"}
          }]
        }]
      }],
      "relationships": [{
        "category": "installed_on",
        "full_product_name": {"product_id": "linux:widget-3.1.4", "name": "Widget Server 3.1.4 installed on Linux"},
        "product_reference": "widget-3.1.4",
        "relates_to_product_reference": "linux"
      }]
    }`
	p, ok := parseProductTree([]byte(tree))["linux:widget-3.1.4"]
	if !ok {
		t.Fatal("relationship not resolved")
	}
	if p.Product != "Widget Server 3.1.4" || p.Version != "3.1.4" || p.Vendor != "Example Corp" {
		t.Errorf("got product=%q version=%q vendor=%q, want the component leaf's identity", p.Product, p.Version, p.Vendor)
	}
}
