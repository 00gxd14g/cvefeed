package parse

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestNVDANDApplicabilityIsNotFlattenedIntoAConfirmedFinding(t *testing.T) {
	configs := []cpeConfiguration{{
		Operator: "OR",
		Nodes: []cpeNode{{
			Operator: "AND",
			CPEMatch: []cpeMatch{
				{
					Vulnerable:          true,
					Criteria:            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
					VersionEndExcluding: "2.0",
				},
				{
					Vulnerable: false,
					Criteria:   "cpe:2.3:o:example:example_os:12:*:*:*:*:*:*:*",
				},
			},
		}},
	}}

	got := cpeAffected(configs, "nvd")
	if len(got) != 1 {
		t.Fatalf("cpeAffected() returned %d rows, want 1: %#v", len(got), got)
	}
	if got[0].Status != model.StatusConditional {
		t.Fatalf("AND-only row status = %q, want %q", got[0].Status, model.StatusConditional)
	}
	if len(got[0].Ranges) != 1 || got[0].Ranges[0].Fixed != "2.0" {
		t.Fatalf("version evidence was lost while preserving the condition: %#v", got[0].Ranges)
	}
}

func TestIndependentORApplicabilityDoesNotUpgradeAConditionalRange(t *testing.T) {
	criterion := "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
	configs := []cpeConfiguration{
		{
			Nodes: []cpeNode{{
				Operator: "AND",
				CPEMatch: []cpeMatch{
					{Vulnerable: true, Criteria: criterion, VersionEndExcluding: "2.0"},
					{Vulnerable: false, Criteria: "cpe:2.3:o:example:example_os:12:*:*:*:*:*:*:*"},
				},
			}},
		},
		{
			Nodes: []cpeNode{{
				Operator: "OR",
				CPEMatch: []cpeMatch{{
					Vulnerable: true, Criteria: criterion,
					VersionStartIncluding: "3.0", VersionEndExcluding: "4.0",
				}},
			}},
		},
	}

	got := cpeAffected(configs, "nvd")
	if len(got) != 2 {
		t.Fatalf("cpeAffected() returned %d rows, want ordinary + conditional: %#v", len(got), got)
	}
	if got[0].Status != "" || len(got[0].Ranges) != 1 ||
		got[0].Ranges[0].Introduced != "3.0" || got[0].Ranges[0].Fixed != "4.0" {
		t.Fatalf("ordinary row = %#v, want independent [3.0,4.0) evidence", got[0])
	}
	if got[1].Status != model.StatusConditional || len(got[1].Ranges) != 1 ||
		got[1].Ranges[0].Fixed != "2.0" {
		t.Fatalf("conditional row = %#v, want conditional <2.0 evidence", got[1])
	}
}

func TestConfigurationLevelANDAcrossNodesIsConditional(t *testing.T) {
	configs := []cpeConfiguration{{
		Operator: "AND",
		Nodes: []cpeNode{
			{CPEMatch: []cpeMatch{{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}}},
			{CPEMatch: []cpeMatch{{Vulnerable: false, Criteria: "cpe:2.3:o:example:example_os:12:*:*:*:*:*:*:*"}}},
		},
	}}

	got := cpeAffected(configs, "nvd")
	if len(got) != 1 || got[0].Status != model.StatusConditional {
		t.Fatalf("configuration-level AND = %#v, want one conditional row", got)
	}
}
