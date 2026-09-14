package match

import (
	"strings"
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

// An NVD "application AND platform" configuration reaches the matcher as a
// conditional row. It must stay undecidable — flattening it is the false
// positive the parser split the row to avoid — and the explanation must not
// claim the upstream said it was still investigating, because it did not.
func TestConditionalApplicabilityIsUndecidableAndSaysWhy(t *testing.T) {
	a := Affected{
		Vendor: "acme", Product: "widget", Source: "nvd",
		CPEs:   []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
		Status: model.StatusConditional,
		Ranges: []model.VersionRange{{Type: "CPE", Fixed: "2.0", CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}},
	}
	c := Component{Name: "widget", Vendor: "acme", Version: "1.5", CPE: "cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*"}

	got, ev := Evaluate(c, a)
	if got != Undecidable {
		t.Fatalf("Evaluate() = %v, want Undecidable: %s", got, ev.Reason)
	}
	if !strings.Contains(ev.Reason, "conditional_applicability") {
		t.Errorf("reason does not name the conditional applicability: %s", ev.Reason)
	}
	if strings.Contains(ev.Reason, "under_investigation") {
		t.Errorf("reason attributes an investigation status the upstream never reported: %s", ev.Reason)
	}
}

// The condition is unprovable; the version bound is not. A build outside the
// stated window is not affected whatever the condition says, and reporting it
// as undecidable buries the real findings under noise.
func TestConditionalApplicabilityStillRespectsItsVersionScope(t *testing.T) {
	a := Affected{
		Vendor: "acme", Product: "widget", Source: "nvd",
		CPEs:   []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
		Status: model.StatusConditional,
		Ranges: []model.VersionRange{{Type: "CPE", Fixed: "2.0", CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}},
	}
	c := Component{Name: "widget", Vendor: "acme", Version: "2.5", CPE: "cpe:2.3:a:acme:widget:2.5:*:*:*:*:*:*:*"}

	if got, ev := Evaluate(c, a); got != NoMatch {
		t.Fatalf("Evaluate() on a build past the fix = %v, want NoMatch: %s", got, ev.Reason)
	}
}

// "conditional" is cvefeed's own vocabulary and never reaches the matcher by
// accident: an unrecognised status must still fold onto under_investigation
// rather than onto affected.
func TestConditionalStatusRoundTripsThroughNormalisation(t *testing.T) {
	if got := model.NormalizeStatus("Conditional"); got != model.StatusConditional {
		t.Errorf("NormalizeStatus(%q) = %q, want %q", "Conditional", got, model.StatusConditional)
	}
	if got := normalizeStatus("something nobody defined"); got != model.StatusUnderInvestigation {
		t.Errorf("normalizeStatus(unknown) = %q, want %q", got, model.StatusUnderInvestigation)
	}
}
