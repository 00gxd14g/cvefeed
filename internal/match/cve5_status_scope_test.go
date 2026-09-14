package match

import (
	"testing"

	"github.com/00gxd14g/cvefeed/internal/model"
)

func TestCVE5UnknownDefaultDoesNotProveUnaffected(t *testing.T) {
	for _, defaultState := range []string{"unknown", "", "unrecognized"} {
		for _, bounded := range []bool{false, true} {
			a := Affected{
				Product: "widget", PURL: "pkg:npm/widget", Source: "cvelist",
				Status: model.StatusAffected, DefaultState: defaultState,
				Versions: []string{"1.0.0"},
			}
			if bounded {
				a.Versions = nil
				a.Ranges = []model.VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0", Type: "SEMVER"}}
			}
			for _, installed := range []string{"0.5.0", "2.0.0", "3.0.0"} {
				c := Component{Name: "widget", PURL: "pkg:npm/widget", Version: installed}
				got, ev := Evaluate(c, a)
				if got != Undecidable {
					t.Errorf("default=%q bounded=%v installed=%s: got %v, want Undecidable: %s", defaultState, bounded, installed, got, ev.Reason)
				}
			}
			c := Component{Name: "widget", PURL: "pkg:npm/widget", Version: "1.0.0"}
			if got, ev := Evaluate(c, a); got != Match {
				t.Errorf("explicit affected version under default %q: got %v: %s", defaultState, got, ev.Reason)
			}
		}
	}
}

func TestUnknownStatusOnlyAppliesInsideItsVersionScope(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		a := Affected{
			Product: "widget", PURL: "pkg:npm/widget", Source: "cvelist",
			Status: model.StatusUnderInvestigation, Versions: []string{"1.0.0"},
		}
		if bounded {
			a.Versions = nil
			a.Ranges = []model.VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0", Type: "SEMVER"}}
		}
		for _, tt := range []struct {
			installed string
			want      Result
		}{{"0.5.0", NoMatch}, {"1.0.0", Undecidable}, {"2.0.0", NoMatch}} {
			got, ev := Evaluate(Component{Name: "widget", PURL: "pkg:npm/widget", Version: tt.installed}, a)
			if got != tt.want {
				t.Errorf("bounded=%v installed=%s: got %v, want %v: %s", bounded, tt.installed, got, tt.want, ev.Reason)
			}
		}
	}
}
