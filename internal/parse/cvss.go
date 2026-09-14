package parse

import (
	"math"
	"strings"
)

// CVSSBaseScore derives the base score from a vector string.
//
// This exists because the OSV schema carries the vector but not the number,
// while CVE 5.x and NVD carry both. Rather than storing a hole for OSV-sourced
// records we recompute from the specification.
//
// CVSS v2 and v3.0/v3.1 are computed exactly per their published formulas.
// CVSS v4.0 is deliberately NOT recomputed: its scoring depends on the official
// 270-entry MacroVector lookup table, and an approximation there would be worse
// than no number at all. For v4.0 vectors the score is taken from whichever
// upstream supplied it numerically (CVE 5.x, NVD, EUVD all do); this function
// returns 0 and callers treat 0 as "no numeric score from this statement".
func CVSSBaseScore(vector string) float64 {
	score, _ := cvssBaseScore(vector)
	return score
}

// cvssBaseScore is CVSSBaseScore with the answer to "was this computed at
// all". A vector whose impact metrics are all N scores 0.0 by the formula —
// CVSS:3.1/.../C:N/I:N/A:N, which GHSA publishes for informational advisories
// — and that is a real score with the band NONE, not a missing one. The bare
// float cannot tell the two apart, so a caller that wants to rate the
// statement reads ok: true means every required metric parsed and the number
// is the specification's answer, false means the vector is a version this
// code does not compute (v4.0) or is malformed.
func cvssBaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return 0, false
	}
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return cvss3Base(parseVector(vector), true)
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return cvss3Base(parseVector(vector), false)
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return 0, false
	case strings.HasPrefix(vector, "AV:"):
		return cvss2Base(parseVector(vector))
	}
	return 0, false
}

func parseVector(vector string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.ToUpper(strings.TrimSpace(kv[0]))] = strings.ToUpper(strings.TrimSpace(kv[1]))
	}
	return out
}

func cvss3Base(m map[string]string, v31 bool) (float64, bool) {
	scopeChanged := m["S"] == "C"

	av, ok := lookup(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}, m["AV"])
	if !ok {
		return 0, false
	}
	ac, ok := lookup(map[string]float64{"L": 0.77, "H": 0.44}, m["AC"])
	if !ok {
		return 0, false
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr, ok := lookup(prTable, m["PR"])
	if !ok {
		return 0, false
	}
	ui, ok := lookup(map[string]float64{"N": 0.85, "R": 0.62}, m["UI"])
	if !ok {
		return 0, false
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
	c, okC := lookup(cia, m["C"])
	i, okI := lookup(cia, m["I"])
	a, okA := lookup(cia, m["A"])
	if !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui

	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	score = math.Min(score, 10)

	if v31 {
		return roundUp31(score), true
	}
	return math.Ceil(score*10) / 10, true
}

// roundUp31 implements the CVSS v3.1 Appendix A integer round-up, which differs
// from a plain ceiling and produces different scores in edge cases.
func roundUp31(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000.0) + 1) / 10.0
}

func cvss2Base(m map[string]string) (float64, bool) {
	av, ok := lookup(map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}, m["AV"])
	if !ok {
		return 0, false
	}
	ac, ok := lookup(map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}, m["AC"])
	if !ok {
		return 0, false
	}
	au, ok := lookup(map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}, m["AU"])
	if !ok {
		return 0, false
	}
	cia := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.660}
	c, okC := lookup(cia, m["C"])
	i, okI := lookup(cia, m["I"])
	a, okA := lookup(cia, m["A"])
	if !okC || !okI || !okA {
		return 0, false
	}

	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	exploitability := 20 * av * ac * au
	fImpact := 1.176
	if impact == 0 {
		fImpact = 0
	}
	score := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact
	if score < 0 {
		score = 0
	}
	return math.Round(score*10) / 10, true
}

func lookup(table map[string]float64, key string) (float64, bool) {
	v, ok := table[key]
	return v, ok
}
