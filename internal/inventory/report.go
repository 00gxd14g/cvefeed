package inventory

// Skip records one inventory entry the reader could not use.
//
// A component that never reaches the scanner is a component that is never
// reported on, and the operator cannot tell the difference between "this is
// clean" and "this was never looked at". Counting the skips and saying what
// they were is the difference between an incomplete answer and a dishonest one.
type Skip struct {
	// Line is the 1-based line number for line-oriented inputs, or 0 when the
	// entry has no line — an SBOM component, a package-manager row.
	Line   int    `json:"line,omitempty"`
	Text   string `json:"text,omitempty"`
	Reason string `json:"reason"`
}

// Report is what an inventory reader could not use.
type Report struct {
	Skipped []Skip `json:"skipped,omitempty"`
}

func (r *Report) add(line int, text, reason string) {
	r.Skipped = append(r.Skipped, Skip{Line: line, Text: text, Reason: reason})
}
