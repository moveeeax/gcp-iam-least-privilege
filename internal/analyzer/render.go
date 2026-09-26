package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
)

// RenderJSON writes the report as indented JSON.
func (r *Report) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// RenderText writes a human-readable report suitable for a terminal or CI log.
func (r *Report) RenderText(w io.Writer) error {
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintf(w, "No over-broad primitive-role bindings found in project %q.\n", r.Project)
		return err
	}
	if _, err := fmt.Fprintf(w, "Least-privilege findings for project %q\n", r.Project); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  HIGH: %d  LOW: %d\n\n", r.Counts[SeverityHigh], r.Counts[SeverityLow]); err != nil {
		return err
	}
	for _, f := range r.Findings {
		tag := ""
		if f.IsServiceAccount {
			tag = " [service account]"
		}
		if _, err := fmt.Fprintf(w, "[%s] %s holds %s%s\n", f.Severity, f.Member, f.Role, tag); err != nil {
			return err
		}
		for _, s := range f.Suggestions {
			if _, err := fmt.Fprintf(w, "        -> %s (%s)\n", s.Role, s.Reason); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	return nil
}
