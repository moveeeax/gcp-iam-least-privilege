package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
		_, err := fmt.Fprintf(w, "No over-broad primitive-role or public bindings found in project %q.\n", r.Project)
		return err
	}
	if _, err := fmt.Fprintf(w, "Least-privilege findings for project %q\n", r.Project); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  CRITICAL: %d  HIGH: %d  LOW: %d\n\n",
		r.Counts[SeverityCritical], r.Counts[SeverityHigh], r.Counts[SeverityLow]); err != nil {
		return err
	}
	for _, f := range r.Findings {
		var labels []string
		if f.IsServiceAccount {
			labels = append(labels, "service account")
		}
		labels = append(labels, f.Tags...)
		tag := ""
		if len(labels) > 0 {
			tag = " [" + strings.Join(labels, ", ") + "]"
		}
		if _, err := fmt.Fprintf(w, "[%s] %s holds %s%s\n", f.Severity, f.Member, f.Role, tag); err != nil {
			return err
		}
		if f.Remediation != "" {
			if _, err := fmt.Fprintf(w, "        fix: %s\n", f.Remediation); err != nil {
				return err
			}
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
