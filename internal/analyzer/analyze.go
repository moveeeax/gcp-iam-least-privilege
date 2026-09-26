package analyzer

import (
	"sort"
)

// Finding describes one over-privileged member/role pairing.
type Finding struct {
	Member           string       `json:"member"`
	MemberKind       string       `json:"memberKind"`
	Role             string       `json:"role"`
	Severity         Severity     `json:"severity"`
	IsServiceAccount bool         `json:"isServiceAccount"`
	Suggestions      []Suggestion `json:"suggestions"`
}

// Suggestion is the exported form of an internal suggestion.
type Suggestion struct {
	Role   string `json:"role"`
	Reason string `json:"reason"`
}

// Report aggregates the findings for a project.
type Report struct {
	Project  string    `json:"project"`
	Findings []Finding `json:"findings"`
	// Counts summarizes findings by severity for quick scanning / exit codes.
	Counts map[Severity]int `json:"counts"`
}

// Options tune the analysis.
type Options struct {
	// ServiceAccountsOnly restricts findings to service-account members,
	// which are the highest-value target: long-lived, non-interactive, and
	// rarely reviewed.
	ServiceAccountsOnly bool
	// IncludeViewer flags roles/viewer bindings as low-severity findings.
	IncludeViewer bool
}

// Analyze walks the policy and reports every primitive-role binding that
// matches the options. Output is deterministic: findings are sorted by
// severity (high first), then role, then member.
func Analyze(project string, p *Policy, opts Options) *Report {
	rep := &Report{
		Project: project,
		Counts:  map[Severity]int{},
	}
	for _, b := range p.Bindings {
		sev, isPrimitive := primitiveRoles[b.Role]
		if !isPrimitive {
			continue
		}
		if b.Role == RoleViewer && !opts.IncludeViewer {
			continue
		}
		sugg := toSuggestions(suggestionsFor(b.Role))
		for _, m := range sortedMembers(b.Members) {
			sa := isServiceAccount(m)
			if opts.ServiceAccountsOnly && !sa {
				continue
			}
			rep.Findings = append(rep.Findings, Finding{
				Member:           m,
				MemberKind:       memberKind(m),
				Role:             b.Role,
				Severity:         sev,
				IsServiceAccount: sa,
				Suggestions:      sugg,
			})
			rep.Counts[sev]++
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			// HIGH before LOW.
			return a.Severity == SeverityHigh
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Member < b.Member
	})
	return rep
}

func toSuggestions(in []suggestion) []Suggestion {
	if len(in) == 0 {
		return nil
	}
	out := make([]Suggestion, len(in))
	for i, s := range in {
		out[i] = Suggestion{Role: s.Role, Reason: s.Reason}
	}
	return out
}

// HasHighSeverity reports whether the report contains any HIGH finding, which
// callers use to drive a non-zero exit code in CI gates.
func (r *Report) HasHighSeverity() bool {
	return r.Counts[SeverityHigh] > 0
}
