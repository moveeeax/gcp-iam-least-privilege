package analyzer

import (
	"sort"
)

// Finding describes one over-privileged member/role pairing.
type Finding struct {
	Member           string   `json:"member"`
	MemberKind       string   `json:"memberKind"`
	Role             string   `json:"role"`
	Severity         Severity `json:"severity"`
	IsServiceAccount bool     `json:"isServiceAccount"`
	// Tags carry extra classification: TagPublic, TagDefaultSA.
	Tags []string `json:"tags,omitempty"`
	// Remediation is the primary fix when it is more specific than swapping
	// in a narrower role (public bindings, default service accounts).
	Remediation string       `json:"remediation,omitempty"`
	Suggestions []Suggestion `json:"suggestions"`
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
// matches the options, plus every binding of any role to allUsers or
// allAuthenticatedUsers (CRITICAL). Output is deterministic: findings are
// sorted by severity (most severe first), then role, then member.
func Analyze(project string, p *Policy, opts Options) *Report {
	rep := &Report{
		Project: project,
		Counts:  map[Severity]int{},
	}
	for _, b := range p.Bindings {
		primSev, isPrimitive := primitiveRoles[b.Role]
		// Viewer is opt-in, but a public viewer binding is still reported.
		reportPrimitive := isPrimitive && (b.Role != RoleViewer || opts.IncludeViewer)
		sugg := toSuggestions(suggestionsFor(b.Role))
		for _, m := range sortedMembers(b.Members) {
			sa := isServiceAccount(m)
			if opts.ServiceAccountsOnly && !sa {
				continue
			}
			f := Finding{
				Member:           m,
				MemberKind:       memberKind(m),
				Role:             b.Role,
				IsServiceAccount: sa,
				Suggestions:      sugg,
			}
			switch {
			case isPublic(m):
				f.Severity = SeverityCritical
				f.Tags = []string{TagPublic}
				f.Remediation = remediationPublic
			case !reportPrimitive:
				continue
			case b.Role != RoleViewer && isDefaultServiceAccount(m):
				f.Severity = primSev
				f.Tags = []string{TagDefaultSA}
				f.Remediation = remediationDefaultSA
			default:
				f.Severity = primSev
			}
			rep.Findings = append(rep.Findings, f)
			rep.Counts[f.Severity]++
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			// Most severe first.
			return severityRank[a.Severity] > severityRank[b.Severity]
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

// HasSeverityAtLeast reports whether the report contains any finding at min
// severity or above, which callers use to drive a non-zero exit code in CI
// gates.
func (r *Report) HasSeverityAtLeast(min Severity) bool {
	for sev, n := range r.Counts {
		if n > 0 && sev.AtLeast(min) {
			return true
		}
	}
	return false
}

// HasHighSeverity reports whether the report contains any HIGH or CRITICAL
// finding.
func (r *Report) HasHighSeverity() bool {
	return r.HasSeverityAtLeast(SeverityHigh)
}
