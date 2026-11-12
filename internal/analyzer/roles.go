package analyzer

import (
	"fmt"
	"strings"
)

// Primitive (basic) roles grant coarse, project-wide access and are the
// standing audit finding this tool exists to catch.
const (
	RoleOwner  = "roles/owner"
	RoleEditor = "roles/editor"
	RoleViewer = "roles/viewer"
)

// primitiveRoles is the set of basic roles we flag. Viewer is included as a
// low-severity finding: it is read-only but still project-wide.
var primitiveRoles = map[string]Severity{
	RoleOwner:  SeverityHigh,
	RoleEditor: SeverityHigh,
	RoleViewer: SeverityLow,
}

// Severity ranks a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityLow      Severity = "LOW"
)

// severityRank orders severities for sorting and threshold checks; a higher
// rank is more severe. Unknown values rank 0.
var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// ParseSeverity maps a case-insensitive name (critical, high, low) to a
// Severity.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToUpper(strings.TrimSpace(s)))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("unknown severity %q (want critical, high or low)", s)
	}
	return sev, nil
}

// AtLeast reports whether s is as severe as min or more.
func (s Severity) AtLeast(min Severity) bool {
	return severityRank[s] >= severityRank[min]
}

// Finding tags mark findings that a primitive-role filter alone would not
// explain.
const (
	// TagPublic marks a binding to allUsers or allAuthenticatedUsers.
	TagPublic = "public"
	// TagDefaultSA marks a Compute Engine or App Engine default service
	// account holding a primitive role.
	TagDefaultSA = "default-sa"
)

// Public principals. allUsers is anyone on the internet; allAuthenticatedUsers
// is anyone signed in to any Google account, not just your organization.
const (
	MemberAllUsers              = "allUsers"
	MemberAllAuthenticatedUsers = "allAuthenticatedUsers"
)

const (
	remediationPublic    = "remove the public binding and grant the role to specific principals"
	remediationDefaultSA = "create a dedicated service account with only the roles the workload needs"
)

// isPublic reports whether the member is allUsers or allAuthenticatedUsers.
func isPublic(member string) bool {
	return member == MemberAllUsers || member == MemberAllAuthenticatedUsers
}

// isDefaultServiceAccount reports whether the member is the Compute Engine
// default service account (PROJECT_NUMBER-compute@developer.gserviceaccount.com)
// or the App Engine default service account (PROJECT_ID@appspot.gserviceaccount.com).
// Both get roles/editor automatically on projects created without the
// iam.automaticIamGrantsForDefaultServiceAccounts constraint.
func isDefaultServiceAccount(member string) bool {
	email, ok := strings.CutPrefix(member, "serviceAccount:")
	if !ok {
		return false
	}
	email = strings.ToLower(email)
	return strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") ||
		strings.HasSuffix(email, "@appspot.gserviceaccount.com")
}

// suggestion pairs a narrower predefined role with a short rationale.
type suggestion struct {
	Role   string
	Reason string
}

// suggestionsFor returns narrower predefined roles that commonly replace a
// primitive role. The list is intentionally opinionated and small: it points
// an operator at the right family of roles rather than guessing exact grants,
// which require usage data (see the recommender stretch goal).
func suggestionsFor(primitive string) []suggestion {
	switch primitive {
	case RoleOwner:
		return []suggestion{
			{"roles/resourcemanager.projectIamAdmin", "manage IAM without full ownership"},
			{"roles/iam.serviceAccountAdmin", "manage service accounts only"},
			{"roles/editor", "still broad, but drops IAM/billing control"},
		}
	case RoleEditor:
		return []suggestion{
			{"roles/viewer", "if the principal only needs to read state"},
			{"roles/compute.instanceAdmin.v1", "scope to Compute if that is the real workload"},
			{"roles/storage.objectAdmin", "scope to GCS objects if that is the real workload"},
			{"roles/run.developer", "scope to Cloud Run deploys if that is the real workload"},
		}
	case RoleViewer:
		return []suggestion{
			{"roles/monitoring.viewer", "scope read access to the service actually observed"},
			{"roles/logging.viewer", "scope read access to logs only"},
		}
	default:
		return nil
	}
}
