package analyzer

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
	SeverityHigh Severity = "HIGH"
	SeverityLow  Severity = "LOW"
)

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
