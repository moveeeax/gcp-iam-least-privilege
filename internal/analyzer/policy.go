// Package analyzer inspects a GCP IAM policy for over-broad primitive-role
// bindings and produces least-privilege recommendations.
package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Policy mirrors the shape returned by
// cloudresourcemanager.projects.getIamPolicy — only the fields we need.
type Policy struct {
	Version  int       `json:"version"`
	Bindings []Binding `json:"bindings"`
	Etag     string    `json:"etag"`
}

// Binding ties a single role to the set of members that hold it.
type Binding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// ParsePolicy decodes a getIamPolicy JSON document from a reader. It tolerates
// extra fields (conditions, auditConfigs) that the live API includes but we do
// not model.
func ParsePolicy(r io.Reader) (*Policy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return ParsePolicyBytes(data)
}

// ParsePolicyBytes decodes a policy document from a byte slice, tolerating
// extra fields that the live API includes but we do not model.
func ParsePolicyBytes(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if len(p.Bindings) == 0 {
		return nil, fmt.Errorf("policy has no bindings")
	}
	return &p, nil
}

// memberKind classifies an IAM member string by its prefix.
func memberKind(member string) string {
	if i := strings.IndexByte(member, ':'); i >= 0 {
		return member[:i]
	}
	return "unknown"
}

// isServiceAccount reports whether the member is a service account.
func isServiceAccount(member string) bool {
	return memberKind(member) == "serviceAccount"
}

// sortedMembers returns a stable, deduplicated copy for deterministic output.
func sortedMembers(members []string) []string {
	seen := make(map[string]struct{}, len(members))
	out := make([]string, 0, len(members))
	for _, m := range members {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
