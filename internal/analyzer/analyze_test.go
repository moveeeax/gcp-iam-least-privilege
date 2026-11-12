package analyzer

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) *Policy {
	t.Helper()
	data, err := os.ReadFile("../../testdata/policy.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := ParsePolicyBytes(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return p
}

// Acceptance criterion: a service account bound to roles/editor is reported as
// over-privileged with at least one suggested predefined alternative.
func TestServiceAccountEditorIsFlaggedWithSuggestion(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{})

	var found *Finding
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if f.Member == "serviceAccount:app-runtime@my-proj.iam.gserviceaccount.com" && f.Role == RoleEditor {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatalf("expected editor service-account finding, got %+v", rep.Findings)
	}
	if !found.IsServiceAccount {
		t.Errorf("expected finding to be marked as a service account")
	}
	if found.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", found.Severity)
	}
	if len(found.Suggestions) == 0 {
		t.Errorf("expected at least one narrower-role suggestion")
	}
}

func TestViewerHiddenByDefault(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{})
	for _, f := range rep.Findings {
		if f.Role == RoleViewer {
			t.Fatalf("roles/viewer should be excluded unless IncludeViewer is set")
		}
	}
}

func TestViewerShownWhenRequested(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{IncludeViewer: true})
	var seen bool
	for _, f := range rep.Findings {
		if f.Role == RoleViewer {
			seen = true
			if f.Severity != SeverityLow {
				t.Errorf("viewer should be LOW severity, got %s", f.Severity)
			}
		}
	}
	if !seen {
		t.Errorf("expected a roles/viewer finding with IncludeViewer")
	}
}

func TestServiceAccountsOnlyFilter(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{ServiceAccountsOnly: true})
	for _, f := range rep.Findings {
		if !f.IsServiceAccount {
			t.Errorf("ServiceAccountsOnly returned a non-SA member: %s", f.Member)
		}
	}
	// The human owner and the platform group must be filtered out.
	for _, f := range rep.Findings {
		if f.Member == "user:admin@example.com" || f.Member == "group:platform@example.com" {
			t.Errorf("expected %s to be filtered out", f.Member)
		}
	}
}

func TestNonPrimitiveRolesIgnored(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{IncludeViewer: true})
	for _, f := range rep.Findings {
		if f.Role == "roles/storage.objectViewer" {
			t.Errorf("predefined role should never be flagged")
		}
	}
}

func TestCountsAndHighSeverity(t *testing.T) {
	p := loadFixture(t)
	rep := Analyze("my-proj", p, Options{})
	// owner: 2 members, editor: 2 members => 4 HIGH findings, 0 LOW.
	if rep.Counts[SeverityHigh] != 4 {
		t.Errorf("expected 4 HIGH findings, got %d", rep.Counts[SeverityHigh])
	}
	if !rep.HasHighSeverity() {
		t.Errorf("expected HasHighSeverity to be true")
	}
}

func TestDeterministicOrdering(t *testing.T) {
	p := loadFixture(t)
	a := Analyze("my-proj", p, Options{IncludeViewer: true})
	b := Analyze("my-proj", p, Options{IncludeViewer: true})
	var bufA, bufB bytes.Buffer
	if err := a.RenderJSON(&bufA); err != nil {
		t.Fatal(err)
	}
	if err := b.RenderJSON(&bufB); err != nil {
		t.Fatal(err)
	}
	if bufA.String() != bufB.String() {
		t.Errorf("analysis output is not deterministic")
	}
	// HIGH findings must precede LOW ones.
	out := bufA.String()
	hi := strings.Index(out, `"HIGH"`)
	lo := strings.Index(out, `"LOW"`)
	if hi == -1 || lo == -1 || hi > lo {
		t.Errorf("expected HIGH findings before LOW; hi=%d lo=%d", hi, lo)
	}
}

func TestRenderTextEmpty(t *testing.T) {
	empty := &Policy{Bindings: []Binding{{Role: "roles/storage.admin", Members: []string{"user:x@example.com"}}}}
	rep := Analyze("clean-proj", empty, Options{})
	var buf bytes.Buffer
	if err := rep.RenderText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No over-broad") {
		t.Errorf("expected clean message, got %q", buf.String())
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := ParsePolicyBytes([]byte(`{"bindings":[]}`)); err == nil {
		t.Errorf("expected error on empty bindings")
	}
	if _, err := ParsePolicyBytes([]byte(`not json`)); err == nil {
		t.Errorf("expected error on invalid JSON")
	}
}

func TestParseToleratesExtraFields(t *testing.T) {
	// The live API includes fields (condition, auditConfigs) we do not model.
	doc := `{
      "version": 3,
      "bindings": [
        {"role": "roles/owner", "members": ["user:a@example.com"],
         "condition": {"title": "t", "expression": "true"}}
      ],
      "auditConfigs": [{"service": "allServices"}]
    }`
	p, err := ParsePolicyBytes([]byte(doc))
	if err != nil {
		t.Fatalf("expected lenient parse, got %v", err)
	}
	if len(p.Bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(p.Bindings))
	}
}

func loadPublicFixture(t *testing.T) *Policy {
	t.Helper()
	data, err := os.ReadFile("../../testdata/policy-public.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := ParsePolicyBytes(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return p
}

func findingFor(rep *Report, member, role string) *Finding {
	for i := range rep.Findings {
		if rep.Findings[i].Member == member && rep.Findings[i].Role == role {
			return &rep.Findings[i]
		}
	}
	return nil
}

// Any role bound to a public principal is CRITICAL, including predefined
// roles and roles/viewer without IncludeViewer.
func TestPublicPrincipalsAreCritical(t *testing.T) {
	rep := Analyze("my-proj", loadPublicFixture(t), Options{})
	for _, tc := range []struct{ member, role string }{
		{"allUsers", "roles/storage.objectViewer"},
		{"allAuthenticatedUsers", RoleViewer},
	} {
		f := findingFor(rep, tc.member, tc.role)
		if f == nil {
			t.Fatalf("expected finding for %s on %s, got %+v", tc.member, tc.role, rep.Findings)
		}
		if f.Severity != SeverityCritical {
			t.Errorf("%s: expected CRITICAL, got %s", tc.member, f.Severity)
		}
		if f.MemberKind != tc.member {
			t.Errorf("%s: expected memberKind %q, got %q", tc.member, tc.member, f.MemberKind)
		}
		if len(f.Tags) != 1 || f.Tags[0] != TagPublic {
			t.Errorf("%s: expected tags [%s], got %v", tc.member, TagPublic, f.Tags)
		}
		if f.Remediation == "" {
			t.Errorf("%s: expected a remediation", tc.member)
		}
	}
	if rep.Counts[SeverityCritical] != 2 {
		t.Errorf("expected 2 CRITICAL findings, got %d", rep.Counts[SeverityCritical])
	}
	if rep.Findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL findings first, got %s", rep.Findings[0].Severity)
	}
	// The non-public member of the predefined-role binding is not a finding.
	if f := findingFor(rep, "serviceAccount:app-runtime@my-proj.iam.gserviceaccount.com", "roles/storage.objectViewer"); f != nil {
		t.Errorf("predefined role on a private member should not be flagged")
	}
}

func TestDefaultServiceAccountsTagged(t *testing.T) {
	rep := Analyze("my-proj", loadPublicFixture(t), Options{IncludeViewer: true})
	for _, m := range []string{
		"serviceAccount:123456789012-compute@developer.gserviceaccount.com",
		"serviceAccount:my-proj@appspot.gserviceaccount.com",
	} {
		f := findingFor(rep, m, RoleEditor)
		if f == nil {
			t.Fatalf("expected editor finding for %s", m)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("%s: expected HIGH, got %s", m, f.Severity)
		}
		if len(f.Tags) != 1 || f.Tags[0] != TagDefaultSA {
			t.Errorf("%s: expected tags [%s], got %v", m, TagDefaultSA, f.Tags)
		}
		if !strings.Contains(f.Remediation, "dedicated service account") {
			t.Errorf("%s: unexpected remediation %q", m, f.Remediation)
		}
	}
	// A user-managed SA with editor is HIGH but not default-sa.
	if f := findingFor(rep, "serviceAccount:app-runtime@my-proj.iam.gserviceaccount.com", RoleEditor); f == nil || len(f.Tags) != 0 {
		t.Errorf("expected untagged editor finding for user-managed SA, got %+v", f)
	}
	// The default-sa tag applies to owner/editor only, not viewer.
	if f := findingFor(rep, "serviceAccount:123456789012-compute@developer.gserviceaccount.com", RoleViewer); f == nil || f.Severity != SeverityLow || len(f.Tags) != 0 {
		t.Errorf("expected untagged LOW viewer finding for default SA, got %+v", f)
	}
}

func TestServiceAccountsOnlyDropsPublic(t *testing.T) {
	rep := Analyze("my-proj", loadPublicFixture(t), Options{ServiceAccountsOnly: true})
	if rep.Counts[SeverityCritical] != 0 {
		t.Errorf("expected public principals filtered by ServiceAccountsOnly, got %d CRITICAL", rep.Counts[SeverityCritical])
	}
}

func TestIsDefaultServiceAccount(t *testing.T) {
	for member, want := range map[string]bool{
		"serviceAccount:123-compute@developer.gserviceaccount.com":          true,
		"serviceAccount:my-proj@appspot.gserviceaccount.com":                true,
		"serviceAccount:x@my-proj.iam.gserviceaccount.com":                  false,
		"user:123-compute@developer.gserviceaccount.com":                    false,
		"serviceAccount:service-123@compute-system.iam.gserviceaccount.com": false,
	} {
		if got := isDefaultServiceAccount(member); got != want {
			t.Errorf("isDefaultServiceAccount(%q) = %v, want %v", member, got, want)
		}
	}
}

func TestHasSeverityAtLeast(t *testing.T) {
	rep := &Report{Counts: map[Severity]int{SeverityHigh: 1}}
	if !rep.HasSeverityAtLeast(SeverityLow) || !rep.HasSeverityAtLeast(SeverityHigh) {
		t.Errorf("HIGH finding should satisfy low and high thresholds")
	}
	if rep.HasSeverityAtLeast(SeverityCritical) {
		t.Errorf("HIGH finding should not satisfy the critical threshold")
	}
	crit := &Report{Counts: map[Severity]int{SeverityCritical: 1}}
	if !crit.HasHighSeverity() {
		t.Errorf("CRITICAL finding should count for HasHighSeverity")
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"critical": SeverityCritical, "HIGH": SeverityHigh, " Low ": SeverityLow} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("medium"); err == nil {
		t.Errorf("expected error for unknown severity")
	}
}

func TestRenderTextShowsTagsAndRemediation(t *testing.T) {
	rep := Analyze("my-proj", loadPublicFixture(t), Options{})
	var buf bytes.Buffer
	if err := rep.RenderText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"CRITICAL: 2  HIGH: 3  LOW: 0",
		"[CRITICAL] allUsers holds roles/storage.objectViewer [public]",
		"[service account, default-sa]",
		"fix: create a dedicated service account",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}
