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
