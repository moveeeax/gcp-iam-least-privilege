package main

import (
	"io"
	"testing"

	"github.com/moveeeax/gcp-iam-least-privilege/internal/analyzer"
)

// TestFailOnHighExitCode exercises the CI-gate path end to end against the
// bundled fixture: HIGH findings present + --fail-on-high must exit 2.
func TestFailOnHighExitCode(t *testing.T) {
	code := run([]string{"--policy-file", "../../testdata/policy.json", "--fail-on-high", "--json"}, io.Discard, io.Discard)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestMissingArgsExit1(t *testing.T) {
	code := run(nil, io.Discard, io.Discard)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestServiceAccountsOnlyRuns(t *testing.T) {
	code := run([]string{"--policy-file", "../../testdata/policy.json", "--service-accounts"}, io.Discard, io.Discard)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestFailOnThresholds(t *testing.T) {
	const public = "../../testdata/policy-public.json"
	const primitiveOnly = "../../testdata/policy.json"
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"critical fails on public", []string{"--policy-file", public, "--fail-on", "critical"}, 2},
		{"critical passes without public", []string{"--policy-file", primitiveOnly, "--fail-on", "critical"}, 0},
		{"high fails on HIGH", []string{"--policy-file", primitiveOnly, "--fail-on", "high"}, 2},
		{"low fails on HIGH", []string{"--policy-file", primitiveOnly, "--fail-on", "LOW"}, 2},
		{"fail-on-high also fails on CRITICAL", []string{"--policy-file", public, "--fail-on-high"}, 2},
		{"no threshold exits 0", []string{"--policy-file", public}, 0},
		{"invalid value", []string{"--policy-file", public, "--fail-on", "medium"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := run(tc.args, io.Discard, io.Discard); code != tc.want {
				t.Fatalf("expected exit code %d, got %d", tc.want, code)
			}
		})
	}
}

func TestFailThresholdAlias(t *testing.T) {
	for _, tc := range []struct {
		failOn     string
		failOnHigh bool
		want       analyzer.Severity
	}{
		{"", false, ""},
		{"", true, analyzer.SeverityHigh},
		{"critical", true, analyzer.SeverityHigh},
		{"low", true, analyzer.SeverityLow},
		{"critical", false, analyzer.SeverityCritical},
	} {
		got, err := failThreshold(tc.failOn, tc.failOnHigh)
		if err != nil || got != tc.want {
			t.Errorf("failThreshold(%q, %v) = %q, %v; want %q", tc.failOn, tc.failOnHigh, got, err, tc.want)
		}
	}
}
