package main

import (
	"io"
	"testing"
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
