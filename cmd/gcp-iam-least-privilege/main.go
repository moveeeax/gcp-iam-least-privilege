// Command gcp-iam-least-privilege audits a GCP project's IAM policy for
// over-broad primitive roles (Owner/Editor) and suggests narrower predefined
// roles. It reads a live policy through gcloud-provided credentials or a local
// JSON file for offline use and CI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/moveeeax/gcp-iam-least-privilege/internal/analyzer"
	"github.com/moveeeax/gcp-iam-least-privilege/internal/gcp"
)

const usage = `gcp-iam-least-privilege — flag over-broad GCP IAM roles

Usage:
  gcp-iam-least-privilege --project PROJECT_ID [flags]
  gcp-iam-least-privilege --policy-file policy.json [flags]

Flags:
  --project string        GCP project id to audit (fetches the live policy)
  --policy-file string    read a getIamPolicy JSON document instead of calling the API
  --json                  emit JSON instead of text
  --service-accounts      only report service-account members
  --include-viewer        also flag roles/viewer (low severity)
  --fail-on-high          exit 2 if any HIGH-severity finding is present

Exit codes:
  0  no failing findings
  1  usage or runtime error
  2  HIGH-severity finding present and --fail-on-high set
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gcp-iam-least-privilege", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	var (
		project    = fs.String("project", "", "GCP project id to audit")
		policyFile = fs.String("policy-file", "", "read a getIamPolicy JSON document")
		asJSON     = fs.Bool("json", false, "emit JSON")
		saOnly     = fs.Bool("service-accounts", false, "only report service-account members")
		incViewer  = fs.Bool("include-viewer", false, "also flag roles/viewer")
		failOnHigh = fs.Bool("fail-on-high", false, "exit 2 on HIGH findings")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *project == "" && *policyFile == "" {
		fmt.Fprintln(stderr, "error: one of --project or --policy-file is required")
		fs.Usage()
		return 1
	}

	data, projectLabel, err := loadPolicy(*project, *policyFile)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	policy, err := analyzer.ParsePolicyBytes(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	report := analyzer.Analyze(projectLabel, policy, analyzer.Options{
		ServiceAccountsOnly: *saOnly,
		IncludeViewer:       *incViewer,
	})

	if *asJSON {
		err = report.RenderJSON(stdout)
	} else {
		err = report.RenderText(stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if *failOnHigh && report.HasHighSeverity() {
		return 2
	}
	return 0
}

// loadPolicy returns the raw policy bytes and a human label for the project.
func loadPolicy(project, policyFile string) ([]byte, string, error) {
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read policy file: %w", err)
		}
		label := project
		if label == "" {
			label = "(from " + policyFile + ")"
		}
		return data, label, nil
	}
	data, err := gcp.FetchPolicy(context.Background(), project)
	if err != nil {
		return nil, "", err
	}
	return data, project, nil
}
