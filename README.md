# gcp-iam-least-privilege

[![CI](https://github.com/moveeeax/gcp-iam-least-privilege/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/gcp-iam-least-privilege/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/moveeeax/gcp-iam-least-privilege.svg)](https://pkg.go.dev/github.com/moveeeax/gcp-iam-least-privilege)
[![Go Report Card](https://goreportcard.com/badge/github.com/moveeeax/gcp-iam-least-privilege)](https://goreportcard.com/report/github.com/moveeeax/gcp-iam-least-privilege)
[![Go Version](https://img.shields.io/github/go-mod/go-version/moveeeax/gcp-iam-least-privilege)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit a GCP project's IAM policy for over-broad **primitive roles**
(`roles/owner`, `roles/editor`) and get concrete narrower-role suggestions —
especially for service accounts, which are long-lived, non-interactive, and
almost never reviewed.

Primitive roles are a standing audit finding: they grant coarse, project-wide
access, they pile up over time, and nobody trims them. This tool lists the
offenders and points you at the right family of predefined roles.

Two more checks catch the most common real-world GCP findings that a
primitive-only filter misses:

- any role granted to `allUsers` or `allAuthenticatedUsers` is reported as
  **CRITICAL** (tag `public`);
- the Compute Engine default service account
  (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) and the App Engine
  default service account (`PROJECT_ID@appspot.gserviceaccount.com`) holding
  `roles/owner` or `roles/editor` are reported as HIGH with tag `default-sa`
  and the fix "create a dedicated service account".

## Install

Requires Go 1.26 or newer (CI tests Go 1.26 and 1.27).

```sh
go install github.com/moveeeax/gcp-iam-least-privilege/cmd/gcp-iam-least-privilege@latest
```

Or clone and build:

```sh
git clone https://github.com/moveeeax/gcp-iam-least-privilege
cd gcp-iam-least-privilege
go build ./cmd/gcp-iam-least-privilege
```

## Usage

Audit a live project (uses your existing `gcloud` credentials to fetch the
policy via the Cloud Resource Manager API):

```sh
gcp-iam-least-privilege --project my-proj
```

Audit a saved policy document offline — useful in CI, or to inspect a policy
someone handed you:

```sh
gcloud projects get-iam-policy my-proj --format=json > policy.json
gcp-iam-least-privilege --policy-file policy.json
```

Example output:

```
Least-privilege findings for project "my-proj"
  CRITICAL: 1  HIGH: 4  LOW: 0

[CRITICAL] allUsers holds roles/storage.objectViewer [public]
        fix: remove the public binding and grant the role to specific principals

[HIGH] serviceAccount:123456789012-compute@developer.gserviceaccount.com holds roles/editor [service account, default-sa]
        fix: create a dedicated service account with only the roles the workload needs
        -> roles/viewer (if the principal only needs to read state)
        ...

[HIGH] serviceAccount:ci-deploy@my-proj.iam.gserviceaccount.com holds roles/owner [service account]
        -> roles/resourcemanager.projectIamAdmin (manage IAM without full ownership)
        -> roles/iam.serviceAccountAdmin (manage service accounts only)
        -> roles/editor (still broad, but drops IAM/billing control)
```

### Flags

| Flag | Description |
| --- | --- |
| `--project` | GCP project id to audit (fetches the live policy). |
| `--policy-file` | Read a `getIamPolicy` JSON document instead of calling the API. |
| `--json` | Emit machine-readable JSON. |
| `--service-accounts` | Only report service-account members (drops `allUsers`/`allAuthenticatedUsers` findings too). |
| `--include-viewer` | Also flag `roles/viewer` (low severity). Public viewer bindings are reported without it. |
| `--fail-on` | Exit `2` if any finding at this severity or above is present: `critical`, `high` or `low`. |
| `--fail-on-high` | Alias for `--fail-on high`. If both are given, the broader threshold wins. |

### CI gate

Use `--fail-on high` to fail a pipeline when a primitive role or a public
binding reappears (`--fail-on critical` to gate on public bindings only):

```yaml
- run: |
    gcloud projects get-iam-policy "$PROJECT" --format=json > policy.json
    gcp-iam-least-privilege --policy-file policy.json --fail-on high
```

Exit codes: `0` clean, `2` finding at or above the `--fail-on` severity
present, `1` usage/runtime error. Severities rank CRITICAL > HIGH > LOW, so
`--fail-on high` also fails on CRITICAL findings.

## How it works

The tool reads a project IAM policy, keeps only the primitive-role bindings
(`owner`/`editor`, plus `viewer` when asked) and every binding of any role to
`allUsers` or `allAuthenticatedUsers`, expands each into per-member findings,
and attaches an opinionated shortlist of predefined roles that commonly
replace the primitive one. Default service accounts and public principals also
get a `remediation` field in JSON output. Output is deterministic — findings
are sorted by severity (CRITICAL, HIGH, LOW), then by role, then by member —
so it diffs cleanly in CI.

Exact per-member grants require usage data; recommending those from
`recommender.googleapis.com` is on the roadmap. Today the tool gets you from
"who has Owner/Editor" to "here's the narrower role to start with" without any
extra API calls.

## License

MIT — see [LICENSE](LICENSE).
