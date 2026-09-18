# Alert Dismissal Automation

A GitHub Actions automation for reviewing delegated GitHub security alert
dismissal requests. It supports three review modes:

| Mode | Behavior |
|---|---|
| `deterministic` | Deny requests that fail configured phrase, pattern, or length checks. |
| `agentic` | Dispatch every open request to a GitHub Agentic Workflow for contextual review. |
| `both` | Run deterministic checks first, then dispatch requests that pass them. |

The default remains `deterministic`. Agentic review is opt-in and starts in
staged mode so its decisions can be evaluated without changing alert state.

> [!NOTE]
> This automation uses GitHub's
> [delegated alert dismissal](https://docs.github.com/en/code-security/concepts/security-at-scale/delegated-alert-dismissal)
> APIs. Delegated alert dismissal must be enabled for the organization.

> [!WARNING]
> Dependabot dismissal request processing is not currently functional in this
> deployment. Track the limitation in #9.

## How it works

The existing scheduled workflow remains the discovery mechanism:

1. Mint a short-lived GitHub App installation token.
2. List open dismissal requests across the configured organization.
3. Apply the configured `review_mode`.
4. For agentic processing, send an `alert-dismissal-requested`
   `repository_dispatch` event to the automation repository.

The dispatch payload contains a sanitized snapshot of the open dismissal
request and the current AppSec team membership. It does not contain alert
content or secret values.

The compiled agentic workflow then:

1. Validates the dispatch payload against `config.yml`.
2. Resolves the monitored organization from trusted `config.yml`, then mints a
   fresh GitHub App installation token in a deterministic pre-agent step.
3. Uses the dispatched request snapshot and fetches the current alert that
   triggered the event.
4. Hides secret values and fetches a bounded set of same-organization GitHub
   issues linked from the request comment.
5. Skips inference when the dispatched request was not open or the alert is
   already assigned to AppSec.
6. Gives the agent only the sanitized local context and one bounded SafeOutput.
7. Runs gh-aw threat detection before applying the requested action.
8. Applies an optimistic denial directly or fetches the current alert only
   when needed to preserve existing assignees.

The agent can make only one of two decisions:

- **Ready for human review:** leave the dismissal request open and assign the
  alert to members of the configured AppSec team.
- **Deny:** deny the dismissal request with a concise reason, guidance about
  what supporting detail is needed, and an AppSec contact.

The agent never approves a dismissal request.

### Alert assignment behavior

The default team slug is `appsec-team` and is configurable.

- Code scanning and Dependabot alerts are assigned to all snapshotted AppSec
  team members. Existing assignees are preserved.
- The secret scanning REST API currently supports one assignee. The automation
  selects one team member deterministically from the configured team.
- The automation intentionally does not make per-user collaborator permission
  requests before assignment.

### AppSec access assumption

The configured AppSec team is assumed to have GitHub's **security manager**
organization role. That role gives the team read access to every repository and
write access to security alerts across the organization. Team membership is
resolved once by the poller and included in the App-authenticated dispatch
snapshot, avoiding team and collaborator lookups in each agentic workflow run.
See
[Managing security managers in your organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization).

## Agentic workflow safety controls

The source workflow is
[`.github/workflows/agentic-dismissal-review.md`](.github/workflows/agentic-dismissal-review.md).
`gh aw compile` generates
[`agentic-dismissal-review.lock.yml`](.github/workflows/agentic-dismissal-review.lock.yml),
which is the workflow GitHub Actions executes.

The workflow follows the
[GitHub Agentic Workflows best practices](https://github.github.com/gh-aw/introduction/how-they-work/#best-practices):

- Strict-mode compilation and SHA-pinned actions in the generated lockfile.
- Read-only built-in `GITHUB_TOKEN` permissions during agent execution.
- GitHub App secrets and installation tokens are scoped to deterministic steps
  and the separate SafeOutput job, not the model.
- GitHub MCP access is disabled, and the source workflow disables edit tools.
  gh-aw v0.82.3 still injects an internal ephemeral workspace write capability
  into the Copilot runtime; there is no commit, pull request, or patch
  SafeOutput, and the state-changing job runs from a fresh checkout.
- Network access is denied except for framework-required services.
- The only external write is a custom `apply_dismissal_decision` SafeOutput.
- Threat detection gates the SafeOutput.
- Dispatch payloads and SafeOutput targets are validated against trusted
  configuration rather than agent-provided owner, repository, or alert IDs.
- Request comments in the dispatch snapshot are redacted, bounded, and treated
  as untrusted evidence.
- Secret scanning values are removed before context is written.
- Requester text and linked issue content are explicitly treated as untrusted
  evidence.
- Concurrency, turn, timeout, and per-run AI credit limits are configured. The
  daily AI credit limit is explicitly disabled.
- Staged mode is enabled in `config.yml` by default.

Do not edit the generated `.lock.yml` directly. Edit the Markdown source and
recompile it.

## Prerequisites

| Requirement | Notes |
|---|---|
| GitHub Advanced Security products | Required for the alert types being monitored. |
| Delegated alert dismissal | Must be enabled in the organization. |
| GitHub App | Used for discovery, dispatch, request review, team lookup, and alert assignment. |
| AppSec security manager team | The configured team must have the organization security manager role. |
| Copilot inference access | The agentic workflow uses `copilot-requests: write` on its built-in Actions token. |
| Node.js 20 or newer | Local development; workflows currently use Node.js 24. |
| `gh-aw` CLI | Required only when editing or recompiling the agentic workflow. |

## GitHub App permissions

Use a dedicated App and grant only the permissions required by the enabled
review modes.

### Organization permissions

| Permission | Access | Used for |
|---|---|---|
| Organization dismissal requests for code scanning | Read & write | List and deny code scanning dismissal requests |
| Organization dismissal requests for Dependabot | Read & write | List and deny Dependabot dismissal requests |
| Secret scanning alert dismissal requests | Read & write | List and deny secret scanning dismissal requests |
| Members | Read-only for agentic mode | Resolve the configured AppSec team and its members |

### Repository permissions

| Permission | Deterministic only | Agentic enabled | Used for |
|---|---:|---:|---|
| Code scanning alerts | Read-only | Read & write | Read alert context and assign code scanning alerts |
| Dependabot alerts | Read-only | Read & write | Read alert context and assign Dependabot alerts |
| Secret scanning alerts | Read-only | Read & write | Read sanitized alert context and assign secret scanning alerts |
| Contents | Not required | Read & write | Emit `repository_dispatch` |
| Metadata | Read-only | Read-only | Required by all GitHub Apps |
| Issues | Not required | Read-only when linked evidence is private | Read same-organization issues linked from dismissal comments |

`repository_dispatch` requires `Contents: write`, and the configured workflow
repository must be in the monitored organization so one installation token can
perform discovery and dispatch. GitHub App repository
permissions apply to every repository in that installation, so review this
permission carefully. For tighter isolation, use a dedicated automation App or
host the dispatch receiver in a narrowly scoped automation repository.

The automation assumes the AppSec team has the security manager role and does
not probe individual repository collaborator permissions before assignment.
GitHub's alert assignment endpoint remains authoritative and any rejected
assignment is surfaced as a workflow failure.

## Setup

### 1. Create and install the GitHub App

Create a GitHub App with the permissions above and install it in the
organization being monitored. Webhooks are not required because request
discovery remains poll-based.

### 2. Add Actions secrets

Add these repository or organization Actions secrets to the automation
repository:

| Secret | Value |
|---|---|
| `ALERT_DISMISSAL_APP_CLIENT_ID` | GitHub App client ID |
| `ALERT_DISMISSAL_APP_PRIVATE_KEY` | Full GitHub App private key PEM |

The agentic workflow uses the built-in `GITHUB_TOKEN` and
`copilot-requests: write` for model inference. It does not use the App token for
inference.

### 3. Configure review behavior

Edit [`config.yml`](config.yml):

```yaml
# deterministic | agentic | both
review_mode: both

agentic:
  appsec_team_slug: appsec-team
  staged: true
  # workflow_repository: my-org/alert-dismissal-automation
  # help_contact: "@my-org/appsec-team"

required_pattern: "https://github\\.com/my-org/[a-zA-Z0-9._-]+/issues/\\d+"
minimum_length: 20

alert_types:
  - code_scanning
  - secret_scanning
```

Recommended rollout:

1. Keep `review_mode: deterministic` while installing the workflow and updating
   App permissions.
2. Set `review_mode: agentic` or `both`, leaving `agentic.staged: true`.
3. Review several workflow summaries and gh-aw audit logs.
4. Set `agentic.staged: false` only after the decisions and messages meet your
   policy.

### 4. Enable polling

The schedule in
[`.github/workflows/alert-dismissal-check.yml`](.github/workflows/alert-dismissal-check.yml)
is currently commented out. Enable and adjust it as needed:

```yaml
on:
  schedule:
    - cron: "*/15 * * * *"
  workflow_dispatch:
```

### 5. Install gh-aw for workflow development

```bash
gh extension install github/gh-aw
```

Compile after editing the Markdown workflow:

```bash
npm run compile:agentic
```

Commit both the `.md` source and generated `.lock.yml`.

## Manual testing

### Poller dry run

Trigger **Alert Dismissal Review** from the Actions tab with `dry_run: true`, or
run locally:

```bash
export GITHUB_TOKEN=<github-app-installation-token>
export GITHUB_REPOSITORY=my-org/alert-dismissal-automation

DRY_RUN=true node scripts/check-dismissals.js
```

Dry-run mode logs deterministic denials and agentic dispatches without making
changes or emitting a dispatch event.

### Direct repository dispatch

The dispatcher normally builds this payload from an open request. With
`review_mode` set to `agentic` or `both`, use an installation token from the
configured GitHub App for targeted testing. Dispatches from other identities
are rejected:

```bash
export GH_TOKEN=<github-app-installation-token>

gh api repos/my-org/alert-dismissal-automation/dispatches \
  --method POST \
  --input - <<'JSON'
{
  "event_type": "alert-dismissal-requested",
  "client_payload": {
    "schema_version": 2,
    "target": {
      "organization": "my-org",
      "repository": "my-org/service-repo",
      "alert_type": "code_scanning",
      "alert_number": 42,
      "dismissal_request_id": 1234,
      "dismissal_request_number": 7
    },
    "request": {
      "id": 1234,
      "number": 7,
      "status": "open",
      "request_type": "dismiss",
      "requester": { "actor_name": "octocat" },
      "requester_comment": "Test-only finding; evidence is linked here.",
      "dismissal_reasons": ["tests"],
      "created_at": "2026-09-18T15:00:00Z"
    },
    "review": {
      "appsec_team_members": ["security-reviewer-1", "security-reviewer-2"]
    },
    "source": {
      "repository": "my-org/alert-dismissal-automation",
      "run_id": "123456"
    },
    "dry_run": true
  }
}
JSON
```

The request snapshot IDs must match the target IDs. Production dispatches are
built directly from the org-level open-request listing response.

## Development

```bash
npm ci
npm test
npm run compile:agentic
```

The test suite covers deterministic validation, sanitized dispatch snapshots,
event validation, secret redaction, evidence URL filtering, assignment
selection, mention neutralization, optimistic stale-request handling, and
denial formatting.

## Configuration reference

### Deterministic checks

| Key | Default | Description |
|---|---|---|
| `required_phrase` | none | Phrase that must appear in the requester comment |
| `required_pattern` | none | JavaScript regular expression the comment must match |
| `minimum_length` | none | Minimum trimmed comment length |
| `case_sensitive` | `false` | Apply phrase and regex checks case-sensitively |

### Review and agentic settings

| Key | Default | Description |
|---|---|---|
| `review_mode` | `deterministic` | `deterministic`, `agentic`, or `both` |
| `agentic.workflow_repository` | `GITHUB_REPOSITORY` | Same-organization repository receiving `repository_dispatch` |
| `agentic.appsec_team_slug` | `appsec-team` | Team used for ready-for-review assignment |
| `agentic.staged` | `true` | Preview SafeOutput actions without applying them |
| `agentic.help_contact` | `@org/team` | Contact included in denial messages |
| `agentic.denial_message` | built-in template | Optional denial message template |

Agentic denial placeholders are `{requester}`, `{denial_reason}`,
`{help_contact}`, `{alert_type}`, `{alert_number}`, and `{repo_full_name}`.

### Scope

| Key | Default | Description |
|---|---|---|
| `alert_types` | all three types | Enabled alert categories |
| `organization` | owner of `GITHUB_REPOSITORY` | Organization whose requests are monitored |

## Repository structure

```text
.
├── .github/
│   ├── aw/
│   │   └── actions-lock.json
│   └── workflows/
│       ├── alert-dismissal-check.yml
│       ├── agentic-dismissal-review.md
│       ├── agentic-dismissal-review.lock.yml
│       └── aw.json
├── scripts/
│   ├── agentic-review.js
│   ├── apply-agentic-decision.js
│   ├── check-dismissals.js
│   ├── export-workflow-config.js
│   ├── prepare-agentic-review.js
│   └── *.test.js
├── config.yml
├── .gitattributes
├── package.json
└── package-lock.json
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No agentic workflow run appears | `review_mode` is deterministic, dry run is enabled, or the dispatch token lacks `Contents: write` | Check configuration and App permissions |
| Agent job exits before inference | The dispatched snapshot was not open or the alert is already assigned to AppSec | Review the workflow summary; this is an idempotency safeguard |
| Team lookup fails | App lacks `Members: read`, the slug is wrong, or the team is not visible to the App | Update App permissions and `appsec_team_slug` |
| Ready decision fails to assign | The AppSec team lacks the security manager role or GitHub rejected an assignee | Verify the team role and alert assignment eligibility |
| Optimistic denial becomes a no-op | A human completed or removed the request while the agent was running | No action is required; the workflow summary records the stale result |
| Workflow only previews changes | `agentic.staged` is still `true` or dispatch payload has `dry_run: true` | Disable staged mode only after validation |
| Copilot inference fails | Organization does not permit `copilot-requests: write` | Confirm Copilot entitlement and Actions policy |
| Lockfile is stale | Markdown source changed without recompilation | Run `npm run compile:agentic` and commit the lockfile |
| 403/404 from dismissal APIs | Delegated dismissal or required App permissions are missing | Verify organization and repository permissions |
