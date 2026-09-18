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

The dispatch payload contains only trusted identifiers. It deliberately does
not include the requester comment or alert content.

The compiled agentic workflow then:

1. Validates the dispatch payload against `config.yml`.
2. Resolves the monitored organization from trusted `config.yml`, then mints a
   fresh GitHub App installation token in a deterministic pre-agent step.
3. Fetches the exact dismissal request and alert that triggered the event.
4. Redacts secret values and fetches a bounded set of same-organization GitHub
   issues linked from the request comment.
5. Skips inference when the request is no longer open or the alert is already
   assigned to AppSec.
6. Gives the agent only the sanitized local context and one bounded SafeOutput.
7. Runs gh-aw threat detection before applying the requested action.
8. Re-fetches current state in the SafeOutput job before making a change.

The agent can make only one of two decisions:

- **Ready for human review:** leave the dismissal request open and assign the
  alert to eligible members of the configured AppSec team.
- **Deny:** deny the dismissal request with a concise reason, guidance about
  what supporting detail is needed, and an AppSec contact.

The agent never approves a dismissal request.

### Alert assignment behavior

The default team slug is `appsec-team` and is configurable.

- Code scanning and Dependabot alerts are assigned to all team members who
  have write access to the repository. Existing assignees are preserved.
- The secret scanning REST API currently supports one assignee. The automation
  selects one eligible team member deterministically from the configured team.
- Team members without repository write access are reported in the workflow
  summary and are not assigned.

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
- Secret scanning values are removed before context is written.
- Requester text and linked issue content are explicitly treated as untrusted
  evidence.
- Concurrency, turn, timeout, per-run AI credit, and daily AI credit limits are
  configured.
- Staged mode is enabled in `config.yml` by default.

Do not edit the generated `.lock.yml` directly. Edit the Markdown source and
recompile it.

## Prerequisites

| Requirement | Notes |
|---|---|
| GitHub Advanced Security products | Required for the alert types being monitored. |
| Delegated alert dismissal | Must be enabled in the organization. |
| GitHub App | Used for discovery, dispatch, request review, team lookup, and alert assignment. |
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
| Metadata | Read-only | Read-only | Required by GitHub Apps and used for collaborator permission checks |
| Issues | Not required | Read-only when linked evidence is private | Read same-organization issues linked from dismissal comments |

`repository_dispatch` requires `Contents: write`, and the configured workflow
repository must be in the monitored organization so one installation token can
perform discovery and dispatch. GitHub App repository
permissions apply to every repository in that installation, so review this
permission carefully. For tighter isolation, use a dedicated automation App or
host the dispatch receiver in a narrowly scoped automation repository.

The AppSec team members must have write access to a repository before GitHub
allows them to be assigned to its alerts.

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
  -f event_type=alert-dismissal-requested \
  -F 'client_payload[schema_version]=1' \
  -f 'client_payload[organization]=my-org' \
  -f 'client_payload[source_repository]=my-org/alert-dismissal-automation' \
  -f 'client_payload[repository]=my-org/service-repo' \
  -f 'client_payload[alert_type]=code_scanning' \
  -F 'client_payload[alert_number]=42' \
  -F 'client_payload[dismissal_request_id]=1234' \
  -F 'client_payload[dismissal_request_number]=7' \
  -F 'client_payload[dry_run]=true'
```

The IDs must match the live request fetched by the workflow.

## Development

```bash
npm ci
npm test
npm run compile:agentic
```

The test suite covers deterministic validation, dispatch payload minimization,
event validation, secret redaction, evidence URL filtering, assignment
selection, mention neutralization, and denial formatting.

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
| Agent job exits before inference | Request was already handled or the alert is already assigned to AppSec | Review the workflow summary; this is an idempotency safeguard |
| Team lookup fails | App lacks `Members: read`, the slug is wrong, or the team is not visible to the App | Update App permissions and `appsec_team_slug` |
| Ready decision fails to assign | No team member has write access to the target repository | Grant eligible members write access |
| Workflow only previews changes | `agentic.staged` is still `true` or dispatch payload has `dry_run: true` | Disable staged mode only after validation |
| Copilot inference fails | Organization does not permit `copilot-requests: write` | Confirm Copilot entitlement and Actions policy |
| Lockfile is stale | Markdown source changed without recompilation | Run `npm run compile:agentic` and commit the lockfile |
| 403/404 from dismissal APIs | Delegated dismissal or required App permissions are missing | Verify organization and repository permissions |
