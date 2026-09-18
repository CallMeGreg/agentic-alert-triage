# Copilot Instructions — Alert Dismissal Automation

## Purpose

This repository polls GitHub's delegated security alert dismissal request APIs
and supports deterministic review, agentic review, or both. Authentication uses
a GitHub App so API actions are attributed to a named, auditable identity.

Delegated alert dismissal must be enabled in the monitored organization.

## Repository layout

```text
.
├── .github/
│   ├── aw/
│   │   └── actions-lock.json
│   ├── copilot-instructions.md
│   └── workflows/
│       ├── alert-dismissal-check.yml
│       ├── agentic-dismissal-review.md
│       ├── agentic-dismissal-review.lock.yml
│       └── aw.json
├── scripts/
│   ├── agentic-review.js
│   ├── agentic-review.test.js
│   ├── apply-agentic-decision.js
│   ├── check-dismissals.js
│   ├── check-dismissals.test.js
│   ├── export-workflow-config.js
│   └── prepare-agentic-review.js
├── config.yml
├── .gitattributes
├── package.json
├── package-lock.json
└── README.md
```

## Key design decisions

| Decision | Rationale |
|---|---|
| Polling remains the discovery mechanism | No public webhook receiver is required. |
| `review_mode` controls deterministic, agentic, or combined review | Agentic behavior is optional and backward compatible. |
| Dispatch payloads contain sanitized snapshots | The poller already has the request and team membership, so agentic runs avoid redundant reads. |
| Agent input is minimized and sanitized | Secret values are removed and linked evidence is bounded to same-org issues. |
| Agent writes use a custom SafeOutput | The model has no App token and cannot directly change GitHub state. |
| Ready is not approval | Ready requests remain open and are assigned to AppSec for final human review. |
| The AppSec team slug is configurable | Defaults to `appsec-team`; the team is assumed to hold the organization security manager role. |
| The `.lock.yml` is generated | Edit the `.md` source and run `npm run compile:agentic`; never hand-edit the lockfile. |

## Poller behavior (`scripts/check-dismissals.js`)

1. Load `config.yml` or `CONFIG_PATH`.
2. Determine the organization from config or `GITHUB_REPOSITORY`.
3. List open org-level dismissal requests for enabled alert types.
4. Apply `review_mode`:
   - `deterministic`: validate the requester comment and deny failures.
   - `agentic`: dispatch all requests not already assigned to AppSec.
   - `both`: deterministically deny failures, then dispatch passing requests.
5. Agentic dispatches use `POST /repos/{owner}/{repo}/dispatches` with event
   type `alert-dismissal-requested`.

The dispatch body contains a bounded, redacted dismissal request snapshot and
the AppSec team member logins. It must not contain alert content, literal
secrets, or agent instructions.

## Agentic workflow behavior

The Markdown source is `.github/workflows/agentic-dismissal-review.md`.
Compilation uses strict mode and generates
`.github/workflows/agentic-dismissal-review.lock.yml`.

### Pre-agent phase

`scripts/prepare-agentic-review.js`:

- validates the event against `config.yml`;
- verifies the dispatch sender matches the GitHub App whose credentials are
  configured for the workflow;
- validates the snapshotted request ID, request number, target org, alert type,
  status, and AppSec membership;
- fetches only the current alert using a GitHub App token;
- skips inference when the snapshot was not open or the alert is already
  assigned to AppSec;
- requests hidden secret values and removes sensitive patterns before context
  is written;
- fetches at most five same-organization linked issues and up to 20 comments
  per issue;
- writes `.github/agentic-review-context.json` for the agent.

All requester and linked issue content is untrusted evidence.

### Agent phase

The agent has:

- read-only built-in Actions permissions;
- no GitHub MCP server;
- `edit: false` in the workflow source; gh-aw v0.82.3 may still expose an
  internal ephemeral workspace write tool, but there is no commit, patch, or
  pull request SafeOutput and the state-changing job uses a fresh checkout;
- bounded shell access for reading local context;
- one custom SafeOutput: `apply_dismissal_decision`;
- turn, timeout, network, concurrency, and AI credit limits.

The agent chooses exactly one decision:

- `ready_for_review`
- `deny`

It never approves a dismissal request.

### SafeOutput phase

`scripts/apply-agentic-decision.js`:

- revalidates the App-authenticated event snapshot without re-fetching the
  request;
- parses exactly one structured decision;
- neutralizes mentions in agent-provided reasoning;
- honors gh-aw staged mode, `agentic.staged`, and dispatch dry-run;
- applies denials optimistically and treats known stale-review responses as
  no-ops;
- assigns ready code scanning and Dependabot alerts to snapshotted AppSec
  members while preserving existing assignees;
- assigns secret scanning alerts to one deterministic member because
  that API supports a single assignee;
- denies invalid requests with actionable requester guidance and the configured
  help contact.

## API version

All dismissal request and alert calls use:

```text
X-GitHub-Api-Version: 2026-03-10
```

The delegated dismissal endpoints are invoked with `octokit.request()` because
they may not exist in Octokit's generated typed methods.

## Configuration reference

| Key | Default | Description |
|---|---|---|
| `review_mode` | `deterministic` | `deterministic`, `agentic`, or `both` |
| `required_phrase` | none | Required requester-comment phrase |
| `required_pattern` | none | Required JavaScript regular expression |
| `minimum_length` | none | Minimum trimmed requester-comment length |
| `case_sensitive` | `false` | Case sensitivity for phrase and regex |
| `alert_types` | all types | Enabled alert categories |
| `organization` | repo owner | Monitored organization |
| `agentic.workflow_repository` | `GITHUB_REPOSITORY` | Same-organization dispatch receiver repository |
| `agentic.appsec_team_slug` | `appsec-team` | Team used for alert assignment |
| `agentic.staged` | `true` | Preview without assigning or denying |
| `agentic.help_contact` | `@org/team` | Contact in agentic denial messages |
| `agentic.denial_message` | built-in | Optional agentic denial template |
| `denial_message` | built-in | Deterministic denial template |

Agentic denial placeholders: `{requester}`, `{denial_reason}`,
`{help_contact}`, `{alert_type}`, `{alert_number}`, `{repo_full_name}`.

Deterministic denial placeholders: `{alert_type}`, `{alert_number}`,
`{required_phrase}`, `{denial_reason}`, `{requester}`, `{repo_full_name}`.

## GitHub App permissions

Organization permissions:

- Organization dismissal requests for code scanning: read/write
- Organization dismissal requests for Dependabot: read/write
- Secret scanning alert dismissal requests: read/write
- Members: read

Repository permissions:

- Code scanning alerts: read/write when agentic mode is enabled
- Dependabot alerts: read/write when agentic mode is enabled
- Secret scanning alerts: read/write when agentic mode is enabled
- Contents: write for `repository_dispatch`
- Issues: read when linked private issue evidence is needed
- Metadata: read

The configured AppSec team is assumed to have GitHub's organization security
manager role, which provides read access to every repository and write access
to security alerts. The automation does not make per-user collaborator
permission checks; assignment API failures are surfaced explicitly.

## Required secrets

| Secret | Description |
|---|---|
| `ALERT_DISMISSAL_APP_CLIENT_ID` | GitHub App client ID |
| `ALERT_DISMISSAL_APP_PRIVATE_KEY` | Full GitHub App private key PEM |

Copilot inference uses `copilot-requests: write` on the built-in Actions token.
Never pass the App private key or installation token to the agent environment.

## Development commands

```bash
npm ci
npm test
npm run compile:agentic
```

Keep `.github/workflows/aw.json` in strict mode. Commit both the Markdown source
and compiled lockfile after agentic workflow changes.
