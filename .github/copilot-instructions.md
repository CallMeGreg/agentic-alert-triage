# Copilot Instructions - Agentic Alert Triage

## Purpose

This repository runs a persistent Probot GitHub App that receives signed
delegated security alert dismissal request webhooks and supports deterministic
review, agentic review, or both.

Delegated alert dismissal must be enabled in the monitored organization.
Secret scanning delegated dismissal is public preview.

## Repository layout

```text
.
├── .github/
│   ├── aw/actions-lock.json
│   ├── copilot-instructions.md
│   └── workflows/
│       ├── agentic-dismissal-review.md
│       ├── agentic-dismissal-review.lock.yml
│       └── aw.json
├── scripts/
│   ├── agentic-review.js
│   ├── agentic-review.test.js
│   ├── apply-agentic-decision.js
│   ├── check-syntax.js
│   ├── deterministic-review.js
│   ├── deterministic-review.test.js
│   ├── export-workflow-config.js
│   ├── prepare-agentic-review.js
│   ├── webhook-review.js
│   └── webhook-review.test.js
├── .env.example
├── app.yml
├── config.yml
├── Dockerfile
├── index.js
├── package.json
└── package-lock.json
```

## Runtime and ingress

- Probot is pinned exactly to `14.3.2`.
- Local/production Node.js must be 22 or newer. Actions may use Node.js 24.
- `index.js` registers the handlers from `scripts/webhook-review.js`.
- The only handled webhook actions are:
  - `dismissal_request_code_scanning.created`
  - `dismissal_request_dependabot.created`
  - `dismissal_request_secret_scanning.created`
- Their required `exemption_request_data.type` values are:
  - `code_scanning_alert_dismissal`
  - `dependabot_alert_dismissal`
  - `secret_scanning_closure`

All three types are enabled by default. A subscribed event whose alert type is
not in `config.yml` is ignored before request processing.

Do not reintroduce scheduled polling or org-level dismissal-request listing.
The signed webhook `exemption_request` is the trusted request snapshot.

## Webhook validation and processing

`scripts/webhook-review.js`:

1. Loads local `config.yml` once at process startup.
2. Validates event/action consistency, configured organization, repository and
   installation IDs, request and requester IDs, request repository ID, request
   data type, and up to 100 bounded alert numbers.
3. Deduplicates alert numbers and handles each unique number once per bounded
   process-local delivery cache entry.
4. Ignores opaque webhook fields such as `metadata`, `responses`, and unknown
   request-data fields.
5. Never logs requester comments or secret-bearing payload content.
6. Uses the incoming installation Octokit for deterministic denials and AppSec
   team membership.
7. Uses App authentication to resolve the control repository installation via
   `GET /repos/{owner}/{repo}/installation`, obtains that installation Octokit
   through Probot, and creates the `repository_dispatch`.

The incoming installation token must never be assumed to access the control
repository.

### Review modes

- `deterministic`: validate with `scripts/deterministic-review.js`; deny each
  invalid alert immediately and leave passing requests open.
- `agentic`: skip deterministic criteria and dispatch every valid created
  request.
- `both`: deny deterministic failures and dispatch passing requests.

Known stale deterministic denial responses are safe no-ops. Other endpoint
errors must surface.

### Caches

The process-local caches are bounded and configurable:

- AppSec team members: default 300 seconds, keyed by organization/team.
- Control repository installation ID: default 600 seconds.
- Successful delivery/alert operations: default 900 seconds, maximum 1000
  entries.

Failed cache loaders/operations are removed so webhook retries can run. These
caches are only an API-efficiency layer; they do not provide durable
exactly-once behavior across restarts or replicas.

## Dispatch schema and safety

`scripts/agentic-review.js` owns the schema-version-1 dispatch and workflow
validation helpers.

The payload is capped at 60,000 characters and contains only:

- validated target organization, repository, repository ID, alert type, alert
  number, and request IDs;
- a bounded/redacted request snapshot;
- sanitized AppSec logins;
- source control repository, official webhook event, incoming installation ID,
  and delivery ID when present.

Do not add opaque webhook objects to the dispatch or agent context. Never pass
alert content, literal secrets, App credentials, installation tokens, or agent
instructions.

Token-shaped text and known secret values are redacted. Request comments,
alert fields, linked issues, and linked issue comments remain untrusted
evidence.

## App authentication and permissions

The same GitHub App must be installed:

1. On the monitored organization/repositories, to receive webhooks, deny
   invalid requests, read team membership, and read/assign alerts.
2. On the configured control repository owner/repository, to create
   `repository_dispatch` using `Contents: write`.

Organization permissions configured in the GitHub App UI:

- Organization dismissal requests for code scanning: read/write
- Organization dismissal requests for Dependabot: read/write
- Secret scanning alert dismissal requests: read/write
- Members: read

Repository permissions:

- Code scanning alerts: read/write
- Dependabot alerts: read/write
- Secret scanning alerts: read/write
- Contents: write for dispatch to the control repository
- Issues: read for linked evidence
- Metadata: read

Do not invent manifest permission slugs for delegated-dismissal permissions.
`app.yml` uses GitHub's current documented slugs, and existing registrations
must still be updated and verified by display name in the App UI.

The AppSec team slug defaults to `appsec-team`. The team is assumed to hold the
organization Security Manager role, which supplies repository read and
security-alert management access. Do not add per-user collaborator permission
lookups. Assignment endpoint failures must remain visible.

## Agentic workflow behavior

Edit `.github/workflows/agentic-dismissal-review.md`; never hand-edit the
generated `.lock.yml`. Run `npm run compile:agentic` after source changes and
commit both files.

### Pre-agent phase

`scripts/prepare-agentic-review.js`:

- validates the App-authenticated dispatch sender and schema against trusted
  config;
- validates target/source metadata and the sanitized request snapshot;
- mints/uses the monitored-organization installation token;
- fetches only the current alert, never current request state;
- sets `hide_secret=true` for secret scanning alert reads;
- skips inference when the snapshotted request was not open/pending or the
  alert is already assigned to AppSec;
- fetches at most five same-organization linked issues and at most 20 comments
  per issue;
- writes `.github/agentic-review-context.json`.

### Agent phase

The agent has:

- read-only built-in Actions permissions;
- no GitHub MCP server;
- `edit: false`;
- bounded `cat` access to local context;
- one custom SafeOutput, `apply_dismissal_decision`;
- threat detection, network denial, concurrency, turn, timeout, and AI credit
  limits.

The agent chooses exactly one decision:

- `ready_for_review`
- `deny`

It never approves a dismissal request.

### SafeOutput phase

`scripts/apply-agentic-decision.js`:

- revalidates the trusted dispatch without fetching current request state;
- parses exactly one structured decision;
- neutralizes mentions and markup in agent reasoning;
- honors gh-aw staged mode, `agentic.staged`, and dispatch dry-run;
- denies optimistically and treats only known stale-review responses as no-ops;
- preserves existing code scanning/Dependabot assignees while adding the
  snapshotted AppSec members;
- selects one deterministic secret scanning assignee;
- surfaces unexpected denial and assignment failures.

The workflow keeps per-alert concurrency with `cancel-in-progress: true`.

## Configuration

Important defaults:

| Key | Default |
|---|---|
| `review_mode` | `deterministic` |
| `alert_types` | all three alert categories |
| `agentic.workflow_repository` | `CallMeGreg/agentic-alert-triage` |
| `agentic.appsec_team_slug` | `appsec-team` |
| `agentic.staged` | `true` |
| `cache.team_members_ttl_seconds` | `300` |
| `cache.control_installation_ttl_seconds` | `600` |
| `cache.delivery_dedupe_ttl_seconds` | `900` |
| `cache.delivery_dedupe_max_entries` | `1000` |

`organization` is the trusted monitored organization. Set it explicitly when
agentic review is enabled or when the control repository has a different owner.

## Required secrets and environment

Probot deployment:

- `APP_ID`
- `PRIVATE_KEY` or `PRIVATE_KEY_PATH`
- `WEBHOOK_SECRET`
- optional `WEBHOOK_PROXY_URL`, `PORT`, `CONFIG_PATH`, `LOG_LEVEL`

Control repository Actions:

- `ALERT_DISMISSAL_APP_CLIENT_ID`
- `ALERT_DISMISSAL_APP_PRIVATE_KEY`

Never pass App credentials or installation tokens into the agent environment.

## Development commands

```bash
npm install
npm run check
npm test
npm run compile:agentic
```

Keep `.github/workflows/aw.json` in strict mode. Preserve the current gh-aw
SafeOutput architecture, threat detection, limits, and concurrency behavior.
