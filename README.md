# Agentic Alert Triage

A persistent [Probot](https://probot.github.io/) GitHub App that reviews
delegated security alert dismissal requests as soon as GitHub delivers the
signed webhook. It supports deterministic policy checks, bounded agentic
review, or both.

| Mode | Behavior |
|---|---|
| `deterministic` | Immediately deny requests whose comments fail configured phrase, pattern, or length checks. Passing requests remain open. |
| `agentic` | Send every created request to the central gh-aw workflow for contextual review. |
| `both` | Deny deterministic failures immediately and dispatch passing requests for agentic review. |

The agent never approves a dismissal request. A request judged ready remains
open and the alert is assigned to the configured AppSec team for final human
review.

## Webhook ingress

The App subscribes to the official GitHub webhook categories below and handles
only the `created` action:

| Webhook event | Probot event | Required `exemption_request_data.type` |
|---|---|---|
| `dismissal_request_code_scanning` | `dismissal_request_code_scanning.created` | `code_scanning_alert_dismissal` |
| `dismissal_request_dependabot` | `dismissal_request_dependabot.created` | `dependabot_alert_dismissal` |
| `dismissal_request_secret_scanning` | `dismissal_request_secret_scanning.created` | `secret_scanning_closure` |

See GitHub's
[webhook events and payloads](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
reference. All three alert types are enabled in [`config.yml`](config.yml) by
default. Removing a type from `alert_types` makes the subscribed event a safe
no-op.

For each signed delivery, the handler:

1. Validates the event/action, organization, repository and installation IDs,
   dismissal request IDs, repository ID, requester, request data type, and up
   to 100 positive unique alert numbers.
2. Ignores opaque `metadata`, `responses`, and unknown request-data fields.
3. Applies deterministic checks with the incoming installation Octokit when
   configured.
4. Resolves and caches the configured AppSec team's sanitized member logins
   with the incoming installation Octokit.
5. Resolves the GitHub App installation for the central control repository
   using App authentication, obtains that installation Octokit, and creates one
   `repository_dispatch` per unique alert number.

The dismissal request is never re-fetched. The trusted snapshot comes directly
from GitHub's signature-verified webhook payload.

## Agentic review flow

The repository dispatch uses schema version 1 and is capped at 60,000
characters. It contains only:

- validated target organization, repository, repository ID, alert type, alert
  number, and dismissal request identifiers;
- a bounded request snapshot with requester login, comment, request status,
  request data type, selected dismissal reasons, dates, and URL;
- a sanitized, sorted AppSec membership snapshot;
- bounded provenance: control repository, webhook event, incoming installation
  ID, and delivery ID when available.

Token-shaped values and private keys are redacted from requester text. Alert
content, secret values, opaque webhook fields, and agent instructions are not
included.

The compiled workflow
[`agentic-dismissal-review.lock.yml`](.github/workflows/agentic-dismissal-review.lock.yml)
is generated from
[`agentic-dismissal-review.md`](.github/workflows/agentic-dismissal-review.md).
It:

1. Validates the App-authenticated dispatch sender, target, schema, request
   snapshot, source event, installation metadata, alert type, and team snapshot
   against trusted `config.yml`.
2. Mints a fresh installation token for the monitored organization using the
   same GitHub App.
3. Fetches only the current alert and up to five same-organization linked
   issues with at most 20 comments each. It does not fetch current request
   state.
4. Requests secret scanning alerts with `hide_secret=true` and removes
   sensitive patterns before writing local agent context.
5. Skips inference when the webhook snapshot was not open/pending or the alert
   is already assigned to AppSec.
6. Gives the model read-only local context, bounded shell access, no GitHub MCP,
   no edit/commit/PR output, and one custom SafeOutput:
   `apply_dismissal_decision`.
7. Runs gh-aw threat detection before a fresh-checkout SafeOutput job applies
   the decision with a new App installation token.

Concurrency is grouped per repository, alert type, and alert number with
`cancel-in-progress: true`. Denials are optimistic writes: known stale responses
from already completed, cancelled, expired, approved, or denied requests are
safe no-ops. Assignment endpoint failures are not hidden.

### Assignment behavior

- Code scanning and Dependabot alerts preserve existing assignees and add all
  snapshotted AppSec members.
- Secret scanning currently supports one alert assignee, selected
  deterministically from the team snapshot.
- No per-user collaborator probes are made.

The configured team is assumed to hold GitHub's organization
[Security Manager role](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization),
which provides repository read access and permission to manage security alerts.

## GitHub App installation and authentication

Use one GitHub App registration, but install it in both security and control
planes:

1. **Monitored organization/repositories:** receives dismissal-request
   webhooks, performs deterministic denials, reads AppSec membership, and
   allows the agentic workflow to read and assign alerts.
2. **Control repository owner/repository:** includes the repository configured
   by `agentic.workflow_repository` (default
   `CallMeGreg/agentic-alert-triage`) and permits `repository_dispatch`.

The incoming webhook installation token is never assumed to reach the control
repository. For dispatch, the service authenticates as the App, calls
[`GET /repos/{owner}/{repo}/installation`](https://docs.github.com/en/rest/apps/installations#get-a-repository-installation-for-the-authenticated-app),
caches the installation ID briefly, obtains that installation's Octokit
through Probot, and calls
[`POST /repos/{owner}/{repo}/dispatches`](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).

The control-repository installation requires **Contents: write**. The same App
permission set applies across installations, so use selected-repository
installations where tighter repository scope is required.

## GitHub App permissions

[`app.yml`](app.yml) is a Probot/GitHub App manifest for initial registration.
It includes the standard parameterized permissions and exact webhook event
subscriptions. Changing it does not update an existing App.

Verify these permissions in the GitHub App settings UI:

### Organization permissions

| Permission shown in GitHub | Access | Purpose |
|---|---|---|
| Organization dismissal requests for code scanning | Read & write | Receive/review code scanning dismissal requests |
| Organization dismissal requests for Dependabot | Read & write | Receive/review Dependabot dismissal requests |
| Secret scanning alert dismissal requests | Read & write | Receive/review secret scanning dismissal requests |
| Members | Read-only | Resolve the configured AppSec team |

The manifest uses GitHub's current documented permission slugs. Existing App
registrations must still be updated and approved in the App UI; verify these
permissions by their display names rather than guessing new slugs.

### Repository permissions

| Permission shown in GitHub | Access | Purpose |
|---|---|---|
| Code scanning alerts | Read & write | Subscribe, read current alerts, and assign ready alerts |
| Dependabot alerts | Read & write | Subscribe, read current alerts, and assign ready alerts |
| Secret scanning alerts | Read & write | Subscribe, read hidden-secret alert context, and assign ready alerts |
| Contents | Write | Create `repository_dispatch` on the control repository |
| Issues | Read-only | Read bounded linked evidence, including private issues when installed |
| Metadata | Read-only | Required GitHub App repository metadata |

GitHub documents the permission required by each endpoint in
[Permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).

## Configure the service

[`config.yml`](config.yml) is loaded once when the Probot process starts:

```yaml
organization: callmegreg-demo-org
review_mode: both

required_pattern: "https://github\\.com/callmegreg-demo-org/[a-zA-Z0-9._-]+/issues/\\d+"
minimum_length: 20
case_sensitive: false

alert_types:
  - code_scanning
  - dependabot
  - secret_scanning

agentic:
  workflow_repository: CallMeGreg/agentic-alert-triage
  appsec_team_slug: appsec-team
  staged: true

cache:
  team_members_ttl_seconds: 300
  control_installation_ttl_seconds: 600
  delivery_dedupe_ttl_seconds: 900
  delivery_dedupe_max_entries: 1000
```

### Configuration reference

| Key | Default | Description |
|---|---|---|
| `organization` | webhook organization in deterministic mode; required trusted value for agentic use | Only this organization's events and workflow targets are accepted |
| `review_mode` | `deterministic` | `deterministic`, `agentic`, or `both` |
| `required_phrase` | none | Phrase required in the requester comment |
| `required_pattern` | none | JavaScript regular expression required in the requester comment |
| `minimum_length` | none | Minimum trimmed requester-comment length |
| `case_sensitive` | `false` | Case-sensitive phrase and regex matching |
| `alert_types` | all three | Enabled alert categories; subscribed disabled types are ignored |
| `agentic.workflow_repository` | `CallMeGreg/agentic-alert-triage` | Central repository receiving schema-v1 dispatches |
| `agentic.appsec_team_slug` | `appsec-team` | Security Manager team used for ready-alert assignment |
| `agentic.staged` | `true` | Preview SafeOutput writes |
| `agentic.help_contact` | `@org/team` | Contact included in agentic denials |
| `agentic.denial_message` | built-in | Optional agentic denial template |
| `denial_message` | built-in | Optional deterministic denial template |
| `cache.team_members_ttl_seconds` | `300` | Process-local team cache TTL, 1-3600 seconds |
| `cache.control_installation_ttl_seconds` | `600` | Process-local control installation cache TTL, 1-3600 seconds |
| `cache.delivery_dedupe_ttl_seconds` | `900` | Successful delivery-operation dedupe TTL, 1-3600 seconds |
| `cache.delivery_dedupe_max_entries` | `1000` | Bounded delivery-operation cache size, 1-10000 |

Agentic denial placeholders are `{requester}`, `{denial_reason}`,
`{help_contact}`, `{alert_type}`, `{alert_number}`, and `{repo_full_name}`.
Deterministic denial placeholders are `{alert_type}`, `{alert_number}`,
`{required_phrase}`, `{denial_reason}`, `{requester}`, and `{repo_full_name}`.

Restart the service after configuration changes.

## Deploy Probot

The application requires Node.js 22 or newer and pins Probot exactly to
`14.3.2`. GitHub Actions workflows may continue using Node.js 24.

### Environment

Copy [`.env.example`](.env.example) to `.env` for local development, or set
these values in the deployment platform:

| Variable | Required | Description |
|---|---:|---|
| `APP_ID` | yes | GitHub App ID |
| `PRIVATE_KEY` or `PRIVATE_KEY_PATH` | yes | GitHub App private key contents or file path |
| `WEBHOOK_SECRET` | yes | Strong secret matching the GitHub App webhook configuration |
| `PORT` | no | HTTP port, default `3000` |
| `WEBHOOK_PROXY_URL` | local only | Smee or equivalent forwarding URL |
| `CONFIG_PATH` | no | Configuration file path, default `./config.yml` |
| `LOG_LEVEL` | no | Probot log level |

Set the GitHub App webhook URL to the public Probot endpoint:

```text
https://your-service.example/api/github/webhooks
```

Probot validates `X-Hub-Signature-256` using `WEBHOOK_SECRET`. Do not deploy
without a webhook secret.

Install dependencies and start the persistent HTTP service:

```bash
npm install
npm start
```

See Probot's
[configuration](https://probot.github.io/docs/configuration/) and
[deployment](https://probot.github.io/docs/deployment/) guides.

### Local webhook development

```bash
cp .env.example .env
# Fill APP_ID, PRIVATE_KEY_PATH, WEBHOOK_SECRET, and WEBHOOK_PROXY_URL.
npm install
npm run dev
```

Create a temporary forwarding URL at [smee.io](https://smee.io/new), use it as
the App webhook URL and `WEBHOOK_PROXY_URL`, and keep its secret identical to
`WEBHOOK_SECRET`.

### Container

The platform-neutral [`Dockerfile`](Dockerfile) uses Node.js 22:

```bash
docker build -t agentic-alert-triage .
docker run --rm -p 3000:3000 --env-file .env agentic-alert-triage
```

Mount a private key file into the container when using `PRIVATE_KEY_PATH`, or
provide `PRIVATE_KEY` through the deployment secret store.

## Configure the agentic workflow

The control repository needs these Actions secrets:

| Secret | Description |
|---|---|
| `ALERT_DISMISSAL_APP_CLIENT_ID` | Client ID for the same GitHub App used by Probot |
| `ALERT_DISMISSAL_APP_PRIVATE_KEY` | Full private key PEM for that App |

The App must be installed on the configured monitored organization so
`actions/create-github-app-token` can mint the alert/evidence and decision
tokens. The model never receives the App private key or installation token.
Copilot inference uses `copilot-requests: write` on the workflow's built-in
Actions token.

Keep `agentic.staged: true` while evaluating decisions. Set it to `false` only
after reviewing workflow summaries and gh-aw audit logs.

Do not edit the generated `.lock.yml` directly. Edit the Markdown source, then:

```bash
npm run compile:agentic
```

Commit both workflow files.

## Delivery, retry, and scaling semantics

GitHub webhook delivery is at-least-once.

- A bounded process-local cache deduplicates each delivery/alert operation
  during its TTL. Failed operations are removed so a GitHub retry can run.
- Team membership and control-installation resolution are cached for short
  configurable TTLs, avoiding one Members API call and one App installation
  lookup per event.
- Caches do not survive restarts and are not shared by replicas. They are an
  efficiency layer, not the durable correctness mechanism.
- Across restarts or replicas, duplicate agentic dispatches converge through
  per-alert gh-aw concurrency with cancellation. Duplicate deterministic or
  agentic denials converge through optimistic writes and stale-response
  handling.
- A multi-alert request creates one dispatch per unique validated alert number.
  If one operation fails, successful cache entries remain and the failed entry
  is retryable.

For multi-replica rate-limit coordination, Probot supports `REDIS_URL` for
Octokit throttling. The delivery dedupe cache in this project remains local;
use an external queue/idempotency store before relying on exactly-once
processing across replicas.

Logs contain event names, delivery/request identifiers, repositories, alert
counts, and outcomes. Requester comments and secret-bearing webhook content are
not logged.

## Development

```bash
npm install
npm run check
npm test
npm run compile:agentic
```

The test suite covers exact event registration and routing, action/type
validation, multi-alert deduplication, disabled alert types, request
snapshotting and redaction, team and control-installation caches, separate
control dispatch authentication, deterministic/agentic/both behavior,
duplicate deliveries, retries, stale writes, secret hiding, assignment, and
failure propagation.

## Repository structure

```text
.
├── .github/
│   ├── aw/actions-lock.json
│   └── workflows/
│       ├── agentic-dismissal-review.md
│       ├── agentic-dismissal-review.lock.yml
│       └── aw.json
├── scripts/
│   ├── agentic-review.js
│   ├── apply-agentic-decision.js
│   ├── deterministic-review.js
│   ├── prepare-agentic-review.js
│   ├── webhook-review.js
│   └── *.test.js
├── .env.example
├── app.yml
├── config.yml
├── Dockerfile
├── index.js
├── package.json
└── package-lock.json
```
