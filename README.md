# Agentic Alert Triage

A GitHub App built with [Probot](https://probot.github.io/) that reviews
delegated security alert dismissal requests across an enterprise.
It supports deterministic policy checks, bounded agentic
review, or both.

| Mode | Behavior |
|---|---|
| `deterministic` | Immediately deny requests whose comments fail configured phrase, pattern, or length checks. Passing requests remain open. |
| `agentic` | Send every created request to the central gh-aw workflow for contextual review. |
| `both` | Deny deterministic failures immediately and dispatch passing requests for agentic review. |

> [!IMPORTANT]
> The agent never approves a dismissal request. A request judged as "ready" remains
open and the alert is assigned to the configured AppSec team for final human
review.

## Webhook ingress

The App subscribes to the GitHub webhook categories below and handles
only the `created` action:

| Webhook event | Probot event | Required `exemption_request_data.type` |
|---|---|---|
| `dismissal_request_code_scanning` | `dismissal_request_code_scanning.created` | `code_scanning_alert_dismissal` |
| `dismissal_request_dependabot` | `dismissal_request_dependabot.created` | `dependabot_alert_dismissal` |
| `dismissal_request_secret_scanning` | `dismissal_request_secret_scanning.created` | `secret_scanning_closure` |

All three alert types are enabled in [`config.yml`](config.yml) by
default. Removing a type from `alert_types` makes the subscribed event a safe
no-op.

For each signed delivery, the handler:

1. Validates the event/action, organization, repository and installation IDs,
   dismissal request IDs, repository ID, requester, request data type, and up
   to 100 positive unique alert numbers. Also verifies with
   App-authenticated `GET /app` that the App is owned by the configured
   enterprise before any denial, team lookup, or dispatch.
2. Ignores opaque `metadata`, `responses`, and unknown request-data fields.
3. Applies deterministic checks with the incoming installation Octokit when
   configured.
4. Resolves the App's **enterprise installation** using App authentication and
   caches the configured enterprise AppSec team's sanitized member logins using
   that installation's Octokit. Organization installation tokens are never
   used for enterprise team membership.
5. Resolves the GitHub App installation for the central control repository
   using App authentication, obtains that installation Octokit, and creates one
   `repository_dispatch` per unique alert number.

The dismissal request is never re-fetched. The trusted snapshot comes directly
from GitHub's signature-verified webhook payload.

## Agentic review flow

When the app receives one of the dismissal request events, 
a repository dispatch event is fired to trigger the agentic workflow.
The dispatch event includes:

- validated target organization, repository, alert type, alert
  number, and dismissal request identifiers;
- a bounded request snapshot with requester login, comment, request status,
  request data type, selected dismissal reasons, dates, and URL;
- a sanitized, sorted enterprise AppSec membership snapshot and its full
  `ent:` team slug (`review.appsec_team_slug`);
- bounded provenance: control repository, webhook event, incoming installation
  ID, delivery ID when available, and the verified enterprise slug
  (`source.enterprise`).

Alert content, secret values, opaque webhook fields, app private keys, and agent instructions are not
included.

The compiled workflow
[`agentic-dismissal-review.lock.yml`](.github/workflows/agentic-dismissal-review.lock.yml)
is generated from
[`agentic-dismissal-review.md`](.github/workflows/agentic-dismissal-review.md).
It:

1. Authenticates as the App with `GET /app`, verifies its enterprise ownership,
   and validates the dispatch sender against the returned App
   identity. Validates the target, schema, request snapshot, source event,
   enterprise provenance, installation metadata, alert type, and team snapshot
   against trusted `config.yml` before exporting a token owner.
2. Mints a fresh installation token for the validated **target organization**,
   not the control repository owner. Checks that its installation ID matches
   the signed webhook's source installation ID before using it.
3. Fetches only the current alert and up to five same-organization linked
   issues with at most 20 comments each.
4. Requests secret scanning alerts with `hide_secret=true` and removes
   sensitive patterns before writing local agent context.
5. Skips inference when the webhook snapshot was not open/pending or the alert
   is already assigned to the AppSec team members.
6. Gives the model read-only local context, bounded shell access, no GitHub MCP,
   no edit/commit/PR output, and one custom SafeOutput:
   `apply_dismissal_decision`.
7. Runs gh-aw threat detection before a fresh-checkout SafeOutput job repeats
   the App/dispatch validation and applies the decision with a new token for
   that same target installation.

Concurrency is grouped per repository, alert type, and alert number with
`cancel-in-progress: true` to avoid wasted token spend. Denials are optimistic writes: known stale responses
from already completed, cancelled, expired, approved, or denied requests are
safe no-ops. Assignment endpoint failures are not hidden.

### Assignment behavior

- Code scanning and Dependabot alerts preserve existing assignees and add all
  snapshotted AppSec members.
- Secret scanning currently supports one alert assignee, selected
  deterministically from the team snapshot.

The configured **enterprise team** is assumed to hold GitHub's **enterprise
Security Manager role**, providing access to manage security alerts across the
enterprise. The application does not validate role assignments or probe
per-user repository permissions; assignment failures remain visible.
Assign the role in the enterprise's **People > Enterprise roles > Role
assignments** settings. GitHub currently documents this role as public preview:
[Assigning enterprise roles](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-accounts-and-repositories/managing-roles-in-your-enterprise/assign-roles).

## GitHub App installation and authentication

Use one enterprise-owned GitHub App registration with separate installations
for enterprise membership, target alerts, and the central workflow repository:

1. **Enterprise account:** reads enterprise team membership with
   **Enterprise teams: read**. Probot resolves this installation using
   `GET /enterprises/{enterprise}/installation` and uses its installation token
   for `GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships`.
2. **Every monitored organization/repositories:** receives dismissal-request
   webhooks, performs deterministic denials, and allows the agentic workflow
   to read and assign alerts.
3. **Control repository owner/repository:** includes the repository configured
   by `agentic.workflow_repository` (default
   `CallMeGreg/agentic-alert-triage`) and permits `repository_dispatch`.

The incoming webhook installation token is never assumed to reach the
enterprise membership API or the control repository. Enterprise tokens are
never used for repository alert writes or dispatch. For dispatch, the service
authenticates as the App, calls
[`GET /repos/{owner}/{repo}/installation`](https://docs.github.com/en/rest/apps/installations#get-a-repository-installation-for-the-authenticated-app),
caches the installation ID briefly, obtains that installation's Octokit
through Probot, and calls
[`POST /repos/{owner}/{repo}/dispatches`](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).

The control-repository installation requires **Contents: write**. The same App
permission set applies across installations, so use selected-repository
installations where tighter repository scope is required.

### Automatic enterprise-wide organization onboarding

1. Register the App **under the enterprise**, or
   [transfer the existing private App to it](https://docs.github.com/en/apps/maintaining-github-apps/transferring-ownership-of-a-github-app).
   An enterprise-owned App has internal visibility and GitHub restricts its
   installations to the enterprise and its organizations. An organization-owned
   private App (`public: false` in `app.yml`) cannot be installed across other
   organizations just because they share an enterprise. Making it public does
   not establish enterprise ownership and is not supported.
2. Place the central workflow repository in an organization **inside the same
   enterprise**. Set `agentic.workflow_repository` to that repository and
   install the App there. The sample `CallMeGreg/agentic-alert-triage` default
   must be replaced for an enterprise deployment; enterprise-owned Apps cannot
   be installed on personal accounts.
3. Enable **Enterprise teams: read** in the enterprise App settings and
   install the App on the **enterprise account**. Create one nonempty enterprise
   team, such as `ent:appsec-team`, and assign it the **enterprise Security
   Manager role**. No organization-local AppSec teams are needed.
4. Install the same App on each monitored organization and the repositories to
   be reviewed. Include any repositories used for linked issue evidence.
   Enable delegated dismissal in each organization.
5. Set `enterprise: your-enterprise` in the service and central repository
   configuration, and set `agentic.appsec_team_slug` to the full enterprise
   team slug, including `ent:`. Keep the trust scope, policy, team slug,
   and workflow repository consistent between both copies; restart Probot
   after changing its local configuration.
6. Store the same App's credentials in the service and central repository
   Actions secrets. Deploy the compiled workflow on the central repository's
   default branch. No workflow files or Actions secrets are needed in monitored
   repositories.

After setup, another organization in the enterprise only needs the App
installation and delegated dismissal; it does not need a config entry or a
separate AppSec team.
Installing an App on the enterprise account itself is **not** a substitute for
organization/repository installations, and organization installations do not
substitute for the enterprise installation. Membership snapshots are fetched
only by Probot; neither the model nor the Actions workflow needs an enterprise
token.

The trust boundary is GitHub's restriction on **enterprise-owned App
installations**, verified via the enterprise owner returned by authenticated
`GET /app`. It does not trust an enterprise name supplied in request comments,
opaque webhook fields, or a human-created repository dispatch. App ownership
lookups are cached briefly in Probot and performed afresh in each workflow
phase; failures do not fall back to accepting arbitrary organizations.

See GitHub's
[enterprise App setup and installation guidance](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-github-apps-for-your-enterprise/creating-github-apps-for-your-enterprise).

## GitHub App permissions

[`app.yml`](app.yml) is a Probot/GitHub App manifest for initial registration.
It includes the standard parameterized permissions and exact webhook event
subscriptions. Changing it does not update an existing App.

Verify these permissions in the GitHub App settings UI:

### Enterprise permissions

| Permission shown in GitHub | Access | Purpose |
|---|---|---|
| Enterprise teams | Read-only | Read the configured enterprise team's members |

Configure this enterprise permission in the App's enterprise settings UI in
addition to the organization/repository permissions in `app.yml`. No classic
PAT or additional service secret is needed. GitHub's
[App permission matrix](https://docs.github.com/en/enterprise-cloud@latest/rest/authentication/permissions-required-for-github-apps#enterprise-permissions-for-enterprise-teams)
lists installation-token access for the membership endpoint, and the
[Enterprise Teams App support announcement](https://github.blog/changelog/2026-02-09-github-apps-can-now-utilize-public-preview-enterprise-teams-apis-via-fine-grained-permissions/)
supersedes older PAT-only wording in the endpoint overview.

### Organization permissions

| Permission shown in GitHub | Access | Purpose |
|---|---|---|
| Organization dismissal requests for code scanning | Read & write | Receive/review code scanning dismissal requests |
| Organization dismissal requests for Dependabot | Read & write | Receive/review Dependabot dismissal requests |
| Secret scanning alert dismissal requests | Read & write | Receive/review secret scanning dismissal requests |

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

## Configure the service

[`config.yml`](config.yml) is loaded once when the Probot process starts:

```yaml
enterprise: your-enterprise
review_mode: both

required_pattern: "https://github\\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9._-]+/issues/\\d+"
minimum_length: 20
case_sensitive: false

alert_types:
  - code_scanning
  - dependabot
  - secret_scanning

agentic:
  workflow_repository: your-security-org/alert-triage
  appsec_team_slug: ent:appsec-team
  staged: true

cache:
  app_identity_ttl_seconds: 600
  enterprise_installation_ttl_seconds: 600
  team_members_ttl_seconds: 300
  control_installation_ttl_seconds: 600
  delivery_dedupe_ttl_seconds: 900
  delivery_dedupe_max_entries: 1000
```

`enterprise` is mandatory in every mode. The removed `organization` key is
rejected rather than ignored, even if `enterprise` is also set. The control
repository owner is never inferred as the monitored organization from
`GITHUB_REPOSITORY`.

Policies and one enterprise AppSec membership snapshot are shared across
organization installations. The default help contact is the enterprise team
mention `@/ent:appsec-team` (or `@/<configured-team-slug>`), using GitHub's
[enterprise team mention syntax](https://docs.github.com/en/enterprise-cloud@latest/admin/concepts/enterprise-fundamentals/teams-in-an-enterprise#what-can-enterprise-teams-do).
An explicit `help_contact` may point to a shared enterprise help desk.
Avoid hard-coded organization names in
shared regexes and denial templates. The example regex checks issue URL format
only; the agentic workflow fetches evidence from the target organization only,
not from other organizations in the same enterprise.

### Migration from organization-local teams

Remove `organization`, set `enterprise`, configure an `ent:` enterprise team,
and grant that team the enterprise Security Manager role. Install the App on
the enterprise with **Enterprise teams: read** and remove the previously
required organization **Members** permission if it is not used elsewhere.
Update the service and central workflow repository together, then restart the
service. Dispatches from the old version without `source.enterprise` or a
matching `review.appsec_team_slug` are rejected; replay the original signed
webhook to produce a fresh enterprise-team snapshot.

### Configuration reference

| Key | Default | Description |
|---|---|---|
| `enterprise` | required | Enterprise URL slug; accepts organization installations of an App owned by this enterprise |
| `review_mode` | `deterministic` | `deterministic`, `agentic`, or `both` |
| `required_phrase` | none | Phrase required in the requester comment |
| `required_pattern` | none | JavaScript regular expression required in the requester comment |
| `minimum_length` | none | Minimum trimmed requester-comment length |
| `case_sensitive` | `false` | Case-sensitive phrase and regex matching |
| `alert_types` | all three | Enabled alert categories; subscribed disabled types are ignored |
| `agentic.workflow_repository` | `CallMeGreg/agentic-alert-triage` | Central repository receiving schema-v1 dispatches |
| `agentic.appsec_team_slug` | `ent:appsec-team` | Enterprise team assumed to hold the enterprise Security Manager role; the `ent:` prefix is required |
| `agentic.staged` | `true` | Preview SafeOutput writes |
| `agentic.help_contact` | `@/ent:appsec-team` | Enterprise team mention included in agentic denials |
| `agentic.denial_message` | built-in | Optional agentic denial template |
| `denial_message` | built-in | Optional deterministic denial template |
| `cache.app_identity_ttl_seconds` | `600` | Verified enterprise App ownership cache TTL, 1-3600 seconds |
| `cache.enterprise_installation_ttl_seconds` | `600` | Process-local enterprise installation ID cache TTL, 1-3600 seconds |
| `cache.team_members_ttl_seconds` | `300` | Enterprise/team membership cache TTL shared across target organizations, 1-3600 seconds |
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

> [!TIP]
> See Probot's
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

The App must be installed on each monitored organization so
`actions/create-github-app-token` can mint the alert/evidence and decision
tokens. Both workflow phases authenticate the App before selecting the target
organization; `export-workflow-config.js` requires the App client ID and private
key in its step environment. The model never receives the App private key or
installation token.
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
- Enterprise team membership and enterprise/control installation IDs are cached
  for short configurable TTLs. Team entries are scoped by enterprise/team and
  shared across target organizations; delivery entries include the full
  repository name. Both installation caches are shared across organizations.
  Enterprise App ownership is cached separately with
  `cache.app_identity_ttl_seconds`.
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
failure propagation. Enterprise coverage includes two organizations with
identical repository names and alert numbers, shared enterprise membership with
isolated delivery caches, enterprise App ownership failures and expiry,
enterprise installation authentication, legacy configuration rejection,
token-owner export validation, and installation-ID mismatches.

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
