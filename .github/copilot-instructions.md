# Copilot Instructions — Alert Dismissal Automation

## Purpose

This repository implements a **GitHub Actions workflow** that automatically
reviews pending GitHub security alert dismissal requests and denies any request
whose comment does not meet a minimum quality bar.  It is intentionally
**poll-based** (no webhooks) and authenticates via a **GitHub App** so that
actions are attributed to a named, auditable identity.

Requires **delegated alert dismissal** to be enabled in the GitHub organization.

---

## Repository layout

```
.
├── .github/
│   ├── copilot-instructions.md   ← you are here
│   └── workflows/
│       └── alert-dismissal-check.yml  ← scheduled GitHub Actions workflow
├── scripts/
│   └── check-dismissals.js       ← core Node.js automation script
├── config.yml                    ← user-facing configuration (edit this)
├── package.json
├── package-lock.json
└── README.md
```

---

## Key design decisions

| Decision | Rationale |
|---|---|
| **Polling, not webhooks** | Simpler operational requirements — no public endpoint or ngrok needed. |
| **GitHub App token** | Actions are attributed to a named bot identity, not a PAT. |
| **config.yml** | All behaviour is driven by a single, well-commented YAML file — no workflow edits needed for routine changes. |
| **GitHub Issues for notifications** | Issues are the most visible, actionable channel available without webhooks; they also create an audit trail. |
| **Dismiss request API, not alert update** | The dedicated dismissal request review API (`/dismissal-requests/*`) is used to deny requests rather than re-opening the alert directly. |
| **Org-level listing** | All pending dismissal requests across the organization are fetched from a single org-level endpoint, avoiding the need to enumerate repositories. |

---

## How the script works (`scripts/check-dismissals.js`)

1. Loads `config.yml` (or the path in `CONFIG_PATH` env var).
2. Determines the organization to check (`config.organization` or the owner
   part of `GITHUB_REPOSITORY`).
3. For each enabled alert type (`code_scanning`, `secret_scanning`,
   `dependabot`), calls the **org-level** dismissal request listing endpoint
   with `request_status=open` to fetch all pending requests.
4. For each pending request, calls `validateDismissalComment()` on the
   `requester_comment` field:
   - Denies blank comments if `deny_blank_comments: true`.
   - Denies comments that do not contain `required_phrase`
     (case-insensitive by default).
5. If invalid:
   - **Denies the dismissal request** via the per-repo review endpoint
     (`PATCH /repos/{owner}/{repo}/dismissal-requests/{type}/{alert_number}`)
     with `{ status: "deny", message: "<reason>" }`.
   - Optionally **creates a GitHub Issue** explaining why the request was
     denied and @-mentioning the requester.
6. If valid: leaves the request open for a human reviewer to approve.

### API version

All dismissal request endpoints require the header:
```
X-GitHub-Api-Version: 2026-03-10
```
These endpoints are not yet in the `@octokit/rest` typed methods, so
`octokit.request()` is used with the version header passed explicitly.

### Exported helpers (used in tests)

```js
const { validateDismissalComment, formatDenialMessage } = require('./scripts/check-dismissals');
```

---

## Configuration reference (`config.yml`)

| Key | Type | Default | Description |
|---|---|---|---|
| `required_phrase` | string | `"mitigating control"` | Phrase that must appear in every dismissal request comment. |
| `deny_blank_comments` | bool | `true` | Deny blank or whitespace-only comments. |
| `case_sensitive` | bool | `false` | Whether the phrase check is case-sensitive. |
| `alert_types` | list | `[code_scanning, secret_scanning, dependabot]` | Alert categories to monitor. |
| `organization` | string | *(owner of GITHUB_REPOSITORY)* | GitHub organization to monitor. |
| `create_denial_issues` | bool | `true` | Create a GitHub Issue for each denial. |
| `denial_issue_labels` | list | `[dismissal-denied]` | Labels applied to denial issues. |
| `denial_message` | string | *(built-in template)* | Custom Markdown template for denial issues. |

Template placeholders for `denial_message`:
`{alert_type}`, `{alert_number}`, `{required_phrase}`, `{denial_reason}`,
`{requester}`, `{repo_full_name}`.

---

## GitHub App permissions required

### Organization permissions

| Permission | Level | Used for |
|---|---|---|
| Organization dismissal requests for code scanning | Read & write | List and deny code scanning dismissal requests |
| Organization dismissal requests for Dependabot | Read & write | List and deny Dependabot dismissal requests |
| Secret scanning alert dismissal requests | Read & write | List and deny secret scanning dismissal requests |

### Repository permissions

| Permission | Level | Used for |
|---|---|---|
| Secret scanning alerts | Read-only | Required by secret scanning dismissal request endpoints |
| Contents | Read-only | Read `config.yml` from the repository |
| Issues | Read & write | Create denial notification issues |
| Metadata | Read-only | *(required by all GitHub Apps)* |

---

## Workflow secrets required

| Secret | Description |
|---|---|
| `ALERT_DISMISSAL_APP_ID` | Numeric GitHub App ID |
| `ALERT_DISMISSAL_APP_PRIVATE_KEY` | GitHub App private key (full PEM content, including headers) |

---

## Extending the automation

- **Add a new alert type**: implement a `processXyzRequests(org)` function
  mirroring the existing ones, add `'xyz'` to the `alert_types` list in
  `config.yml`, and call the new function in `main()`.
- **Change denial behaviour**: edit `validateDismissalComment()` in
  `scripts/check-dismissals.js`.
- **Customize the denial message**: set `denial_message` in `config.yml` using
  the supported placeholders.
- **Change the schedule**: edit the `cron` value in
  `.github/workflows/alert-dismissal-check.yml`.

---

## Running locally / dry-run

```bash
# Set credentials
export GITHUB_TOKEN=<installation-token>
export GITHUB_REPOSITORY=my-org/this-repo

# Dry run (no changes)
DRY_RUN=true node scripts/check-dismissals.js

# Live run
node scripts/check-dismissals.js
```

You can also trigger the workflow manually from the **Actions** tab and select
`dry_run: true`.
