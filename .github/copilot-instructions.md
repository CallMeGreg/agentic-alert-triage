# Copilot Instructions — Alert Dismissal Automation

## Purpose

This repository implements a **GitHub Actions workflow** that automatically
reviews GitHub security alert dismissals and re-opens ("denies") any dismissal
whose comment does not meet a minimum quality bar.  It is intentionally
**poll-based** (no webhooks) and authenticates via a **GitHub App** so that
actions are attributed to a named, auditable identity.

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
| **Re-open = deny** | There is no separate "deny dismissal" API — re-opening the alert is the functional equivalent. |

---

## How the script works (`scripts/check-dismissals.js`)

1. Loads `config.yml` (or the path in `CONFIG_PATH` env var).
2. Determines which repositories to check (current repo, explicit list, or all
   repos in an org — configured in `config.yml`).
3. For each repository, iterates over the enabled alert types
   (`code_scanning`, `secret_scanning`, `dependabot`).
4. Fetches **dismissed** (or resolved) alerts whose timestamp falls within
   the `polling_window_minutes` window.
5. For each recent dismissal, calls `validateDismissalComment()`:
   - Denies blank comments if `deny_blank_comments: true`.
   - Denies comments that do not contain `required_phrase`
     (case-insensitive by default).
6. If invalid:
   - **Re-opens the alert** via the appropriate GitHub REST API endpoint.
   - Optionally **creates a GitHub Issue** explaining why the dismissal was
     denied and @-mentioning the person who dismissed it.
7. If valid: leaves the alert in its dismissed/resolved state.

### Exported helpers (used in tests)

```js
const { validateDismissalComment, formatDenialMessage } = require('./scripts/check-dismissals');
```

---

## Configuration reference (`config.yml`)

| Key | Type | Default | Description |
|---|---|---|---|
| `required_phrase` | string | `"mitigating control"` | Phrase that must appear in every dismissal comment. |
| `deny_blank_comments` | bool | `true` | Deny blank or whitespace-only comments. |
| `case_sensitive` | bool | `false` | Whether the phrase check is case-sensitive. |
| `alert_types` | list | `[code_scanning, secret_scanning, dependabot]` | Alert categories to monitor. |
| `repositories` | list | *(current repo)* | Explicit list of `owner/repo` strings to monitor. |
| `organization` | string | *(none)* | Monitor all repos in this org. |
| `polling_window_minutes` | int | `30` | How far back to look for dismissals on each run. |
| `create_denial_issues` | bool | `true` | Create a GitHub Issue for each denial. |
| `denial_issue_labels` | list | `[dismissal-denied]` | Labels applied to denial issues. |
| `denial_message` | string | *(built-in template)* | Custom Markdown template for denial issues. |

Template placeholders for `denial_message`:
`{alert_type}`, `{alert_number}`, `{required_phrase}`, `{denial_reason}`,
`{requester}`, `{repo_full_name}`.

---

## GitHub App permissions required

| Permission | Level | Used for |
|---|---|---|
| Code scanning alerts | Read & write | List and re-open code scanning alerts |
| Secret scanning alerts | Read & write | List and re-open secret scanning alerts |
| Dependabot alerts | Read & write | List and re-open Dependabot alerts |
| Issues | Write | Create denial notification issues |
| Contents | Read | Read `config.yml` from the repository |
| Metadata | Read | *(required by all GitHub Apps)* |

---

## Workflow secrets required

| Secret | Description |
|---|---|
| `APP_ID` | Numeric GitHub App ID |
| `APP_PRIVATE_KEY` | GitHub App private key (full PEM content, including headers) |

---

## Extending the automation

- **Add a new alert type**: implement a `processXyzAlerts(owner, repo)` function
  mirroring the existing ones, add `'xyz'` to the `alert_types` list in
  `config.yml`, and call the new function in `main()`.
- **Change denial behaviour**: edit `validateDismissalComment()` in
  `scripts/check-dismissals.js`.
- **Customize the denial message**: set `denial_message` in `config.yml` using
  the supported placeholders.
- **Change the schedule**: edit the `cron` value in
  `.github/workflows/alert-dismissal-check.yml` and update
  `polling_window_minutes` in `config.yml` to match.

---

## Running locally / dry-run

```bash
# Set credentials
export GITHUB_TOKEN=<installation-token>
export GITHUB_REPOSITORY=owner/repo

# Dry run (no changes)
DRY_RUN=true node scripts/check-dismissals.js

# Live run
node scripts/check-dismissals.js
```

You can also trigger the workflow manually from the **Actions** tab and select
`dry_run: true`.
