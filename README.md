# Alert Dismissal Automation

A **GitHub Actions workflow** that automatically reviews GitHub security alert
dismissals and re-opens ("denies") any dismissal whose comment does not meet a
minimum quality bar.

The workflow runs on a configurable schedule (no webhooks required) and
authenticates via a **GitHub App** so that every action is attributed to a
named, auditable identity rather than a personal access token.

---

## How it works

```
┌─────────────┐    schedule     ┌──────────────────────────────┐
│  GitHub     │ ──────────────► │  Alert Dismissal Workflow     │
│  Actions    │                 │                              │
└─────────────┘                 │  1. Get GitHub App token     │
                                │  2. Load config.yml          │
                                │  3. Fetch recently dismissed │
                                │     alerts (code scanning,   │
                                │     secret scanning,         │
                                │     Dependabot)              │
                                │  4. Validate comment         │
                                │     ✅ contains phrase?      │
                                │     ✅ not blank?            │
                                │  5. If invalid:              │
                                │     • Re-open the alert      │
                                │     • Create denial issue    │
                                └──────────────────────────────┘
```

A dismissal is **denied** if the dismissal comment is:

* **Blank** (empty or whitespace-only), OR
* Does **not** contain the phrase `mitigating control`
  (configurable in `config.yml`)

When denied, the alert is automatically re-opened and a GitHub Issue is created
in the repository explaining why the dismissal was rejected.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **GitHub Advanced Security** | Required for code scanning and secret scanning. Dependabot works on all public repos and on private repos with a GitHub Advanced Security license. |
| **GitHub App** | Used for authentication. See [Create a GitHub App](#1-create-a-github-app) below. |
| **Node.js ≥ 20** | Used by the automation script. Provided automatically by `actions/setup-node` in the workflow. |
| **`dismissal-denied` label** | Must exist in every monitored repository before the workflow runs if `create_denial_issues: true` (default). See [Create the issue label](#4-create-the-issue-label). |

---

## Setup instructions

### 1. Create a GitHub App

1. Navigate to **Settings → Developer settings → GitHub Apps → New GitHub App**
   (or your organization's **Settings → Developer settings → GitHub Apps**).

2. Fill in the required fields:
   * **GitHub App name**: e.g. `Alert Dismissal Bot`
   * **Homepage URL**: URL of this repository
   * **Webhooks**: uncheck "Active" — this workflow does **not** use webhooks

3. Set the following **Repository permissions**:

   | Permission | Access |
   |---|---|
   | Code scanning alerts | Read & write |
   | Secret scanning alerts | Read & write |
   | Dependabot alerts | Read & write |
   | Issues | Read & write |
   | Contents | Read-only |
   | Metadata | Read-only *(required)* |

4. Under **Where can this GitHub App be installed?**, choose **Only on this
   account** or **Any account** depending on your needs.

5. Click **Create GitHub App**.

6. On the App's settings page:
   * Note the **App ID** (shown near the top).
   * Scroll to **Private keys** and click **Generate a private key**. Save the
     downloaded `.pem` file — you will need it in the next step.

7. Click **Install App** and install it on the repository (or organization)
   that this workflow will monitor.

---

### 2. Add repository secrets

In the repository that hosts this workflow, go to
**Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret name | Value |
|---|---|
| `APP_ID` | The numeric App ID from step 1.6 |
| `APP_PRIVATE_KEY` | The full contents of the `.pem` file, including the `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----` lines |

---

### 3. Configure the automation

Edit [`config.yml`](config.yml) in the root of this repository.  All settings
are documented inline.  The most important ones:

```yaml
# Phrase that must appear in every dismissal comment
required_phrase: "mitigating control"

# Deny blank dismissal comments
deny_blank_comments: true

# Alert types to monitor
alert_types:
  - code_scanning
  - secret_scanning
  - dependabot

# How far back to look on each run (should be ≥ schedule interval)
polling_window_minutes: 30
```

To monitor repositories other than the one hosting this workflow, uncomment
and populate one of these settings:

```yaml
# Monitor specific repositories
repositories:
  - my-org/repo-one
  - my-org/repo-two

# OR monitor all repositories in an organization
# organization: my-org
```

> **Note**: The GitHub App must be installed in every repository it needs to
> monitor.

---

### 4. Create the issue label

The workflow creates a GitHub Issue for each denied dismissal and applies the
label `dismissal-denied` (configurable via `denial_issue_labels` in
`config.yml`).

Create the label in each monitored repository before the workflow runs:

```bash
gh label create "dismissal-denied" \
  --description "Alert dismissal request was automatically denied" \
  --color "B60205" \
  --repo owner/repo
```

---

### 5. Adjust the schedule (optional)

The workflow runs every **15 minutes** by default.  To change this, edit the
`cron` expression in
[`.github/workflows/alert-dismissal-check.yml`](.github/workflows/alert-dismissal-check.yml):

```yaml
on:
  schedule:
    - cron: '*/15 * * * *'   # ← change this
```

Also update `polling_window_minutes` in `config.yml` to be at least as large
as the new interval (add a few minutes of buffer to avoid missing dismissals
between runs).

---

## Running manually / dry-run

Trigger the workflow from the **Actions** tab and choose `dry_run: true` to
see what the automation *would* do without making any changes.

To run locally:

```bash
export GITHUB_TOKEN=<github-app-installation-token>
export GITHUB_REPOSITORY=owner/repo

# Dry run
DRY_RUN=true node scripts/check-dismissals.js

# Live run
node scripts/check-dismissals.js
```

---

## File structure

```
.
├── .github/
│   ├── copilot-instructions.md   # Copilot workspace context
│   └── workflows/
│       └── alert-dismissal-check.yml  # Scheduled workflow
├── scripts/
│   └── check-dismissals.js       # Core automation script
├── config.yml                    # User-facing configuration
├── package.json
├── package-lock.json
└── README.md
```

---

## Customizing the denial message

Set `denial_message` in `config.yml` using Markdown.  Available placeholders:

| Placeholder | Replaced with |
|---|---|
| `{alert_type}` | e.g. `code scanning` |
| `{alert_number}` | Numeric alert ID |
| `{required_phrase}` | Value of `required_phrase` |
| `{denial_reason}` | Human-readable reason |
| `{requester}` | GitHub username of the person who dismissed |
| `{repo_full_name}` | `owner/repo` |

---

## Security considerations

* The GitHub App private key is stored as an encrypted repository secret and
  is never logged or exposed in workflow output.
* The App token generated during each run is short-lived (1 hour) and scoped
  to the installations the App has been granted.
* The workflow uses `permissions: contents: read` for the built-in
  `GITHUB_TOKEN`; all security-sensitive operations use the App token.
* Enable [branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
  on the default branch so that changes to `config.yml` and the workflow
  require review.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Workflow fails with `Resource not accessible` | App not installed in the target repo, or missing permission | Install the App and verify permissions |
| Alerts are not being checked | Alert type not in `alert_types`, or feature not enabled | Enable the feature in repo settings; check `config.yml` |
| Denial issues not created | Label does not exist | Create the `dismissal-denied` label |
| Same alert keeps getting denied | User keeps re-dismissing without a valid comment | Expected behaviour — the automation will continue to deny until a compliant comment is provided |
| 404 on alert endpoints | GitHub Advanced Security not enabled | Enable GHAS in the repository or organization settings |
