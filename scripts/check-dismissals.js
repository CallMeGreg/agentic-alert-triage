#!/usr/bin/env node
// scripts/check-dismissals.js
//
// Polls GitHub security alert APIs for recently dismissed alerts and
// automatically re-opens (denies) any dismissal whose comment does not meet
// the criteria defined in config.yml.
//
// Designed to run as a scheduled GitHub Actions workflow using a GitHub App
// token so that it operates under a named, auditable identity rather than a
// personal access token.

'use strict';

const { Octokit } = require('@octokit/rest');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function loadConfig() {
  const configPath =
    process.env.CONFIG_PATH ||
    path.join(process.cwd(), 'config.yml');

  if (!fs.existsSync(configPath)) {
    console.error(`[ERROR] Config file not found: ${configPath}`);
    process.exit(1);
  }

  return yaml.load(fs.readFileSync(configPath, 'utf8'));
}

const config = loadConfig();

const REQUIRED_PHRASE = config.required_phrase || 'mitigating control';
const DENY_BLANK = config.deny_blank_comments !== false;
const CASE_SENSITIVE = config.case_sensitive === true;
const POLLING_WINDOW_MINUTES =
  typeof config.polling_window_minutes === 'number'
    ? config.polling_window_minutes
    : 30;
const ALERT_TYPES = Array.isArray(config.alert_types)
  ? config.alert_types
  : ['code_scanning', 'secret_scanning', 'dependabot'];
const CREATE_DENIAL_ISSUES = config.create_denial_issues !== false;
const DENIAL_ISSUE_LABELS = Array.isArray(config.denial_issue_labels)
  ? config.denial_issue_labels
  : ['dismissal-denied'];
const DRY_RUN = process.env.DRY_RUN === 'true';

const SECONDS_PER_MINUTE = 60;
const MILLISECONDS_PER_SECOND = 1000;

// ---------------------------------------------------------------------------
// GitHub client
// ---------------------------------------------------------------------------

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

// ---------------------------------------------------------------------------
// Validation logic
// ---------------------------------------------------------------------------

/**
 * Checks whether a dismissal comment satisfies the configured criteria.
 *
 * @param {string|null|undefined} comment
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateDismissalComment(comment) {
  const trimmed = (comment || '').trim();

  if (DENY_BLANK && trimmed === '') {
    return {
      valid: false,
      reason: 'The dismissal comment was blank or empty.',
    };
  }

  const haystack = CASE_SENSITIVE ? trimmed : trimmed.toLowerCase();
  const needle = CASE_SENSITIVE
    ? REQUIRED_PHRASE
    : REQUIRED_PHRASE.toLowerCase();

  if (!haystack.includes(needle)) {
    return {
      valid: false,
      reason: `The dismissal comment did not include the required phrase: "${REQUIRED_PHRASE}"`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Denial message formatting
// ---------------------------------------------------------------------------

function getDefaultDenialTemplate() {
  return `## ⚠️ Alert Dismissal Request Denied

Your request to dismiss this **{alert_type}** alert (#{alert_number}) has been automatically denied because the dismissal comment does not meet the required criteria.

**Reason:** {denial_reason}

### Requirements

To have a dismissal request accepted, the comment must:

1. **Not be blank** — provide a meaningful justification.
2. **Include the phrase** \`{required_phrase}\` — this confirms that a mitigating control has been identified and documented.

Please re-dismiss the alert with an updated comment that satisfies both requirements.

---
*This action was performed automatically by the [Alert Dismissal Automation](https://github.com/{repo_full_name}) workflow.*`;
}

/**
 * Formats the denial notification body by substituting placeholders.
 *
 * @param {object} params
 * @returns {string}
 */
function formatDenialMessage({
  alertType,
  alertNumber,
  requester,
  denialReason,
  repoFullName,
}) {
  const template =
    config.denial_message && config.denial_message.trim()
      ? config.denial_message
      : getDefaultDenialTemplate();

  return template
    .replace(/{alert_type}/g, alertType.replace(/_/g, ' '))
    .replace(/{alert_number}/g, String(alertNumber))
    .replace(/{requester}/g, requester || 'unknown')
    .replace(/{required_phrase}/g, REQUIRED_PHRASE)
    .replace(/{denial_reason}/g, denialReason)
    .replace(/{repo_full_name}/g, repoFullName);
}

// ---------------------------------------------------------------------------
// Denial notifications (GitHub Issues)
// ---------------------------------------------------------------------------

/**
 * Creates a GitHub Issue to notify the team about a denied dismissal.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {object} params
 */
async function createDenialIssue(
  owner,
  repo,
  { alertType, alertNumber, alertUrl, requester, denialReason }
) {
  const repoFullName = `${owner}/${repo}`;
  const mentionLine = requester ? `@${requester} — ` : '';
  const body =
    mentionLine +
    formatDenialMessage({
      alertType,
      alertNumber,
      requester,
      denialReason,
      repoFullName,
    }) +
    `\n\n**Alert:** ${alertUrl}`;

  const title = `🚫 Alert Dismissal Denied: ${alertType.replace(/_/g, ' ')} alert #${alertNumber}`;

  if (DRY_RUN) {
    console.log(
      `  [DRY RUN] Would create issue: "${title}" in ${repoFullName}`
    );
    return;
  }

  try {
    const { data: issue } = await octokit.rest.issues.create({
      owner,
      repo,
      title,
      body,
      labels: DENIAL_ISSUE_LABELS,
    });
    console.log(
      `  📝 Created denial notification issue #${issue.number}: ${issue.html_url}`
    );
  } catch (error) {
    // Issues may be disabled in the repo — degrade gracefully.
    if (error.status === 410 || error.status === 403 || error.status === 404) {
      console.warn(
        `  ⚠️  Could not create issue in ${repoFullName} (HTTP ${error.status}): ${error.message}`
      );
    } else {
      throw error;
    }
  }
}

// ---------------------------------------------------------------------------
// Repository discovery
// ---------------------------------------------------------------------------

/**
 * Returns the list of {owner, name} pairs to monitor based on config.
 *
 * @returns {Promise<Array<{owner: string, name: string}>>}
 */
async function getReposToCheck() {
  if (config.repositories && config.repositories.length > 0) {
    return config.repositories.map((spec) => {
      const [owner, name] = spec.split('/');
      return { owner, name };
    });
  }

  if (config.organization) {
    console.log(
      `\n🔎 Discovering repositories for org: ${config.organization}`
    );
    const orgRepos = await octokit.paginate(
      octokit.rest.repos.listForOrg,
      { org: config.organization, type: 'all', per_page: 100 }
    );
    return orgRepos.map((r) => ({
      owner: config.organization,
      name: r.name,
    }));
  }

  // Fall back to the repository that is running this workflow.
  if (!process.env.GITHUB_REPOSITORY) {
    console.error(
      '[ERROR] GITHUB_REPOSITORY is not set and no repositories are configured in config.yml.'
    );
    process.exit(1);
  }
  const [owner, name] = process.env.GITHUB_REPOSITORY.split('/');
  return [{ owner, name }];
}

// ---------------------------------------------------------------------------
// Cut-off timestamp (shared across all checks in this run)
// ---------------------------------------------------------------------------

const cutoffTime = new Date(
  Date.now() -
    POLLING_WINDOW_MINUTES * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND
);

// ---------------------------------------------------------------------------
// Code Scanning
// ---------------------------------------------------------------------------

async function processCodeScanningAlerts(owner, repo) {
  console.log(`\n  🔍 Code scanning alerts…`);

  let alerts;
  try {
    alerts = await octokit.paginate(
      octokit.rest.codeScanning.listAlertsForRepo,
      { owner, repo, state: 'dismissed', per_page: 100 }
    );
  } catch (error) {
    if (error.status === 404) {
      console.log('     Code scanning not enabled — skipping.');
      return;
    }
    throw error;
  }

  const recent = alerts.filter(
    (a) => a.dismissed_at && new Date(a.dismissed_at) > cutoffTime
  );
  console.log(
    `     ${recent.length} dismissal(s) in the last ${POLLING_WINDOW_MINUTES} min.`
  );

  for (const alert of recent) {
    const result = validateDismissalComment(alert.dismissed_comment);
    if (result.valid) {
      console.log(
        `     ✅ Alert #${alert.number} — valid comment, keeping dismissed.`
      );
      continue;
    }

    console.log(
      `     ❌ Alert #${alert.number} — DENIED: ${result.reason}`
    );

    if (!DRY_RUN) {
      await octokit.rest.codeScanning.updateAlert({
        owner,
        repo,
        alert_number: alert.number,
        state: 'open',
      });
      console.log(`     🔓 Re-opened alert #${alert.number}.`);
    } else {
      console.log(`     [DRY RUN] Would re-open alert #${alert.number}.`);
    }

    if (CREATE_DENIAL_ISSUES) {
      await createDenialIssue(owner, repo, {
        alertType: 'code_scanning',
        alertNumber: alert.number,
        alertUrl: alert.html_url,
        requester: alert.dismissed_by?.login,
        denialReason: result.reason,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Secret Scanning
// ---------------------------------------------------------------------------

// These are the resolution values that represent a user-initiated dismissal
// (as opposed to automated revocations or pattern changes).
const SECRET_SCANNING_DISMISSAL_RESOLUTIONS = new Set([
  'false_positive',
  'wont_fix',
  'used_in_tests',
]);

async function processSecretScanningAlerts(owner, repo) {
  console.log(`\n  🔍 Secret scanning alerts…`);

  let alerts;
  try {
    alerts = await octokit.paginate(
      octokit.rest.secretScanning.listAlertsForRepo,
      { owner, repo, state: 'resolved', per_page: 100 }
    );
  } catch (error) {
    if (error.status === 404) {
      console.log('     Secret scanning not enabled — skipping.');
      return;
    }
    throw error;
  }

  const recent = alerts.filter(
    (a) =>
      a.resolved_at &&
      new Date(a.resolved_at) > cutoffTime &&
      SECRET_SCANNING_DISMISSAL_RESOLUTIONS.has(a.resolution)
  );
  console.log(
    `     ${recent.length} dismissal(s) in the last ${POLLING_WINDOW_MINUTES} min.`
  );

  for (const alert of recent) {
    const result = validateDismissalComment(alert.resolution_comment);
    if (result.valid) {
      console.log(
        `     ✅ Alert #${alert.number} — valid comment, keeping resolved.`
      );
      continue;
    }

    console.log(
      `     ❌ Alert #${alert.number} — DENIED: ${result.reason}`
    );

    if (!DRY_RUN) {
      await octokit.rest.secretScanning.updateAlert({
        owner,
        repo,
        alert_number: alert.number,
        state: 'open',
      });
      console.log(`     🔓 Re-opened alert #${alert.number}.`);
    } else {
      console.log(`     [DRY RUN] Would re-open alert #${alert.number}.`);
    }

    if (CREATE_DENIAL_ISSUES) {
      await createDenialIssue(owner, repo, {
        alertType: 'secret_scanning',
        alertNumber: alert.number,
        alertUrl: alert.html_url,
        requester: alert.resolved_by?.login,
        denialReason: result.reason,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Dependabot
// ---------------------------------------------------------------------------

async function processDependabotAlerts(owner, repo) {
  console.log(`\n  🔍 Dependabot alerts…`);

  let alerts;
  try {
    alerts = await octokit.paginate(
      octokit.rest.dependabot.listAlertsForRepo,
      { owner, repo, state: 'dismissed', per_page: 100 }
    );
  } catch (error) {
    if (error.status === 404) {
      console.log('     Dependabot not enabled — skipping.');
      return;
    }
    throw error;
  }

  const recent = alerts.filter(
    (a) => a.dismissed_at && new Date(a.dismissed_at) > cutoffTime
  );
  console.log(
    `     ${recent.length} dismissal(s) in the last ${POLLING_WINDOW_MINUTES} min.`
  );

  for (const alert of recent) {
    const result = validateDismissalComment(alert.dismissed_comment);
    if (result.valid) {
      console.log(
        `     ✅ Alert #${alert.number} — valid comment, keeping dismissed.`
      );
      continue;
    }

    console.log(
      `     ❌ Alert #${alert.number} — DENIED: ${result.reason}`
    );

    if (!DRY_RUN) {
      await octokit.rest.dependabot.updateAlert({
        owner,
        repo,
        alert_number: alert.number,
        state: 'open',
      });
      console.log(`     🔓 Re-opened alert #${alert.number}.`);
    } else {
      console.log(`     [DRY RUN] Would re-open alert #${alert.number}.`);
    }

    if (CREATE_DENIAL_ISSUES) {
      await createDenialIssue(owner, repo, {
        alertType: 'dependabot',
        alertNumber: alert.number,
        alertUrl: alert.html_url,
        requester: alert.dismissed_by?.login,
        denialReason: result.reason,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('🤖 Alert Dismissal Automation');
  console.log('================================');
  if (DRY_RUN) {
    console.log('⚠️  DRY RUN mode — no changes will be made.\n');
  }
  console.log('Configuration:');
  console.log(`  required_phrase     : "${REQUIRED_PHRASE}"`);
  console.log(`  deny_blank_comments : ${DENY_BLANK}`);
  console.log(`  case_sensitive      : ${CASE_SENSITIVE}`);
  console.log(`  alert_types         : ${ALERT_TYPES.join(', ')}`);
  console.log(`  polling_window      : ${POLLING_WINDOW_MINUTES} min`);
  console.log(`  create_denial_issues: ${CREATE_DENIAL_ISSUES}`);
  console.log(`  cutoff_time         : ${cutoffTime.toISOString()}`);

  const repos = await getReposToCheck();
  console.log(`\nMonitoring ${repos.length} repository/repositories…`);

  for (const { owner, name: repo } of repos) {
    console.log(`\n━━━ ${owner}/${repo} ━━━`);

    if (ALERT_TYPES.includes('code_scanning')) {
      await processCodeScanningAlerts(owner, repo);
    }
    if (ALERT_TYPES.includes('secret_scanning')) {
      await processSecretScanningAlerts(owner, repo);
    }
    if (ALERT_TYPES.includes('dependabot')) {
      await processDependabotAlerts(owner, repo);
    }
  }

  console.log('\n✅ Done.');
}

main().catch((error) => {
  console.error('\n[FATAL]', error.message || error);
  process.exit(1);
});

// Export helpers for unit tests.
module.exports = { validateDismissalComment, formatDenialMessage };
