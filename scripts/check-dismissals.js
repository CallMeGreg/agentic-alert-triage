#!/usr/bin/env node
// scripts/check-dismissals.js
//
// Polls GitHub's alert dismissal request APIs for pending (open) dismissal
// requests and automatically denies any request whose comment does not meet
// the criteria defined in config.yml.
//
// Uses org-level listing endpoints to discover all pending requests across
// every repository in the organization, then calls the per-repo review
// endpoint to deny non-compliant ones.
//
// Requires delegated alert dismissal to be enabled on the organization.
// Designed to run as a scheduled GitHub Actions workflow using a GitHub App
// token so that all actions are attributed to a named, auditable identity.

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

const REQUIRED_PHRASE = config.required_phrase || null;
const REQUIRED_PATTERN = config.required_pattern || null;
const MINIMUM_LENGTH =
  Number.isFinite(config.minimum_length) && config.minimum_length > 0
    ? config.minimum_length
    : null;
const CASE_SENSITIVE = config.case_sensitive === true;
const ALERT_TYPES = Array.isArray(config.alert_types)
  ? config.alert_types
  : ['code_scanning', 'secret_scanning', 'dependabot'];
const DRY_RUN = process.env.DRY_RUN === 'true';

// All new dismissal request endpoints require this API version header.
const API_VERSION = '2026-03-10';

// Maximum length allowed by the dismissal request review API for the message body.
const MAX_DENIAL_MESSAGE_LENGTH = 2048;

// ---------------------------------------------------------------------------
// GitHub client
// ---------------------------------------------------------------------------

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

// ---------------------------------------------------------------------------
// Organization resolution
// ---------------------------------------------------------------------------

/**
 * Returns the GitHub organization name to monitor.
 * Falls back to the owner component of GITHUB_REPOSITORY when
 * config.organization is not set.
 *
 * @returns {string}
 */
function getOrg() {
  if (config.organization) return config.organization;

  if (process.env.GITHUB_REPOSITORY) {
    return process.env.GITHUB_REPOSITORY.split('/')[0];
  }

  console.error(
    '[ERROR] Cannot determine organization. ' +
      'Set "organization" in config.yml or run inside a GitHub Actions context.'
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Validation logic
// ---------------------------------------------------------------------------

/**
 * Checks whether a dismissal comment satisfies the configured criteria.
 *
 * Each check is only enforced when the corresponding configuration value is
 * set.  If none of the optional criteria are configured every comment is
 * considered valid.
 *
 * @param {string|null|undefined} comment
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateDismissalComment(comment) {
  const trimmed = (comment || '').trim();

  // 1. Minimum length --------------------------------------------------
  if (MINIMUM_LENGTH != null && trimmed.length < MINIMUM_LENGTH) {
    return {
      valid: false,
      reason: `The dismissal comment must be at least ${MINIMUM_LENGTH} characters long (found ${trimmed.length}).`,
    };
  }

  // 2. Required phrase --------------------------------------------------
  if (REQUIRED_PHRASE) {
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
  }

  // 3. Required pattern (regex) -----------------------------------------
  if (REQUIRED_PATTERN) {
    const flags = CASE_SENSITIVE ? '' : 'i';
    const regex = new RegExp(REQUIRED_PATTERN, flags);
    if (!regex.test(trimmed)) {
      return {
        valid: false,
        reason: `The dismissal comment did not match the required pattern: "${REQUIRED_PATTERN}"`,
      };
    }
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

Please re-submit a dismissal request with an updated comment that satisfies the requirements.

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
    .replace(/{required_phrase}/g, REQUIRED_PHRASE || '')
    .replace(/{denial_reason}/g, denialReason)
    .replace(/{repo_full_name}/g, repoFullName);
}

// ---------------------------------------------------------------------------
// Dismissal request review (deny)
// ---------------------------------------------------------------------------

/**
 * Calls the review endpoint to deny a dismissal request.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} alertType  — 'code-scanning' | 'secret-scanning' | 'dependabot'
 * @param {number} alertNumber
 * @param {string} message    — reason for denial (≤ 2048 chars)
 */
async function denyDismissalRequest(owner, repo, alertType, alertNumber, message) {
  const truncatedMessage =
    message.length > MAX_DENIAL_MESSAGE_LENGTH
      ? message.slice(0, MAX_DENIAL_MESSAGE_LENGTH - 3) + '...'
      : message;

  await octokit.request(
    `PATCH /repos/{owner}/{repo}/dismissal-requests/${alertType}/{alert_number}`,
    {
      owner,
      repo,
      alert_number: alertNumber,
      status: 'deny',
      message: truncatedMessage,
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
}

// ---------------------------------------------------------------------------
// Code Scanning dismissal requests
// ---------------------------------------------------------------------------

async function processCodeScanningRequests(org) {
  console.log(`\n  🔍 Code scanning dismissal requests…`);

  let requests;
  try {
    requests = await octokit.paginate(
      'GET /orgs/{org}/dismissal-requests/code-scanning',
      {
        org,
        request_status: 'open',
        per_page: 100,
        headers: { 'X-GitHub-Api-Version': API_VERSION },
      }
    );
  } catch (error) {
    if (error.status === 404 || error.status === 403) {
      console.log(
        `     Code scanning dismissal requests not available (HTTP ${error.status}) — skipping.`
      );
      return;
    }
    throw error;
  }

  console.log(`     ${requests.length} open request(s) found.`);

  for (const req of requests) {
    const repoFullName = req.repository.full_name;
    const [owner, repo] = repoFullName.split('/');
    // For code scanning dismissal requests, data[0].alert_number holds the
    // alert number.  Fall back to resource_identifier if data is unavailable.
    const alertNumber = Number(
      (req.data && req.data[0] && req.data[0].alert_number != null)
        ? req.data[0].alert_number
        : req.resource_identifier
    );
    const requester = req.requester?.actor_name;

    const result = validateDismissalComment(req.requester_comment);

    if (result.valid) {
      console.log(
        `     ✅ Request #${req.number} (${repoFullName} alert #${alertNumber}) — valid comment, leaving open for human review.`
      );
      continue;
    }

    console.log(
      `     ❌ Request #${req.number} (${repoFullName} alert #${alertNumber}) — DENIED: ${result.reason}`
    );

    const denialMessage = formatDenialMessage({
      alertType: 'code_scanning',
      alertNumber,
      requester,
      denialReason: result.reason,
      repoFullName,
    });

    if (!DRY_RUN) {
      await denyDismissalRequest(owner, repo, 'code-scanning', alertNumber, denialMessage);
      console.log(`     🚫 Denied dismissal request #${req.number}.`);
    } else {
      console.log(`     [DRY RUN] Would deny dismissal request #${req.number}.`);
    }
  }
}

// ---------------------------------------------------------------------------
// Secret Scanning dismissal requests
// ---------------------------------------------------------------------------

async function processSecretScanningRequests(org) {
  console.log(`\n  🔍 Secret scanning dismissal requests…`);

  let requests;
  try {
    requests = await octokit.paginate(
      'GET /orgs/{org}/dismissal-requests/secret-scanning',
      {
        org,
        request_status: 'open',
        per_page: 100,
        headers: { 'X-GitHub-Api-Version': API_VERSION },
      }
    );
  } catch (error) {
    if (error.status === 404 || error.status === 403) {
      console.log(
        `     Secret scanning dismissal requests not available (HTTP ${error.status}) — skipping.`
      );
      return;
    }
    throw error;
  }

  console.log(`     ${requests.length} open request(s) found.`);

  for (const req of requests) {
    const repoFullName = req.repository.full_name;
    const [owner, repo] = repoFullName.split('/');
    // For secret scanning dismissal requests, resource_identifier is the
    // numeric alert number (unlike code scanning where it is "repo_id/alert").
    const alertNumber = Number(req.resource_identifier);
    const requester = req.requester?.actor_name;

    const result = validateDismissalComment(req.requester_comment);

    if (result.valid) {
      console.log(
        `     ✅ Request #${req.number} (${repoFullName} alert #${alertNumber}) — valid comment, leaving open for human review.`
      );
      continue;
    }

    console.log(
      `     ❌ Request #${req.number} (${repoFullName} alert #${alertNumber}) — DENIED: ${result.reason}`
    );

    const denialMessage = formatDenialMessage({
      alertType: 'secret_scanning',
      alertNumber,
      requester,
      denialReason: result.reason,
      repoFullName,
    });

    if (!DRY_RUN) {
      await denyDismissalRequest(owner, repo, 'secret-scanning', alertNumber, denialMessage);
      console.log(`     🚫 Denied dismissal request #${req.number}.`);
    } else {
      console.log(`     [DRY RUN] Would deny dismissal request #${req.number}.`);
    }
  }
}

// ---------------------------------------------------------------------------
// Dependabot dismissal requests
// ---------------------------------------------------------------------------

async function processDependabotRequests(org) {
  console.log(`\n  🔍 Dependabot dismissal requests…`);

  let requests;
  try {
    requests = await octokit.paginate(
      'GET /orgs/{org}/dismissal-requests/dependabot',
      {
        org,
        request_status: 'open',
        per_page: 100,
        headers: { 'X-GitHub-Api-Version': API_VERSION },
      }
    );
  } catch (error) {
    if (error.status === 404 || error.status === 403) {
      console.log(
        `     Dependabot dismissal requests not available (HTTP ${error.status}) — skipping.`
      );
      return;
    }
    throw error;
  }

  console.log(`     ${requests.length} open request(s) found.`);

  for (const req of requests) {
    const repoFullName = req.repository.full_name;
    const [owner, repo] = repoFullName.split('/');
    // For Dependabot dismissal requests, resource_identifier is the alert
    // number as a numeric string (unlike code scanning where it is "repo_id/alert").
    const alertNumber = Number(req.resource_identifier);
    const requester = req.requester?.actor_name;

    const result = validateDismissalComment(req.requester_comment);

    if (result.valid) {
      console.log(
        `     ✅ Request #${req.number} (${repoFullName} alert #${alertNumber}) — valid comment, leaving open for human review.`
      );
      continue;
    }

    console.log(
      `     ❌ Request #${req.number} (${repoFullName} alert #${alertNumber}) — DENIED: ${result.reason}`
    );

    const denialMessage = formatDenialMessage({
      alertType: 'dependabot',
      alertNumber,
      requester,
      denialReason: result.reason,
      repoFullName,
    });

    if (!DRY_RUN) {
      await denyDismissalRequest(owner, repo, 'dependabot', alertNumber, denialMessage);
      console.log(`     🚫 Denied dismissal request #${req.number}.`);
    } else {
      console.log(`     [DRY RUN] Would deny dismissal request #${req.number}.`);
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

  const org = getOrg();

  console.log('Configuration:');
  console.log(`  organization        : ${org}`);
  console.log(`  required_phrase     : ${REQUIRED_PHRASE ? `"${REQUIRED_PHRASE}"` : '(not set)'}`);
  console.log(`  required_pattern    : ${REQUIRED_PATTERN ? `"${REQUIRED_PATTERN}"` : '(not set)'}`);
  console.log(`  minimum_length      : ${MINIMUM_LENGTH != null ? MINIMUM_LENGTH : '(not set)'}`);
  console.log(`  case_sensitive      : ${CASE_SENSITIVE}`);
  console.log(`  alert_types         : ${ALERT_TYPES.join(', ')}`);

  console.log(`\nChecking open dismissal requests for org: ${org}…`);

  if (ALERT_TYPES.includes('code_scanning')) {
    await processCodeScanningRequests(org);
  }
  if (ALERT_TYPES.includes('secret_scanning')) {
    await processSecretScanningRequests(org);
  }
  if (ALERT_TYPES.includes('dependabot')) {
    await processDependabotRequests(org);
  }

  console.log('\n✅ Done.');
}

main().catch((error) => {
  console.error('\n[FATAL]', error.message || error);
  process.exit(1);
});

// Export helpers for unit tests.
module.exports = { validateDismissalComment, formatDenialMessage };

