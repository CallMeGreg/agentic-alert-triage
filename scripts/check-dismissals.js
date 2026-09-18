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
const {
  API_VERSION,
  buildDispatchPayload,
  denyDismissalRequest,
  dispatchAgenticReview,
  extractAlertNumber,
  getAgenticSettings,
  getAlert,
  getOrganization,
  isAssignedToTeam,
  listTeamMembers,
  loadConfig,
} = require('./agentic-review');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const config = loadConfig();
const agenticSettings = getAgenticSettings(config);

const REQUIRED_PHRASE = config.required_phrase ?? null;
const REQUIRED_PATTERN = config.required_pattern ?? null;
const MINIMUM_LENGTH =
  Number.isFinite(config.minimum_length) && config.minimum_length > 0
    ? config.minimum_length
    : null;
const CASE_SENSITIVE = config.case_sensitive === true;
const ALERT_TYPES = Array.isArray(config.alert_types)
  ? config.alert_types
  : ['code_scanning', 'secret_scanning', 'dependabot'];
const REVIEW_MODE = agenticSettings.reviewMode;
const DRY_RUN = process.env.DRY_RUN === 'true';
const DEBUG = process.env.DEBUG === 'true';

// ---------------------------------------------------------------------------
// Debug helper
// ---------------------------------------------------------------------------

function debug(...args) {
  if (DEBUG) console.log('[DEBUG]', ...args);
}

// ---------------------------------------------------------------------------
// GitHub client
// ---------------------------------------------------------------------------

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

/**
 * Log details about the authenticated token — scopes, identity, etc.
 * Only runs when DEBUG=true.
 */
async function debugAuth() {
  if (!DEBUG) return;

  const token = process.env.GITHUB_TOKEN;
  debug(`GITHUB_TOKEN present: ${!!token}`);
  debug(`GITHUB_TOKEN length : ${token ? token.length : 0}`);
  debug(`GITHUB_REPOSITORY   : ${process.env.GITHUB_REPOSITORY || '(not set)'}`);
  debug(`DRY_RUN             : ${DRY_RUN}`);

  try {
    // Check who we are authenticated as
    const { data, headers } = await octokit.request('GET /meta', {
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    });
    debug('GET /meta succeeded — API is reachable');
    debug(`  x-github-request-id  : ${headers['x-github-request-id'] || '(none)'}`);
    debug(`  x-oauth-scopes       : ${headers['x-oauth-scopes'] || '(none — likely app token)'}`);
  } catch (e) {
    debug(`GET /meta failed: ${e.status} ${e.message}`);
  }

  try {
    const { data } = await octokit.request('GET /app', {
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    });
    debug(`Authenticated as GitHub App: "${data.name}" (id: ${data.id})`);
  } catch (e) {
    debug(`GET /app failed (may not be an app token): ${e.status} ${e.message}`);
  }

  try {
    const { data } = await octokit.request('GET /installation/repositories', {
      per_page: 5,
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    });
    debug(`Installation has access to ${data.total_count} repo(s). First few:`);
    for (const r of data.repositories) {
      debug(`  - ${r.full_name} (permissions: ${JSON.stringify(r.permissions)})`);
    }
  } catch (e) {
    debug(`GET /installation/repositories failed: ${e.status} ${e.message}`);
  }
}

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
  return agenticSettings.organization || getOrganization(config);
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
 * @param {object} [overrides]
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateDismissalComment(comment, overrides = {}) {
  const requiredPhrase = Object.hasOwn(overrides, 'requiredPhrase')
    ? overrides.requiredPhrase
    : REQUIRED_PHRASE;
  const requiredPattern = Object.hasOwn(overrides, 'requiredPattern')
    ? overrides.requiredPattern
    : REQUIRED_PATTERN;
  const minimumLength = Object.hasOwn(overrides, 'minimumLength')
    ? overrides.minimumLength
    : MINIMUM_LENGTH;
  const caseSensitive = Object.hasOwn(overrides, 'caseSensitive')
    ? overrides.caseSensitive
    : CASE_SENSITIVE;
  const trimmed = (comment || '').trim();

  // 1. Minimum length --------------------------------------------------
  if (minimumLength != null && trimmed.length < minimumLength) {
    return {
      valid: false,
      reason: `The dismissal comment must be at least ${minimumLength} characters long (found ${trimmed.length}).`,
    };
  }

  // 2. Required phrase --------------------------------------------------
  if (requiredPhrase) {
    const haystack = caseSensitive ? trimmed : trimmed.toLowerCase();
    const needle = caseSensitive
      ? requiredPhrase
      : requiredPhrase.toLowerCase();

    if (!haystack.includes(needle)) {
      return {
        valid: false,
        reason: `The dismissal comment did not include the required phrase: "${requiredPhrase}"`,
      };
    }
  }

  // 3. Required pattern (regex) -----------------------------------------
  if (requiredPattern) {
    const flags = caseSensitive ? '' : 'i';
    let regex;
    try {
      regex = new RegExp(requiredPattern, flags);
    } catch (e) {
      return {
        valid: false,
        reason: `The configured required_pattern is not a valid regular expression: ${e.message}`,
      };
    }
    if (!regex.test(trimmed)) {
      return {
        valid: false,
        reason: `The dismissal comment did not match the required pattern: "${requiredPattern}"`,
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
}, templateConfig = config) {
  const template =
    templateConfig.denial_message && templateConfig.denial_message.trim()
      ? templateConfig.denial_message
      : getDefaultDenialTemplate();

  return template
    .replace(/{alert_type}/g, alertType.replace(/_/g, ' '))
    .replace(/{alert_number}/g, String(alertNumber))
    .replace(/{requester}/g, requester || 'unknown')
    .replace(
      /{required_phrase}/g,
      templateConfig.required_phrase || REQUIRED_PHRASE || ''
    )
    .replace(/{denial_reason}/g, denialReason)
    .replace(/{repo_full_name}/g, repoFullName);
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

let appSecTeamLoginsPromise;

async function getAppSecTeamLogins() {
  if (!appSecTeamLoginsPromise) {
    appSecTeamLoginsPromise = listTeamMembers(
      octokit,
      agenticSettings.organization,
      agenticSettings.teamSlug
    ).then((members) => members.map((member) => member.login));
  }
  return appSecTeamLoginsPromise;
}

async function processDismissalRequest(req, alertType) {
  const repoFullName = req.repository.full_name;
  const [owner, repo] = repoFullName.split('/');
  const alertNumber = extractAlertNumber(alertType, req);
  const requester = req.requester?.actor_name;

  if (!Number.isInteger(alertNumber) || alertNumber <= 0) {
    throw new Error(
      `Could not determine the alert number for dismissal request #${req.number} (${repoFullName}, ${alertType}).`
    );
  }

  if (REVIEW_MODE !== 'agentic') {
    const result = validateDismissalComment(req.requester_comment);

    if (!result.valid) {
      console.log(
        `     ❌ Request #${req.number} (${repoFullName} alert #${alertNumber}) — DENIED: ${result.reason}`
      );

      const denialMessage = formatDenialMessage({
        alertType,
        alertNumber,
        requester,
        denialReason: result.reason,
        repoFullName,
      });

      if (!DRY_RUN) {
        await denyDismissalRequest(
          octokit,
          owner,
          repo,
          alertType,
          alertNumber,
          denialMessage
        );
        console.log(`     🚫 Denied dismissal request #${req.number}.`);
      } else {
        console.log(`     [DRY RUN] Would deny dismissal request #${req.number}.`);
      }
      return;
    }

    if (REVIEW_MODE === 'deterministic') {
      console.log(
        `     ✅ Request #${req.number} (${repoFullName} alert #${alertNumber}) — valid comment, leaving open for human review.`
      );
      return;
    }
  }

  const [alert, teamLogins] = await Promise.all([
    getAlert(octokit, owner, repo, alertType, alertNumber),
    getAppSecTeamLogins(),
  ]);
  if (isAssignedToTeam(alertType, alert, teamLogins)) {
    console.log(
      `     ⏭️  Request #${req.number} (${repoFullName} alert #${alertNumber}) — already assigned to @${agenticSettings.organization}/${agenticSettings.teamSlug}.`
    );
    return;
  }

  const payload = buildDispatchPayload({
    organization: agenticSettings.organization,
    sourceRepository:
      process.env.GITHUB_REPOSITORY || agenticSettings.workflowRepository,
    repository: repoFullName,
    alertType,
    alertNumber,
    dismissalRequest: req,
    teamLogins,
    dryRun: DRY_RUN,
    runId: process.env.GITHUB_RUN_ID || null,
  });

  if (DRY_RUN) {
    console.log(
      `     [DRY RUN] Would dispatch agentic review for request #${req.number} (${repoFullName} alert #${alertNumber}).`
    );
    return;
  }

  await dispatchAgenticReview(
    octokit,
    agenticSettings.workflowRepository,
    payload
  );
  console.log(
    `     🤖 Dispatched agentic review for request #${req.number} (${repoFullName} alert #${alertNumber}).`
  );
}

// ---------------------------------------------------------------------------
// Code Scanning dismissal requests
// ---------------------------------------------------------------------------

async function processCodeScanningRequests(org) {
  console.log(`\n  🔍 Code scanning dismissal requests…`);

  const endpoint = 'GET /orgs/{org}/dismissal-requests/code-scanning';
  const params = {
    org,
    request_status: 'open',
    per_page: 100,
    headers: { 'X-GitHub-Api-Version': API_VERSION },
  };

  debug(`Code scanning — endpoint: ${endpoint}`);
  debug(`Code scanning — params: ${JSON.stringify({ org, request_status: 'open', per_page: 100, apiVersion: API_VERSION })}`);

  let requests;
  try {
    // When DEBUG is on, make a single non-paginated request first to inspect
    // the raw response (status, headers, body structure).
    if (DEBUG) {
      try {
        const raw = await octokit.request(endpoint, params);
        debug(`Code scanning — raw response status: ${raw.status}`);
        debug(`Code scanning — response headers:`);
        debug(`  x-github-request-id : ${raw.headers['x-github-request-id'] || '(none)'}`);
        debug(`  link                : ${raw.headers['link'] || '(none — no pagination)'}`);
        debug(`  x-github-api-version-selected: ${raw.headers['x-github-api-version-selected'] || '(none)'}`);
        debug(`Code scanning — raw data type: ${typeof raw.data}, isArray: ${Array.isArray(raw.data)}`);
        debug(`Code scanning — raw data length: ${Array.isArray(raw.data) ? raw.data.length : 'N/A'}`);
        if (Array.isArray(raw.data) && raw.data.length > 0) {
          debug(`Code scanning — first item keys: ${Object.keys(raw.data[0]).join(', ')}`);
          debug(
            `Code scanning — first item summary: ${JSON.stringify({
              id: raw.data[0].id,
              number: raw.data[0].number,
              status: raw.data[0].status,
              repository: raw.data[0].repository?.full_name,
            })}`
          );
        } else if (raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) {
          debug(`Code scanning — response is object, not array. Keys: ${Object.keys(raw.data).join(', ')}`);
        } else {
          debug(`Code scanning — response body is empty or unexpected: ${JSON.stringify(raw.data)}`);
        }
      } catch (debugErr) {
        debug(`Code scanning — raw request failed: ${debugErr.status} ${debugErr.message}`);
        if (debugErr.response) {
          debug(
            `Code scanning — error response: ${JSON.stringify({
              message: debugErr.response.data?.message,
              documentation_url: debugErr.response.data?.documentation_url,
              request_id: debugErr.response.headers?.['x-github-request-id'],
            })}`
          );
        }
      }
    }

    requests = await octokit.paginate(endpoint, params);
    debug(`Code scanning — paginate returned ${requests.length} item(s)`);
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
    await processDismissalRequest(req, 'code_scanning');
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
    await processDismissalRequest(req, 'secret_scanning');
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
    await processDismissalRequest(req, 'dependabot');
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
  if (DEBUG) {
    console.log('🐛 DEBUG mode enabled — verbose logging active.\n');
  }

  await debugAuth();

  const org = getOrg();

  console.log('Configuration:');
  console.log(`  organization        : ${org}`);
  console.log(`  required_phrase     : ${REQUIRED_PHRASE ? `"${REQUIRED_PHRASE}"` : '(not set)'}`);
  console.log(`  required_pattern    : ${REQUIRED_PATTERN ? `"${REQUIRED_PATTERN}"` : '(not set)'}`);
  console.log(`  minimum_length      : ${MINIMUM_LENGTH != null ? MINIMUM_LENGTH : '(not set)'}`);
  console.log(`  case_sensitive      : ${CASE_SENSITIVE}`);
  console.log(`  alert_types         : ${ALERT_TYPES.join(', ')}`);
  console.log(`  review_mode         : ${REVIEW_MODE}`);
  if (REVIEW_MODE === 'agentic' || REVIEW_MODE === 'both') {
    console.log(
      `  agentic_workflow    : ${agenticSettings.workflowRepository}`
    );
    console.log(
      `  appsec_team         : @${agenticSettings.organization}/${agenticSettings.teamSlug}`
    );
    console.log(`  agentic_staged      : ${agenticSettings.staged}`);
  }

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

if (require.main === module) {
  main().catch((error) => {
    console.error('\n[FATAL]', error.message || error);
    process.exit(1);
  });
}

// Export helpers for unit tests.
module.exports = {
  formatDenialMessage,
  main,
  processDismissalRequest,
  validateDismissalComment,
};
