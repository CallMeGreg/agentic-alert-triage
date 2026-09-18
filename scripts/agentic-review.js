'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const API_VERSION = '2026-03-10';
const DISPATCH_EVENT_TYPE = 'alert-dismissal-requested';
const DISPATCH_SCHEMA_VERSION = 1;
const MAX_DISPATCH_PAYLOAD_LENGTH = 60000;
const MAX_DENIAL_MESSAGE_LENGTH = 2048;
const MAX_AGENT_REASON_LENGTH = 1200;
const MAX_EVIDENCE_ISSUES = 5;
const MAX_EVIDENCE_BODY_LENGTH = 6000;
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
];

const ALERT_TYPE_METADATA = {
  code_scanning: {
    dismissalSegment: 'code-scanning',
    alertPath: 'code-scanning',
  },
  secret_scanning: {
    dismissalSegment: 'secret-scanning',
    alertPath: 'secret-scanning',
  },
  dependabot: {
    dismissalSegment: 'dependabot',
    alertPath: 'dependabot',
  },
};

function loadConfig(configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'config.yml')) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  return yaml.load(fs.readFileSync(configPath, 'utf8')) || {};
}

function getOrganization(config, env = process.env) {
  const organization =
    config.organization ||
    (env.GITHUB_REPOSITORY ? env.GITHUB_REPOSITORY.split('/')[0] : null);

  if (!organization) {
    throw new Error(
      'Cannot determine organization. Set "organization" in config.yml or GITHUB_REPOSITORY.'
    );
  }

  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(organization)) {
    throw new Error(`Invalid GitHub organization name "${organization}".`);
  }

  return organization;
}

function getAgenticSettings(config, env = process.env) {
  const reviewMode = config.review_mode || 'deterministic';
  if (!['deterministic', 'agentic', 'both'].includes(reviewMode)) {
    throw new Error(
      `Invalid review_mode "${reviewMode}". Expected deterministic, agentic, or both.`
    );
  }

  const agentic = config.agentic || {};
  const organization =
    (config.organization || env.GITHUB_REPOSITORY)
      ? getOrganization(config, env)
      : null;
  const teamSlug = agentic.appsec_team_slug || 'appsec-team';
  const workflowRepository =
    agentic.workflow_repository || env.GITHUB_REPOSITORY || null;

  if (reviewMode === 'agentic' || reviewMode === 'both') {
    if (!organization) {
      throw new Error(
        'Agentic review requires organization or GITHUB_REPOSITORY.'
      );
    }
    if (!workflowRepository) {
      throw new Error(
        'Agentic review requires agentic.workflow_repository or GITHUB_REPOSITORY.'
      );
    }
    const workflowOwner = splitRepository(workflowRepository).owner;
    if (workflowOwner.toLowerCase() !== organization.toLowerCase()) {
      throw new Error(
        'agentic.workflow_repository must be in the monitored organization because one installation token performs both discovery and dispatch.'
      );
    }
  }

  return {
    reviewMode,
    organization,
    teamSlug,
    workflowRepository,
    staged: agentic.staged !== false,
    helpContact:
      agentic.help_contact ||
      (organization ? `@${organization}/${teamSlug}` : `@${teamSlug}`),
    denialMessage: agentic.denial_message || null,
  };
}

function getAlertTypeMetadata(alertType) {
  const metadata = ALERT_TYPE_METADATA[alertType];
  if (!metadata) {
    throw new Error(
      `Unsupported alert type "${alertType}". Expected ${Object.keys(
        ALERT_TYPE_METADATA
      ).join(', ')}.`
    );
  }
  return metadata;
}

function splitRepository(repoFullName) {
  const parts = String(repoFullName || '').split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Invalid repository name "${repoFullName}". Expected owner/repo.`);
  }
  return { owner: parts[0], repo: parts[1] };
}

function extractAlertNumber(alertType, request) {
  getAlertTypeMetadata(alertType);

  if (alertType === 'code_scanning') {
    const alertData = Array.isArray(request.data)
      ? request.data.find((item) => item && item.alert_number != null)
      : null;
    const value = alertData?.alert_number ?? request.resource_identifier;
    const trailingNumber = String(value || '').match(/(\d+)$/);
    return trailingNumber ? Number(trailingNumber[1]) : NaN;
  }

  const alertData = Array.isArray(request.data)
    ? request.data.find((item) => item && item.alert_number != null)
    : null;
  return Number(alertData?.alert_number ?? request.resource_identifier);
}

function isOpenDismissalRequest(request) {
  return ['open', 'pending'].includes(String(request?.status || '').toLowerCase());
}

function normalizeTeamLogins(teamLogins) {
  if (!Array.isArray(teamLogins)) {
    throw new Error('AppSec team members must be provided as an array.');
  }

  const uniqueLogins = new Map();
  for (const value of teamLogins) {
    const login = String(value);
    uniqueLogins.set(login.toLowerCase(), login);
  }
  const normalized = [...uniqueLogins.values()];
  for (const login of normalized) {
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(login)) {
      throw new Error(`Invalid GitHub team member login "${login}".`);
    }
  }
  return normalized.sort((a, b) => a.localeCompare(b));
}

function buildDispatchPayload({
  organization,
  sourceRepository,
  repository,
  alertType,
  alertNumber,
  dismissalRequest,
  teamLogins,
  dryRun = false,
  runId = null,
}) {
  const normalizedTeamLogins = normalizeTeamLogins(teamLogins);
  if (normalizedTeamLogins.length === 0) {
    throw new Error('The configured AppSec team has no members.');
  }

  const payload = {
    schema_version: DISPATCH_SCHEMA_VERSION,
    target: {
      organization,
      repository,
      alert_type: alertType,
      alert_number: alertNumber,
      dismissal_request_id: dismissalRequest.id,
      dismissal_request_number: dismissalRequest.number,
    },
    request: sanitizeDismissalRequest(dismissalRequest),
    review: {
      appsec_team_members: normalizedTeamLogins,
    },
    source: {
      repository: sourceRepository,
      run_id: runId,
    },
    dry_run: dryRun,
  };

  if (JSON.stringify(payload).length > MAX_DISPATCH_PAYLOAD_LENGTH) {
    throw new Error(
      `Dispatch payload exceeds the ${MAX_DISPATCH_PAYLOAD_LENGTH}-character safety limit.`
    );
  }

  return payload;
}

async function dispatchAgenticReview(octokit, workflowRepository, payload) {
  const { owner, repo } = splitRepository(workflowRepository);
  await octokit.request('POST /repos/{owner}/{repo}/dispatches', {
    owner,
    repo,
    event_type: DISPATCH_EVENT_TYPE,
    client_payload: payload,
    headers: { 'X-GitHub-Api-Version': API_VERSION },
  });
}

async function getAlert(octokit, owner, repo, alertType, alertNumber) {
  const { alertPath } = getAlertTypeMetadata(alertType);
  const response = await octokit.request(
    `GET /repos/{owner}/{repo}/${alertPath}/alerts/{alert_number}`,
    {
      owner,
      repo,
      alert_number: alertNumber,
      ...(alertType === 'secret_scanning' ? { hide_secret: true } : {}),
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
  return response.data;
}

async function listTeamMembers(octokit, organization, teamSlug) {
  return octokit.paginate('GET /orgs/{org}/teams/{team_slug}/members', {
    org: organization,
    team_slug: teamSlug,
    role: 'all',
    per_page: 100,
    headers: { 'X-GitHub-Api-Version': API_VERSION },
  });
}

function getAssignedLogins(alertType, alert) {
  getAlertTypeMetadata(alertType);

  if (alertType === 'secret_scanning') {
    return alert?.assigned_to?.login ? [alert.assigned_to.login] : [];
  }

  return Array.isArray(alert?.assignees)
    ? alert.assignees.map((assignee) => assignee.login).filter(Boolean)
    : [];
}

function isAssignedToTeam(alertType, alert, teamLogins) {
  const team = new Set(teamLogins.map((login) => login.toLowerCase()));
  return getAssignedLogins(alertType, alert).some((login) =>
    team.has(login.toLowerCase())
  );
}

async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  }

  const workerCount = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

function selectSecretScanningAssignee(logins, alertNumber) {
  const sorted = [...new Set(logins)].sort((a, b) => a.localeCompare(b));
  if (sorted.length === 0) return null;
  return sorted[Math.abs(Number(alertNumber)) % sorted.length];
}

function mergeAssignees(existingLogins, teamLogins) {
  return [...new Set([...existingLogins, ...teamLogins])].sort((a, b) =>
    a.localeCompare(b)
  );
}

async function assignAlertToTeam({
  octokit,
  owner,
  repo,
  organization,
  teamSlug,
  alertType,
  alertNumber,
  alert,
  teamMembers,
  dryRun = false,
}) {
  const members =
    teamMembers || (await listTeamMembers(octokit, organization, teamSlug));
  const teamLogins = normalizeTeamLogins(
    members.map((member) =>
      typeof member === 'string' ? member : member.login
    )
  );
  if (teamLogins.length === 0) {
    throw new Error(`The @${organization}/${teamSlug} team has no members.`);
  }

  if (alertType === 'secret_scanning') {
    const assignee = selectSecretScanningAssignee(
      teamLogins,
      alertNumber
    );

    if (!dryRun && alert?.assigned_to?.login !== assignee) {
      await octokit.request(
        'PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}',
        {
          owner,
          repo,
          alert_number: alertNumber,
          assignee,
          headers: { 'X-GitHub-Api-Version': API_VERSION },
        }
      );
    }

    return {
      assigned: [assignee],
      skipped: [],
      limitation:
        'The secret scanning API supports one alert assignee, so one AppSec team member was selected deterministically.',
    };
  }

  const assignees = mergeAssignees(
    getAssignedLogins(alertType, alert),
    teamLogins
  );
  const endpoint =
    alertType === 'code_scanning'
      ? 'PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}'
      : 'PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}';

  if (!dryRun) {
    await octokit.request(endpoint, {
      owner,
      repo,
      alert_number: alertNumber,
      assignees,
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    });
  }

  return {
    assigned: teamLogins,
    skipped: [],
    limitation: null,
  };
}

function truncate(value, maxLength) {
  const text = String(value || '');
  return text.length > maxLength
    ? `${text.slice(0, maxLength - 3)}...`
    : text;
}

function redactSensitiveText(value, sensitiveValues = []) {
  let text = String(value || '');

  for (const sensitiveValue of sensitiveValues) {
    const secret = String(sensitiveValue || '');
    if (secret.length >= 4) {
      text = text.split(secret).join('[REDACTED SECRET]');
    }
  }

  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, '[REDACTED SECRET]');
  }

  return text;
}

function sanitizeDismissalRequest(request, sensitiveValues = []) {
  const reasonValues = Array.isArray(request.dismissal_reasons)
    ? request.dismissal_reasons
    : Array.isArray(request.data)
      ? request.data.map((item) => item?.reason)
      : [];

  return {
    id: request.id,
    number: request.number,
    status: request.status,
    request_type: request.request_type,
    requester: request.requester
      ? { actor_name: request.requester.actor_name }
      : null,
    requester_comment: truncate(
      redactSensitiveText(request.requester_comment, sensitiveValues),
      10000
    ),
    dismissal_reasons: [
      ...new Set(
        reasonValues
          .filter((reason) => typeof reason === 'string' && reason)
          .map((reason) => truncate(redactSensitiveText(reason), 100))
      ),
    ].slice(0, 10),
    created_at: request.created_at,
    expires_at: request.expires_at,
    html_url: request.html_url,
  };
}

function sanitizeCodeScanningAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    rule: alert.rule
      ? {
          id: alert.rule.id,
          name: alert.rule.name,
          description: alert.rule.description,
          severity: alert.rule.severity,
          security_severity_level: alert.rule.security_severity_level,
          tags: alert.rule.tags,
        }
      : null,
    tool: alert.tool
      ? {
          name: alert.tool.name,
          version: alert.tool.version,
        }
      : null,
    most_recent_instance: alert.most_recent_instance
      ? {
          ref: alert.most_recent_instance.ref,
          state: alert.most_recent_instance.state,
          environment: alert.most_recent_instance.environment,
          category: alert.most_recent_instance.category,
          classifications: alert.most_recent_instance.classifications,
          location: alert.most_recent_instance.location,
        }
      : null,
    assignees: getAssignedLogins('code_scanning', alert),
  };
}

function sanitizeSecretScanningAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    secret_type: alert.secret_type,
    secret_type_display_name: alert.secret_type_display_name,
    provider: alert.provider,
    provider_slug: alert.provider_slug,
    validity: alert.validity,
    publicly_leaked: alert.publicly_leaked,
    multi_repo: alert.multi_repo,
    is_base64_encoded: alert.is_base64_encoded,
    first_location_detected: alert.first_location_detected,
    has_more_locations: alert.has_more_locations,
    assigned_to: alert.assigned_to?.login || null,
  };
}

function sanitizeDependabotAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    dependency: alert.dependency,
    security_advisory: alert.security_advisory
      ? {
          ghsa_id: alert.security_advisory.ghsa_id,
          cve_id: alert.security_advisory.cve_id,
          summary: alert.security_advisory.summary,
          description: truncate(
            alert.security_advisory.description,
            MAX_EVIDENCE_BODY_LENGTH
          ),
          severity: alert.security_advisory.severity,
          cvss: alert.security_advisory.cvss,
          cwes: alert.security_advisory.cwes,
          identifiers: alert.security_advisory.identifiers,
          references: alert.security_advisory.references,
        }
      : null,
    security_vulnerability: alert.security_vulnerability,
    assignees: getAssignedLogins('dependabot', alert),
  };
}

function sanitizeAlert(alertType, alert) {
  if (alertType === 'code_scanning') {
    return sanitizeCodeScanningAlert(alert);
  }
  if (alertType === 'secret_scanning') {
    return sanitizeSecretScanningAlert(alert);
  }
  if (alertType === 'dependabot') {
    return sanitizeDependabotAlert(alert);
  }
  return getAlertTypeMetadata(alertType);
}

function sanitizeEvidence(evidence, sensitiveValues = []) {
  return evidence.map((item) => ({
    ...item,
    body:
      item.body == null
        ? item.body
        : truncate(
            redactSensitiveText(item.body, sensitiveValues),
            MAX_EVIDENCE_BODY_LENGTH
          ),
    comments: Array.isArray(item.comments)
      ? item.comments.map((comment) => ({
          ...comment,
          body: truncate(
            redactSensitiveText(comment.body, sensitiveValues),
            MAX_EVIDENCE_BODY_LENGTH
          ),
        }))
      : item.comments,
  }));
}

function extractIssueReferences(text, allowedOwner, max = MAX_EVIDENCE_ISSUES) {
  const references = [];
  const seen = new Set();
  const regex =
    /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/issues\/(\d+)/g;
  let match;

  while ((match = regex.exec(String(text || ''))) && references.length < max) {
    const owner = match[1];
    const repo = match[2];
    const issueNumber = Number(match[3]);

    if (owner.toLowerCase() !== allowedOwner.toLowerCase()) continue;

    const key = `${owner.toLowerCase()}/${repo.toLowerCase()}#${issueNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    references.push({
      owner,
      repo,
      issue_number: issueNumber,
      url: match[0],
    });
  }

  return references;
}

async function fetchIssueEvidence(octokit, references) {
  return mapWithConcurrency(references, 3, async (reference) => {
    try {
      const [issueResponse, commentsResponse] = await Promise.all([
        octokit.request('GET /repos/{owner}/{repo}/issues/{issue_number}', {
          owner: reference.owner,
          repo: reference.repo,
          issue_number: reference.issue_number,
          headers: { 'X-GitHub-Api-Version': API_VERSION },
        }),
        octokit.request(
          'GET /repos/{owner}/{repo}/issues/{issue_number}/comments',
          {
            owner: reference.owner,
            repo: reference.repo,
            issue_number: reference.issue_number,
            per_page: 20,
            headers: { 'X-GitHub-Api-Version': API_VERSION },
          }
        ),
      ]);

      return {
        ...reference,
        title: issueResponse.data.title,
        state: issueResponse.data.state,
        author: issueResponse.data.user?.login || null,
        author_association: issueResponse.data.author_association,
        body: truncate(issueResponse.data.body, MAX_EVIDENCE_BODY_LENGTH),
        comments: commentsResponse.data.map((comment) => ({
          author: comment.user?.login || null,
          author_association: comment.author_association,
          body: truncate(comment.body, MAX_EVIDENCE_BODY_LENGTH),
          created_at: comment.created_at,
        })),
      };
    } catch (error) {
      if (error.status === 403 || error.status === 404) {
        return {
          ...reference,
          unavailable: `GitHub returned HTTP ${error.status} while fetching this evidence.`,
        };
      }
      throw error;
    }
  });
}

function readDispatchEvent(eventPath = process.env.GITHUB_EVENT_PATH) {
  if (!eventPath || !fs.existsSync(eventPath)) {
    throw new Error('GITHUB_EVENT_PATH is not available.');
  }
  return JSON.parse(fs.readFileSync(eventPath, 'utf8'));
}

function validateDispatchEvent(event, config, env = process.env) {
  const settings = getAgenticSettings(config, env);
  if (settings.reviewMode !== 'agentic' && settings.reviewMode !== 'both') {
    throw new Error(
      'Agentic review is disabled. Set review_mode to agentic or both.'
    );
  }
  if (event.action !== DISPATCH_EVENT_TYPE) {
    throw new Error(
      `Unexpected repository_dispatch action "${event.action}". Expected "${DISPATCH_EVENT_TYPE}".`
    );
  }

  const payload = event.client_payload || {};
  if (payload.schema_version !== DISPATCH_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported dispatch schema_version "${payload.schema_version}".`
    );
  }

  const dispatchedTarget = payload.target || {};
  if (
    typeof dispatchedTarget.organization !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(
      dispatchedTarget.organization
    )
  ) {
    throw new Error('Dispatch payload contains an invalid organization.');
  }

  if (
    dispatchedTarget.organization.toLowerCase() !==
    settings.organization.toLowerCase()
  ) {
    throw new Error(
      `Dispatch organization ${dispatchedTarget.organization} does not match configured organization ${settings.organization}.`
    );
  }

  if (
    env.EXPECTED_DISPATCH_SENDER &&
    event.sender?.login?.toLowerCase() !==
      env.EXPECTED_DISPATCH_SENDER.toLowerCase()
  ) {
    throw new Error(
      `Dispatch sender ${event.sender?.login || '(unknown)'} does not match the configured GitHub App identity.`
    );
  }

  const { owner, repo } = splitRepository(dispatchedTarget.repository);
  if (owner.toLowerCase() !== settings.organization.toLowerCase()) {
    throw new Error(
      `Dispatch target ${dispatchedTarget.repository} is outside configured organization ${settings.organization}.`
    );
  }

  getAlertTypeMetadata(dispatchedTarget.alert_type);
  if (
    Array.isArray(config.alert_types) &&
    !config.alert_types.includes(dispatchedTarget.alert_type)
  ) {
    throw new Error(
      `Alert type "${dispatchedTarget.alert_type}" is not enabled in config.yml.`
    );
  }

  const alertNumber = Number(dispatchedTarget.alert_number);
  const dismissalRequestId = Number(
    dispatchedTarget.dismissal_request_id
  );
  const dismissalRequestNumber = Number(
    dispatchedTarget.dismissal_request_number
  );
  if (
    !Number.isInteger(alertNumber) ||
    alertNumber <= 0 ||
    !Number.isInteger(dismissalRequestId) ||
    dismissalRequestId <= 0 ||
    !Number.isInteger(dismissalRequestNumber) ||
    dismissalRequestNumber <= 0
  ) {
    throw new Error('Dispatch payload contains invalid alert or request identifiers.');
  }

  const dismissalRequest = sanitizeDismissalRequest(payload.request || {});
  if (
    Number(dismissalRequest.id) !== dismissalRequestId ||
    Number(dismissalRequest.number) !== dismissalRequestNumber
  ) {
    throw new Error(
      'Dispatch request snapshot does not match the target request identifiers.'
    );
  }

  const teamLogins = normalizeTeamLogins(
    payload.review?.appsec_team_members
  );
  if (teamLogins.length === 0) {
    throw new Error('Dispatch payload contains no AppSec team members.');
  }

  if (
    settings.workflowRepository &&
    env.GITHUB_REPOSITORY &&
    settings.workflowRepository.toLowerCase() !==
      env.GITHUB_REPOSITORY.toLowerCase()
  ) {
    throw new Error(
      `This workflow is running in ${env.GITHUB_REPOSITORY}, but agentic.workflow_repository is ${settings.workflowRepository}.`
    );
  }

  return {
    ...settings,
    payload,
    owner,
    repo,
    repository: `${owner}/${repo}`,
    alertType: dispatchedTarget.alert_type,
    alertNumber,
    dismissalRequestId,
    dismissalRequestNumber,
    dismissalRequest,
    teamLogins,
    dryRun: payload.dry_run === true || payload.dry_run === 'true',
  };
}

function buildReviewContext({
  target,
  dismissalRequest,
  alert,
  evidence,
}) {
  const sensitiveValues =
    target.alertType === 'secret_scanning' && alert.secret
      ? [alert.secret]
      : [];

  return {
    schema_version: 1,
    target: {
      organization: target.organization,
      repository: target.repository,
      alert_type: target.alertType,
      alert_number: target.alertNumber,
      dismissal_request_id: target.dismissalRequestId,
      dismissal_request_number: target.dismissalRequestNumber,
      appsec_team_slug: target.teamSlug,
      staged: target.staged || target.dryRun,
    },
    dismissal_request: sanitizeDismissalRequest(
      dismissalRequest,
      sensitiveValues
    ),
    alert: sanitizeAlert(target.alertType, alert),
    linked_issue_evidence: sanitizeEvidence(evidence, sensitiveValues),
  };
}

function appendNoop(message, safeOutputsPath = process.env.GH_AW_SAFE_OUTPUTS) {
  if (!safeOutputsPath) {
    throw new Error('GH_AW_SAFE_OUTPUTS is not available.');
  }
  fs.appendFileSync(
    safeOutputsPath,
    `${JSON.stringify({ type: 'noop', message })}\n`
  );
}

function sanitizeAgentReason(reason) {
  const normalized = String(reason || '')
    .replace(/\0/g, '')
    .replace(/<[^>\n]*>/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]+\)/g, '$1')
    .replace(/\bhttps?:\/\/\S+/gi, '[link omitted]')
    .replace(/@/g, '@\u200b')
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length < 10) {
    throw new Error('The agent decision reason must be at least 10 characters.');
  }
  return truncate(normalized, MAX_AGENT_REASON_LENGTH);
}

function parseAgentDecision(outputPath = process.env.GH_AW_AGENT_OUTPUT) {
  if (!outputPath || !fs.existsSync(outputPath)) {
    throw new Error('GH_AW_AGENT_OUTPUT is not available.');
  }

  const output = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
  const decisions = (output.items || []).filter(
    (item) => item.type === 'apply_dismissal_decision'
  );
  if (decisions.length !== 1) {
    throw new Error(
      `Expected exactly one apply_dismissal_decision item, found ${decisions.length}.`
    );
  }

  const decision = decisions[0].decision;
  if (!['ready_for_review', 'deny'].includes(decision)) {
    throw new Error(`Unsupported agent decision "${decision}".`);
  }

  return {
    decision,
    reason: sanitizeAgentReason(decisions[0].reason),
  };
}

function formatAgenticDenialMessage({
  config,
  target,
  dismissalRequest,
  reason,
}) {
  const requester =
    dismissalRequest.requester?.actor_name || 'requester';
  const template =
    target.denialMessage ||
    `## Dismissal request denied after agentic review

@{requester}, this dismissal request is not ready for human review.

**Why it was denied:** {denial_reason}

Please submit a new request with a specific explanation of why the alert can be dismissed, supporting evidence or links, and any relevant mitigating controls or remediation plan.

For help, contact {help_contact}.`;

  return truncate(
    template
      .replace(/{requester}/g, requester)
      .replace(/{denial_reason}/g, reason)
      .replace(/{help_contact}/g, target.helpContact)
      .replace(/{alert_type}/g, target.alertType.replace(/_/g, ' '))
      .replace(/{alert_number}/g, String(target.alertNumber))
      .replace(/{repo_full_name}/g, target.repository),
    MAX_DENIAL_MESSAGE_LENGTH
  );
}

async function denyDismissalRequest(
  octokit,
  owner,
  repo,
  alertType,
  alertNumber,
  message
) {
  const { dismissalSegment } = getAlertTypeMetadata(alertType);
  await octokit.request(
    `PATCH /repos/{owner}/{repo}/dismissal-requests/${dismissalSegment}/{alert_number}`,
    {
      owner,
      repo,
      alert_number: alertNumber,
      status: 'deny',
      message: truncate(message, MAX_DENIAL_MESSAGE_LENGTH),
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
}

function isStaleDismissalReviewError(error) {
  if (error?.status === 404) return true;
  if (error?.status !== 422) return false;

  const message = JSON.stringify(
    error.response?.data || error.message || ''
  ).toLowerCase();
  return /(already|completed|cancelled|expired|approved|denied|not open|not pending|no pending)/.test(
    message
  );
}

module.exports = {
  ALERT_TYPE_METADATA,
  API_VERSION,
  DISPATCH_EVENT_TYPE,
  appendNoop,
  assignAlertToTeam,
  buildDispatchPayload,
  buildReviewContext,
  denyDismissalRequest,
  dispatchAgenticReview,
  extractAlertNumber,
  extractIssueReferences,
  fetchIssueEvidence,
  formatAgenticDenialMessage,
  getAgenticSettings,
  getAlert,
  getAssignedLogins,
  getOrganization,
  isAssignedToTeam,
  isOpenDismissalRequest,
  listTeamMembers,
  loadConfig,
  mergeAssignees,
  normalizeTeamLogins,
  parseAgentDecision,
  readDispatchEvent,
  redactSensitiveText,
  sanitizeAlert,
  sanitizeEvidence,
  sanitizeAgentReason,
  selectSecretScanningAssignee,
  splitRepository,
  isStaleDismissalReviewError,
  validateDispatchEvent,
};
