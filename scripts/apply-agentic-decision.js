#!/usr/bin/env node

'use strict';

const fs = require('fs');
const { Octokit } = require('@octokit/rest');
const {
  assignAlertToTeam,
  denyDismissalRequest,
  formatAgenticDenialMessage,
  getAlert,
  getDismissalRequest,
  isOpenDismissalRequest,
  loadConfig,
  parseAgentDecision,
  readDispatchEvent,
  validateDispatchEvent,
} = require('./agentic-review');

function appendSummary(markdown) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown.trim()}\n`);
}

async function main() {
  const config = loadConfig();
  const event = readDispatchEvent();
  const target = validateDispatchEvent(event, config);
  const decision = parseAgentDecision();
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  const dismissalRequest = await getDismissalRequest(
    octokit,
    target.owner,
    target.repo,
    target.alertType,
    target.alertNumber
  );

  if (
    dismissalRequest.id !== target.dismissalRequestId ||
    dismissalRequest.number !== target.dismissalRequestNumber
  ) {
    throw new Error(
      'The fetched dismissal request does not match the dispatched request identifiers.'
    );
  }

  if (!isOpenDismissalRequest(dismissalRequest)) {
    console.log('Dismissal request is no longer open; no action is required.');
    appendSummary(
      `## Agentic dismissal review\n\nNo action was taken because dismissal request #${target.dismissalRequestNumber} is no longer open.`
    );
    return;
  }

  const staged =
    process.env.GH_AW_SAFE_OUTPUTS_STAGED === 'true' ||
    target.staged ||
    target.dryRun;

  if (decision.decision === 'deny') {
    const message = formatAgenticDenialMessage({
      config,
      target,
      dismissalRequest,
      reason: decision.reason,
    });

    if (!staged) {
      await denyDismissalRequest(
        octokit,
        target.owner,
        target.repo,
        target.alertType,
        target.alertNumber,
        message
      );
    }

    console.log(
      `${staged ? '[STAGED] Would deny' : 'Denied'} dismissal request #${target.dismissalRequestNumber}.`
    );
    appendSummary(`## Agentic dismissal review

**Decision:** Deny${staged ? ' (staged preview)' : ''}

**Target:** ${target.repository} ${target.alertType.replace(/_/g, ' ')} alert #${target.alertNumber}

**Reason:** ${decision.reason}`);
    return;
  }

  const alert = await getAlert(
    octokit,
    target.owner,
    target.repo,
    target.alertType,
    target.alertNumber
  );
  const assignment = await assignAlertToTeam({
    octokit,
    owner: target.owner,
    repo: target.repo,
    organization: target.organization,
    teamSlug: target.teamSlug,
    alertType: target.alertType,
    alertNumber: target.alertNumber,
    alert,
    dryRun: staged,
  });

  console.log(
    `${staged ? '[STAGED] Would assign' : 'Assigned'} alert #${target.alertNumber} to ${assignment.assigned.join(', ')}.`
  );
  if (assignment.skipped.length > 0) {
    console.log(
      `Skipped team members without write access: ${assignment.skipped
        .map((member) => `${member.login} (${member.permission})`)
        .join(', ')}`
    );
  }

  appendSummary(`## Agentic dismissal review

**Decision:** Ready for human review${staged ? ' (staged preview)' : ''}

**Target:** ${target.repository} ${target.alertType.replace(/_/g, ' ')} alert #${target.alertNumber}

**Assigned AppSec members:** ${assignment.assigned.join(', ')}

**Agent rationale:** ${decision.reason}
${assignment.limitation ? `\n> ${assignment.limitation}\n` : ''}
${
  assignment.skipped.length > 0
    ? `\n**Not assigned (write access required):** ${assignment.skipped
        .map((member) => `${member.login} (${member.permission})`)
        .join(', ')}\n`
    : ''
}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  });
}

module.exports = { main };
