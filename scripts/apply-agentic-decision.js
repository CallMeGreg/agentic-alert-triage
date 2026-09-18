#!/usr/bin/env node

'use strict';

const fs = require('fs');
const { Octokit } = require('@octokit/rest');
const {
  assignAlertToTeam,
  denyDismissalRequest,
  formatAgenticDenialMessage,
  getAlert,
  isStaleDismissalReviewError,
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
  const dismissalRequest = target.dismissalRequest;

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
      try {
        await denyDismissalRequest(
          octokit,
          target.owner,
          target.repo,
          target.alertType,
          target.alertNumber,
          message
        );
      } catch (error) {
        if (!isStaleDismissalReviewError(error)) throw error;

        console.log(
          'Dismissal request is no longer reviewable; treating the optimistic denial as a no-op.'
        );
        appendSummary(
          `## Agentic dismissal review\n\nNo action was taken because dismissal request #${target.dismissalRequestNumber} is no longer reviewable.`
        );
        return;
      }
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
    enterprise: target.enterprise,
    teamSlug: target.teamSlug,
    alertType: target.alertType,
    alertNumber: target.alertNumber,
    alert,
    teamMembers: target.teamLogins,
    dryRun: staged,
  });

  console.log(
    `${staged ? '[STAGED] Would assign' : 'Assigned'} alert #${target.alertNumber} to ${assignment.assigned.join(', ')}.`
  );
  appendSummary(`## Agentic dismissal review

**Decision:** Ready for human review${staged ? ' (staged preview)' : ''}

**Target:** ${target.repository} ${target.alertType.replace(/_/g, ' ')} alert #${target.alertNumber}

**Assigned AppSec members:** ${assignment.assigned.join(', ')}

**Agent rationale:** ${decision.reason}
${assignment.limitation ? `\n> ${assignment.limitation}\n` : ''}
`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  });
}

module.exports = { main };
