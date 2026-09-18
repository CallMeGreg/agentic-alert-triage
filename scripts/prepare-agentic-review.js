#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { Octokit } = require('@octokit/rest');
const {
  appendNoop,
  buildReviewContext,
  extractIssueReferences,
  fetchIssueEvidence,
  getAlert,
  getAssignedLogins,
  getDismissalRequest,
  isAssignedToTeam,
  isOpenDismissalRequest,
  listTeamMembers,
  loadConfig,
  readDispatchEvent,
  validateDispatchEvent,
} = require('./agentic-review');

async function main() {
  const config = loadConfig();
  const event = readDispatchEvent();
  const target = validateDispatchEvent(event, config);
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
    appendNoop(
      `Dismissal request #${target.dismissalRequestNumber} is no longer open.`
    );
    console.log('Dismissal request is no longer open; skipping agent execution.');
    return;
  }

  const [alert, teamMembers] = await Promise.all([
    getAlert(
      octokit,
      target.owner,
      target.repo,
      target.alertType,
      target.alertNumber
    ),
    listTeamMembers(octokit, target.organization, target.teamSlug),
  ]);
  const teamLogins = teamMembers.map((member) => member.login);

  if (isAssignedToTeam(target.alertType, alert, teamLogins)) {
    appendNoop(
      `Alert #${target.alertNumber} is already assigned to @${target.organization}/${target.teamSlug}.`
    );
    console.log('Alert is already assigned to the AppSec team; skipping agent execution.');
    return;
  }

  const evidenceReferences = extractIssueReferences(
    dismissalRequest.requester_comment,
    target.organization
  );
  const evidence = await fetchIssueEvidence(octokit, evidenceReferences);
  const context = buildReviewContext({
    target,
    dismissalRequest,
    alert,
    evidence,
  });

  const outputPath = path.join(
    process.cwd(),
    '.github',
    'agentic-review-context.json'
  );
  fs.writeFileSync(outputPath, `${JSON.stringify(context, null, 2)}\n`, {
    mode: 0o600,
  });

  console.log(
    `Prepared sanitized context for ${target.repository} ${target.alertType} alert #${target.alertNumber}.`
  );
  console.log(
    `Current assignees: ${getAssignedLogins(target.alertType, alert).join(', ') || '(none)'}`
  );
  console.log(`Linked evidence items fetched: ${evidence.length}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  });
}

module.exports = { main };
