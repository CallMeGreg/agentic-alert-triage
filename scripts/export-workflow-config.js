#!/usr/bin/env node

'use strict';

const fs = require('fs');
const { Octokit } = require('@octokit/rest');
const { createAppAuth } = require('@octokit/auth-app');
const {
  API_VERSION,
  getAgenticSettings,
  loadConfig,
  readDispatchEvent,
  validateDispatchEvent,
  validateEnterpriseApp,
} = require('./agentic-review');

async function resolveWorkflowTarget({
  config,
  event,
  appOctokit,
  env = process.env,
}) {
  const settings = getAgenticSettings(config);
  const { data: appInfo } = await appOctokit.request('GET /app', {
    headers: { 'X-GitHub-Api-Version': API_VERSION },
  });
  validateEnterpriseApp(appInfo, settings.enterprise);
  if (
    typeof appInfo.slug !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,99}$/.test(appInfo.slug)
  ) {
    throw new Error('Authenticated GitHub App has an invalid slug.');
  }
  return validateDispatchEvent(event, config, {
    ...env,
    EXPECTED_DISPATCH_SENDER: `${appInfo.slug}[bot]`,
  });
}

async function main({
  env = process.env,
  config = loadConfig(),
  event = readDispatchEvent(env.GITHUB_EVENT_PATH),
  appOctokit,
} = {}) {
  if (!env.GITHUB_OUTPUT) {
    throw new Error('GITHUB_OUTPUT is not available.');
  }
  if (!appOctokit) {
    if (
      !env.ALERT_DISMISSAL_APP_CLIENT_ID ||
      !env.ALERT_DISMISSAL_APP_PRIVATE_KEY
    ) {
      throw new Error('GitHub App client ID and private key are required.');
    }
    appOctokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: env.ALERT_DISMISSAL_APP_CLIENT_ID,
        privateKey: env.ALERT_DISMISSAL_APP_PRIVATE_KEY,
      },
    });
  }
  const target = await resolveWorkflowTarget({ config, event, appOctokit, env });
  fs.appendFileSync(
    env.GITHUB_OUTPUT,
    `organization=${target.organization}\n`
  );
  console.log(`Using validated target organization: ${target.organization}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  });
}

module.exports = { main, resolveWorkflowTarget };
