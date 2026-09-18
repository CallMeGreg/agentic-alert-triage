#!/usr/bin/env node

'use strict';

const fs = require('fs');
const {
  getOrganization,
  loadConfig,
} = require('./agentic-review');

function main() {
  if (!process.env.GITHUB_OUTPUT) {
    throw new Error('GITHUB_OUTPUT is not available.');
  }

  const organization = getOrganization(loadConfig());
  fs.appendFileSync(
    process.env.GITHUB_OUTPUT,
    `organization=${organization}\n`
  );
  console.log(`Using configured organization: ${organization}`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  }
}

module.exports = { main };
