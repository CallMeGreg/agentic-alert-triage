'use strict';

const { registerWebhookHandlers } = require('./scripts/webhook-review');

module.exports = (app) => {
  registerWebhookHandlers(app);
};
