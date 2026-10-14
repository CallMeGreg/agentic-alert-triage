'use strict';

const { ALERT_TYPE_METADATA } = require('./agentic-review');

function getDeterministicRules(config = {}) {
  const configuredReasons = config.allowed_dismissal_reasons;
  if (
    configuredReasons !== undefined &&
    (!configuredReasons ||
      typeof configuredReasons !== 'object' ||
      Array.isArray(configuredReasons))
  ) {
    throw new Error(
      'allowed_dismissal_reasons must be an object keyed by alert type.'
    );
  }

  const allowedDismissalReasons = {};
  for (const [alertType, reasons] of Object.entries(configuredReasons || {})) {
    if (!Object.hasOwn(ALERT_TYPE_METADATA, alertType)) {
      throw new Error(
        `Unsupported alert type "${alertType}" in allowed_dismissal_reasons.`
      );
    }
    if (
      !Array.isArray(reasons) ||
      reasons.some((reason) => typeof reason !== 'string' || !reason.trim())
    ) {
      throw new Error(
        `allowed_dismissal_reasons.${alertType} must be an array of non-empty strings.`
      );
    }
    allowedDismissalReasons[alertType] = [...new Set(reasons)];
  }

  return {
    allowedDismissalReasons,
    requiredPhrase: config.required_phrase ?? null,
    requiredPattern: config.required_pattern ?? null,
    minimumLength:
      Number.isFinite(config.minimum_length) && config.minimum_length > 0
        ? config.minimum_length
        : null,
    caseSensitive: config.case_sensitive === true,
  };
}

function validateDismissalReasons(reasons, alertType, rules = {}) {
  const permittedReasons = rules.allowedDismissalReasons?.[alertType];
  if (permittedReasons === undefined) return { valid: true };
  if (
    reasons.length > 0 &&
    reasons.every((reason) => permittedReasons.includes(reason))
  ) {
    return { valid: true };
  }

  const alertLabel = alertType.replace(/_/g, ' ');
  const guidance = permittedReasons.length
    ? `Please resubmit the dismissal request using a permitted reason. Permitted reasons: ${permittedReasons.map((reason) => JSON.stringify(reason)).join(', ')}.`
    : 'Permitted reasons: none. Please resubmit the dismissal request once the policy permits an appropriate reason.';
  return {
    valid: false,
    reason: `The dismissal reason is not permitted for ${alertLabel}. ${guidance}`,
  };
}

function validateDismissalComment(comment, rules = {}) {
  const {
    requiredPhrase = null,
    requiredPattern = null,
    minimumLength = null,
    caseSensitive = false,
  } = rules;
  const trimmed = String(comment || '').trim();

  if (minimumLength != null && trimmed.length < minimumLength) {
    return {
      valid: false,
      reason: `The dismissal comment must be at least ${minimumLength} characters long (found ${trimmed.length}).`,
    };
  }

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

  if (requiredPattern) {
    let regex;
    try {
      regex = new RegExp(requiredPattern, caseSensitive ? '' : 'i');
    } catch (error) {
      return {
        valid: false,
        reason: `The configured required_pattern is not a valid regular expression: ${error.message}`,
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

function getDefaultDenialTemplate() {
  return `DISMISSAL REQUEST DENIED.

Reason: {denial_reason}

Next step: Submit a new dismissal request with an updated comment that satisfies the requirements.

For more help, mention the {help_contact}`;
}

function formatDenialMessage(
  {
    alertType,
    alertNumber,
    requester,
    denialReason,
    repoFullName,
    helpContact,
    requireDenialReason = false,
  },
  config = {}
) {
  const template =
    typeof config.denial_message === 'string' &&
    config.denial_message.trim()
      ? config.denial_message
      : getDefaultDenialTemplate();

  const message = template
    .replace(/{alert_type}/g, alertType.replace(/_/g, ' '))
    .replace(/{alert_number}/g, String(alertNumber))
    .replace(/{requester}/g, requester || 'unknown')
    .replace(/{required_phrase}/g, config.required_phrase || '')
    .replace(/{denial_reason}/g, () => denialReason)
    .replace(/{repo_full_name}/g, repoFullName)
    .replace(/{help_contact}/g, helpContact);

  if (requireDenialReason && !template.includes('{denial_reason}')) {
    return `Reason: ${denialReason}\n\n${message}`;
  }
  return message;
}

module.exports = {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
  validateDismissalReasons,
};
