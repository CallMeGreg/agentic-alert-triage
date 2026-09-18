'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  formatDenialMessage,
  validateDismissalComment,
} = require('./check-dismissals');

describe('validateDismissalComment', () => {
  const phraseRules = {
    requiredPhrase: 'mitigating control',
    requiredPattern: null,
    minimumLength: null,
    caseSensitive: false,
  };

  it('accepts a comment containing the required phrase', () => {
    const result = validateDismissalComment(
      'We have a mitigating control in place via WAF rules.',
      phraseRules
    );
    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it('accepts the required phrase regardless of case', () => {
    const result = validateDismissalComment(
      'MITIGATING CONTROL documented.',
      phraseRules
    );
    assert.equal(result.valid, true);
  });

  it('rejects a comment missing the required phrase', () => {
    const result = validateDismissalComment(
      'This is not relevant.',
      phraseRules
    );
    assert.equal(result.valid, false);
    assert.match(result.reason, /required phrase/);
  });

  it('rejects empty comments when criteria are configured', () => {
    assert.equal(validateDismissalComment(null, phraseRules).valid, false);
    assert.equal(validateDismissalComment(undefined, phraseRules).valid, false);
    assert.equal(validateDismissalComment('', phraseRules).valid, false);
    assert.equal(validateDismissalComment('   ', phraseRules).valid, false);
  });

  it('enforces minimum length and regular expression rules', () => {
    const rules = {
      requiredPhrase: null,
      requiredPattern: '^SEC-\\d+:',
      minimumLength: 12,
      caseSensitive: true,
    };

    assert.equal(
      validateDismissalComment('SEC-42: accepted risk', rules).valid,
      true
    );
    assert.match(
      validateDismissalComment('SEC-42:', rules).reason,
      /at least 12 characters/
    );
    assert.match(
      validateDismissalComment('sec-42: accepted risk', rules).reason,
      /required pattern/
    );
  });

  it('reports invalid configured regular expressions', () => {
    const result = validateDismissalComment('anything', {
      requiredPhrase: null,
      requiredPattern: '[',
      minimumLength: null,
      caseSensitive: false,
    });

    assert.equal(result.valid, false);
    assert.match(result.reason, /not a valid regular expression/);
  });
});

describe('formatDenialMessage', () => {
  it('substitutes all supported placeholders', () => {
    const msg = formatDenialMessage(
      {
        alertType: 'code_scanning',
        alertNumber: 42,
        requester: 'octocat',
        denialReason: 'Missing required phrase.',
        repoFullName: 'my-org/my-repo',
      },
      {
        required_phrase: 'mitigating control',
        denial_message:
          '{alert_type} #{alert_number} {requester} {required_phrase} {denial_reason} {repo_full_name}',
      }
    );

    assert.equal(
      msg,
      'code scanning #42 octocat mitigating control Missing required phrase. my-org/my-repo'
    );
  });

  it('uses the built-in template when no custom template is configured', () => {
    const msg = formatDenialMessage(
      {
        alertType: 'dependabot',
        alertNumber: 7,
        requester: undefined,
        denialReason: 'Too short.',
        repoFullName: 'org/repo',
      },
      {}
    );

    assert.match(msg, /dependabot/);
    assert.match(msg, /#7/);
    assert.match(msg, /Too short/);
    assert.match(msg, /org\/repo/);
  });
});
