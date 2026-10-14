'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
  validateDismissalReasons,
} = require('./deterministic-review');

describe('deterministic dismissal review', () => {
  const phraseRules = {
    requiredPhrase: 'mitigating control',
    requiredPattern: null,
    minimumLength: null,
    caseSensitive: false,
  };

  it('normalizes configured validation rules', () => {
    assert.deepEqual(
      getDeterministicRules({
        required_phrase: 'approved exception',
        required_pattern: '^SEC-\\d+',
        minimum_length: 20,
        case_sensitive: true,
        allowed_dismissal_reasons: {
          code_scanning: ['false positive', 'used in tests', 'false positive'],
          secret_scanning: ['revoked'],
        },
      }),
      {
        allowedDismissalReasons: {
          code_scanning: ['false positive', 'used in tests'],
          secret_scanning: ['revoked'],
        },
        requiredPhrase: 'approved exception',
        requiredPattern: '^SEC-\\d+',
        minimumLength: 20,
        caseSensitive: true,
      }
    );
  });

  it('permits all dismissal reasons by default and for omitted alert types', () => {
    for (const config of [{}, { allowed_dismissal_reasons: {} }]) {
      const rules = getDeterministicRules(config);
      assert.deepEqual(rules.allowedDismissalReasons, {});
      for (const alertType of ['code_scanning', 'dependabot', 'secret_scanning']) {
        assert.deepEqual(
          validateDismissalReasons(['any reason', undefined], alertType, rules),
          { valid: true }
        );
      }
    }

    const rules = getDeterministicRules({
      allowed_dismissal_reasons: { secret_scanning: ['revoked'] },
    });
    assert.equal(
      validateDismissalReasons(['used in tests'], 'code_scanning', rules).valid,
      true
    );
    assert.equal(
      validateDismissalReasons(['not_used'], 'dependabot', rules).valid,
      true
    );
  });

  it('rejects malformed dismissal reason configuration', () => {
    for (const value of [null, true, 'revoked', []]) {
      assert.throws(
        () => getDeterministicRules({ allowed_dismissal_reasons: value }),
        /allowed_dismissal_reasons must be an object keyed by alert type/
      );
    }
    assert.throws(
      () => getDeterministicRules({
        allowed_dismissal_reasons: { unknown: ['revoked'] },
      }),
      /Unsupported alert type "unknown"/
    );
    for (const value of [null, 'revoked', [null], [42], [''], ['   ']]) {
      assert.throws(
        () => getDeterministicRules({
          allowed_dismissal_reasons: { secret_scanning: value },
        }),
        /allowed_dismissal_reasons.secret_scanning must be an array of non-empty strings/
      );
    }
  });

  it('accepts permitted reasons using exact matching independently of comment casing', () => {
    const config = {
      allowed_dismissal_reasons: {
        code_scanning: ['false positive', 'used in tests'],
      },
    };
    for (const caseSensitive of [true, false]) {
      const rules = getDeterministicRules({
        ...config,
        case_sensitive: caseSensitive,
      });
      assert.deepEqual(
        validateDismissalReasons(
          ['false positive', 'used in tests'],
          'code_scanning',
          rules
        ),
        { valid: true }
      );
      for (const reasons of [
        [],
        [undefined],
        [null],
        [''],
        ['False positive'],
        ['false positive '],
        ['false positive', "won't fix"],
      ]) {
        const result = validateDismissalReasons(reasons, 'code_scanning', rules);
        assert.equal(result.valid, false);
        assert.equal(
          result.reason,
          'The dismissal reason is not permitted for code scanning. Please resubmit the dismissal request using a permitted reason. Permitted reasons: "false positive", "used in tests".'
        );
      }
    }
  });

  it('permits no reasons when an empty list is configured', () => {
    const rules = getDeterministicRules({
      allowed_dismissal_reasons: { secret_scanning: [] },
    });
    const result = validateDismissalReasons(
      ['revoked'],
      'secret_scanning',
      rules
    );
    assert.equal(result.valid, false);
    assert.match(result.reason, /Permitted reasons: none/);
    assert.match(result.reason, /resubmit the dismissal request/);
  });

  it('accepts a comment containing the required phrase', () => {
    const result = validateDismissalComment(
      'We have a mitigating control in place via WAF rules.',
      phraseRules
    );
    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it('accepts the required phrase regardless of case', () => {
    assert.equal(
      validateDismissalComment(
        'MITIGATING CONTROL documented.',
        phraseRules
      ).valid,
      true
    );
  });

  it('rejects missing and empty comments when criteria are configured', () => {
    assert.match(
      validateDismissalComment('This is not relevant.', phraseRules).reason,
      /required phrase/
    );
    for (const comment of [null, undefined, '', '   ']) {
      assert.equal(
        validateDismissalComment(comment, phraseRules).valid,
        false
      );
    }
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

  it('substitutes denial message placeholders', () => {
    const message = formatDenialMessage(
      {
        alertType: 'code_scanning',
        alertNumber: 42,
        requester: 'octocat',
        denialReason: 'Missing required phrase.',
        repoFullName: 'my-org/my-repo',
        helpContact: 'the security team',
      },
      {
        required_phrase: 'mitigating control',
        denial_message:
          '{alert_type} #{alert_number} {requester} {required_phrase} {denial_reason} {repo_full_name} {help_contact}',
      }
    );

    assert.equal(
      message,
      'code scanning #42 octocat mitigating control Missing required phrase. my-org/my-repo the security team'
    );
  });

  it('uses the built-in denial template when none is configured', () => {
    const message = formatDenialMessage(
      {
        alertType: 'dependabot',
        alertNumber: 7,
        requester: undefined,
        denialReason: 'Too short.',
        repoFullName: 'org/repo',
        helpContact:
          'Enterprise AppSec team in your alert (@/ent:appsec-team)',
      },
      {}
    );

    assert.equal(
      message,
      `DISMISSAL REQUEST DENIED.

Reason: Too short.

Next step: Submit a new dismissal request with an updated comment that satisfies the requirements.

For more help, mention the Enterprise AppSec team in your alert (@/ent:appsec-team)`
    );
    assert.doesNotMatch(message, /\*/);
  });

  it('preserves required reason guidance even when a custom template omits the placeholder', () => {
    const parameters = {
      alertType: 'secret_scanning',
      alertNumber: 42,
      requester: 'octocat',
      denialReason: 'Please resubmit using a permitted reason: revoked.',
      repoFullName: 'org/repo',
      helpContact: 'the security team',
      requireDenialReason: true,
    };
    assert.equal(
      formatDenialMessage(parameters, { denial_message: 'Denied for {requester}.' }),
      'Reason: Please resubmit using a permitted reason: revoked.\n\nDenied for octocat.'
    );
    assert.equal(
      formatDenialMessage(parameters, { denial_message: '{denial_reason}' }),
      parameters.denialReason
    );
    assert.equal(
      formatDenialMessage(
        { ...parameters, requireDenialReason: false },
        { denial_message: 'Denied.' }
      ),
      'Denied.'
    );
  });
});
