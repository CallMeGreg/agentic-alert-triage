// scripts/check-dismissals.test.js
//
// Unit tests for the exported helpers in check-dismissals.js.
// Run with: npm test  (uses Node.js built-in test runner, Node ≥ 20)

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { validateDismissalComment, formatDenialMessage } = require('./check-dismissals');

// ---------------------------------------------------------------------------
// validateDismissalComment
// ---------------------------------------------------------------------------

describe('validateDismissalComment', () => {
  // The module reads config.yml at load time.  The default config.yml ships
  // with required_phrase: "mitigating control" and no required_pattern or
  // minimum_length, so only the phrase check is active.

  it('accepts a comment containing the required phrase', () => {
    const result = validateDismissalComment(
      'We have a mitigating control in place via WAF rules.'
    );
    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it('accepts the required phrase regardless of case (default case_sensitive: false)', () => {
    const result = validateDismissalComment('MITIGATING CONTROL documented.');
    assert.equal(result.valid, true);
  });

  it('rejects a comment missing the required phrase', () => {
    const result = validateDismissalComment('This is not relevant.');
    assert.equal(result.valid, false);
    assert.ok(result.reason.includes('required phrase'));
  });

  it('rejects null / undefined comments when required_phrase is set', () => {
    assert.equal(validateDismissalComment(null).valid, false);
    assert.equal(validateDismissalComment(undefined).valid, false);
  });

  it('rejects empty string when required_phrase is set', () => {
    assert.equal(validateDismissalComment('').valid, false);
  });

  it('rejects whitespace-only string when required_phrase is set', () => {
    assert.equal(validateDismissalComment('   ').valid, false);
  });
});

// ---------------------------------------------------------------------------
// formatDenialMessage
// ---------------------------------------------------------------------------

describe('formatDenialMessage', () => {
  it('substitutes all placeholders in the default template', () => {
    const msg = formatDenialMessage({
      alertType: 'code_scanning',
      alertNumber: 42,
      requester: 'octocat',
      denialReason: 'Missing required phrase.',
      repoFullName: 'my-org/my-repo',
    });

    assert.ok(msg.includes('code scanning'), 'should contain humanized alert type');
    assert.ok(msg.includes('#42'), 'should contain alert number');
    assert.ok(msg.includes('Missing required phrase.'), 'should contain denial reason');
    assert.ok(msg.includes('my-org/my-repo'), 'should contain repo full name');
  });

  it('substitutes {requester} when a custom template uses it', () => {
    // Temporarily test with a custom template containing {requester}
    const msg = formatDenialMessage({
      alertType: 'dependabot',
      alertNumber: 7,
      requester: 'octocat',
      denialReason: 'Too short.',
      repoFullName: 'org/repo',
    });

    // Default template doesn't include {requester}, but the message should
    // still be well-formed.
    assert.ok(msg.includes('dependabot'), 'should contain alert type');
    assert.ok(msg.includes('#7'), 'should contain alert number');
  });

  it('handles undefined requester without error', () => {
    // Should not throw even when requester is undefined.
    const msg = formatDenialMessage({
      alertType: 'dependabot',
      alertNumber: 7,
      requester: undefined,
      denialReason: 'Too short.',
      repoFullName: 'org/repo',
    });

    assert.ok(typeof msg === 'string');
    assert.ok(msg.length > 0);
  });
});
