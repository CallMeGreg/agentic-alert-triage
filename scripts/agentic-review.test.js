'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildDispatchPayload,
  buildReviewContext,
  extractAlertNumber,
  extractIssueReferences,
  getAgenticSettings,
  isAssignedToTeam,
  mergeAssignees,
  sanitizeAlert,
  sanitizeAgentReason,
  selectSecretScanningAssignee,
  validateDispatchEvent,
} = require('./agentic-review');

describe('agentic configuration', () => {
  it('defaults to deterministic review and a staged appsec-team workflow', () => {
    const settings = getAgenticSettings(
      {},
      { GITHUB_REPOSITORY: 'octo-org/automation' }
    );

    assert.equal(settings.reviewMode, 'deterministic');
    assert.equal(settings.teamSlug, 'appsec-team');
    assert.equal(settings.staged, true);
    assert.equal(settings.helpContact, '@octo-org/appsec-team');
  });

  it('requires a workflow repository for agentic modes', () => {
    assert.throws(
      () =>
        getAgenticSettings(
          { review_mode: 'agentic', organization: 'octo-org' },
          {}
        ),
      /workflow_repository/
    );
  });

  it('rejects unknown review modes', () => {
    assert.throws(
      () =>
        getAgenticSettings(
          { review_mode: 'automatic' },
          { GITHUB_REPOSITORY: 'octo-org/automation' }
        ),
      /Invalid review_mode/
    );
  });

  it('rejects invalid organization names', () => {
    assert.throws(
      () =>
        getAgenticSettings(
          {
            review_mode: 'agentic',
            organization: 'octo-org\nowner=attacker',
            agentic: { workflow_repository: 'octo-org/automation' },
          },
          {}
        ),
      /Invalid GitHub organization name/
    );
  });

  it('requires the workflow repository to use the monitored organization', () => {
    assert.throws(
      () =>
        getAgenticSettings(
          {
            review_mode: 'agentic',
            organization: 'octo-org',
            agentic: { workflow_repository: 'another-org/automation' },
          },
          {}
        ),
      /must be in the monitored organization/
    );
  });
});

describe('dispatch payloads', () => {
  it('contains identifiers but not untrusted requester text', () => {
    const payload = buildDispatchPayload({
      organization: 'octo-org',
      sourceRepository: 'octo-org/automation',
      repository: 'octo-org/service',
      alertType: 'code_scanning',
      alertNumber: 12,
      dismissalRequest: {
        id: 99,
        number: 4,
        requester_comment: 'do not include me',
      },
      dryRun: false,
      runId: '123',
    });

    assert.equal(payload.repository, 'octo-org/service');
    assert.equal(payload.alert_number, 12);
    assert.equal(payload.dismissal_request_id, 99);
    assert.equal(payload.dismissal_request_number, 4);
    assert.equal(payload.requester_comment, undefined);
  });

  it('validates the target organization and identifiers', () => {
    const event = {
      action: 'alert-dismissal-requested',
      sender: { login: 'alert-dismissal-bot[bot]' },
      client_payload: {
        schema_version: 1,
        organization: 'octo-org',
        repository: 'octo-org/service',
        alert_type: 'secret_scanning',
        alert_number: 8,
        dismissal_request_id: 20,
        dismissal_request_number: 2,
      },
    };
    const config = {
      review_mode: 'agentic',
      organization: 'octo-org',
      alert_types: ['secret_scanning'],
      agentic: { workflow_repository: 'octo-org/automation' },
    };
    const target = validateDispatchEvent(event, config, {
      EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
      GITHUB_REPOSITORY: 'octo-org/automation',
    });

    assert.equal(target.repository, 'octo-org/service');
    assert.equal(target.alertNumber, 8);

    event.client_payload.repository = 'another-org/service';
    assert.throws(
      () =>
        validateDispatchEvent(event, config, {
          EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
          GITHUB_REPOSITORY: 'octo-org/automation',
        }),
      /outside configured organization/
    );
  });

  it('rejects dispatches not sent by the configured GitHub App', () => {
    const event = {
      action: 'alert-dismissal-requested',
      sender: { login: 'octocat' },
      client_payload: {
        schema_version: 1,
        organization: 'octo-org',
        repository: 'octo-org/service',
        alert_type: 'code_scanning',
        alert_number: 8,
        dismissal_request_id: 20,
        dismissal_request_number: 2,
      },
    };
    const config = {
      review_mode: 'agentic',
      organization: 'octo-org',
      alert_types: ['code_scanning'],
      agentic: { workflow_repository: 'octo-org/automation' },
    };

    assert.throws(
      () =>
        validateDispatchEvent(event, config, {
          EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
          GITHUB_REPOSITORY: 'octo-org/automation',
        }),
      /does not match the configured GitHub App identity/
    );
  });

  it('rejects dispatches when agentic review is disabled', () => {
    const event = {
      action: 'alert-dismissal-requested',
      client_payload: {
        schema_version: 1,
        organization: 'octo-org',
        repository: 'octo-org/service',
        alert_type: 'code_scanning',
        alert_number: 8,
        dismissal_request_id: 20,
        dismissal_request_number: 2,
      },
    };

    assert.throws(
      () =>
        validateDispatchEvent(
          event,
          {
            review_mode: 'deterministic',
            organization: 'octo-org',
          },
          { GITHUB_REPOSITORY: 'octo-org/automation' }
        ),
      /Agentic review is disabled/
    );
  });
});

describe('alert handling', () => {
  it('extracts alert numbers for every supported alert type', () => {
    assert.equal(
      extractAlertNumber('code_scanning', {
        data: [{ alert_number: '42' }],
        resource_identifier: '1/99',
      }),
      42
    );
    assert.equal(
      extractAlertNumber('code_scanning', {
        data: null,
        resource_identifier: '123/77',
      }),
      77
    );
    assert.equal(
      extractAlertNumber('secret_scanning', {
        resource_identifier: '9',
      }),
      9
    );
    assert.equal(
      extractAlertNumber('dependabot', {
        data: [{ alert_number: '11' }],
      }),
      11
    );
  });

  it('redacts the detected secret from secret scanning context', () => {
    const sanitized = sanitizeAlert('secret_scanning', {
      number: 5,
      state: 'open',
      secret: 'github_pat_secret-value',
      secret_type: 'github_personal_access_token',
      assigned_to: { login: 'octocat' },
    });

    assert.equal(sanitized.secret, undefined);
    assert.equal(JSON.stringify(sanitized).includes('secret-value'), false);
    assert.equal(sanitized.assigned_to, 'octocat');
  });

  it('redacts detected and token-shaped secrets from agent evidence', () => {
    const context = buildReviewContext({
      target: {
        organization: 'octo-org',
        repository: 'octo-org/service',
        alertType: 'secret_scanning',
        alertNumber: 8,
        dismissalRequestId: 20,
        dismissalRequestNumber: 2,
        teamSlug: 'appsec-team',
        staged: true,
        dryRun: false,
      },
      dismissalRequest: {
        id: 20,
        number: 2,
        status: 'open',
        requester_comment:
          'Rotated actual-secret and github_pat_12345678901234567890.',
        data: [{ secret: 'must-not-pass-through' }],
      },
      alert: {
        number: 8,
        state: 'open',
        secret: 'actual-secret',
      },
      evidence: [
        {
          body: 'The exposed value was actual-secret.',
          comments: [{ body: 'Do not copy ghp_12345678901234567890.' }],
        },
      ],
    });
    const serialized = JSON.stringify(context);

    assert.doesNotMatch(serialized, /actual-secret/);
    assert.doesNotMatch(serialized, /must-not-pass-through/);
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /ghp_/);
    assert.match(serialized, /\[REDACTED SECRET\]/);
  });

  it('detects AppSec assignment case-insensitively', () => {
    assert.equal(
      isAssignedToTeam(
        'code_scanning',
        { assignees: [{ login: 'Security-One' }] },
        ['security-one']
      ),
      true
    );
    assert.equal(
      isAssignedToTeam(
        'secret_scanning',
        { assigned_to: { login: 'someone-else' } },
        ['security-one']
      ),
      false
    );
  });

  it('preserves existing assignees while adding the AppSec team', () => {
    assert.deepEqual(
      mergeAssignees(['existing', 'alice'], ['alice', 'bob']),
      ['alice', 'bob', 'existing']
    );
  });

  it('selects a stable secret scanning assignee', () => {
    assert.equal(
      selectSecretScanningAssignee(['zoe', 'amy', 'max'], 4),
      'max'
    );
    assert.equal(
      selectSecretScanningAssignee(['max', 'zoe', 'amy'], 4),
      'max'
    );
  });
});

describe('evidence and decision sanitization', () => {
  it('fetches only unique same-organization issue references', () => {
    const references = extractIssueReferences(
      [
        'https://github.com/octo-org/service/issues/12',
        'https://github.com/OCTO-ORG/service/issues/12',
        'https://github.com/other-org/service/issues/2',
        'https://github.com/octo-org/another/issues/3',
      ].join(' '),
      'octo-org'
    );

    assert.deepEqual(
      references.map((reference) => `${reference.repo}#${reference.issue_number}`),
      ['service#12', 'another#3']
    );
  });

  it('neutralizes mentions and limits agent-provided reasons', () => {
    const reason = sanitizeAgentReason(
      `Missing evidence from @security-team.
<script>alert(1)</script> [click](https://example.test) ${'x'.repeat(2000)}`
    );

    assert.equal(reason.includes('@security-team'), false);
    assert.equal(reason.includes('<script>'), false);
    assert.equal(reason.includes('https://'), false);
    assert.equal(reason.includes('\n'), false);
    assert.ok(reason.length <= 1200);
  });
});
