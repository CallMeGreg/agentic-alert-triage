'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  assignAlertToTeam,
  buildDispatchPayload,
  buildReviewContext,
  DEFAULT_WORKFLOW_REPOSITORY,
  extractIssueReferences,
  getAgenticSettings,
  getAlert,
  isAssignedToTeam,
  isStaleDismissalReviewError,
  mergeAssignees,
  sanitizeAlert,
  sanitizeAgentReason,
  selectSecretScanningAssignee,
  validateDispatchEvent,
} = require('./agentic-review');

const WORKFLOW_REPOSITORY = 'CallMeGreg/agentic-alert-triage';

function agenticConfig(overrides = {}) {
  return {
    review_mode: 'agentic',
    organization: 'octo-org',
    alert_types: ['code_scanning', 'secret_scanning', 'dependabot'],
    agentic: {
      workflow_repository: WORKFLOW_REPOSITORY,
      ...overrides,
    },
  };
}

function createDispatchEvent(overrides = {}) {
  return {
    action: 'alert-dismissal-requested',
    repository: { full_name: WORKFLOW_REPOSITORY },
    sender: { login: 'alert-dismissal-bot[bot]' },
    client_payload: {
      schema_version: 1,
      target: {
        organization: 'octo-org',
        repository: 'octo-org/service',
        repository_id: 101,
        alert_type: 'code_scanning',
        alert_number: 8,
        dismissal_request_id: 20,
        dismissal_request_number: 2,
      },
      request: {
        id: 20,
        number: 2,
        repository_id: 101,
        status: 'open',
        request_type: 'dismiss',
        exemption_request_data_type: 'code_scanning_alert_dismissal',
        requester: { actor_name: 'octocat' },
        requester_comment: 'The finding is limited to test code.',
        dismissal_reasons: ['tests'],
      },
      review: {
        appsec_team_members: ['security-one', 'security-two'],
      },
      source: {
        repository: WORKFLOW_REPOSITORY,
        webhook_event: 'dismissal_request_code_scanning',
        delivery_id: 'delivery-123',
        installation_id: 44,
      },
      dry_run: false,
      ...overrides,
    },
  };
}

function validationEnv() {
  return {
    EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
    GITHUB_REPOSITORY: WORKFLOW_REPOSITORY,
  };
}

describe('agentic configuration', () => {
  it('defaults to deterministic review and the central workflow repository', () => {
    const settings = getAgenticSettings({}, {});

    assert.equal(settings.reviewMode, 'deterministic');
    assert.equal(settings.teamSlug, 'appsec-team');
    assert.equal(settings.workflowRepository, DEFAULT_WORKFLOW_REPOSITORY);
    assert.equal(settings.staged, true);
    assert.equal(settings.helpContact, '@appsec-team');
  });

  it('requires a trusted organization for agentic modes', () => {
    assert.throws(
      () => getAgenticSettings({ review_mode: 'agentic' }, {}),
      /requires organization/
    );
  });

  it('allows the control repository to use a different owner', () => {
    const settings = getAgenticSettings(
      {
        review_mode: 'agentic',
        organization: 'octo-org',
        agentic: { workflow_repository: 'control-owner/automation' },
      },
      {}
    );

    assert.equal(settings.workflowRepository, 'control-owner/automation');
  });

  it('rejects unknown review modes and invalid trusted identifiers', () => {
    assert.throws(
      () => getAgenticSettings({ review_mode: 'automatic' }, {}),
      /Invalid review_mode/
    );
    assert.throws(
      () =>
        getAgenticSettings(
          {
            review_mode: 'agentic',
            organization: 'octo-org\nowner=attacker',
          },
          {}
        ),
      /Invalid GitHub organization/
    );
    assert.throws(
      () =>
        getAgenticSettings(
          {
            agentic: { appsec_team_slug: '../appsec' },
          },
          {}
        ),
      /Invalid AppSec team slug/
    );
  });
});

describe('dispatch payloads', () => {
  it('contains a sanitized request, source provenance, and team snapshot', () => {
    const payload = buildDispatchPayload({
      organization: 'octo-org',
      sourceRepository: WORKFLOW_REPOSITORY,
      repository: 'octo-org/service',
      repositoryId: 101,
      alertType: 'code_scanning',
      alertNumber: 12,
      dismissalRequest: {
        id: 99,
        number: 4,
        repository_id: 101,
        requester_id: 55,
        requester_login: 'octocat',
        request_type: 'dismiss',
        status: 'open',
        requester_comment:
          'Rotated github_pat_12345678901234567890 and documented the result.',
        exemption_request_data: {
          type: 'code_scanning_alert_dismissal',
          data: [{ alert_number: 12, reason: 'revoked', secret: 'omit-me' }],
        },
        metadata: { untrusted: 'omit-me-too' },
        responses: [{ body: 'opaque' }],
      },
      teamLogins: ['security-two', 'security-one'],
      webhookEvent: 'dismissal_request_code_scanning',
      deliveryId: 'delivery-123',
      installationId: 44,
    });

    assert.equal(payload.schema_version, 1);
    assert.equal(payload.target.repository, 'octo-org/service');
    assert.equal(payload.target.repository_id, 101);
    assert.equal(payload.target.alert_number, 12);
    assert.equal(payload.request.id, 99);
    assert.equal(
      payload.request.exemption_request_data_type,
      'code_scanning_alert_dismissal'
    );
    assert.deepEqual(payload.request.dismissal_reasons, ['revoked']);
    assert.deepEqual(payload.review.appsec_team_members, [
      'security-one',
      'security-two',
    ]);
    assert.deepEqual(payload.source, {
      repository: WORKFLOW_REPOSITORY,
      webhook_event: 'dismissal_request_code_scanning',
      installation_id: 44,
      delivery_id: 'delivery-123',
    });
    const serialized = JSON.stringify(payload);
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /omit-me/);
    assert.doesNotMatch(serialized, /responses/);
    assert.ok(serialized.length <= 60000);
  });

  it('rejects inconsistent event, request type, and repository identity', () => {
    const base = {
      organization: 'octo-org',
      sourceRepository: WORKFLOW_REPOSITORY,
      repository: 'octo-org/service',
      repositoryId: 101,
      alertType: 'code_scanning',
      alertNumber: 12,
      dismissalRequest: {
        id: 99,
        number: 4,
        repository_id: 101,
        requester_login: 'octocat',
        request_type: 'dismiss',
        status: 'open',
        exemption_request_data: {
          type: 'code_scanning_alert_dismissal',
          data: [{ alert_number: 12 }],
        },
      },
      teamLogins: ['security-one'],
      webhookEvent: 'dismissal_request_code_scanning',
      installationId: 44,
    };

    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          webhookEvent: 'dismissal_request_dependabot',
        }),
      /does not match alert type/
    );
    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          dismissalRequest: {
            ...base.dismissalRequest,
            exemption_request_data: {
              type: 'dependabot_alert_dismissal',
              data: [{ alert_number: 12 }],
            },
          },
        }),
      /does not match alert type/
    );
    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          repository: 'another-org/service',
        }),
      /outside organization/
    );
  });

  it('validates dispatch targets and source provenance', () => {
    const event = createDispatchEvent();
    const target = validateDispatchEvent(
      event,
      agenticConfig(),
      validationEnv()
    );

    assert.equal(target.repository, 'octo-org/service');
    assert.equal(target.repositoryId, 101);
    assert.equal(target.alertNumber, 8);
    assert.equal(target.dismissalRequest.requester.actor_name, 'octocat');
    assert.equal(target.webhookEvent, 'dismissal_request_code_scanning');
    assert.equal(target.deliveryId, 'delivery-123');
    assert.equal(target.sourceInstallationId, 44);
    assert.deepEqual(target.teamLogins, [
      'security-one',
      'security-two',
    ]);

    event.client_payload.target.repository = 'another-org/service';
    assert.throws(
      () =>
        validateDispatchEvent(event, agenticConfig(), validationEnv()),
      /outside configured organization/
    );
  });

  it('rejects an unexpected sender, source event, or request data type', () => {
    const wrongSender = createDispatchEvent();
    wrongSender.sender.login = 'octocat';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongSender,
          agenticConfig(),
          validationEnv()
        ),
      /does not match the configured GitHub App identity/
    );

    const wrongEvent = createDispatchEvent();
    wrongEvent.client_payload.source.webhook_event =
      'dismissal_request_dependabot';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongEvent,
          agenticConfig(),
          validationEnv()
        ),
      /webhook event does not match/
    );

    const wrongType = createDispatchEvent();
    wrongType.client_payload.request.exemption_request_data_type =
      'dependabot_alert_dismissal';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongType,
          agenticConfig(),
          validationEnv()
        ),
      /snapshot type does not match/
    );
  });

  it('rejects dispatches when agentic review or the alert type is disabled', () => {
    assert.throws(
      () =>
        validateDispatchEvent(
          createDispatchEvent(),
          { review_mode: 'deterministic', organization: 'octo-org' },
          validationEnv()
        ),
      /Agentic review is disabled/
    );
    assert.throws(
      () =>
        validateDispatchEvent(
          createDispatchEvent(),
          {
            ...agenticConfig(),
            alert_types: ['secret_scanning'],
          },
          validationEnv()
        ),
      /not enabled/
    );
  });
});

describe('alert handling', () => {
  it('always hides secret values when reading secret scanning alerts', async () => {
    const requests = [];
    const octokit = {
      request: async (endpoint, parameters) => {
        requests.push({ endpoint, parameters });
        return { data: { number: parameters.alert_number } };
      },
    };

    await getAlert(octokit, 'octo-org', 'service', 'secret_scanning', 5);
    await getAlert(octokit, 'octo-org', 'service', 'code_scanning', 6);

    assert.equal(requests[0].parameters.hide_secret, true);
    assert.equal(
      Object.hasOwn(requests[1].parameters, 'hide_secret'),
      false
    );
  });

  it('redacts secret scanning values from alert context', () => {
    const sanitized = sanitizeAlert('secret_scanning', {
      number: 5,
      state: 'open',
      secret: 'github_pat_secret-value',
      secret_type: 'github_personal_access_token',
      assigned_to: { login: 'octocat' },
    });

    assert.equal(sanitized.secret, undefined);
    assert.doesNotMatch(JSON.stringify(sanitized), /secret-value/);
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
        webhookEvent: 'dismissal_request_secret_scanning',
        deliveryId: 'delivery-123',
        sourceInstallationId: 44,
      },
      dismissalRequest: {
        id: 20,
        number: 2,
        repository_id: 101,
        requester_login: 'octocat',
        status: 'open',
        request_type: 'dismiss',
        requester_comment:
          'Rotated actual-secret and github_pat_12345678901234567890.',
        exemption_request_data: {
          type: 'secret_scanning_closure',
          data: [{ alert_number: 8, secret: 'must-not-pass-through' }],
        },
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
    assert.deepEqual(context.source, {
      webhook_event: 'dismissal_request_secret_scanning',
      delivery_id: 'delivery-123',
      installation_id: 44,
    });
  });

  it('detects AppSec assignment and preserves existing assignees', () => {
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

  it('assigns snapshotted team members without collaborator reads', async () => {
    const requests = [];
    const octokit = {
      request: async (endpoint, parameters) => {
        requests.push({ endpoint, parameters });
        return { data: {} };
      },
    };

    const result = await assignAlertToTeam({
      octokit,
      owner: 'octo-org',
      repo: 'service',
      organization: 'octo-org',
      teamSlug: 'appsec-team',
      alertType: 'code_scanning',
      alertNumber: 8,
      alert: { assignees: [{ login: 'existing' }] },
      teamMembers: ['security-one', 'security-two'],
    });

    assert.deepEqual(result.assigned, ['security-one', 'security-two']);
    assert.equal(requests.length, 1);
    assert.equal(
      requests[0].endpoint,
      'PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}'
    );
    assert.deepEqual(requests[0].parameters.assignees, [
      'existing',
      'security-one',
      'security-two',
    ]);
  });

  it('surfaces alert assignment endpoint failures', async () => {
    await assert.rejects(
      assignAlertToTeam({
        octokit: {
          request: async () => {
            throw new Error('assignment rejected');
          },
        },
        owner: 'octo-org',
        repo: 'service',
        organization: 'octo-org',
        teamSlug: 'appsec-team',
        alertType: 'dependabot',
        alertNumber: 8,
        alert: { assignees: [] },
        teamMembers: ['security-one'],
      }),
      /assignment rejected/
    );
  });
});

describe('evidence and decision sanitization', () => {
  it('extracts only unique same-organization issue references', () => {
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
      references.map(
        (reference) => `${reference.repo}#${reference.issue_number}`
      ),
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

  it('only treats known stale optimistic-write errors as no-ops', () => {
    assert.equal(isStaleDismissalReviewError({ status: 404 }), true);
    assert.equal(
      isStaleDismissalReviewError({
        status: 422,
        response: { data: { message: 'Request already completed' } },
      }),
      true
    );
    assert.equal(
      isStaleDismissalReviewError({
        status: 422,
        response: { data: { message: 'Validation failed' } },
      }),
      false
    );
  });
});
