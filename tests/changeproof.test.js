import test from 'node:test';
import assert from 'node:assert/strict';
import {
  appendAuditEntry,
  assessChangeControl,
  calculateRpn,
  verifyAuditChain,
  verifySeparationOfDuties,
} from '../src/core/complianceEngine.js';
import { createToolHandlers } from '../src/mcp/tools.js';

function createMockAdapter() {
  const chains = new Map();
  const capas = new Map();
  const standards = new Map();
  const comments = [];

  const mockIssue = {
    key: 'QMS-42',
    id: '10042',
    summary: 'Update Sterile Fill Sensor Calibration Tolerance per SOP-QA-104 and WI-MFG-22',
    description:
      'Severity: 8, Occurrence: 4, Detectability: 3. Addresses CAPA-2026-009 with full IQ/OQ validation plan and rollback procedure.',
    status: 'In Review',
    priority: 'High',
    issueType: 'Change Request',
    labels: ['21cfr11', 'validation-required'],
    reporterAccountId: 'acct-proposer-01',
    reporterName: 'Dr. Elena Vance',
    assigneeAccountId: 'acct-eng-02',
    assigneeName: 'Marcus Chen',
    comments: [
      {
        id: 'c-1',
        authorAccountId: 'acct-eng-02',
        body: 'Rollback plan verified on line B; impacted SOP-QA-104 and SOP-VAL-019.',
      },
    ],
    issueLinks: [],
  };

  const mockSops = [
    {
      id: '9001',
      title: 'SOP-QA-104 Sterile Fill Calibration Standard Operating Procedure',
      excerpt: 'Defines calibration tolerances, sensor drift thresholds, and 21 CFR Part 11 logs.',
      version: 6,
      lastUpdated: '2024-01-10T00:00:00.000Z', // stale > 365d
      labels: ['controlled-sop', 'gmp'],
      url: '/spaces/QMS/pages/9001',
    },
    {
      id: '9002',
      title: 'WI-MFG-22 Line B Sensor Calibration Work Instruction',
      excerpt: 'Step-by-step technician verification procedure for fill line sensors.',
      version: 3,
      lastUpdated: '2026-10-01T00:00:00.000Z',
      labels: ['work-instruction'],
      url: '/spaces/MFG/pages/9002',
    },
  ];

  const mockGraphLinks = [
    {
      id: '9001',
      relationship: 'impacts',
      title: 'SOP-QA-104 Sterile Fill Calibration Standard Operating Procedure',
      url: '/spaces/QMS/pages/9001',
      source: 'teamwork-cross-reference',
    },
  ];

  return {
    comments,
    chains,
    async getCurrentActor(ctx = {}) {
      const id = ctx.accountId || 'acct-qa-09';
      return { accountId: id, displayName: `User ${id}` };
    },
    async getJiraIssue(key) {
      return { ...mockIssue, key };
    },
    async getTeamworkGraphLinks() {
      return mockGraphLinks;
    },
    async searchConfluenceSops() {
      return mockSops;
    },
    async getConfluencePage(id) {
      return {
        id: String(id || '9001'),
        title: mockSops[0].title,
        bodyText: mockSops[0].excerpt,
        version: mockSops[0].version,
        lastUpdated: mockSops[0].lastUpdated,
        labels: mockSops[0].labels,
      };
    },
    async searchJiraIssuesByText() {
      return [
        {
          key: 'QMS-42',
          summary: mockIssue.summary,
          status: 'In Review',
          priority: 'High',
        },
      ];
    },
    async postJiraAuditComment(issueKey, text) {
      comments.push({ issueKey, text });
      return { posted: true, status: 201 };
    },
    async getAuditChain(issueKey) {
      return chains.get(issueKey) || [];
    },
    async saveAuditChain(issueKey, entries) {
      chains.set(issueKey, entries);
      return entries;
    },
    async getCapaRecords(issueKey) {
      return capas.get(issueKey) || [];
    },
    async saveCapaRecords(issueKey, recs) {
      capas.set(issueKey, recs);
      return recs;
    },
    async getSelectedStandard(issueKey) {
      return standards.get(issueKey) || 'FDA_21CFR11';
    },
    async saveSelectedStandard(issueKey, std) {
      standards.set(issueKey, std);
      return std;
    },
  };
}

test('evaluates RPN and readiness across all 3 regulated industry standards', () => {
  for (const std of ['FDA_21CFR11', 'ISO_13485', 'AS9100D']) {
    const rpn = calculateRpn({ severity: 8, occurrence: 5, detectability: 3, standardCode: std });
    assert.equal(rpn.rpn, 120);
    assert.equal(rpn.requiresReleaseAuthority, true);

    const assessment = assessChangeControl({
      issue: {
        key: 'CHG-10',
        summary: 'Update SOP-QA-104 control firmware',
        description: 'Validation protocol and rollback plan documented. CAPA-101 linked.',
        reporterAccountId: 'acct-p1',
      },
      standardCode: std,
      fmea: { severity: 8, occurrence: 5, detectability: 3 },
    });
    assert.equal(assessment.standard.code, std);
    assert.ok(assessment.readinessScore >= 0 && assessment.readinessScore <= 100);
  }
});

test('enforces strict separation-of-duties and blocks self-approval', () => {
  const selfApproval = verifySeparationOfDuties({
    proposerAccountId: 'acct-alice',
    qaApproverAccountId: 'acct-alice',
    rpn: 40,
    standardCode: 'FDA_21CFR11',
  });
  assert.equal(selfApproval.compliant, false);
  assert.ok(selfApproval.violations.length >= 1);

  const highRiskMissingRelease = verifySeparationOfDuties({
    proposerAccountId: 'acct-alice',
    qaApproverAccountId: 'acct-bob',
    releaseAuthorityAccountId: null,
    rpn: 96,
    standardCode: 'FDA_21CFR11',
  });
  assert.equal(highRiskMissingRelease.compliant, false);

  const fullTriad = verifySeparationOfDuties({
    proposerAccountId: 'acct-alice',
    qaApproverAccountId: 'acct-bob',
    releaseAuthorityAccountId: 'acct-carol',
    rpn: 96,
    standardCode: 'FDA_21CFR11',
  });
  assert.equal(fullTriad.compliant, true);
});

test('SHA-256 hash chain passes valid sequence and catches 1-byte tampering or reordering', () => {
  let chain = [];
  chain = appendAuditEntry(chain, {
    issueKey: 'QMS-42',
    actorAccountId: 'acct-p1',
    role: 'PROPOSER',
    action: 'CHANGE_SUBMITTED',
    standard: 'FDA_21CFR11',
    rationale: 'Initial change request with IQ/OQ test plan.',
  }).entries;
  chain = appendAuditEntry(chain, {
    issueKey: 'QMS-42',
    actorAccountId: 'acct-qa1',
    role: 'QA_APPROVER',
    action: 'SIGNOFF_APPROVED',
    standard: 'FDA_21CFR11',
    rationale: 'Verified SOP-QA-104 impact and calibration test data.',
  }).entries;

  const valid = verifyAuditChain(chain);
  assert.equal(valid.valid, true);
  assert.equal(valid.status, 'VERIFIED');
  assert.equal(valid.verifiedCount, 2);

  // Tamper 1 character in rationale
  const tampered = structuredClone(chain);
  tampered[0].rationale = tampered[0].rationale + ' ';
  const bad = verifyAuditChain(tampered);
  assert.equal(bad.valid, false);
  assert.equal(bad.status, 'TAMPERED');

  // Reorder entries
  const reordered = [chain[1], chain[0]];
  const badOrder = verifyAuditChain(reordered);
  assert.equal(badOrder.valid, false);
});

test('all 6 rovo:mcp / rovo:agent handlers execute end-to-end with anti-self-approval and dossier export', async () => {
  const adapter = createMockAdapter();
  const tools = createToolHandlers(adapter);

  // 1. assess-change-control
  const assessRes = await tools.assessChangeControlTool({ issueKey: 'QMS-42', standardCode: 'FDA_21CFR11' });
  assert.equal(assessRes.ok, true);
  assert.equal(assessRes.assessment.rpn.rpn, 96);

  // 2. scan-sop-blast-radius
  const sopRes = await tools.scanSopBlastRadiusTool({ issueKey: 'QMS-42' });
  assert.equal(sopRes.ok, true);
  assert.ok(sopRes.blastRadius.referencedCodes.includes('SOP-QA-104'));
  assert.ok(sopRes.blastRadius.referencedCodes.includes('WI-MFG-22'));
  assert.ok(sopRes.blastRadius.impactedDocuments.length >= 2);

  // 3. verify-dual-signoff rejects proposer attempting QA self-approval!
  const blocked = await tools.verifyDualSignoffTool(
    {
      issueKey: 'QMS-42',
      role: 'QA_APPROVER',
      decision: 'APPROVED',
      rationale: 'Attempting self-approval should be rejected.',
      actorAccountId: 'acct-proposer-01',
    },
    { accountId: 'acct-proposer-01' },
  );
  assert.equal(blocked.ok, false);
  assert.equal(blocked.rejectedBySeparationOfDuties, true);

  // Valid QA Approver + independent Release Authority sign-offs succeed
  const qaOk = await tools.verifyDualSignoffTool(
    {
      issueKey: 'QMS-42',
      role: 'QA_APPROVER',
      decision: 'APPROVED',
      rationale: 'Independent QA verified IQ/OQ protocol and SOP-QA-104 redline.',
      actorAccountId: 'acct-qa-09',
    },
    { accountId: 'acct-qa-09' },
  );
  assert.equal(qaOk.ok, true);
  assert.equal(qaOk.entry.seq, 1);

  const relOk = await tools.verifyDualSignoffTool(
    {
      issueKey: 'QMS-42',
      role: 'RELEASE_AUTHORITY',
      decision: 'APPROVED',
      rationale: 'Director of Quality Operations authorized production release.',
      actorAccountId: 'acct-rel-77',
    },
    { accountId: 'acct-rel-77' },
  );
  assert.equal(relOk.ok, true);
  assert.equal(relOk.separationOfDuties.compliant, true);

  // 4. log-capa-deviation
  const capaRes = await tools.logCapaDeviationTool(
    {
      issueKey: 'QMS-42',
      capaId: 'CAPA-2026-014',
      severity: 'MAJOR',
      rootCause: 'Thermal drift on sensor batch #B44 exceeded 0.2C specification.',
      containmentAction: 'Quarantined lot #B44 and recalibrated dual redundant probes.',
      actorAccountId: 'acct-qa-09',
    },
    { accountId: 'acct-qa-09' },
  );
  assert.equal(capaRes.ok, true);
  assert.equal(capaRes.totalCapaCount, 1);

  // 5. verify-audit-chain
  const verifyRes = await tools.verifyAuditChainTool({ issueKey: 'QMS-42' });
  assert.equal(verifyRes.ok, true);
  assert.equal(verifyRes.verification.status, 'VERIFIED');
  assert.equal(verifyRes.entryCount, 3);

  // 6. generate-audit-packet
  const packetRes = await tools.generateAuditPacketTool({ issueKey: 'QMS-42' });
  assert.equal(packetRes.ok, true);
  assert.ok(packetRes.packetDigest.length === 64);
  assert.ok(packetRes.markdown.includes('QMS-42'));
  assert.ok(packetRes.markdown.includes('SOP-QA-104'));
  assert.ok(packetRes.markdown.includes('CAPA-2026-014'));

  // Bonus: Confluence SOP Content Action check
  const confRes = await tools.inspectConfluenceSopImpact('9001');
  assert.equal(confRes.ok, true);
  assert.equal(confRes.activeChangeCount, 1);
});
