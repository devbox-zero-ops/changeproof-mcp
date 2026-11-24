import {
  analyzeSopBlastRadius,
  appendAuditEntry,
  assessChangeControl,
  extractControlledDocCodes,
  generateAuditPacket,
  getStandardProfile,
  verifyAuditChain,
  verifySeparationOfDuties,
} from '../core/complianceEngine.js';

function unwrapPayload(event) {
  if (!event || typeof event !== 'object') return {};
  if (event.payload && typeof event.payload === 'object') return event.payload;
  return event;
}

/**
 * Factory producing all 6 rovo:mcp / rovo:agent tool handlers and UI Kit helpers
 * backed by an injected Atlassian/KVS adapter (enabling zero-network unit/E2E testing).
 */
export function createToolHandlers(adapter) {
  async function assessChangeControlTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    if (!issueKey) {
      return { ok: false, error: 'issueKey is required.' };
    }

    const savedStd = await adapter.getSelectedStandard(issueKey);
    const standardCode = getStandardProfile(p.standardCode || savedStd).code;
    if (p.standardCode && p.standardCode !== savedStd) {
      await adapter.saveSelectedStandard(issueKey, standardCode);
    }

    const issue = await adapter.getJiraIssue(issueKey);
    const [confluencePages, graphLinks, auditEntries, capaRecords] = await Promise.all([
      adapter.searchConfluenceSops(issue),
      adapter.getTeamworkGraphLinks(issueKey, issue.id),
      adapter.getAuditChain(issueKey),
      adapter.getCapaRecords(issueKey),
    ]);

    const fmea = {};
    if (p.severity !== undefined) fmea.severity = Number(p.severity);
    if (p.occurrence !== undefined) fmea.occurrence = Number(p.occurrence);
    if (p.detectability !== undefined) fmea.detectability = Number(p.detectability);

    const assessment = assessChangeControl({
      issue,
      standardCode,
      fmea,
      confluencePages,
      graphLinks,
      auditEntries,
      signoffs: {
        proposerAccountId: issue.reporterAccountId || undefined,
      },
      capaRecords,
    });

    return {
      ok: true,
      tool: 'assess-change-control',
      issueKey,
      standardCode,
      assessment,
    };
  }

  async function scanSopBlastRadiusTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    if (!issueKey) {
      return { ok: false, error: 'issueKey is required.' };
    }

    const standardCode = getStandardProfile(
      p.standardCode || (await adapter.getSelectedStandard(issueKey)),
    ).code;
    const issue = await adapter.getJiraIssue(issueKey);
    const [confluencePages, graphLinks] = await Promise.all([
      adapter.searchConfluenceSops(issue),
      adapter.getTeamworkGraphLinks(issueKey, issue.id),
    ]);

    const blastRadius = analyzeSopBlastRadius({
      issue,
      confluencePages,
      graphLinks,
      standardCode,
    });

    return {
      ok: true,
      tool: 'scan-sop-blast-radius',
      issueKey,
      standardCode,
      blastRadius,
    };
  }

  async function verifyDualSignoffTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    if (!issueKey) {
      return { ok: false, error: 'issueKey is required.' };
    }

    const role = String(p.role || '').trim().toUpperCase();
    const decision = String(p.decision || 'APPROVED').trim().toUpperCase();
    const rationale = String(p.rationale || '').trim();
    if (!['PROPOSER', 'QA_APPROVER', 'RELEASE_AUTHORITY'].includes(role)) {
      return {
        ok: false,
        error: 'role must be PROPOSER, QA_APPROVER, or RELEASE_AUTHORITY.',
      };
    }
    if (!['APPROVED', 'REJECTED', 'CONDITIONAL'].includes(decision)) {
      return {
        ok: false,
        error: 'decision must be APPROVED, REJECTED, or CONDITIONAL.',
      };
    }
    if (rationale.length < 6) {
      return {
        ok: false,
        error: 'rationale must provide an auditable objective justification (>= 6 chars).',
      };
    }

    const standardCode = getStandardProfile(
      p.standardCode || (await adapter.getSelectedStandard(issueKey)),
    ).code;
    const [actor, issue, existingChain, capaRecords] = await Promise.all([
      adapter.getCurrentActor({ ...context, accountId: p.actorAccountId || context.accountId }),
      adapter.getJiraIssue(issueKey),
      adapter.getAuditChain(issueKey),
      adapter.getCapaRecords(issueKey),
    ]);

    // Pre-check existing chain integrity before appending
    const preCheck = verifyAuditChain(existingChain);
    if (!preCheck.valid) {
      return {
        ok: false,
        error: 'Refusing to append sign-off: existing SHA-256 audit chain is tampered.',
        chainVerification: preCheck,
      };
    }

    // Compute current assessment to know RPN and existing actors
    const baseAssessment = assessChangeControl({
      issue,
      standardCode,
      auditEntries: existingChain,
      signoffs: { proposerAccountId: issue.reporterAccountId || undefined },
      capaRecords,
    });

    const candidateActors = {
      proposerAccountId: baseAssessment.separationOfDuties.actors.proposerAccountId,
      qaApproverAccountId: baseAssessment.separationOfDuties.actors.qaApproverAccountId,
      releaseAuthorityAccountId:
        baseAssessment.separationOfDuties.actors.releaseAuthorityAccountId,
    };

    if (role === 'PROPOSER') candidateActors.proposerAccountId = actor.accountId;
    if (role === 'QA_APPROVER') candidateActors.qaApproverAccountId = actor.accountId;
    if (role === 'RELEASE_AUTHORITY') candidateActors.releaseAuthorityAccountId = actor.accountId;

    // Enforce separation-of-duties BEFORE writing an APPROVED attestation
    const sodCheck = verifySeparationOfDuties({
      ...candidateActors,
      rpn: baseAssessment.rpn.rpn,
      standardCode,
    });

    const conflictViolations = (sodCheck.violations || []).filter((v) =>
      String(v.code || '').includes('CONFLICT') || String(v.code || '').includes('SELF'),
    );
    if (decision === 'APPROVED' && conflictViolations.length > 0) {
      return {
        ok: false,
        rejectedBySeparationOfDuties: true,
        error: `Separation-of-duties violation: ${conflictViolations.map((v) => v.message).join(' ')}`,
        separationOfDuties: sodCheck,
      };
    }

    const chainAction =
      decision === 'APPROVED'
        ? role === 'QA_APPROVER'
          ? 'APPROVE_QA'
          : role === 'RELEASE_AUTHORITY'
            ? 'APPROVE_RELEASE'
            : 'PROPOSE_CHANGE'
        : `SIGNOFF_${decision}`;

    const { entry: latestEntry, entries: updatedChain } = appendAuditEntry(existingChain, {
      issueKey,
      actorAccountId: actor.accountId,
      actorDisplayName: actor.displayName,
      role,
      action: chainAction,
      standard: standardCode,
      rationale,
      metadata: {
        decision,
        rpn: baseAssessment.rpn.rpn,
        issueStatus: issue.status,
      },
    });

    await adapter.saveAuditChain(issueKey, updatedChain);
    const postVerify = verifyAuditChain(updatedChain);

    await adapter.postJiraAuditComment(
      issueKey,
      `[ChangeProof MCP] ${role} ${decision} by ${actor.displayName} (${standardCode}) | Entry #${latestEntry.seq} SHA-256: ${latestEntry.entryHash.slice(0, 16)}... | Rationale: ${rationale}`,
    );

    return {
      ok: true,
      tool: 'verify-dual-signoff',
      issueKey,
      standardCode,
      entry: latestEntry,
      separationOfDuties: sodCheck,
      chainVerification: postVerify,
    };
  }

  async function generateAuditPacketTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    if (!issueKey) {
      return { ok: false, error: 'issueKey is required.' };
    }

    const assessmentRes = await assessChangeControlTool(
      { issueKey, standardCode: p.standardCode },
      context,
    );
    if (!assessmentRes.ok) return assessmentRes;

    const [actor, auditEntries, capaRecords] = await Promise.all([
      adapter.getCurrentActor(context),
      adapter.getAuditChain(issueKey),
      adapter.getCapaRecords(issueKey),
    ]);

    const packet = generateAuditPacket({
      assessment: assessmentRes.assessment,
      auditEntries,
      capaRecords,
      generatedBy: actor.displayName || actor.accountId,
    });

    return {
      ok: true,
      tool: 'generate-audit-packet',
      issueKey,
      packetId: packet.packetId,
      packetDigest: packet.packetDigest,
      markdown: packet.markdown,
      dossier: packet.dossier,
    };
  }

  async function verifyAuditChainTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    if (!issueKey) {
      return { ok: false, error: 'issueKey is required.' };
    }

    const entries = await adapter.getAuditChain(issueKey);
    const verification = verifyAuditChain(entries);
    return {
      ok: true,
      tool: 'verify-audit-chain',
      issueKey,
      verification,
      entryCount: entries.length,
    };
  }

  async function logCapaDeviationTool(event, context = {}) {
    const p = unwrapPayload(event);
    const issueKey = String(p.issueKey || context.extension?.issue?.key || '').trim().toUpperCase();
    const capaId = String(p.capaId || '').trim().toUpperCase();
    const severity = String(p.severity || 'MAJOR').trim().toUpperCase();
    const rootCause = String(p.rootCause || '').trim();
    const containmentAction = String(p.containmentAction || '').trim();

    if (!issueKey || !capaId || !rootCause || !containmentAction) {
      return {
        ok: false,
        error: 'issueKey, capaId, rootCause, and containmentAction are all required.',
      };
    }

    const standardCode = getStandardProfile(
      p.standardCode || (await adapter.getSelectedStandard(issueKey)),
    ).code;
    const [actor, existingCapa, existingChain] = await Promise.all([
      adapter.getCurrentActor({ ...context, accountId: p.actorAccountId || context.accountId }),
      adapter.getCapaRecords(issueKey),
      adapter.getAuditChain(issueKey),
    ]);

    const record = {
      capaId,
      severity: ['CRITICAL', 'MAJOR', 'MINOR'].includes(severity) ? severity : 'MAJOR',
      rootCause,
      containmentAction,
      loggedBy: actor.accountId,
      loggedAt: new Date().toISOString(),
      status: 'OPEN',
    };

    const nextCapa = [...existingCapa, record];
    const { entry: capaEntry, entries: nextChain } = appendAuditEntry(existingChain, {
      issueKey,
      actorAccountId: actor.accountId,
      actorDisplayName: actor.displayName,
      role: 'QA_ENGINEER',
      action: 'CAPA_DEVIATION_LOGGED',
      standard: standardCode,
      rationale: `${capaId} (${record.severity}): ${rootCause}`,
      metadata: record,
    });

    await Promise.all([
      adapter.saveCapaRecords(issueKey, nextCapa),
      adapter.saveAuditChain(issueKey, nextChain),
      adapter.postJiraAuditComment(
        issueKey,
        `[ChangeProof MCP] Logged ${capaId} (${record.severity}) | Root Cause: ${rootCause} | Containment: ${containmentAction} | Chain #${nextChain.length} SHA-256: ${capaEntry.entryHash.slice(0, 16)}...`,
      ),
    ]);

    return {
      ok: true,
      tool: 'log-capa-deviation',
      issueKey,
      capaRecord: record,
      totalCapaCount: nextCapa.length,
      chainHeadHash: capaEntry.entryHash,
    };
  }

  async function inspectConfluenceSopImpact(pageId) {
    const page = await adapter.getConfluencePage(pageId);
    const docCodes = extractControlledDocCodes(`${page.title} ${page.bodyText}`);
    const queryToken = docCodes[0] || page.title.split(/\s+/).slice(0, 3).join(' ');
    const linkedChanges = await adapter.searchJiraIssuesByText(queryToken);
    return {
      ok: true,
      page: {
        id: page.id,
        title: page.title,
        version: page.version,
        lastUpdated: page.lastUpdated,
        docCodes,
      },
      linkedChanges,
      activeChangeCount: linkedChanges.filter((c) => !/done|closed|resolved/i.test(c.status)).length,
    };
  }

  return {
    assessChangeControlTool,
    scanSopBlastRadiusTool,
    verifyDualSignoffTool,
    generateAuditPacketTool,
    verifyAuditChainTool,
    logCapaDeviationTool,
    inspectConfluenceSopImpact,
  };
}
