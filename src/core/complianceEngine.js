import crypto from 'node:crypto';

export const GENESIS_HASH = '0'.repeat(64);

export const REGULATORY_STANDARDS = Object.freeze({
  FDA_21CFR11: Object.freeze({
    code: 'FDA_21CFR11',
    name: 'FDA 21 CFR Part 11',
    sector: 'Biotech & Clinical GxP',
    citation: '21 CFR §11.10(e), §11.50, §11.70, §11.200; 21 CFR §211.100',
    sopStaleDays: 365,
    highRiskRpnThreshold: 60,
    criticalRiskRpnThreshold: 120,
    minReadinessScore: 85,
    gateWeights: Object.freeze({
      classification: 12,
      riskAssessment: 18,
      validationAndRollback: 18,
      sopImpact: 17,
      capaTraceability: 15,
      dualSignOff: 20,
    }),
    validationTerms: ['iq/oq/pq', 'iq', 'oq', 'pq', 'validation', 'verification', 'protocol', 'gxp', 'test script', 'acceptance criteria'],
  }),
  ISO_13485: Object.freeze({
    code: 'ISO_13485',
    name: 'ISO 13485:2016',
    sector: 'Medical Devices & Diagnostics',
    citation: 'ISO 13485:2016 §4.2.4, §7.3.9, §8.5.2; ISO 14971',
    sopStaleDays: 365,
    highRiskRpnThreshold: 60,
    criticalRiskRpnThreshold: 100,
    minReadinessScore: 85,
    gateWeights: Object.freeze({
      classification: 10,
      riskAssessment: 20,
      validationAndRollback: 18,
      sopImpact: 16,
      capaTraceability: 16,
      dualSignOff: 20,
    }),
    validationTerms: ['verification', 'validation', 'dhf', 'dmr', 'dhr', 'design review', 'traceability', 'test protocol', 'acceptance criteria'],
  }),
  AS9100D: Object.freeze({
    code: 'AS9100D',
    name: 'AS9100D',
    sector: 'Aerospace & Precision Manufacturing',
    citation: 'AS9100D §8.1.2 (Config Mgmt), §8.5.6 (Change Control), §10.2 (Nonconformity)',
    sopStaleDays: 180,
    highRiskRpnThreshold: 60,
    criticalRiskRpnThreshold: 100,
    minReadinessScore: 90,
    gateWeights: Object.freeze({
      classification: 12,
      riskAssessment: 20,
      validationAndRollback: 20,
      sopImpact: 16,
      capaTraceability: 12,
      dualSignOff: 20,
    }),
    validationTerms: ['fai', 'first article', 'as9102', 'qualification', 'verification', 'validation', 'test plan', 'airworthiness', 'acceptance criteria'],
  }),
});

const CONTROLLED_DOC_REGEX = /\b(?:SOP|WI|QMS|DHF|DMR|VAL|FAI|SPEC)-[A-Z0-9]{2,8}-\d{2,5}\b/gi;
const CAPA_ID_REGEX = /\b(?:CAPA|NCR|DEV|SCAR)-\d{2,6}\b/gi;

const DOMAIN_KEYWORDS = Object.freeze({
  sterilization_cleanroom: ['steriliz', 'autoclave', 'cleanroom', 'aseptic', 'bioburden', 'endotoxin', 'gmp'],
  calibration_equipment: ['calibrat', 'sensor', 'thermal', 'chamber', 'bioreactor', 'centrifuge', 'metrology', 'torque'],
  software_csv: ['firmware', 'software', 'csv', '21 cfr', 'audit trail', 'electronic signature', 'lims', 'mes', 'erp', 'patch'],
  clinical_data: ['clinical', 'edc', 'trial', 'patient', 'cohort', 'pharmacovigilance', 'gcp', 'protocol'],
  packaging_labeling: ['label', 'udi', 'packaging', 'barcode', 'ifu', 'insert', 'serialization', 'lot'],
  manufacturing_process: ['batch', 'lot release', 'machining', 'cnc', 'welding', 'assembly', 'tooling', 'first article', 'fai'],
  supplier_quality: ['supplier', 'vendor', 'incoming inspection', 'material cert', 'coa', 'scar', 'raw material'],
  capa_quality: ['capa', 'deviation', 'nonconformity', 'ncr', 'root cause', 'effectiveness check', 'recall', 'complaint'],
  flight_safety: ['avionics', 'flight', 'propulsion', 'actuator', 'airworthiness', 'nadcap', 'as9100', 'traceability'],
});

const CHANGE_CLASS_PATTERNS = [
  { label: 'CRITICAL', regex: /\b(critical change|class\s*1|safety[- ]critical|emergency change|major deviation)\b/i },
  { label: 'MAJOR', regex: /\b(major change|class\s*2|design change|process change|spec change|ecr|eco|ecn|change control|capa)\b/i },
  { label: 'MINOR', regex: /\b(minor change|class\s*3|administrative|editorial|routine update)\b/i },
];

const ROLLBACK_TERMS = [
  'rollback',
  'roll-back',
  'backout',
  'back-out',
  'revert',
  'fallback',
  'contingency',
  'containment',
  'quarantine',
  'recovery plan',
];

const ROOT_CAUSE_TERMS = [
  'root cause',
  '5-why',
  'five why',
  'fishbone',
  'ishikawa',
  'corrective action',
  'preventive action',
  'effectiveness check',
  'nonconformity',
  'deviation',
];

/**
 * Resolves a standard identifier to a validated profile object.
 */
export function getStandardProfile(standardCode = 'FDA_21CFR11') {
  const normalized = String(standardCode || 'FDA_21CFR11').trim().toUpperCase().replace(/[\s-]+/g, '_');
  if (REGULATORY_STANDARDS[normalized]) {
    return REGULATORY_STANDARDS[normalized];
  }
  const aliases = {
    '21CFR11': 'FDA_21CFR11',
    FDA: 'FDA_21CFR11',
    BIOTECH: 'FDA_21CFR11',
    CLINICAL: 'FDA_21CFR11',
    ISO13485: 'ISO_13485',
    MEDTECH: 'ISO_13485',
    AEROSPACE: 'AS9100D',
    AS9100: 'AS9100D',
  };
  if (aliases[normalized]) {
    return REGULATORY_STANDARDS[aliases[normalized]];
  }
  throw new Error(`Unsupported regulatory standard "${standardCode}". Supported: ${Object.keys(REGULATORY_STANDARDS).join(', ')}`);
}

/**
 * Deterministic canonical JSON serialization with lexicographically sorted keys.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

/**
 * SHA-256 hex digest helper.
 */
export function sha256Hex(input) {
  const raw = typeof input === 'string' ? input : canonicalize(input);
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

/**
 * Extracts plain text from either plain strings or Jira Cloud ADF JSON structures.
 */
export function extractTextFromAdf(node) {
  if (node == null) return '';
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) {
    return node.map(extractTextFromAdf).filter(Boolean).join(' ');
  }
  if (typeof node === 'object') {
    const parts = [];
    if (typeof node.text === 'string') {
      parts.push(node.text);
    }
    if (node.attrs && typeof node.attrs.url === 'string') {
      parts.push(node.attrs.url);
    }
    if (node.attrs && typeof node.attrs.text === 'string') {
      parts.push(node.attrs.text);
    }
    if (Array.isArray(node.content)) {
      parts.push(node.content.map(extractTextFromAdf).filter(Boolean).join(' '));
    }
    return parts.filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
  }
  return String(node);
}

/**
 * Extracts explicit controlled document codes (SOP-*, WI-*, QMS-*, DHF-*, etc.).
 */
export function extractControlledDocCodes(text) {
  const source = String(text || '');
  const matches = source.match(CONTROLLED_DOC_REGEX) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))].sort();
}

/**
 * Extracts CAPA / Deviation / NCR identifiers.
 */
export function extractCapaIds(text) {
  const source = String(text || '');
  const matches = source.match(CAPA_ID_REGEX) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))].sort();
}

/**
 * Parses FMEA numeric dimensions from free-form text if not provided as structured inputs.
 */
export function parseFmeaFromText(text) {
  const source = String(text || '');
  const pick = (patterns) => {
    for (const rx of patterns) {
      const m = source.match(rx);
      if (m && m[1]) {
        const val = Number(m[1]);
        if (Number.isInteger(val) && val >= 1 && val <= 10) return val;
      }
    }
    return null;
  };
  return {
    severity: pick([/\bseverity\s*[:=]\s*(\d{1,2})\b/i, /\bS\s*=\s*(\d{1,2})\b/]),
    occurrence: pick([/\boccurrence\s*[:=]\s*(\d{1,2})\b/i, /\bO\s*=\s*(\d{1,2})\b/]),
    detectability: pick([/\bdetect(?:ability|ion)\s*[:=]\s*(\d{1,2})\b/i, /\bD\s*=\s*(\d{1,2})\b/]),
  };
}

function clampFmeaScore(val, label) {
  const num = Number(val);
  if (!Number.isFinite(num) || num < 1 || num > 10) {
    throw new Error(`Invalid FMEA ${label}: expected number between 1 and 10, received "${val}"`);
  }
  return Math.round(num);
}

/**
 * Computes Risk Priority Number (RPN = Severity * Occurrence * Detectability).
 */
export function calculateRpn({
  severity,
  occurrence,
  detectability,
  standardCode = 'FDA_21CFR11',
  fallbackText = '',
  priority = '',
} = {}) {
  const standard = getStandardProfile(standardCode);
  const parsed = parseFmeaFromText(fallbackText);

  const hasExplicitSeverity = severity !== undefined && severity !== null && severity !== '';
  const hasExplicitOccurrence = occurrence !== undefined && occurrence !== null && occurrence !== '';
  const hasExplicitDetectability = detectability !== undefined && detectability !== null && detectability !== '';

  const resolvedSeverity = hasExplicitSeverity ? clampFmeaScore(severity, 'severity') : parsed.severity;
  const resolvedOccurrence = hasExplicitOccurrence ? clampFmeaScore(occurrence, 'occurrence') : parsed.occurrence;
  const resolvedDetectability = hasExplicitDetectability ? clampFmeaScore(detectability, 'detectability') : parsed.detectability;

  const isExplicit =
    resolvedSeverity !== null && resolvedOccurrence !== null && resolvedDetectability !== null;

  let s = resolvedSeverity;
  let o = resolvedOccurrence;
  let d = resolvedDetectability;

  if (!isExplicit) {
    const prio = String(priority || '').toLowerCase();
    const defaultS = prio.includes('highest') || prio.includes('critical') ? 8 : prio.includes('high') ? 6 : 4;
    const defaultO = prio.includes('highest') || prio.includes('critical') ? 5 : 4;
    const defaultD = 4;
    s = s ?? defaultS;
    o = o ?? defaultO;
    d = d ?? defaultD;
  }

  const rpn = s * o * d;
  let tier = 'LOW';
  if (rpn >= standard.criticalRiskRpnThreshold) {
    tier = 'CRITICAL';
  } else if (rpn >= standard.highRiskRpnThreshold) {
    tier = 'HIGH';
  } else if (rpn >= 25) {
    tier = 'MEDIUM';
  }

  return {
    severity: s,
    occurrence: o,
    detectability: d,
    rpn,
    tier,
    explicit: isExplicit,
    requiresReleaseAuthority: rpn >= standard.highRiskRpnThreshold,
    thresholds: {
      high: standard.highRiskRpnThreshold,
      critical: standard.criticalRiskRpnThreshold,
    },
  };
}

/**
 * Creates a single SHA-256 tamper-evident audit ledger entry linked to prevHash.
 */
export function createAuditEntry({
  seq,
  timestamp = new Date().toISOString(),
  issueKey,
  actorAccountId,
  actorDisplayName = '',
  role,
  action,
  standard = 'FDA_21CFR11',
  rationale = '',
  metadata = {},
  prevHash = GENESIS_HASH,
}) {
  if (!Number.isInteger(seq) || seq < 1) {
    throw new Error(`Audit entry seq must be a positive integer; received "${seq}"`);
  }
  if (!issueKey || !String(issueKey).trim()) {
    throw new Error('Audit entry requires a non-empty issueKey');
  }
  if (!actorAccountId || !String(actorAccountId).trim()) {
    throw new Error('Audit entry requires a non-empty actorAccountId');
  }
  if (!role || !String(role).trim()) {
    throw new Error('Audit entry requires a non-empty role');
  }
  if (!action || !String(action).trim()) {
    throw new Error('Audit entry requires a non-empty action');
  }

  const normalizedStandard = getStandardProfile(standard).code;
  const cleanPayload = {
    seq,
    timestamp: String(timestamp),
    issueKey: String(issueKey).trim().toUpperCase(),
    actorAccountId: String(actorAccountId).trim(),
    actorDisplayName: String(actorDisplayName || '').trim(),
    role: String(role).trim().toUpperCase(),
    action: String(action).trim().toUpperCase(),
    standard: normalizedStandard,
    rationale: String(rationale || '').trim(),
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
  };

  const payloadHash = sha256Hex(cleanPayload);
  const entryHash = sha256Hex({
    seq: cleanPayload.seq,
    timestamp: cleanPayload.timestamp,
    issueKey: cleanPayload.issueKey,
    actorAccountId: cleanPayload.actorAccountId,
    role: cleanPayload.role,
    action: cleanPayload.action,
    standard: cleanPayload.standard,
    prevHash: String(prevHash),
    payloadHash,
  });

  return {
    ...cleanPayload,
    prevHash: String(prevHash),
    payloadHash,
    entryHash,
  };
}

/**
 * Appends a newly hashed entry onto an existing chain without mutating the input array.
 */
export function appendAuditEntry(existingEntries = [], entryInput) {
  const chain = Array.isArray(existingEntries) ? existingEntries : [];
  const prevHash = chain.length > 0 ? chain[chain.length - 1].entryHash : GENESIS_HASH;
  const seq = chain.length + 1;
  const entry = createAuditEntry({
    ...entryInput,
    seq,
    prevHash,
  });
  return {
    entry,
    entries: [...chain, entry],
  };
}

/**
 * Cryptographically verifies an audit chain for payload tampering, deletion, insertion, or reordering.
 */
export function verifyAuditChain(entries = []) {
  if (!Array.isArray(entries)) {
    return {
      valid: false,
      status: 'TAMPERED',
      verifiedCount: 0,
      totalCount: 0,
      genesisHash: GENESIS_HASH,
      headHash: null,
      anomalies: [{ seq: null, code: 'INVALID_CHAIN_TYPE', message: 'Audit ledger is not an array.' }],
    };
  }

  if (entries.length === 0) {
    return {
      valid: true,
      status: 'VERIFIED',
      verifiedCount: 0,
      totalCount: 0,
      genesisHash: GENESIS_HASH,
      headHash: GENESIS_HASH,
      anomalies: [],
    };
  }

  const anomalies = [];
  let expectedPrevHash = GENESIS_HASH;
  let verifiedCount = 0;

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    const expectedSeq = i + 1;
    let entryOk = true;

    if (!entry || typeof entry !== 'object') {
      anomalies.push({
        index: i,
        seq: expectedSeq,
        code: 'MALFORMED_ENTRY',
        message: `Entry at index ${i} is not a valid object.`,
      });
      expectedPrevHash = null;
      continue;
    }

    if (entry.seq !== expectedSeq) {
      entryOk = false;
      anomalies.push({
        index: i,
        seq: entry.seq,
        code: 'SEQUENCE_MISMATCH',
        message: `Expected sequence #${expectedSeq} at index ${i}, found #${entry.seq} (possible deletion or reordering).`,
      });
    }

    if (entry.prevHash !== expectedPrevHash) {
      entryOk = false;
      anomalies.push({
        index: i,
        seq: entry.seq,
        code: 'BROKEN_PREV_HASH',
        message: `Broken hash link at index ${i} (seq #${entry.seq}): expected prevHash ${expectedPrevHash}, found ${entry.prevHash}.`,
      });
    }

    const reconstructedPayload = {
      seq: entry.seq,
      timestamp: entry.timestamp,
      issueKey: entry.issueKey,
      actorAccountId: entry.actorAccountId,
      actorDisplayName: entry.actorDisplayName ?? '',
      role: entry.role,
      action: entry.action,
      standard: entry.standard,
      rationale: entry.rationale ?? '',
      metadata: entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : {},
    };

    const recomputedPayloadHash = sha256Hex(reconstructedPayload);
    if (entry.payloadHash !== recomputedPayloadHash) {
      entryOk = false;
      anomalies.push({
        index: i,
        seq: entry.seq,
        code: 'PAYLOAD_TAMPERED',
        message: `Payload hash mismatch at seq #${entry.seq}: recorded content was modified after signing.`,
      });
    }

    const recomputedEntryHash = sha256Hex({
      seq: entry.seq,
      timestamp: entry.timestamp,
      issueKey: entry.issueKey,
      actorAccountId: entry.actorAccountId,
      role: entry.role,
      action: entry.action,
      standard: entry.standard,
      prevHash: entry.prevHash,
      payloadHash: entry.payloadHash,
    });

    if (entry.entryHash !== recomputedEntryHash) {
      entryOk = false;
      anomalies.push({
        index: i,
        seq: entry.seq,
        code: 'ENTRY_HASH_FORGED',
        message: `Entry hash mismatch at seq #${entry.seq}: entry envelope hash does not match computed digest.`,
      });
    }

    if (entryOk) {
      verifiedCount += 1;
    }
    expectedPrevHash = entry.entryHash;
  }

  const valid = anomalies.length === 0;
  return {
    valid,
    status: valid ? 'VERIFIED' : 'TAMPERED',
    verifiedCount,
    totalCount: entries.length,
    genesisHash: GENESIS_HASH,
    headHash: entries[entries.length - 1]?.entryHash ?? null,
    anomalies,
  };
}

/**
 * Extracts latest approved QA & Release Authority accounts from an audit chain if present.
 */
export function extractSignoffsFromChain(entries = []) {
  const result = {
    proposerAccountId: null,
    qaApproverAccountId: null,
    releaseAuthorityAccountId: null,
    signoffs: [],
  };
  for (const entry of entries || []) {
    if (!entry || typeof entry !== 'object') continue;
    const role = String(entry.role || '').toUpperCase();
    const action = String(entry.action || '').toUpperCase();
    if (action === 'PROPOSE_CHANGE' && !result.proposerAccountId) {
      result.proposerAccountId = entry.actorAccountId;
    }
    if (action === 'APPROVE_QA' || (action === 'SIGN_OFF' && role === 'QA_APPROVER')) {
      result.qaApproverAccountId = entry.actorAccountId;
      result.signoffs.push(entry);
    }
    if (action === 'APPROVE_RELEASE' || (action === 'SIGN_OFF' && role === 'RELEASE_AUTHORITY')) {
      result.releaseAuthorityAccountId = entry.actorAccountId;
      result.signoffs.push(entry);
    }
  }
  return result;
}

/**
 * Enforces Separation of Duties across Proposer, QA Approver, and (for RPN >= threshold) Release Authority.
 */
export function verifySeparationOfDuties({
  proposerAccountId,
  qaApproverAccountId,
  releaseAuthorityAccountId = null,
  rpn = 0,
  standardCode = 'FDA_21CFR11',
} = {}) {
  const standard = getStandardProfile(standardCode);
  const proposer = proposerAccountId ? String(proposerAccountId).trim() : null;
  const qaApprover = qaApproverAccountId ? String(qaApproverAccountId).trim() : null;
  const releaseAuthority = releaseAuthorityAccountId ? String(releaseAuthorityAccountId).trim() : null;

  const requiresThreePartyApproval = Number(rpn) >= standard.highRiskRpnThreshold;
  const violations = [];

  if (!proposer) {
    violations.push({
      code: 'SOD_MISSING_PROPOSER',
      severity: 'BLOCKER',
      message: 'Change proposer account ID is missing; cannot verify proposer independence.',
    });
  }

  if (!qaApprover) {
    violations.push({
      code: 'SOD_MISSING_QA_APPROVER',
      severity: 'BLOCKER',
      message: 'Independent QA Approver electronic sign-off is required.',
    });
  } else if (proposer && qaApprover === proposer) {
    violations.push({
      code: 'SOD_SELF_APPROVAL_QA',
      severity: 'BLOCKER',
      message: `Self-approval prohibited: QA Approver (${qaApprover}) cannot be the change proposer (${proposer}).`,
    });
  }

  if (requiresThreePartyApproval) {
    if (!releaseAuthority) {
      violations.push({
        code: 'SOD_MISSING_RELEASE_AUTHORITY',
        severity: 'BLOCKER',
        message: `High/Critical risk (RPN=${rpn} >= ${standard.highRiskRpnThreshold}) requires an independent Release Authority distinct from both proposer and QA Approver.`,
      });
    }
  }

  if (releaseAuthority) {
    if (proposer && releaseAuthority === proposer) {
      violations.push({
        code: 'SOD_SELF_APPROVAL_RELEASE',
        severity: 'BLOCKER',
        message: `Self-approval prohibited: Release Authority (${releaseAuthority}) cannot be the change proposer (${proposer}).`,
      });
    }
    if (qaApprover && releaseAuthority === qaApprover) {
      violations.push({
        code: 'SOD_DUPLICATE_APPROVER_ROLE',
        severity: 'BLOCKER',
        message: `Role separation violation: Release Authority (${releaseAuthority}) must be distinct from QA Approver (${qaApprover}).`,
      });
    }
  }

  const requiredRoles = requiresThreePartyApproval
    ? ['PROPOSER', 'QA_APPROVER', 'RELEASE_AUTHORITY']
    : ['PROPOSER', 'QA_APPROVER'];

  const distinctVerifiedApprovers = new Set(
    [qaApprover, releaseAuthority].filter((id) => Boolean(id) && id !== proposer)
  );

  return {
    compliant: violations.length === 0,
    standard: standard.code,
    rpn: Number(rpn),
    highRiskThreshold: standard.highRiskRpnThreshold,
    requiresThreePartyApproval,
    requiredRoles,
    distinctApproverCount: distinctVerifiedApprovers.size,
    actors: {
      proposerAccountId: proposer,
      qaApproverAccountId: qaApprover,
      releaseAuthorityAccountId: releaseAuthority,
    },
    violations,
  };
}

function detectDomains(text) {
  const lower = String(text || '').toLowerCase();
  const matched = [];
  for (const [domain, keywords] of Object.entries(DOMAIN_KEYWORDS)) {
    if (keywords.some((kw) => lower.includes(kw))) {
      matched.push(domain);
    }
  }
  return matched;
}

/**
 * Analyzes Confluence SOP blast radius for a given Jira change-control issue.
 */
export function analyzeSopBlastRadius({
  issue = {},
  confluencePages = [],
  graphLinks = [],
  standardCode = 'FDA_21CFR11',
  asOfDate = new Date().toISOString(),
} = {}) {
  const standard = getStandardProfile(standardCode);
  const issueDescription = extractTextFromAdf(issue.description);
  const commentText = Array.isArray(issue.comments)
    ? issue.comments.map((c) => extractTextFromAdf(typeof c === 'string' ? c : c.body)).join(' ')
    : '';
  const combinedIssueText = [
    issue.key || '',
    issue.summary || '',
    issueDescription,
    ...(issue.labels || []),
    ...(issue.components || []),
    commentText,
  ].join(' ');

  const referencedCodes = extractControlledDocCodes(combinedIssueText);
  const issueDomains = detectDomains(combinedIssueText);

  const linkedPageIds = new Set();
  const linkedUrls = new Set();
  for (const link of [...(issue.remoteLinks || []), ...(graphLinks || [])]) {
    if (!link) continue;
    if (link.pageId) linkedPageIds.add(String(link.pageId));
    if (link.id) linkedPageIds.add(String(link.id));
    if (link.url) linkedUrls.add(String(link.url).toLowerCase());
    if (link.object?.url) linkedUrls.add(String(link.object.url).toLowerCase());
  }

  const nowMs = Date.parse(asOfDate) || Date.now();
  const matchedCodesAcrossPages = new Set();
  const impactedDocuments = [];

  for (const page of confluencePages || []) {
    if (!page || !page.title) continue;
    const pageText = [
      page.title || '',
      page.spaceKey || '',
      ...(page.labels || []),
      extractTextFromAdf(page.bodyText || page.body || ''),
    ].join(' ');
    const pageCodes = extractControlledDocCodes(pageText);
    const pageDomains = detectDomains(pageText);

    const directCodeMatches = pageCodes.filter((code) => referencedCodes.includes(code));
    directCodeMatches.forEach((c) => matchedCodesAcrossPages.add(c));

    const isGraphLinked =
      linkedPageIds.has(String(page.id || '')) ||
      (page.url && linkedUrls.has(String(page.url).toLowerCase())) ||
      Boolean(page.linkedViaGraph);

    const sharedDomains = pageDomains.filter((d) => issueDomains.includes(d));

    let score = 0;
    const reasons = [];

    if (isGraphLinked) {
      score += 45;
      reasons.push('Direct Jira/Teamwork Graph link');
    }
    if (directCodeMatches.length > 0) {
      score += 40;
      reasons.push(`Explicit document reference (${directCodeMatches.join(', ')})`);
    }
    if (sharedDomains.length > 0) {
      score += Math.min(35, sharedDomains.length * 18);
      reasons.push(`Shared regulated domain(s): ${sharedDomains.join(', ')}`);
    }

    // Also include controlled documents explicitly tagged in controlled spaces if there is partial title overlap
    const normalizedTitleTokens = String(page.title)
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 5);
    const issueLower = combinedIssueText.toLowerCase();
    const tokenHits = normalizedTitleTokens.filter((tok) => issueLower.includes(tok));
    if (score === 0 && tokenHits.length >= 2) {
      score += 22;
      reasons.push(`Title keyword overlap (${tokenHits.slice(0, 3).join(', ')})`);
    }

    if (score < 20) continue;

    let daysSinceReview = null;
    let isStale = false;
    if (page.lastUpdated) {
      const updatedMs = Date.parse(page.lastUpdated);
      if (Number.isFinite(updatedMs)) {
        daysSinceReview = Math.max(0, Math.floor((nowMs - updatedMs) / (1000 * 60 * 60 * 24)));
        isStale = daysSinceReview > standard.sopStaleDays;
        if (isStale) {
          score += 12;
          reasons.push(`Stale review cycle (${daysSinceReview}d > ${standard.sopStaleDays}d limit for ${standard.code})`);
        }
      }
    }

    const cappedScore = Math.min(100, score);
    const impactLevel = cappedScore >= 70 ? 'critical' : cappedScore >= 45 ? 'high' : 'medium';

    impactedDocuments.push({
      id: String(page.id || pageCodes[0] || page.title),
      title: page.title,
      spaceKey: page.spaceKey || 'QMS',
      url: page.url || null,
      version: page.version ?? 1,
      docCodes: pageCodes,
      matchedCodes: directCodeMatches,
      sharedDomains,
      linkedViaGraph: isGraphLinked,
      lastUpdated: page.lastUpdated || null,
      daysSinceReview,
      isStale,
      impactScore: cappedScore,
      impactLevel,
      reasons,
    });
  }

  impactedDocuments.sort((a, b) => b.impactScore - a.impactScore || a.title.localeCompare(b.title));

  const unlinkedReferencedCodes = referencedCodes.filter((c) => !matchedCodesAcrossPages.has(c));
  const staleDocuments = impactedDocuments.filter((d) => d.isStale);

  const counts = {
    critical: impactedDocuments.filter((d) => d.impactLevel === 'critical').length,
    high: impactedDocuments.filter((d) => d.impactLevel === 'high').length,
    medium: impactedDocuments.filter((d) => d.impactLevel === 'medium').length,
  };

  let blastRadiusLevel = 'LOW';
  if (counts.critical > 0 || staleDocuments.length > 0 && counts.high > 0) {
    blastRadiusLevel = 'CRITICAL';
  } else if (counts.high > 0 || unlinkedReferencedCodes.length > 0) {
    blastRadiusLevel = 'HIGH';
  } else if (counts.medium > 0) {
    blastRadiusLevel = 'MEDIUM';
  }

  const recommendedActions = [];
  if (counts.critical > 0) {
    recommendedActions.push(
      `Initiate controlled revision review for ${counts.critical} critical impacted SOP(s) prior to release.`
    );
  }
  if (staleDocuments.length > 0) {
    recommendedActions.push(
      `Re-verify ${staleDocuments.length} stale controlled document(s) exceeding the ${standard.sopStaleDays}-day ${standard.code} review cycle.`
    );
  }
  if (unlinkedReferencedCodes.length > 0) {
    recommendedActions.push(
      `Link or verify missing Confluence records for referenced controlled IDs: ${unlinkedReferencedCodes.join(', ')}.`
    );
  }
  if (recommendedActions.length === 0 && impactedDocuments.length > 0) {
    recommendedActions.push('Document SOP impact assessment outcome and attach redline summary to Jira change control.');
  }

  return {
    standard: standard.code,
    sopStaleLimitDays: standard.sopStaleDays,
    issueKey: issue.key || null,
    issueDomains,
    referencedCodes,
    unlinkedReferencedCodes,
    blastRadiusLevel,
    counts,
    staleCount: staleDocuments.length,
    impactedDocuments,
    recommendedActions,
  };
}

function detectChangeClassification(issue, combinedText) {
  if (issue.changeClass && String(issue.changeClass).trim()) {
    return {
      detected: true,
      classification: String(issue.changeClass).trim().toUpperCase(),
      source: 'structured_field',
    };
  }
  for (const label of issue.labels || []) {
    const upper = String(label).toUpperCase();
    if (['CRITICAL', 'MAJOR', 'MINOR', 'EMERGENCY', 'CAPA', 'CLASS-1', 'CLASS-2', 'CLASS-3'].includes(upper)) {
      return { detected: true, classification: upper, source: 'jira_label' };
    }
  }
  for (const entry of CHANGE_CLASS_PATTERNS) {
    if (entry.regex.test(combinedText)) {
      return { detected: true, classification: entry.label, source: 'issue_text' };
    }
  }
  return { detected: false, classification: 'UNCLASSIFIED', source: 'none' };
}

/**
 * Full deterministic regulated change-control readiness assessment (0-100).
 */
export function assessChangeControl({
  issue = {},
  standardCode = 'FDA_21CFR11',
  fmea = {},
  confluencePages = [],
  graphLinks = [],
  auditEntries = [],
  signoffs = {},
  capaRecords = [],
  asOfDate = new Date().toISOString(),
} = {}) {
  const standard = getStandardProfile(standardCode);
  const descriptionText = extractTextFromAdf(issue.description);
  const commentText = Array.isArray(issue.comments)
    ? issue.comments.map((c) => extractTextFromAdf(typeof c === 'string' ? c : c.body)).join(' ')
    : '';
  const combinedText = [
    issue.key || '',
    issue.summary || '',
    issue.issueType || '',
    descriptionText,
    ...(issue.labels || []),
    ...(issue.components || []),
    commentText,
  ].join(' ');
  const lowerText = combinedText.toLowerCase();

  // 1. Change Classification
  const classificationInfo = detectChangeClassification(issue, combinedText);
  const classificationEarned = classificationInfo.detected ? standard.gateWeights.classification : 0;

  // 2. Risk Priority Number (FMEA)
  const rpn = calculateRpn({
    severity: fmea.severity ?? issue.severity,
    occurrence: fmea.occurrence ?? issue.occurrence,
    detectability: fmea.detectability ?? issue.detectability,
    standardCode: standard.code,
    fallbackText: combinedText,
    priority: issue.priority,
  });
  const riskEarned = rpn.explicit
    ? standard.gateWeights.riskAssessment
    : Math.round(standard.gateWeights.riskAssessment * 0.35);

  // 3. Validation / Verification & Rollback Plan
  const matchedValidationTerms = standard.validationTerms.filter((t) => lowerText.includes(t));
  const matchedRollbackTerms = ROLLBACK_TERMS.filter((t) => lowerText.includes(t));
  const hasValidation = matchedValidationTerms.length > 0 || Boolean(issue.validationPlan);
  const hasRollback = matchedRollbackTerms.length > 0 || Boolean(issue.rollbackPlan);

  let valRollbackEarned = 0;
  let valRollbackStatus = 'FAIL';
  if (hasValidation && hasRollback) {
    valRollbackEarned = standard.gateWeights.validationAndRollback;
    valRollbackStatus = 'PASS';
  } else if (hasValidation || hasRollback) {
    valRollbackEarned = Math.round(standard.gateWeights.validationAndRollback * 0.5);
    valRollbackStatus = 'WARN';
  }

  // 4. Confluence SOP Blast-Radius Assessment
  const sopBlastRadius = analyzeSopBlastRadius({
    issue,
    confluencePages,
    graphLinks,
    standardCode: standard.code,
    asOfDate,
  });
  const explicitNoSopImpact = /\bno\s+sop\s+impact\b/i.test(lowerText);
  let sopEarned = 0;
  let sopStatus = 'FAIL';
  if (sopBlastRadius.impactedDocuments.length > 0) {
    if (sopBlastRadius.unlinkedReferencedCodes.length === 0 && sopBlastRadius.staleCount === 0) {
      sopEarned = standard.gateWeights.sopImpact;
      sopStatus = 'PASS';
    } else {
      sopEarned = Math.round(standard.gateWeights.sopImpact * 0.65);
      sopStatus = 'WARN';
    }
  } else if (explicitNoSopImpact && rpn.tier === 'LOW') {
    sopEarned = standard.gateWeights.sopImpact;
    sopStatus = 'PASS';
  } else if (sopBlastRadius.unlinkedReferencedCodes.length > 0) {
    sopEarned = Math.round(standard.gateWeights.sopImpact * 0.25);
    sopStatus = 'FAIL';
  }

  // 5. CAPA & Root-Cause Linkage
  const extractedCapaIds = extractCapaIds(combinedText);
  const linkedCapas = [
    ...new Set([
      ...extractedCapaIds,
      ...(capaRecords || []).map((c) => c.capaId || c.id).filter(Boolean),
      ...(issue.linkedCapaIds || []),
    ]),
  ];
  const hasRootCauseAnalysis = ROOT_CAUSE_TERMS.some((t) => lowerText.includes(t)) || linkedCapas.length > 0;
  const requiresCapa =
    rpn.rpn >= standard.highRiskRpnThreshold ||
    ['CRITICAL', 'MAJOR', 'CAPA'].includes(classificationInfo.classification) ||
    /\b(deviation|nonconformity|incident|capa|defect|failure)\b/i.test(lowerText);

  let capaEarned = 0;
  let capaStatus = 'FAIL';
  if (linkedCapas.length > 0) {
    capaEarned = standard.gateWeights.capaTraceability;
    capaStatus = 'PASS';
  } else if (!requiresCapa) {
    capaEarned = standard.gateWeights.capaTraceability;
    capaStatus = 'PASS';
  } else if (hasRootCauseAnalysis) {
    capaEarned = Math.round(standard.gateWeights.capaTraceability * 0.55);
    capaStatus = 'WARN';
  }

  // 6. Cryptographic Audit Chain & Dual Approval Separation-of-Duties
  const auditChain = verifyAuditChain(auditEntries);
  const chainSignoffs = extractSignoffsFromChain(auditEntries);
  const separationOfDuties = verifySeparationOfDuties({
    proposerAccountId:
      signoffs.proposerAccountId || issue.reporterAccountId || chainSignoffs.proposerAccountId,
    qaApproverAccountId: signoffs.qaApproverAccountId || chainSignoffs.qaApproverAccountId,
    releaseAuthorityAccountId:
      signoffs.releaseAuthorityAccountId || chainSignoffs.releaseAuthorityAccountId,
    rpn: rpn.rpn,
    standardCode: standard.code,
  });

  let signOffEarned = 0;
  let signOffStatus = 'FAIL';
  if (auditChain.valid && separationOfDuties.compliant) {
    signOffEarned = standard.gateWeights.dualSignOff;
    signOffStatus = 'PASS';
  } else if (
    auditChain.valid &&
    separationOfDuties.requiresThreePartyApproval &&
    separationOfDuties.actors.qaApproverAccountId &&
    separationOfDuties.violations.every((v) => v.code === 'SOD_MISSING_RELEASE_AUTHORITY')
  ) {
    signOffEarned = Math.round(standard.gateWeights.dualSignOff * 0.5);
    signOffStatus = 'WARN';
  }

  const gates = [
    {
      id: 'classification',
      name: 'Change Classification',
      status: classificationInfo.detected ? 'PASS' : 'FAIL',
      weight: standard.gateWeights.classification,
      earned: classificationEarned,
      details: classificationInfo.detected
        ? `Classified as ${classificationInfo.classification} (via ${classificationInfo.source}).`
        : 'Missing explicit change classification (Major / Minor / Critical / CAPA).',
      citation: standard.citation,
    },
    {
      id: 'riskAssessment',
      name: 'FMEA Risk Assessment (RPN)',
      status: rpn.explicit ? 'PASS' : 'WARN',
      weight: standard.gateWeights.riskAssessment,
      earned: riskEarned,
      details: rpn.explicit
        ? `Quantified RPN=${rpn.rpn} (S=${rpn.severity}, O=${rpn.occurrence}, D=${rpn.detectability}; tier=${rpn.tier}).`
        : `Estimated RPN=${rpn.rpn} (${rpn.tier}) from ticket priority; explicit S/O/D FMEA ratings required.`,
      citation: standard.citation,
    },
    {
      id: 'validationAndRollback',
      name: 'Validation & Rollback Plan',
      status: valRollbackStatus,
      weight: standard.gateWeights.validationAndRollback,
      earned: valRollbackEarned,
      details:
        hasValidation && hasRollback
          ? `Validation (${matchedValidationTerms.slice(0, 3).join(', ') || 'documented'}) and rollback/containment plan verified.`
          : !hasValidation && !hasRollback
            ? 'Missing both verification/validation protocol and rollback/containment plan.'
            : !hasValidation
              ? 'Rollback plan found, but verification/validation protocol evidence is missing.'
              : 'Validation evidence found, but rollback/contingency plan is missing.',
      citation: standard.citation,
    },
    {
      id: 'sopImpact',
      name: 'Confluence SOP Blast Radius',
      status: sopStatus,
      weight: standard.gateWeights.sopImpact,
      earned: sopEarned,
      details:
        sopBlastRadius.impactedDocuments.length > 0
          ? `${sopBlastRadius.impactedDocuments.length} impacted controlled document(s) identified (level=${sopBlastRadius.blastRadiusLevel}, stale=${sopBlastRadius.staleCount}, unlinked=${sopBlastRadius.unlinkedReferencedCodes.length}).`
          : explicitNoSopImpact && rpn.tier === 'LOW'
            ? 'Low-risk change with documented no-SOP-impact justification.'
            : 'No linked Confluence SOP impact assessment detected.',
      citation: standard.citation,
    },
    {
      id: 'capaTraceability',
      name: 'CAPA & Root-Cause Traceability',
      status: capaStatus,
      weight: standard.gateWeights.capaTraceability,
      earned: capaEarned,
      details:
        linkedCapas.length > 0
          ? `Linked CAPA/Deviation records: ${linkedCapas.join(', ')}.`
          : !requiresCapa
            ? 'Routine low-risk change; CAPA record not mandatory.'
            : hasRootCauseAnalysis
              ? 'Root-cause narrative present, but formal CAPA/Deviation ID is not linked.'
              : 'High-risk/Major change requires CAPA or formal deviation traceability.',
      citation: standard.citation,
    },
    {
      id: 'dualSignOff',
      name: 'Separation-of-Duties & Audit Chain',
      status: signOffStatus,
      weight: standard.gateWeights.dualSignOff,
      earned: signOffEarned,
      details: !auditChain.valid
        ? `AUDIT CHAIN INTEGRITY FAILURE (${auditChain.anomalies.length} anomaly/anomalies detected).`
        : separationOfDuties.compliant
          ? `Electronic attestation verified (${separationOfDuties.requiresThreePartyApproval ? '3-party' : '2-party'} SoD satisfied; chain ${auditChain.status}).`
          : separationOfDuties.violations.map((v) => v.message).join(' '),
      citation: standard.citation,
    },
  ];

  const rawScore = gates.reduce((acc, g) => acc + g.earned, 0);
  const readinessScore = auditChain.valid ? Math.min(100, Math.max(0, rawScore)) : 0;

  const blockers = [];
  if (!auditChain.valid) {
    blockers.push(`CRITICAL: Audit ledger integrity compromised (${auditChain.anomalies[0]?.code || 'TAMPERED'}).`);
  }
  for (const v of separationOfDuties.violations) {
    blockers.push(v.message);
  }
  if (!hasRollback && rpn.rpn >= standard.highRiskRpnThreshold) {
    blockers.push(`High/Critical risk change (RPN=${rpn.rpn}) lacks a documented rollback/containment plan.`);
  }
  if (sopBlastRadius.unlinkedReferencedCodes.length > 0) {
    blockers.push(
      `Referenced controlled document(s) not linked in Confluence: ${sopBlastRadius.unlinkedReferencedCodes.join(', ')}.`
    );
  }

  let releaseDecision = 'READY_FOR_RELEASE';
  if (!auditChain.valid || blockers.length > 0 || readinessScore < 65) {
    releaseDecision = 'BLOCKED';
  } else if (readinessScore < standard.minReadinessScore || gates.some((g) => g.status !== 'PASS')) {
    releaseDecision = 'CONDITIONAL_HOLD';
  }

  return {
    issueKey: issue.key || 'UNKNOWN',
    summary: issue.summary || '',
    evaluatedAt: asOfDate,
    standard: {
      code: standard.code,
      name: standard.name,
      sector: standard.sector,
      citation: standard.citation,
      minReadinessScore: standard.minReadinessScore,
    },
    classification: classificationInfo,
    rpn,
    readinessScore,
    releaseDecision,
    blockers,
    gates,
    linkedCapas,
    separationOfDuties,
    sopBlastRadius,
    auditChain,
  };
}

/**
 * Generates an inspector-ready regulatory audit dossier (structured JSON + clean Markdown).
 */
export function generateAuditPacket({
  assessment,
  auditEntries = [],
  capaRecords = [],
  generatedBy = 'system',
  generatedAt = new Date().toISOString(),
} = {}) {
  if (!assessment || !assessment.issueKey) {
    throw new Error('generateAuditPacket requires a valid change-control assessment object.');
  }

  const chainCheck = verifyAuditChain(auditEntries);
  const packetId = `CP-${assessment.issueKey}-${generatedAt.slice(0, 10).replace(/-/g, '')}-${sha256Hex({
    issueKey: assessment.issueKey,
    headHash: chainCheck.headHash,
    standard: assessment.standard.code,
  }).slice(0, 8).toUpperCase()}`;

  const dossierCore = {
    packetId,
    generatedAt,
    generatedBy,
    issueKey: assessment.issueKey,
    summary: assessment.summary,
    standard: assessment.standard,
    releaseDecision: assessment.releaseDecision,
    readinessScore: assessment.readinessScore,
    classification: assessment.classification,
    rpn: assessment.rpn,
    gates: assessment.gates,
    blockers: assessment.blockers,
    separationOfDuties: assessment.separationOfDuties,
    sopBlastRadius: assessment.sopBlastRadius,
    capaRecords: capaRecords || [],
    auditChainIntegrity: chainCheck,
    auditLedger: auditEntries,
  };

  const packetDigest = sha256Hex(dossierCore);
  const dossier = {
    ...dossierCore,
    packetDigest,
  };

  const gateRows = assessment.gates
    .map(
      (g) =>
        `| ${g.name} | **${g.status}** | ${g.earned}/${g.weight} | ${g.details.replace(/\|/g, '/')} |`
    )
    .join('\n');

  const ledgerRows =
    auditEntries.length > 0
      ? auditEntries
          .map(
            (e) =>
              `| #${e.seq} | ${e.timestamp} | ${e.actorDisplayName || e.actorAccountId} (\`${e.actorAccountId}\`) | ${e.role} | ${e.action} | \`${e.entryHash.slice(0, 16)}...\` |`
          )
          .join('\n')
      : '| — | — | No electronic sign-off entries recorded | — | — | — |';

  const sopRows =
    assessment.sopBlastRadius.impactedDocuments.length > 0
      ? assessment.sopBlastRadius.impactedDocuments
          .map(
            (d) =>
              `| ${d.docCodes.join(', ') || d.id} | ${d.title.replace(/\|/g, '/')} | ${d.impactLevel.toUpperCase()} (${d.impactScore}) | v${d.version} | ${d.isStale ? `STALE (${d.daysSinceReview}d)` : 'Current'} |`
          )
          .join('\n')
      : '| — | No impacted controlled SOPs identified | — | — | — |';

  const capaRows =
    (capaRecords || []).length > 0
      ? capaRecords
          .map(
            (c) =>
              `| ${c.capaId} | ${c.severity} | ${c.rootCause.replace(/\|/g, '/')} | ${c.containmentAction.replace(/\|/g, '/')} | ${c.loggedAt} |`
          )
          .join('\n')
      : '| — | None logged in ChangeProof ledger | — | — | — |';

  const blockersSection =
    assessment.blockers.length > 0
      ? assessment.blockers.map((b) => `- **BLOCKER:** ${b}`).join('\n')
      : '- None. All mandatory release gates satisfied.';

  const markdown = [
    `# Regulatory Change-Control Audit Dossier — ${assessment.issueKey}`,
    '',
    `- **Packet ID:** \`${packetId}\``,
    `- **Generated (UTC):** ${generatedAt}`,
    `- **Regulatory Framework:** ${assessment.standard.name} (${assessment.standard.sector})`,
    `- **Citations:** ${assessment.standard.citation}`,
    `- **Release Decision:** **${assessment.releaseDecision}** (Readiness Score: **${assessment.readinessScore}/100**, Min Required: ${assessment.standard.minReadinessScore})`,
    `- **Audit Chain Integrity:** **${chainCheck.status}** (${chainCheck.verifiedCount}/${chainCheck.totalCount} verified entries)`,
    `- **Chain Head SHA-256:** \`${chainCheck.headHash}\``,
    `- **Dossier SHA-256 Digest:** \`${packetDigest}\``,
    '',
    '## 1. Change Summary & FMEA Risk Matrix',
    '',
    `- **Summary:** ${assessment.summary || 'N/A'}`,
    `- **Change Classification:** ${assessment.classification.classification}`,
    `- **Risk Priority Number (RPN):** **${assessment.rpn.rpn}** — Tier: **${assessment.rpn.tier}** (Severity=${assessment.rpn.severity}, Occurrence=${assessment.rpn.occurrence}, Detectability=${assessment.rpn.detectability}; ${assessment.rpn.explicit ? 'Explicit FMEA' : 'Inferred Estimate'})`,
    `- **3-Party Release Authority Required:** ${assessment.rpn.requiresReleaseAuthority ? 'YES (RPN >= ' + assessment.rpn.thresholds.high + ')' : 'NO'}`,
    '',
    '## 2. Compliance Gate Evaluation',
    '',
    '| Gate | Status | Points | Evidence & Findings |',
    '| :--- | :---: | :---: | :--- |',
    gateRows,
    '',
    '### Active Release Blockers',
    blockersSection,
    '',
    '## 3. Separation-of-Duties & Cryptographic Sign-Off Ledger',
    '',
    `- **SoD Compliant:** **${assessment.separationOfDuties.compliant ? 'YES' : 'NO'}**`,
    `- **Proposer:** \`${assessment.separationOfDuties.actors.proposerAccountId || 'UNASSIGNED'}\``,
    `- **QA Approver:** \`${assessment.separationOfDuties.actors.qaApproverAccountId || 'PENDING'}\``,
    `- **Release Authority:** \`${assessment.separationOfDuties.actors.releaseAuthorityAccountId || (assessment.rpn.requiresReleaseAuthority ? 'PENDING (REQUIRED)' : 'N/A')}\``,
    '',
    '| Seq | Timestamp (UTC) | Actor | Role | Action | Entry SHA-256 |',
    '| :---: | :--- | :--- | :--- | :--- | :--- |',
    ledgerRows,
    '',
    '## 4. Impacted Controlled Documents (Confluence SOP Blast Radius)',
    '',
    `- **Blast Radius Level:** **${assessment.sopBlastRadius.blastRadiusLevel}**`,
    `- **Referenced Controlled IDs:** ${assessment.sopBlastRadius.referencedCodes.join(', ') || 'None'}`,
    `- **Unlinked Citations:** ${assessment.sopBlastRadius.unlinkedReferencedCodes.join(', ') || 'None'}`,
    '',
    '| Doc Code | Document Title | Impact | Version | Review Cycle |',
    '| :--- | :--- | :---: | :---: | :---: |',
    sopRows,
    '',
    '## 5. CAPA & Deviation Traceability',
    '',
    '| CAPA ID | Severity | Root Cause | Containment Action | Logged (UTC) |',
    '| :--- | :---: | :--- | :--- | :--- |',
    capaRows,
    '',
    '---',
    '*Verification Note: Recompute each entry `payloadHash` and `entryHash` sequentially from Genesis (`0x00...00`) to confirm tamper evidence.*',
  ].join('\n');

  return {
    packetId,
    packetDigest,
    dossier,
    markdown,
  };
}
