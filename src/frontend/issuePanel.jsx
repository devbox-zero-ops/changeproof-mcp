import React, { useCallback, useEffect, useState } from 'react';
import ForgeReconciler, {
  Badge,
  Box,
  Button,
  CodeBlock,
  Heading,
  Inline,
  Lozenge,
  SectionMessage,
  Select,
  Stack,
  Text,
  Textfield,
} from '@forge/react';
import { invoke } from '@forge/bridge';

const STANDARD_OPTIONS = [
  { label: 'FDA 21 CFR Part 11 (Biotech / Clinical)', value: 'FDA_21CFR11' },
  { label: 'ISO 13485 (Medical Devices QMS)', value: 'ISO_13485' },
  { label: 'AS9100D (Aerospace / Precision Mfg)', value: 'AS9100D' },
];

const ROLE_OPTIONS = [
  { label: 'QA Approver', value: 'QA_APPROVER' },
  { label: 'Release Authority', value: 'RELEASE_AUTHORITY' },
  { label: 'Change Proposer', value: 'PROPOSER' },
];

const DECISION_OPTIONS = [
  { label: 'Approve Gate', value: 'APPROVED' },
  { label: 'Conditional Approval', value: 'CONDITIONAL' },
  { label: 'Reject Change', value: 'REJECTED' },
];

function IssuePanelApp() {
  const [standardCode, setStandardCode] = useState('FDA_21CFR11');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState('QA_APPROVER');
  const [decision, setDecision] = useState('APPROVED');
  const [rationale, setRationale] = useState('');
  const [packetMd, setPacketMd] = useState('');
  const [notice, setNotice] = useState(null);

  const loadCompliance = useCallback(async (std) => {
    setLoading(true);
    try {
      const res = await invoke('getIssueCompliance', { standardCode: std });
      if (res && res.ok) {
        setData(res);
      } else {
        setNotice({ type: 'error', text: res?.error || 'Unable to evaluate compliance.' });
      }
    } catch (err) {
      setNotice({ type: 'error', text: String(err) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCompliance(standardCode);
  }, [standardCode, loadCompliance]);

  const handleSignoff = async () => {
    setNotice(null);
    const res = await invoke('recordSignoff', {
      standardCode,
      role,
      decision,
      rationale,
    });
    if (res && res.ok) {
      setRationale('');
      setNotice({
        type: 'confirmation',
        text: `Recorded #${res.entry.seq} (${role} ${decision}) · SHA-256 ${res.entry.entryHash.slice(0, 14)}…`,
      });
      await loadCompliance(standardCode);
    } else {
      setNotice({ type: 'error', text: res?.error || 'Sign-off rejected.' });
    }
  };

  const handleExportPacket = async () => {
    setNotice(null);
    const res = await invoke('generatePacket', { standardCode });
    if (res && res.ok) {
      setPacketMd(res.markdown);
      setNotice({
        type: 'information',
        text: `Compiled Audit Packet ${res.packetId} (Digest ${res.packetDigest.slice(0, 14)}…).`,
      });
    } else {
      setNotice({ type: 'error', text: res?.error || 'Failed to generate packet.' });
    }
  };

  if (loading && !data) {
    return <Text>Evaluating regulated change-control gates…</Text>;
  }

  const assessment = data?.assessment;
  const chain = assessment?.auditChain;
  const sod = assessment?.separationOfDuties;
  const blast = assessment?.sopBlastRadius;

  return (
    <Stack space="space.200">
      <Inline spread="space-between" alignBlock="center">
        <Heading as="h3">ChangeProof Regulated Governance</Heading>
        {assessment && (
          <Inline space="space.100">
            <Lozenge appearance={assessment.readinessScore >= 80 ? 'success' : 'moved'}>
              Readiness {assessment.readinessScore}/100
            </Lozenge>
            <Lozenge appearance={chain?.valid ? 'success' : 'removed'}>
              Chain: {chain?.status || 'EMPTY'}
            </Lozenge>
          </Inline>
        )}
      </Inline>

      <Select
        label="Regulatory Framework"
        options={STANDARD_OPTIONS}
        value={STANDARD_OPTIONS.find((o) => o.value === standardCode)}
        onChange={(opt) => opt && setStandardCode(opt.value)}
      />

      {notice && (
        <SectionMessage appearance={notice.type}>
          <Text>{notice.text}</Text>
        </SectionMessage>
      )}

      {assessment && (
        <Stack space="space.150">
          <Inline space="space.150">
            <Badge appearance="primary">RPN {assessment.rpn.rpn}</Badge>
            <Lozenge appearance={assessment.rpn.tier === 'CRITICAL' ? 'removed' : 'inprogress'}>
              Risk: {assessment.rpn.tier}
            </Lozenge>
            <Lozenge appearance={sod?.compliant ? 'success' : 'moved'}>
              SoD: {sod?.compliant ? 'COMPLIANT' : 'PENDING'}
            </Lozenge>
            <Lozenge appearance="default">
              SOP Impact: {blast?.impactedDocuments?.length || 0} docs
            </Lozenge>
          </Inline>

          <Box>
            <Heading as="h4">Mandatory Gate Checklist</Heading>
            <Stack space="space.075">
              {(assessment.gates || []).map((g) => (
                <Inline key={g.id} space="space.100" alignBlock="center">
                  <Lozenge appearance={g.status === 'PASS' ? 'success' : g.status === 'WARN' ? 'moved' : 'removed'}>
                    {g.status}
                  </Lozenge>
                  <Text>
                    {g.name} — {g.details}
                  </Text>
                </Inline>
              ))}
            </Stack>
          </Box>

          <Box>
            <Heading as="h4">Cryptographic Dual Sign-off Attestation</Heading>
            <Stack space="space.100">
              <Inline space="space.100">
                <Select
                  options={ROLE_OPTIONS}
                  value={ROLE_OPTIONS.find((o) => o.value === role)}
                  onChange={(opt) => opt && setRole(opt.value)}
                />
                <Select
                  options={DECISION_OPTIONS}
                  value={DECISION_OPTIONS.find((o) => o.value === decision)}
                  onChange={(opt) => opt && setDecision(opt.value)}
                />
              </Inline>
              <Textfield
                name="rationale"
                placeholder="Objective verification rationale (e.g. IQ/OQ protocol passed, SOP-QA-104 updated)"
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
              />
              <Inline space="space.100">
                <Button appearance="primary" onClick={() => void handleSignoff()}>
                  Sign & Hash to Ledger
                </Button>
                <Button appearance="subtle" onClick={() => void handleExportPacket()}>
                  Compile Inspector Dossier
                </Button>
              </Inline>
            </Stack>
          </Box>

          {packetMd && (
            <Box>
              <Heading as="h4">Inspector-Ready Audit Packet (Markdown)</Heading>
              <CodeBlock language="markdown" text={packetMd} />
            </Box>
          )}
        </Stack>
      )}
    </Stack>
  );
}

ForgeReconciler.render(
  <React.StrictMode>
    <IssuePanelApp />
  </React.StrictMode>,
);
