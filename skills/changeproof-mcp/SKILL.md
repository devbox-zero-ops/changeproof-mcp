---
name: changeproof-mcp
description: Audit Jira change-control and CAPA workflows against FDA 21 CFR Part 11, ISO 13485, and AS9100D using the ChangeProof Atlassian Forge rovo:mcp server. Use when assessing release readiness, scanning impacted Confluence SOPs, verifying separation-of-duties dual sign-offs, checking SHA-256 audit chains, or exporting regulatory inspection dossiers.
---

# ChangeProof MCP Companion Skill

Use this skill when connecting Claude Code, Cursor, Codex, or Antigravity to a workspace where **ChangeProof MCP** is installed on Atlassian Cloud (Jira + Confluence + Rovo).

## Connected `rovo:mcp` Tools

1. **`assess-change-control`** (`issueKey`, optional `standardCode`, `severity`, `occurrence`, `detectability`)
   - Evaluates mandatory regulatory gates (`FDA_21CFR11`, `ISO_13485`, `AS9100D`), calculates FMEA Risk Priority Number (`RPN`), checks CAPA traceability, and returns a 0–100 readiness score.
2. **`scan-sop-blast-radius`** (`issueKey`, optional `standardCode`)
   - Traces Confluence controlled SOP codes (e.g., `SOP-QA-104`, `WI-MFG-22`) and Teamwork Graph links to surface impacted procedures and overdue review cycles.
3. **`verify-dual-signoff`** (`issueKey`, `role`, `decision`, `rationale`, optional `standardCode`)
   - Enforces strict separation-of-duties (`PROPOSER != QA_APPROVER != RELEASE_AUTHORITY`) and appends a SHA-256 hash-chained attestation to Forge KVS storage.
4. **`verify-audit-chain`** (`issueKey`)
   - Recomputes every `payloadHash` and `entryHash` from Genesis (`0x00...00`) to detect any tampering.
5. **`generate-audit-packet`** (`issueKey`, optional `standardCode`)
   - Exports a complete Markdown + JSON inspection dossier with `packetDigest` and cryptographic head hash.
6. **`log-capa-deviation`** (`issueKey`, `capaId`, `severity`, `rootCause`, `containmentAction`)
   - Logs a linked CAPA / quality deviation into Forge KVS, appends it to the SHA-256 audit ledger, and posts a traceable Jira comment.

## Standard Pre-Release Audit Procedure

1. Call `assess-change-control` on the target Jira issue key first.
2. Call `scan-sop-blast-radius` to confirm no unlinked or stale Confluence SOPs remain unreviewed.
3. Call `verify-audit-chain` and verify `status === "VERIFIED"` before approving any release.
4. Never advise a user to self-approve a change where their Atlassian `accountId` matches the proposer; explain the exact separation-of-duties block and identify which independent role is required next.
5. Finish by calling `generate-audit-packet` and presenting the `packetId`, `packetDigest`, and chain `headHash` verbatim.
