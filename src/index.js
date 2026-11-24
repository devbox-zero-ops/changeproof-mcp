import Resolver from '@forge/resolver';
import { createAtlassianAdapter } from './services/atlassianClient.js';
import { createToolHandlers } from './mcp/tools.js';

const adapter = createAtlassianAdapter();
const handlers = createToolHandlers(adapter);

const resolver = new Resolver();

resolver.define('getIssueCompliance', async ({ payload, context }) => {
  return handlers.assessChangeControlTool(payload || {}, context || {});
});

resolver.define('recordSignoff', async ({ payload, context }) => {
  return handlers.verifyDualSignoffTool(payload || {}, context || {});
});

resolver.define('generatePacket', async ({ payload, context }) => {
  return handlers.generateAuditPacketTool(payload || {}, context || {});
});

resolver.define('verifyChain', async ({ payload, context }) => {
  return handlers.verifyAuditChainTool(payload || {}, context || {});
});

resolver.define('logCapa', async ({ payload, context }) => {
  return handlers.logCapaDeviationTool(payload || {}, context || {});
});

resolver.define('getConfluenceSopImpact', async ({ payload, context }) => {
  const pageId = payload?.pageId || context?.extension?.content?.id;
  return handlers.inspectConfluenceSopImpact(pageId);
});

export const panelResolver = resolver.getDefinitions();

export async function assessChangeControlFn(event, context) {
  return handlers.assessChangeControlTool(event, context);
}

export async function scanSopBlastRadiusFn(event, context) {
  return handlers.scanSopBlastRadiusTool(event, context);
}

export async function verifyDualSignoffFn(event, context) {
  return handlers.verifyDualSignoffTool(event, context);
}

export async function generateAuditPacketFn(event, context) {
  return handlers.generateAuditPacketTool(event, context);
}

export async function verifyAuditChainFn(event, context) {
  return handlers.verifyAuditChainTool(event, context);
}

export async function logCapaDeviationFn(event, context) {
  return handlers.logCapaDeviationTool(event, context);
}
