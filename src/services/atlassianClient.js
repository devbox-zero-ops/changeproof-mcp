import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import { extractControlledDocCodes, extractTextFromAdf } from '../core/complianceEngine.js';

const CHAIN_KEY_PREFIX = 'cp:chain:';
const CAPA_KEY_PREFIX = 'cp:capa:';
const STANDARD_KEY_PREFIX = 'cp:std:';

function safeIssueKey(issueKey) {
  const clean = String(issueKey || '').trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_]+-\d+$/.test(clean)) {
    throw new Error(`Invalid Jira issue key format: "${issueKey}"`);
  }
  return clean;
}

/**
 * Production Atlassian Cloud + Forge KVS adapter.
 * Every method supports dependency injection in src/mcp/tools.js for deterministic offline tests.
 */
export function createAtlassianAdapter() {
  return {
    async getCurrentActor(context = {}) {
      if (context.accountId) {
        return {
          accountId: context.accountId,
          displayName: context.displayName || context.accountId,
        };
      }
      try {
        const res = await api.asUser().requestJira(route`/rest/api/3/myself`, {
          headers: { Accept: 'application/json' },
        });
        if (res.ok) {
          const data = await res.json();
          return {
            accountId: data.accountId || 'unknown-actor',
            displayName: data.displayName || data.accountId || 'Atlassian User',
          };
        }
      } catch {
        // Fallback when invoked outside interactive user context
      }
      return { accountId: 'system-actor', displayName: 'System Actor' };
    },

    async getJiraIssue(issueKey) {
      const key = safeIssueKey(issueKey);
      const res = await api
        .asUser()
        .requestJira(
          route`/rest/api/3/issue/${key}?fields=summary,description,status,priority,issuetype,labels,reporter,assignee,comment,issuelinks,created,updated`,
          { headers: { Accept: 'application/json' } },
        );
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(`Jira issue lookup failed (${res.status}) for ${key}: ${msg.slice(0, 180)}`);
      }
      const raw = await res.json();
      const fields = raw.fields || {};
      return {
        key: raw.key || key,
        id: raw.id || '',
        summary: fields.summary || '',
        description: fields.description || '',
        status: fields.status?.name || 'Unknown',
        priority: fields.priority?.name || 'Medium',
        issueType: fields.issuetype?.name || 'Change',
        labels: Array.isArray(fields.labels) ? fields.labels : [],
        reporterAccountId: fields.reporter?.accountId || null,
        reporterName: fields.reporter?.displayName || '',
        assigneeAccountId: fields.assignee?.accountId || null,
        assigneeName: fields.assignee?.displayName || '',
        comments: Array.isArray(fields.comment?.comments)
          ? fields.comment.comments.map((c) => ({
              id: c.id,
              authorAccountId: c.author?.accountId || null,
              body: c.body,
              created: c.created,
            }))
          : [],
        issueLinks: Array.isArray(fields.issuelinks) ? fields.issuelinks : [],
        created: fields.created || null,
        updated: fields.updated || null,
      };
    },

    async getJiraRemoteLinks(issueKey) {
      const key = safeIssueKey(issueKey);
      try {
        const res = await api.asUser().requestJira(route`/rest/api/3/issue/${key}/remotelink`, {
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) return [];
        const links = await res.json();
        return Array.isArray(links)
          ? links.map((l) => ({
              id: String(l.id || ''),
              relationship: l.relationship || 'relates to',
              title: l.object?.title || '',
              url: l.object?.url || '',
              source: 'jira-remote-link',
            }))
          : [];
      } catch {
        return [];
      }
    },

    /**
     * Queries Atlassian Teamwork Graph / cross-product links when available on the tenant,
     * falling back cleanly to Jira remote links if TWG scopes are not enabled.
     */
    async getTeamworkGraphLinks(issueKey, issueId = '') {
      const remoteLinks = await this.getJiraRemoteLinks(issueKey);
      const graphLinks = [...remoteLinks];
      if (!issueId) return graphLinks;

      try {
        const res = await api.asUser().requestConfluence(
          route`/wiki/rest/api/search?cql=${`text ~ "${issueKey}" AND type = "page"`}&limit=10`,
          { headers: { Accept: 'application/json' } },
        );
        if (res.ok) {
          const data = await res.json();
          for (const item of data.results || []) {
            const content = item.content || item;
            graphLinks.push({
              id: String(content.id || ''),
              relationship: 'references-change',
              title: content.title || item.title || '',
              url: content._links?.webui || '',
              source: 'teamwork-cross-reference',
            });
          }
        }
      } catch {
        // Non-fatal if Confluence search is unavailable in a Jira-only tenant
      }
      return graphLinks;
    },

    async searchConfluenceSops(issue) {
      const text = [issue.summary, extractTextFromAdf(issue.description)].join(' ');
      const codes = extractControlledDocCodes(text);
      const clauses = codes.slice(0, 6).map((c) => `text ~ "${c}"`);
      if (clauses.length === 0) {
        clauses.push(`title ~ "SOP" OR title ~ "Procedure" OR text ~ "${issue.key}"`);
      }
      const cql = `type = "page" AND (${clauses.join(' OR ')})`;

      try {
        const res = await api
          .asUser()
          .requestConfluence(
            route`/wiki/rest/api/search?cql=${cql}&expand=content.version,content.metadata.labels,content.body.storage&limit=12`,
            { headers: { Accept: 'application/json' } },
          );
        if (!res.ok) return [];
        const data = await res.json();
        return (data.results || []).map((item) => {
          const c = item.content || item;
          const labels = (c.metadata?.labels?.results || []).map((l) => l.name);
          return {
            id: String(c.id || ''),
            title: c.title || item.title || 'Untitled SOP',
            excerpt: item.excerpt || c.body?.storage?.value || '',
            version: c.version?.number || 1,
            lastUpdated: c.version?.when || item.lastModified || null,
            labels,
            url: c._links?.webui || '',
          };
        });
      } catch {
        return [];
      }
    },

    async getConfluencePage(pageId) {
      const id = String(pageId || '').trim();
      if (!id) throw new Error('Confluence pageId is required.');
      const res = await api
        .asUser()
        .requestConfluence(
          route`/wiki/rest/api/content/${id}?expand=version,metadata.labels,body.storage`,
          { headers: { Accept: 'application/json' } },
        );
      if (!res.ok) {
        throw new Error(`Confluence page fetch failed (${res.status}) for ${id}`);
      }
      const c = await res.json();
      return {
        id: String(c.id || id),
        title: c.title || 'Untitled SOP',
        bodyText: String(c.body?.storage?.value || '').replace(/<[^>]+>/g, ' '),
        version: c.version?.number || 1,
        lastUpdated: c.version?.when || null,
        labels: (c.metadata?.labels?.results || []).map((l) => l.name),
      };
    },

    async searchJiraIssuesByText(queryText) {
      const q = String(queryText || '').replace(/"/g, '').trim();
      if (!q) return [];
      try {
        const jql = `text ~ "${q}" ORDER BY updated DESC`;
        const res = await api
          .asUser()
          .requestJira(
            route`/rest/api/3/search/jql?jql=${jql}&maxResults=10&fields=summary,status,priority,updated`,
            { headers: { Accept: 'application/json' } },
          );
        if (!res.ok) return [];
        const data = await res.json();
        return (data.issues || []).map((it) => ({
          key: it.key,
          summary: it.fields?.summary || '',
          status: it.fields?.status?.name || 'Unknown',
          priority: it.fields?.priority?.name || 'Medium',
          updated: it.fields?.updated || null,
        }));
      } catch {
        return [];
      }
    },

    async postJiraAuditComment(issueKey, markdownText) {
      const key = safeIssueKey(issueKey);
      const bodyAdf = {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [{ type: 'text', text: String(markdownText).slice(0, 4000) }],
          },
        ],
      };
      try {
        const res = await api.asUser().requestJira(route`/rest/api/3/issue/${key}/comment`, {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: JSON.stringify({ body: bodyAdf }),
        });
        return { posted: res.ok, status: res.status };
      } catch (err) {
        return { posted: false, error: String(err) };
      }
    },

    async getAuditChain(issueKey) {
      const key = safeIssueKey(issueKey);
      const entries = await kvs.get(`${CHAIN_KEY_PREFIX}${key}`);
      return Array.isArray(entries) ? entries : [];
    },

    async saveAuditChain(issueKey, entries) {
      const key = safeIssueKey(issueKey);
      await kvs.set(`${CHAIN_KEY_PREFIX}${key}`, entries);
      return entries;
    },

    async getCapaRecords(issueKey) {
      const key = safeIssueKey(issueKey);
      const records = await kvs.get(`${CAPA_KEY_PREFIX}${key}`);
      return Array.isArray(records) ? records : [];
    },

    async saveCapaRecords(issueKey, records) {
      const key = safeIssueKey(issueKey);
      await kvs.set(`${CAPA_KEY_PREFIX}${key}`, records);
      return records;
    },

    async getSelectedStandard(issueKey) {
      const key = safeIssueKey(issueKey);
      const saved = await kvs.get(`${STANDARD_KEY_PREFIX}${key}`);
      return typeof saved === 'string' && saved ? saved : 'FDA_21CFR11';
    },

    async saveSelectedStandard(issueKey, standardCode) {
      const key = safeIssueKey(issueKey);
      await kvs.set(`${STANDARD_KEY_PREFIX}${key}`, standardCode);
      return standardCode;
    },
  };
}
