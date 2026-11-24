import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(rootDir, 'manifest.yml');
const manifest = yaml.load(fs.readFileSync(manifestPath, 'utf8'));

const errors = [];

// 1. Validate against official @forge/manifest JSON Schema via local AJV if installed
const schemaPath = path.join(
  rootDir,
  'node_modules',
  '@forge',
  'cli',
  'node_modules',
  '@forge',
  'manifest',
  'out',
  'schema',
  'manifest-schema.json',
);

if (fs.existsSync(schemaPath)) {
  const ajvPkgPath = path.join(rootDir, 'node_modules', '@forge', 'cli', 'node_modules', 'ajv', 'dist', 'ajv.js');
  if (fs.existsSync(ajvPkgPath)) {
    const { default: Ajv } = await import(`file://${ajvPkgPath.replace(/\\/g, '/')}`);
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    if (!validate(manifest)) {
      for (const e of validate.errors || []) {
        errors.push(`Schema error at ${e.instancePath || '/'}: ${e.message} (${JSON.stringify(e.params)})`);
      }
    }
  }
}

// 2. Cross-reference module keys, functions, resources, and exported handlers
const mods = manifest.modules || {};
const actionKeys = new Set((mods.action || []).map((a) => a.key));
const fnKeys = new Set((mods.function || []).map((f) => f.key));
const resKeys = new Set((manifest.resources || []).map((r) => r.key));

for (const mcp of mods['rovo:mcp'] || []) {
  for (const t of mcp.tools || []) {
    if (!actionKeys.has(t)) errors.push(`rovo:mcp tool "${t}" missing from modules.action`);
  }
}

for (const ag of mods['rovo:agent'] || []) {
  for (const a of ag.actions || []) {
    if (!actionKeys.has(a)) errors.push(`rovo:agent action "${a}" missing from modules.action`);
  }
}

for (const act of mods.action || []) {
  if (!fnKeys.has(act.function)) {
    errors.push(`action "${act.key}" references unknown function "${act.function}"`);
  }
}

for (const res of manifest.resources || []) {
  const full = path.join(rootDir, res.path);
  if (!fs.existsSync(full)) {
    errors.push(`resource "${res.key}" file does not exist: ${res.path}`);
  }
}

for (const panel of [...(mods['jira:issuePanel'] || []), ...(mods['confluence:contentAction'] || [])]) {
  if (panel.resource && !resKeys.has(panel.resource)) {
    errors.push(`UI module "${panel.key}" references unknown resource "${panel.resource}"`);
  }
  if (panel.resolver?.function && !fnKeys.has(panel.resolver.function)) {
    errors.push(`UI module "${panel.key}" references unknown resolver "${panel.resolver.function}"`);
  }
}

// Verify every handler referenced in manifest.yml exists as an export in src/index.js
const indexSource = fs.readFileSync(path.join(rootDir, 'src', 'index.js'), 'utf8');
for (const fn of mods.function || []) {
  const [, exportName] = String(fn.handler || '').split('.');
  const rx = new RegExp(`export\\s+(?:async\\s+function|const)\\s+${exportName}\\b`);
  if (!rx.test(indexSource)) {
    errors.push(`function "${fn.key}" handler "${fn.handler}" not exported in src/index.js`);
  }
}

if (errors.length > 0) {
  console.error('MANIFEST_VALIDATION_FAILED:\n' + errors.map((e) => '  - ' + e).join('\n'));
  process.exit(1);
}

console.log(
  `MANIFEST_VALIDATION_PASS | rovo:mcp_tools=${(mods['rovo:mcp']?.[0]?.tools || []).length} | rovo:agents=${(mods['rovo:agent'] || []).length} | functions=${fnKeys.size} | resources=${resKeys.size} | runtime=${manifest.app?.runtime?.name}`,
);
