'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP, ATLAS } = require('../lib/frameworks.js');
const { readAll, shortenHome } = require('../lib/config.js');

/*
 * CHECK — MCP server trust (tool supply chain).
 *
 * Agents call external MCP servers for tools. A REMOTE MCP server is third-party
 * code in your agent's control sphere: it can return malicious tool definitions
 * or exfiltrate whatever you pass it. CWE-829, OWASP LLM03, ATLAS T0010.
 *
 * IMPORTANT precision note: an actual MCP SERVER LIST lives under a dedicated key
 * (`mcpServers` / `mcp.servers`). We must NOT trigger on the mere word "mcp"
 * appearing elsewhere (e.g. Hermes' `auxiliary.mcp` is a model config, not a
 * server; `inherit_mcp_toolsets` / `mcp_reload_confirm` are flags). And we only
 * extract URLs from inside the server block — never the whole file — so a model
 * provider URL (model.base_url) is never mislabeled as an MCP server.
 */

const REMOTE_RE = /\bhttps?:\/\/[^\s"'),]+/gi;
const LOCALHOSTY = /(127\.0\.0\.1|localhost|::1|0\.0\.0\.0)/i;

// Locate a real MCP server-list block and return its (bounded) text, or null.
function findServerBlock(raw) {
  // de-facto MCP server-list keys: mcpServers, mcp_servers, mcp.servers, or a
  // `servers:` block nested under an `mcp:` section.
  const re = /\b(mcpServers|mcp_servers)\b\s*[:=]\s*([\s\S]{0,1000})/i;
  let m = raw.match(re);
  if (m) return m[2];
  // `mcp: { ... servers: {...} }` (dotted/nested form)
  m = raw.match(/\bmcp\b\s*[:=]\s*[\{\[][\s\S]{0,1200}?\bservers\b\s*[:=]\s*([\s\S]{0,1000})/i);
  if (m) return m[1];
  return null;
}

function run(install) {
  const f = makeFinding({
    id: 'mcp-trust',
    title: 'MCP tool servers (external code the agent can call)',
    category: 'Supply chain',
    severity: SEV.MEDIUM,
    cwe: 'CWE-829',
    owasp: [OWASP.LLM03],
    atlas: [ATLAS.T0010],
    fix: 'Prefer local/stdio MCP servers you control. For remote servers, pin ' +
      'to trusted hosts over HTTPS, review their tool definitions, and never ' +
      'point at unknown endpoints.'
  });

  let block = null, source = null;
  for (const file of readAll(install)) {
    const b = findServerBlock(file.raw);
    if (b) { block = b; source = file.file; break; }
  }

  if (block == null) {
    f.status = 'green';
    f.detail = 'No MCP tool servers configured.';
    return f;
  }

  // Extract remote (non-localhost) URLs from WITHIN the server block only.
  const remotes = new Set();
  for (const u of block.match(REMOTE_RE) || []) {
    if (!LOCALHOSTY.test(u)) remotes.add(u.replace(/[.,)\]}]+$/, ''));
  }

  if (remotes.size > 0) {
    f.status = 'yellow';
    f.severity = SEV.MEDIUM;
    f.detail = `Agent has ${remotes.size} remote MCP server(s) configured. Each is ` +
      `third-party code in your agent's trust boundary — confirm you control or ` +
      `trust every one.`;
    for (const u of [...remotes].slice(0, 6)) f.evidence.push(`remote MCP: ${u}`);
    if (source) f.evidence.push(`configured in ${shortenHome(source)}`);
    return f;
  }

  f.status = 'green';
  f.detail = 'MCP servers are configured but appear local/stdio (lower risk).';
  if (source) f.evidence.push(`configured in ${shortenHome(source)}`);
  return f;
}

module.exports = { run, findServerBlock };
