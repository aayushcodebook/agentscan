'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Permissive CORS.
 *
 * A wildcard CORS origin ("*") on the agent's local API lets ANY website your
 * browser visits make cross-origin calls to the agent — a key ingredient in
 * the cross-site-WebSocket/HTTP class of attacks. CWE-942.
 */
function run(install) {
  const f = makeFinding({
    id: 'cors',
    title: 'Cross-origin policy (can any website call the agent?)',
    category: 'Network',
    severity: SEV.MEDIUM,
    cwe: 'CWE-942',
    owasp: [OWASP.LLM06],
    fix: 'Restrict CORS to explicit, trusted origins. Never use "*" for an API ' +
      'that can act on your behalf (Hermes: API_SERVER_CORS_ORIGINS; OpenClaw: ' +
      'cors.allowedOrigins).'
  });

  const keys = install.target.corsKeys || [];
  if (keys.length === 0) { f.scanned = false; f.status = 'yellow'; f.detail = 'NOT SCANNED — no CORS keys known for this agent.'; return f; }

  const hit = findKey(install, keys);
  if (!hit.found) {
    f.status = 'green';
    f.detail = 'No permissive CORS origin configured (defaults are restrictive).';
    return f;
  }
  const val = String(hit.value).trim();
  if (val === '*' || /(^|[,\s])\*([,\s]|$)/.test(val)) {
    f.status = 'red';
    f.severity = SEV.HIGH;
    f.detail = 'CORS is set to a wildcard ("*"). Any website you visit can make ' +
      'cross-origin requests to the agent API.';
    f.evidence.push(`${hit.key} = ${val} in ${shortenHome(hit.source)}`);
    return f;
  }
  f.status = 'green';
  f.detail = `CORS restricted to specific origins.`;
  f.evidence.push(`${hit.key} = ${val} in ${shortenHome(hit.source)}`);
  return f;
}

module.exports = { run };
