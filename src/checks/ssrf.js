'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');
const { truthy } = require('../util/parse.js');

/*
 * CHECK — SSRF / private-URL access.
 *
 * The agent's URL-capable tools (web search, extract, vision, browser, media
 * download) block private destinations by default — RFC1918, loopback,
 * link-local, CGNAT, and cloud-metadata (169.254.169.254). Enabling
 * `allow_private_urls` removes that guard, so a prompt-injected URL can reach
 * your internal network or steal cloud credentials from the metadata endpoint.
 * Default is fail-closed, so we only flag an EXPLICIT enable. CWE-918, OWASP LLM06.
 */

function run(install) {
  const f = makeFinding({
    id: 'ssrf-private-urls',
    title: 'SSRF guard (can the agent fetch private/internal URLs?)',
    category: 'Network',
    severity: SEV.HIGH,
    cwe: 'CWE-918',
    owasp: [OWASP.LLM06],
    fix: 'Leave private-URL access OFF (Hermes: security.allow_private_urls=false). ' +
      'With it on, a prompt-injected link can reach 10.0.0.0/8, 192.168.x, ' +
      'localhost, or the cloud metadata endpoint (169.254.169.254) and exfiltrate ' +
      'credentials. Only enable on an isolated host where that risk is acceptable.'
  });

  const keys = install.target.ssrfAllowKeys || [];
  if (keys.length === 0) {
    f.status = 'green';
    f.severity = SEV.INFO;
    f.detail = 'No private-URL toggle is known for this agent; assuming the secure ' +
      '(fail-closed) default.';
    return f;
  }

  const hit = findKey(install, keys);
  if (hit.found && truthy(hit.value)) {
    f.status = 'red';
    f.detail = 'Private-URL access is ENABLED — the agent\'s web/browser tools can ' +
      'reach internal hosts and the cloud metadata endpoint. A poisoned URL becomes ' +
      'an SSRF / credential-theft path.';
    f.evidence.push(`${hit.key} = ${hit.value} in ${shortenHome(hit.source)}`);
    return f;
  }

  f.status = 'green';
  f.detail = 'Private/internal URL access is disabled (SSRF guard active).';
  if (hit.found) f.evidence.push(`${hit.key} = ${hit.value} in ${shortenHome(hit.source)}`);
  return f;
}

module.exports = { run };
