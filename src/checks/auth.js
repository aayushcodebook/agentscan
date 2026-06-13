'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP, ATLAS } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');
const { truthy } = require('../util/parse.js');
const exposure = require('./exposure.js');

/*
 * CHECK — Gateway authentication.
 *
 * The exposure check asks "is the door open?". This asks "is it LOCKED?".
 * An open port with no auth token/password is the actual precondition behind
 * the ClawJacked / ClawBleed auth-bypass class (CVE-2026-25253): a malicious
 * page brute-forces or steals the gateway credential and registers as a
 * trusted device. Severity is escalated when we can confirm the agent is also
 * network-exposed (the correlation engine emits the compound critical).
 */

// A weak/placeholder credential is barely better than none.
function looksWeak(v) {
  if (v == null) return true;
  const s = String(v).trim();
  if (s.length < 12) return true;
  if (/^(changeme|password|admin|secret|token|test|1234|0000)/i.test(s)) return true;
  if (/^\$\{?[A-Z0-9_]+\}?$/.test(s)) return false; // env ref — assume real
  return false;
}

function run(install) {
  const f = makeFinding({
    id: 'gateway-auth',
    title: 'Gateway authentication (is the local API/WebSocket protected?)',
    category: 'Access control',
    severity: SEV.HIGH,
    cwe: ['CWE-306', 'CWE-307'],
    owasp: [OWASP.LLM06],
    atlas: [ATLAS.T0012, ATLAS.T0049],
    references: [{ id: 'CVE-2026-25253', url: 'https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/' }],
    fix: 'Set a strong gateway auth token/password (OpenClaw: gateway.auth.token ' +
      'or OPENCLAW_GATEWAY_TOKEN; Hermes: API_SERVER_KEY), keep the port bound to ' +
      'localhost, and upgrade past the ClawJacked/ClawBleed fix (OpenClaw ≥ 3.1.8).'
  });

  const keys = install.target.authKeys || [];
  if (keys.length === 0) {
    f.scanned = false;
    f.status = 'yellow';
    f.detail = 'NOT SCANNED — no auth-config keys are known for this agent.';
    return f;
  }

  // If the local API server is OPT-IN (e.g. Hermes' API_SERVER_ENABLED) and is
  // not enabled, there is no server to protect — missing auth is not a finding.
  const enabledKeys = install.target.authEnabledKeys || [];
  if (enabledKeys.length > 0) {
    const en = findKey(install, enabledKeys);
    if (!en.found || !truthy(en.value)) {
      f.status = 'green';
      f.severity = SEV.INFO;
      f.detail = 'The optional local API server is not enabled, so there is no ' +
        'exposed endpoint to authenticate. If you enable it, set a strong key.';
      f.evidence.push(`${enabledKeys[0]} not enabled`);
      return f;
    }
  }

  const hit = findKey(install, keys);
  const exposed = isLikelyExposed(install);

  if (!hit.found) {
    // No credential configured at all.
    f.status = 'red';
    f.severity = exposed ? SEV.CRITICAL : SEV.HIGH;
    f.detail = exposed
      ? 'No gateway auth token/password is configured AND the agent appears ' +
        'network-exposed. This is the ClawJacked/ClawBleed precondition: anyone ' +
        'who can reach the port can register as a trusted device and run code.'
      : 'No gateway auth token/password is configured. It is currently bound to ' +
        'localhost, but any local process (including a malicious skill or webpage ' +
        'via CSWSH) can talk to it unauthenticated.';
    f.evidence.push(`no value found for: ${keys.join(', ')}`);
    return f;
  }

  if (looksWeak(hit.value)) {
    f.status = 'red';
    f.severity = exposed ? SEV.CRITICAL : SEV.HIGH;
    f.detail = 'A gateway credential is set but looks weak/short/default — local ' +
      'connections are not rate-limited, so a weak password is brute-forceable ' +
      '(the ClawJacked technique).';
    f.evidence.push(`${hit.key} set in ${shortenHome(hit.source)} but appears weak`);
    return f;
  }

  f.status = 'green';
  f.detail = 'A gateway auth credential is configured.';
  f.evidence.push(`${hit.key} present in ${shortenHome(hit.source)}`);
  return f;
}

/* Reuse the exposure check's classification for the auth severity bump. */
function isLikelyExposed(install) {
  try {
    const e = exposure.run(install);
    return e.status === 'red' || e.status === 'yellow';
  } catch (_) { return false; }
}

module.exports = { run, looksWeak };
