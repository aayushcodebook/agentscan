'use strict';

const { makeFinding } = require('./lib/findings.js');
const { SEV, OWASP, ATLAS } = require('./lib/frameworks.js');

/*
 * Correlation engine.
 *
 * Individual findings can each be "only" a warning, yet their COMBINATION is a
 * critical, exploitable chain. Real attacks are chains; a serious scanner names
 * them. Each rule looks at the per-install findings and, when a known-bad
 * combination is present, emits a synthetic finding that ties them together.
 */

function byId(findings) {
  const m = {};
  for (const f of findings) m[f.id] = f;
  return m;
}
const isFail = (f) => f && f.status === 'red';
const isFailOrWarn = (f) => f && (f.status === 'red' || f.status === 'yellow');

const RULES = [
  // 1. Exposed + no auth = the ClawJacked/ClawBleed exploit precondition.
  function exposedUnauthenticated(f) {
    if (isFailOrWarn(f['exposure']) && isFail(f['gateway-auth'])) {
      return makeFinding({
        id: 'chain-exposed-unauthenticated',
        title: 'CHAIN: network-exposed AND unauthenticated gateway (RCE-class)',
        category: 'Attack chain',
        severity: SEV.CRITICAL,
        status: 'red',
        synthetic: true,
        cwe: ['CWE-306', 'CWE-668'],
        owasp: [OWASP.LLM06],
        atlas: [ATLAS.T0049, ATLAS.T0012],
        references: [{ id: 'CVE-2026-25253', url: 'https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/' }],
        detail: 'The agent is reachable beyond localhost AND has no/weak gateway ' +
          'auth. This is precisely the ClawJacked/ClawBleed precondition: a remote ' +
          'or cross-site attacker can register as a trusted device and reach RCE. ' +
          'Fix either half immediately to break the chain.',
        evidence: [
          'exposure: ' + f['exposure'].status.toUpperCase(),
          'gateway-auth: ' + f['gateway-auth'].status.toUpperCase()
        ],
        fix: 'Bind to localhost AND set a strong gateway auth token, then upgrade ' +
          'past the fix (OpenClaw ≥ 3.1.8).'
      });
    }
    return null;
  },

  // 2. Untrusted input + unsandboxed + a malicious/suspicious extension present.
  function injectionWithLiveMalware(f) {
    const inj = f['prompt-injection'];
    const skills = f['skills'];
    if (isFailOrWarn(inj) && isFail(skills)) {
      return makeFinding({
        id: 'chain-injection-plus-malware',
        title: 'CHAIN: untrusted-input exposure AND a malicious/suspicious extension',
        category: 'Attack chain',
        severity: SEV.CRITICAL,
        status: 'red',
        synthetic: true,
        owasp: [OWASP.LLM01, OWASP.LLM03],
        atlas: [ATLAS.T0051_001, ATLAS.T0010],
        detail: 'The agent ingests untrusted content AND is running a flagged ' +
          'skill/plugin. A poisoned message/page plus hostile extension code is ' +
          'a direct path from prompt injection to code execution and exfiltration.',
        evidence: ['prompt-injection: ' + inj.status.toUpperCase(), 'skills: ' + skills.status.toUpperCase()],
        fix: 'Remove the flagged extension first, then harden the injection surface.'
      });
    }
    return null;
  },

  // 3. Exposed + open access policy = anyone can drive the agent remotely.
  function exposedAndOpenAccess(f) {
    if (isFailOrWarn(f['exposure']) && isFail(f['access-policy'])) {
      return makeFinding({
        id: 'chain-exposed-open-access',
        title: 'CHAIN: network-exposed AND open command policy',
        category: 'Attack chain',
        severity: SEV.CRITICAL,
        status: 'red',
        synthetic: true,
        cwe: ['CWE-284', 'CWE-668'],
        owasp: [OWASP.LLM06],
        detail: 'The agent is reachable beyond localhost AND accepts commands ' +
          'from anyone. That is remote, unauthenticated control of something with ' +
          'tool access.',
        evidence: ['exposure: ' + f['exposure'].status.toUpperCase(), 'access-policy: ' + f['access-policy'].status.toUpperCase()],
        fix: 'Lock the access policy to an allowlist AND bind to localhost.'
      });
    }
    return null;
  }
];

/* Run all rules against one install's findings; return synthetic findings. */
function correlate(findings) {
  const map = byId(findings);
  const out = [];
  for (const rule of RULES) {
    try { const r = rule(map); if (r) out.push(r); } catch (_) {}
  }
  return out;
}

module.exports = { correlate };
