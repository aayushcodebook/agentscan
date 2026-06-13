'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Sandboxing / excessive agency.
 *
 * An agent that runs tools unsandboxed has the full power of your user account:
 * one bad instruction (or one prompt injection) becomes shell access to
 * everything. Running the gateway as root makes it worse. CWE-250, OWASP LLM06.
 */
function run(install) {
  const f = makeFinding({
    id: 'sandbox',
    title: 'Agent autonomy / sandboxing (how much can it do unchecked?)',
    category: 'Excessive agency',
    severity: SEV.MEDIUM,
    cwe: 'CWE-250',
    owasp: [OWASP.LLM06],
    fix: 'Run agent sessions sandboxed (OpenClaw: agents.defaults.sandbox.mode ' +
      '"non-main" or "all"), scope tools to least-privilege, and never run the ' +
      'gateway as root.'
  });

  const evidence = [];
  let worst = 'green';

  // 1. Sandbox mode.
  const sbKeys = install.target.sandboxKeys || [];
  const unsafe = (install.target.sandboxUnsafeValues || []).map((v) => v.toLowerCase());
  const safe = (install.target.sandboxSafeValues || []).map((v) => v.toLowerCase());
  const sb = findKey(install, sbKeys);
  if (sb.found) {
    const v = String(sb.value).toLowerCase();
    if (unsafe.includes(v)) { worst = 'red'; evidence.push(`sandbox disabled (${sb.key} = ${sb.value}) in ${shortenHome(sb.source)}`); }
    else if (safe.includes(v)) { evidence.push(`sandbox enabled (${sb.key} = ${sb.value})`); }
    else { worst = worse(worst, 'yellow'); evidence.push(`sandbox set to "${sb.value}" — verify it isolates sessions`); }
  } else {
    worst = worse(worst, 'yellow');
    evidence.push('no sandbox setting found — sessions may run unsandboxed by default');
  }

  // 2. Running as root (POSIX).
  if (process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0) {
    worst = 'red';
    evidence.push('agentscan is running as root — if the agent runs as root too, any tool call is root-level');
  }

  f.status = worst;
  f.severity = worst === 'red' ? SEV.HIGH : SEV.MEDIUM;
  f.evidence = evidence;
  f.detail = worst === 'red'
    ? 'The agent can execute tools with little/no isolation. A single bad ' +
      'instruction or prompt injection becomes full access to your account/machine.'
    : worst === 'yellow'
      ? 'Could not confirm session sandboxing. Verify the agent isolates tool ' +
        'execution rather than running with your full privileges.'
      : 'Agent sessions are sandboxed.';
  return f;
}

function worse(a, b) {
  const rank = { green: 0, yellow: 1, red: 2 };
  return rank[a] >= rank[b] ? a : b;
}

module.exports = { run };
