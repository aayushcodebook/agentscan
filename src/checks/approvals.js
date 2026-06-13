'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP, ATLAS } = require('../lib/frameworks.js');
const { findKey, readAll, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Human-in-the-loop approvals for high-impact actions.
 *
 * The strongest mitigation against a hijacked or prompt-injected agent is a
 * human gate on destructive/high-impact actions (sending, spending, deleting,
 * shelling out). If approvals are set to auto/yolo, a single bad instruction
 * executes with no human in the loop. CWE-250, OWASP LLM06, ATLAS T0051.
 */

function run(install) {
  const f = makeFinding({
    id: 'approvals',
    title: 'Approvals (human-in-the-loop for high-impact actions)',
    category: 'Excessive agency',
    severity: SEV.MEDIUM,
    cwe: 'CWE-250',
    owasp: [OWASP.LLM06],
    atlas: [ATLAS.T0051],
    fix: 'Require manual approval for high-impact actions (Hermes: approvals.mode ' +
      '"manual"; keep destructive-action confirmations on). Auto-approving tools ' +
      'removes the last safeguard against prompt-injection-driven actions.'
  });

  const keys = install.target.approvalKeys || [];
  const safe = (install.target.approvalSafeValues || []).map((x) => x.toLowerCase());
  const unsafe = (install.target.approvalUnsafeValues || []).map((x) => x.toLowerCase());

  if (keys.length) {
    const a = findKey(install, keys);
    if (a.found) {
      const v = String(a.value).trim().toLowerCase();
      if (unsafe.includes(v)) {
        f.status = 'red';
        f.severity = SEV.HIGH;
        f.detail = 'High-impact actions are auto-approved (no human in the loop). ' +
          'A prompt injection or rogue instruction can act on your accounts/machine ' +
          'with no confirmation.';
        f.evidence.push(`${a.key} = ${a.value} in ${shortenHome(a.source)}`);
        return f;
      }
      if (safe.includes(v)) {
        f.status = 'green';
        f.detail = `Approvals require a human (${a.key} = ${a.value}).`;
        f.evidence.push(`${a.key} = ${a.value} in ${shortenHome(a.source)}`);
        // Secondary: subagents that auto-approve undercut the gate.
        if (autoApprovesSubagents(install)) {
          f.status = 'yellow';
          f.severity = SEV.MEDIUM;
          f.detail += ' However, sub-agents are set to auto-approve, which can ' +
            'bypass the human gate.';
          f.evidence.push('subagent_auto_approve is enabled');
        }
        return f;
      }
    }
  }

  // No approval setting found — honest low/unknown, not a false alarm.
  f.scanned = false;
  f.status = 'yellow';
  f.severity = SEV.LOW;
  f.detail = 'Could not determine an approval policy for high-impact actions. ' +
    'Confirm the agent asks before sending/spending/deleting or running commands.';
  f.evidence.push(`no value for: ${keys.join(', ') || '(no approval key known for this agent)'}`);
  return f;
}

function autoApprovesSubagents(install) {
  for (const file of readAll(install)) {
    if (/subagent_auto_approve\s*[:=]\s*true/i.test(file.raw)) return true;
  }
  return false;
}

module.exports = { run };
