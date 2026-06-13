'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, readAll, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Access / DM policy (who may command the agent).
 *
 * These agents accept commands over messaging channels (Slack/Telegram/
 * Discord/WhatsApp). If the DM policy is "open" (especially with allowFrom
 * "*"), ANY sender on a connected channel can drive the agent — a stranger
 * giving orders to something with shell/file access. CWE-284, OWASP LLM06.
 */

function run(install) {
  const f = makeFinding({
    id: 'access-policy',
    title: 'Access policy (who is allowed to command the agent)',
    category: 'Access control',
    severity: SEV.HIGH,
    cwe: 'CWE-284',
    owasp: [OWASP.LLM06],
    fix: 'Set dmPolicy to "pairing" or "allowlist" and avoid allowFrom: ["*"]. ' +
      'Only let known identities command the agent; gate group chats behind ' +
      'mention + allowlist.'
  });

  const policyKeys = install.target.accessKeys || [];
  const openVals = (install.target.accessOpenValues || []).map((v) => v.toLowerCase());
  if (policyKeys.length === 0) {
    f.scanned = false;
    f.status = 'yellow';
    f.detail = 'NOT SCANNED — no access-policy keys known for this agent.';
    return f;
  }

  const policy = findKey(install, policyKeys);
  // allowFrom: ["*"] is the dangerous wildcard regardless of policy wording.
  const wildcardAllow = hasWildcardAllow(install);

  if ((policy.found && openVals.includes(String(policy.value).toLowerCase())) || wildcardAllow) {
    f.status = 'red';
    f.severity = SEV.HIGH;
    f.detail = 'The agent accepts commands from anyone on a connected channel ' +
      '(open DM policy / wildcard allowlist). A stranger who can message the bot ' +
      'can make it act on your accounts and machine.';
    if (policy.found) f.evidence.push(`${policy.key} = ${policy.value} in ${shortenHome(policy.source)}`);
    if (wildcardAllow) f.evidence.push(`allowFrom contains "*" in ${shortenHome(wildcardAllow.source)}`);
    return f;
  }

  if (policy.found) {
    f.status = 'green';
    f.detail = `Access is gated (${policy.key} = ${policy.value}).`;
    f.evidence.push(`${policy.key} = ${policy.value} in ${shortenHome(policy.source)}`);
    return f;
  }

  // No explicit policy found. OpenClaw defaults to "pairing" (safe-ish), but we
  // can't confirm channels are even configured — report low/uncertain, not pass.
  f.status = 'yellow';
  f.severity = SEV.LOW;
  f.detail = 'No explicit access policy found. Defaults are usually safe ' +
    '("pairing"), but confirm no channel is set to open/allow-all.';
  f.evidence.push(`no value for: ${policyKeys.join(', ')}`);
  return f;
}

function hasWildcardAllow(install) {
  const keys = install.target.allowFromKeys || [];
  for (const file of readAll(install)) {
    for (const k of keys) {
      // match  allowFrom: ["*"]  or  allowFrom = *  in raw text
      const re = new RegExp(`${k}["']?\\s*[:=]\\s*\\[?\\s*["']?\\*`, 'i');
      if (re.test(file.raw)) return { source: file.file };
    }
  }
  return null;
}

module.exports = { run };
