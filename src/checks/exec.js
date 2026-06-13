'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, readAll, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Command / shell execution policy.
 *
 * An agent that can run arbitrary shell with no allowlist turns one bad
 * instruction (or one prompt injection) into arbitrary code execution. We flag
 * the clearly-dangerous setting (OpenClaw `tools.exec.security="full"`) and the
 * absence of any command allowlist when a shell/terminal tool is in play.
 * CWE-250, OWASP LLM06. (Mirrors OpenClaw `tools.exec.security_full_configured`.)
 */

function run(install) {
  const f = makeFinding({
    id: 'command-exec',
    title: 'Command/shell execution policy (can it run arbitrary commands?)',
    category: 'Excessive agency',
    severity: SEV.MEDIUM,
    cwe: 'CWE-250',
    owasp: [OWASP.LLM06],
    fix: 'Constrain what the agent can execute: use a command allowlist, avoid ' +
      'host exec with security="full", and prefer a sandboxed terminal backend. ' +
      'Least-privilege tools are the main mitigation against prompt-injection RCE.'
  });

  // 1. The clearly-dangerous one: host exec running with security="full".
  const secKeys = install.target.execSecurityKeys || [];
  const unsafe = (install.target.execUnsafeValues || ['full']).map((x) => x.toLowerCase());
  if (secKeys.length) {
    const s = findKey(install, secKeys);
    if (s.found && unsafe.includes(String(s.value).toLowerCase())) {
      f.status = 'red';
      f.severity = SEV.HIGH;
      f.detail = 'Host command execution is configured with security="full" — the ' +
        'agent can run arbitrary host commands with no sandbox guard.';
      f.evidence.push(`${s.key} = ${s.value} in ${shortenHome(s.source)}`);
      return f;
    }
  }

  // 2. An explicit but EMPTY command allowlist => all commands permitted.
  const alKeys = install.target.allowlistKeys || [];
  for (const file of readAll(install)) {
    for (const k of alKeys) {
      const leaf = k.split('.').pop();
      // match  command_allowlist: []   or   command_allowlist=[]
      const re = new RegExp(`${leaf}["']?\\s*[:=]\\s*\\[\\s*\\]`, 'i');
      if (re.test(file.raw)) {
        f.status = 'yellow';
        f.severity = SEV.MEDIUM;
        f.detail = 'The command allowlist is empty, so the agent\'s shell/terminal ' +
          'tool may run any command. Add an allowlist of the commands it actually ' +
          'needs.';
        f.evidence.push(`${leaf} = [] (no restriction) in ${shortenHome(file.file)}`);
        return f;
      }
    }
  }

  // 3. A populated allowlist is good.
  const al = alKeys.length ? findKey(install, alKeys) : { found: false };
  if (al.found) {
    f.status = 'green';
    f.detail = 'A command allowlist is configured.';
    f.evidence.push(`${al.key} set in ${shortenHome(al.source)}`);
    return f;
  }

  // 4. A tool profile is a (coarser) policy — recognize it (OpenClaw).
  const profKeys = install.target.toolsProfileKeys || [];
  if (profKeys.length) {
    const p = findKey(install, profKeys);
    if (p.found) {
      const v = String(p.value).trim().toLowerCase();
      const permissive = (install.target.permissiveProfileValues || []).map((x) => x.toLowerCase());
      if (permissive.includes(v)) {
        f.status = 'yellow';
        f.severity = SEV.MEDIUM;
        f.detail = `Tool profile "${p.value}" is permissive — the agent can use a ` +
          `broad set of tools including command execution. Prefer a minimal profile ` +
          `or an explicit allowlist.`;
        f.evidence.push(`${p.key} = ${p.value} in ${shortenHome(p.source)}`);
        return f;
      }
      f.status = 'green';
      f.severity = SEV.INFO;
      f.detail = `A tool profile ("${p.value}") is set, which scopes available ` +
        `tools. Verify it limits or sandboxes command execution.`;
      f.evidence.push(`${p.key} = ${p.value} in ${shortenHome(p.source)}`);
      return f;
    }
  }

  // 5. Genuinely couldn't determine — SKIP (honest, low weight), not a WARN.
  f.scanned = false;
  f.status = 'yellow';
  f.severity = SEV.LOW;
  f.detail = 'Could not determine the command-execution policy from config. If the ' +
    'agent has a shell/terminal tool, confirm it is allowlisted or sandboxed.';
  f.evidence.push(`no exec/allowlist/profile key found`);
  return f;
}

module.exports = { run };
