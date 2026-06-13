'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Sensitive-data redaction (logs & tool output).
 *
 * Agents redact API-key/token/password-shaped strings from tool output before
 * it enters the conversation and the logs. If that's turned OFF, secrets leak
 * into transcripts, status, and on-disk logs (a real, reported failure mode).
 * Default is ON for both agents, so we only flag an EXPLICIT disable — no false
 * alarm on defaults. CWE-532, OWASP LLM02.
 */

const OFF = new Set(['false', 'off', 'none', 'disabled', 'no', '0']);

function isDisabled(v) {
  if (v === false) return true;
  if (v === true) return false;
  return OFF.has(String(v).trim().toLowerCase());
}

function run(install) {
  const f = makeFinding({
    id: 'secret-redaction',
    title: 'Secret redaction (are secrets stripped from logs & output?)',
    category: 'Secrets',
    severity: SEV.HIGH,
    cwe: 'CWE-532',
    owasp: [OWASP.LLM02],
    fix: 'Keep secret redaction ON (Hermes: security.redact_secrets=true; ' +
      'OpenClaw: logging.redactSensitive). With it off, API keys/tokens leak ' +
      'into transcripts and on-disk logs.'
  });

  const keys = install.target.redactionKeys || [];
  if (keys.length === 0) {
    f.status = 'green';
    f.severity = SEV.INFO;
    f.detail = 'No redaction toggle is known for this agent; assuming the secure default.';
    return f;
  }

  const hit = findKey(install, keys);
  if (hit.found && isDisabled(hit.value)) {
    f.status = 'red';
    f.detail = 'Secret redaction is DISABLED — API keys, tokens, and passwords in ' +
      'tool output will be written to the conversation and logs in the clear.';
    f.evidence.push(`${hit.key} = ${hit.value} in ${shortenHome(hit.source)}`);
    return f;
  }

  // Secondary, informational: PII redaction is OFF by default (a privacy
  // preference, not a security misconfig) — note it without penalizing.
  const piiKeys = install.target.piiRedactionKeys || [];
  const pii = piiKeys.length ? findKey(install, piiKeys) : { found: false };

  f.status = 'green';
  if (pii.found && isDisabled(pii.value)) {
    f.severity = SEV.INFO;
    f.detail = 'Secret redaction is on (good). Note: PII redaction is off (the ' +
      'default) — fine for personal use, but enable it for shared or regulated ' +
      'deployments.';
    f.evidence.push(`${pii.key} = ${pii.value} (default; enable for shared use)`);
    return f;
  }
  f.detail = hit.found
    ? `Secret redaction is enabled (${hit.key} = ${hit.value}).`
    : 'Secret redaction is at its secure default (enabled).';
  if (hit.found) f.evidence.push(`${hit.key} = ${hit.value} in ${shortenHome(hit.source)}`);
  return f;
}

module.exports = { run, isDisabled };
