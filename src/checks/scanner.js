'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { findKey, shortenHome } = require('../lib/config.js');
const { truthy } = require('../util/parse.js');

/*
 * CHECK — Command-content scanner (Hermes "Tirith").
 *
 * Hermes scans terminal commands for dangerous operations before running them,
 * inside a hardened sandbox. Disabling it removes a defense layer; leaving it
 * "fail-open" means commands still run if the scanner is unavailable. We only
 * flag explicit weakening, and report N/A for agents without this control.
 * CWE-693 (Protection Mechanism Failure), OWASP LLM06.
 */

function run(install) {
  const f = makeFinding({
    id: 'command-scanner',
    title: 'Command-content scanner (dangerous-command pre-screening)',
    category: 'Excessive agency',
    severity: SEV.MEDIUM,
    cwe: 'CWE-693',
    owasp: [OWASP.LLM06],
    fix: 'Keep the command scanner enabled (Hermes: security.tirith_enabled=true). ' +
      'For high-security setups, set tirith_fail_open=false so commands are blocked ' +
      'when the scanner is unavailable rather than allowed through.'
  });

  const enabledKeys = install.target.scannerEnabledKeys || [];
  if (enabledKeys.length === 0) {
    f.status = 'green';
    f.severity = SEV.INFO;
    f.detail = 'This agent has no built-in command-content scanner; rely on the ' +
      'sandbox, command allowlist, and approval checks instead.';
    return f;
  }

  const en = findKey(install, enabledKeys);
  // Default is enabled; flag only an explicit disable.
  if (en.found && !truthy(en.value)) {
    f.status = 'yellow';
    f.severity = SEV.MEDIUM;
    f.detail = 'The command-content scanner is disabled — dangerous shell commands ' +
      'are not pre-screened before execution.';
    f.evidence.push(`${en.key} = ${en.value} in ${shortenHome(en.source)}`);
    return f;
  }

  // Enabled (or default-on). Fail-open is the shipped default, so note it as a
  // hardening opportunity (INFO) rather than penalizing every default install.
  const foKeys = install.target.scannerFailOpenKeys || [];
  const fo = foKeys.length ? findKey(install, foKeys) : { found: false };
  f.status = 'green';
  if (fo.found && truthy(fo.value)) {
    f.severity = SEV.INFO;
    f.detail = 'Command scanning is enabled. It is set to fail-open (the default): ' +
      'commands still run if the scanner is unavailable. For a high-security ' +
      'setup, set tirith_fail_open=false to block on scanner failure.';
    f.evidence.push(`${fo.key} = ${fo.value} (default; consider fail-closed)`);
    return f;
  }
  f.detail = 'Command-content scanning is enabled.';
  if (en.found) f.evidence.push(`${en.key} = ${en.value} in ${shortenHome(en.source)}`);
  return f;
}

module.exports = { run };
