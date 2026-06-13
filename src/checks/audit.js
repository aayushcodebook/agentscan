'use strict';

const fs = require('fs');
const path = require('path');
const { readConfigText, lookupKey, truthy } = require('../util/parse.js');

/*
 * CHECK 4 — Audit logging.
 *
 * An autonomous agent that acts on your accounts with no record of what it did
 * is a compliance and incident-response problem: if it sends a bad email or a
 * skill goes rogue, there's no trail. We look for an audit-logging flag in
 * config, and for an actual audit log file on disk.
 */

const LOG_HINTS = ['audit.log', 'audit.jsonl', 'actions.log', 'activity.log', 'audit/'];

/* Per-target log directories (e.g. ~/.hermes/logs, ~/.openclaw/logs). */
function logDirHints(install) {
  return (install.target.logDirs || []).concat(LOG_HINTS);
}

function findAuditConfig(install) {
  for (const cf of install.configFiles) {
    let content;
    try { content = fs.readFileSync(cf, 'utf8'); } catch (_) { continue; }
    const parsed = readConfigText(content);
    for (const key of install.target.auditKeys) {
      const { found, value } = lookupKey(parsed, key);
      if (found) return { source: cf, key, value, on: truthy(value) };
    }
  }
  return null;
}

function findAuditLogFile(install) {
  for (const hint of logDirHints(install)) {
    const abs = path.join(install.homeDir, hint);
    try {
      const st = fs.statSync(abs);
      if (st.isFile() && st.size > 0) return { file: abs, size: st.size };
      if (st.isDirectory()) {
        const entries = fs.readdirSync(abs);
        if (entries.length > 0) return { file: abs, size: null };
      }
    } catch (_) { /* not present */ }
  }
  return null;
}

function run(install) {
  const finding = {
    id: 'audit',
    title: 'Audit logging (a record of what the agent did)',
    category: 'Logging',
    status: 'green',
    severity: 'medium',
    cwe: 'CWE-778',
    owasp: [],
    atlas: [],
    references: [],
    detail: '',
    evidence: [],
    fix: ''
  };

  const cfg = findAuditConfig(install);
  const logFile = findAuditLogFile(install);

  if (cfg && cfg.on) {
    finding.status = 'green';
    finding.detail = 'Audit logging is enabled in config.';
    finding.evidence.push(`${cfg.key} = ${cfg.value} in ${shorten(cfg.source)}`);
    if (logFile) finding.evidence.push(`audit log present at ${shorten(logFile.file)}`);
  } else if (!cfg && logFile) {
    finding.status = 'yellow';
    finding.detail =
      'An audit log file exists but no audit setting was found in config — ' +
      'logging may be partial or default. Confirm every agent action is recorded.';
    finding.evidence.push(`log file: ${shorten(logFile.file)}`);
  } else {
    finding.status = cfg && !cfg.on ? 'red' : 'yellow';
    finding.detail =
      cfg && !cfg.on
        ? 'Audit logging is explicitly turned OFF. There is no record of what ' +
          'your agent does — bad for incident response and a blocker for any ' +
          'regulated environment (SOC2 / HIPAA / GDPR).'
        : 'No audit logging configured and no audit log file found. By default ' +
          'these agents keep no record of their actions.';
    if (cfg) finding.evidence.push(`${cfg.key} = ${cfg.value} in ${shorten(cfg.source)}`);
    else finding.evidence.push('no audit setting found in any config file');
  }

  finding.fix =
    'Turn on audit logging so every action (emails sent, files touched, API ' +
    'calls) is recorded with a timestamp, and centralize the logs somewhere ' +
    'tamper-evident for retention and incident response.';

  return finding;
}

function shorten(p) {
  const home = require('os').homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { run };
