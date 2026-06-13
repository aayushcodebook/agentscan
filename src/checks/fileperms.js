'use strict';

const fs = require('fs');
const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { shortenHome } = require('../lib/config.js');

/*
 * CHECK — Permissions on secret-bearing files.
 *
 * A key in ~/.openclaw/.env is only as safe as the file's mode. If it's group-
 * or world-readable, any other user or process on the box can read your keys,
 * even though they're "out of config". CWE-732. POSIX only (skipped on Windows).
 */

const SECRET_FILES = ['.env', 'config.json', 'openclaw.json', 'credentials.json', 'secrets.json', '.clawhub'];

function run(install) {
  const f = makeFinding({
    id: 'file-perms',
    title: 'File permissions on secret-bearing files',
    category: 'Secrets',
    severity: SEV.MEDIUM,
    cwe: 'CWE-732',
    owasp: [OWASP.LLM02],
    fix: 'Restrict secret files to owner-only: chmod 600 ~/.openclaw/.env (and ' +
      'similar). On shared hosts this is the difference between one compromised ' +
      'account and all of them.'
  });

  if (process.platform === 'win32') {
    f.scanned = false; f.status = 'yellow';
    f.detail = 'NOT SCANNED — POSIX file modes do not apply on Windows.';
    return f;
  }

  const offenders = [];
  let checked = 0;
  for (const cf of install.configFiles || []) {
    if (!SECRET_FILES.some((s) => cf.endsWith(s))) continue;
    let st;
    try { st = fs.statSync(cf); } catch (_) { continue; }
    checked++;
    const mode = st.mode & 0o777;
    if (mode & 0o077) { // any group/other permission bit set
      offenders.push({ file: cf, mode: mode.toString(8).padStart(3, '0') });
    }
  }

  if (checked === 0) {
    f.scanned = false; f.status = 'yellow';
    f.detail = 'NOT SCANNED — no secret-bearing files were found to check.';
    return f;
  }
  if (offenders.length) {
    f.status = 'red';
    f.detail = `${offenders.length} secret file(s) are readable beyond the owner. ` +
      `Other users/processes on this machine can read your keys.`;
    for (const o of offenders) f.evidence.push(`mode ${o.mode} on ${shortenHome(o.file)} (should be 600)`);
    return f;
  }
  f.status = 'green';
  f.detail = `Checked ${checked} secret file(s); all are owner-only.`;
  return f;
}

module.exports = { run };
