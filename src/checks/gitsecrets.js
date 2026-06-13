'use strict';

const fs = require('fs');
const path = require('path');
const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { shortenHome } = require('../lib/config.js');

/*
 * CHECK — Secrets in version control.
 *
 * People back up their agent home to git. If the agent dir is a git repo and
 * a secret file (.env, credentials.json) is NOT git-ignored, those keys get
 * committed and pushed — a very common real-world leak. CWE-540 / CWE-312.
 */

const SECRET_BASENAMES = ['.env', 'credentials.json', 'secrets.json'];

function run(install) {
  const f = makeFinding({
    id: 'secrets-in-git',
    title: 'Secrets exposed to version control',
    category: 'Secrets',
    severity: SEV.MEDIUM,
    cwe: ['CWE-540', 'CWE-312'],
    owasp: [OWASP.LLM02],
    fix: 'Add secret files to .gitignore (and purge them from history with e.g. ' +
      'git filter-repo if already committed), then rotate the exposed keys.'
  });

  const gitDir = path.join(install.homeDir, '.git');
  let isRepo = false;
  try { isRepo = fs.statSync(gitDir).isDirectory(); } catch (_) {}

  if (!isRepo) {
    f.scanned = false; f.status = 'yellow';
    f.detail = 'NOT SCANNED — the agent home is not a git repository.';
    return f;
  }

  // Read .gitignore (best effort) and see whether secret files are ignored.
  let ignore = '';
  try { ignore = fs.readFileSync(path.join(install.homeDir, '.gitignore'), 'utf8'); } catch (_) {}
  const ignored = (name) => ignore.split('\n').some((line) => {
    const p = line.trim();
    return p && !p.startsWith('#') && (p === name || p === '/' + name || p.endsWith(name) || p === '*' + path.extname(name));
  });

  const exposed = [];
  for (const cf of install.configFiles || []) {
    const base = path.basename(cf);
    if (!SECRET_BASENAMES.includes(base)) continue;
    try { fs.statSync(cf); } catch (_) { continue; }
    if (!ignored(base)) exposed.push(base);
  }

  if (exposed.length) {
    f.status = 'red';
    f.detail = 'This agent home is a git repo and secret file(s) are not ' +
      'git-ignored — committing/pushing leaks your keys.';
    f.evidence.push(`repo at ${shortenHome(gitDir)}`);
    for (const e of [...new Set(exposed)]) f.evidence.push(`${e} is NOT in .gitignore`);
    return f;
  }

  f.status = 'green';
  f.detail = 'Agent home is a git repo, but secret files are git-ignored.';
  f.evidence.push(`repo at ${shortenHome(gitDir)}`);
  return f;
}

module.exports = { run };
