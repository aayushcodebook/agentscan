'use strict';

const fs = require('fs');
const path = require('path');
const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP } = require('../lib/frameworks.js');
const { loadAdvisories } = require('../feed.js');
const { findKey, shortenHome } = require('../lib/config.js');
const semver = require('../lib/semver.js');

const advisories = loadAdvisories();

/*
 * CHECK — Installed version vs known CVEs.
 *
 * Running a version with a published advisory (e.g. ClawJacked/ClawBleed,
 * CVE-2026-25253, fixed in 3.1.8) is one of the highest-signal findings a
 * scanner can produce. We read the installed version, then compare against the
 * feed-updatable advisories list. CWE-1395. If the version can't be determined
 * or compared, we report UNCERTAIN — never a false clean.
 */

function readVersion(install) {
  // 1. version key in config (e.g. package.json "version").
  const k = findKey(install, install.target.versionKeys || []);
  if (k.found && typeof k.value === 'string' && /\d/.test(k.value)) {
    return { version: k.value.trim(), source: k.source };
  }
  // 2. version files in the home dir.
  for (const vf of install.target.versionFiles || []) {
    const p = path.join(install.homeDir, vf);
    let txt;
    try { txt = fs.readFileSync(p, 'utf8'); } catch (_) { continue; }
    if (vf.endsWith('.json')) {
      try { const j = JSON.parse(txt); if (j.version) return { version: String(j.version), source: p }; } catch (_) {}
    } else {
      const m = txt.match(/\d+(?:\.\d+){1,3}/);
      if (m) return { version: m[0], source: p };
    }
  }
  return null;
}

function run(install) {
  const f = makeFinding({
    id: 'agent-version',
    title: 'Agent version vs. known security advisories (CVEs)',
    category: 'Vulnerable component',
    severity: SEV.HIGH,
    cwe: 'CWE-1395',
    owasp: [OWASP.LLM03],
    fix: 'Upgrade to the latest patched release. Several 2026 OpenClaw CVEs are ' +
      'unauthenticated RCE; running an old build is the single biggest risk.'
  });

  const relevant = (advisories.advisories || []).filter((a) => a.agent === install.id);

  // If the feed tracks no advisories for this agent yet, there is nothing to
  // compare against — report that honestly instead of a scary HIGH "SKIP".
  if (relevant.length === 0) {
    f.status = 'green';
    f.severity = SEV.INFO;
    f.detail = `No security advisories are tracked for ${install.name} in the ` +
      `feed (${advisories.version}) yet, so there is nothing to compare against. ` +
      `Keep the agent updated and re-run after \`agentscan --update-feed\`.`;
    return f;
  }

  const got = readVersion(install);
  if (!got) {
    f.scanned = false; f.status = 'yellow';
    f.detail = 'NOT SCANNED — could not determine the installed agent version. ' +
      'Check it manually against published advisories.';
    f.evidence.push('no version found in config or version files');
    return f;
  }

  const hits = [];
  let uncertain = false;
  for (const a of relevant) {
    const before = semver.isBefore(got.version, a.fixedIn);
    if (before === null) { uncertain = true; continue; }
    if (before) hits.push(a);
  }

  if (hits.length) {
    const top = hits.reduce((m, a) => (a.cvss > m.cvss ? a : m), hits[0]);
    f.status = 'red';
    f.severity = top.cvss >= 9 ? SEV.CRITICAL : SEV.HIGH;
    f.detail = `Installed version ${got.version} is affected by ${hits.length} ` +
      `known advisory(ies), incl. ${top.id} (CVSS ${top.cvss}). ${top.summary}`;
    f.references = hits.flatMap((a) => a.references || []);
    for (const a of hits) f.evidence.push(`${a.id} (${a.alias}, CVSS ${a.cvss}) — fixed in ${a.fixedIn}; you run ${got.version}`);
    f.evidence.push(`version read from ${shortenHome(got.source)}`);
    return f;
  }

  if (uncertain) {
    f.scanned = false; f.status = 'yellow';
    f.detail = `Found version "${got.version}" but its scheme couldn't be ` +
      `compared to the advisory ranges. Verify manually.`;
    f.evidence.push(`version "${got.version}" from ${shortenHome(got.source)}`);
    return f;
  }

  f.status = 'green';
  f.detail = `Installed version ${got.version} is not affected by any advisory ` +
    `in the feed (${advisories.version}).`;
  f.evidence.push(`version ${got.version} from ${shortenHome(got.source)}`);
  return f;
}

module.exports = { run, readVersion };
