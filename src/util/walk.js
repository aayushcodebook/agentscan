'use strict';

const fs = require('fs');
const path = require('path');

/*
 * Extension discovery (skills AND plugins).
 *
 * We discover by SIGNATURE, not by trusting a hardcoded directory name:
 *
 *   - A SKILL is a folder containing `SKILL.md` (case-sensitive) and/or
 *     `skill.json`. Confirmed for BOTH OpenClaw and Hermes — Hermes uses the
 *     same agentskills.io SKILL.md, nested by category
 *     (skills/<category>/<skill>/SKILL.md). The canonical name is the
 *     frontmatter `name:` (skills) which can differ from the folder name, so we
 *     capture both.
 *   - A PLUGIN is a folder containing `openclaw.plugin.json`. Plugins are
 *     runtime TS modules — they execute code, a bigger attack surface than a
 *     SKILL.md instruction pack — so we scan them too. A plugin may bundle its
 *     own skills, so we descend into plugin dirs.
 *   - `.clawhub/lock.json` lists installed skills authoritatively.
 *
 * If we find NOWHERE to look, the caller treats the check as "not scanned"
 * rather than clean.
 */

const SKILL_MARKERS = ['SKILL.md', 'skill.json'];
const PLUGIN_MARKER = 'openclaw.plugin.json';
const LOCKFILE_REL = path.join('.clawhub', 'lock.json');

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'sessions', 'logs', 'cron', 'output',
  'memories', '.cache', 'dist', 'build', 'state', 'tmp', '__pycache__',
  // Python virtualenvs / installed deps — their bundled skills are transitive
  // dependencies, not the agent's own; don't scan them.
  '.venv', 'venv', 'site-packages', '.agents'
]);

const MAX_DEPTH = 6;
const MAX_VISITS = 6000;

function safeStat(p) { try { return fs.statSync(p); } catch (_) { return null; } }
function isDir(p) { const s = safeStat(p); return s && s.isDirectory(); }
function isFile(p) { const s = safeStat(p); return s && s.isFile(); }

/* Returns 'plugin' | 'skill' | null for a directory, by marker file. */
function classifyDir(dir) {
  if (isFile(path.join(dir, PLUGIN_MARKER))) return 'plugin';
  if (SKILL_MARKERS.some((m) => isFile(path.join(dir, m)))) return 'skill';
  return null;
}

/* Pull canonical identifiers (besides folder name) for blocklist matching. */
function canonicalNames(dir, kind) {
  const names = [];
  if (kind === 'skill') {
    // SKILL.md frontmatter: name: <id>   (scan only the first ~40 lines)
    try {
      const head = fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf8').split('\n', 40).join('\n');
      const m = head.match(/^\s*name\s*:\s*["']?([A-Za-z0-9._-]+)/im);
      if (m) names.push(m[1]);
    } catch (_) {}
    try {
      const j = JSON.parse(fs.readFileSync(path.join(dir, 'skill.json'), 'utf8'));
      if (j && typeof j.name === 'string') names.push(j.name);
    } catch (_) {}
  } else if (kind === 'plugin') {
    // openclaw.plugin.json is JSON5; JSON.parse may fail -> regex fallback.
    let raw = '';
    try { raw = fs.readFileSync(path.join(dir, PLUGIN_MARKER), 'utf8'); } catch (_) {}
    try {
      const j = JSON.parse(raw);
      if (j && typeof j.id === 'string') names.push(j.id);
      if (j && typeof j.name === 'string') names.push(j.name);
    } catch (_) {
      const m = raw.match(/\bid\s*:\s*["']([^"']+)["']/);
      if (m) names.push(m[1]);
    }
  }
  return names;
}

function parseLockfile(file) {
  const names = [];
  let data;
  try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return names; }
  const pushName = (n, v) => { if (n && typeof n === 'string') names.push({ name: n, version: v || null, lockPath: file }); };
  const containers = [data.skills, data.entries, data.installed, data];
  for (const cont of containers) {
    if (!cont) continue;
    if (Array.isArray(cont)) {
      for (const e of cont) {
        if (typeof e === 'string') pushName(e);
        else if (e && typeof e === 'object') pushName(e.name || e.id, e.version);
      }
    } else if (typeof cont === 'object') {
      for (const k of Object.keys(cont)) {
        if (k === 'skills' || k === 'entries' || k === 'installed') continue;
        const v = cont[k];
        pushName(k, v && typeof v === 'object' ? v.version : (typeof v === 'string' ? v : null));
      }
    }
  }
  const seen = new Set();
  return names.filter((n) => (seen.has(n.name) ? false : (seen.add(n.name), true)));
}

/*
 * discoverSkills(homeDir, candidateRoots)
 * Returns { skills, lockSkills, lookedIn, scanned }.
 *   skills:  [{ name, abs, kind: 'skill'|'plugin', altNames: [] }]
 */
function discoverSkills(homeDir, candidateRoots) {
  const skills = [];
  const lockSkills = [];
  const lookedIn = [];
  const seen = new Set();

  let visits = 0;
  const stack = [{ dir: homeDir, depth: 0 }];
  // Candidate roots (e.g. the package's bundled skills dir, which lives OUTSIDE
  // the agent home) are both recorded as "looked here" AND walked for skills.
  for (const root of candidateRoots || []) {
    if (isDir(root)) {
      lookedIn.push(root);
      stack.push({ dir: root, depth: 0 });
    }
  }
  while (stack.length) {
    const { dir, depth } = stack.pop();
    if (visits++ > MAX_VISITS || depth > MAX_DEPTH) continue;

    const lf = path.join(dir, LOCKFILE_REL);
    if (isFile(lf)) {
      if (!lookedIn.includes(dir)) lookedIn.push(dir);
      for (const s of parseLockfile(lf)) lockSkills.push(s);
    }

    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }

    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (e.name.startsWith('.') && e.name !== '.clawhub') continue;
      if (SKIP_DIRS.has(e.name)) continue;

      const child = path.join(dir, e.name);
      const kind = classifyDir(child);
      if (kind) {
        if (!seen.has(child)) {
          seen.add(child);
          skills.push({ name: e.name, abs: child, kind, altNames: canonicalNames(child, kind) });
        }
        if (!lookedIn.includes(dir)) lookedIn.push(dir);
        // Skills are leaves; plugins may bundle skills, so keep descending.
        if (kind === 'plugin') stack.push({ dir: child, depth: depth + 1 });
        continue;
      }
      stack.push({ dir: child, depth: depth + 1 });
    }
  }

  const scanned = lookedIn.length > 0 || skills.length > 0 || lockSkills.length > 0;
  return { skills, lockSkills, lookedIn, scanned };
}

module.exports = { discoverSkills, parseLockfile, classifyDir, canonicalNames, SKILL_MARKERS, PLUGIN_MARKER };
