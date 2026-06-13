'use strict';

const fs = require('fs');
const path = require('path');
const targets = require('./data/targets.js');
const { expandHome } = require('./util/parse.js');

function safeStat(p) {
  try { return fs.statSync(p); } catch (_) { return null; }
}

function exists(p) {
  return safeStat(p) !== null;
}

/*
 * Discover installed agents. For each known target we check its candidate home
 * directories; if one exists we record it as an install and collect the config
 * files and skill directories actually present inside it.
 *
 * Returns an array of:
 *   { id, name, homeDir, configFiles: [abs...], skillDirs: [abs...], target }
 */
function detectInstalls(opts) {
  opts = opts || {};
  const installs = [];

  // 1. Auto-detect known installs in each target's standard locations.
  for (const target of targets) {
    for (const dir of target.homeDirs.map(expandHome)) {
      const built = buildInstall(dir, target);
      if (built) installs.push(built);
    }
  }

  // 2. Custom paths from --path: scan each ONCE, attributing it to whichever
  //    agent its contents best resemble (so a dir isn't reported twice).
  for (const raw of opts.extraPaths || []) {
    const dir = expandHome(raw);
    if (!exists(dir) || !safeStat(dir).isDirectory()) continue;
    const target = bestMatchTarget(dir);
    const built = buildInstall(dir, target, /*force*/ true);
    if (built) installs.push(built);
  }

  return dedupe(installs);
}

/* Build an install record for a dir under a given target, or null if absent. */
function buildInstall(dir, target, force) {
  if (!exists(dir)) return null;
  const stat = safeStat(dir);
  if (!stat || !stat.isDirectory()) return null;

  const configFiles = [];
  for (const cf of target.configFiles) {
    const abs = path.join(dir, cf);
    if (exists(abs)) configFiles.push(abs);
  }

  const skillDirs = [];
  for (const sd of target.skillDirs) {
    const abs = path.join(dir, sd);
    const s = safeStat(abs);
    if (s && s.isDirectory()) skillDirs.push(abs);
  }

  // For auto-detected dirs, require at least one config or skill dir so we
  // don't claim an empty/unrelated folder. For --path the user is explicit.
  if (!force && configFiles.length === 0 && skillDirs.length === 0) return null;

  return { id: target.id, name: target.name, homeDir: dir, configFiles, skillDirs, target };
}

/* Pick the target whose known files are most present in dir (fingerprinting). */
function bestMatchTarget(dir) {
  let best = targets[0];
  let bestScore = -1;
  for (const target of targets) {
    let score = 0;
    for (const cf of target.configFiles) if (exists(path.join(dir, cf))) score++;
    for (const sd of target.skillDirs) {
      const s = safeStat(path.join(dir, sd));
      if (s && s.isDirectory()) score++;
    }
    // A dir name hint breaks ties (e.g. ".../hermes-agent").
    if (dir.toLowerCase().includes(target.id)) score += 0.5;
    if (score > bestScore) { bestScore = score; best = target; }
  }
  return best;
}

/* Two candidate paths can resolve to the same install; keep the first. */
function dedupe(installs) {
  const seen = new Set();
  const out = [];
  for (const i of installs) {
    const key = `${i.id}::${tryRealpath(i.homeDir)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(i);
  }
  return out;
}

function tryRealpath(p) {
  try { return fs.realpathSync(p); } catch (_) { return p; }
}

module.exports = { detectInstalls, exists, safeStat };
