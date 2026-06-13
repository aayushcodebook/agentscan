'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadBlocklist } = require('../feed.js');
const { discoverSkills } = require('../util/walk.js');
const { readConfigText, lookupKey, expandHome } = require('../util/parse.js');
const taint = require('../lib/taint.js');
const promptscan = require('../lib/promptscan.js');
const { verifyAgainstFirstParty } = require('../lib/integrity.js');

// Loaded once per process. Prefers a user-fetched feed cache over the bundled
// floor (see src/feed.js). A scan itself makes no network calls.
const blocklist = loadBlocklist();

/*
 * CHECK 3 — Malicious / suspicious skills.
 *
 * Layers:
 *   (1) Blocklist match — an installed skill name (or alias) is a known-bad
 *       skill from the maintained feed. Hard RED.
 *   (2) Heuristic — a skill's code reads secrets/env AND touches the
 *       network/shell, or contains classic exfiltration patterns. YELLOW.
 *
 * Skills are DISCOVERED by signature (a folder containing SKILL.md/skill.json)
 * plus any `.clawhub/lock.json` lockfile — not by guessing directory names.
 *
 * Crucially: if we cannot find ANY place skills would live, this check returns
 * `scanned: false` so the report shows it as NOT SCANNED rather than a clean
 * pass. A security tool must never hand out a false all-clear.
 */

// Build a fast lookup of bad names -> entry (includes aliases).
const badIndex = new Map();
for (const entry of blocklist.entries) {
  badIndex.set(entry.name.toLowerCase(), entry);
  for (const a of entry.aliases || []) badIndex.set(a.toLowerCase(), entry);
}

function readSkillSource(skillAbs) {
  const MAX = 200 * 1024; // 200KB cap so a huge skill can't stall us
  let buf = '';
  const pushFile = (f) => {
    if (buf.length >= MAX) return;
    try { buf += fs.readFileSync(f, 'utf8').slice(0, MAX - buf.length) + '\n'; } catch (_) {}
  };
  const stat = (() => { try { return fs.statSync(skillAbs); } catch (_) { return null; } })();
  if (stat && stat.isDirectory()) {
    let entries;
    try { entries = fs.readdirSync(skillAbs); } catch (_) { entries = []; }
    for (const e of entries) {
      if (/\.(js|ts|py|sh|json|md)$/i.test(e)) pushFile(path.join(skillAbs, e));
    }
  } else if (stat) {
    pushFile(skillAbs);
  }
  return buf;
}

/*
 * Verdict via TAINT-TRACKING dataflow analysis (src/lib/taint.js): does a secret
 * value actually FLOW INTO a network/exec sink? This is far more precise than
 * "secret pattern present AND sink pattern present" — it distinguishes a real
 * stealer (env-secret -> fetch body) from a benign skill that merely uses an env
 * var. The verdict carries a confidence so the report can say "traced flow"
 * (high) vs "patterns co-occur" (review).
 */
function heuristicVerdict(source) {
  const t = taint.analyze(source);       // code: does a secret flow to a sink?
  const p = promptscan.analyze(source);  // text: injection payload in SKILL.md?
  if (!t.flagged && !p.flagged) return { flagged: false };
  const reasons = [];
  const patterns = [];
  if (t.flagged) { reasons.push(t.reason); patterns.push(...(t.patterns || t.evidence || [])); }
  if (p.flagged) { reasons.push(p.reason); patterns.push(...(p.evidence || [])); }
  const confidence = (t.confidence === 'high' || p.confidence === 'high') ? 'high' : 'review';
  return { flagged: true, reason: reasons.join(' + '), patterns: patterns.slice(0, 4), confidence };
}

/*
 * Candidate skill roots = the target's known skill dirs joined to the install
 * home, plus the configured workspace's skills dir (OpenClaw lets you relocate
 * the workspace, so we read it from config when present).
 */
function isDirSafe(p) { try { return fs.statSync(p).isDirectory(); } catch (_) { return false; } }

/*
 * Locate the agent's npm package skills dir. Built-in skills ship INSIDE the
 * installed package (e.g. ~/.npm-global/lib/node_modules/openclaw/skills),
 * which lives outside ~/.openclaw — so a home-only walk misses them entirely.
 */
function packageSkillDirs(install) {
  const pkg = install.target.packageName;
  if (!pkg) return [];
  const home = os.homedir();
  const out = [];
  const prefixes = [
    process.env.NPM_CONFIG_PREFIX,
    process.env.npm_config_prefix,
    path.join(home, '.npm-global'),
    path.join(home, '.npm-packages'),
    path.join(home, '.local'),
    '/usr/local',
    '/usr',
    '/opt/homebrew'
  ].filter(Boolean);
  for (const pre of prefixes) {
    const d = path.join(pre, 'lib', 'node_modules', pkg, 'skills');
    if (isDirSafe(d)) out.push(d);
  }
  // nvm-managed Node installs.
  const nvmRoot = path.join(home, '.nvm', 'versions', 'node');
  try {
    for (const v of fs.readdirSync(nvmRoot)) {
      const d = path.join(nvmRoot, v, 'lib', 'node_modules', pkg, 'skills');
      if (isDirSafe(d)) out.push(d);
    }
  } catch (_) {}
  return out;
}

function candidateRoots(install) {
  const roots = [];
  for (const sd of install.target.skillDirs || []) {
    roots.push(path.join(install.homeDir, sd));
  }
  for (const pd of install.target.pluginDirs || []) {
    roots.push(path.join(install.homeDir, pd));
  }
  for (const pkgDir of packageSkillDirs(install)) roots.push(pkgDir);
  // OpenClaw: agents.defaults.workspace can point the workspace elsewhere;
  // skills then live in <workspace>/skills.
  for (const cf of install.configFiles) {
    let content;
    try { content = fs.readFileSync(cf, 'utf8'); } catch (_) { continue; }
    const { found, value } = lookupKey(readConfigText(content), 'workspace');
    if (found && typeof value === 'string' && value.trim()) {
      roots.push(path.join(expandHome(value.trim()), 'skills'));
    }
  }
  return roots;
}

function run(install) {
  const finding = {
    id: 'skills',
    title: 'Malicious or suspicious skills & plugins',
    category: 'Supply chain',
    status: 'green',
    severity: 'critical',
    cwe: ['CWE-506', 'CWE-1357'],
    owasp: ['LLM03:2025 Supply Chain'],
    atlas: ['AML.T0010 ML Supply Chain Compromise'],
    references: [],
    detail: '',
    evidence: [],
    fix: '',
    scanned: true
  };

  const disco = discoverSkills(install.homeDir, candidateRoots(install));

  // FAIL LOUD: nowhere to look -> not a pass.
  if (!disco.scanned) {
    finding.status = 'yellow';
    finding.scanned = false;
    finding.detail =
      'NOT SCANNED — no skills/plugins directory or lockfile was found for this ' +
      'install, so the malware check could not run. This is not an all-clear: ' +
      'if extensions are installed somewhere unexpected, point agentscan at it.';
    finding.evidence.push(`looked under ${shorten(install.homeDir)} and known skill/plugin paths`);
    finding.fix =
      'If you use skills or plugins, tell agentscan where they live: ' +
      'npx agentscan --path <parent-dir>. Otherwise, treat this as ' +
      '"unknown", not "safe".';
    return finding;
  }

  // Union of discovered extensions (skills + plugins) and lockfile-declared
  // skills. Keep kind and the alternate (canonical/frontmatter) names so a bad
  // skill can't hide behind an innocent folder name.
  // origin: 'bundled' = ships inside the agent's own package/code (first-party,
  // trusted); 'user' = installed by the user (ClawHub/Skills Hub, untrusted).
  // First-party skills are NOT judged (the official package's skills legitimately
  // read env + shell out). We detect first-party by path segment:
  //   - npm layout:  .../node_modules/<pkg>/skills/...   (OpenClaw)
  //   - repo layout: .../<codeDir>/skills/...            (Hermes -> hermes-agent)
  const codeMarkers = install.target.codeMarkers || [];
  const originOf = (abs) => {
    if (!abs) return 'user';
    const segs = abs.split(path.sep);
    if (segs.includes('node_modules')) return 'bundled';
    if (codeMarkers.some((m) => segs.includes(m))) return 'bundled';
    return 'user';
  };

  const items = new Map(); // key -> { name, abs, kind, names:Set, origin }
  for (const s of disco.skills) {
    items.set(s.abs, { name: s.name, abs: s.abs, kind: s.kind, names: new Set([s.name, ...(s.altNames || [])]), origin: originOf(s.abs) });
  }
  for (const s of disco.lockSkills) {
    const key = 'lock:' + s.name;
    if (!items.has(key)) items.set(key, { name: s.name, abs: null, kind: 'skill', names: new Set([s.name]), origin: 'user' });
  }

  // Seeded first-party copies, verified CRYPTOGRAPHICALLY. Some agents (Hermes)
  // copy their built-in skills into the same dir users install into. We trust a
  // same-named copy ONLY if it is byte-identical (SHA-256) to the first-party
  // original — trusting by name alone is spoofable. A copy whose hash DIFFERS
  // (impostor or tampered/trojaned) is treated as untrusted and analyzed.
  const firstPartyByName = new Map(); // name(lc) -> { dir }
  for (const it of items.values()) {
    if (it.origin === 'bundled' && it.abs) {
      for (const n of it.names) {
        const key = String(n).toLowerCase();
        if (!firstPartyByName.has(key)) firstPartyByName.set(key, { dir: it.abs });
      }
    }
  }
  for (const it of items.values()) {
    if (it.origin !== 'user' || !it.abs) continue;
    const named = [...it.names].some((n) => firstPartyByName.has(String(n).toLowerCase()));
    if (!named) continue;
    const name = [...it.names].find((n) => firstPartyByName.has(String(n).toLowerCase()));
    const v = verifyAgainstFirstParty(it.abs, name, firstPartyByName);
    if (v.status === 'verified') it.origin = 'bundled';        // hash matches original -> trusted
    else if (v.status === 'tampered') it.tampered = true;       // same name, different bytes -> analyze it
    // 'unknown' -> stays user, analyzed normally
  }

  const confirmedBad = [];
  const suspicious = [];
  let nSkills = 0, nPlugins = 0, nBundled = 0, nUser = 0;

  for (const item of items.values()) {
    if (item.kind === 'plugin') nPlugins++; else nSkills++;
    if (item.origin === 'bundled') { nBundled++; continue; } // first-party: counted, not judged
    nUser++;

    // The community blocklist + exfiltration heuristic apply ONLY to USER-
    // installed (untrusted) extensions. Skills shipped inside the official
    // package are first-party — e.g. OpenClaw bundles a legit skill literally
    // named "clawhub", which must NOT collide with the typosquat blocklist.
    let hit = null;
    for (const n of item.names) { hit = badIndex.get(String(n).toLowerCase()); if (hit) break; }
    if (hit) { confirmedBad.push({ name: item.name, kind: item.kind, entry: hit }); continue; }

    if (item.abs) {
      const src = readSkillSource(item.abs);
      if (src) {
        const v = heuristicVerdict(src);
        if (v.flagged) {
          suspicious.push({
            name: item.name, kind: item.kind, reason: v.reason,
            patterns: v.patterns, confidence: v.confidence, tampered: !!item.tampered
          });
        }
      }
    }
  }

  // De-dupe by name+kind (a skill can appear at more than one path).
  const uniqBy = (arr, key) => {
    const seen = new Set();
    return arr.filter((x) => { const k = key(x); return seen.has(k) ? false : (seen.add(k), true); });
  };
  const confirmed = uniqBy(confirmedBad, (b) => b.kind + ':' + b.name.toLowerCase());
  const flagged = uniqBy(suspicious, (s) => s.kind + ':' + s.name.toLowerCase());

  // A "high"-confidence taint flow on a TAMPERED first-party impostor is as
  // serious as a blocklist hit — surface those as confirmed-malicious.
  const impostors = flagged.filter((s) => s.tampered && s.confidence === 'high');
  const reviewFlags = flagged.filter((s) => !(s.tampered && s.confidence === 'high'));
  const tagOf = (s) => s.confidence === 'high' ? 'HIGH-CONFIDENCE' : 'review';

  if (confirmed.length > 0 || impostors.length > 0) {
    finding.status = 'red';
    const n = confirmed.length + impostors.length;
    finding.detail =
      `Found ${n} malicious extension(s): ${confirmed.length} on the community ` +
      `blocklist${impostors.length ? `, ${impostors.length} tampered first-party impostor(s) with a traced exfiltration flow` : ''}. ` +
      `Remove immediately.`;
    for (const b of confirmed) {
      finding.evidence.push(`MALICIOUS ${b.kind}: "${b.name}" — ${b.entry.category}: ${b.entry.note}`);
    }
    for (const s of impostors) {
      finding.evidence.push(`MALICIOUS ${s.kind} (impostor): "${s.name}" — modified copy of a first-party skill; ${s.reason} (${s.patterns.join('; ')})`);
    }
    for (const s of reviewFlags) {
      finding.evidence.push(`${tagOf(s)} ${s.kind}: "${s.name}" — ${s.reason} (${s.patterns.join('; ')})`);
    }
  } else if (flagged.length > 0) {
    finding.status = 'yellow';
    const highN = flagged.filter((s) => s.confidence === 'high').length;
    finding.detail =
      `No blocklisted extensions, but ${flagged.length} ${flagged.length === 1 ? 'extension' : 'extensions'} ` +
      `show an exfiltration signature` +
      (highN ? ` (${highN} with a TRACED secret→sink data flow)` : ` (pattern co-occurrence)`) +
      `. Review by hand.`;
    for (const s of flagged) {
      finding.evidence.push(`${tagOf(s)} ${s.kind}: "${s.name}" — ${s.reason} (${s.patterns.join('; ')})`);
    }
  } else {
    finding.status = 'green';
    const bits = [`${nUser} user extension(s) checked`];
    if (nPlugins) bits.push(`${nPlugins} plugin(s)`);
    if (nBundled) bits.push(`${nBundled} first-party built-in (trusted, skipped)`);
    finding.detail = `Scanned: ${bits.join(', ')}; nothing flagged against the ` +
      `blocklist or exfiltration heuristic.`;
  }

  finding.fix =
    `Remove flagged extensions and rotate any credentials they could have read. ` +
    `Blocklist ${blocklist.version} (${blocklist._source || 'bundled'}). Plugins run ` +
    `code — treat them like npm packages; only install ones you can read and trust.`;

  return finding;
}

function shorten(p) {
  const home = require('os').homedir();
  return p && p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { run, badIndex };
