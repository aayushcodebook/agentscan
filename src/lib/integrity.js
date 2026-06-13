'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/*
 * Integrity / provenance verification (zero external deps — Node's built-in
 * crypto only).
 *
 * Why: trusting a skill because its NAME matches a first-party one is
 * spoofable (a malicious skill can call itself "notion"). The rigorous check is
 * CRYPTOGRAPHIC: a seeded/first-party copy should be byte-identical to the
 * original that ships in the agent's package. We hash both and compare:
 *   - hash matches the first-party original  -> genuinely first-party (trust)
 *   - same name but hash DIFFERS             -> tampered / impostor (analyze it)
 *
 * Also: ClawHub lockfiles may pin integrity hashes; we verify installed files
 * against them, and flag unpinned installs. And if a skill ships a detached
 * Ed25519 signature and the feed pins a public key, we verify it.
 */

const MAX_FILE = 512 * 1024; // cap per-file hashing
const HASH_EXT = /\.(js|ts|py|sh|json|md|mjs|cjs)$/i;

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/* Stable content hash of a skill directory: hash of (relpath + filehash) pairs,
 * sorted, so it's order-independent and tamper-evident. */
function hashSkillDir(dir) {
  const entries = [];
  walkFiles(dir, dir, entries, 0);
  entries.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  const h = crypto.createHash('sha256');
  for (const e of entries) h.update(e.rel + '\0' + e.hash + '\n');
  return sha256(h.digest());
}

function walkFiles(root, dir, out, depth) {
  if (depth > 6) return;
  let items;
  try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const it of items) {
    if (it.name === 'node_modules' || it.name === '.git') continue;
    const abs = path.join(dir, it.name);
    if (it.isDirectory()) { walkFiles(root, abs, out, depth + 1); continue; }
    if (!HASH_EXT.test(it.name)) continue;
    try {
      const st = fs.statSync(abs);
      if (st.size > MAX_FILE) { out.push({ rel: path.relative(root, abs), hash: 'oversized:' + st.size }); continue; }
      out.push({ rel: path.relative(root, abs), hash: sha256(fs.readFileSync(abs)) });
    } catch (_) {}
  }
}

/*
 * Given first-party skills (name -> dir) and a candidate skill, decide trust:
 *   'verified'   name matches a first-party skill AND hashes match
 *   'tampered'   name matches a first-party skill BUT hashes differ
 *   'unknown'    no first-party original to compare against
 */
function verifyAgainstFirstParty(candidateDir, candidateName, firstPartyByName) {
  const orig = firstPartyByName.get(String(candidateName).toLowerCase());
  if (!orig || !orig.dir) return { status: 'unknown' };
  try {
    const a = hashSkillDir(candidateDir);
    const b = orig.hash || hashSkillDir(orig.dir);
    return { status: a === b ? 'verified' : 'tampered', candidateHash: a, originalHash: b };
  } catch (_) {
    return { status: 'unknown' };
  }
}

/* Parse a ClawHub lockfile and report integrity posture. */
function lockfilePosture(lockPath) {
  let data;
  try { data = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch (_) { return null; }
  const entries = collectEntries(data);
  let withIntegrity = 0, withoutIntegrity = 0;
  for (const e of entries) {
    if (e.integrity || e.sha256 || e.hash) withIntegrity++; else withoutIntegrity++;
  }
  return { total: entries.length, withIntegrity, withoutIntegrity, unpinned: withoutIntegrity };
}

function collectEntries(data) {
  const out = [];
  const containers = [data.skills, data.entries, data.installed];
  for (const c of containers) {
    if (!c) continue;
    if (Array.isArray(c)) out.push(...c.filter((x) => x && typeof x === 'object'));
    else if (typeof c === 'object') for (const k of Object.keys(c)) { const v = c[k]; if (v && typeof v === 'object') out.push(v); }
  }
  return out;
}

/*
 * Verify a detached Ed25519 signature over a skill dir hash, against a pinned
 * public key (PEM). Returns 'valid' | 'invalid' | 'unsigned'. Forward-looking:
 * most skills are unsigned today, but the capability is here and audited.
 */
function verifyEd25519(dir, pubKeyPem) {
  const sigFile = ['SIGNATURE', 'skill.sig', '.sig'].map((f) => path.join(dir, f)).find((p) => { try { return fs.statSync(p).isFile(); } catch (_) { return false; } });
  if (!sigFile || !pubKeyPem) return 'unsigned';
  try {
    const sig = fs.readFileSync(sigFile);
    const digest = Buffer.from(hashSkillDir(dir), 'hex');
    const ok = crypto.verify(null, digest, pubKeyPem, sig.length === 64 ? sig : Buffer.from(sig.toString().trim(), 'base64'));
    return ok ? 'valid' : 'invalid';
  } catch (_) {
    return 'unsigned';
  }
}

module.exports = { sha256, hashSkillDir, verifyAgainstFirstParty, lockfilePosture, verifyEd25519 };
