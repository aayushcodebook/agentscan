'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');

const BUNDLED = require('./data/malicious-skills.json');
const BUNDLED_ADVISORIES = require('./data/advisories.json');

/*
 * Blocklist feed.
 *
 * Trust model:
 *   - A SCAN never touches the network. It loads the bundled offline blocklist,
 *     or a locally-cached feed the user explicitly fetched earlier — whichever
 *     is newer. This keeps "agentscan = no network calls" true by default.
 *   - Updating is an EXPLICIT, separate action (`agentscan --update-feed`).
 *   - The bundled list is a FLOOR: a fetched feed is only accepted if it is
 *     well-formed and its version is >= the bundled version, so a stale or
 *     tampered (e.g. emptied) cache can't silently weaken detection.
 *
 * Production hardening (documented, not yet enforced here): the remote feed
 * should be served over HTTPS and carry a detached Ed25519 signature that
 * agentscan verifies against a pinned public key before accepting it.
 */

// Cache lives in ~/.agentscan by default; AGENTSCAN_CACHE_DIR relocates it
// (used by tests, and handy for locked-down or multi-user setups).
const CACHE_DIR = process.env.AGENTSCAN_CACHE_DIR || path.join(os.homedir(), '.agentscan');
const CACHE_FILE = path.join(CACHE_DIR, 'blocklist.json');
const DEFAULT_FEED_URL =
  process.env.AGENTSCAN_FEED_URL || 'https://feed.agentscan.dev/blocklist.json';

function validShape(obj) {
  return !!(obj &&
    Array.isArray(obj.entries) &&
    obj.entries.every((e) => e && typeof e.name === 'string') &&
    obj.heuristics &&
    typeof obj.version === 'string');
}

// Compare version strings like "2026-02-16". Falls back to string compare.
function versionGte(a, b) {
  return String(a) >= String(b);
}

function readCache() {
  try {
    const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    if (validShape(data)) return data;
  } catch (_) {}
  return null;
}

/*
 * loadBlocklist() — used by the scanner. Prefers a cached feed only when it is
 * valid AND at least as new as the bundled floor; otherwise uses the bundle.
 */
function loadBlocklist() {
  const cache = readCache();
  if (cache && versionGte(cache.version, BUNDLED.version)) {
    return Object.assign({}, cache, { _source: 'cache', _path: CACHE_FILE });
  }
  return Object.assign({}, BUNDLED, { _source: 'bundled' });
}

/* Advisories (CVE) list — bundled offline; same trust model as the blocklist. */
function loadAdvisories() {
  return Object.assign({}, BUNDLED_ADVISORIES, { _source: 'bundled' });
}

/* Fetch a URL or local path. Supports http(s):// and file:// / bare paths. */
function fetchRaw(url) {
  return new Promise((resolve, reject) => {
    // Local paths / file URLs — handy for air-gapped mirrors and for tests.
    if (url.startsWith('file://') || (!/^https?:\/\//i.test(url))) {
      const p = url.startsWith('file://') ? url.slice('file://'.length) : url;
      try { return resolve(fs.readFileSync(p, 'utf8')); }
      catch (e) { return reject(new Error(`cannot read ${p}: ${e.message}`)); }
    }
    const lib = url.startsWith('https://') ? https : http;
    const req = lib.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from feed`));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; if (body.length > 5 * 1024 * 1024) req.destroy(); });
      res.on('end', () => resolve(body));
    });
    req.on('timeout', () => { req.destroy(new Error('feed request timed out')); });
    req.on('error', reject);
  });
}

/*
 * updateFeed({ url }) — explicit refresh. Returns a result object; never throws
 * for the normal failure cases (returns { ok:false, ... } instead) so the CLI
 * can print a clean message and fall back to the bundled list.
 */
async function updateFeed(opts) {
  opts = opts || {};
  const url = opts.url || DEFAULT_FEED_URL;
  let raw;
  try {
    raw = await fetchRaw(url);
  } catch (e) {
    return { ok: false, reason: `fetch failed: ${e.message}`, url, usingBundled: true };
  }

  let data;
  try { data = JSON.parse(raw); }
  catch (e) { return { ok: false, reason: `feed is not valid JSON: ${e.message}`, url, usingBundled: true }; }

  if (!validShape(data)) {
    return { ok: false, reason: 'feed failed shape validation (missing entries/heuristics/version)', url, usingBundled: true };
  }

  // Don't accept a downgrade below the shipped floor.
  if (!versionGte(data.version, BUNDLED.version)) {
    return {
      ok: false,
      reason: `feed version ${data.version} is older than bundled ${BUNDLED.version}; keeping bundled`,
      url, usingBundled: true
    };
  }

  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    return { ok: false, reason: `could not write cache: ${e.message}`, url, usingBundled: true };
  }

  return {
    ok: true,
    url,
    version: data.version,
    entries: data.entries.length,
    cachePath: CACHE_FILE
  };
}

module.exports = { loadBlocklist, loadAdvisories, updateFeed, CACHE_FILE, BUNDLED_VERSION: BUNDLED.version, validShape, versionGte };
