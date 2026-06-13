'use strict';

const fs = require('fs');
const os = require('os');
const { readConfigText, lookupKey } = require('../util/parse.js');

/* Read every config file of an install once; cache nothing across calls. */
function readAll(install) {
  const out = [];
  for (const cf of install.configFiles || []) {
    let content;
    try { content = fs.readFileSync(cf, 'utf8'); } catch (_) { continue; }
    out.push({ file: cf, parsed: readConfigText(content), raw: content });
  }
  return out;
}

/*
 * Find the first config file where any of `keys` is set.
 * Returns { found, value, source, key } (value may be string|bool|number).
 */
function findKey(install, keys) {
  const files = readAll(install);
  for (const f of files) {
    for (const key of keys || []) {
      const { found, value } = lookupKey(f.parsed, key);
      if (found) return { found: true, value, source: f.file, key };
    }
  }
  return { found: false };
}

/* Does any config file's raw text contain a substring? (for presence checks) */
function rawIncludes(install, needle) {
  for (const f of readAll(install)) {
    if (f.raw.includes(needle)) return { found: true, source: f.file };
  }
  return { found: false };
}

function shortenHome(p) {
  const home = os.homedir();
  return p && p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { readAll, findKey, rawIncludes, shortenHome };
