'use strict';

/*
 * Minimal, defensive version comparison. Agent versioning in the wild is messy
 * (3.1.8 vs 2026.1.29 vs 2026415), so we parse a dotted numeric core and
 * compare field-by-field. If a version can't be parsed into comparable numbers
 * we return null and the caller reports UNCERTAIN rather than false-alarming.
 */

function parse(v) {
  if (v == null) return null;
  const m = String(v).trim().replace(/^v/i, '').match(/^\d+(?:\.\d+)*/);
  if (!m) return null;
  const parts = m[0].split('.').map((n) => parseInt(n, 10));
  if (parts.some((n) => Number.isNaN(n))) return null;
  return parts;
}

/* Returns -1, 0, 1, or null (incomparable). */
function compare(a, b) {
  const pa = parse(a), pb = parse(b);
  if (!pa || !pb) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/* Is `version` affected by a "<fixedIn" advisory? null when uncertain. */
function isBefore(version, fixedIn) {
  const c = compare(version, fixedIn);
  if (c === null) return null;
  return c < 0;
}

module.exports = { parse, compare, isBefore };
