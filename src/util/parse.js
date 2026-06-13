'use strict';

const os = require('os');
const path = require('path');

/* Expand a leading "~" to the user's home directory. */
function expandHome(p) {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return path.join(os.homedir(), p.slice(2));
  }
  return p;
}

/*
 * Best-effort config reader. We deliberately do NOT pull in a YAML/TOML
 * dependency. For our checks we only need to (a) find string values that look
 * like secrets and (b) read a handful of known keys (bind address, audit
 * flags). A forgiving line/JSON scan covers JSON, .env, YAML and TOML well
 * enough for those purposes without trusting a parser with attacker-adjacent
 * input.
 */
function readConfigText(content) {
  // Try strict JSON first — gives us structured key access when possible.
  let json = null;
  try {
    json = JSON.parse(content);
  } catch (_) {
    json = null;
  }
  return { json, raw: content };
}

/* Flatten a nested object into dot.path => value pairs (for key lookups). */
function flatten(obj, prefix, out) {
  out = out || {};
  prefix = prefix || '';
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const k of Object.keys(obj)) {
      flatten(obj[k], prefix ? `${prefix}.${k}` : k, out);
    }
  } else {
    out[prefix] = obj;
  }
  return out;
}

/*
 * Look up a key in either the parsed JSON (by dotted path or leaf name) or,
 * failing that, in the raw text with a "key: value" / "key=value" regex.
 * Returns { found, value } — value is a string when matched from raw text.
 */
function lookupKey(parsed, key) {
  if (parsed.json) {
    const flat = flatten(parsed.json);
    // exact dotted path
    if (Object.prototype.hasOwnProperty.call(flat, key)) {
      return { found: true, value: flat[key] };
    }
    // Suffix match. For a DOTTED key we require the last TWO segments to match
    // (e.g. "sandbox.mode"), NOT just the final leaf — otherwise a query for
    // "agents.defaults.sandbox.mode" would wrongly grab "gateway.mode". For a
    // single-segment key, match that leaf as a path suffix.
    const segs = key.split('.');
    const suffix = segs.length >= 2 ? segs.slice(-2).join('.') : segs[0];
    for (const k of Object.keys(flat)) {
      if (k === suffix || k.endsWith('.' + suffix)) {
        return { found: true, value: flat[k] };
      }
    }
  }
  // raw text fallback (used when JSON.parse failed, e.g. JSON5 with comments).
  // Works for .env (KEY=value), pretty-printed YAML, and inline JSON5.
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rsegs = key.split('.');
  const leaf = esc(rsegs[rsegs.length - 1]);

  if (rsegs.length >= 2) {
    // Dotted key: require the PARENT segment to appear shortly before the leaf,
    // so "sandbox.mode" doesn't accidentally match an unrelated "gateway.mode".
    const parent = esc(rsegs[rsegs.length - 2]);
    const re = new RegExp(
      `${parent}["']?\\s*[:=]?\\s*[{(\\[\\s][\\s\\S]{0,160}?["']?${leaf}["']?\\s*[:=]\\s*["']?([^"'\\n#,}]+)`,
      'im'
    );
    const m = parsed.raw.match(re);
    if (m) return { found: true, value: m[1].trim() };
    return { found: false, value: undefined }; // avoid a bare-leaf false match
  }

  // Single-segment key: match the leaf as a "key: value" / "key=value".
  const re = new RegExp(`(?:^|[\\s,{])["']?${leaf}["']?\\s*[:=]\\s*["']?([^"'\\n#,}]+)`, 'im');
  const m = parsed.raw.match(re);
  if (m) return { found: true, value: m[1].trim() };
  return { found: false, value: undefined };
}

function truthy(v) {
  if (v === true) return true;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    return s === 'true' || s === '1' || s === 'yes' || s === 'on' || s === 'enabled';
  }
  if (typeof v === 'number') return v === 1;
  return false;
}

module.exports = { expandHome, readConfigText, flatten, lookupKey, truthy };
