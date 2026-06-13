'use strict';

const fs = require('fs');

/*
 * CHECK 2 — Plaintext credentials.
 *
 * Scan the agent's config files for secrets sitting in cleartext: provider API
 * keys, cloud keys, and generic password/token fields. We NEVER print the
 * secret itself — only its type, a masked preview, and which file it's in.
 */

// High-signal provider key shapes. Each has a label and a regex.
const KEY_PATTERNS = [
  { label: 'OpenAI API key', re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  { label: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: 'AWS secret access key', re: /\baws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+]{40}\b/gi },
  { label: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { label: 'Stripe secret key', re: /\bsk_live_[A-Za-z0-9]{20,}\b/g },
  { label: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { label: 'JWT', re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g }
];

// Generic "field that holds a secret" assignments, e.g. password: "hunter2".
const GENERIC_FIELD = /\b(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["']?([^\s"'#,}]{6,})/gi;

// Values that look like a placeholder, env reference, or already-encrypted — not a real leak.
function looksLikePlaceholder(v) {
  if (!v) return true;
  const s = String(v).trim();
  if (s.length < 6) return true;
  if (/^\$\{?[A-Z0-9_]+\}?$/.test(s)) return true;           // ${OPENAI_API_KEY}
  if (/^(env|process\.env)[.\[]/i.test(s)) return true;        // env.X / process.env[...]
  if (/^(your|changeme|xxx+|placeholder|example|todo|none|null|true|false)$/i.test(s)) return true;
  if (/^(enc:|vault:|secret:|ref:|aws-kms:|sops:)/i.test(s)) return true; // already managed
  if (/^[*•]{4,}$/.test(s)) return true;                       // masked
  return false;
}

function mask(secret) {
  const s = String(secret);
  if (s.length <= 8) return s[0] + '***';
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

function scanFile(file, hits) {
  let content;
  try { content = fs.readFileSync(file, 'utf8'); } catch (_) { return; }

  for (const pat of KEY_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(content)) !== null) {
      hits.push({ file, type: pat.label, preview: mask(m[0]) });
    }
  }

  GENERIC_FIELD.lastIndex = 0;
  let g;
  while ((g = GENERIC_FIELD.exec(content)) !== null) {
    const fieldName = g[1];
    const value = g[2];
    if (looksLikePlaceholder(value)) continue;
    hits.push({ file, type: `${fieldName} (plaintext value)`, preview: mask(value) });
  }
}

function run(install) {
  const finding = {
    id: 'credentials',
    title: 'Plaintext credentials in config files',
    category: 'Secrets',
    status: 'green',
    severity: 'high',
    cwe: 'CWE-312',
    owasp: ['LLM02:2025 Sensitive Information Disclosure'],
    atlas: [],
    references: [],
    detail: '',
    evidence: [],
    fix: ''
  };

  const hits = [];
  for (const cf of install.configFiles) scanFile(cf, hits);

  // De-duplicate identical (file,type,preview) triples.
  const seen = new Set();
  const unique = hits.filter((h) => {
    const k = `${h.file}|${h.type}|${h.preview}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  if (unique.length === 0) {
    finding.status = 'green';
    finding.detail = install.configFiles.length
      ? 'No plaintext API keys or passwords found in the agent\'s config files.'
      : 'No config files found to scan for this install.';
  } else {
    finding.status = 'red';
    finding.detail =
      `Found ${unique.length} credential(s) stored in cleartext. Anyone who ` +
      `reads these files — a malicious skill, another user on the box, a stolen ` +
      `backup — gets your keys.`;
    for (const h of unique) {
      finding.evidence.push(`${h.type} → ${h.preview}  [${shorten(h.file)}]`);
    }
  }

  finding.fix =
    'Move secrets out of config files: reference them from environment ' +
    'variables or a secrets manager/vault, and rotate any key that was sitting ' +
    'in plaintext.';

  return finding;
}

function shorten(p) {
  const home = require('os').homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { run, looksLikePlaceholder, mask };
