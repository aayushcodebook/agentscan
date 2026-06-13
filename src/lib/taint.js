'use strict';

/*
 * Lightweight taint-tracking dataflow analyzer (JS & Python).
 *
 * The flat heuristic ("file mentions process.env AND file mentions fetch")
 * over-flags: plenty of benign skills read an env var AND make a network call
 * without the secret ever flowing to the network. This analyzer instead asks
 * the question that actually matters: does a SECRET value FLOW INTO a network /
 * exec sink? That is the real exfiltration signature.
 *
 * It is deliberately NOT a full compiler AST (that would mean a heavy parser
 * dependency and break the zero-dependency, auditable promise). It is a
 * comment/string-aware, statement-level dataflow approximation: it tracks which
 * identifiers hold tainted (secret-derived) data and whether any of them reach
 * a sink. This yields a CONFIDENCE level:
 *   - 'flow'        a tainted value provably reaches a sink   -> high confidence
 *   - 'obfuscated'  decode-and-execute / ClickFix             -> high confidence
 *   - 'sink'        a hardcoded exfil endpoint + net/exec      -> high confidence
 *   - 'cooccur'     secret-read and a sink both present, no traced flow -> review
 *   - null          nothing
 */

// ---- source / sink vocabulary --------------------------------------------

// Common, often-benign secret reads. These TAINT a variable, but on their own
// (without a traced flow to a sink) they are NOT enough to flag — a skill using
// process.env is everyday and must not false-positive.
const COMMON_SOURCES = [
  /\bprocess\.env\b/, /\bos\.environ\b/, /\bgetenv\s*\(/, /\bread_env\b/
];

// High-signal credential/wallet/browser-secret reads. Co-occurrence with a sink
// is suspicious even without a fully traced flow.
const STRONG_SOURCES = [
  /\.ssh\/id_[a-z0-9]+/i, /\bid_ed25519\b/, /\bkeychain\b/i, /find-generic-password/,
  /security\s+find-/, /\bcookies\.sqlite\b/, /\bLogin Data\b/, /\bwallet\.dat\b/,
  /\bread_credentials\b/, /\bread_secrets\b/,
  // a .env FILE reference (preceded by quote/slash/space) — NOT "process.env"
  /[\/'"\s]\.env\b/
];

const SECRET_SOURCES = COMMON_SOURCES.concat(STRONG_SOURCES);

// Evaluating decoded/obfuscated content is malicious on its own — the payload
// is hidden inside the base64, so the shell command never appears in source.
const EVAL_DECODE = [
  /\beval\s*\(\s*atob/i, /\beval\s*\(\s*Buffer\.from/i, /\bexec\s*\(\s*atob/i,
  /new\s+Function\s*\(\s*atob/i, /\bexec\s*\(\s*base64/i, /\bpickle\.loads\b/
];

const NET_EXEC_SINKS = [
  /\bfetch\s*\(/, /\.post\s*\(/, /\.put\s*\(/, /\brequests\.(post|get|put|patch)\s*\(/,
  /\burllib\b/, /\bhttp\.request\b/, /\baxios\b/, /\bsendBeacon\b/, /\bXMLHttpRequest\b/,
  /\bchild_process\b/, /\bexecSync\s*\(/, /\bexec\s*\(/, /\bspawn\s*\(/,
  /\bos\.system\s*\(/, /\bos\.popen\s*\(/, /\bsubprocess\./, /\bpopen\s*\(/,
  /\|\s*(bash|sh)\b/, /\bcurl\s+http/i, /\bwget\s+http/i
];

const EXFIL_SINKS = [
  /discord\.com\/api\/webhooks/i, /hooks\.slack\.com/i, /webhook\.site/i,
  /pastebin\.com/i, /ngrok\.io/i, /requestbin/i, /\b0x0\.st\b/i, /transfer\.sh/i
];

const OBFUSCATED = [
  /\beval\s*\(\s*atob/i, /\batob\s*\(/, /\bbase64\s*-d\b/, /\bbase64\s+--decode\b/,
  /Buffer\.from\s*\([^)]*['"]base64['"]/, /\bFromBase64String\b/, /powershell\s+-enc/i
];
const SHELL_PIPE = [/\|\s*(bash|sh)\b/, /\bcurl\b/i, /\bwget\b/i, /os\.system|exec|popen|subprocess/];
const CLICKFIX = [/paste the following/i, /run this command/i, /copy and paste/i, /curl\s+-fsSL/i];

const IDENT = /[A-Za-z_$][\w$]*/g;
const ASSIGN = /^\s*(?:const|let|var|final)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;

// ---- comment / string handling -------------------------------------------

/* Remove line/block comments but keep code and string contents. */
function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let str = null; // current string delimiter
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (str) {
      out += c;
      if (c === '\\') { out += (c2 || ''); i += 2; continue; }
      if (c === str) str = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { str = c; out += c; i++; continue; }
    if (c === '/' && c2 === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && c2 === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++; i += 2; continue; }
    if (c === '#') { while (i < n && src[i] !== '\n') i++; continue; } // python / shell / yaml
    out += c;
    i++;
  }
  return out;
}

function anyMatch(list, s) { return list.some((re) => re.test(s)); }
function identsIn(s) { return (s.match(IDENT) || []); }

/* Split into rough statements (newline and ; boundaries). */
function statements(code) {
  return code.split(/[\n;]+/).map((s) => s.trim()).filter(Boolean);
}

/*
 * analyze(src) -> { flagged, confidence, reason, evidence:[...] }
 * confidence: 'high' | 'review' | null
 */
function analyze(src) {
  const raw = String(src || '');
  const code = stripComments(raw);
  const stmts = statements(code);

  // 1. Propagate taint across assignments (a couple of fixpoint passes).
  const tainted = new Set();
  const taintReason = new Map();
  for (let pass = 0; pass < 3; pass++) {
    for (const st of stmts) {
      const m = st.match(ASSIGN);
      if (!m) continue;
      const name = m[1];
      const rhs = m[2];
      if (anyMatch(SECRET_SOURCES, rhs)) { tainted.add(name); if (!taintReason.has(name)) taintReason.set(name, 'secret source'); }
      else if (identsIn(rhs).some((id) => tainted.has(id))) { tainted.add(name); if (!taintReason.has(name)) taintReason.set(name, 'derived from secret'); }
    }
  }

  // 2. A tainted identifier reaching a sink statement = proven exfil flow.
  for (const st of stmts) {
    const isSink = anyMatch(NET_EXEC_SINKS, st) || anyMatch(EXFIL_SINKS, st);
    if (!isSink) continue;
    const used = identsIn(st).filter((id) => tainted.has(id));
    if (used.length) {
      return {
        flagged: true, confidence: 'high', reason: 'tainted value flows to a network/exec sink',
        evidence: [`secret-derived "${used[0]}" (${taintReason.get(used[0]) || 'secret'}) reaches a sink`]
      };
    }
  }

  // 3. Evaluating decoded/obfuscated content is malicious on its own (the real
  //    command is hidden inside the base64, so it never appears as source text).
  if (anyMatch(EVAL_DECODE, code)) {
    return { flagged: true, confidence: 'high', reason: 'evaluates decoded/obfuscated code', evidence: ['eval/exec of a base64-decoded payload'] };
  }

  // 3b. Obfuscated decode together with a visible shell pipe / ClickFix prose.
  if (anyMatch(OBFUSCATED, code) && (anyMatch(SHELL_PIPE, code) || anyMatch(CLICKFIX, raw))) {
    return { flagged: true, confidence: 'high', reason: 'obfuscated decode-and-execute / ClickFix', evidence: ['base64/eval decode piped to a shell'] };
  }

  // 4. Hardcoded exfil endpoint plus any network/exec or secret read.
  if (anyMatch(EXFIL_SINKS, code) && (anyMatch(NET_EXEC_SINKS, code) || anyMatch(SECRET_SOURCES, code))) {
    const sink = EXFIL_SINKS.find((re) => re.test(code));
    return { flagged: true, confidence: 'high', reason: 'hardcoded exfiltration endpoint', evidence: [`exfil sink: ${(code.match(sink) || [''])[0]}`] };
  }

  // 5. Weaker signal: a HIGH-SIGNAL credential read (keychain, .ssh, wallet,
  //    cookies — NOT bare process.env) co-occurring with a sink. process.env on
  //    its own requires a traced flow (steps 1-2) to avoid false positives.
  if (anyMatch(STRONG_SOURCES, code) && anyMatch(NET_EXEC_SINKS, code)) {
    return { flagged: true, confidence: 'review', reason: 'credential read and network/exec present (no traced flow)', evidence: ['high-signal secret access near a sink — manual review suggested'] };
  }

  return { flagged: false, confidence: null };
}

module.exports = { analyze, stripComments, statements };
