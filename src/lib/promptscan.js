'use strict';

/*
 * Prompt-injection detector for skill TEXT (SKILL.md / instruction files).
 *
 * A skill's SKILL.md is injected verbatim into the agent's system prompt, so a
 * malicious skill needs no code — just words. This complements the code-level
 * taint analyzer (taint.js) by scanning the INSTRUCTION TEXT for the injection
 * payloads seen in real ClawHub malware: invisible/bidi unicode hiding text,
 * instructions buried in HTML comments, role-hijack / instruction-override
 * phrases, and prompts that tell the agent to exfiltrate secrets. OWASP LLM01.
 *
 * Tuned for PRECISION: a skill legitimately contains instruction-like prose, so
 * we flag only high-signal patterns and never a lone benign phrase. (Runs on
 * untrusted user skills only — first-party skills are hash-verified and skipped.)
 */

// Zero-width, bidi-override, and other invisible control chars used to hide
// instructions a human reviewer can't see but the model still reads:
// U+200B-200F (zero-width/ZWNJ/ZWJ/LRM/RLM), U+202A-202E (bidi embed/override),
// U+2060-2064 (word-joiner/invisible ops), U+2066-206F (bidi isolates), U+FEFF.
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/;

// Instructions hidden inside an HTML/markdown comment.
const HIDDEN_COMMENT = /<!--[\s\S]*?(ignore|override|system|\.env|secret|password|token|exfil|send\b)[\s\S]*?-->/i;

// Prompts that instruct exfiltration of secrets.
const EXFIL_PROMPT = [
  /contents?\s+of\s+[^\n]{0,24}\.env/i,
  /\b(send|post|upload|forward|exfiltrate|leak)\b[^\n]{0,50}(\.env|secret|credential|api[\s_-]?key|token|password)/i,
  /(\.env|secrets|credentials)[^\n]{0,30}(to|->|→)\s*https?:\/\//i
];

// Instruction-override / role-hijack phrasing.
const OVERRIDE = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts|messages)/i,
  /disregard\s+(all\s+)?(previous|prior|above)/i,
  /forget\s+(everything|all|your)\b/i,
  /system\s+override/i,
  /\[\s*system[^\]]*\]/i,
  /you\s+are\s+now\b[^.\n]{0,60}\b(no\s+restrictions|unrestricted|jailbroken|dan|developer\s+mode)\b/i,
  /new\s+instructions\s*:/i
];

// Telling the agent to hide its behavior from the user (modifier, not enough alone).
const CONCEAL = [
  /never\s+(reveal|tell|mention|disclose|say)\b/i,
  /do\s+not\s+(reveal|tell the user|mention|disclose|let the user)/i,
  /keep\s+this\s+(secret|hidden|between us)/i
];

function firstMatch(list, t) { return list.find((re) => re.test(t)); }

function analyze(text) {
  const t = String(text || '');
  const ev = [];
  let strong = false;

  if (INVISIBLE.test(t)) { ev.push('invisible/zero-width or bidi-override characters hiding text'); strong = true; }
  if (HIDDEN_COMMENT.test(t)) { ev.push('instructions concealed in an HTML comment'); strong = true; }
  if (firstMatch(EXFIL_PROMPT, t)) { ev.push('prompt instructs exfiltration of secrets / .env'); strong = true; }

  const override = firstMatch(OVERRIDE, t);
  const conceal = firstMatch(CONCEAL, t);

  if (!ev.length && !override) return { flagged: false };

  if (!ev.length && override) {
    // Only an override phrase: review by default, high if it also says "conceal".
    const e = ['instruction-override / role-hijack phrase'];
    if (conceal) e.push('+ instructs the agent to conceal it');
    return { flagged: true, confidence: conceal ? 'high' : 'review', reason: 'prompt-injection in skill text', evidence: e };
  }

  if (override) ev.push('instruction-override / role-hijack phrase');
  if (conceal) ev.push('instructs the agent to conceal this');
  return { flagged: true, confidence: strong ? 'high' : 'review', reason: 'prompt-injection in skill text', evidence: ev.slice(0, 4) };
}

module.exports = { analyze, INVISIBLE };
