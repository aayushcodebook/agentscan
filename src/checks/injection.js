'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP, ATLAS } = require('../lib/frameworks.js');
const { readAll, findKey } = require('../lib/config.js');

/*
 * CHECK — Prompt-injection exposure (posture, not proof).
 *
 * Indirect prompt injection (OWASP LLM01, ATLAS T0051.001) is THE signature
 * agent risk: untrusted content the agent reads (an email, a web page, a chat
 * message, a webhook payload) carries hidden instructions it then executes.
 *
 * A static config scan cannot PROVE an injection path, so this is an explicit
 * posture assessment: it raises a flag when the ingredients line up —
 *   (1) the agent ingests untrusted external content, AND
 *   (2) it has high-impact capability (unsandboxed tools / shell), AND
 *   (3) gating is weak (open access).
 * It is intentionally advisory and says so.
 */

// Strip comment lines (# ...) so commented-out tokens in a default config
// aren't mistaken for an active, configured channel.
function uncommented(raw) {
  return raw
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

// Map a credential's prefix/name to the surface it activates.
const SURFACE_MAP = [
  [/telegram/i, 'telegram'], [/slack/i, 'slack'], [/discord/i, 'discord'],
  [/whatsapp/i, 'whatsapp'], [/signal/i, 'signal'], [/matrix/i, 'matrix'],
  [/teams/i, 'teams'], [/mattermost/i, 'mattermost'], [/google_?chat/i, 'google chat'],
  [/(weixin|wecom|feishu|lark|dingtalk|qq|yuanbao|\bline\b|zalo)/i, 'china-messaging'],
  [/(browserbase|camofox)/i, 'browser'],
  [/(\bexa\b|firecrawl|parallel|tavily|serpapi|searxng)/i, 'web search'],
  [/(email|imap|smtp|gmail)/i, 'email']
];

const PLACEHOLDER = /^(\$\{|<|your[-_]|changeme|example|xxx|true$|false$|none$|''$|""$)/i;

/*
 * ACTIVE untrusted-input surfaces: a channel only counts if there is a REAL
 * credential/token configured for it (or it is explicitly enabled / open).
 * Hermes/OpenClaw default configs list every platform as a config SECTION even
 * when nothing is connected — counting those would be crying wolf. We require
 * an actual secret value, an explicit enable, or a non-empty allowlist.
 */
function activeSurfaces(install) {
  const found = new Set();
  // A credential assignment with a real (>=8 char, non-placeholder) value.
  const CRED = /([a-z][a-z0-9_]*?(?:bot[_-]?token|app[_-]?token|api[_-]?token|api[_-]?key|webhook[_-]?url|webhook[_-]?secret|access[_-]?token|bot[_-]?secret))\s*[:=]\s*["']?([^\s"'#,}]{8,})/ig;

  for (const file of readAll(install)) {
    const text = uncommented(file.raw);
    let m;
    while ((m = CRED.exec(text)) !== null) {
      const name = m[1];
      const val = m[2];
      if (PLACEHOLDER.test(val)) continue;
      const hit = SURFACE_MAP.find(([re]) => re.test(name));
      found.add(hit ? hit[1] : 'messaging channel');
    }
    // OpenClaw inline channel token: botToken: "<real>"
    if (/\bbottoken\s*[:=]\s*["'][^"'\s]{8,}/i.test(text)) found.add('messaging channel');
    // Explicit open access / all-users.
    if (/\ballow_all_users\s*[:=]\s*true/i.test(text) || /gateway_allow_all_users\s*=\s*true/i.test(text)) found.add('open messaging');
    // A non-empty allowlist means a channel is wired up.
    if (/\ballowed_(channels|chats|users|rooms)\s*[:=]\s*["']?[^\s"'#\][]/i.test(text)) found.add('messaging channel');
    // Browser actually routed through a non-local cloud provider.
    if (/cloud_provider\s*[:=]\s*["']?(?!local)\w/i.test(text)) found.add('browser');
  }
  return [...found];
}

function run(install) {
  const f = makeFinding({
    id: 'prompt-injection',
    title: 'Prompt-injection exposure (untrusted input × capability × gating)',
    category: 'Prompt injection',
    severity: SEV.MEDIUM,
    cwe: 'CWE-77',
    owasp: [OWASP.LLM01],
    atlas: [ATLAS.T0051, ATLAS.T0051_001],
    references: [{ id: 'OWASP LLM01:2025', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/' }],
    fix: 'Assume any content the agent reads can carry instructions. Sandbox ' +
      'tools, require human confirmation for high-impact actions (sending, ' +
      'spending, deleting), restrict who/what it ingests, and keep untrusted ' +
      'channels on least-privilege agents.'
  });

  const surface = activeSurfaces(install);

  // Capability/gating signals (reuse config, not the other checks' verdicts).
  const sbKeys = install.target.sandboxKeys || [];
  const unsafe = (install.target.sandboxUnsafeValues || []).map((v) => v.toLowerCase());
  const sb = findKey(install, sbKeys);
  const sandboxOff = sb.found && unsafe.includes(String(sb.value).toLowerCase());
  const sandboxUnknown = !sb.found;

  const accessOpen = (() => {
    const openVals = (install.target.accessOpenValues || []).map((v) => v.toLowerCase());
    const p = findKey(install, install.target.accessKeys || []);
    return p.found && openVals.includes(String(p.value).toLowerCase());
  })();

  if (surface.length === 0) {
    f.status = 'green';
    f.detail = 'No ACTIVE untrusted-input channels are configured (no connected ' +
      'messaging/browser/email credentials), so indirect prompt-injection ' +
      'exposure is limited. (Connecting a channel later raises this.)';
    return f;
  }

  // There IS an active untrusted surface — weigh capability + gating.
  f.evidence.push(`connected untrusted-input surface(s): ${surface.join(', ')}`);
  const aggravators = [];
  if (sandboxOff) aggravators.push('tools run unsandboxed');
  if (accessOpen) aggravators.push('open access policy');

  if (aggravators.length >= 1) {
    f.status = 'red';
    f.severity = SEV.HIGH;
    f.detail = 'The agent reads untrusted external content AND ' + aggravators.join(' AND ') +
      '. Hidden instructions in an email/page/message could drive high-impact ' +
      'actions. (Posture assessment — a config scan cannot prove the path, but ' +
      'the ingredients are present.)';
    aggravators.forEach((a) => f.evidence.push('aggravator: ' + a));
    return f;
  }

  f.status = 'yellow';
  f.severity = SEV.MEDIUM;
  f.detail = 'The agent reads untrusted external content. Even with reasonable ' +
    'gating, treat anything it reads as potentially carrying instructions; ' +
    'require confirmation for high-impact actions. ' +
    (sandboxUnknown ? '(Could not confirm sandboxing.)' : '');
  return f;
}

module.exports = { run };
