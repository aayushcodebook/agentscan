'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const { readConfigText, lookupKey } = require('../util/parse.js');

/*
 * CHECK 1 — Network exposure.
 *
 * Two things make an agent reachable from outside the machine:
 *   (a) its server binds to 0.0.0.0 / :: (all interfaces) rather than
 *       127.0.0.1 (localhost only), and
 *   (b) one of its ports is actually LISTENING.
 *
 * We read the bind address from config AND look at the live listening sockets
 * so we catch the real state even if config and runtime disagree.
 */

function listListeningPorts() {
  // Try, in order: `ss` (modern Linux), `lsof` (mac/Linux), `netstat` (fallback/Windows).
  const out = [];
  const tryCmd = (cmd) => {
    try {
      return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 4000 });
    } catch (_) {
      return null;
    }
  };

  let text = tryCmd('ss -tlnp 2>/dev/null') || tryCmd('ss -tln 2>/dev/null');
  if (text) {
    for (const line of text.split('\n')) {
      // e.g. "LISTEN 0 128 0.0.0.0:18080 0.0.0.0:*"
      const m = line.match(/LISTEN\s+\S+\s+\S+\s+(\S+):(\d+)\s/);
      if (m) out.push({ addr: m[1], port: parseInt(m[2], 10) });
    }
    return out;
  }

  text = tryCmd('lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null');
  if (text) {
    for (const line of text.split('\n')) {
      // e.g. "node 1234 user 20u IPv4 ... TCP 127.0.0.1:18080 (LISTEN)"
      const m = line.match(/TCP\s+(\[?[0-9a-fA-F.:*]+\]?):(\d+)\s+\(LISTEN\)/);
      if (m) out.push({ addr: m[1].replace(/[[\]]/g, ''), port: parseInt(m[2], 10) });
    }
    return out;
  }

  text = tryCmd('netstat -an 2>/dev/null');
  if (text) {
    for (const line of text.split('\n')) {
      if (!/LISTEN/i.test(line)) continue;
      const m = line.match(/(\d{1,3}(?:\.\d{1,3}){3}|\[?::\]?|\*|0\.0\.0\.0):(\d+)/);
      if (m) out.push({ addr: m[1].replace(/[[\]]/g, ''), port: parseInt(m[2], 10) });
    }
    return out;
  }

  return null; // couldn't enumerate
}

function isAllInterfaces(addr) {
  return addr === '0.0.0.0' || addr === '*' || addr === '::' || addr === '0:0:0:0:0:0:0:0';
}

/*
 * Classify a configured bind value against the target's documented model.
 * Agents like OpenClaw use NAMED modes (loopback/lan/tailnet/custom), not just
 * IP literals, so we consult the per-target safe/exposed lists first, then fall
 * back to the generic all-interfaces IP check.
 * Returns 'safe' | 'exposed' | 'unknown'.
 */
function classifyBind(install, value) {
  const v = String(value).trim().toLowerCase();
  const model = install.target.bind || {};
  const safe = (model.safeValues || []).map((s) => s.toLowerCase());
  const exposed = (model.exposedValues || []).map((s) => s.toLowerCase());
  if (exposed.includes(v) || isAllInterfaces(v)) return 'exposed';
  if (safe.includes(v)) return 'safe';
  return 'unknown';
}

function readBindAddress(install) {
  const keys = (install.target.bind && install.target.bind.keys) || [];
  for (const cf of install.configFiles) {
    let content;
    try { content = fs.readFileSync(cf, 'utf8'); } catch (_) { continue; }
    const parsed = readConfigText(content);
    for (const key of keys) {
      const { found, value } = lookupKey(parsed, key);
      if (found && typeof value === 'string') {
        return { addr: value.trim(), source: cf, key, klass: classifyBind(install, value) };
      }
    }
  }
  return null;
}

function run(install) {
  const finding = {
    id: 'exposure',
    title: 'Network exposure (port reachable from outside this machine)',
    category: 'Network',
    status: 'green',
    severity: 'high',
    cwe: 'CWE-668',
    owasp: ['LLM06:2025 Excessive Agency'],
    atlas: ['AML.T0049 Exploit Public-Facing Application'],
    references: [],
    detail: '',
    evidence: [],
    fix: ''
  };

  const listening = listListeningPorts();
  const bind = readBindAddress(install);
  const agentPorts = install.target.defaultPorts;

  // Which of the agent's known ports are actually listening, and on what addr.
  let exposedSockets = [];
  let localOnlySockets = [];
  if (listening) {
    for (const sock of listening) {
      if (!agentPorts.includes(sock.port)) continue;
      if (isAllInterfaces(sock.addr)) exposedSockets.push(sock);
      else localOnlySockets.push(sock);
    }
  }

  if (exposedSockets.length > 0) {
    finding.status = 'red';
    finding.detail =
      `The agent is listening on ${exposedSockets
        .map((s) => `${s.addr}:${s.port}`)
        .join(', ')} — bound to ALL network interfaces. Anyone who can reach ` +
      `this machine (other devices on your Wi-Fi, or the whole internet if this ` +
      `is a VPS without a firewall) can talk to your agent.`;
    exposedSockets.forEach((s) =>
      finding.evidence.push(`listening on ${s.addr}:${s.port} (all interfaces)`));
  } else if (bind && bind.klass === 'exposed') {
    // Config says exposed (an all-interfaces IP, or a named mode like
    // OpenClaw's lan/tailnet/custom) even without a confirmed live socket.
    finding.status = 'yellow';
    const named = !isAllInterfaces(bind.addr.toLowerCase());
    finding.detail = named
      ? `Config sets ${bind.key} = "${bind.addr}", which exposes the agent ` +
        `beyond localhost. If it's running, other machines can reach its port. ` +
        `Couldn't confirm a live socket — the agent may be stopped right now.`
      : `Config sets the bind address to ${bind.addr} (all interfaces). If the ` +
        `agent is running, its port is reachable from other machines. Couldn't ` +
        `confirm a live socket — the agent may be stopped right now.`;
    finding.evidence.push(`${bind.key} = ${bind.addr} in ${shortenHome(bind.source)}`);
  } else if (!listening && bind == null) {
    finding.status = 'yellow';
    finding.detail =
      `Couldn't read the listening sockets or a bind address on this system, ` +
      `so exposure can't be confirmed either way. On a server, verify manually ` +
      `that the agent's port is firewalled.`;
    finding.evidence.push('socket enumeration unavailable on this OS/permissions');
  } else {
    finding.status = 'green';
    finding.detail =
      localOnlySockets.length > 0
        ? `The agent is bound to localhost only (${localOnlySockets
            .map((s) => `${s.addr}:${s.port}`)
            .join(', ')}). Good — it's not reachable from other machines.`
        : `No agent port is exposed to all interfaces.`;
  }

  finding.fix =
    'Bind the agent to localhost (OpenClaw: gateway.bind "loopback"; Hermes: ' +
    'API_SERVER_HOST=127.0.0.1) and put a reverse proxy + firewall in front of ' +
    'any server. Never expose the raw agent port to the internet.';

  return finding;
}

function shortenHome(p) {
  const home = require('os').homedir();
  return p && p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { run, listListeningPorts, isAllInterfaces, classifyBind };
