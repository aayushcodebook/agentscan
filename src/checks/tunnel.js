'use strict';

const { makeFinding } = require('../lib/findings.js');
const { SEV, OWASP, ATLAS } = require('../lib/frameworks.js');
const { findKey, readAll, shortenHome } = require('../lib/config.js');

/*
 * CHECK — Tunnel exposure.
 *
 * The network-exposure check looks at the bind address. But an agent bound to
 * localhost can STILL be on the public internet if it's fronted by a tunnel:
 * Tailscale Funnel, ngrok, or cloudflared. That's a blind spot — a "safe"
 * loopback bind plus a public tunnel is full exposure. CWE-668.
 * (Mirrors OpenClaw's native `gateway.tailscale_funnel` check.)
 */

const TUNNEL_HINTS = ['ngrok', 'cloudflared', 'trycloudflare', 'localtunnel', 'bore.pub'];

function run(install) {
  const f = makeFinding({
    id: 'tunnel-exposure',
    title: 'Tunnel exposure (localhost agent published to the internet?)',
    category: 'Network',
    severity: SEV.HIGH,
    cwe: 'CWE-668',
    owasp: [OWASP.LLM06],
    atlas: [ATLAS.T0049],
    fix: 'Do not expose the agent via a public tunnel. Tailscale: use private ' +
      'Serve (tailnet-only), never Funnel. Avoid ngrok/cloudflared for an agent ' +
      'with tools. If remote access is needed, put auth + an allowlist in front.'
  });

  // 1. Tailscale mode (OpenClaw: gateway.tailscale.mode).
  const tsKeys = install.target.tailscaleKeys || [];
  const ts = tsKeys.length ? findKey(install, tsKeys) : { found: false };
  if (ts.found) {
    const v = String(ts.value).trim().toLowerCase();
    const funnel = (install.target.tunnelFunnelValues || ['funnel']).map((x) => x.toLowerCase());
    const serve = (install.target.tunnelServeValues || ['serve']).map((x) => x.toLowerCase());
    if (funnel.includes(v)) {
      f.status = 'red';
      f.severity = SEV.CRITICAL;
      f.detail = 'Tailscale Funnel is enabled — the agent is published to the ' +
        'PUBLIC internet, regardless of its localhost bind.';
      f.evidence.push(`${ts.key} = ${ts.value} in ${shortenHome(ts.source)}`);
      return f;
    }
    if (serve.includes(v)) {
      f.status = 'yellow';
      f.severity = SEV.LOW;
      f.detail = 'Tailscale Serve is enabled — the agent is reachable across your ' +
        'tailnet (not the public internet). Confirm every tailnet device is trusted.';
      f.evidence.push(`${ts.key} = ${ts.value} in ${shortenHome(ts.source)}`);
      return f;
    }
  }

  // 2. ngrok / cloudflared / etc. referenced in config (case-insensitive).
  for (const file of readAll(install)) {
    const lc = file.raw.toLowerCase();
    for (const hint of TUNNEL_HINTS) {
      if (lc.includes(hint)) {
        f.status = 'yellow';
        f.severity = SEV.MEDIUM;
        f.detail = `A public tunneling tool ("${hint}") is referenced in config. ` +
          `If it fronts the agent, your localhost bind is bypassed and the agent ` +
          `is internet-reachable.`;
        f.evidence.push(`"${hint}" referenced in ${shortenHome(file.file)}`);
        return f;
      }
    }
  }

  f.status = 'green';
  f.detail = 'No public tunnel (Tailscale Funnel / ngrok / cloudflared) detected.';
  return f;
}

module.exports = { run };
