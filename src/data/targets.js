'use strict';

/*
 * Known layouts for the agents we scan. Values below are taken from each
 * project's official docs (June 2026), not guesses:
 *
 *   OpenClaw   docs.openclaw.ai/gateway/configuration
 *              - config: ~/.openclaw/openclaw.json  (JSON5)
 *              - secrets/env: ~/.openclaw/.env
 *              - default port: 18789  (gateway.port; Control UI on 127.0.0.1:18789)
 *              - bind is a NAMED MODE under gateway.bind:
 *                  loopback (default, safe) | lan | tailnet | custom
 *
 *   Hermes     hermes-agent.nousresearch.com/docs/user-guide/configuration
 *              - home: ~/.hermes  (override via HERMES_HOME; %LOCALAPPDATA%\hermes on Windows)
 *              - config: config.yaml ; secrets: .env ; identity: SOUL.md
 *              - API server is configured by ENV VARS in ~/.hermes/.env:
 *                  API_SERVER_HOST (default 127.0.0.1), API_SERVER_PORT (default 8642)
 *              - dashboard default port: 9119
 *              - skills: ~/.hermes/skills ; logs: ~/.hermes/logs
 *
 * Paths use "~" for the user's home dir; detect.js expands it.
 */

module.exports = [
  {
    id: 'openclaw',
    name: 'OpenClaw',
    // OpenClaw was formerly "ClawdBot" / "Moltbot"; legacy installs (and the
    // ClawHavoc IoCs, which target ~/.clawdbot/.env) still use the old dirs.
    homeDirs: [
      '~/.openclaw',
      '~/.clawdbot',
      '~/.moltbot'
    ],
    // Scanned for secrets, bind mode, and audit/logging settings.
    configFiles: [
      'openclaw.json',
      '.env'
    ],
    // Skill roots: ~/.openclaw/skills (global) and the workspace's skills dir
    // (default ~/.openclaw/workspace/skills). A skill is a folder with SKILL.md;
    // discovery also finds them anywhere via marker/lockfile, so these are just
    // the well-known starting points.
    skillDirs: ['skills', 'workspace/skills'],
    // Plugins (openclaw.plugin.json) run code at runtime — a separate, bigger
    // attack surface. Discovery also finds them by marker anywhere in the home.
    pluginDirs: ['plugins'],
    defaultPorts: [18789],
    bind: {
      // keys (config dotted or env) that hold the network bind setting.
      // NOTE: gateway.mode is the deployment mode (local/remote), NOT the bind
      // address — deliberately excluded so it isn't misread as a bind value.
      keys: ['gateway.bind', 'bind', 'host'],
      // values that mean "localhost only" -> safe
      safeValues: ['loopback', '127.0.0.1', 'localhost', '::1'],
      // values that mean "reachable from other machines" -> exposed
      exposedValues: ['lan', 'tailnet', 'custom', '0.0.0.0', '::', '*']
    },
    auditKeys: ['logging.audit', 'logging.enabled', 'audit_log', 'auditLog'],
    logDirs: ['logs'],
    // --- hardening surface (used by the extended checks) -------------------
    // Gateway auth: a token/password protecting the local API/WebSocket.
    authKeys: ['gateway.auth.token', 'gateway.auth.password', 'OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD'],
    // Who may DM/command the agent. 'open' (+ allowFrom *) lets strangers in.
    accessKeys: ['dmPolicy', 'groupPolicy'],
    accessOpenValues: ['open'],
    allowFromKeys: ['allowFrom', 'groupAllowFrom'],
    // Permissive CORS lets any website call the local API.
    corsKeys: ['cors.allowedOrigins', 'allowedOrigins', 'cors'],
    // Cleartext transport.
    tlsKeys: ['gateway.tls', 'gateway.http.tls', 'tls'],
    // Agent autonomy: sandbox off / unrestricted = excessive agency.
    sandboxKeys: ['agents.defaults.sandbox.mode', 'sandbox.mode', 'sandbox'],
    sandboxSafeValues: ['non-main', 'all'],
    sandboxUnsafeValues: ['off', 'none', 'false', 'disabled'],
    // MCP tool servers (external code/tools the agent can call).
    mcpKeys: ['mcp', 'mcpServers', 'mcp.servers'],
    // Where to read the installed agent version for the CVE check. Real
    // OpenClaw records it in config under meta.lastTouchedVersion /
    // wizard.lastRunVersion (date-based scheme, e.g. "2026.6.6").
    versionFiles: ['package.json', 'VERSION', 'version.txt'],
    versionKeys: ['meta.lastTouchedVersion', 'wizard.lastRunVersion', 'version'],
    // npm package name — its bundled skills live in <global>/node_modules/<pkg>/skills.
    packageName: 'openclaw',
    // Path segments that mark the agent's own first-party code (besides
    // node_modules). OpenClaw is npm-installed so node_modules covers it.
    codeMarkers: [],
    // Hooks/webhook ingress secret (reused-secret / open-hook risk).
    hookKeys: ['hooks.token', 'hooks.enabled'],
    // Tunnel exposure: Tailscale Funnel = public internet; Serve = tailnet.
    tailscaleKeys: ['gateway.tailscale.mode'],
    tunnelFunnelValues: ['funnel'],
    tunnelServeValues: ['serve'],
    // Command/exec policy: tools.exec.security="full" is unrestricted host exec.
    execSecurityKeys: ['tools.exec.security'],
    execUnsafeValues: ['full'],
    allowlistKeys: ['command_allowlist', 'tools.exec.allow'],
    toolsProfileKeys: ['tools.profile'],
    permissiveProfileValues: ['all', 'full', 'unrestricted', 'everything', '*'],
    // Approvals: OpenClaw uses exec-approvals files, not a simple config key.
    approvalKeys: [],
    approvalSafeValues: [],
    approvalUnsafeValues: [],
    // Sensitive-data redaction in logs/output (OpenClaw: logging.redactSensitive;
    // values like "tools"/"all" are on, "off"/"none" disable it).
    redactionKeys: ['logging.redactSensitive'],
    piiRedactionKeys: [],
    // SSRF / private-URL access (best-effort keys for OpenClaw browser tools).
    ssrfAllowKeys: ['browser.allowPrivateUrls', 'browser.ssrfPolicy.allowPrivate'],
    // No built-in command-content scanner.
    scannerEnabledKeys: [],
    scannerFailOpenKeys: []
  },
  {
    id: 'hermes',
    name: 'Hermes Agent',
    homeDirs: [
      '~/.hermes',
      '~/.hermes/profiles/default'
    ],
    configFiles: [
      'config.yaml',
      'config.yml',
      '.env',
      'SOUL.md'
    ],
    skillDirs: ['skills'],
    defaultPorts: [8642, 9119],
    bind: {
      // Hermes configures the server via env vars in ~/.hermes/.env today.
      keys: ['API_SERVER_HOST', 'DASHBOARD_HOST', 'host', 'bind'],
      safeValues: ['127.0.0.1', 'localhost', '::1'],
      exposedValues: ['0.0.0.0', '::', '*']
    },
    // Hermes has no dedicated audit-log toggle today; the check falls back to
    // detecting the ~/.hermes/logs directory. (API_SERVER_KEY is a bearer
    // token, NOT an audit flag — deliberately not listed here.)
    auditKeys: ['audit_log', 'auditLog'],
    logDirs: ['logs'],
    // Hermes ships its code as a cloned repo at ~/.hermes/hermes-agent; its
    // first-party skills live under that dir (and in a Python venv we skip).
    codeMarkers: ['hermes-agent'],
    // --- hardening surface --------------------------------------------------
    // Hermes API auth bearer token (this one IS the auth key). The API server
    // is OPT-IN — only flag missing auth when it's actually enabled.
    authKeys: ['API_SERVER_KEY'],
    authEnabledKeys: ['API_SERVER_ENABLED'],
    accessKeys: ['dmPolicy'],
    accessOpenValues: ['open'],
    allowFromKeys: ['allowFrom'],
    corsKeys: ['API_SERVER_CORS_ORIGINS'],
    tlsKeys: ['API_SERVER_TLS', 'tls'],
    sandboxKeys: ['sandbox', 'sandbox.mode'],
    sandboxSafeValues: ['non-main', 'all', 'docker'],
    sandboxUnsafeValues: ['off', 'none', 'false', 'disabled'],
    mcpKeys: ['mcp', 'mcpServers'],
    versionFiles: ['package.json', 'VERSION', 'pyproject.toml'],
    versionKeys: ['meta.lastTouchedVersion', 'version'],
    packageName: 'hermes-agent',
    hookKeys: [],
    // Hermes doesn't use Tailscale-gateway exposure the same way; rely on the
    // generic ngrok/cloudflared raw-scan in the tunnel check.
    tailscaleKeys: [],
    tunnelFunnelValues: [],
    tunnelServeValues: [],
    execSecurityKeys: [],
    allowlistKeys: ['command_allowlist'],
    // Hermes approval policy: modes are manual | smart | off.
    approvalKeys: ['approvals.mode'],
    approvalSafeValues: ['manual', 'smart', 'ask', 'prompt', 'require', 'confirm'],
    approvalUnsafeValues: ['off', 'none', 'disabled', 'auto', 'yolo', 'never', 'always', 'auto_approve'],
    // Sensitive-data redaction (Hermes: security.redact_secrets boolean; PII separate).
    redactionKeys: ['security.redact_secrets'],
    piiRedactionKeys: ['privacy.redact_pii'],
    // SSRF / private-URL access (applies to web, browser, vision, media tools).
    ssrfAllowKeys: ['security.allow_private_urls', 'browser.allow_private_urls'],
    // Tirith command-content scanner.
    scannerEnabledKeys: ['security.tirith_enabled'],
    scannerFailOpenKeys: ['security.tirith_fail_open']
  }
];
