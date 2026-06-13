'use strict';

const c = require('./util/colors.js');
const { detectInstalls } = require('./detect.js');
const { renderText, overallStatus } = require('./report.js');
const { updateFeed } = require('./feed.js');
const { correlate } = require('./correlate.js');
const { scoreAll } = require('./score.js');
const { toSarif } = require('./sarif.js');

/*
 * The check registry. Order = report order. Each module exports run(install)
 * and returns a canonical finding (see lib/findings.js). Adding a check is one
 * line here. Compound risks are derived afterwards by the correlation engine.
 */
const checks = [
  require('./checks/exposure.js'),     // Network reachability
  require('./checks/tunnel.js'),       // Tunnel exposure (Funnel/ngrok/cloudflared)
  require('./checks/auth.js'),         // Gateway authentication
  require('./checks/access.js'),       // Who can command the agent
  require('./checks/cors.js'),         // Cross-origin policy
  require('./checks/credentials.js'),  // Plaintext secrets
  require('./checks/redaction.js'),    // Secret redaction in logs/output
  require('./checks/fileperms.js'),    // Secret file permissions
  require('./checks/gitsecrets.js'),   // Secrets in version control
  require('./checks/version.js'),      // Version vs known CVEs
  require('./checks/skills.js'),       // Malicious skills & plugins
  require('./checks/mcp.js'),          // MCP tool-server supply chain
  require('./checks/ssrf.js'),         // SSRF / private-URL access
  require('./checks/privilege.js'),    // Sandboxing / excessive agency
  require('./checks/exec.js'),         // Command/shell execution policy
  require('./checks/scanner.js'),      // Command-content scanner (Tirith)
  require('./checks/approvals.js'),    // Human-in-the-loop approvals
  require('./checks/injection.js'),    // Prompt-injection exposure
  require('./checks/audit.js')         // Audit logging
];

const VERSION = require('../package.json').version;

const HELP = `
agentscan v${VERSION} — free, local security scanner for self-hosted AI agents
(OpenClaw, Hermes). Runs a framework-mapped posture assessment (CWE / OWASP LLM
Top 10 / MITRE ATLAS), correlates compound risks, and grades your setup A–F.
Everything runs on your machine; nothing is ever uploaded.

USAGE
  npx agentscan [options]

OPTIONS
  --path <dir>     Also scan an agent install at a custom location (repeatable)
  --json           Machine-readable JSON (findings, score, frameworks)
  --sarif          SARIF 2.1.0 output for CI / code-scanning dashboards
  --update-feed    Refresh the malicious-skill + advisory feeds (explicit
                   network call; a normal scan never touches the net)
  --feed-url <u>   Override the feed URL (also via AGENTSCAN_FEED_URL)
  --no-color       Disable ANSI colors
  -q, --quiet      Only print the summary line
  -h, --help       Show this help
  -v, --version    Show version

EXIT CODES
  0  all clear            1  warnings / skipped checks
  2  critical findings    3  scanner / feed error

WHAT IT CHECKS (19 checks + compound-risk correlation)
  Network exposure · tunnel exposure (Funnel/ngrok/cloudflared) · gateway auth ·
  access policy · CORS · plaintext secrets · secret redaction (logs) · secret
  file permissions · secrets in git · version vs CVEs · malicious skills/plugins ·
  MCP supply chain · SSRF / private-URL access · sandboxing/agency · command/exec
  policy · command-content scanner · approvals (human-in-the-loop) ·
  prompt-injection exposure · audit logging.

agentscan never sends your data anywhere (except the explicit --update-feed).
Read the source — zero dependencies, on purpose.
`;

function parseArgs(argv) {
  const opts = {
    json: false, sarif: false, quiet: false, color: true, extraPaths: [],
    help: false, version: false, updateFeed: false, feedUrl: null
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--json': opts.json = true; break;
      case '--sarif': opts.sarif = true; break;
      case '--no-color': opts.color = false; break;
      case '-q':
      case '--quiet': opts.quiet = true; break;
      case '-h':
      case '--help': opts.help = true; break;
      case '-v':
      case '--version': opts.version = true; break;
      case '--update-feed': opts.updateFeed = true; break;
      case '--feed-url':
        if (argv[i + 1]) opts.feedUrl = argv[++i];
        break;
      case '--path':
        if (argv[i + 1]) { opts.extraPaths.push(argv[++i]); }
        break;
      default:
        if (a.startsWith('--path=')) opts.extraPaths.push(a.slice('--path='.length));
        else if (a.startsWith('--feed-url=')) opts.feedUrl = a.slice('--feed-url='.length);
        // ignore unknown flags rather than failing a security tool on a typo
    }
  }
  return opts;
}

function countByStatus(installReports) {
  const counts = { green: 0, yellow: 0, red: 0 };
  for (const ir of installReports) {
    for (const f of ir.findings) counts[f.status]++;
  }
  return counts;
}

function countNotScanned(installReports) {
  let n = 0;
  for (const ir of installReports) {
    for (const f of ir.findings) if (f.scanned === false) n++;
  }
  return n;
}

function countChecks(installReports) {
  let n = 0;
  for (const ir of installReports) n += ir.findings.length;
  return n;
}

function statusToExitCode(status) {
  if (status === 'red') return 2;
  if (status === 'yellow') return 1;
  return 0;
}

async function run(argv) {
  const opts = parseArgs(argv || []);

  if (!opts.color || process.env.NO_COLOR) c.setEnabled(false);
  if (opts.help) { process.stdout.write(HELP + '\n'); return 0; }
  if (opts.version) { process.stdout.write(VERSION + '\n'); return 0; }

  if (opts.updateFeed) {
    process.stdout.write(c.dim('Refreshing blocklist feed…\n'));
    const r = await updateFeed({ url: opts.feedUrl });
    if (r.ok) {
      process.stdout.write(
        c.green('✓ ') + `feed updated to ${c.bold(r.version)} (${r.entries} entries)\n` +
        c.dim(`  cached at ${shorten(r.cachePath)}\n`));
      return 0;
    }
    process.stdout.write(
      c.yellow('! ') + `feed not updated: ${r.reason}\n` +
      c.dim('  continuing to use the bundled offline blocklist.\n'));
    return 3;
  }

  const installs = detectInstalls({ extraPaths: opts.extraPaths });

  const installReports = installs.map((install) => {
    const findings = checks.map((check) => {
      try {
        return check.run(install);
      } catch (err) {
        return {
          id: 'error', title: 'Check failed to run', category: 'General',
          status: 'yellow', severity: 'medium', scanned: false,
          detail: `A check errored: ${err.message}`,
          evidence: [], fix: 'This is a agentscan bug; please report it.',
          cwe: null, owasp: [], atlas: [], references: []
        };
      }
    });
    // Derive compound/chain findings, then append them.
    const chained = correlate(findings);
    return { id: install.id, name: install.name, homeDir: install.homeDir, findings: findings.concat(chained) };
  });

  const overall = installReports.length ? overallStatus(installReports) : 'green';
  const counts = countByStatus(installReports);
  const notScanned = countNotScanned(installReports);
  const totalChecks = countChecks(installReports);
  const { score, grade } = scoreAll(installReports);

  const result = {
    tool: 'agentscan',
    version: VERSION,
    scannedAt: new Date().toISOString(),
    installs: installReports,
    overall,
    score,
    grade,
    counts,
    notScanned,
    totalChecks
  };

  if (opts.sarif) {
    process.stdout.write(JSON.stringify(toSarif(result), null, 2) + '\n');
  } else if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else if (opts.quiet) {
    process.stdout.write(summaryLine(result) + '\n');
  } else {
    process.stdout.write(renderText(result) + '\n');
  }

  // No installs found is not a failure of the machine's security — exit 0.
  if (installReports.length === 0) return 0;
  // A check that couldn't run is not a clean bill of health: never exit 0.
  if (overall === 'green' && notScanned > 0) return 1;
  return statusToExitCode(overall);
}

function shorten(p) {
  const os = require('os');
  return p && p.startsWith(os.homedir()) ? '~' + p.slice(os.homedir().length) : p;
}

function summaryLine(result) {
  if (result.installs.length === 0) return 'agentscan: no agent install found';
  const { green, yellow, red } = result.counts;
  const skipped = result.notScanned || 0;
  const verdict = result.overall === 'red' ? 'AT RISK'
    : result.overall === 'yellow' ? 'NEEDS ATTENTION'
    : skipped > 0 ? 'INCOMPLETE' : 'LOOKS GOOD';
  const skipStr = skipped > 0 ? ` / ${skipped} skipped` : '';
  return `agentscan: grade ${result.grade} (${result.score}/100) — ${verdict} — ` +
    `${green} pass / ${yellow} warn / ${red} fail${skipStr}`;
}

/* Run every check + correlation against one install (used by tests/regression). */
function scanInstall(install) {
  const findings = checks.map((check) => {
    try { return check.run(install); }
    catch (err) {
      return { id: 'error', title: 'Check failed', category: 'General', status: 'yellow',
        severity: 'medium', scanned: false, detail: err.message, evidence: [], fix: '',
        cwe: null, owasp: [], atlas: [], references: [] };
    }
  });
  return findings.concat(correlate(findings));
}

module.exports = { run, parseArgs, statusToExitCode, scanInstall };
