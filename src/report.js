'use strict';

const c = require('./util/colors.js');
const { tagLine } = require('./lib/frameworks.js');

const SEV_LABEL = {
  critical: (s) => c.bgRed(c.bold(' CRIT ')),
  high: (s) => c.red('HIGH'),
  medium: (s) => c.yellow('MED'),
  low: (s) => c.blue('LOW'),
  info: (s) => c.gray('INFO')
};
function sevBadge(f) {
  const fn = SEV_LABEL[f.severity] || SEV_LABEL.medium;
  return fn(f.severity);
}

function gradeBadge(g) {
  if (g === 'A') return c.bgGreen(c.bold(` ${g} `));
  if (g === 'B' || g === 'C') return c.bgYellow(c.bold(` ${g} `));
  return c.bgRed(c.bold(` ${g} `));
}

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const STATUS_RANK = { red: 3, yellow: 2, green: 0 };
/* Sort weight: failures/criticals first, skipped above passes. */
function sortKey(f) {
  const sev = SEV_RANK[f.severity] || 2;
  const st = f.scanned === false ? 1 : (STATUS_RANK[f.status] || 0);
  const synth = f.synthetic ? 1 : 0;
  return st * 100 + sev * 10 + synth;
}

const RANK = { green: 0, yellow: 1, red: 2 };

/* A not-scanned finding renders as SKIP (gray) even though it ranks as yellow. */
function labelFor(f) {
  if (f.scanned === false) return c.gray('SKIP');
  if (f.status === 'red') return c.red('FAIL');
  if (f.status === 'yellow') return c.yellow('WARN');
  return c.green('PASS');
}

function dotFor(f) {
  if (f.scanned === false) return c.gray('○');
  if (f.status === 'red') return c.red('●');
  if (f.status === 'yellow') return c.yellow('●');
  return c.green('●');
}

function worst(a, b) {
  return RANK[a] >= RANK[b] ? a : b;
}

/* Overall grade from the set of findings across all installs. */
function overallStatus(installReports) {
  let s = 'green';
  for (const ir of installReports) {
    for (const f of ir.findings) s = worst(s, f.status);
  }
  return s;
}

function banner() {
  const W = 48; // inner width between the borders
  const top = '┌─ ' + c.bold('agentscan') + ' ' + '─'.repeat(W - ' agentscan '.length - 2) + '┐';
  const bottom = '└' + '─'.repeat(W) + '┘';
  return (
    '\n' +
    '  ' + c.cyan(top) + '\n' +
    '  ' + c.cyan('│ ') + c.dim('local security check for self-hosted AI agents'.padEnd(W - 2)) + c.cyan('│') + '\n' +
    '  ' + c.cyan('│ ') + c.dim('runs 100% locally · nothing is uploaded'.padEnd(W - 2)) + c.cyan('│') + '\n' +
    '  ' + c.cyan(bottom) +
    '\n'
  );
}

function renderText(result) {
  const lines = [];
  lines.push(banner());

  if (result.installs.length === 0) {
    lines.push(c.yellow('  No OpenClaw or Hermes install was found on this machine.'));
    lines.push(c.dim('  If you have one in a custom location, point agentscan at it:'));
    lines.push(c.dim('      npx agentscan --path /path/to/agent'));
    lines.push('');
    return lines.join('\n');
  }

  for (const ir of result.installs) {
    const gradeStr = ir.grade ? '  ' + gradeBadge(ir.grade) + c.dim(` ${ir.score}/100`) : '';
    lines.push('  ' + c.bold(ir.name) + c.dim('  ' + shortenHome(ir.homeDir)) + gradeStr);
    lines.push('  ' + c.dim('─'.repeat(50)));

    // Findings sorted worst-first so the scary stuff is at the top.
    const ordered = ir.findings.slice().sort((a, b) => sortKey(b) - sortKey(a));
    for (const f of ordered) {
      const sev = (f.status !== 'green' || f.scanned === false) ? '  ' + sevBadge(f) : '';
      lines.push(`  ${dotFor(f)} ${labelFor(f)}  ${f.title}${sev}`);
      const tags = tagLine(f);
      if (tags) lines.push('       ' + c.gray(tags));
      lines.push('       ' + wrap(f.detail, 66, '       '));
      for (const e of f.evidence.slice(0, 6)) {
        lines.push('         ' + c.dim('• ' + e));
      }
      if (f.status !== 'green' || f.scanned === false) {
        lines.push('       ' + c.cyan('fix: ') + c.dim(wrap(f.fix, 60, '            ')));
      }
      lines.push('');
    }
  }

  // Summary
  const status = result.overall;
  const counts = result.counts;
  const notScanned = result.notScanned || 0;
  const ranChecks = result.totalChecks - notScanned;

  lines.push('  ' + c.bold('Summary'));
  lines.push('  ' + c.dim('─'.repeat(50)));
  if (result.grade) {
    lines.push('  ' + c.bold('posture grade ') + gradeBadge(result.grade) +
      c.dim(`  ${result.score}/100`));
  }
  lines.push(
    '  ' +
      c.green(`${counts.green} pass`) + c.dim('  ·  ') +
      c.yellow(`${counts.yellow} warn`) + c.dim('  ·  ') +
      c.red(`${counts.red} fail`) +
      (notScanned ? c.dim('  ·  ') + c.gray(`${notScanned} skipped`) : '')
  );
  // Coverage line — make skipped checks impossible to miss.
  lines.push(
    '  ' + c.dim('coverage: ') +
      (notScanned
        ? c.gray(`${ranChecks}/${result.totalChecks} checks ran — `) +
          c.yellow(`${notScanned} could not run (see SKIP above)`)
        : c.dim(`${ranChecks}/${result.totalChecks} checks ran`))
  );

  let verdict;
  if (status === 'red') {
    verdict = c.bgRed(c.bold(' AT RISK ')) +
      '  ' + c.red('Critical problems found. Fix the FAILs above now.');
  } else if (status === 'yellow') {
    verdict = c.bgYellow(c.bold(' NEEDS ATTENTION ')) +
      '  ' + c.yellow('No criticals, but review the warnings.');
  } else if (notScanned > 0) {
    // All green, but a check couldn't run — never claim "looks good".
    verdict = c.bgYellow(c.bold(' INCOMPLETE ')) +
      '  ' + c.yellow('Checks that ran passed, but ' + notScanned +
      ' could not run. Not an all-clear.');
  } else {
    verdict = c.bgGreen(c.bold(' LOOKS GOOD ')) +
      '  ' + c.green('No issues found in the checks we run.');
  }
  lines.push('  ' + verdict);
  lines.push('');
  lines.push(c.dim('  agentscan checks a fixed list of known issues; a clean result is not a'));
  lines.push(c.dim('  guarantee. Free & open source — re-run after you install a skill or'));
  lines.push(c.dim('  update your agent. Refresh threat intel: ') + c.cyan('agentscan --update-feed') + c.dim('.'));
  lines.push(c.dim('  Found a false positive? Please open an issue.'));
  lines.push('');
  return lines.join('\n');
}

/* Soft word-wrap with a hanging indent. */
function wrap(text, width, indent) {
  if (!text) return '';
  const words = String(text).split(/\s+/);
  const out = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      out.push(line);
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) out.push(line);
  return out.join('\n' + indent);
}

function shortenHome(p) {
  const home = require('os').homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

module.exports = { renderText, overallStatus, worst };
