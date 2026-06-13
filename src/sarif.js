'use strict';

/*
 * SARIF 2.1.0 export.
 *
 * SARIF is the OASIS standard static-analysis result format; GitHub code
 * scanning, Azure DevOps, and most security dashboards ingest it directly.
 * Emitting it lets agentscan results flow into the same pipeline as every other
 * security tool — the difference between a toy and something a security team
 * will actually wire into CI.
 */

const { statusKind } = require('./lib/findings.js');

// SARIF severity = problem.severity ("error"/"warning"/"note") + security-severity (CVSS-ish 0-10).
const SEV_TO_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'warning', info: 'note' };
const SEV_TO_SCORE = { critical: '9.5', high: '8.0', medium: '5.0', low: '3.0', info: '1.0' };

function ruleFromFinding(f) {
  const help = [f.detail, f.fix ? 'Remediation: ' + f.fix : ''].filter(Boolean).join('\n\n');
  return {
    id: f.id,
    name: f.id.replace(/(^|-)(\w)/g, (_, d, c) => c.toUpperCase()),
    shortDescription: { text: f.title },
    fullDescription: { text: f.detail || f.title },
    help: { text: help },
    defaultConfiguration: { level: SEV_TO_LEVEL[f.severity] || 'warning' },
    properties: {
      'security-severity': SEV_TO_SCORE[f.severity] || '5.0',
      tags: ['security', f.category]
        .concat(f.cwe ? (Array.isArray(f.cwe) ? f.cwe : [f.cwe]) : [])
        .concat((f.owasp || []).map((o) => o.split(' ')[0]))
        .concat((f.atlas || []).map((a) => a.split(' ')[0]))
    }
  };
}

function resultFromFinding(f, installName, homeDir) {
  const kind = statusKind(f); // pass|warn|fail|skipped
  return {
    ruleId: f.id,
    level: kind === 'pass' ? 'none' : (SEV_TO_LEVEL[f.severity] || 'warning'),
    kind: kind === 'pass' ? 'pass' : (kind === 'skipped' ? 'notApplicable' : 'fail'),
    message: { text: `[${installName}] ${f.detail}` + (f.evidence.length ? '\nEvidence: ' + f.evidence.join('; ') : '') },
    locations: [{
      physicalLocation: { artifactLocation: { uri: toUri(homeDir) } }
    }],
    properties: {
      severity: f.severity,
      status: f.status,
      scanned: f.scanned !== false,
      synthetic: !!f.synthetic,
      references: f.references || []
    }
  };
}

function toUri(p) {
  if (!p) return 'unknown';
  return 'file://' + p.replace(/\\/g, '/');
}

function toSarif(result) {
  const rulesById = {};
  const results = [];
  for (const ir of result.installs) {
    for (const f of ir.findings) {
      if (!rulesById[f.id]) rulesById[f.id] = ruleFromFinding(f);
      results.push(resultFromFinding(f, ir.name, ir.homeDir));
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'agentscan',
          informationUri: 'https://github.com/agentscan/agentscan',
          version: result.version,
          rules: Object.values(rulesById)
        }
      },
      properties: {
        postureScore: result.score,
        grade: result.grade,
        coverage: `${(result.totalChecks || 0) - (result.notScanned || 0)}/${result.totalChecks || 0}`
      },
      results
    }]
  };
}

module.exports = { toSarif };
