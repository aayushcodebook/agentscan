'use strict';

const { SEV } = require('./frameworks.js');

/*
 * Canonical finding object. Every check returns one of these so the report,
 * scoring, correlation, and SARIF export can all rely on the same shape.
 *
 *   id         stable check id (kebab-case)
 *   title      human title
 *   category   short bucket ("Network", "Secrets", "Supply chain", ...)
 *   severity   intrinsic weakness severity (info|low|medium|high|critical)
 *   status     outcome: 'green' (pass) | 'yellow' (warn) | 'red' (fail)
 *   scanned    false when the check could not run (renders SKIP, not a pass)
 *   detail     one-paragraph explanation
 *   evidence   array of concrete strings (paths, values — secrets masked)
 *   fix        remediation guidance
 *   cwe        CWE id(s)
 *   owasp      array of OWASP LLM Top-10 labels
 *   atlas      array of MITRE ATLAS labels
 *   references array of { id, url } citations
 *   synthetic  true for correlation-derived findings
 */
function makeFinding(o) {
  return {
    id: o.id,
    title: o.title,
    category: o.category || 'General',
    severity: o.severity || SEV.MEDIUM,
    status: o.status || 'green',
    scanned: o.scanned !== false,
    detail: o.detail || '',
    evidence: o.evidence || [],
    fix: o.fix || '',
    cwe: o.cwe || null,
    owasp: o.owasp || [],
    atlas: o.atlas || [],
    references: o.references || [],
    synthetic: !!o.synthetic
  };
}

// Map a status to a pass/fail-ish word for SARIF & summaries.
function statusKind(f) {
  if (f.scanned === false) return 'skipped';
  if (f.status === 'red') return 'fail';
  if (f.status === 'yellow') return 'warn';
  return 'pass';
}

module.exports = { makeFinding, statusKind };
