'use strict';

const { SEV_WEIGHT } = require('./lib/frameworks.js');

/*
 * Posture scoring.
 *
 * Start at 100 and subtract a penalty per finding, weighted by the finding's
 * severity and its outcome:
 *   fail     = full weight
 *   warn     = half weight
 *   skipped  = quarter weight (uncertainty is a real, if smaller, risk)
 *   pass     = 0
 * Score is floored at 0. Grade is a simple banding. Coverage (how many checks
 * actually ran) is reported separately so a high score on thin coverage can't
 * masquerade as safety.
 */

const OUTCOME_FACTOR = { fail: 1.0, warn: 0.5, skipped: 0.25, pass: 0 };

function outcome(f) {
  if (f.scanned === false) return 'skipped';
  if (f.status === 'red') return 'fail';
  if (f.status === 'yellow') return 'warn';
  return 'pass';
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/* Score one install's findings (including synthetic chain findings). */
function scoreInstall(findings) {
  let penalty = 0;
  for (const f of findings) {
    const w = SEV_WEIGHT[f.severity] || SEV_WEIGHT.medium;
    penalty += w * OUTCOME_FACTOR[outcome(f)];
  }
  const score = Math.max(0, Math.round(100 - penalty));
  return { score, grade: gradeFor(score) };
}

/* Aggregate across installs (worst grade drives the headline). */
function scoreAll(installReports) {
  let minScore = 100;
  for (const ir of installReports) {
    const s = scoreInstall(ir.findings);
    ir.score = s.score;
    ir.grade = s.grade;
    if (s.score < minScore) minScore = s.score;
  }
  return { score: installReports.length ? minScore : 100, grade: gradeFor(installReports.length ? minScore : 100) };
}

module.exports = { scoreInstall, scoreAll, gradeFor, outcome };
