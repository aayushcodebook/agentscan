'use strict';

/*
 * Security taxonomy used to tag every finding so the report is auditable
 * against recognized frameworks rather than being ad-hoc:
 *
 *   - CWE                — Common Weakness Enumeration (the specific flaw class)
 *   - OWASP LLM Top 10   — 2025 risks for LLM/agent applications
 *   - MITRE ATLAS        — adversary techniques against AI systems
 *
 * Keeping the IDs in one place means the mapping is consistent and reviewable.
 */

// Severity model (intrinsic to the weakness, independent of pass/fail status).
const SEV = { INFO: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
// Risk weights used by the posture score (see src/score.js).
const SEV_WEIGHT = { info: 1, low: 4, medium: 10, high: 20, critical: 40 };

// OWASP Top 10 for LLM Applications — 2025.
const OWASP = {
  LLM01: 'LLM01:2025 Prompt Injection',
  LLM02: 'LLM02:2025 Sensitive Information Disclosure',
  LLM03: 'LLM03:2025 Supply Chain',
  LLM04: 'LLM04:2025 Data and Model Poisoning',
  LLM05: 'LLM05:2025 Improper Output Handling',
  LLM06: 'LLM06:2025 Excessive Agency',
  LLM07: 'LLM07:2025 System Prompt Leakage',
  LLM08: 'LLM08:2025 Vector and Embedding Weaknesses',
  LLM09: 'LLM09:2025 Misinformation',
  LLM10: 'LLM10:2025 Unbounded Consumption'
};

// MITRE ATLAS techniques (subset relevant to self-hosted agents).
const ATLAS = {
  T0010: 'AML.T0010 ML Supply Chain Compromise',
  T0012: 'AML.T0012 Valid Accounts',
  T0024: 'AML.T0024 Exfiltration via ML Inference API',
  T0049: 'AML.T0049 Exploit Public-Facing Application',
  T0051: 'AML.T0051 LLM Prompt Injection',
  T0051_001: 'AML.T0051.001 LLM Prompt Injection: Indirect'
};

// Common CWE labels we reference (for nicer output).
const CWE = {
  'CWE-77': 'Command Injection',
  'CWE-250': 'Execution with Unnecessary Privileges',
  'CWE-284': 'Improper Access Control',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
  'CWE-312': 'Cleartext Storage of Sensitive Information',
  'CWE-319': 'Cleartext Transmission of Sensitive Information',
  'CWE-506': 'Embedded Malicious Code',
  'CWE-540': 'Inclusion of Sensitive Information in Source Code',
  'CWE-668': 'Exposure of Resource to Wrong Sphere',
  'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
  'CWE-778': 'Insufficient Logging',
  'CWE-829': 'Inclusion of Functionality from Untrusted Control Sphere',
  'CWE-942': 'Permissive Cross-domain Policy with Untrusted Domains',
  'CWE-1104': 'Use of Unmaintained Third Party Components',
  'CWE-1395': 'Dependency on Vulnerable Third-Party Component'
};

/* Compact one-line framework tag, e.g. "CWE-306 · LLM06 · AML.T0051". */
function tagLine(f) {
  const parts = [];
  if (f.cwe) parts.push(Array.isArray(f.cwe) ? f.cwe.join(',') : f.cwe);
  if (f.owasp && f.owasp.length) parts.push(f.owasp.map((o) => o.split(' ')[0]).join(','));
  if (f.atlas && f.atlas.length) parts.push(f.atlas.map((a) => a.split(' ')[0]).join(','));
  return parts.join(' · ');
}

function worseSeverity(a, b) {
  return SEV_RANK[a || 'info'] >= SEV_RANK[b || 'info'] ? (a || 'info') : (b || 'info');
}

module.exports = { SEV, SEV_RANK, SEV_WEIGHT, OWASP, ATLAS, CWE, tagLine, worseSeverity };
