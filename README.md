# agentscan

**The cross-agent security posture scanner for self-hosted AI agents.**


https://github.com/user-attachments/assets/422a90a9-3ce1-4071-8ce9-38c10cf77238


Most agent-security tools scan one skill, for one agent, before you install it.
agentscan audits your **whole running install** — and works across **OpenClaw,
Hermes, and more** from a single tool. One command runs a framework-mapped
posture assessment — **19 checks plus compound-risk correlation** — covering
network exposure, gateway auth, CVEs, secrets, SSRF, sandboxing, *and* malicious
skills/plugins (with taint analysis + prompt-injection detection). It maps every
finding to CWE / OWASP LLM Top 10 / MITRE ATLAS, grades your setup **A–F**, and
emits **SARIF** for CI. Everything runs on your machine — nothing is ever
uploaded, and there are **zero dependencies** so you can read every line before
you trust it.

Validated against real, default installs of **both** OpenClaw and Hermes — each
grades **B** with specific, actionable findings and **zero false alarms** (incl.
across 300+ real bundled skills).

```bash
npx @aayushcodebook/agentscan
```

```
  OpenClaw  ~/.openclaw   F  0/100
  ──────────────────────────────────────────────────
  ● FAIL  CHAIN: network-exposed AND unauthenticated gateway (RCE-class)   CRIT
       CWE-306,CWE-668 · LLM06:2025 · AML.T0049,AML.T0012
  ● FAIL  Agent version vs. known security advisories (CVEs)   CRIT
       CWE-1395 · LLM03:2025
       Installed version 3.0.0 is affected by CVE-2026-25253 (CVSS 8.8)…
  ● FAIL  Malicious or suspicious skills & plugins   CRIT
  ● FAIL  Gateway authentication (is the local API/WebSocket protected?)   CRIT
  …
  posture grade  F  0/100
  coverage: 13/15 checks ran
```

## What it checks

Each finding is tagged with its **CWE**, **OWASP LLM Top 10 (2025)**, and where
applicable a **MITRE ATLAS** technique, and carries an intrinsic severity used
for scoring.

| Check | Maps to | Why it matters |
|-------|---------|----------------|
| **Network exposure** | CWE-668 · ATLAS T0049 | Is the port reachable beyond localhost? (63% of public instances are.) |
| **Tunnel exposure** | CWE-668 · LLM06 | A localhost-bound agent fronted by Tailscale Funnel / ngrok / cloudflared is on the public internet anyway — the bind-address blind spot. |
| **Gateway authentication** | CWE-306/307 · LLM06 | Open port + no/weak auth = the ClawJacked/ClawBleed (CVE-2026-25253) precondition. |
| **Access policy** | CWE-284 · LLM06 | `dmPolicy: open` / `allowFrom: ["*"]` lets any stranger on a channel command the agent. |
| **CORS** | CWE-942 | A wildcard origin lets any website you visit call the agent's API. |
| **Plaintext credentials** | CWE-312 · LLM02 | API keys/passwords stored in cleartext config. |
| **Secret redaction** | CWE-532 · LLM02 | If redaction is off, secrets in tool output leak into transcripts and on-disk logs. |
| **Secret file permissions** | CWE-732 | A key in `.env` is only safe if the file isn't world-readable. |
| **Secrets in git** | CWE-540 · LLM02 | Agent home is a repo and secrets aren't `.gitignore`d → committed/pushed. |
| **Version vs CVEs** | CWE-1395 · LLM03 | Running a build with a published advisory (feed-updatable; ships with the 2026 OpenClaw CVEs). |
| **Malicious skills & plugins** | CWE-506 · LLM01/LLM03 · ATLAS T0010 | Signature-discovered (`SKILL.md`/`openclaw.plugin.json`), matched to the ClawHavoc blocklist, **taint-analyzed** (does a secret actually *flow* into a network/exec sink?), **prompt-injection-scanned** in the SKILL.md *text* (invisible/bidi unicode, hidden-comment instructions, role-hijack/override, exfil prompts), and **integrity-verified** (a "first-party" skill is trusted only if its bytes hash-match the original; impostors are caught). SKIP (never pass) if nothing found. |
| **MCP supply chain** | CWE-829 · LLM03 | Remote MCP tool servers are third-party code in the agent's trust boundary. |
| **SSRF / private URLs** | CWE-918 · LLM06 | If private-URL access is on, a poisoned link can reach internal hosts or the cloud-metadata endpoint (169.254.169.254). |
| **Command-content scanner** | CWE-693 · LLM06 | Hermes pre-screens shell commands (Tirith); flags it disabled or fail-open. |
| **Sandboxing / agency** | CWE-250 · LLM06 | Unsandboxed tools (or running as root) turn one bad instruction into full machine access. |
| **Command/exec policy** | CWE-250 · LLM06 | Unrestricted shell (`tools.exec.security="full"`, empty command allowlist) is the path from prompt injection to RCE. |
| **Approvals (HITL)** | CWE-250 · LLM06 | Auto-approving high-impact actions removes the last human gate against a hijacked agent. |
| **Prompt-injection exposure** | CWE-77 · LLM01 · ATLAS T0051 | Posture: untrusted input × capability × weak gating. Honest that a static scan can't *prove* an injection path. |
| **Audit logging** | CWE-778 | No record of agent actions = no incident response, no SOC2/HIPAA/GDPR. |

**Compound-risk correlation.** Individually-yellow findings can be a critical
chain. agentscan names them — e.g. *exposed + unauthenticated* (RCE-class,
CVE-2026-25253), *exposed + open command policy*, *untrusted input + a live
malicious extension*.

**Posture score & grade.** Start at 100, subtract severity-weighted penalties
(fail = full, warn = half, **skipped = ¼**, so uncertainty still costs), floored
at 0, banded A–F. Coverage is reported separately so a high score on thin
coverage can't masquerade as safety.

## Continuous monitoring (free)

A scan is point-in-time, but the risky moment is *after* setup — when you install
a new skill or change config. Re-run on a schedule and get alerted only when your
posture gets **worse**. No extra tooling — just `agentscan`, a scheduler, and a diff.

A cron one-liner that re-scans daily and notifies on any new finding (drop in
grade or a new fail), comparing against the last run:

```bash
# crontab -e  →  scan at 8am daily; alert only if the grade/score regresses
0 8 * * * cur=$(npx @aayushcodebook/agentscan@latest --quiet 2>/dev/null); prev=$(cat ~/.agentscan/last 2>/dev/null); \
  echo "$cur" > ~/.agentscan/last; [ "$cur" != "$prev" ] && \
  printf '%s\n' "$cur" | grep -qE 'AT RISK|fail' && \
  osascript -e "display notification \"$cur\" with title \"agentscan\"" 2>/dev/null || true
```

On Linux, swap the `osascript` line for `notify-send "agentscan" "$cur"` (or pipe to
Slack/email). In CI, the GitHub Action in `examples/agentscan-scan.yml` does the
same on a schedule and uploads SARIF.

A built-in `agentscan --watch` (file-watch the agent's config + skills dirs, scan
the moment something changes) is on the roadmap — open an issue if you'd use it.
Live behavioral monitoring (catching an exfil or injection *as it happens*) is a
separate, bigger effort, not part of this CLI.

### How it relates to native tools

agentscan is **complementary** to an agent's own auditor, not a replacement.
OpenClaw's built-in `openclaw security audit --deep` goes far deeper on
OpenClaw-specific config hardening (filesystem ACLs, hooks, Docker sandbox
internals) and can auto-fix — run it. agentscan's distinct value is **cross-agent
coverage** (OpenClaw *and* Hermes), a **curated malicious-skill blocklist** and
**CVE advisory feed** (threat intel a built-in `doctor` won't maintain), and
**framework-mapped, SARIF output** for security teams and CI. Use both.

A clean result means none of *these* known issues were found. It is not a
guarantee of overall security — notably, prompt injection is assessed as
*posture*, not proven absent, and a native `--deep` audit will catch
config-hardening details agentscan doesn't.

## Usage

```bash
npx @aayushcodebook/agentscan                      # scan auto-detected installs
npx @aayushcodebook/agentscan --path ~/my-agent    # also scan a custom location (repeatable)
npx @aayushcodebook/agentscan --json               # full findings + score + framework tags (JSON)
npx @aayushcodebook/agentscan --sarif              # SARIF 2.1.0 for GitHub code scanning / CI
npx @aayushcodebook/agentscan --quiet              # one-line graded verdict
npx @aayushcodebook/agentscan --update-feed        # refresh blocklist + CVE advisory feeds
npx @aayushcodebook/agentscan --help
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | all green (or no agent found) |
| `1` | warnings only — review recommended |
| `2` | critical issues — fix now |
| `3` | scanner error |

Useful in CI: `npx @aayushcodebook/agentscan --quiet || echo "agent needs attention"`.

## Privacy

agentscan reads local files and lists local sockets to produce the report. It
makes **no network calls** and uploads nothing. The malicious-skill blocklist
ships offline inside the package. You can confirm all of this by reading
`src/` — it's a few hundred lines of plain Node with no third-party packages.

## Supported agents

Layouts in `src/data/targets.js` are taken from each project's official docs:

| Agent | Config | Default port | Bind setting | Extensions |
|-------|--------|--------------|--------------|------------|
| **OpenClaw** | `~/.openclaw/openclaw.json` (JSON5), `~/.openclaw/.env`; legacy `~/.clawdbot/` | `18789` | `gateway.bind`: `loopback` (safe) / `lan` / `tailnet` / `custom` | skills (`SKILL.md`) + plugins (`openclaw.plugin.json`) |
| **Hermes Agent** | `~/.hermes/config.yaml`, `~/.hermes/.env` | `8642` API, `9119` dashboard | `API_SERVER_HOST` env var (`127.0.0.1` safe, `0.0.0.0` exposed) | skills (`SKILL.md`, nested by category) |

Adding another agent is one entry in `src/data/targets.js` (its config paths,
default ports, bind model, and skill directory).

## Updating the threat feed

The bundled malicious-skill blocklist + CVE advisories are a *floor*. Refresh
them without upgrading the package:

```bash
agentscan --update-feed
agentscan --update-feed --feed-url https://your-mirror/blocklist.json
```

Trust guarantees (see `src/feed.js`):

- A **scan makes zero network calls** — it reads the bundled list or a feed you
  explicitly fetched earlier, whichever is newer. `--update-feed` is the only
  command that touches the network.
- The bundled version is a **downgrade floor**: a stale or tampered (e.g.
  emptied) cache is refused, so detection can't be silently weakened.
- A fetch failure **falls back to the bundle** and exits non-zero.

## Contributing

Issues and PRs welcome — especially new agent definitions (`src/data/targets.js`),
blocklist/CVE entries, and false-positive reports. The whole tool is dependency-free
and meant to be read end-to-end; `node test/run.js` runs the suite.

## License

MIT.
