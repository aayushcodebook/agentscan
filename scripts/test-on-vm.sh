#!/usr/bin/env bash
#
# test-on-vm.sh — one-command agentscan tryout for a throwaway VM.
#
# What it does, in order:
#   1. Makes sure a modern Node (>=16) is available (installs one if not).
#   2. Runs agentscan's own test suite (sanity that the tool itself works here).
#   3. Builds a DELIBERATELY-INSECURE sample agent config in a temp dir and
#      scans it, so you can see the scanner light up before trusting it.
#   4. Looks for a REAL OpenClaw/Hermes install and scans that too (if present).
#   5. Cleans up the temp fixture.
#
# Safety: the sample config contains only obviously-FAKE values. This script
# never touches your real agent's files (it scans a real install read-only).
# Intended for a disposable VM — see GO-TO-MARKET.md / the README.
#
# Usage (inside the VM, from anywhere):
#   bash /path/to/agentscan/scripts/test-on-vm.sh
#
# Do NOT use `set -e`: agentscan intentionally exits non-zero when it finds
# problems, and that must not abort the script.
set -uo pipefail

# --- locate agentscan -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAW_ROOT="$(dirname "$SCRIPT_DIR")"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
hr()   { printf '%s\n' "----------------------------------------------------------------"; }
say()  { printf '\n'; bold "==> $*"; }

if [ -f "$CLAW_ROOT/bin/agentscan.js" ]; then
  CLAW=(node "$CLAW_ROOT/bin/agentscan.js")
elif command -v agentscan >/dev/null 2>&1; then
  CLAW=(agentscan)
else
  CLAW=(npx --yes agentscan@latest)
fi

# --- 1. ensure Node >= 16 --------------------------------------------------
node_major() { node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1; }

ensure_node() {
  if command -v node >/dev/null 2>&1 && [ "$(node_major)" -ge 16 ] 2>/dev/null; then
    bold "Node $(node -v) already present."
    return
  fi
  say "Installing Node (>=16)…"
  if command -v snap >/dev/null 2>&1; then
    sudo snap install node --classic --channel=20 && return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    # NodeSource gives a modern Node on Debian/Ubuntu (distro apt is often old).
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - \
      && sudo apt-get install -y nodejs && return
  fi
  echo "Could not auto-install Node. Install Node >=16 manually, then re-run." >&2
  exit 1
}

# --- 2. self-test ----------------------------------------------------------
self_test() {
  if [ -f "$CLAW_ROOT/test/run.js" ]; then
    say "Running agentscan's own test suite (sanity check)…"
    node "$CLAW_ROOT/test/run.js" 2>&1 | grep -E '[0-9]+ passed' | tail -1
  fi
}

# --- 3. insecure sample fixture -------------------------------------------
make_fixture() {
  FIXTURE="$(mktemp -d)"
  mkdir -p "$FIXTURE/.openclaw/skills/clawdhub1"
  cat > "$FIXTURE/.openclaw/openclaw.json" <<'JSON'
{
  // DELIBERATELY INSECURE sample — fake values only.
  gateway: { bind: "lan", port: 18789 },   // exposed beyond localhost, no auth
  dmPolicy: "open",                          // anyone can command it
  allowFrom: ["*"],
  agents: { defaults: { sandbox: { mode: "off" } } },
  channels: { telegram: { botToken: "FAKE" } },
  version: "3.0.0"                            // < 3.1.8 -> ClawJacked CVE
}
JSON
  # Fake-but-pattern-matching key so the plaintext-secret check fires.
  echo 'OPENAI_API_KEY=sk-FAKEfakeFAKE1234567890fakeFAKE1234' > "$FIXTURE/.openclaw/.env"
  chmod 644 "$FIXTURE/.openclaw/.env"        # world-readable on purpose
  # A known-bad ClawHavoc skill name so the malware check fires.
  printf -- '---\nname: clawdhub1\n---\nSample.\n' > "$FIXTURE/.openclaw/skills/clawdhub1/SKILL.md"
}

# --- run -------------------------------------------------------------------
ensure_node
self_test

say "Scanning a DELIBERATELY-INSECURE sample config (should light up red)…"
hr
make_fixture
"${CLAW[@]}" --path "$FIXTURE/.openclaw"
echo "(exit code $? — non-zero is expected here: the sample is intentionally bad)"
rm -rf "$FIXTURE"

say "Looking for a REAL agent install to scan…"
hr
FOUND=0
for d in "$HOME/.openclaw" "$HOME/.clawdbot" "$HOME/.hermes"; do
  if [ -d "$d" ]; then FOUND=1; fi
done

if [ "$FOUND" -eq 1 ]; then
  "${CLAW[@]}"
  echo
  bold "Tip: capture the full result to share/compare:"
  echo "    ${CLAW[*]} --json  > agentscan-report.json"
else
  cat <<'TXT'
No real OpenClaw/Hermes install found in this VM yet.

Install one (in this disposable VM), then re-run this script:
  Hermes:    curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
  OpenClaw:  npm install -g openclaw   &&   openclaw onboard
             (check the official install page for the current command)

Reminder: use DUMMY API keys and do NOT connect real Slack/email/Discord.
Inspect any `curl | bash` installer before running it — that's the exact
ClickFix pattern agentscan flags.
TXT
fi

say "Done."
echo "What to verify: did agentscan (1) FIND the real install, (2) read its real"
echo "config keys, and (3) discover its skills dir? Any unexpected SKIP = a gap"
echo "to report. When finished, destroy the VM (multipass delete / droplet destroy)."
