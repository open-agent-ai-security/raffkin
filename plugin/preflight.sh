#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Raffkin preflight — read-only diagnostics, on any host agent.
#
# Everything the plugin needs to actually work is the same on Claude Code, Codex and Antigravity:
# credentials, a toolchain, and a bridge that can reach the tenant. Only the
# human-in-the-loop gate differs — a bundled hook on Claude Code, approval policy on Codex, and
# nothing of ours on Antigravity — so only the gate check branches.
#
# This script NEVER writes. Not to settings.json, not to config.toml, not to the
# credentials file. Where a gate exists it ships inside the plugin (a PreToolUse hook on Claude
# Code, approval policy on Codex); this stays a mirror, not a hand.
#
# Usage:
#   preflight.sh                       detect the host agent and check everything
#   preflight.sh --platform codex      force a host (claude | codex | antigravity | none)
#   preflight.sh --skip-connectivity   skip the live MCP call
#   preflight.sh --no-color
#
# Exit: 0 when nothing failed, 1 when something did. Warnings do not fail.
#
# install.sh sources this file for the shared checks; sourcing defines functions and reads the
# identity include — it runs no checks. The UI helpers are only defined if the caller has not
# already defined them.

# Identity from identity.sh (GENERATED from identity.json by gen_identity.py; no python3 needed). The same
# RAFFKIN_PLUGIN / RAFFKIN_MARKETPLACE overrides install.sh honors apply here, so a remediation message
# names the key the operator actually installed. Both halves come from the same source or neither does:
# a key stitched from one real half and one guessed half is one no marketplace serves.
_PF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_PF_DIR/identity.sh" ]; then . "$_PF_DIR/identity.sh"; fi
PLUGIN_NAME="${RAFFKIN_PLUGIN:-${RAFFKIN_ID_NAME:-}}"
_PF_MKT="${RAFFKIN_MARKETPLACE:-${RAFFKIN_ID_MARKETPLACE_NAME:-}}"
if [ -n "$PLUGIN_NAME" ] && [ -n "$_PF_MKT" ]; then
  PLUGIN_KEY="${PLUGIN_NAME}@${_PF_MKT}"
else
  PLUGIN_NAME="${PLUGIN_NAME:-plugin}"
  PLUGIN_KEY="<plugin>@<marketplace>  (identity.sh missing — regenerate with python3 $_PF_DIR/gen_identity.py)"
fi
# The product's name as prose uses it, for the handful of user-visible strings this script writes itself.
# Shell text is not rewritten on a re-key — only the docs are — so a literal product name here would ship
# inside a distribution's copy under the upstream's name (review of #306).
PRODUCT_NAME="${RAFFKIN_ID_PRODUCT_NAME:-the plugin}"


# ---- ui (only if the sourcing script has not already provided these) ----
# Palette as a function, not a one-shot assignment: --no-color is parsed inside preflight_main,
# which runs AFTER this file loads, so assigning here only would make the documented flag a no-op
# on a TTY (it silently "worked" whenever stdout was already a pipe). preflight_main re-derives.
_palette() {
  if [ "${USE_COLOR:-1}" = 1 ] && [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
    CYAN=$'\033[1;36m'; GRN=$'\033[1;32m'; YLW=$'\033[1;33m'; RED=$'\033[1;31m'; GRY=$'\033[0;90m'
  else
    BOLD=""; DIM=""; RST=""; CYAN=""; GRN=""; YLW=""; RED=""; GRY=""
  fi
}

if ! declare -F ok >/dev/null 2>&1; then
  _palette
  PASS=0; WARN_N=0; FAIL=0; SUMMARY=()
  ok()   { printf '   %s✓%s %s\n'  "$GRN" "$RST" "$1"; PASS=$((PASS+1)); SUMMARY+=("${GRN}✓${RST} $1"); }
  warn() { printf '   %s!%s %s\n'  "$YLW" "$RST" "$1"; WARN_N=$((WARN_N+1)); SUMMARY+=("${YLW}!${RST} $1"); }
  fail() { printf '   %s✗%s %s\n'  "$RED" "$RST" "$1"; FAIL=$((FAIL+1)); SUMMARY+=("${RED}✗${RST} $1"); }
  skip() { printf '   %s↷ %s%s\n'  "$GRY" "$1" "$RST"; SUMMARY+=("${GRY}↷ $1${RST}"); }
  step() { printf '   %s▸%s %s\n'  "$CYAN" "$RST" "$1"; }
  head2(){ printf '\n%s   %s%s\n' "$BOLD" "$1" "$RST"; }
  hr()   { printf '%s   ────────────────────────────────────────────────────%s\n' "$GRY" "$RST"; }
fi

: "${ENV_FILE:=${EXABEAM_ENV_FILE:-$HOME/.exabeam-mcp.env}}"
: "${CREDS_OK:=0}"

# ---- host detection ----
# Which agent is this install for? Both CLIs can be present on one machine, so an explicit
# --platform always wins; otherwise prefer the one whose plugin cache actually holds Raffkin,
# and fall back to whichever CLI exists.
detect_platform() {
  if [ -n "${RAFFKIN_PLATFORM:-}" ]; then printf '%s' "$RAFFKIN_PLATFORM"; return; fi
  # Where this copy SITS beats which CLIs exist. Antigravity installs a plugin into
  # ~/.gemini/config/plugins/<name>/, so a preflight.sh running from there is an Antigravity install by
  # construction -- no guessing. Without this, a machine that also has Claude Code reported "claude" and
  # then told an Antigravity operator the gate was OFF and to reinstall with `claude plugin install`
  # (review of #306). The match is on the host's own directory layout, not on our plugin name, so it
  # holds for a re-keyed distribution too.
  case "$_PF_DIR/" in
    */.gemini/config/plugins/*) printf 'antigravity'; return ;;
  esac
  local has_claude=0 has_codex=0 has_agy=0
  command -v claude >/dev/null 2>&1 && has_claude=1
  command -v codex  >/dev/null 2>&1 && has_codex=1
  command -v agy    >/dev/null 2>&1 && has_agy=1
  if [ "$has_claude" = 1 ] && [ "$has_codex" = 1 ]; then
    # Both installed — let an actual Raffkin install break the tie.
    if codex mcp get exabeam >/dev/null 2>&1; then printf 'codex'; else printf 'claude'; fi
  elif [ "$has_codex" = 1 ]; then printf 'codex'
  elif [ "$has_claude" = 1 ]; then printf 'claude'
  elif [ "$has_agy" = 1 ]; then printf 'antigravity'
  else printf 'none'; fi
}

# ---- shared checks (identical on every host) ----

# The bridge is launched with `uv run --locked`: its dependencies are pinned by hash in the script lock
# beside it, and uv refuses to start it if that lock is missing or stale instead of resolving without it
# (#248). Script locks need uv 0.5.17; the `--locked` warning on scripts went away in 0.5.23, so that is
# the floor. Below it the bridge does not start at all, which is the safe direction — say so here.
UV_MIN="0.5.23"
uv_version() { uv --version 2>/dev/null | awk '{print $2}'; }
version_ge() {     # version_ge A B: true when A is at least B, numerically per dot-field
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}
check_toolchain() {
  if command -v uv >/dev/null 2>&1; then
    local uvv; uvv="$(uv_version)"
    if [ -n "$uvv" ] && version_ge "$uvv" "$UV_MIN"; then
      ok "uv present — $(uv --version 2>/dev/null)"
    else
      fail "uv ${uvv:-?} is older than ${UV_MIN} — the bundled Exabeam bridge starts with 'uv run --locked' so its hash-pinned dependencies are honored, and that needs uv ${UV_MIN} or newer; upgrade: uv self update (or https://docs.astral.sh/uv/)"
    fi
  else
    warn "uv not found — the bundled Exabeam bridge needs it (${UV_MIN} or newer): https://docs.astral.sh/uv/"
  fi
  if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
      ok "python3 present ($(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null))"
    else
      fail "python3 is older than 3.7 — the bundled dismiss/close gate (hooks/gate.py) cannot run on it, and the hook fails closed (every gated call refused). Install a current python3."
    fi
  else
    # A failure only where the gate needs it. On Claude Code the bundled hook is python3 and nothing else,
    # so this is fatal. On Codex the gate is approval policy and the bridge runs under uv's own interpreter,
    # so a python3-less Codex host is a healthy install and "warnings do not fail" holds (review,
    # 2026-09-05). On Antigravity the hook is the same python3 script, but its command falls back to uv --
    # so python3 alone is not the question, and this branch must not answer it. The gate check below runs
    # the hook for real and is the authority; saying anything stronger here would be guessing at a control
    # (review of #306).
    if [ "${PF_PLATFORM:-}" = claude ]; then
      fail "python3 not found — the bundled dismiss/close gate (hooks/gate.py) cannot execute. The hook is wired to fail closed (every gated call is refused until python3 is on PATH), so install python3: https://www.python.org/downloads/"
    elif [ "${PF_PLATFORM:-}" = antigravity ]; then
      warn "python3 not found — this host runs the same bundled gate (hooks/gate.py), falling back to uv when python3 is absent. The gate line below ran the hook and is the authority on whether it is active; installing python3 removes the dependency on uv for it"
    else
      warn "python3 not found — fine on this host (the gate is approval policy here); on a Claude Code host the bundled hook would need it"
    fi
  fi
}

# The bundled hook, as INSTALLED: the copy Claude Code actually loads (claude plugin list --json), enabled,
# with hooks/hooks.json in it. The plugin copy this script sits in proves nothing about the install --
# a clone with the hook beside an older installed version read "gate ON" (review, 2026-09-05).
# Prints: "on <version> <path>" | "off <version> <path>" (installed copy has no hook) | "none" | "unknown"
# | "failed <version> <path>" followed by the load error on a second line -- the host reports a plugin it
# refused to load under errors[], with enabled still true and the files still on disk, so neither of
# those proves the hook is registered.
installed_hook_state() {
  local json key="$PLUGIN_KEY"
  command -v claude >/dev/null 2>&1 || { printf 'unknown'; return; }
  command -v python3 >/dev/null 2>&1 || { printf 'unknown'; return; }
  json="$(claude plugin list --json 2>/dev/null)" || { printf 'unknown'; return; }
  printf '%s' "$json" | python3 -c '
import json, os, sys
key = sys.argv[1]
try:
    plugins = json.load(sys.stdin)
except Exception:
    print("unknown"); sys.exit(0)
hits = [p for p in plugins if p.get("id") == key and p.get("enabled", True)]
if not hits:
    print("none"); sys.exit(0)
p = hits[0]
path = p.get("installPath") or ""
raw = p.get("errors")
errs = [str(e) for e in (raw if isinstance(raw, list) else ([raw] if raw else [])) if str(e).strip()]
if errs:
    print("failed", p.get("version") or "unknown", path)
    msg = "; ".join(errs).replace("\n", " ")
    print(msg if len(msg) <= 300 else msg[:297] + "...")
    sys.exit(0)
state = "on" if path and os.path.isfile(os.path.join(path, "hooks", "hooks.json")) else "off"
print(state, p.get("version") or "unknown", path)
' "$key" 2>/dev/null || printf 'unknown'
}

# Sets CREDS_OK=1 when the file exists and carries all three keys. Reports the file mode but
# never changes it: 0600 is advice here, exactly as it is in install.sh.
check_credentials() {
  CREDS_OK=0
  if [ ! -f "$ENV_FILE" ]; then
    warn "No credentials yet — create $ENV_FILE with EXABEAM_MCP_URL, EXABEAM_API_KEY and EXABEAM_API_SECRET (chmod 600)"
    return
  fi
  local missing="" k perms
  for k in EXABEAM_MCP_URL EXABEAM_API_KEY EXABEAM_API_SECRET; do
    grep -q "^${k}=" "$ENV_FILE" 2>/dev/null || missing="$missing $k"
  done
  if [ -n "$missing" ]; then
    warn "Credentials file present but missing:$missing"
    return
  fi
  # #174: the bridge refuses to start over any scheme but https (plain http to a loopback host excepted),
  # so say so here, before it is ever started, with the value that needs fixing.
  local url host scheme
  url="$(grep -m1 '^EXABEAM_MCP_URL=' "$ENV_FILE" | cut -d= -f2- | sed -E 's/[[:space:]]+#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
  scheme="$(printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]')"    # the bridge compares schemes case-insensitively (#231)
  case "$scheme" in
    https) ;;
    http)
      host="${url#*://}"; host="${host%%/*}"
      case "$host" in
        \[*\]*) host="${host%%]*}]" ;;          # bracketed IPv6: keep through the closing bracket
        *)       host="${host%%:*}" ;;           # else drop a :port
      esac
      host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"    # the bridge lowercases the host too
      case "$host" in
        localhost|\[::1\]) ;;
        *) if ! printf '%s' "$host" | grep -Eq '^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
             fail "EXABEAM_MCP_URL uses http:// to a non-loopback host (${host}) — the bridge refuses to start rather than send the client id, secret and bearer token in the clear; use https://"
             return
           fi ;;
      esac ;;
    *) fail "EXABEAM_MCP_URL must start with https:// (found: ${url:-<empty>}) — the bridge refuses to start over any other scheme"
       return ;;
  esac
  CREDS_OK=1; ok "Credentials — $ENV_FILE (all keys present, https)"
  perms="$(stat -f '%A' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')"
  [ "$perms" = "600" ] || warn "  $ENV_FILE is mode $perms — consider: chmod 600 $ENV_FILE"
}

# The one check that proves the whole path works: same bridge, same --check, on both hosts.
check_connectivity() {
  local bridge="${BRIDGE:-$SCRIPT_DIR/connector/exabeam-mcp-bridge.py}" out
  if [ "${SKIP_CONN:-0}" = 1 ]; then
    skip "MCP connectivity check skipped (--skip-connectivity)"
  elif [ "$CREDS_OK" = 0 ]; then
    skip "MCP connectivity check skipped — fix the credentials file first (see above)"
  elif ! command -v uv >/dev/null 2>&1; then
    skip "MCP connectivity check skipped — uv not installed"
  elif [ ! -f "$bridge" ]; then
    skip "MCP connectivity check skipped — bridge not found (run from a cloned repo)"
  else
    step "Connecting to Exabeam MCP via the bundled bridge…"
    if out="$(uv run --quiet --locked "$bridge" --check 2>&1)"; then
      ok "Exabeam MCP reachable — ${out##*OK — }"
    else
      warn "Could not reach the Exabeam MCP: $(printf '%s' "$out" | tail -1) — check the region in EXABEAM_MCP_URL first (the slug from your console address), then the key and secret"
    fi
  fi
}

# ---- gate check (the only part that differs by host) ----

# Codex: the gate ships inside the plugin, so this reads the resolved server config. ON means Codex
# resolved both halves — the approve default and the containment deny-list. Codex itself prompts for
# approval for the Exabeam write tools (annotated destructive) in every mode and refuses them when no
# human is present, so the dismiss/close gate needs nothing merged. A missing server reads as "unknown".
# Does any config.toml loosen a per-tool approval mode on a gated write?
#
# `codex mcp get` prints the server's default mode and disabled_tools, but NOT per-tool
# overrides — so an operator who sets ONLY exabeam_update_case to "auto" leaves a server
# that still reports 'default: approve' while dismiss/close runs unattended. Reading the
# resolved server config alone therefore produces a false green on precisely the change
# that matters most, which is the dangerous direction.
#
# This does not resolve TOML — it detects that an override exists and refuses to claim
# green, which is the conservative half of the job and the only half worth doing here. An
# override that TIGHTENS the gate reads as "overridden" too; safe direction, and rare.
# Prints: yes (a gated write's approval_mode is loosened somewhere) | no | unverifiable (a config.toml
# does not parse -- reported as "cannot verify", never as gate ON).
#
# Codex accepts every TOML spelling of the same override -- section header, dotted key, inline table,
# quoted keys -- so the file is PARSED (#139) wherever python3 has tomllib (3.11+), and the tree is walked for any gated tool whose
# approval_mode is anything but approve. The awk scan below is the fallback for a host without it.
codex_write_override() {
  local f verdict
  for f in "${CODEX_HOME:-$HOME/.codex}/config.toml" "./.codex/config.toml"; do
    [ -f "$f" ] || continue
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import tomllib' 2>/dev/null; then
      verdict="$(python3 - "$f" <<'PY' 2>/dev/null
import sys, tomllib
GATED = {"exabeam_update_alert", "exabeam_update_case"}
try:
    with open(sys.argv[1], "rb") as fh:
        cfg = tomllib.load(fh)
except Exception:
    print("unverifiable"); sys.exit(0)
def loosened(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in GATED and isinstance(v, dict):
                mode = v.get("approval_mode")
                if mode is not None and str(mode).strip().lower() != "approve":
                    return True
            if loosened(v):
                return True
    elif isinstance(node, list):
        return any(loosened(x) for x in node)
    return False
print("yes" if loosened(cfg) else "no")
PY
)"
      case "$verdict" in
        yes) printf 'yes'; return ;;
        unverifiable) printf 'unverifiable'; return ;;
        no) continue ;;
      esac
    fi
    # Fallback without tomllib: three TOML spellings say the same thing, and Codex accepts all of them:
    #   [mcp_servers.exabeam.tools.exabeam_update_alert]   approval_mode = "never"     (section header)
    #   [mcp_servers.exabeam]  tools.exabeam_update_alert.approval_mode = "never"      (dotted key)
    #   tools = { exabeam_update_alert = { approval_mode = "never" } }                 (inline table)
    # A line is a loosening when a gated tool is in scope (the enclosing section, a dotted key, or its own
    # inline table, the key quoted or bare) and the approval_mode it carries is anything but approve
    # (either quote style). Inline tables are walked tool by tool inside their own balanced {…}, so
    # neither a sibling's "approve" nor a sibling gated tool can mask a loosened one. Comment lines are
    # not settings.
    awk '
      function loose(s) { return (s ~ /approval_mode/ && s !~ /approval_mode[[:space:]]*=[[:space:]]*["\047]approve["\047]/) }
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*\[/ { sec = $0; next }
      {
        line = $0
        if (line !~ /approval_mode/) next
        if ((sec " " line) !~ /exabeam_update_(alert|case)/) next
        if (line !~ /exabeam_update_(alert|case)["\047]?[[:space:]]*=[[:space:]]*\{/) {   # section or dotted key
          if (loose(line)) { print "loose"; exit }
          next
        }
        s = line                                                                   # inline table(s), key bare or quoted
        while (match(s, /exabeam_update_(alert|case)["\047]?[[:space:]]*=[[:space:]]*\{/)) {
          rest = substr(s, RSTART + RLENGTH); depth = 1; body = ""
          for (i = 1; i <= length(rest) && depth > 0; i++) {
            c = substr(rest, i, 1)
            if (c == "{") depth++; else if (c == "}") depth--
            if (depth > 0) body = body c
          }
          if (loose(body)) { print "loose"; exit }
          s = rest
        }
      }
    ' "$f" | grep -q loose && { printf 'yes'; return; }
  done
  printf 'no'
}

gate_state_codex() {
  local out
  command -v codex >/dev/null 2>&1 || { printf 'unknown'; return; }
  out="$(codex mcp get exabeam 2>/dev/null)" || { printf 'unknown'; return; }
  [ -n "$out" ] || { printf 'unknown'; return; }
  if printf '%s' "$out" | grep -q 'default_tools_approval_mode: *approve' \
     && printf '%s' "$out" | grep -q 'disabled_tools:'; then
    case "$(codex_write_override)" in
      yes) printf 'overridden'; return ;;
      unverifiable) printf 'unverifiable'; return ;;
    esac
    printf 'on'
  else
    printf 'off'
  fi
}

# Lines of `claude mcp list` ("<name>: <command or url> - <status>") whose command/url mentions Exabeam
# but whose NAME does not: the gate is keyed on the server name, so such a registration escapes it
# (Praxen 2026-09-07-004). Reads stdin so it is testable without the CLI.
gate_reach_warnings() {
  awk -F': ' '
    /^[^ ][^:]*: / {
      name = $1; rest = substr($0, length($1) + 3)
      lname = tolower(name); lrest = tolower(rest)
      if (index(lrest, "exabeam") > 0 && index(lname, "exabeam") == 0) print name
    }'
}

check_gate_reach() {
  command -v claude >/dev/null 2>&1 || return 0
  # `claude mcp list` health-checks every approved server, i.e. it STARTS the bridge and reaches Exabeam --
  # exactly what --skip-connectivity promises not to do (#158).
  [ "${SKIP_CONN:-0}" = 1 ] && { skip "Gate-reach check skipped (--skip-connectivity: 'claude mcp list' would start every registered MCP server)"; return 0; }
  local missed
  # `claude mcp list` exits non-zero when ANY registered server fails its health check -- an ordinary state
  # on a working machine -- and under `set -euo pipefail` that status would abort the whole Governance
  # section before a single gate verdict printed (automated review of #158). The listing it did print is
  # still what we need; the status is not.
  missed="$(claude mcp list 2>/dev/null | gate_reach_warnings | tr '\n' ' ')" || true
  [ -n "$missed" ] && warn "An Exabeam MCP server is registered under a name the gate does not reach: ${missed}— the hook keys on the server NAME; register it as 'exabeam' (claude mcp add exabeam …)"
  return 0
}

check_gate() {
  local platform="$1" state
  case "$platform" in
    antigravity)
      # Antigravity reads a plugin's hooks from hooks.json at the plugin ROOT and honours {"decision":
      # "deny"} as a hard block, so the bundled gate runs here. What this branch must NOT do is report it
      # from the file's existence: "0 HOOK MISS" meant nothing on the red team's hook leg precisely
      # because nobody had made the control answer. So the gate is EXERCISED -- fed a containment call on
      # stdin exactly as the host would, and believed only if it denies it.
      local root hookfile runner pyc verdict spec matcher cmd
      root="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
      hookfile="$root/hooks.json"
      runner=""; pyc=""
      command -v python3 >/dev/null 2>&1 && { runner="python3"; pyc="python3"; }
      # uv brings its own Python and the connector already needs it, so it is the fallback the hook itself
      # falls back to; neither present means the bridge cannot start either.
      [ -z "$runner" ] && command -v uv >/dev/null 2>&1 && {
        runner="uv run --quiet --no-project"; pyc="uv run --quiet --no-project python"; }
      if [ ! -f "$hookfile" ]; then
        fail "Gate is OFF — no hooks.json at the plugin root (${root}). Antigravity reads a plugin's hooks from there and nowhere else, so ${PRODUCT_NAME}'s deny tier, ask tier and write budget are not in force; reinstall the plugin"
      elif ! grep -q '"PreToolUse"' "$hookfile" 2>/dev/null; then
        fail "Gate is OFF — ${hookfile} declares no PreToolUse handler, so nothing is consulted before an Exabeam write; reinstall the plugin"
      elif [ -z "$runner" ]; then
        fail "Gate is OFF — neither 'python3' nor 'uv' is on PATH, so the hook cannot start and the shell fallback answers instead. That fallback refuses EVERY Exabeam call, reads included: containment is still never executed, but there is no ask tier and no write budget, and ${PRODUCT_NAME} cannot work a case in this state. Install uv (https://docs.astral.sh/uv/) — the Exabeam connector needs it too"
      else
        # Read the hook the way the HOST reads it, then run exactly what it says. The earlier version
        # invoked gate.py itself and only grepped for "PreToolUse", so it reported the gate ON with the
        # command pointing at a missing script and with a matcher (^run_command$) the host would never
        # fire on. That proves the decision function and leaves the wiring untested -- the same "0 HOOK
        # MISS" shape one layer up. Review verified all three false passes.
        spec="$($pyc -c '
import json, re, sys
h = json.load(open(sys.argv[1]))
keys = [k for k in h if k.endswith("-gate")] or list(h)
g = h[keys[0]]["PreToolUse"][0]
# call_mcp_tool is the step name a REAL dispatched MCP call arrives under (captured 2026-10-22);
# mcp_tool is the one the host docs imply. A matcher catching only the documented name would never
# fire on a live call, so the live name is the one that must match. (No apostrophes in here: this
# program is a single-quoted shell word and one would end it.)
print("MATCH" if re.search(g["matcher"], "call_mcp_tool") else "NOMATCH")
print(g["hooks"][0]["command"])
' "$hookfile" 2>/dev/null)" || true
        matcher="$(printf '%s' "$spec" | sed -n 1p)"
        cmd="$(printf '%s' "$spec" | sed -n '2,$p')"
        if [ -z "$cmd" ]; then
          fail "Gate is OFF — ${hookfile} has no runnable PreToolUse command for this plugin, so the host has nothing to consult before an Exabeam write; reinstall the plugin"
          return 0
        fi
        if [ "$matcher" != "MATCH" ]; then
          fail "Gate is OFF — the PreToolUse matcher in ${hookfile} does not match 'call_mcp_tool', the step type a dispatched MCP call actually arrives under on this host. A matcher that misses it is never fired, so the gate is never asked; reinstall the plugin"
          return 0
        fi
        # RAFFKIN_GATE_LOG=off: a probe must not forge a decision in the analyst's audit trail. cwd is the
        # directory holding hooks.json, which is what this host sets for a hook command.
        # The probe is in the shape the host really sends -- PascalCase keys beside the server, the
        # dispatcher as the step name -- not the documented camelCase one. Probing with the documented
        # shape is how a gate that cannot read live calls still passed its own diagnostic.
        verdict="$(printf '%s' '{"conversationId":"preflight","stepIdx":0,"toolCall":{"name":"call_mcp_tool","args":{"ServerName":"'"${RAFFKIN_ID_NAME:-raffkin}"'_'"${RAFFKIN_ID_MCP_SERVER:-exabeam}"'","ToolName":"exabeam_isolate_host","Arguments":{"arg0":{}}}}}' \
          | ( cd "$root" && RAFFKIN_GATE_LOG=off sh -c "$cmd" ) 2>/dev/null | tr -d ' \n')" || true
        # Spaces are stripped so one pattern matches whatever spacing the JSON came with, which is why
        # the reason fragments below are run together.
        case "$verdict" in
          *'"decision":"deny"'*couldnotrun*)
            # The shell fallback refuses everything on our server, reads included: no ask tier, no write
            # budget. It is the right failure direction and it is NOT the gate, so reporting it as one
            # would be the false pass review found after the fallback was added.
            fail "Gate CANNOT RUN — ${hookfile} is wired correctly, but neither python3 nor uv could execute hooks/gate.py, so the hook answered with its last-resort refusal. Every Exabeam call is refused, reads included: there is no ask tier and no write budget. Check that hooks/gate.py exists in this install and that python3 or uv is on the PATH the host launches hooks with" ;;
          *'"decision":"deny"'*containmentaction*)
            # The command refuses containment. One thing is still unproven from in here: whether the HOST
            # has this copy registered at all. agy can answer that without a session.
            if command -v agy >/dev/null 2>&1; then
              local listing
              # Does the HOST have THIS copy registered, with the gate among its hooks? `path` in the
              # listing is what makes the difference between "these files are fine" and "the agent you
              # are about to run will consult them" -- the gap review found when preflight passed from a
              # clone the host had never been told about.
              listing="$(agy plugin list --json 2>/dev/null | $pyc -c '
import json, os, sys
root = os.path.realpath(sys.argv[1])
gate = sys.argv[2] + "-gate"
try:
    rows = json.load(sys.stdin)
except Exception:
    print("UNREADABLE"); raise SystemExit(0)
here = [r for r in rows if os.path.realpath(r.get("path") or "") == root]
if here:
    r = here[0]
    if not r.get("enabled"):
        print("DISABLED")
    elif gate in (r.get("hooks") or []):
        print("HERE")
    else:
        print("NOHOOK")
else:
    named = [r for r in rows if gate in (r.get("hooks") or [])]
    print("ELSEWHERE " + (named[0].get("path") or "?") if named else "NOTLISTED")
' "$root" "${RAFFKIN_ID_NAME:-raffkin}" 2>/dev/null)" || true
              case "$listing" in
                HERE)
                  ok "Human-in-the-loop gate ON via the bundled hook at ${hookfile} — ran the host's own PreToolUse command, asked it to isolate a host, and it refused. Denies containment, asks on dismiss/close. ${AGY_NAME:-Antigravity} also reports the hook registered as '${RAFFKIN_ID_NAME:-raffkin}-gate'. The deny holds even under --dangerously-skip-permissions; the ask does not, so run attended" ;;
                DISABLED)
                  fail "Gate is OFF — the host has this plugin installed but DISABLED, so none of its hooks run and the deny tier is not in force. Run 'agy plugin enable ${RAFFKIN_ID_NAME:-raffkin}'" ;;
                NOHOOK)
                  fail "Gate is OFF — the host lists this install but names no '${RAFFKIN_ID_NAME:-raffkin}-gate' hook for it, so hooks.json was not picked up at install time. The files here refuse containment; the host is not consulting them. Reinstall with 'agy plugin install'" ;;
                ELSEWHERE*)
                  warn "Gate verified for THIS copy, but the host is running a different one (${listing#ELSEWHERE }). These files refuse containment; the agent will consult that install instead, which this check has not exercised. Re-run preflight from there, or reinstall from this directory" ;;
                NOTLISTED)
                  warn "Gate verified for this copy, but the host does not list it at all — the agent will not load this directory. Install it with 'agy plugin install', or run this script from the installed copy under ~/.gemini/config/plugins/" ;;
                *)
                  warn "Human-in-the-loop gate ON for this copy — ran the host's own PreToolUse command and it refused a containment call. Could not read 'agy plugin list --json', so this verifies the plugin, not the installation" ;;
              esac
            else
              ok "Human-in-the-loop gate ON via the bundled hook at ${hookfile} — ran the host's own PreToolUse command, asked it to isolate a host, and it refused. Denies containment, asks on dismiss/close. The deny holds even under --dangerously-skip-permissions; the ask does not, so run attended"
            fi ;;
          "")
            fail "Gate is OFF — the hook produced no decision when handed a containment call (ran: ${runner}). No decision is read as no objection here; run '$runner \"$root/hooks/gate.py\" --antigravity' by hand to see the error" ;;
          *'"decision":"deny"'*)
            fail "Gate refused the containment call, but not with the gate's own reason — the hook answered ${verdict}. ${PRODUCT_NAME} cannot confirm that its permission tiers are what refused this, rather than a fallback refusing everything; treat the ask tier and the write budget as unverified on this install" ;;
          *)
            fail "Gate is NOT refusing containment — handed an isolate-host call, the hook answered ${verdict}. ${PRODUCT_NAME} never executes containment, so this is a broken gate, not a configuration choice" ;;
        esac
      fi ;;
    codex)
      state="$(gate_state_codex)"
      case "$state" in
        on)  ok "Human-in-the-loop gate ON — containment disabled by the plugin; Codex requires approval for the destructive write tools and refuses them with no human present" ;;
        unverifiable)
             warn "Cannot verify the gate — a config.toml does not parse as TOML, so per-tool overrides on update_alert/update_case cannot be read; fix the file (codex would reject it too)" ;;
        overridden)
             fail "Gate WEAKENED by local config — a config.toml sets a per-tool approval_mode on update_alert/update_case; dismiss/close may run unattended" ;;
        off) fail "Gate is not active on the resolved Exabeam server — reinstall: codex plugin add ${PLUGIN_KEY}" ;;
        *)   warn "Cannot verify the gate — no 'exabeam' server resolved (is the plugin installed and enabled?)" ;;
      esac ;;
    claude)
      check_gate_reach
      local hook hstate hver hpath herr
      hook="$(installed_hook_state)"; herr="${hook#*$'\n'}"; [ "$herr" = "$hook" ] && herr=""; hook="${hook%%$'\n'*}"
      hstate="${hook%% *}"; hver="$(printf '%s' "$hook" | awk '{print $2}')"; hpath="${hook#* * }"
      case "$hstate" in
        on)     ok "Human-in-the-loop gate ON via the bundled hook in the INSTALLED plugin (${hver} at ${hpath}) — asks on dismiss/close, denies containment, holds even under --dangerously-skip-permissions" ;;
        failed) fail "Gate is OFF — the installed plugin (${hver} at ${hpath}) FAILED TO LOAD: ${herr}. Nothing is registered (no hook, no MCP server); update the plugin (claude plugin update ${PLUGIN_KEY}) and restart, then check 'claude plugin list'" ;;
        off)    fail "Gate is OFF — the installed plugin (${hver} at ${hpath}) predates the bundled hook; update it (claude plugin update ${PLUGIN_KEY}) and restart" ;;
        none)   fail "Gate is OFF — the plugin is not installed or not enabled for Claude Code (${PLUGIN_KEY}); install it (claude plugin install ${PLUGIN_KEY})" ;;
        *)      if [ -f "${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/hooks/hooks.json" ]; then
                  warn "Cannot verify the installed plugin (needs the claude CLI with 'plugin list --json' and python3). This plugin copy carries the bundled hook, but only the INSTALLED copy gates — check 'claude plugin list'"
                else
                  fail "Gate is OFF — no bundled hook in this plugin copy and the install cannot be verified; reinstall the plugin (claude plugin install ${PLUGIN_KEY})"
                fi ;;
      esac ;;
    *)
      skip "Gate check skipped — no host agent detected" ;;
  esac
}

# ---- standalone entry point ----

preflight_main() {
  local platform=""
  # A while/shift loop, not `for arg in "$@"`: `--platform codex` needs to consume its value,
  # and a `shift` inside a for-loop does not advance the loop variable — the value came back
  # round as an unknown option.
  while [ $# -gt 0 ]; do
    case "$1" in
      --platform=*) platform="${1#*=}" ;;
      --platform)   shift; platform="${1:-}"
                    [ -n "$platform" ] || { printf '--platform needs a value (claude|codex|antigravity|none)\n' >&2; return 2; } ;;
      --skip-connectivity) SKIP_CONN=1 ;;
      --no-color) USE_COLOR=0 ;;
      -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; return 0 ;;
      *) printf 'unknown option: %s (try --help)\n' "$1" >&2; return 2 ;;
    esac
    shift
  done
  case "${platform:-auto}" in
    claude|codex|antigravity|none|auto) ;;
    *) printf 'unknown platform: %s (want claude|codex|antigravity|none)\n' "$platform" >&2; return 2 ;;
  esac
  [ "$platform" = "auto" ] && platform=""
  [ -n "$platform" ] || platform="$(detect_platform)"
  PF_PLATFORM="$platform"
  _palette          # re-derive now that --no-color has actually been parsed

  printf '\n%s   %s preflight%s  %s(read-only — nothing is written)%s\n' "$BOLD" "$PLUGIN_NAME" "$RST" "$DIM" "$RST"

  head2 "Host agent"
  case "$platform" in
    claude) ok "Claude Code — $(claude --version 2>/dev/null | head -1)" ;;
    codex)  ok "OpenAI Codex — $(codex --version 2>/dev/null | head -1)" ;;
    antigravity)
            if command -v agy >/dev/null 2>&1; then ok "Google Antigravity — $(agy --version 2>/dev/null | head -1)"
            else warn "Google Antigravity CLI ('agy') not found on PATH — the checks below still apply to the installed plugin"; fi ;;
    *)      warn "No host agent CLI found (looked for 'claude', 'codex' and 'agy')" ;;
  esac

  head2 "Toolchain";    check_toolchain
  head2 "Credentials";  check_credentials
  head2 "Connectivity"; check_connectivity
  head2 "Governance";   check_gate "$platform"

  hr
  printf '\n%s   Summary%s   %s%d ok%s · %s%d warn%s · %s%d fail%s\n\n' \
    "$BOLD" "$RST" "$GRN" "$PASS" "$RST" "$YLW" "$WARN_N" "$RST" "$RED" "$FAIL" "$RST"
  local line; for line in "${SUMMARY[@]}"; do printf '     %b\n' "$line"; done
  printf '\n'
  [ "$FAIL" -gt 0 ] && return 1 || return 0
}

# Run only when executed directly; sourcing defines the checks and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -euo pipefail
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  preflight_main "$@"
fi
