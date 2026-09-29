#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Post-release plugin install smoke — run after promoting dev -> main.
#
# Exercises both real Claude Code journeys in throwaway scratch config dirs,
# never touching your live install:
#   Leg 1 (clean):   add the COMMUNITY marketplace (open-agent-ai-security/plugins,
#                    whose Raffkin entry pins this repo's main) + plugin install.
#                    This is the documented install path, end to end over the network.
#   Leg 2 (upgrade): install the PRIOR release, then marketplace update +
#                    plugin update to the current one — the re-run path (#43). Since the
#                    in-repo marketplace was retired (#58 hard cutover), this
#                    leg fabricates a minimal same-named marketplace manifest
#                    inside a throwaway worktree to make the version rewind
#                    locally controllable.
#
# Raffkin has no tags, so "releases" are resolved from git history:
#   current = origin/main@HEAD
#   prior   = the commit just before the last change to plugin.json on main
#             (i.e. the previous version), overridable as $1.
#
# Usage: scripts/release/plugin-smoke.sh [prior-ref]
# Run from anywhere inside the repo. Requires: git, python3, claude.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
# Identity from the generated include (see plugin/gen_identity.py) — a re-keyed payload smokes under its own key.
. "${REPO_ROOT}/plugin/identity.sh"
PLUGIN="${RAFFKIN_ID_NAME}"
MARKETPLACE="${RAFFKIN_ID_MARKETPLACE_NAME}"
MARKETPLACE_REPO="${RAFFKIN_ID_MARKETPLACE_REPO}"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/raffkin-smoke.XXXXXX")"
WT_CURRENT="${SCRATCH}/wt-current"
WT_UPGRADE="${SCRATCH}/wt-upgrade"

cleanup() {
  git -C "${REPO_ROOT}" worktree remove --force "${WT_CURRENT}" 2>/dev/null || true
  git -C "${REPO_ROOT}" worktree remove --force "${WT_UPGRADE}" 2>/dev/null || true
  rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# Read a worktree's plugin version, from whichever layout that ref carries. The PRIOR ref is
# routinely pre-#29 — on the first run after this restructure promotes, prior IS the last
# root-layout release — and hardcoding the plugin/ path made that a FileNotFoundError that killed
# the whole smoke run under set -e. Probe, don't assume. A genuinely missing manifest must still be
# a hard error (python raises, set -e stops us), never an empty version: that would sail through the
# current-vs-prior equality check below and silently smoke-test nothing.
version_at() {  # version_at <dir>
  local manifest="$1/plugin/.claude-plugin/plugin.json"
  if [ ! -f "$manifest" ]; then manifest="$1/.claude-plugin/plugin.json"; fi
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$manifest"
}

installed_version() {  # installed_version <config-dir>
  CLAUDE_CONFIG_DIR="$1" claude plugin list --json 2>/dev/null | python3 -c '
import json, sys
plugins = json.load(sys.stdin)
print(next((p.get("version") or "" for p in plugins
            if p.get("id") == "'"${PLUGIN}@${MARKETPLACE}"'"), ""))'
}

assert_version() {  # assert_version <leg> <config-dir> <expected>
  local got
  got="$(installed_version "$2")"
  if [ "${got}" = "$3" ]; then
    echo "  ok: ${1} — installed version ${got}"
  else
    echo "  FAIL: ${1} — expected version ${3}, got '${got:-<not installed>}'" >&2
    exit 1
  fi
}

assert_loads() {  # assert_loads <leg> <config-dir>
  # A plugin that installs is not a plugin that LOADS. 0.8.6 shipped to both catalogs declaring
  # hooks/hooks.json in its manifest, a path the host already auto-loads; the loader saw one file twice
  # and failed the entire plugin -- gate, three skills and the MCP server -- while `plugin install`
  # reported success and `enabled` stayed true (#197).
  #
  # `plugin list --json` carries the failure in `errors[]` beside `"enabled": true`, so the check is
  # deterministic: a non-empty errors array for our plugin fails the leg, whatever the text says.
  local js
  js="$(CLAUDE_CONFIG_DIR="$2" claude plugin list --json 2>/dev/null)" || true
  printf '%s' "${js}" | PLUGIN_ID="${PLUGIN}@${MARKETPLACE}" LEG="$1" python3 -c '
import json, os, sys
leg, pid = os.environ["LEG"], os.environ["PLUGIN_ID"]
try:
    plugins = json.load(sys.stdin)
except Exception as e:
    print(f"  FAIL: {leg} - could not read `plugin list --json` ({e})", file=sys.stderr); raise SystemExit(1)
me = next((p for p in plugins if p.get("id") == pid), None)
if me is None:
    print(f"  FAIL: {leg} - {pid} is not installed", file=sys.stderr); raise SystemExit(1)
errs = me.get("errors") or []
if errs:
    print(f"  FAIL: {leg} - installed but did not load:", file=sys.stderr)
    for e in errs[:3]:
        print(f"    {str(e)[:200]}", file=sys.stderr)
    raise SystemExit(1)
print(f"  ok: {leg} - plugin loaded, no errors reported")
' || return 1   # return, not exit: the positive control calls this inside an `if` and needs the false, not the script's death
}

assert_load_check_works() {  # assert_load_check_works <config-dir> <payload-dir>
  # Positive control: inject a manifest field that makes the plugin fail to load (#197), require
  # assert_loads to FAIL, then restore and require it to pass.
  local manifest="$2/.claude-plugin/plugin.json"
  [ -f "${manifest}" ] || { echo "  FAIL: positive control - no manifest at ${manifest}" >&2; exit 1; }
  cp "${manifest}" "${manifest}.smoke-bak"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["hooks"]="./hooks/hooks.json"; json.dump(d,open(p,"w"))' "${manifest}"
  if assert_loads "positive control (expected to fail)" "$1" >/dev/null 2>&1; then
    mv "${manifest}.smoke-bak" "${manifest}"
    echo "  FAIL: positive control - a manifest declaring hooks/hooks.json still passed assert_loads" >&2
    exit 1
  fi
  mv "${manifest}.smoke-bak" "${manifest}"
  echo "  ok: positive control - the load check fails a plugin that cannot load"
}

git -C "${REPO_ROOT}" fetch origin --quiet
CURRENT_SHA="$(git -C "${REPO_ROOT}" rev-parse origin/main)"
LAST_BUMP="$(git -C "${REPO_ROOT}" log -1 --follow --format=%H origin/main -- plugin/.claude-plugin/plugin.json)"
PRIOR_REF="${1:-${LAST_BUMP}^}"
PRIOR_SHA="$(git -C "${REPO_ROOT}" rev-parse "${PRIOR_REF}")"

git -C "${REPO_ROOT}" worktree add --detach --quiet "${WT_CURRENT}" "${CURRENT_SHA}"
git -C "${REPO_ROOT}" worktree add --detach --quiet "${WT_UPGRADE}" "${PRIOR_SHA}"

CURRENT_VER="$(version_at "${WT_CURRENT}")"
PRIOR_VER="$(version_at "${WT_UPGRADE}")"
echo "smoke: current ${CURRENT_VER} (origin/main ${CURRENT_SHA:0:7}), prior ${PRIOR_VER} (${PRIOR_SHA:0:7})"
if [ "${CURRENT_VER}" = "${PRIOR_VER}" ]; then
  echo "  FAIL: current and prior resolve to the same version (${CURRENT_VER}) — pass a prior-ref explicitly" >&2
  exit 1
fi

# Write a minimal marketplace manifest into a worktree so it can be added as a
# local marketplace under the community marketplace's name. Needed for the
# upgrade leg (rewindable source) and for worktrees at refs after the in-repo
# marketplace.json was retired (#58). Re-fabricated after every checkout: when
# a checkout crosses the cutover boundary (prior ref tracks the path, target
# ref doesn't), git wants to delete the tracked copy and refuses over our
# untracked one — hence `checkout -f` at the version flip, which discards
# whatever is in the way before we immediately re-assert our manifest.
fabricate_marketplace() {  # fabricate_marketplace <worktree>
  # Point at the subdirectory THIS ref actually ships from: post-#29 refs serve ./plugin, older
  # ones serve the worktree root. Resolved per call, not once — the upgrade leg fabricates twice
  # against the same worktree, straddling the checkout that crosses the restructure boundary.
  local src="./"
  if [ -d "$1/plugin" ]; then src="./plugin"; fi
  mkdir -p "$1/.claude-plugin"
  python3 - "$1" "$src" "$MARKETPLACE" "$PLUGIN" <<'PY'
import json, sys
json.dump({"name": sys.argv[3],
           "owner": {"name": "Open Agent AI Security",
                     "url": "https://github.com/open-agent-ai-security"},
           "plugins": [{"name": sys.argv[4], "source": sys.argv[2]}]},
          open(sys.argv[1] + "/.claude-plugin/marketplace.json", "w"))
PY
}

echo "leg 1: clean install of ${CURRENT_VER} from the community marketplace (${MARKETPLACE_REPO})"
CFG1="${SCRATCH}/config-clean"; mkdir -p "${CFG1}"
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "clean install" "${CFG1}" "${CURRENT_VER}"
assert_loads "clean install" "${CFG1}"
assert_load_check_works "${CFG1}" "$(CLAUDE_CONFIG_DIR="${CFG1}" claude plugin list --json 2>/dev/null | python3 -c 'import json,sys;print(next((p["installPath"] for p in json.load(sys.stdin) if p.get("id")=="'"${PLUGIN}@${MARKETPLACE}"'"),""))')"

echo "leg 2: upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
CFG2="${SCRATCH}/config-upgrade"; mkdir -p "${CFG2}"
git -C "${WT_UPGRADE}" rm -q --cached .claude-plugin/marketplace.json 2>/dev/null || true  # pre-#58 refs track it; make ours the only copy
fabricate_marketplace "${WT_UPGRADE}"
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace add "${WT_UPGRADE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "prior install" "${CFG2}" "${PRIOR_VER}"
git -C "${WT_UPGRADE}" checkout -f --detach --quiet "${CURRENT_SHA}"   # marketplace dir now serves the new release (-f: see fabricate_marketplace)
fabricate_marketplace "${WT_UPGRADE}"                                  # re-assert ours over whatever the ref carries
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace update "${MARKETPLACE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin update "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "upgrade" "${CFG2}" "${CURRENT_VER}"
assert_loads "upgrade" "${CFG2}"

echo "smoke: PASS — clean ${CURRENT_VER}, upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
