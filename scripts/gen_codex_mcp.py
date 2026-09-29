# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Derive plugin/.mcp.codex.json from the Claude Code permissions snippet.

Raffkin's human-in-the-loop gate is expressed twice, because the two host agents
enforce it in different places:

  Claude Code  settings.snippet.json -> generated from permissions.json, the tier file the bundled
               PreToolUse hook reads (the gate ships ON; the snippet is the hook's fallback), and
               the permissions.allow / ask / deny block published for organizations that push
               the same tiers as host policy.

  Codex        .mcp.codex.json -> the same three tiers as approval modes on the
               plugin-bundled server. Codex reads this straight out of the installed
               plugin, so the gate ships ON — no merge step, no operator action.
               Note: the Exabeam write tools are annotated destructiveHint:true, and
               Codex requires approval for a destructive tool in EVERY mode (refusing it
               when no human is present, incl. under `codex exec`) — so "approve" here is
               intent, not the enforcing lever; Codex gates these regardless. The
               deny -> disabled_tools half IS load-bearing: it removes containment from
               the model's view entirely.

Keeping the two by hand would guarantee drift, and drift in this particular pair is a
safety regression rather than a cosmetic one. So the Codex file is generated from the
Claude one and pinned by tests/test_repo_invariants.py.

Tier mapping:

    allow -> approval_mode "auto"      run without asking
    ask   -> approval_mode "approve"   always require a human
    deny  -> disabled_tools            removed from the tool list entirely; Codex
                                       applies disabled_tools after any allowlist, so
                                       these cannot be re-enabled at runtime

`default_tools_approval_mode` is "approve", which is the one place the Codex gate is
deliberately stricter than the Claude one: a tool the remote server grows that nobody
has classified yet asks a human instead of inheriting a default. Fail-safe, not
fail-open — and it's why we do NOT set `enabled_tools`, which would silently drop an
unclassified tool instead of surfacing it.

Run:  python3 scripts/gen_codex_mcp.py        (writes)
      python3 scripts/gen_codex_mcp.py --check (exits 1 if the file is stale)
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNIPPET = ROOT / "plugin" / "skills" / "soc-investigate" / "settings.snippet.json"
TARGET = ROOT / "plugin" / ".mcp.codex.json"

# Transport. Deliberately NOT shared with .mcp.json: Claude Code expands
# ${CLAUDE_PLUGIN_ROOT} in args, Codex expands nothing but does resolve a relative
# `cwd` against the installed plugin root. Verified against codex-cli 0.146.0.
TRANSPORT = {
    "command": "uv",
    "args": ["run", "--quiet", "--locked", "connector/exabeam-mcp-bridge.py"],
    "cwd": ".",
}


def bare(entries):
    """Claude permission entries are mcp__<server>__<tool>; Codex keys on <tool>."""
    out = []
    for e in entries:
        tool = e.split("__")[-1]
        if tool not in out:
            out.append(tool)
    return out


def build():
    perms = json.loads(SNIPPET.read_text())["permissions"]
    tools = {t: {"approval_mode": "auto"} for t in bare(perms["allow"])}
    tools.update({t: {"approval_mode": "approve"} for t in bare(perms["ask"])})
    return {
        "exabeam": {
            **TRANSPORT,
            "default_tools_approval_mode": "approve",
            "disabled_tools": bare(perms["deny"]),
            "tools": tools,
        }
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed file differs from the derived one")
    args = ap.parse_args()

    want = json.dumps(build(), indent=2) + "\n"
    if args.check:
        have = TARGET.read_text() if TARGET.exists() else ""
        if have != want:
            print("stale: plugin/.mcp.codex.json — run python3 scripts/gen_codex_mcp.py",
                  file=sys.stderr)
            return 1
        print("plugin/.mcp.codex.json is in sync with settings.snippet.json")
        return 0
    TARGET.write_text(want)
    d = json.loads(want)["exabeam"]
    print(f"wrote {TARGET.relative_to(ROOT)} — "
          f"{sum(1 for v in d['tools'].values() if v['approval_mode'] == 'auto')} auto, "
          f"{sum(1 for v in d['tools'].values() if v['approval_mode'] == 'approve')} approve, "
          f"{len(d['disabled_tools'])} disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
