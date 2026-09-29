# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the settings merger (scripts/merge_permissions.py — kept in the repo for organizations that push
the tiers as host policy; not part of the install path since #226).

This module writes to the operator's real ~/.claude/settings.json, so the failure modes
that matter are not "did it merge" but "what did it do to everything it wasn't asked to
touch". Each test below pins one of those: operator rules survive, unknown settings
survive, a conflict writes nothing at all, and a broken input never leaves a half-written
settings.json behind.

Run:  uv run --with pytest pytest -q tests/
"""
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "plugin" / "skills" / "soc-investigate"
SNIPPET = SKILL_DIR / "settings.snippet.json"


def _load_merger():
    spec = importlib.util.spec_from_file_location(
        "merge_permissions", ROOT / "scripts" / "merge_permissions.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mp = _load_merger()

REAL_SNIPPET = json.loads(SNIPPET.read_text())
GATED = {"exabeam_update_alert", "exabeam_update_case"}


# ---------- helpers ----------

def run(settings_path, snippet_path=None, dry_run=False):
    argv = ["--snippet", str(snippet_path or SNIPPET), "--settings", str(settings_path)]
    if dry_run:
        argv.append("--dry-run")
    return mp.main(argv)


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2))
    return path


def backups(tmp_path):
    return sorted(p for p in Path(tmp_path).iterdir() if ".raffkin-backup-" in p.name)


def gate_on(settings_path):
    """The reading preflight's gate check made when the rules were a lock: dismiss/close
    sit specifically in `ask`. Kept so these tests fail for the reason an operator would
    call the merged file wrong."""
    ask = json.loads(Path(settings_path).read_text()).get("permissions", {}).get("ask", [])
    return GATED <= {t.split("__")[-1] for t in ask}


# =====================================================================
# the happy paths
# =====================================================================

def test_creates_settings_when_absent_and_turns_the_gate_on(tmp_path):
    """Fresh install: no settings.json at all. It gets created, and the resulting file
    satisfies the installer's own gate check."""
    target = tmp_path / "settings.json"
    assert run(target) == mp.EXIT_APPLIED
    assert gate_on(target)
    perms = json.loads(target.read_text())["permissions"]
    for tier in ("allow", "ask", "deny"):
        assert perms[tier] == REAL_SNIPPET["permissions"][tier]


def test_no_backup_when_there_was_no_file_to_back_up(tmp_path):
    """Nothing to lose, nothing to preserve — a backup of a nonexistent file would just
    be litter in ~/.claude/."""
    run(tmp_path / "settings.json")
    assert backups(tmp_path) == []


def test_is_idempotent(tmp_path):
    """Re-running must detect the already-merged gate and change nothing — including not
    appending a second copy of every rule."""
    target = tmp_path / "settings.json"
    assert run(target) == mp.EXIT_APPLIED
    before = target.read_text()
    assert run(target) == mp.EXIT_NOOP
    assert target.read_text() == before


def test_topping_up_a_hand_merged_ask_tier(tmp_path):
    """The gap this closes: an operator who hand-copied only the two dismiss/close lines
    has a gate that reads ON while the containment deny-list is entirely missing. A
    merge must still have work to do."""
    target = write_json(tmp_path / "settings.json", {
        "permissions": {"ask": list(REAL_SNIPPET["permissions"]["ask"])}})
    assert gate_on(target)                      # gate already reads ON...
    assert run(target) == mp.EXIT_APPLIED       # ...and there is still work to do
    perms = json.loads(target.read_text())["permissions"]
    assert perms["deny"] == REAL_SNIPPET["permissions"]["deny"]
    assert perms["ask"] == REAL_SNIPPET["permissions"]["ask"]   # not duplicated


# =====================================================================
# what must survive the merge
# =====================================================================

def test_operator_rules_are_preserved_and_never_reordered(tmp_path):
    """Additive union: their rules stay, in their order, with ours appended after."""
    theirs = ["Bash(git status)", "Read(//Users/me/notes/**)"]
    target = write_json(tmp_path / "settings.json", {
        "permissions": {"allow": list(theirs), "deny": ["Bash(rm:*)"]}})
    assert run(target) == mp.EXIT_APPLIED
    perms = json.loads(target.read_text())["permissions"]
    assert perms["allow"][:2] == theirs
    assert perms["deny"][0] == "Bash(rm:*)"
    assert set(REAL_SNIPPET["permissions"]["allow"]) <= set(perms["allow"])


def test_unrelated_settings_are_preserved(tmp_path):
    """We know nothing about most of settings.json and must not touch any of it —
    including keys inside `permissions` that aren't tiers."""
    target = write_json(tmp_path / "settings.json", {
        "model": "claude-opus-5",
        "env": {"FOO": "bar"},
        "hooks": {"PreToolUse": [{"matcher": "Bash"}]},
        "permissions": {"defaultMode": "acceptEdits", "additionalDirectories": ["/srv"]},
    })
    assert run(target) == mp.EXIT_APPLIED
    after = json.loads(target.read_text())
    assert after["model"] == "claude-opus-5"
    assert after["env"] == {"FOO": "bar"}
    assert after["hooks"] == {"PreToolUse": [{"matcher": "Bash"}]}
    assert after["permissions"]["defaultMode"] == "acceptEdits"
    assert after["permissions"]["additionalDirectories"] == ["/srv"]


def test_key_order_is_preserved(tmp_path):
    """json round-tripping must not shuffle the operator's file into some other order."""
    target = write_json(tmp_path / "settings.json",
                        {"zeta": 1, "permissions": {"allow": []}, "alpha": 2})
    run(target)
    assert list(json.loads(target.read_text()).keys())[:3] == ["zeta", "permissions", "alpha"]


def test_file_mode_is_preserved(tmp_path):
    """A 600 settings.json must not widen to the umask default just because we rewrote it
    through a temp file."""
    target = write_json(tmp_path / "settings.json", {"permissions": {}})
    os.chmod(target, 0o600)
    assert run(target) == mp.EXIT_APPLIED
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_backup_holds_the_original_content(tmp_path):
    original = {"permissions": {"allow": ["Bash(ls)"]}, "model": "sonnet"}
    target = write_json(tmp_path / "settings.json", original)
    assert run(target) == mp.EXIT_APPLIED
    made = backups(tmp_path)
    assert len(made) == 1
    assert json.loads(made[0].read_text()) == original


def test_backup_does_not_widen_permissions(tmp_path):
    """The backup is a verbatim copy of the operator's settings; it must not be the thing
    that leaves them world-readable."""
    target = write_json(tmp_path / "settings.json", {"permissions": {}})
    os.chmod(target, 0o600)
    run(target)
    assert stat.S_IMODE(os.stat(backups(tmp_path)[0]).st_mode) == 0o600


# =====================================================================
# refusals — every one of these must write nothing
# =====================================================================

def test_tier_conflict_aborts_without_writing(tmp_path):
    """An operator who put a gated tool in `allow` made a decision about a safety control.
    Moving it for them would override a human; we stop and report instead."""
    gated = REAL_SNIPPET["permissions"]["ask"][0]
    original = {"permissions": {"allow": [gated]}}
    target = write_json(tmp_path / "settings.json", original)
    before = target.read_text()

    assert run(target) == mp.EXIT_CONFLICT
    assert target.read_text() == before
    assert backups(tmp_path) == []   # refused before touching anything


def test_conflict_report_names_the_rule_and_both_tiers(tmp_path, capsys):
    gated = REAL_SNIPPET["permissions"]["ask"][0]
    target = write_json(tmp_path / "settings.json", {"permissions": {"deny": [gated]}})
    run(target)
    err = capsys.readouterr().err
    assert gated in err and "ask" in err and "deny" in err


def test_malformed_settings_is_an_error_not_an_overwrite(tmp_path):
    """The dangerous reading of 'unparseable' is 'empty' — that would silently discard
    every setting the operator has."""
    target = tmp_path / "settings.json"
    target.write_text("{ this is not json")
    assert run(target) == mp.EXIT_ERROR
    assert target.read_text() == "{ this is not json"
    assert backups(tmp_path) == []


@pytest.mark.parametrize("bad", [
    {"permissions": {"allow": "not-a-list"}},
    {"permissions": ["not", "an", "object"]},
    ["not", "an", "object"],
])
def test_wrong_shaped_settings_is_an_error(tmp_path, bad):
    target = write_json(tmp_path / "settings.json", bad)
    before = target.read_text()
    assert run(target) == mp.EXIT_ERROR
    assert target.read_text() == before


def test_missing_snippet_is_an_error(tmp_path):
    target = tmp_path / "settings.json"
    assert run(target, snippet_path=tmp_path / "nope.json") == mp.EXIT_ERROR
    assert not target.exists()


@pytest.mark.parametrize("bad", [
    {},                                              # no permissions block
    {"permissions": {}},                             # no rules at all
    {"permissions": {"ask": [{"tool": "x"}]}},       # not strings
])
def test_wrong_shaped_snippet_is_an_error_not_an_empty_merge(tmp_path, bad):
    """A snippet that parses but carries no usable rules must never read as a green
    no-op — that would report 'gate installed' having installed nothing."""
    snippet = write_json(tmp_path / "snippet.json", bad)
    target = tmp_path / "settings.json"
    assert run(target, snippet_path=snippet) == mp.EXIT_ERROR
    assert not target.exists()


def test_write_failure_restores_from_backup(tmp_path, monkeypatch):
    """Simulate the disk dying mid-write: the operator's settings must come back."""
    original = {"permissions": {"allow": ["Bash(ls)"]}}
    target = write_json(tmp_path / "settings.json", original)

    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(mp.os, "replace", boom)

    assert run(target) == mp.EXIT_ERROR
    assert json.loads(target.read_text()) == original
    assert len(backups(tmp_path)) == 1
    # and no temp file left behind
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".raffkin-settings-")]


# =====================================================================
# --dry-run
# =====================================================================

def test_dry_run_writes_nothing_but_reports_the_additions(tmp_path, capsys):
    """This is the consent surface for the interactive prompt: it must show the operator
    exactly what they're agreeing to, and must not have done it already."""
    target = tmp_path / "settings.json"
    assert run(target, dry_run=True) == mp.EXIT_APPLIED
    assert not target.exists()
    out = capsys.readouterr().out
    for rule in REAL_SNIPPET["permissions"]["ask"]:
        assert rule in out


def test_dry_run_on_an_already_merged_file_reports_no_op(tmp_path):
    target = tmp_path / "settings.json"
    run(target)
    assert run(target, dry_run=True) == mp.EXIT_NOOP


# =====================================================================
# the invariant that ties this module to the shipped gate
# =====================================================================

def test_merging_the_shipped_snippet_satisfies_the_installers_gate_check(tmp_path):
    """After a merge, dismiss/close must sit in `ask`. If the snippet's tiers are ever
    restructured such that this stops holding, the merger is installing something that
    isn't the gate."""
    target = tmp_path / "settings.json"
    assert run(target) == mp.EXIT_APPLIED
    assert gate_on(target)


def test_every_snippet_rule_lands_in_its_declared_tier(tmp_path):
    target = tmp_path / "settings.json"
    run(target)
    perms = json.loads(target.read_text())["permissions"]
    for tier, rules in REAL_SNIPPET["permissions"].items():
        assert set(rules) <= set(perms[tier]), f"{tier} rules did not all land in {tier}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
