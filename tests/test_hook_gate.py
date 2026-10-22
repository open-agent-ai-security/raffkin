# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The bundled PreToolUse gate (plugin/hooks/gate.py): the one control on Claude Code that is active on
install and survives --dangerously-skip-permissions. Pinned here: its decisions per tier, its fail-safe
posture, that it reads the SAME tiers the permission snippet ships, and that the manifest actually
declares it (a hook that isn't declared is a file, not a gate)."""
import json
import os
import pathlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
HOOK = PLUGIN / "hooks" / "gate.py"
HOOKS_JSON = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
SNIPPET = json.loads((PLUGIN / "skills" / "soc-investigate" / "settings.snippet.json").read_text())["permissions"]


import importlib.util
_spec = importlib.util.spec_from_file_location("gate", HOOK)
gate = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(gate)
bare = gate.bare                       # the shipped one, not a copy
NO_DECISION = {"permissionDecision": None}


def run_hook(tool_name, stdin=None, env=None):
    """The end-to-end contract: a subprocess, exactly as Claude Code runs it. Empty stdout is the hook
    asserting nothing (the normal permission flow runs) and is returned as NO_DECISION."""
    e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "RAFFKIN_GATE_LOG": "off",
         "RAFFKIN_GATE_STATE_DIR": os.environ.get("RAFFKIN_TEST_GATE_STATE_DIR", "/nonexistent-raffkin-state"), **(env or {})}
    r = subprocess.run([sys.executable, str(HOOK)], input=stdin if stdin is not None else json.dumps({"tool_name": tool_name}),
                       capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else NO_DECISION


def test_the_hook_ships_and_the_manifest_stays_out_of_it():
    """#197 -- this asserted the opposite until 0.8.6 shipped unloadable to both catalogs.

    Claude Code loads hooks/hooks.json from the standard path on its own. Declaring that same path in the
    manifest makes the loader see one file twice and fail the ENTIRE plugin load, so the gate, the three
    skills and the MCP server all go missing at once -- with nothing but a Status line in
    `claude plugin list` to say so. Shipping the file is what registers the gate.
    """
    pj = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert "hooks" not in pj, "the host auto-loads hooks/hooks.json; naming it too fails the whole load"
    assert (PLUGIN / "hooks" / "hooks.json").is_file() and HOOK.is_file()


def test_matcher_covers_every_way_the_server_can_be_named():
    m = re.compile(HOOKS_JSON["hooks"]["PreToolUse"][0]["matcher"])
    for name in ("mcp__plugin_raffkin_exabeam__exabeam_update_alert",   # bundled, upstream key
                 "mcp__plugin_soc_exabeam__exabeam_update_alert",      # bundled, a vendor catalog's key
                 "mcp__exabeam__exabeam_update_alert",                 # manually wired (#86)
                 "mcp__exabeam-prod__exabeam_update_alert",            # wired by hand under another name
                 "mcp__Exabeam__exabeam_update_alert"):
        assert m.search(name), name
        assert gate.is_ours(name), name
    # Not ^mcp__: that would put every MCP server in the session behind this hook's python3 fail-closed.
    assert not m.search("mcp__github__create_issue") and not gate.is_ours("mcp__github__create_issue"), "must not gate other servers"
    assert not m.search("Bash"), "must not gate built-in tools"


def test_another_servers_tool_gets_no_decision_and_no_record(tmp_path):
    log = tmp_path / "gate.jsonl"
    assert run_hook("mcp__github__create_issue", env={"RAFFKIN_GATE_LOG": str(log)}) == NO_DECISION
    assert not log.exists()


@pytest.mark.parametrize("prefix", ["mcp__plugin_raffkin_exabeam__", "mcp__plugin_soc_exabeam__", "mcp__exabeam__", "mcp__EXABEAM-prod__"])
def test_decisions_match_the_shipped_tiers_under_every_prefix(prefix):
    """Exhaustive, in-process (decide(, bundled=True) is a plain function; the subprocess contract is tested beside it):
    deny and ask apply under EVERY Exabeam-named prefix; allow applies to the bundled bridge only
    (Praxen 2026-09-07-003) — elsewhere an allow-tier tool gets no decision."""
    tiers = gate.load_tiers(PLUGIN)
    name = gate.plugin_name(PLUGIN)
    for tier, expected in (("deny", "deny"), ("ask", "ask")):
        for rule in SNIPPET[tier]:
            decision, reason = gate.decide(prefix + bare(rule), tiers, bundled=gate.is_bundled(prefix + bare(rule), name))
            assert decision == expected, (tier, rule, decision, reason)
    for rule in SNIPPET["allow"]:
        tool = prefix + bare(rule)
        decision, _ = gate.decide(tool, tiers, bundled=gate.is_bundled(tool, name))
        assert decision == ("allow" if prefix == "mcp__plugin_raffkin_exabeam__" else gate.NO_DECISION), (prefix, rule, decision)


def test_the_allow_tier_is_the_bundled_bridges_alone(tmp_path):
    """Praxen 2026-09-07-003: the prompt-free allow used to apply under any server whose name contained
    'exabeam'. Now it is granted to `plugin_<name>_exabeam` only, with <name> read from identity.json --
    so a vendor-keyed copy (soc@exabeam) recognizes ITS bridge, and a manual or third-party server gets
    the operator's own rules for reads while still getting ask/deny."""
    assert run_hook("mcp__plugin_raffkin_exabeam__exabeam_search_alerts")["permissionDecision"] == "allow"
    assert run_hook("mcp__exabeam__exabeam_search_alerts") == NO_DECISION            # manual registration: your rules
    assert run_hook("mcp__exabeam-prod__exabeam_get_case_details") == NO_DECISION
    assert run_hook("mcp__exabeam__exabeam_update_alert")["permissionDecision"] == "ask"     # tightening still reaches it
    assert run_hook("mcp__EXABEAM__exabeam_isolate_host")["permissionDecision"] == "deny"    # any case
    # a vendor catalog's copy: same hook, its own identity.json says "soc"
    import shutil
    vendored = tmp_path / "soc"
    shutil.copytree(PLUGIN, vendored, ignore=shutil.ignore_patterns("__pycache__"))
    ident = json.loads((vendored / "identity.json").read_text()); ident["name"] = "soc"
    (vendored / "identity.json").write_text(json.dumps(ident))
    manifest = vendored / ".claude-plugin" / "plugin.json"
    man = json.loads(manifest.read_text()); man["name"] = "soc"           # gen_identity regenerates it from identity.json
    manifest.write_text(json.dumps(man))
    out = run_hook("mcp__plugin_soc_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out["permissionDecision"] == "allow"
    out = run_hook("mcp__plugin_raffkin_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out == NO_DECISION, "under the vendored copy, the upstream key is not its bridge"
    # an overlaid identity.json that was never regenerated into the manifest: Claude Code builds the prefix
    # from the MANIFEST, so the manifest wins (review of #158) -- the bundled reads keep their allow
    man["name"] = "raffkin"; manifest.write_text(json.dumps(man))
    out = run_hook("mcp__plugin_raffkin_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out["permissionDecision"] == "allow", "the manifest's name is the one Claude Code registered"
    out = run_hook("mcp__plugin_soc_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out == NO_DECISION


def test_matcher_and_hook_agree_on_case(tmp_path):
    """Praxen 2026-09-07-004: the matcher was case-sensitive while the hook lowercased, so the two could
    disagree about which calls are ours. Now both are case-insensitive."""
    m = re.compile(HOOKS_JSON["hooks"]["PreToolUse"][0]["matcher"])
    for name in ("mcp__EXABEAM__exabeam_update_alert", "mcp__Exabeam-Prod__exabeam_update_alert", "mcp__plugin_raffkin_exabeam__x"):
        assert m.search(name) and gate.is_ours(name), name
    assert not m.search("mcp__github__create_issue") and not gate.is_ours("mcp__github__create_issue")


def test_preflight_warns_about_an_exabeam_server_the_gate_does_not_reach():
    import subprocess
    sample = ("Checking MCP server health…\n\n"
              "exabeam: uv run /x/exabeam-mcp-bridge.py - ✓ Connected\n"
              "siem: uv run /x/exabeam-mcp-bridge.py - ✓ Connected\n"
              "claude.ai Gmail: https://gmailmcp.googleapis.com/mcp/v1 - ✓ Connected\n"
              "prod-mcp: https://api.us-west.exabeam.cloud/mcp - ✓ Connected\n")
    r = subprocess.run(["bash", "-c", f"source '{PLUGIN / 'preflight.sh'}'; gate_reach_warnings"], input=sample, capture_output=True, text=True)
    assert r.stdout.split() == ["siem", "prod-mcp"], r.stdout


def test_safe_operations_are_allowed_so_nothing_prompts_with_nothing_merged():
    """The point of the bundled hook: an install needs no permission merge. Reads and the two escalation
    writes are allowed outright (Codex runs the same tools as `auto`); dismiss/close ask; containment denied."""
    assert run_hook("mcp__plugin_raffkin_exabeam__exabeam_search_alerts")["permissionDecision"] == "allow"
    first = json.dumps({"tool_name": "mcp__plugin_raffkin_exabeam__exabeam_create_case_notes", "session_id": "safe-ops"})
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        assert run_hook(None, stdin=first, env={"RAFFKIN_GATE_STATE_DIR": d})["permissionDecision"] == "allow"
    codex = json.loads((PLUGIN / ".mcp.codex.json").read_text())["exabeam"]["tools"]
    auto = {t for t, spec in codex.items() if spec.get("approval_mode") == "auto"}
    assert auto == set(gate.load_tiers(PLUGIN)["allow"]), "Claude's allow tier must be exactly Codex's auto set"


def test_dismiss_and_close_ask_and_containment_denies():
    assert run_hook("mcp__plugin_raffkin_exabeam__exabeam_update_alert")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_raffkin_exabeam__exabeam_update_case")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_raffkin_exabeam__exabeam_isolate_host")["permissionDecision"] == "deny"
    assert run_hook("mcp__plugin_raffkin_exabeam__isolate_host")["permissionDecision"] == "deny"


def test_unclassified_tool_asks_instead_of_inheriting_the_session_default():
    """The Codex map's `default_tools_approval_mode: approve` equivalent — a tool the remote MCP grew
    that nobody classified must not run unattended (exabeam_create_analytics_rule was the live example
    until #143 classified it as deny; the name here is one no release will classify)."""
    out = run_hook("mcp__plugin_raffkin_exabeam__exabeam_brand_new_thing")
    assert out["permissionDecision"] == "ask" and "not classified" in out["permissionDecisionReason"]


def test_never_fails_open():
    assert run_hook("", stdin="not json")["permissionDecision"] == "ask"
    assert run_hook("", stdin="{}")["permissionDecision"] == "ask"
    # tiers unreadable (bogus plugin root) -> ask, never allow
    out = run_hook("mcp__plugin_raffkin_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": "/nonexistent"})
    assert out["permissionDecision"] == "ask" and "could not evaluate" in out["permissionDecisionReason"]


def test_decision_log_is_best_effort(tmp_path):
    log = tmp_path / "gate.jsonl"
    run_hook("mcp__plugin_raffkin_exabeam__exabeam_update_case", env={"RAFFKIN_GATE_LOG": str(log)})
    rec = json.loads(log.read_text().strip().splitlines()[-1])
    assert rec["decision"] == "ask" and rec["tool"].endswith("exabeam_update_case") and "ts" in rec
    # an unwritable log path must not change the decision
    out = run_hook("mcp__plugin_raffkin_exabeam__exabeam_update_case", env={"RAFFKIN_GATE_LOG": "/proc/no/such/dir/x.jsonl"})
    assert out["permissionDecision"] == "ask"



def test_hook_invocation_fails_closed_without_an_interpreter(tmp_path):
    """Praxen PRAX-2026-09-05-001: gate.py never fails open, but a hook whose command errors is
    NON-blocking on the host — so a missing python3 meant no gate. The command now exits 2 (the host's
    blocking code) when the interpreter is missing or the script cannot run."""
    import subprocess, json as _json
    cmd = _json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.endswith("|| exit 2")
    env = {"PATH": str(tmp_path), "CLAUDE_PLUGIN_ROOT": str(PLUGIN)}     # no python3 on PATH
    proc = subprocess.run(["/bin/sh", "-c", cmd], input="{}", capture_output=True, text=True, env=env)
    assert proc.returncode == 2


def test_gate_log_rotates_at_a_ceiling_and_the_off_switch_discloses_itself(tmp_path):
    """Praxen PRAX-2026-09-05-012: the decision log grew without bound and `off` was silent."""
    import subprocess, os
    log = tmp_path / "gate.jsonl"
    log.write_text("x" * 100)
    env = dict(os.environ, RAFFKIN_GATE_LOG=str(log), RAFFKIN_GATE_LOG_MAX_BYTES="50", CLAUDE_PLUGIN_ROOT=str(PLUGIN))
    subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_update_case"}',
                   capture_output=True, text=True, env=env, check=True)
    assert (tmp_path / "gate.jsonl.1").read_text() == "x" * 100, "the full log was not rotated aside"
    assert log.read_text().count("\n") == 1 and "update_case" in log.read_text()
    env["RAFFKIN_GATE_LOG"] = "off"
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_update_case"}',
                          capture_output=True, text=True, env=env, check=True)
    assert "decision log is OFF" in proc.stderr
    assert "permissionDecision" in proc.stdout          # the decision itself is unaffected


def test_the_exact_hook_command_runs_with_python3_present(tmp_path):
    """The command string in hooks.json, run by /bin/sh as the host runs it: exit 0 and one JSON decision."""
    import subprocess, json as _json, os
    cmd = _json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN), RAFFKIN_GATE_LOG="off")
    proc = subprocess.run(["/bin/sh", "-c", cmd], input='{"tool_name":"mcp__exabeam__exabeam_update_alert"}', capture_output=True, text=True, env=env)
    assert proc.returncode == 0
    assert _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_gate_never_crashes_on_a_bad_log_path(tmp_path):
    """A bad RAFFKIN_GATE_LOG ('~nosuchuser') used to raise outside the guard: no JSON, exit 1, and via
    `|| exit 2` every gated call blocked. Logging must never change the decision."""
    import subprocess, json as _json, os
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN), RAFFKIN_GATE_LOG="~nosuchuser_zz/gate.jsonl")
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__plugin_raffkin_exabeam__exabeam_search_alerts"}', capture_output=True, text=True, env=env)
    assert proc.returncode == 0 and _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def _fake_claude(tmp_path, install_path, mcp_list_out="", mcp_list_rc=0, errors=None):
    """A `claude` on PATH whose `plugin list --json` reports Raffkin installed at install_path (or nothing),
    and whose `mcp list` prints `mcp_list_out` and exits `mcp_list_rc` (non-zero = a server failed its
    health check, which is how the real CLI behaves)."""
    bin_ = tmp_path / "bin"; bin_.mkdir(exist_ok=True)
    entry = {"id": "raffkin@open-agent-ai-security", "version": "0.8.6", "scope": "user", "enabled": True,
             "installPath": str(install_path)}
    if errors:
        entry["errors"] = errors                                  # what the host reports for a plugin it refused to load
    body = json.dumps([entry] if install_path else [])
    (bin_ / "mcp_list.txt").write_text(mcp_list_out)
    (bin_ / "claude").write_text(
        "#!/bin/sh\ncase \"$*\" in *'plugin list'*) printf '%s' '" + body + "' ;; "
        f"*'mcp list'*) cat '{bin_ / 'mcp_list.txt'}'; exit {int(mcp_list_rc)} ;; *) exit 0 ;; esac\n")
    (bin_ / "claude").chmod(0o755)
    return str(bin_)


def _preflight(tmp_path, install_path, errors=None):
    import subprocess, os
    env = dict(os.environ, RAFFKIN_PLATFORM="claude", HOME=str(tmp_path),
               PATH=_fake_claude(tmp_path, install_path, errors=errors) + os.pathsep + os.environ.get("PATH", ""))
    return subprocess.run(["bash", str(PLUGIN / "preflight.sh"), "--skip-connectivity"], capture_output=True, text=True, env=env)


def test_preflight_survives_an_unhealthy_mcp_server_and_still_reports_the_gate(tmp_path):
    """Automated review of #158: `claude mcp list` exits non-zero when any registered server fails its
    health check; under `set -euo pipefail` the reach check's unguarded assignment aborted the Governance
    section before any gate verdict printed and preflight exited 1. The listing is still used; the
    status is ignored; the gate verdict and the reach warning both print."""
    import subprocess, os
    listing = ("Checking MCP server health…\n\n"
               "siem: uv run /x/exabeam-mcp-bridge.py - ✗ Failed to connect\n"
               "exabeam: uv run /x/exabeam-mcp-bridge.py - ✓ Connected\n")
    env = dict(os.environ, RAFFKIN_PLATFORM="claude", HOME=str(tmp_path),
               PATH=_fake_claude(tmp_path, PLUGIN, mcp_list_out=listing, mcp_list_rc=1) + os.pathsep + os.environ.get("PATH", ""))
    # no --skip-connectivity: the reach check must run (connectivity itself is skipped: no credentials under HOME)
    proc = subprocess.run(["bash", str(PLUGIN / "preflight.sh")], capture_output=True, text=True, env=env)
    out = proc.stdout + proc.stderr
    assert "gate ON via the bundled hook" in out, out
    assert "registered under a name the gate does not reach: siem" in out, out
    assert proc.returncode == 0, out


def test_preflight_reports_the_installed_hook(tmp_path):
    """Preflight must report the hook ON -- attested from the INSTALLED
    plugin (claude plugin list --json), not from the copy the script sits in (review 2026-09-05) -- and
    must not die on an unbound variable (an earlier review: _PF_DIR under set -u)."""
    proc = _preflight(tmp_path, PLUGIN)                       # installed copy == this tree, which has the hook
    assert "unbound variable" not in proc.stderr + proc.stdout
    assert "gate ON via the bundled hook in the INSTALLED plugin" in proc.stdout, proc.stdout


def test_preflight_never_attests_a_hook_the_installed_plugin_lacks(tmp_path):
    """A clone with the hook beside an installed version without it must read OFF, not ON."""
    old = tmp_path / "installed-old"; old.mkdir()              # an installed copy that predates the hook
    proc = _preflight(tmp_path, old)
    assert "gate ON" not in proc.stdout and "predates the bundled hook" in proc.stdout, proc.stdout
    proc = _preflight(tmp_path, None)                          # not installed at all
    assert "gate ON" not in proc.stdout and "not installed or not enabled" in proc.stdout, proc.stdout


def test_preflight_reports_a_plugin_the_host_refused_to_load_as_gate_off(tmp_path):
    """#226: `enabled: true` and hooks/hooks.json on disk are both true for a plugin the host refused to
    load; only errors[] carries that. Preflight must say the plugin failed to load, name the error, and
    never print a gate ON line."""
    import subprocess, os
    err = "Invalid manifest: hooks must not be declared in plugin.json"
    proc = _preflight(tmp_path, PLUGIN, errors=[err])
    out = proc.stdout + proc.stderr
    assert "gate ON" not in out, out
    assert "FAILED TO LOAD" in out and err in out, out
    assert "unbound variable" not in out
    # and the installer's own governance block, same fake: never a green line, and the checks fail
    env = dict(os.environ, HOME=str(tmp_path), PATH=_fake_claude(tmp_path, PLUGIN, errors=[err]) + os.pathsep + os.environ.get("PATH", ""))
    proc = subprocess.run(["bash", str(PLUGIN / "install.sh"), "--checks-only", "--skip-connectivity", "--no-color"],
                          capture_output=True, text=True, env=env)
    out = proc.stdout + proc.stderr
    assert "gate ON" not in out, out
    assert "FAILED TO LOAD" in out and err in out, out
    assert proc.returncode != 0, "a plugin the host refused to load must fail the installer's checks"
    # and a healthy listing (no errors key at all, which is what the host prints) still reads ON via the hook
    assert "gate ON via the bundled hook in the INSTALLED plugin" in _preflight(tmp_path, PLUGIN).stdout


def test_decision_log_records_the_safe_target_fields_and_never_free_text(tmp_path):
    """A refused dismiss must read as "tried to dismiss alert X as FP" in the gate log (the near-miss is the
    record a SOC wants), while the free-text fields a payload can ride in never enter it."""
    import subprocess, os, json as _json
    log = tmp_path / "gate.jsonl"
    env = dict(os.environ, RAFFKIN_GATE_LOG=str(log), CLAUDE_PLUGIN_ROOT=str(PLUGIN))
    event = {"tool_name": "mcp__plugin_raffkin_exabeam__exabeam_update_alert",
             "tool_input": {"arg1": {"alertId": "4471", "alertStatus": "DISMISSED", "closedReason": "FP",
                                     "alertDescription": "SECRET FREE TEXT " * 20, "supportingReason": "planted note",
                                     "nested": {"caseId": "c-9", "note": "more free text"},
                                     "useCases": ["ua", "x" * 200]}}}
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input=_json.dumps(event),
                          capture_output=True, text=True, env=env, check=True)
    assert _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    rec = _json.loads(log.read_text().splitlines()[-1])
    assert rec["target"]["alertId"] == "4471" and rec["target"]["alertStatus"] == "DISMISSED" and rec["target"]["caseId"] == "c-9"
    assert "alertDescription" not in rec["target"] and "supportingReason" not in rec["target"] and "note" not in rec["target"]
    assert "closedReason" not in rec["target"], "a close reason is free text"
    assert len(rec["target"]["useCases"][1]) == 80, "list values are capped"
    assert "SECRET FREE TEXT" not in log.read_text()
    # a read with no id fields carries no target key at all
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_search_alerts","tool_input":{"arg0":{"filter":"x"}}}',
                          capture_output=True, text=True, env=env, check=True)
    assert "target" not in _json.loads(log.read_text().splitlines()[-1])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_post_tool_hook_records_the_approval_and_nothing_for_reads(tmp_path):
    """#5: the same gate, run as PostToolUse, appends the human's yes: an ask-tier call that ran is recorded
    as `approved` with the safe target fields, a deny-tier call that ran as `ran_despite_deny`, and an
    allow-tier read leaves no line. Never a decision on stdout."""
    import subprocess, os, json as _json
    log = tmp_path / "gate.jsonl"
    env = dict(os.environ, RAFFKIN_GATE_LOG=str(log), CLAUDE_PLUGIN_ROOT=str(PLUGIN))
    def post(tool, tool_input, raw=None, **extra):
        ev = {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": tool_input, "tool_response": [{"type": "text", "text": "ok"}], **extra}
        return subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py"), "--post"], input=raw if raw is not None else _json.dumps(ev),
                              capture_output=True, text=True, env=env, check=True)
    proc = post("mcp__plugin_raffkin_exabeam__exabeam_update_alert", {"arg1": {"alertId": "4471", "alertStatus": "DISMISSED", "note": "SECRET FREE TEXT"}},
                permission_mode="default", tool_use_id="toolu_01ABC")
    assert proc.stdout.strip() == "", "a post-call record is never a decision"
    rec = _json.loads(log.read_text().splitlines()[-1])
    assert rec["decision"] == "approved" and rec["tool"].endswith("exabeam_update_alert")
    assert rec["permission_mode"] == "default" and rec["tool_use_id"] == "toolu_01ABC"
    assert rec["target"] == {"alertId": "4471", "alertStatus": "DISMISSED"} and "SECRET" not in log.read_text()
    # under a mode where nobody could answer, a completed ask-tier call is NOT an approval
    post("mcp__plugin_raffkin_exabeam__exabeam_update_alert", {"arg1": {"alertId": "4471"}}, permission_mode="bypassPermissions")
    assert _json.loads(log.read_text().splitlines()[-1])["decision"] == "ran_unasked"
    # malformed stdin on the post invocation: no stdout, no record (never a decision)
    before = len(log.read_text().splitlines())
    for raw in ("{not json", "[1,2]", ""):
        proc = post("", {}, raw=raw)
        assert proc.stdout.strip() == "" and proc.returncode == 0, raw
    assert len(log.read_text().splitlines()) == before, "a record the hook cannot write is not a decision"
    post("mcp__plugin_raffkin_exabeam__exabeam_disable_analytics_rule", {"arg1": {"ruleId": "r-1"}})
    assert _json.loads(log.read_text().splitlines()[-1])["decision"] == "ran_despite_deny"
    n = len(log.read_text().splitlines())
    post("mcp__plugin_raffkin_exabeam__exabeam_search_alerts", {"arg0": {"filter": "x"}})
    assert len(log.read_text().splitlines()) == n, "an allow-tier read leaves no post-call line"
    post("mcp__other__some_tool", {"x": 1})
    assert len(log.read_text().splitlines()) == n, "another server's tool is not our business"


def test_hooks_json_registers_the_post_tool_hook_on_the_same_matcher():
    """#5: the approval record needs the gate run after the call too, on exactly the tools the gate covers."""
    pre, post = HOOKS_JSON["hooks"]["PreToolUse"][0], HOOKS_JSON["hooks"]["PostToolUse"][0]
    assert post["matcher"] == pre["matcher"]
    assert "gate.py" in post["hooks"][0]["command"] and "--post" in post["hooks"][0]["command"], "the post invocation is decided by the command line, not stdin"
    assert "exit 2" not in post["hooks"][0]["command"], "a failed post-call record must never block"


def _esc(tool, sid, d):
    ev = {"hook_event_name": "PreToolUse", "tool_name": f"mcp__plugin_raffkin_exabeam__exabeam_{tool}", "session_id": sid}
    return run_hook(None, stdin=json.dumps(ev), env={"RAFFKIN_GATE_STATE_DIR": str(d)})


def test_escalation_writes_run_on_a_budget_then_ask(tmp_path):
    """#247 (Matt's design, the threshold from the 2026-09-24 data pass): per session, the first two
    allow-tier writes run without a prompt and the third asks; a second create_case asks at once. The count
    is the hook's own, keyed on the host's session id, so a sweep talked into acting on its queue meets a
    prompt on its third write whatever the prose says. Reads are never counted."""
    d = tmp_path / "state"
    assert _esc("create_case", "s1", d)["permissionDecision"] == "allow"
    assert _esc("create_case_notes", "s1", d)["permissionDecision"] == "allow"
    third = _esc("create_case_notes", "s1", d)
    assert third["permissionDecision"] == "ask" and "escalation write 3" in third["permissionDecisionReason"]
    for _ in range(3):   # reads are free
        ev = {"tool_name": "mcp__plugin_raffkin_exabeam__exabeam_search_alerts", "session_id": "s1"}
        assert run_hook(None, stdin=json.dumps(ev), env={"RAFFKIN_GATE_STATE_DIR": str(d)})["permissionDecision"] == "allow"
    # a second case asks even under the write budget
    assert _esc("create_case", "s2", d)["permissionDecision"] == "allow"
    second_case = _esc("create_case", "s2", d)
    assert second_case["permissionDecision"] == "ask" and "case 2" in second_case["permissionDecisionReason"]
    # notes alone: two run, the third asks
    assert [_esc("create_case_notes", "s3", d)["permissionDecision"] for _ in range(3)] == ["allow", "allow", "ask"]
    # a new session starts fresh
    assert _esc("create_case", "s4", d)["permissionDecision"] == "allow"
    # an ask does not spend the budget: the next write still asks, it does not slip through
    assert _esc("create_case_notes", "s1", d)["permissionDecision"] == "ask"


def test_the_write_budget_never_fails_open(tmp_path):
    """No session id, a malformed one, an unwritable state directory, or a corrupt count file: every one
    of them asks rather than allowing the escalation write."""
    d = tmp_path / "state"
    no_sid = {"tool_name": "mcp__plugin_raffkin_exabeam__exabeam_create_case"}
    assert run_hook(None, stdin=json.dumps(no_sid), env={"RAFFKIN_GATE_STATE_DIR": str(d)})["permissionDecision"] == "ask"
    assert _esc("create_case", "../../etc/passwd", d)["permissionDecision"] == "ask"
    blocked = tmp_path / "not-a-dir"; blocked.write_text("x")
    assert _esc("create_case", "s1", blocked)["permissionDecision"] == "ask"
    d.mkdir(); (d / "s9.json").write_text("{not json")
    assert _esc("create_case", "s9", d)["permissionDecision"] == "ask"


def test_parallel_escalation_writes_cannot_all_slip_under_the_budget(tmp_path):
    """Several create_case_notes in one assistant message reach PreToolUse together; the count is reserved
    under a file lock at decision time, so exactly two are allowed however they interleave."""
    import concurrent.futures
    d = tmp_path / "state"
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        out = list(ex.map(lambda _: _esc("create_case_notes", "par", d)["permissionDecision"], range(6)))
    assert out.count("allow") == 2 and out.count("ask") == 4, out


# ---- the Antigravity envelope (#306) ----
AGY_HOOKS = json.loads((PLUGIN / "hooks.json").read_text())


def agy_step(tool=None, server=None, args_json="{}", step=1, extra=None):
    """An Antigravity PreToolUse payload: the STEP, as that host hands it to a hook. Every MCP call on the
    machine arrives as `mcp_tool` whatever server it came from, with the real name nested inside."""
    inner = {}
    if tool is not None:
        inner["toolName"] = tool
    if args_json is not None:
        inner["argumentsJson"] = args_json
    args = {} if extra is None else dict(extra)
    if server is not None:
        args["serverName"] = server
    if inner:
        args["toolCall"] = inner
    return {"conversationId": "test-conv", "stepIdx": step, "toolCall": {"name": "mcp_tool", "args": args}}


def run_agy(payload, post=False, env=None):
    """The hook as Antigravity runs it: --antigravity, the step on stdin, a JSON object back. `{}` is the
    no-decision answer this host's contract wants, returned as NO_DECISION."""
    e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "RAFFKIN_GATE_LOG": "off",
         "RAFFKIN_GATE_STATE_DIR": os.environ.get("RAFFKIN_TEST_GATE_STATE_DIR", "/nonexistent-raffkin-state"),
         **(env or {})}
    argv = [sys.executable, str(HOOK), "--antigravity"] + (["--post"] if post else [])
    r = subprocess.run(argv, input=json.dumps(payload), capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return out or {"decision": None}


def test_the_antigravity_hook_file_invokes_this_gate_on_every_mcp_call():
    """Its matcher keys on the STEP type, so it cannot select the Exabeam server the way Claude Code's
    regex does -- it has to catch every MCP call and let the gate decide."""
    spec = AGY_HOOKS[json.loads((PLUGIN / "identity.json").read_text())["name"] + "-gate"]
    for event in ("PreToolUse", "PostToolUse"):
        group = spec[event][0]
        assert re.search(group["matcher"], "mcp_tool")
        assert "--antigravity" in group["hooks"][0]["command"]


def test_antigravity_decisions_match_the_shipped_tiers():
    assert run_agy(agy_step("exabeam_isolate_host", "raffkin_exabeam"))["decision"] == "deny"
    assert run_agy(agy_step("exabeam_update_alert", "raffkin_exabeam"))["decision"] == "ask"
    assert run_agy(agy_step("exabeam_get_case_details", "raffkin_exabeam"))["decision"] == "allow"
    # the bundled bridge is `<plugin>_<server>` on this host; a hand-wired `exabeam` is not bundled, so an
    # allow-tier read falls through to the operator's own rules rather than being waved past
    assert run_agy(agy_step("exabeam_get_case_details", "exabeam"))["decision"] is None
    out = run_agy(agy_step("exabeam_brand_new_thing", "raffkin_exabeam"))
    assert out["decision"] == "ask" and "not classified" in out["reason"]


def test_another_servers_call_gets_no_decision_on_antigravity():
    """The matcher sees every MCP call on the machine. Someone else's tools must not collect our verdicts
    -- a gate that prompts on `create_pull_request` gets switched off by the person it annoys."""
    assert run_agy(agy_step("create_pull_request", "github"))["decision"] is None
    assert run_agy(agy_step("list_issues", server=None))["decision"] is None


def test_an_unidentifiable_mcp_step_asks_rather_than_standing_aside():
    """THE fail-open hole on this host, closed deliberately.

    The payload shape is read from the host's documented contract and its proto descriptor, not from a
    live call. If it differs, every Exabeam call becomes a step the gate cannot read -- and treating that
    like another server's call would mean no decision on exactly the tools we promise to gate, on the host
    whose docs say the gate holds. So a step that names NOTHING we can recognise asks. The cost of being
    wrong is a prompt on somebody else's call; the cost the other way is a silent ungated close.
    """
    for payload, why in [
        ({"conversationId": "c", "stepIdx": 1, "toolCall": {"name": "mcp_tool", "args": {}}}, "no args"),
        ({"conversationId": "c", "stepIdx": 1}, "no toolCall at all"),
        ({"conversationId": "c", "toolCall": {"name": "mcp_tool", "args": {"payload": {"invocation": {"identifier": "exabeam_update_alert"}}}}},
         "the shape changed: the tool is in there, under keys we do not read"),
    ]:
        out = run_agy(payload)
        assert out["decision"] == "ask", f"an unreadable step ({why}) got {out!r} instead of asking"
        assert "could not identify" in out["reason"]

    # ...but the POST record is never a verdict: it answers {} and writes nothing
    assert run_agy({"conversationId": "c", "toolCall": {"name": "mcp_tool", "args": {}}}, post=True) == {"decision": None}


def test_the_write_budget_counts_on_antigravity_too(tmp_path):
    """Keyed on conversationId there, since this host has no session_id. Without a counter the budget
    fails open on the one host where nobody has watched the gate work."""
    env = {"RAFFKIN_GATE_STATE_DIR": str(tmp_path)}
    decisions = [run_agy(agy_step("exabeam_create_case_notes", "raffkin_exabeam", step=i), env=env)["decision"]
                 for i in range(3)]
    assert decisions == ["allow", "allow", "ask"], decisions


def test_the_antigravity_hook_refuses_when_no_interpreter_can_run_the_gate(tmp_path):
    """The host-specific half of fail-closed, and the reason it needs its own test.

    On Claude Code a hook command that exits 2 blocks the call, so a missing python3 there is a refusal
    (#296, PRAX-2026-09-05-001). Antigravity reads a `deny` object on stdout and nothing else: its own
    changelog records the permission manager being fixed to handle "empty decision strings returned by
    pre-tool hooks" safely rather than erroring, so a gate that cannot start on this host is a gate that
    goes unheard -- the #212 "0 HOOK MISS" shape again. The command therefore writes the refusal itself.

    Driven through /bin/sh with an empty PATH, which is the real failure (no interpreter), not a mocked one.
    """
    name = json.loads((PLUGIN / "identity.json").read_text())["name"]
    spec = AGY_HOOKS[f"{name}-gate"]
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    step = json.dumps(agy_step(tool="exabeam_search_cases", server="exabeam"))   # an ALLOW-tier call

    def run(event):
        command = spec[event][0]["hooks"][0]["command"]
        r = subprocess.run(["/bin/sh", "-c", command], input=step, capture_output=True, text=True,
                           cwd=str(PLUGIN), env={"PATH": str(empty)})
        assert r.stdout.strip(), f"{event} printed nothing: this host would hear no decision — {r.stderr}"
        return json.loads(r.stdout)

    pre = run("PreToolUse")
    assert pre["decision"] == "deny", (
        f"a call the gate could not evaluate must be refused, not allowed through: {pre}")
    assert "python3" in pre["reason"] and "uv" in pre["reason"], (
        f"the refusal has to name what is missing, or the operator sees only the shell's own message: {pre}")

    # Post expects the empty object. Anything else and this host marks the tool call itself failed.
    assert run("PostToolUse") == {}


def test_the_fallback_cannot_fire_once_the_gate_has_already_decided():
    """The fallback is chained with `||`, so it must only run when nothing was printed. Every path through
    gate.py returns 0 — including the broad `except` — so a non-zero exit means the interpreter never ran
    it. If that ever stopped being true, the hook would print a decision AND the refusal, and this host
    would be handed two JSON objects on one stdout."""
    import ast
    tree = ast.parse(HOOK.read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    codes = [n.value for n in ast.walk(main) if isinstance(n, ast.Return) and n.value is not None]
    assert codes, "main() has no explicit return: the fallback's safety rests on its exit code"
    for c in codes:
        assert isinstance(c, ast.Constant) and c.value == 0, (
            f"main() can return {ast.unparse(c)}; a non-zero exit after printing would append the "
            "Antigravity fallback to a decision already on stdout")


def _bare_deny_names():
    """The deny-tier entries written WITHOUT the `exabeam_` prefix. They exist because a hand-wired server
    exposes containment under its bare verb, and they are the half of the tier that review found going
    unjudged on Antigravity."""
    tiers = json.loads((PLUGIN / "skills" / "soc-investigate" / "permissions.json").read_text())["tiers"]
    return [t for t in tiers["deny"]["tools"] if not t.startswith("exabeam_")]


def test_a_bare_deny_tier_name_on_our_server_is_denied():
    """Review, blocking item 1: `agy_call()` decided "ours" from the tool-name regex `^exabeam_`, so a
    containment call spelled `isolate_host` on our own server returned OTHER and got NO decision, while
    Claude Code denied the same call. The server is what makes a step ours; the tool name only says which
    tier it lands in."""
    bare = _bare_deny_names()
    assert bare, "the deny tier no longer carries bare spellings — this test is guarding nothing"
    for name in bare:
        for server in ("raffkin_exabeam", "raffkin-exabeam", "exabeam"):
            out = run_agy(agy_step(tool=name, server=server))
            assert out.get("decision") == "deny", (
                f"{name} on {server} answered {out} — a containment tool on the Exabeam server must be "
                "refused whatever spelling the host hands over")


def test_the_tool_name_may_arrive_prefixed_by_its_server():
    """`<server>/<tool>` is how the host's own guide spells a namespaced call, and `mcp__a__b` is the shape
    a step could carry if it echoed Claude's naming. Both must reduce to the bare tool the tiers use."""
    for spelling in ("raffkin_exabeam/exabeam_isolate_host", "raffkin_exabeam/isolate_host",
                     "mcp__raffkin_exabeam__exabeam_isolate_host"):
        out = run_agy(agy_step(tool=spelling, server="raffkin_exabeam"))
        assert out.get("decision") == "deny", f"{spelling} answered {out}, so the tier lookup never saw the tool"


def test_our_server_with_an_unreadable_tool_asks_and_says_why():
    """Review's third case: the tool name present but under a key the gate does not read. The step names
    OUR server, so standing aside is the hole; and the reason must not claim no server was named, which
    is what the first fix printed because `serverName` is itself a name-ish key."""
    out = run_agy(agy_step(tool=None, server="raffkin_exabeam", extra={"identifier": "exabeam_isolate_host"}))
    assert out.get("decision") == "ask", f"a call on our server that cannot be read must ask, got {out}"
    assert "no tool name and no server name" not in out["reason"], (
        f"the reason contradicts the payload, which named our server: {out['reason']!r}")
    assert "server" in out["reason"], f"the reason should say what it could and could not read: {out['reason']!r}"


def test_either_separator_keeps_the_bundled_tiers():
    """Review, blocking item 2: the host's guide namespaces servers `<plugin>-<server>` while the payload
    we modelled used `_`, and no live call has settled it (#305). With the hyphen unrecognised, the deny
    tier still held but the bundled allow, the ask and the #247 write budget were all lost — so the gate
    looked fine on the one tier that is loudest and had quietly stopped governing the rest."""
    for server in ("raffkin_exabeam", "raffkin-exabeam"):
        allow = run_agy(agy_step(tool="exabeam_get_case_details", server=server))
        assert allow.get("decision") == "allow", (
            f"an allow-tier read on {server} answered {allow}: not recognised as the bundled bridge, so the "
            "plugin's own permission grant does not apply")
        ask = run_agy(agy_step(tool="exabeam_update_case", server=server))
        assert ask.get("decision") == "ask", f"an ask-tier write on {server} answered {ask}"


def test_the_shell_fallback_refuses_our_calls_and_only_ours(tmp_path):
    """Review, should-fix item 4. The matcher is the step type, so with no interpreter the fallback is
    handed every MCP call on the machine. Denying all of them protects nothing of ours and is how a
    control gets switched off by whoever it annoys. It reads the step with `grep`, the only test available
    without an interpreter — and only grep's exit 1, a clean "our server is not in here", stands aside.
    A missing grep (127) cannot read the step at all, so it refuses."""
    name = json.loads((PLUGIN / "identity.json").read_text())["name"]
    cmd = AGY_HOOKS[f"{name}-gate"]["PreToolUse"][0]["hooks"][0]["command"]
    grep_only = tmp_path / "grep-only"
    grep_only.mkdir()
    for candidate in ("/usr/bin/grep", "/bin/grep"):
        if os.path.exists(candidate):
            (grep_only / "grep").symlink_to(candidate)
            break
    else:
        import pytest
        pytest.skip("no grep on this machine to build the probe PATH with")

    def run(step, path):
        r = subprocess.run(["/bin/sh", "-c", cmd], input=json.dumps(step), capture_output=True,
                           text=True, cwd=str(PLUGIN), env={"PATH": path})
        assert r.stdout.strip(), f"the fallback printed nothing, so this host would hear no decision: {r.stderr}"
        return json.loads(r.stdout)

    ours = agy_step(tool="exabeam_isolate_host", server="raffkin_exabeam")
    theirs = {"conversationId": "c", "stepIdx": 1,
              "toolCall": {"name": "mcp_tool", "args": {"serverName": "github",
                                                        "toolCall": {"toolName": "create_pull_request"}}}}
    assert run(ours, str(grep_only))["decision"] == "deny"
    assert run(theirs, str(grep_only)) == {}, (
        "another server's call was refused by a gate that is not even running — the deny the operator "
        "turns off because it blocks their pull requests")
    # Neither interpreter NOR grep: the step cannot be read, so it is not somebody else's by default.
    assert run(ours, "/nonexistent")["decision"] == "deny"
    assert run(theirs, "/nonexistent")["decision"] == "deny", (
        "with no way to read the step, standing aside is a guess in the ungated direction")


# A REAL Antigravity PreToolUse payload, captured from a live `agy` 1.4.5 session on 2026-10-22 by
# teeing the host's stdin (local paths replaced). Every earlier Antigravity fixture in this file was
# written from the host's documented contract and its proto descriptor; this one is what the host
# actually sends, and it disagreed with the documentation in three ways that each disabled part of the
# gate:
#   * the tool call's keys are PascalCase (`ServerName`, `ToolName`, `Arguments`) even though the hook
#     docs say "All JSON keys in the hook payloads use camelCase (protojson encoding)" -- which is true
#     of the common fields beside them. Read as camelCase, the SERVER was never seen: the bundled allow
#     tier went inert and a bare deny-tier name (`isolate_host`) got no decision at all;
#   * the tool name sits BESIDE the server, not nested under `toolCall`, and the step's own `name` is
#     the dispatcher (`call_mcp_tool`), not the tool being dispatched;
#   * arguments arrive positionally wrapped (`Arguments: {arg0: {...}}`), so an audit record would keep
#     its decision and lose its target -- which case was closed.
REAL_STEP = {
    "artifactDirectoryPath": "/home/u/.gemini/antigravity-cli/brain/2da04291",
    "conversationId": "2da04291-d330-480e-a753-5ec381532585",
    "modelName": "gemini-3.8-flash-high",
    "stepIdx": 4,
    "toolCall": {"name": "call_mcp_tool",
                 "args": {"Arguments": {"arg0": {"caseId": "ABC-123"}},
                          "ServerName": "raffkin_exabeam",
                          "ToolName": "exabeam_get_case_details"}},
    "transcriptPath": "/home/u/.gemini/antigravity-cli/brain/2da04291/transcript_full.jsonl",
    "workspacePaths": ["/tmp/ws"],
}


def _real(tool):
    step = json.loads(json.dumps(REAL_STEP))
    step["toolCall"]["args"]["ToolName"] = tool
    return step


def test_the_captured_payload_is_judged_on_every_tier():
    """The shape the host really sends, across the tiers. Before the key spellings were handled, this
    exact payload produced: allow-tier -> no decision, bare deny-tier -> no decision."""
    tiers = json.loads((PLUGIN / "skills" / "soc-investigate" / "permissions.json").read_text())["tiers"]
    assert run_agy(_real(tiers["allow"]["tools"][0])).get("decision") == "allow"
    assert run_agy(_real(tiers["ask"]["tools"][0])).get("decision") == "ask"
    for name in tiers["deny"]["tools"][:12]:
        out = run_agy(_real(name))
        assert out.get("decision") == "deny", f"{name} on the real payload shape answered {out}"


def test_the_captured_payload_is_recognised_as_the_bundled_bridge():
    """`ServerName: raffkin_exabeam` -- underscore, settling #305: the host's guide documents
    `<plugin>-<server>`. Reading it is what makes the allow tier the PLUGIN's grant rather than a call
    the gate has no opinion on, so a miss here is silent and total."""
    assert run_agy(_real("exabeam_get_case_details")).get("decision") == "allow"


def test_the_captured_payload_keeps_what_was_attempted():
    """`Arguments: {arg0: {...}}`. A decision the log cannot attach to an object is close to no log."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        log = pathlib.Path(d) / "gate.jsonl"
        e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "RAFFKIN_GATE_LOG": str(log),
             "RAFFKIN_GATE_STATE_DIR": d}
        subprocess.run([sys.executable, str(HOOK), "--antigravity"],
                       input=json.dumps(_real("exabeam_update_case")), capture_output=True, text=True, env=e)
        rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert rows, "the decision was never recorded"
    assert rows[-1].get("target") == {"caseId": "ABC-123"}, (
        f"the record lost which case was attempted: {rows[-1].get('target')!r}")


def test_a_key_spelling_cannot_hide_the_server_or_the_tool():
    """The generalisation of the defect, rather than the one spelling that caused it: a host that renames
    these keys by case must not be able to turn the gate off by doing so."""
    for server_key in ("ServerName", "serverName", "SERVERNAME", "server_name"):
        for tool_key in ("ToolName", "toolName", "TOOLNAME", "tool_name"):
            step = {"conversationId": "c", "stepIdx": 1,
                    "toolCall": {"name": "call_mcp_tool",
                                 "args": {server_key: "raffkin_exabeam", tool_key: "isolate_host"}}}
            out = run_agy(step)
            assert out.get("decision") == "deny", f"{server_key}/{tool_key} answered {out}"


def test_a_completed_ask_on_this_host_does_not_claim_consent():
    """Observed 2026-10-22 (agy 1.4.5): a session run with --dangerously-skip-permissions completed an
    ask-tier case closure ONE SECOND after the gate asked, with nobody prompted. The post-call record
    said `approved`, reason "an ask completes only on a yes" — a consent in the audit trail that never
    happened, which is the one failure mode a log must not have. This host reports no permission mode, so
    the gate cannot tell an answered prompt from an auto-approved one and must not pretend otherwise.

    Also pins `arg1` rather than `arg0`: the real capture used both, so the positional index varies."""
    import tempfile
    step = json.loads(json.dumps(REAL_STEP))
    step["toolCall"]["args"]["ToolName"] = "exabeam_update_case"
    step["toolCall"]["args"]["Arguments"] = {"arg1": {"caseId": "ZZZZ-GATE-TEST-0000", "stage": "CLOSED"}}
    with tempfile.TemporaryDirectory() as d:
        log = pathlib.Path(d) / "gate.jsonl"
        e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "RAFFKIN_GATE_LOG": str(log),
             "RAFFKIN_GATE_STATE_DIR": d}
        r = subprocess.run([sys.executable, str(HOOK), "--antigravity", "--post"],
                           input=json.dumps(step), capture_output=True, text=True, env=e)
        assert r.returncode == 0, r.stderr
        rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert rows, "a completed ask-tier call left no record at all"
    rec = rows[-1]
    assert rec["decision"] != "approved", (
        "the record claims a human approved this call; on this host the gate cannot see the prompt, and a "
        "session with --dangerously-skip-permissions completes an ask without one")
    assert rec["decision"] == "ran_consent_unconfirmed", rec["decision"]
    assert "NOT evidenced" in rec["reason"], f"the reason must say what it cannot vouch for: {rec['reason']!r}"
    assert rec.get("target") == {"caseId": "ZZZZ-GATE-TEST-0000", "stage": "CLOSED"}, (
        f"positional arg index other than arg0 lost the target: {rec.get('target')!r}")
