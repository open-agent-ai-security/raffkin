# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 — static + smoke checks on the connector bridge.

No live MCP, no credentials, no network on the static path. These guard the two
properties that matter most for a stdio bridge that handles an OAuth secret:
it must never leak the token/secret to stdout, and it must fail *closed* (exit
non-zero with a helpful message) when credentials are absent.

Run:  uv run --with pytest pytest -q tests/test_bridge_static.py
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "plugin" / "connector" / "exabeam-mcp-bridge.py"
SRC = BRIDGE.read_text()


# ---------- static ----------

def test_bridge_byte_compiles():
    import py_compile
    py_compile.compile(str(BRIDGE), doraise=True)


def test_pep723_header_well_formed():
    """The inline metadata must declare requires-python and the runtime deps, so
    `uv run` can resolve the environment on a cold machine."""
    hdr = re.search(r"# /// script\n(.*?)\n# ///", SRC, re.S)
    assert hdr, "missing PEP 723 inline-metadata header"
    block = hdr.group(1)
    assert re.search(r'requires-python\s*=\s*">=3\.\d+"', block), "no requires-python"
    assert re.search(r"dependencies\s*=\s*\[", block), "no dependencies array"
    for dep in ("mcp", "httpx", "certifi"):
        assert dep in block, f"PEP723 deps missing {dep!r}"


def test_no_secret_written_to_output():
    """A stdio MCP server must keep stdout clean (JSON-RPC only) and must never print
    the OAuth token or API secret anywhere. Assert no print/stdout/stderr write mentions
    a secret-bearing identifier."""
    out_calls = ("print(", "stdout.write", "stderr.write")
    secret_idents = ("SECRET", "client_secret", "access_token", "_token", "Bearer")
    offenders = []
    for line in SRC.splitlines():
        if any(o in line for o in out_calls):
            hit = [s for s in secret_idents if s in line]
            if hit:
                offenders.append((hit, line.strip()))
    assert not offenders, f"secret-bearing identifiers in output calls: {offenders}"


def test_fails_closed_without_credentials():
    """main() must guard on all three creds and exit non-zero, writing guidance to
    stderr (not stdout — stdout is the protocol channel)."""
    assert re.search(r"if not \(URL and KEY and SECRET\)", SRC), "missing credential guard"
    assert "sys.exit(1)" in SRC, "guard must exit non-zero"
    guard = SRC.split("def main()", 1)[1]
    assert "stderr" in guard.split("sys.exit(1)")[0], "guidance must go to stderr"


def test_setup_message_references_existing_paths():
    """The missing-creds guidance must not point at retired files — connect-exabeam.sh
    was removed in v0.3.0, so a reference to it would misdirect a stuck user."""
    for ref in re.findall(r"connector/[A-Za-z0-9_./-]+", SRC):
        # only check things that look like a file (have an extension)
        if "." in Path(ref).name:
            assert (ROOT / "plugin" / ref).exists(), f"bridge references a missing path: {ref}"


# ---------- smoke (opt-in; skips cleanly if the env can't run it) ----------

def test_check_without_creds_exits_clean():
    """Behavioral confirmation of fail-closed: `--check` with no creds exits non-zero
    with the guidance message, no traceback, and nothing on stdout. Runs the bridge
    under a throwaway HOME so it can't find (or use) the operator's real creds; skips
    if uv/deps/network can't set up the ephemeral environment."""
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH")
    tmp = tempfile.mkdtemp()
    # Preserve uv's real cache (compute against the *current* HOME before we override it)
    real_cache = os.environ.get("UV_CACHE_DIR") or os.path.expanduser("~/.cache/uv")
    env = {k: v for k, v in os.environ.items() if not k.startswith("EXABEAM")}
    env["HOME"] = tmp                 # ~/.exabeam-mcp.env now resolves into an empty dir
    env["UV_CACHE_DIR"] = real_cache
    try:
        proc = subprocess.run(
            ["uv", "run", "--quiet", "--locked", str(BRIDGE), "--check"],
            capture_output=True, text=True, timeout=300, env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        pytest.skip(f"could not run bridge --check: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Distinguish our expected failure from an environment/dep failure (then skip). A TRACEBACK is
    # never an environment problem — it means the bridge itself crashed — and skipping on one is
    # exactly how #67 hid: mcp 2.0.0 dropped streamablehttp_client, the bridge died at import, and
    # this guard downgraded that to a skip on both maintainers' machines. The assertions below
    # already reject tracebacks; they just never ran. Fail here, and let only genuine provisioning
    # failures (uv can't build the env, no network) reach the skip.
    if proc.returncode != 0 and "missing credentials" not in proc.stderr.lower():
        if "traceback" in proc.stderr.lower():
            pytest.fail(f"bridge crashed instead of failing closed:\n{proc.stderr}")
        pytest.skip(f"bridge could not initialize (deps/env): {proc.stderr[:200]!r}")

    assert proc.returncode != 0, "no-creds --check must fail closed"
    assert "missing credentials" in proc.stderr.lower(), proc.stderr
    assert "traceback" not in proc.stderr.lower(), f"should exit cleanly, not crash:\n{proc.stderr}"
    assert proc.stdout.strip() == "", f"no-creds run must not print to stdout: {proc.stdout!r}"


# ---------- dry run (the write refusal that does not depend on host approval semantics) ----------
#
# Context: with no human present, both hosts refuse a destructive write. Claude Code's ask tier fails
# CLOSED under `claude -p`; Codex cancels its destructive-annotated write tools under `codex exec`,
# because approval can't be granted. (An earlier build on this branch read Codex's approve mode as
# failing OPEN headlessly and added a connector-side confirmation for it; that did not reproduce and the
# claim was retracted — see CHANGELOG.) RAFFKIN_DRY_RUN is therefore a host-independent test switch, not a
# safety fix: the bridge is the only shared layer, so it is the only place a write can be refused
# identically on both without depending on either host's approval semantics. These pin the properties
# that make that refusal trustworthy.

def _call_tool_body():
    i = SRC.index("async def call_tool(")
    j = SRC.index("\nasync def _check(", i)
    return SRC[i:j]


def _dry_run_guard():
    """Just the dry-run block. Anchored on the main try's first statement, because the guard contains a
    nested try of its own and a naive search for `    try:` stops inside it."""
    body = _call_tool_body()
    i = body.index("if DRY_RUN and is_write_tool(name):")
    return body[i:body.index("    try:\n        if is_write:", i)]


def test_dry_run_is_off_unless_the_env_says_otherwise():
    """A dry run that turns itself on would silently stop protecting a real tenant; one that turns
    itself off would silently write to it. It must come from the environment and nowhere else."""
    assert 'DRY_RUN = _truthy(os.environ.get("RAFFKIN_DRY_RUN", ""))' in SRC
    assert "DRY_RUN = True" not in SRC


def test_truthy_accepts_only_explicit_affirmatives():
    """Executed, not eyeballed — extracted from source so this needs none of the bridge's imports."""
    i = SRC.index("def _truthy(")
    ns = {}
    exec(SRC[i:SRC.index("\n\n", i)], ns)          # noqa: S102 — our own source, no input
    truthy = ns["_truthy"]
    for v in ("1", "true", "TRUE", " yes ", "on"):
        assert truthy(v), f"{v!r} should enable the dry run"
    for v in ("", "0", "false", "no", "off", "maybe"):
        assert not truthy(v), f"{v!r} must NOT enable the dry run"


def test_dry_run_refuses_on_the_tool_name_not_on_having_arguments():
    """`is_write` is `is_write_tool(name) and bool(arguments)`. Keying the refusal on that would forward
    an argument-less write to the tenant, which is still a write. (Writes are the default since Praxen
    2026-09-07-005: `is_write_tool` is "not a classified read", so an unknown tool is refused too.)"""
    body = _call_tool_body()
    assert "if DRY_RUN and is_write_tool(name):" in body, (
        "the dry-run guard must key on the tool name, not on is_write")


def test_dry_run_refuses_before_the_remote_call():
    """A refusal after `await remote(...)` refuses nothing — the write has already happened."""
    body = _call_tool_body()
    assert body.index("if DRY_RUN and is_write_tool(name):") < body.index("await remote("), (
        "the dry-run guard must come before the remote call")


def test_dry_run_returns_a_refusal_rather_than_raising():
    """Claude Code's permission layer hands the model a tool RESULT saying it was denied, and the
    red-team grader needs the attempt recorded as a completed call. Raising would make an attempted
    gated write look like a transport error instead."""
    guard = _dry_run_guard()
    assert "return [TextContent(" in guard, "the refusal must be returned to the agent"
    assert "raise" not in guard, "the refusal must not raise"
    assert "was not granted" in guard and "not executed" in guard


def test_refusal_text_does_not_coach_the_model():
    """The refusal is read by the agent mid-run, including mid-attack in a red-team exercise. Telling it
    to defer to a human, or not to retry, is coaching the exact behavior the exercise measures — and it
    is text the Claude Code baseline (a bare "you haven't granted it yet") never saw, so it would make
    the two hosts non-comparable as well as flattering. Keep it a statement of fact."""
    guard = _dry_run_guard()
    text = guard[guard.index("TextContent("):]
    for phrase in ("leave the action", "a human", "do not retry", "report what you would",
                   "escalate", "instead you should"):
        assert phrase not in text.lower(), f"refusal text coaches the model: {phrase!r}"


def test_dry_run_attempt_is_marked_in_the_audit_record():
    """The emit layer's `result` means 'the MCP call completed', which is true for a refusal too. Without
    an explicit marker an audit reader sees action.stage=closed / result=success and concludes the close
    landed."""
    guard = _dry_run_guard()
    assert '"dryRunRefused"' in guard, "a refused write must be distinguishable from a landed one"
    assert "telemetry.tool_end(" in guard, "the attempt must still reach the audit trail"


def test_dry_run_is_announced_on_startup():
    """A dry run mistaken for a live one wastes an exercise; a live run mistaken for a dry one writes to
    a real tenant. Neither may be silent."""
    assert "DRY RUN is ON" in SRC
    assert "DRY RUN" in SRC[SRC.index("async def _check("):], "--check must report dry-run state too"
