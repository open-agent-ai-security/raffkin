#!/usr/bin/env python3
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Raffkin's human-in-the-loop gate for Claude Code, shipped INSIDE the plugin as a PreToolUse hook.

Why this exists. Claude Code lets a plugin ship code that takes part in permission decisions, but not
permission rules: rules are the operator's to set. A PreToolUse hook is active the moment the plugin is enabled, its
`deny` holds even under `--dangerously-skip-permissions`, and its `ask` forces a human prompt in every
mode and is refused when no human is present — the same posture the Codex package gets from
`default_tools_approval_mode`. Verified live on 2026-09-04 (issue #9's two open questions).

What it decides, keyed on the BARE tool name (the last `__` segment). `deny` and `ask` apply equally to
every Exabeam-named server -- the bundled server under any plugin key (`mcp__plugin_raffkin_exabeam__…`,
`mcp__plugin_soc_exabeam__…`), the manually wired `mcp__exabeam__…`, a third party's -- because tightening
is always safe; `allow` applies to the bundled bridge only (below):

    deny tier  → deny   containment: Raffkin never executes it, it recommends it
    ask tier   → ask    dismiss / close (and send_email): an explicit human yes, every time
    allow tier → allow  reads and the two escalation writes (create case, write notes): safe operations
                        run without a prompt, so an install needs NOTHING merged — the same tools Codex
                        runs as `auto`. This allow removes only the DEFAULT prompt: an operator's own
                        settings rule on one of these tools still wins — a `deny` removes the tool from
                        the model's list before the hook ever runs, and an `ask` still prompts (both
                        verified live in default permission mode, headless, 2026-09-06). Returning no
                        decision here instead would make every read prompt with nothing merged, which is
                        the permission merge back under another name.
                        The allow is granted ONLY to the bundled bridge — the server named
                        `plugin_<this plugin's name>_exabeam`, the name read from identity.json beside
                        this hook. On any other Exabeam-named server (a manual registration, a third
                        party's server) an allow-tier tool gets NO decision: the operator's own rules
                        apply, exactly as the generated permission snippet already spells it (its allow
                        rules exist under the bundled prefix only). Praxen 2026-09-07-003.
    anything else → ask a tool the remote MCP grew that nobody has classified asks rather than
                        inheriting the session default — Codex's `approve` default, on Claude
    a tool of another MCP server → (no decision, not logged): the matcher is broad enough to survive a
                        renamed server, so the hook, not the matcher, decides whether a call is ours.
                        "Ours" is case-insensitive here AND in the matcher (Praxen 2026-09-07-004).

The tiers come from the file that ships beside this hook — `skills/soc-investigate/permissions.json`
(bare names) when present, else `settings.snippet.json` (prefixed rules, stripped) — so the hook, the
snippet and the Codex map cannot disagree. If the tiers cannot be read at all, every tool asks: the human
decides interactively, and headless the call is refused. The gate never fails open.

Each decision is appended, best-effort, to `~/.raffkin/gate.jsonl` with the call's SAFE target fields —
identifiers and dispositions only (alertId, caseId, alertStatus, stage, …), never free text — so a
refused attempt reads as "tried to dismiss alert X as false positive", not just "tried update_alert".
The near-miss is the record that matters in a SOC (`RAFFKIN_GATE_LOG=off` disables;
another path overrides) — a first-party record of what was attempted and what the gate said, including
attempts that never reached the bridge (#87).

The same hook runs as PostToolUse, invoked with `--post` (#5). An ask-tier call that COMPLETED is
appended as `"decision": "approved"` with the same safe target fields, beside the `ask` line — inferred
from completion: an ask completes only when a human answered yes, unless the session ran in a mode where
nobody could answer (bypassPermissions, dontAsk), recorded as `"ran_unasked"`. A deny-tier tool that ran
anyway is `"ran_despite_deny"`. Allow-tier tools leave no post-call line: the gate log is a log of
decisions, and the bridge's telemetry already records every call. Both lines carry the host's
`permission_mode` and `tool_use_id` when present, so a post line ties to its ask. No output on stdout.

The two escalation writes are allowed on a budget (#247): per host session, the first two allow-tier
writes run without a prompt and a third asks, and a second `create_case` asks whatever the count. One
investigation opens at most one case and writes its note; a sweep that starts acting on its queue meets a
prompt on its third write. The count is the hook's own (keyed on the host's session id, kept in a small
state file under ~/.raffkin/gate-sessions/, never in the decision log, which can be switched off), so there
is nothing for an injected instruction to talk it out of. No session id, or a state file that cannot be
read or written, means ask: the budget never fails open.

Stdlib only. Exit 0 always; the decision is the JSON on stdout.
"""
from __future__ import annotations   # `tuple[str, str]` must not be evaluated on an old system python3

import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

try:                                    # POSIX file locks keep parallel tool calls in one message honest;
    import fcntl                        # without them (never on the supported hosts) the count is best-effort
except ImportError:  # pragma: no cover
    fcntl = None

SERVER = "exabeam"
NO_DECISION = "none"               # the allow tier off the bundled bridge: the operator's rules apply


def bare(tool_name: str) -> str:
    return tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name


def server_of(tool_name: str) -> str:
    """The <server> in mcp__<server>__<tool>; '' when the name is not an MCP tool name."""
    m = re.match(r"^mcp__(.+)__[^_].*$", tool_name)
    return m.group(1) if m else ""


def is_ours(tool_name: str) -> bool:
    """mcp__<server>__<tool> where <server> is an Exabeam MCP: `exabeam`, a bundled `plugin_<key>_exabeam`,
    or any server an operator named with `exabeam` in it (any case). Anything else belongs to another server."""
    return SERVER in server_of(tool_name).lower()


def plugin_name(plugin_root: Path):
    """This plugin's own name — the one Claude Code builds the bundled server prefix from. Claude Code reads
    it from the manifest (.claude-plugin/plugin.json), so that is the authority; identity.json is the source
    the manifest is generated from and the fallback. When both are present and disagree (an overlaid copy
    that was not regenerated), say so on stderr and trust the manifest -- silently trusting identity.json
    would make every bundled read fall through to a prompt (#158). None when neither is readable,
    which means no server can be recognized as the bundled bridge: reads then fall through, never allow."""
    names = {}
    for rel in (".claude-plugin/plugin.json", "identity.json"):
        try:
            name = json.loads((plugin_root / rel).read_text()).get("name")
            if isinstance(name, str) and name:
                names[rel] = name
        except Exception:  # noqa: BLE001, S110 — try the other source; the caller treats None as "not bundled"
            pass
    manifest, ident = names.get(".claude-plugin/plugin.json"), names.get("identity.json")
    if manifest and ident and manifest != ident:
        sys.stderr.write(f"Raffkin gate: identity.json names this plugin {ident!r} but the manifest Claude Code reads "
                         f"names it {manifest!r} — using the manifest; regenerate with gen_identity.py\n")
    return manifest or ident


def is_bundled(tool_name: str, name) -> bool:
    """Exactly the bundled bridge: `plugin_<name>_exabeam`, no substring, no case games."""
    return bool(name) and server_of(tool_name) == f"plugin_{name}_{SERVER}"


def load_tiers(plugin_root: Path):
    """{'allow': set, 'ask': set, 'deny': set} of bare tool names, from the shipped tier file."""
    perms = plugin_root / "skills" / "soc-investigate" / "permissions.json"
    if perms.is_file():
        d = json.loads(perms.read_text())
        return {t: set(spec["tools"]) for t, spec in d["tiers"].items()}
    snippet = plugin_root / "skills" / "soc-investigate" / "settings.snippet.json"
    p = json.loads(snippet.read_text())["permissions"]
    return {t: {bare(r) for r in p.get(t, [])} for t in ("allow", "ask", "deny")}


def decide(tool_name: str, tiers, *, bundled: bool) -> tuple[str, str]:
    """deny and ask apply to every Exabeam-named server (tightening only); allow applies to the bundled
    bridge alone -- elsewhere an allow-tier tool gets NO decision and the operator's rules apply."""
    name = bare(tool_name)
    if name in tiers["deny"]:
        return "deny", f"Raffkin gate: {name} is a containment action. Raffkin recommends containment for a human to perform and never executes it."
    if name in tiers["ask"]:
        return "ask", f"Raffkin gate: {name} dismisses or closes. It needs the analyst's explicit yes — ask, and wait."
    if name in tiers["allow"]:
        if bundled:
            return "allow", f"Raffkin gate: {name} is a read or an escalation write."
        return NO_DECISION, f"Raffkin gate: {name} is a read or an escalation write, but this is not the bundled bridge — no decision; the operator's own permission rules apply."
    return "ask", f"Raffkin gate: {name} is not classified in this release's permission tiers, so it asks rather than inheriting the session default."


# The SAFE fields of a call worth recording beside the decision — the same allowlist the bridge's audit
# trail uses (_AUDIT_FIELDS in exabeam-mcp-bridge.py): identifiers and enums, never free text (note,
# description, reason, subject, body). Scalars and short lists only, values capped, first occurrence wins.
AUDIT_FIELDS = {"alertid", "caseid", "alertstatus", "casestatus", "stage",
                "priority", "severity", "queue", "disposition", "usecases", "recipients"}
_CAP = 80


def target_fields(obj, into=None, depth=0):
    """Collect AUDIT_FIELDS from anywhere in the (possibly nested) tool input. Never raises."""
    into = {} if into is None else into
    try:
        if isinstance(obj, dict) and depth < 4:
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in AUDIT_FIELDS and isinstance(v, (str, int, float, bool)):
                    into.setdefault(k, v[:_CAP] if isinstance(v, str) else v)
                elif lk in AUDIT_FIELDS and isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
                    into.setdefault(k, [x[:_CAP] if isinstance(x, str) else x for x in v[:10]])
                elif isinstance(v, dict):
                    target_fields(v, into, depth + 1)
    except Exception:  # noqa: BLE001, S110 — the record is best-effort; the decision never depends on it
        pass
    return into


LOG_MAX_BYTES = 5_000_000   # rotate at ~5 MB, keep 3 backups — bounded like the telemetry log beside it
LOG_BACKUPS = 3


def _rotate(path: Path) -> None:
    """gate.jsonl → gate.jsonl.1 → .2 → .3 (oldest dropped). Best-effort, like the write itself. Two
    concurrent hook invocations can both see the ceiling; the loser's replace() finds the file already
    moved — swallow that, the decision is unaffected and this record still appends below."""
    for i in range(LOG_BACKUPS, 0, -1):
        src = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
        try:
            if src.exists():
                src.replace(path.with_name(f"{path.name}.{i}"))
        except FileNotFoundError:
            pass


def log_decision(record: dict) -> None:
    target = os.environ.get("RAFFKIN_GATE_LOG", "").strip()
    if target.lower() == "off":
        # The off switch discloses itself, as the telemetry shim's does — a silent switch is how a
        # forensic record disappears without anyone noticing.
        print("Raffkin gate: decision log is OFF (RAFFKIN_GATE_LOG=off) — this decision is not recorded", file=sys.stderr)
        return
    try:
        # Inside the guard: expanduser() on "~nosuchuser" and Path.home() with no HOME / unknown uid both
        # raise, and a crash here would turn "logging failed" into "every call blocked" via `|| exit 2`.
        path = Path(target).expanduser() if target else Path.home() / ".raffkin" / "gate.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            limit = int(os.environ.get("RAFFKIN_GATE_LOG_MAX_BYTES", LOG_MAX_BYTES))
        except ValueError:
            limit = LOG_MAX_BYTES
        if path.exists() and path.stat().st_size >= limit:
            _rotate(path)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001, S110 — logging must never change the decision, so nothing is raised here
        pass


# ---- the escalation-write budget (#247) ----
ESCALATION_WRITES = {"exabeam_create_case", "exabeam_create_case_notes"}
WRITE_BUDGET = 2            # allow-tier writes per session before a prompt; from the data: legitimate
CASE_BUDGET = 1             # sessions made at most one case plus its note, and a sweep makes none
_STATE_TTL = 7 * 24 * 3600  # a session's count file is pruned a week after its last write
_SESSION_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _state_dir() -> Path:
    target = os.environ.get("RAFFKIN_GATE_STATE_DIR", "").strip()
    return Path(target).expanduser() if target else Path.home() / ".raffkin" / "gate-sessions"


def spend_write_budget(event, name: str) -> tuple[bool, str]:
    """Reserve one escalation write for this session. Returns (allowed, reason). Counted at decision time,
    not after the call, so parallel calls in one message cannot all slip under the budget. Any failure to
    identify the session or to read and write its count returns (False, reason): ask, never allow."""
    sid = str(event.get("session_id") or "").strip()
    if not _SESSION_ID.match(sid):
        return False, f"Raffkin gate: {name} is an escalation write, and without a session id the hook cannot count them; asking rather than allowing."
    try:
        d = _state_dir()
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{sid}.json"
        with open(path, "a+", encoding="utf-8") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            fh.seek(0)
            raw = fh.read()
            state = json.loads(raw) if raw.strip() else {}
            writes, cases = int(state.get("writes", 0)), int(state.get("cases", 0))
            if writes >= WRITE_BUDGET:
                return False, (f"Raffkin gate: {name} would be escalation write {writes + 1} in this session; the first "
                               f"{WRITE_BUDGET} run without a prompt, and past that the analyst decides. Ask, and wait.")
            if name == "exabeam_create_case" and cases >= CASE_BUDGET:
                return False, (f"Raffkin gate: {name} would open case {cases + 1} in this session; one investigation "
                               "opens one case, so another needs the analyst's yes. Ask, and wait.")
            state = {"writes": writes + 1, "cases": cases + (name == "exabeam_create_case"), "updated": int(time.time())}
            fh.seek(0); fh.truncate(); fh.write(json.dumps(state)); fh.flush()
        _prune(d)
        return True, ""
    except Exception as e:  # noqa: BLE001 — cannot count → the human decides
        return False, f"Raffkin gate: {name} is an escalation write and the session count could not be read ({type(e).__name__}); asking rather than allowing."


def _prune(d: Path) -> None:
    """Best-effort: drop count files for sessions idle past the TTL. Never raises."""
    try:
        cutoff = time.time() - _STATE_TTL
        for f in d.glob("*.json"):
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001, S110 — housekeeping must never change a decision
        pass


_UNATTENDED_MODES = {"bypasspermissions", "dontask"}


def _context(event) -> dict:
    """The host fields that let a post-call line be tied to its ask and judged: the permission mode the
    session ran in and the call's id. Both documented on PreToolUse and PostToolUse; absent = omitted."""
    out = {}
    mode = event.get("permission_mode")
    if isinstance(mode, str) and mode.strip():
        out["permission_mode"] = mode.strip()[:40]
    tid = event.get("tool_use_id")
    if isinstance(tid, str) and tid.strip():
        out["tool_use_id"] = tid.strip()[:80]
    return out


def _post_call(event, tool: str, target: dict) -> int:
    """PostToolUse (#5): the call completed. For an ask-tier tool that is recorded as `approved` — the gate
    asked before it, and an ask completes only when a human answered yes — unless the session ran in a
    mode where nobody could answer (bypassPermissions, dontAsk), which is recorded as `ran_unasked`: the
    ask did not hold for that call. A deny-tier tool that ran is `ran_despite_deny`. Allow-tier tools
    leave no line. Never a decision, never stdout: this is a record, not a verdict."""
    try:
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        decision, _reason = decide(tool, load_tiers(root), bundled=is_bundled(tool, plugin_name(root)))
    except Exception:  # noqa: BLE001 — unclassifiable: record that it ran, as the ask it would have been
        decision = "ask"
    ctx = _context(event)
    if decision == "ask":
        if ctx.get("permission_mode", "").lower() in _UNATTENDED_MODES:
            outcome, reason = "ran_unasked", f"an ask-tier call completed under {ctx['permission_mode']}, where no human could answer: the gate's ask did not hold for this call"
        else:
            outcome, reason = "approved", "an ask-tier call completed after the gate asked: inferred from completion, an ask completes only on a yes"
    elif decision == "deny":
        outcome, reason = "ran_despite_deny", "a deny-tier tool ran: the gate's deny was not in effect for this call"
    else:
        return 0                           # allow tier: the telemetry records the call; the gate log records decisions
    record = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool": tool, "decision": outcome, "reason": reason, **ctx}
    if target:
        record["target"] = target
    log_decision(record)
    return 0


def main(argv=None) -> int:
    # --post: this invocation is the PostToolUse record (hooks.json passes it). Decided by the command
    # line, not by stdin, so an unparseable event can never turn a record into a permission decision.
    post = "--post" in (sys.argv[1:] if argv is None else argv)
    tool, target, ctx = "", {}, {}
    try:
        event = json.load(sys.stdin)
        tool = str(event.get("tool_name", ""))
        if tool and not is_ours(tool):
            return 0                       # another server's tool: no decision, no record (not our business)
        target = target_fields(event.get("tool_input"))
        if post or str(event.get("hook_event_name", "")) == "PostToolUse":
            return _post_call(event, tool, target)
        ctx = _context(event)
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        decision, reason = decide(tool, load_tiers(root), bundled=is_bundled(tool, plugin_name(root)))
        if decision == "allow" and bare(tool) in ESCALATION_WRITES:
            ok, why = spend_write_budget(event, bare(tool))
            if not ok:
                decision, reason = "ask", why
    except Exception as e:  # noqa: BLE001 — cannot classify → the human decides; headless → refused
        if post:
            return 0                       # a record we cannot write is not a decision to make
        decision, reason = "ask", f"Raffkin gate could not evaluate this call ({type(e).__name__}); asking rather than allowing."
    record = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool": tool, "decision": decision, "reason": reason, **ctx}
    if target:
        record["target"] = target          # what was attempted, on which object — never the free text
    log_decision(record)
    if decision == NO_DECISION:
        return 0                           # no JSON on stdout = no decision: the normal permission flow runs
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
