#!/usr/bin/env python3
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Raffkin's human-in-the-loop gate, shipped INSIDE the plugin as a PreToolUse hook on two hosts.

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
appended beside the `ask` line with the same safe target fields, as whatever the gate can actually vouch
for: `"approved"` only where the host reported an attended permission mode, so completion does imply a
human answered yes; `"ran_unasked"` where it reported an unattended one (bypassPermissions, dontAsk);
and `"ran_consent_unconfirmed"` where it reported none at all, which is Antigravity — an ask there was
observed completing with nobody prompted, so `approved` would record a consent that never happened. A deny-tier tool that ran
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

GOOGLE ANTIGRAVITY runs this same file, invoked with `--antigravity` from the plugin's root hooks.json.
Same tiers, same budget, same log; three differences, all in the envelope rather than the decision:

  * The host matches hooks on the STEP TYPE, so every MCP call on the machine arrives here as `mcp_tool`
    whichever server it belongs to, with the real tool name inside the payload (`serverName` plus a nested
    `toolCall`). A call we cannot identify as an Exabeam one gets no decision, exactly as on Claude Code --
    the difference is that here the matcher cannot do any of that filtering, so the parsing below is the
    only thing standing between another server's calls and our verdicts.
  * The decision is `{"decision": "deny"|"ask"|"force_ask"|"allow", "reason": ...}` rather than Claude
    Code's `hookSpecificOutput`. The host documents `deny` as a hard block; what has been OBSERVED is
    that `ask` is NOT one — a session run with `--dangerously-skip-permissions` completed an ask-tier
    write a second after the gate asked, nobody prompted (agy 1.4.5, 2026-10-22). `deny` does hold under
    that flag: measured on the same host and version, a hook `deny` blocked the call.
  * The host does not report its permission mode, so a completed ask-tier call is logged as
    `ran_consent_unconfirmed` rather than `approved`
    without being able to prove a human answered -- the one thing the Claude Code record can distinguish
    and this one cannot. Records carry `"host"` so the log never has to be guessed at.

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


def is_bundled(tool_name: str, name, host: str = "claude") -> bool:
    """Exactly the bundled bridge, under either host's namespacing: Claude Code prefixes a plugin's MCP
    server `plugin_<name>_<server>`, Antigravity `<plugin>_<server>`. No substring, no case games.

    Antigravity's own guide spells that namespace with a HYPHEN (`<plugin>-<server>`) while the payload we
    modelled used an underscore, and no live call has settled which one it sends (#305). Both are accepted,
    because being wrong costs the bundled allow tier: review measured `raffkin-exabeam` losing every
    allow-tier read, the `create_case` ask and the #247 write budget, while only the deny tier survived.

    A bare `exabeam` is deliberately NOT bundled on either host: that is what a hand-wired server is
    called, on Antigravity as much as on Claude Code, so it gets the operator's own rules and not our
    allow."""
    if not name:
        return False
    server = server_of(tool_name)
    if host == "antigravity":
        # This host's own namespacing, with both separators (#305: the live payload uses the underscore,
        # the guide documents the hyphen).
        return server in (f"{name}_{SERVER}", f"{name}-{SERVER}")
    # Claude Code prefixes `plugin_`. Accepting this host's forms here too was a REGRESSION: review
    # measured all 21 allow-tier tools changing from no-decision to allow on Claude Code for a server an
    # operator had hand-wired as `<plugin>_exabeam`. A hand-wired server gets the operator's own rules,
    # and which spellings count as bundled is a property of the host, not of the string.
    return server == f"plugin_{name}_{SERVER}"


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


def _post_call(event, tool: str, target: dict, ctx=None) -> int:
    """PostToolUse (#5): the call completed, recorded as what the gate can actually VOUCH for.

    `approved` is only written where completion really does imply a human said yes: the host reported an
    attended permission mode. Where it reported an unattended one (bypassPermissions, dontAsk) the line is
    `ran_unasked`. Where it reported NOTHING -- Antigravity -- the line is `ran_consent_unconfirmed`,
    because an ask there was observed completing with nobody prompted. A deny-tier tool that ran is
    `ran_despite_deny`. Allow-tier tools leave no line. Never a decision, never stdout: this is a record,
    not a verdict, and a record that overstates what it knows is worse than a shorter one."""
    try:
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        host_for_bundling = (ctx or {}).get("host") or "claude"
        decision, _reason = decide(tool, load_tiers(root),
                                   bundled=is_bundled(tool, plugin_name(root), host_for_bundling))
    except Exception:  # noqa: BLE001 — unclassifiable: record that it ran, as the ask it would have been
        decision = "ask"
    ctx = _context(event) if ctx is None else ctx
    if decision == "ask":
        if ctx.get("permission_mode", "").lower() in _UNATTENDED_MODES:
            outcome, reason = "ran_unasked", f"an ask-tier call completed under {ctx['permission_mode']}, where no human could answer: the gate's ask did not hold for this call"
        elif not ctx.get("permission_mode"):
            # The host never told us the mode, so "it completed" does not mean "a human said yes". On
            # Antigravity that is not hypothetical: a session started with --dangerously-skip-permissions
            # was OBSERVED completing an ask-tier case closure one second after the gate asked, with
            # nobody prompted (2026-10-22, agy 1.4.5). Recording that as `approved` would put a consent
            # in the audit trail that never happened, which is worse than recording less.
            outcome, reason = "ran_consent_unconfirmed", ("an ask-tier call completed, but this host does "
                "not report its permission mode, so the gate cannot tell an answered prompt from a "
                "session that auto-approved it; consent is NOT evidenced by this record")
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


# ---- the Antigravity envelope (#306) ----
# Antigravity hands a hook the step, not the tool: `{"toolCall": {"name": "mcp_tool", "args": {...}}}`,
# where args is the MCP step -- a `serverName` and a nested `toolCall` carrying the real tool name and its
# arguments as a JSON string. Normalizing that onto Claude Code's `mcp__<server>__<tool>` spelling here is
# what lets ONE decide() serve both hosts; a second copy of the tier logic is how two hosts start
# disagreeing about what is denied.
_AGY_TOOL = re.compile(rf"^{SERVER}_[A-Za-z0-9_]+$")
# Key spellings are matched CASE-INSENSITIVELY, and that is not defensive programming -- it is what a
# captured payload forced. The host's own hook docs say "All JSON keys in the hook payloads use camelCase
# (protojson encoding)", which holds for the common fields (`conversationId`, `stepIdx`) and NOT for the
# tool call, where a real `call_mcp_tool` step carries `ServerName`, `ToolName` and `Arguments`. Reading
# those as camelCase meant the server was never seen: the bundled allow tier went inert and a bare
# deny-tier name got no decision at all, which is the exact hole this adapter exists to close.
_NAME_KEYS = ("toolName", "tool_name", "name")
_SERVER_KEYS = ("serverName", "server_name")
_JSON_ARG_KEYS = ("argumentsJson", "arguments_json")
_DICT_ARG_KEYS = ("arguments", "args", "toolArgs", "tool_args")


def _ci(d):
    """{lowercased key: value} so a spelling difference cannot hide a tool name or a server from us."""
    return {str(k).lower(): v for k, v in d.items()} if isinstance(d, dict) else {}


def _first_str(d, keys) -> str:
    low = _ci(d)
    for k in keys:
        v = low.get(k.lower())
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _find_named(obj, pattern=None, depth=0) -> str:
    """The first string under a key that NAMES something, anywhere in the step; with `pattern`, the first
    one matching it. The restriction to name-ish keys is deliberate: a free-text argument that happens to
    quote a tool name must not be read as the call being made, which is how a gate starts denying case
    notes."""
    if not isinstance(obj, dict) or depth > 4:
        return ""
    for k, v in obj.items():
        lk = str(k).lower()
        if isinstance(v, str) and v.strip() and ("name" in lk or "tool" in lk) \
                and (pattern is None or pattern.match(v.strip())):
            return v.strip()
        if isinstance(v, dict):
            found = _find_named(v, pattern, depth + 1)
            if found:
                return found
    return ""


def _agy_tool_name(raw: str) -> str:
    """The tool alone, out of whatever spelling the step used for it.

    Observed and documented spellings put the server in front of the tool: `raffkin_exabeam/isolate_host`,
    and the `mcp__<server>__<tool>` form if a step ever carries one. Taking the last segment is what lets
    the tier lookup see the same bare name Claude Code's `bare()` sees."""
    tool = (raw or "").strip().rsplit("/", 1)[-1]
    if "__" in tool:
        tool = tool.rsplit("__", 1)[-1]
    return tool if re.fullmatch(r"[A-Za-z0-9_.-]+", tool or "") else ""


def _unwrap_positional(d):
    """`{"arg0": {...}}` -> `{...}`.

    A captured `call_mcp_tool` step nests the real arguments one level down under positional names:
    `Arguments: {arg0: {caseId: "ABC-123"}}`. Without unwrapping, the audit record keeps the decision but
    loses its `target` -- WHICH case was closed -- and a log that cannot say what was touched is most of
    the way to no log at all."""
    if not isinstance(d, dict) or not d:
        return d
    if all(re.fullmatch(r"arg\d+", str(k)) for k in d):
        merged = {}
        for _, v in sorted(d.items(), key=lambda kv: str(kv[0])):
            if isinstance(v, dict):
                merged.update(v)
        return merged or d
    return d


def _agy_args(inner: dict, args: dict) -> dict:
    """The call's arguments, from the JSON string this host documents or the object it actually sends."""
    raw = _first_str(inner, _JSON_ARG_KEYS)
    if raw:
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001 — unparseable arguments cost the record its target, never the decision
            payload = {}
        if isinstance(payload, dict) and payload:
            return _unwrap_positional(payload)
    for src in (inner, args):
        low = _ci(src)
        for k in _DICT_ARG_KEYS:
            v = low.get(k.lower())
            if isinstance(v, dict):
                return _unwrap_positional(v)
    return {}


# What agy_call() concluded about a step, which is NOT the same question as what to decide:
OURS, OTHER, UNKNOWN, UNREADABLE = "ours", "other", "unknown", "unreadable"


def agy_call(event) -> tuple[str, dict, str]:
    """(tool name in Claude Code's spelling, the call's arguments, what this step is).

    The third value is the one that matters, because on this host the matcher catches every MCP call on the
    machine and only this function can tell them apart:

      OURS     an Exabeam tool: judge it.
      OTHER    the step named a tool or a server, and it is not ours: no decision, quietly. Another
               server's calls must not collect our verdicts.
      UNREADABLE  the step named OUR server but no tool we could read: ask. Standing aside here is the
               hole review found -- our own server's calls going unjudged because the tool name was spelled
               somewhere we do not look.
      UNKNOWN  the step named NOTHING we could recognise. This is the fail-open hole: the payload shape
               here is read from the host's documented contract and its proto descriptor, not from a live
               call, and if it differs then every Exabeam call lands in this branch. Returning OTHER for it
               would mean no decision on a tool we are supposed to be gating, on the host whose docs now
               promise the gate holds -- so it asks instead. The cost of being wrong is a prompt on
               somebody else's MCP call; the cost the other way is a silent ungated close.
    """
    call = event.get("toolCall")
    args = call.get("args") if isinstance(call, dict) else None
    if not isinstance(args, dict):
        return "", {}, UNKNOWN
    low_args = _ci(args)
    inner = low_args.get("toolcall") or low_args.get("tool_call")
    inner = inner if isinstance(inner, dict) else {}
    named_server = _first_str(args, _SERVER_KEYS) or _first_str(inner, _SERVER_KEYS)
    # Deliberately NOT the loose _find_named(args) here: `serverName` is a name-ish key, so a step whose
    # tool sits under a key we do not read would come back with the SERVER as its tool and be reported as
    # an unclassified tool rather than an unreadable step. The loose search stays below, where all it does
    # is tell "somebody else's call" apart from "a shape we cannot read".
    # The tool may be nested under `toolCall` (the documented shape) or sit directly beside the server
    # (what a real `call_mcp_tool` step sends). `name` is read only from the nested object: on the step
    # itself it holds the dispatcher's own name, `call_mcp_tool`, not the tool being dispatched.
    tool = _agy_tool_name(_first_str(inner, _NAME_KEYS)
                          or _first_str(args, ("toolName", "tool_name"))
                          or _find_named(args, _AGY_TOOL))

    if SERVER in named_server.lower():
        # OUR server, so the step is ours whatever the tool is called. Deciding this from the tool name
        # instead is what review caught: half the deny tier is written in bare spellings (`isolate_host`,
        # `disable_account`, `lock_account`, `revoke_session`...) because a hand-wired server exposes them
        # that way, and every one of them was getting no decision here while Claude Code denied it.
        if not tool:
            return "", {}, UNREADABLE       # our server, unreadable tool: ask, never stand aside
        return f"mcp__{named_server}__{tool}", _agy_args(inner, args), OURS
    if named_server:
        return "", {}, OTHER                # somebody else's server: their calls are not ours to judge
    # Nothing said which server. The tool naming itself `exabeam_*` is then the only evidence, and it is
    # enough to judge on -- but not enough to call it the BUNDLED bridge, so an allow-tier read falls
    # through to the operator's own rules rather than being waved past on a guess.
    if not _AGY_TOOL.match(tool):
        return "", {}, (OTHER if (tool or _find_named(args)) else UNKNOWN)
    server = SERVER
    return f"mcp__{server}__{tool}", _agy_args(inner, args), OURS


def emit(host: str, decision: str, reason: str) -> None:
    """The decision, in the envelope the host reads. No decision is silence on Claude Code and an empty
    object on Antigravity, whose contract says a hook writes a JSON object on stdout."""
    if host == "antigravity":
        print(json.dumps({} if decision == NO_DECISION else {"decision": decision, "reason": reason}))
    elif decision != NO_DECISION:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                                 "permissionDecisionReason": reason}}))


def main(argv=None) -> int:
    # --post: this invocation is the PostToolUse record (hooks.json passes it). Decided by the command
    # line, not by stdin, so an unparseable event can never turn a record into a permission decision.
    argv = sys.argv[1:] if argv is None else argv
    post = "--post" in argv
    # The host, like --post, is decided by the command line and not by stdin: an unparseable or hostile
    # event can change neither which envelope we answer in nor whether this call is a record or a verdict.
    host = "antigravity" if "--antigravity" in argv else "claude"
    tool, target, ctx = "", {}, {}
    try:
        raw = sys.stdin.read()
        # Nothing on stdin is not "somebody else's call". It means whatever feeds this hook is broken:
        # review found that with `cat` missing the shell chain delivers an empty payload, python3 then
        # SUCCEEDS on it, the fallback never runs, and the JSONDecodeError below answers `ask` -- the one
        # decision this host overrides under --dangerously-skip-permissions, so the deny tier would be
        # lost in exactly that state. The shell chain now refuses an empty payload before reaching any
        # interpreter; this is the same refusal written where the gate itself can be run directly.
        # Claude Code is left alone on purpose: there `ask` already refuses when nobody can answer.
        if host == "antigravity" and not post and not raw.strip():
            # Deliberately worded to share no phrase with the tier refusal: preflight proves the gate is
            # armed by matching that refusal, and an empty-payload deny must fail that check rather than
            # satisfy it. A deny is still the right answer to the host; it is not evidence of a live gate.
            reason = ("Raffkin gate received no payload on standard input, so it could read nothing about "
                      "this step and refuses rather than standing aside.")
            log_decision({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                          "tool": "", "decision": "deny", "reason": reason, "host": host})
            emit(host, "deny", reason)
            return 0
        event = json.loads(raw)
        if host == "antigravity":
            tool, args, what = agy_call(event)
            if what == OTHER:
                emit(host, NO_DECISION, "")
                return 0                   # not an Exabeam MCP call: this host's matcher sees them all
            if what in (UNKNOWN, UNREADABLE):
                if post:
                    print(json.dumps({}))
                    return 0               # a record we cannot write is not a decision to make
                reason = ("Raffkin gate: this step names the Exabeam MCP server but no tool name the gate "
                          "could read, so it cannot tell which tier the call belongs to and asks rather "
                          "than standing aside." if what == UNREADABLE else
                          "Raffkin gate: this host handed the hook an MCP call it could not identify — no "
                          "tool name and no server name in the step. The gate cannot tell whether this is an "
                          "Exabeam call, so it asks rather than standing aside.")
                log_decision({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                              "tool": "", "decision": "ask", "reason": reason, "host": host})
                emit(host, "ask", reason)
                return 0
            event = dict(event)
            event["session_id"] = str(event.get("conversationId") or "")
            target = target_fields(args)
            ctx = {"host": host}
            step = event.get("stepIdx")
            if isinstance(step, int):
                ctx["tool_use_id"] = f"step-{step}"   # ties a post line to the ask that preceded it
        else:
            tool = str(event.get("tool_name", ""))
            target = target_fields(event.get("tool_input"))
            ctx = _context(event)
        if tool and not is_ours(tool):
            return 0                       # another server's tool: no decision, no record (not our business)
        if post or str(event.get("hook_event_name", "")) == "PostToolUse":
            _post_call(event, tool, target, ctx)
            if host == "antigravity":
                print(json.dumps({}))      # its PostToolUse contract is an empty object, not silence
            return 0
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        decision, reason = decide(tool, load_tiers(root), bundled=is_bundled(tool, plugin_name(root), host))
        if decision == "allow" and bare(tool) in ESCALATION_WRITES:
            ok, why = spend_write_budget(event, bare(tool))
            if not ok:
                decision, reason = "ask", why
    except Exception as e:  # noqa: BLE001 — cannot classify → the human decides; headless → refused
        if post:
            if host == "antigravity":
                print(json.dumps({}))
            return 0                       # a record we cannot write is not a decision to make
        decision, reason = "ask", f"Raffkin gate could not evaluate this call ({type(e).__name__}); asking rather than allowing."
    record = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool": tool, "decision": decision, "reason": reason, **ctx}
    if target:
        record["target"] = target          # what was attempted, on which object — never the free text
    log_decision(record)
    emit(host, decision, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
