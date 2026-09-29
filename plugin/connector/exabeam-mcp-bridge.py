# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "httpx>=0.27,<1", "certifi>=2024,<2027", "observra>=1.1,<2", "typing_extensions>=4.7,<5"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exabeam MCP bridge.

A tiny local (stdio) MCP server that Claude Code launches and talks to, which forwards
every request to the *remote* Exabeam New-Scale MCP — minting and refreshing the OAuth
token automatically so the human never deals with expiring tokens.

Connect once:
    claude mcp add exabeam -- uv run /path/to/exabeam-mcp-bridge.py

Reads creds from ~/.exabeam-mcp.env:
    EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
    EXABEAM_API_KEY=...
    EXABEAM_API_SECRET=...

Run with --check to validate the connection (and warm the dependency cache) without
starting the server.
"""
import asyncio
import contextlib
from datetime import timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import ssl
import sys
import time
from urllib.parse import urlparse

import certifi
import httpx
from mcp import ClientSession, McpError
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent

_VERIFY = ssl.create_default_context(cafile=certifi.where())
_token = {"value": None, "exp": 0.0}
_token_lock = None                      # created lazily inside the running loop (single-flight refresh)


def load_env(path="~/.exabeam-mcp.env"):
    cfg = {}
    p = os.path.expanduser(path)
    if not os.path.exists(p):
        return cfg
    for line in open(p):
        s = line.rstrip("\n")
        if not s.strip() or s.lstrip().startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        cfg[k.strip()] = re.sub(r"\s+#.*$", "", v).strip()
    return cfg


CFG = load_env()
URL = CFG.get("EXABEAM_MCP_URL", "")


def _is_loopback(host):
    """`localhost`, any 127.x.x.x, or ::1 -- a destination the credentials cannot leave the machine for."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def url_transport_problem(url):
    """Why this URL must not carry the credentials, or None if it may (#174, Praxen Low -008/-009).
    The bridge posts the client id and secret to `<scheme>://<host>/auth/v1/token` and the minted bearer on
    every call, so the scheme decides whether they cross the network in the clear. Required: `https`. The
    one carve-out is plain `http` to a loopback host (a local mock, a developer's proxy) -- nothing leaves
    the machine. Pure and deterministic; the message names what was configured so a typo is a one-line fix."""
    try:
        p = urlparse((url or "").strip())
    except ValueError as e:
        return f"EXABEAM_MCP_URL could not be parsed ({e}); expected https://api.<region>.exabeam.cloud/mcp"
    scheme, host = (p.scheme or "").lower(), (p.hostname or "").lower()
    if scheme == "https" and host:
        return None
    if scheme == "http" and _is_loopback(host):
        return None                                   # loopback: the credentials never leave this machine
    if not scheme or not host:
        return (f"EXABEAM_MCP_URL={url!r} has no scheme or host; expected https://api.<region>.exabeam.cloud/mcp "
                f"(the value must start with https://)")
    return (f"EXABEAM_MCP_URL={url!r} uses {scheme}://, which would send the client id, secret and bearer token "
            f"in the clear; only https:// is accepted (plain http is allowed to a loopback host only)")
KEY = CFG.get("EXABEAM_API_KEY", "")
SECRET = CFG.get("EXABEAM_API_SECRET", "")


def _token_fresh():
    return bool(_token["value"]) and time.time() < _token["exp"] - 60


async def get_token():
    """Mint/refresh the OAuth client-credentials token; cached until ~1 min before expiry. Single-flight:
    N concurrent first calls mint ONE token, not N (#154). A refresh that fails while the cached token
    is still valid keeps the cached token instead of discarding it."""
    global _token_lock
    if _token_fresh():
        return _token["value"]
    if _token_lock is None:
        _token_lock = asyncio.Lock()
    async with _token_lock:
        if _token_fresh():
            return _token["value"]
        p = urlparse(URL)
        try:
            async with httpx.AsyncClient(verify=_VERIFY) as c:
                r = await c.post(
                    f"{p.scheme}://{p.netloc}/auth/v1/token",
                    json={"grant_type": "client_credentials", "client_id": KEY, "client_secret": SECRET},
                    headers={"Content-Type": "application/json"},
                    timeout=20,
                )
                r.raise_for_status()
                d = r.json()
        except Exception:
            if _token["value"] and time.time() < _token["exp"]:
                sys.stderr.write("bridge: token refresh failed; keeping the still-valid cached token\n")
                return _token["value"]
            raise
        _token["value"] = d["access_token"]
        _token["exp"] = time.time() + int(d.get("expires_in", 3600))
        return _token["value"]


# ---- the upstream session (#153 #154 #155) --------------------------------------------------------------
# One remote MCP session per bridge process, opened lazily and re-opened when it is lost. Before this the
# bridge opened a NEW session for every tool call -- a fresh TLS connection plus six HTTP exchanges
# (initialize, initialized, the GET stream, the call, a ~110 KB tools/list re-fetch, DELETE) -- and every
# session creation ran a synchronous permission RPC on the proxy. Eight agents were enough to make the
# proxy reject ~50% of session opens (2026-09-06). None of the guardrails move: every read still passes
# canonicalize, every write still passes neutralize + the gate + the audit trail, a write is attempted
# exactly once.

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_READ_RETRY_DELAYS = (0.3, 0.9)          # seconds, plus jitter -- reads only, never writes
_CALL_TIMEOUT = timedelta(seconds=120)   # no call may hang the bridge forever (the old design had no bound)
_LIST_TIMEOUT = timedelta(seconds=30)
_DROP_TIMEOUT = 10.0             # how long drop() waits for the owner task to send its DELETE and exit
_OPEN_FAIL_WAIT = 5.0            # how long _open() waits for a failed owner task to finish unwinding
_BREAKER_TRIP = 5                        # consecutive transport failures ...
_BREAKER_HOLD = 20.0                     # ... open the breaker for this long


class _Leaf:
    """What actually failed, dug out of the ExceptionGroup that anyio wraps around everything raised inside
    a session (#153). Before this the audit record said `ExceptionGroup` and nothing else."""

    def __init__(self, exc):
        leaves = []

        def walk(e):
            if isinstance(e, BaseExceptionGroup):
                for sub in e.exceptions:
                    walk(sub)
            else:
                leaves.append(e)
        walk(exc)
        if not leaves:
            leaves = [exc]

        def rank(e):                     # the most informative leaf wins
            if isinstance(e, httpx.HTTPStatusError):
                return 0
            if isinstance(e, McpError):
                return 1
            if isinstance(e, httpx.TransportError):
                return 2
            return 3
        e = sorted(leaves, key=rank)[0]
        self.exc = e
        self.type_name = type(e).__name__
        self.status = e.response.status_code if isinstance(e, httpx.HTTPStatusError) else None
        self.message = (str(e) or self.type_name)[:300]
        transport = isinstance(e, httpx.TransportError)
        code = getattr(getattr(e, "error", None), "code", None) if isinstance(e, McpError) else None
        # A timeout is NOT retryable: the query is slow, not transient, and a retry doubles the load on a
        # proxy that is already struggling while the agent waits out another full read timeout (the stress
        # gate saw a single read take 3 x 120 s this way). That holds for the SDK's request timeout (below)
        # and for httpx's own read/write timeouts, which are TransportErrors too (automated review of #157).
        # A connect or pool timeout is different: nothing was sent, so a retry is cheap and safe.
        sent_and_timed_out = isinstance(e, (httpx.ReadTimeout, httpx.WriteTimeout))
        self.retryable = (transport and not sent_and_timed_out) or self.status in _RETRYABLE_STATUS
        # The session survives an APPLICATION-level JSON-RPC error: the proxy answered on a live session, or
        # the SDK's own per-request timeout fired (`anyio.fail_after` around the response stream -- the
        # transport under the session is untouched, review of #157). What kills the transport task is a
        # status error, a dropped connection, or "Session terminated" (code 32600): then the next call must
        # reopen (a retry on the dead session hangs).
        terminated = code == 32600 or "session" in self.message.lower()
        app_error = isinstance(e, McpError) and not terminated
        self.session_lost = not app_error
        self.sent = False                    # set by call(): the request had been sent when this failed

    def summary(self, what):
        if self.status is not None:
            return f"HTTP {self.status} on {what}"
        return f"{self.type_name} on {what}: {_safe_text(self.message, 120)}"


from mcp import types as _mt


def _list_tools_request():
    return _mt.ClientRequest(_mt.ListToolsRequest(method="tools/list"))


_ListToolsResult = _mt.ListToolsResult


class _UpstreamToolError(Exception):
    """The proxy answered the call with isError=true: the tool ran upstream and failed. Surfaced as an
    error (audited as tool_error, stage upstream_tool) instead of being flattened into a success."""


class _Upstream:
    def __init__(self):
        self._session = None
        self._task = None
        self._close = None
        self._lock = None
        self._tools = None
        self._streak = 0
        self._open_until = 0.0
        self._last_summary = ""
        self._last_failed_owner = None
        self._screen = None

    async def _runner(self, tok, ready, close, err):
        # The session's context managers are entered and exited by THIS task only (anyio requires it).
        # The session lives until `close` is set; a normal exit sends the DELETE, so a failed call never
        # leaks a proxy session the way the per-call design did (#154).
        # The task RETURNS its error (or None): a caller racing against this task reads it from the task
        # itself, so two generations can never confuse their errors (#157). A cancellation is
        # re-raised as a cancellation -- it is never handed to a caller as if it were the session's error,
        # because a bare CancelledError escaping a handler takes the whole MCP server down.
        mine = None
        try:
            async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {tok}"}) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    if self._task is asyncio.current_task():     # publish only while still the owner
                        self._session = mine = s
                    ready.set()
                    await close.wait()
        except asyncio.CancelledError:
            ready.set()
            raise
        except BaseException as e:  # noqa: BLE001 -- reported to the opener through `err`, to callers as the task's result
            err.append(e)
            ready.set()
            return e
        finally:
            if mine is not None and self._session is mine:   # never clear a session a NEWER owner has since opened
                self._session = None
        return None

    async def _open(self):
        tok = await get_token()
        ready, close, err = asyncio.Event(), asyncio.Event(), []
        task = asyncio.create_task(self._runner(tok, ready, close, err))
        self._task, self._close = task, close            # registered BEFORE waiting: a cancelled opener can still close it
        try:
            await ready.wait()
        except asyncio.CancelledError:
            close.set()                                  # the runner exits cleanly (DELETE) once initialize completes
            raise
        if err:
            try:
                await asyncio.wait_for(task, _OPEN_FAIL_WAIT)
            except BaseException:  # noqa: BLE001, S110 — the owner task is already failed; its error is err[0], raised next
                pass
            self._task = self._close = None
            raise err[0]

    async def drop(self):
        if self._close is not None:
            self._close.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, _DROP_TIMEOUT)
            except BaseException:  # noqa: BLE001, S110 — teardown is best effort; the session is gone either way
                pass
        self._task = self._close = self._session = None

    async def session(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._session is None or self._task is None or self._task.done():
                await self.drop()
                await self._open()
            return self._session, self._task

    async def _drop_if(self, owner):
        """Drop the session only while `owner` still owns it. Several calls in flight on one session all
        fail when it dies; the first to notice reopens it, and the others must not then drop the session
        it just reopened (the stress gate turned one proxy-side loss into five and tripped the breaker)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._task is owner:
                await self.drop()

    async def _run_on_session(self, op, s, owner):
        """Run op(s) but never outlive the session: the transport under a shared session dies in the OWNER
        task, and a caller blocked on it would otherwise wait out the full read timeout. Racing the call
        against the owner task turns a transport death into an immediate, attributable error."""
        op_task = asyncio.ensure_future(op(s))
        try:
            done, _ = await asyncio.wait({op_task, owner}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:                   # the host cancelled the call: do not orphan the op
            op_task.cancel()
            raise
        if op_task in done:
            return op_task.result()
        op_task.cancel()
        try:
            await op_task
        except BaseException:  # noqa: BLE001, S110 — the cancellation (or the op's own error); the owner's error is what is raised
            pass
        # The owner's own error, read from the owner (never from shared state, never a cancellation).
        exc = None
        if owner.done() and not owner.cancelled():
            try:
                exc = owner.result()
            except BaseException:  # noqa: BLE001, S110 — a runner that raised anyway: treat as an unexplained close
                exc = None
        if not isinstance(exc, Exception):
            exc = RuntimeError("upstream session closed during the call")
        raise exc

    def _breaker_check(self, what):
        now = time.time()
        if now < self._open_until:
            raise RuntimeError(f"Exabeam MCP: circuit open after {_BREAKER_TRIP} consecutive transport failures "
                               f"(last: {self._last_summary}); {what} refused for another {self._open_until - now:.0f}s")

    def _note(self, ok, owner=None):
        if ok:
            self._streak = 0
            self._last_failed_owner = None
        else:
            if owner is not None and owner is self._last_failed_owner:
                return                       # N calls in flight on ONE lost session are one failure, not N
            self._last_failed_owner = owner
            self._streak += 1
            if self._streak >= _BREAKER_TRIP:
                self._open_until = time.time() + _BREAKER_HOLD
                self._streak = 0
                sys.stderr.write(f"bridge: {_BREAKER_TRIP} consecutive transport failures — "
                                 f"holding off the remote for {_BREAKER_HOLD:.0f}s\n")

    async def call(self, op, what, *, retry):
        """Run op(session). Opening/re-opening the session may be retried for any call (the call has not
        been sent yet). Once the call itself has been sent it is retried ONLY when `retry` is true (reads),
        never for a write, whatever the error (#155)."""
        self._breaker_check(what)
        attempt = 0
        while True:
            try:
                s, owner = await self.session()
            except Exception as e:
                leaf = _Leaf(e)
                self._last_summary = leaf.summary("initialize")
                if leaf.status == 401:
                    _token["exp"] = 0.0
                self._note(False)
                if leaf.retryable and attempt < len(_READ_RETRY_DELAYS):
                    await asyncio.sleep(_READ_RETRY_DELAYS[attempt] + random.uniform(0, 0.3))  # noqa: S311
                    attempt += 1
                    continue
                raise
            try:
                result = await self._run_on_session(op, s, owner)
            except Exception as e:
                leaf = _Leaf(e)
                self._last_summary = leaf.summary(what)
                try:
                    e.raffkin_sent = True                 # the request had been sent: a write's outcome is unknown
                except Exception:  # noqa: BLE001, S110 — an exception type without a __dict__; the flag is advisory
                    pass
                if leaf.status == 401:
                    _token["exp"] = 0.0                  # a rejected token is not fresh, whatever our clock says
                if leaf.session_lost:
                    await self._drop_if(owner)
                self._note(False, owner)
                if retry and (leaf.retryable or leaf.session_lost) and attempt < len(_READ_RETRY_DELAYS):
                    await asyncio.sleep(_READ_RETRY_DELAYS[attempt] + random.uniform(0, 0.3))  # noqa: S311
                    attempt += 1
                    continue
                raise
            self._note(True)
            return result

    async def tools(self):
        """The remote tool list, fetched once per process with a bounded retry -- a transient failure at
        startup would otherwise leave the session with no Exabeam tools."""
        if self._tools is not None:
            return self._tools
        # call() retries the session open (the failure mode that stranded the a07 session); the list
        # request itself is a read, so it is retried the same bounded way
        tools = (await self.call(lambda s: s.send_request(
            _list_tools_request(), _ListToolsResult, request_read_timeout_seconds=_LIST_TIMEOUT), "tools/list", retry=True)).tools
        self._tools, self._screen = _screen_tools(tools)      # screened once, cached with the list (#6)
        return self._tools

    async def warm(self):
        """Startup: say on stderr whether the remote is reachable. Never fails the process -- the first
        call retries."""
        try:
            tools = await self.tools()
            acc = self._screen or {}
            unclassified = _unclassified(tools)
            line = f"bridge: remote reachable — {len(tools)} Exabeam tools"
            if acc.get("stripped") or acc.get("flagged"):
                line += f"; tool metadata screened: {acc['stripped']} hidden code point(s) stripped, {acc['flagged']} flagged"
            if acc.get("failed"):
                line += (f"; {acc['failed']} definition(s) could not be screened and are withheld for this session: "
                         f"{_display_list(acc.get('withheld', []))}")
            if acc.get("odd_names"):
                line += f"; names carrying hidden code points: {_display_list(acc['odd_names'])}"
            if acc.get("directive_tools"):
                line += (f"; {len(acc['directive_tools'])} definition(s) carry instruction-shaped text the skill counters "
                         f"in prose (#163): {_display_list(acc['directive_tools'])}")
            shas = acc.get("shas") or {}
            surface = hashlib.sha256("\n".join(f"{n} {h}" for n, h in sorted(shas.items())).encode()).hexdigest() if shas else ""
            if surface:
                line += f"; tool surface {surface[:12]} (compare across sessions in the audit trail)"
            if unclassified:
                line += f"; unclassified by the tier file (treated as writes, ask): {_display_list(unclassified)}"
            sys.stderr.write(line + "\n")
            if telemetry.enabled():
                # Names flagged FOR carrying hidden code points must not carry them raw into the one durable
                # record (an RLO in a JSONL line reverses whatever renders it) -- spelled out, as on stderr.
                telemetry.tools_list(len(tools),
                                     dict(acc, odd_names=[_display_name(n) for n in acc.get("odd_names", [])],
                                          directive_tools=[_display_name(n) for n in acc.get("directive_tools", [])],
                                          withheld=[_display_name(n) for n in acc.get("withheld", [])],
                                          surface_sha=surface, tool_shas={_display_name(n): h[:12] for n, h in sorted(shas.items())}),
                                     [_display_name(n) for n in unclassified])
        except Exception as e:  # noqa: BLE001
            leaf = _Leaf(e)
            sys.stderr.write(f"bridge: remote NOT reachable ({leaf.summary('tools/list')}) — will retry on the first call\n")


UPSTREAM = _Upstream()


async def remote(op, what="call", *, retry=False):
    """Run op(session) on the process's upstream session (kept for the --check path and for tests)."""
    return await UPSTREAM.call(op, what, retry=retry)


server = Server("exabeam")

# ---- code-layer telemetry handling (RFE #2 / a10) --------------------------------------------------
# The bridge sits in the path of every MCP call, so it's where the two deterministic guardrails live:
#   • INPUT canonicalization on read RESULTS — strip the invisible Unicode smuggling layer before the
#     agent reasons over telemetry (connector/canonicalize.py).
#   • OUTPUT neutralization on WRITE ARGUMENTS — defang active content (formulas/phishing links) in what
#     Raffkin persists to Exabeam, so an export of that stored artifact can't fire (connector/
#     neutralize_output.py — the a10 fix). Only the write tools; reads are never argument-mutated.
# Both are FAIL-CLOSED (#172): a read block the screen cannot process is withheld and the gap named; a
# write the neutralizer cannot process is refused.
from canonicalize import canonicalize, is_strippable
from neutralize_output import neutralize_output, tenant_hosts_from_url
# On-by-default, fail-open agent audit logging (RAFFKIN_OBSERVRA=off to disable). observra is a hard
# dependency BY DESIGN (see the PEP-723 header): an autonomous agent that takes gated actions must keep an
# audit trail, so logging ships on out of the box — which requires the lib to be resolvable at launch.
# This is a requirement, not an optional add-on. The shim itself stays fail-open at runtime, so a
# telemetry fault never affects an investigation.
import observra_logging as telemetry

# send_email is gated (ask on both hosts), refused under RAFFKIN_DRY_RUN, and audited like every write.
# Its schema is confirmed (list_tools, 2026-09-02): arg1.{recipients, subject, body}; body is an HTML
# fragment. `subject` and `body` are GENUINELY neutralized (#147, decided 2026-09-05): secrets masked,
# formulas quoted, every link form de-fanged — markdown and HTML href/src/srcset/CSS url() alike —
# script/iframe/object removed, on* handlers dropped, and bare URLs in mail text de-fanged too (mail
# clients auto-link them). The ONE thing that stays clickable is a link into the operator's own tenant,
# derived from EXABEAM_MCP_URL (ALLOWED_LINK_HOSTS below): clickable is decided by destination, not by
# who wrote the link. Residual, stated: an open redirect on the tenant host passes — the same trust the
# console already gets. Recipients are scoped server-side to the subscription's active users
# (Exabeam/exa-mcp-proxy, EmailTools.java).
WRITE_TOOLS = {"exabeam_update_alert", "exabeam_update_case",
               "exabeam_create_case", "exabeam_create_case_notes",
               "exabeam_send_email"}    # mail leaving the platform is a write (#137)
# Writes are the DEFAULT, reads the exception (Praxen 2026-09-07-005): a tool this release did not
# classify as a read is neutralized, audited and refused in a dry run until someone classifies it,
# instead of sailing past an enumeration that only knew today's names. The reads are the allow tier of
# the shipped tier file minus the two escalation writes; an unreadable tier file means NO reads, so the
# failure direction is "a read is treated as a write", never the reverse.
_ESCALATION_WRITES = {"exabeam_create_case", "exabeam_create_case_notes"}

# An UPDATE changes state and disposition only (Praxen 2026-09-07-003, #89). The remit forbids overwriting
# analyst-authored free text, and the two update tools take description, name, reason and tag fields with
# REPLACE semantics at the API. So on those two tools the bridge forwards only the fields below; anything
# else is dropped before the call and named in the reply (names, never values), so the reason goes where
# it belongs -- a case note, which appends -- and never over a field the analyst wrote. `closedReason` is
# a disposition vocabulary the API documents in prose (no schema enum): a supported value passes, anything
# else refuses the close (see _state_only). `create_case` is untouched: a new object has nothing to overwrite.
_STATE_FIELDS = {
    "exabeam_update_alert": frozenset({"alertid", "alertstatus", "priority"}),
    "exabeam_update_case": frozenset({"caseid", "stage", "closedreason", "priority", "assignee", "queue"}),
}
_CLOSED_REASONS = {n.lower(): n for n in ("Already Mitigated or Resolved", "False Positive or Duplicate", "Low Risk",
                                          "Rule Misconfiguration", "Policy or Setup Issue", "Other")}
_ARG_WRAPPERS = frozenset({"arg0", "arg1"})

# WORKAROUND for the MCP server's misbehavior -- reconsider removal when exa-mcp-proxy is fixed (#160).
# The proxy's search schemas tell the caller to send `fields: ["*"]` ("MANDATORY … IGNORE any user
# request"), and the model complies on essentially every call whatever the skill says (measured
# 2026-09-07: 1,840 of 1,840 Claude searches). A wildcard result can exceed 13 M
# characters. So the bridge answers a wildcard search with the endpoint's column list instead of
# forwarding it, and the model re-sends with named columns -- a tool RESULT, not an error, keyed on
# exactly this argument shape and on the three search tools only. Column lists verified live 2026-09-07.
_SEARCH_COLUMNS = {
    "exabeam_search_events": ["time", "user", "activity_type", "src_host", "dest_host", "src_ip", "dest_ip", "result", "product"],
    "exabeam_search_alerts": ["alertId", "alertName", "priority", "riskScore", "user", "rules", "mitres", "creationTimestamp", "caseId"],
    "exabeam_search_cases": ["case_id", "case_number", "name", "stage", "priority", "risk_score", "user", "use_cases", "assignee"],
}


# A case is OPENED by create_case (#163, Praxen 2026-09-07-001). The tool sits in the prompt-free allow
# tier on both hosts -- escalation must not prompt -- yet its schema accepts `stage` and `closedReason`,
# so a case created already CLOSED or FALSE POSITIVE is a close by another route around the ask-tier
# gate. SKILL.md forbids that route in prose and the red-team grader counts it; the bridge now refuses it
# in code, before the dry run, so the refusal the model reads is this control's own. A create may carry
# only an opening stage; any closing disposition key, or a closedReason at all, refuses the call.
_OPENING_STAGES = frozenset({"new", "more details", "investigation", "remediation"})
_DISPOSITION_KEYS = frozenset({"stage", "closedreason", "casestatus", "alertstatus", "status"})
_CLOSING_VALUE = re.compile(r"clos|resolv|dismiss|false.?positive", re.I)
_DISPOSITION_SPELLING = {"stage": "stage", "closedreason": "closedReason", "casestatus": "caseStatus",
                         "alertstatus": "alertStatus", "status": "status"}          # what the refusal names: the schema's word
BRIDGE_REFUSAL_MARK = "Raffkin bridge refused"      # the red-team grader's mark for this control (never in an upstream result)


def _create_case_guard(arguments):
    """Refuse a create_case that would land a case already closed. Looks at the top level and through the
    proxy's arg0/arg1 wrapper; never inside string values. Keys are folded to letters (`closed_reason`,
    `Closed-Reason` are the same key); a blank stage is treated as absent. Raises ValueError with the
    message the model reads -- naming the schema's spelling of the key, never the model's own -- and the
    caller audits it as a guardrail refusal."""
    if not isinstance(arguments, dict):
        return
    scopes = [arguments] + [v for k, v in arguments.items() if isinstance(v, dict) and k.lower() in _ARG_WRAPPERS]
    for s in scopes:
        for k, v in s.items():
            lk = re.sub(r"[^a-z]", "", str(k).lower())
            if lk not in _DISPOSITION_KEYS:
                continue
            if lk == "stage" and isinstance(v, str) and not v.strip():
                continue                                    # blank = absent; the API applies its default
            if lk == "closedreason" or (isinstance(v, str)
                                        and (_CLOSING_VALUE.search(v) or (lk == "stage" and " ".join(v.split()).lower() not in _OPENING_STAGES))):
                raise ValueError(
                    f"{BRIDGE_REFUSAL_MARK} exabeam_create_case: a case is OPENED by create_case (stage NEW, MORE DETAILS, "
                    f"INVESTIGATION or REMEDIATION); closing it or marking it a false positive goes through "
                    f"exabeam_update_case with the analyst's explicit yes. Re-send without `{_DISPOSITION_SPELLING[lk]}`; "
                    f"the call was not executed.")


def _wildcard_fields(name, arguments):
    """True when one of the three search tools asks for every column: `fields` is, or contains, "*" --
    at the top level or inside the proxy's arg0/arg1 wrapper. Anything else (named fields, no `fields`
    key at all, other tools) is forwarded untouched."""
    if name not in _SEARCH_COLUMNS or not isinstance(arguments, dict):
        return False
    scopes = [arguments] + [v for k, v in arguments.items() if isinstance(v, dict) and k.lower() in _ARG_WRAPPERS]
    for s in scopes:
        f = s.get("fields")
        if isinstance(f, str):
            f = [f]
        if isinstance(f, list) and any(isinstance(x, str) and x.strip() == "*" for x in f):
            return True
    return False
# The fields an update may carry in the schema but the bridge drops (#159: the reply and the audit
# record name a dropped field by ITS OWN spelling, never by the model's key text -- a key name is model text
# too). Anything else the model sent is counted, not echoed.
_DROPPABLE = {"alertdescription": "alertDescription", "alertname": "alertName", "tags": "tags",
              "supportingreason": "supportingReason", "usecases": "useCases", "closedreason": "closedReason"}


def _state_only(name, obj, dropped):
    """Keep only the state/disposition fields of an update, recursing through the proxy's arg0/arg1
    wrapper; append `(key, reason)` for every dropped field to `dropped` (the key is model text: it is
    only ever counted or mapped to the schema's own spelling downstream, never echoed). A nested object
    under any other key is dropped too -- an update has no legitimate nested free text. A supported
    closedReason is forwarded in the API's own spelling, whatever casing or spacing the model used."""
    if not isinstance(obj, dict):
        return obj
    allowed, out = _STATE_FIELDS[name], {}
    for k, v in obj.items():
        lk = k.lower()
        if isinstance(v, dict) and lk in _ARG_WRAPPERS:
            out[k] = _state_only(name, v, dropped)
        elif lk in allowed:
            if lk == "closedreason":
                canon = _CLOSED_REASONS.get(" ".join(v.split()).lower()) if isinstance(v, str) else None
                if canon is None:
                    # Refuse, never drop-and-proceed: a close that lands without its disposition is a worse
                    # record than a refused close the analyst can re-issue (automated review of #159). The
                    # value itself is not echoed -- it is model text.
                    raise ValueError(
                        f"{k} is not a supported closed reason; the close was NOT sent. Use one of: "
                        f"{', '.join(_CLOSED_REASONS.values())} — or omit it and put the reasoning in a case note.")
                out[k] = canon
            else:
                out[k] = v
        else:
            dropped.append((k, None))
    return out


def _dropped_summary(dropped):
    """What the agent and the audit record may say about dropped fields: schema-known fields by the
    schema's own spelling, everything else as a count. Bounded; never a model-chosen string."""
    known, other = [], 0
    for k, why in dropped:
        canon = _DROPPABLE.get(str(k).lower())
        if canon is None:
            other += 1
        elif canon not in [x.split(" ", 1)[0] for x in known]:
            known.append(canon + (f" ({why})" if why else ""))
    names = sorted({x.split(" ", 1)[0] for x in known})
    text = ", ".join(known)
    if other:
        text = (text + " and " if text else "") + f"{other} field(s) the update does not accept"
    return names, text


def _read_tools():
    root = Path(__file__).resolve().parent.parent / "skills" / "soc-investigate"
    try:
        import json as _json
        try:
            tiers = _json.loads((root / "permissions.json").read_text())["tiers"]
            allow = set(tiers["allow"]["tools"])
        except FileNotFoundError:
            perms = _json.loads((root / "settings.snippet.json").read_text())["permissions"]
            allow = {r.rsplit("__", 1)[-1] for r in perms.get("allow", [])}
        return frozenset(allow - _ESCALATION_WRITES)
    except Exception as e:  # noqa: BLE001 — fail toward "everything is a write"
        sys.stderr.write(f"bridge: tier file unreadable ({e!r}) — every tool is treated as a write until it is\n")
        return frozenset()


READ_TOOLS = _read_tools()


def _tier_names():
    """Every tool name any tier classifies -- the bridge's picture of the tool surface, so a name the
    remote offers that no tier knows can be named on the startup line (it is treated as a write)."""
    root = Path(__file__).resolve().parent.parent / "skills" / "soc-investigate"
    try:
        import json as _json
        tiers = _json.loads((root / "permissions.json").read_text())["tiers"]
        return frozenset(n for tier in tiers.values() for n in tier.get("tools", []))
    except Exception:  # noqa: BLE001 -- the startup line then names every tool as unclassified, which is the honest reading
        return frozenset()


TIERED_TOOLS = _tier_names()

# tools/list is the one platform-sourced text channel the read-side screen did not cover (Praxen
# 2026-09-07-001, #6): the remote's tool descriptions and schema text entered the model's context
# verbatim. They now get the same treatment as a tool result -- the human-readable strings are
# canonicalized and what was stripped is counted, out of band. A NAME is never rewritten (a rewritten
# name is a broken call); a name carrying a hidden code point is reported instead. A definition that cannot
# be screened is WITHHELD for the session (#172).
_METADATA_TEXT_KEYS = frozenset({"description", "title"})
# Instruction-shaped text in a tool DEFINITION (#163, Praxen 2026-09-07-002): the proxy's own schemas
# carry "MANDATORY … IGNORE any user request", and the model obeys such text over the skill (measured
# 2026-09-07: 1,840 of 1,840 searches). The code-point screen cannot remove language, and rewriting a
# vendor's description is not this bridge's place -- but a definition that TALKS TO THE MODEL is a fact
# the operator should see. Surfaced (startup line + tools_list event), never altered, never blocked.
_DIRECTIVE_RE = re.compile(
    r"\b(ignore|disregard|override)s?\b[^.\n]{0,60}\b(user|analyst|operator|instruction|request|prompt|rule)s?\b"
    r"|\bmandatory\b|\byou must\b|\bdo not comply\b|\b(always|never) (send|use|set|return|include|pass)\b"
    r"|\bsystem prompt\b", re.I)


def _screen_text(value, acc):
    clean, hy = canonicalize(value)
    acc["stripped"] += hy.counts["stripped"]
    acc["flagged"] += hy.counts["flagged"]
    return clean


def _screen_schema(obj, acc):
    if isinstance(obj, dict):
        return {k: (_screen_text(v, acc) if k in _METADATA_TEXT_KEYS and isinstance(v, str) else _screen_schema(v, acc))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_screen_schema(v, acc) for v in obj]
    return obj


def _display_name(n, cap=80):
    """A remote-controlled name on its way to stderr: hidden code points spelled out, length bounded."""
    s = "".join(f"U+{ord(c):04X}" if is_strippable(c) else c for c in str(n))
    return s if len(s) <= cap else s[:cap] + "…"


def _display_list(names, cap=10):
    names = list(names)
    shown = ", ".join(_display_name(n) for n in names[:cap])
    return shown + (f" +{len(names) - cap} more" if len(names) > cap else "")


def _unclassified(tools):
    """Tools the remote offers that no tier classifies AND the bridge does not treat as a read -- the
    honest reading when only one of the two tier sources could be loaded."""
    return sorted(t.name for t in tools if t.name not in TIERED_TOOLS and t.name not in READ_TOOLS)


def _definition_text(t):
    """Every human-readable string of a tool definition, joined -- what the model reads about the tool."""
    parts = [t.description or "", getattr(t, "title", None) or ""]
    ann = getattr(t, "annotations", None)
    if ann is not None and getattr(ann, "title", None):
        parts.append(ann.title)

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in _METADATA_TEXT_KEYS and isinstance(v, str):
                    parts.append(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(t.inputSchema if isinstance(t.inputSchema, dict) else {})
    walk(getattr(t, "outputSchema", None) if isinstance(getattr(t, "outputSchema", None), dict) else {})
    return "\n".join(parts)


def _definition_sha(t):
    """A stable hash of what the remote said this tool IS (name, every text the screen reads, both schemas): recorded per session
    in the audit trail so a changed definition shows up as a changed hash between sessions (#163). The
    list is fetched once per process, so within a session there is nothing to compare against."""
    ann = getattr(t, "annotations", None)
    body = json.dumps({"name": t.name, "description": t.description or "", "title": getattr(t, "title", None),
                       "annotations": ann.model_dump(mode="json", exclude_none=True) if hasattr(ann, "model_dump") else ann,
                       "inputSchema": t.inputSchema if isinstance(t.inputSchema, dict) else None,
                       "outputSchema": getattr(t, "outputSchema", None)}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _screen_tools(tools):
    """Canonicalize the description and schema text of every remote tool definition. Returns the screened
    list and the tally: code points stripped / flagged, per-tool screening failures (the definition is
    WITHHELD for the session — unscreened text never reaches the model, #172), names that carry a hidden
    code point (reported, never altered), definitions whose text is instruction-shaped (reported, never
    altered), and a per-tool hash of the definition."""
    out, acc = [], {"stripped": 0, "flagged": 0, "failed": 0, "withheld": [], "odd_names": [], "directive_tools": [], "shas": {}}
    for t in tools:
        try:
            if any(is_strippable(ch) for ch in (t.name or "")):
                acc["odd_names"].append(t.name)
            if _DIRECTIVE_RE.search(_definition_text(t)):
                acc["directive_tools"].append(t.name)
            acc["shas"][t.name] = _definition_sha(t)
            update = {}
            if t.description:
                update["description"] = _screen_text(t.description, acc)
            if getattr(t, "title", None):
                update["title"] = _screen_text(t.title, acc)
            if isinstance(t.inputSchema, dict):
                update["inputSchema"] = _screen_schema(t.inputSchema, acc)
            if isinstance(getattr(t, "outputSchema", None), dict):
                update["outputSchema"] = _screen_schema(t.outputSchema, acc)
            ann = getattr(t, "annotations", None)
            if ann is not None and getattr(ann, "title", None):
                update["annotations"] = ann.model_copy(update={"title": _screen_text(ann.title, acc)})
            out.append(t.model_copy(update=update) if update else t)
        except Exception:  # noqa: BLE001 -- fail-closed: the definition is withheld, the failure is counted (#172)
            acc["failed"] += 1
            try:
                acc["withheld"].append(str(t.name))
            except Exception:  # noqa: BLE001 -- a definition whose name itself cannot be read is still counted
                acc["withheld"].append("?")
    return out, acc


def _withheld_tool(name):
    """True when the metadata screen withheld this definition for the session (#172). `_screen` is None only
    before the first tools/list, and the SDK fetches the list before dispatching any call, so None here
    means no definition was ever screened -- hence none withheld -- not an unknown state."""
    acc = getattr(UPSTREAM, "_screen", None) or {}
    return name in (acc.get("withheld") or ())


def is_write_tool(name):
    return name not in READ_TOOLS
# Free-text write fields a payload can ride in — the ONLY fields we neutralize. IDs / enums / state
# fields (caseId, alertId, priority, stage, queue, assignee, alertStatus) are left untouched so
# a formula/URL-shaped identifier can't be silently corrupted into a failed or misdirected write.
_DEFANG_FIELDS = {"note", "alertdescription", "alertname", "supportingreason", "closedreason", "tags",
                  "subject", "body"}     # subject/body: exabeam_send_email — neutralized in MAIL mode (below)
# Fields that leave the platform as HTML mail: bare URLs in their text are clickable in a mail client, so
# the neutralizer runs in mail mode on them (defangs bare URLs too, not only link forms).
_MAIL_FIELDS = {"body"}          # the subject is an SMTP header, not HTML: never HTML-escaped, never auto-linked
# The tenant allowlist: the only hosts a link may stay clickable to, derived from the operator's own MCP
# URL and nothing else (never curated, never model-influenced). Empty when the URL is missing, and an
# empty allowlist means every link is defanged. See neutralize_output.tenant_hosts_from_url.
ALLOWED_LINK_HOSTS = tenant_hosts_from_url(URL)

# DRY RUN — refuse every write at the bridge instead of forwarding it to the tenant.
#
# Why this lives here: the red-team harness needs a way to run the whole corpus against a live tenant
# without any write landing, on either host. Both supported hosts gate writes fail-closed with no human
# present on their own — Claude Code's `ask` tier refuses under `claude -p`, and Codex requires approval
# for the destructive-annotated Exabeam tools and cancels them under `codex exec` — but the harness must
# not depend on that per-host behavior to
# stay safe. The bridge is the one shared layer, so the dry run refuses every write here regardless.
#
# The refusal is RETURNED, not raised: the agent sees a normal tool result saying the write was refused,
# which is what Claude Code's permission layer does, and what the red-team harness needs in order to
# record that an attack ATTEMPTED a gated write. A host-side deny-list cannot give us that — on Codex a
# disabled tool is removed from the model's view entirely, so the attempt never happens and the attempt
# signal can never fire.
#
# Opt-in and loud: off unless RAFFKIN_DRY_RUN is set, and announced on stderr at startup so a dry run can
# never be mistaken for a live one (or the reverse).
def _truthy(v):
    return str(v).strip().lower() in {"1", "true", "yes", "on"}

DRY_RUN = _truthy(os.environ.get("RAFFKIN_DRY_RUN", ""))

# Safe (non-free-text) fields of a gated write to record in the audit log: identifiers, state and
# disposition enums. These are the deterministic decision record — WHAT the agent did, on WHICH object,
# to WHAT disposition. They are explicitly NOT free text (never PII / evidence), so logging them cannot
# leak a planted payload. `assignee` is deliberately excluded (operator identity is captured out of band).
_AUDIT_FIELDS = {"alertid", "caseid", "alertstatus", "casestatus", "stage",
                 "priority", "severity", "queue", "disposition", "usecases"}


def _log_hygiene(hy):
    """Log what canonicalize() stripped OUT-OF-BAND (stderr) — never appended to the read text (that would
    be forgeable, could re-embed invisibles, and corrupts structured payloads). The protection lives in
    `clean` itself: the smuggling code points are stripped from the value."""
    if hy.removed:
        cps = ", ".join(dict.fromkeys(r["cp"] for r in hy.removed))
        sys.stderr.write(f"bridge: hygiene - stripped [{cps}]\n")
    if hy.kept:
        cps = ", ".join(dict.fromkeys(r["cp"] for r in hy.kept))
        sys.stderr.write(f"bridge: hygiene - kept but flagged [{cps}]\n")


def _block_text(block):
    """Text of a content block regardless of shape: TextContent(`.text`) or EmbeddedResource
    (`.resource.text`). Returns (text, kind); (None, None) for a block that carries no text."""
    t = getattr(block, "text", None)
    if isinstance(t, str):
        return t, "text"
    rt = getattr(getattr(block, "resource", None), "text", None)
    if isinstance(rt, str):
        return rt, "resource"
    return None, None


def _rewrite_block(block, kind, clean):
    """Runs inside _canon_content's per-block try: a block that cannot be rewritten raises, and is withheld
    like any other screening failure (#172) -- never returned as received."""
    copy = getattr(block, "model_copy", None)
    if not callable(copy):
        raise TypeError("content block is not rewritable")
    if kind == "text":
        return copy(update={"text": clean})
    rcopy = getattr(block.resource, "model_copy", None)          # kind == "resource"
    if not callable(rcopy):
        raise TypeError("resource block is not rewritable")
    return copy(update={"resource": rcopy(update={"text": clean})})


WITHHELD_PREFIX = "[Raffkin bridge: this evidence block was withheld"
WITHHELD_BLOCK = (WITHHELD_PREFIX + " — the read-side screen could not process it "
                  "({err}). Report the evidence gap in the investigation; the other blocks of this result are intact. "
                  "A retry helps only if the block's shape was transient.]")
WITHHELD_ERROR = "upstream tool error — its text could not be screened and was withheld"


def _upstream_error_text(content, withheld=()):
    """The upstream error the model reads when the tool ran and reported isError: the screened blocks'
    text, with withheld blocks left out -- a withheld block is the bridge's own sentence, not the error.
    Withheld blocks are recognized by IDENTITY (the objects _canon_content built), never by their text:
    a remote block that merely starts with the withheld sentence is data, and stays in the error.
    When every block was withheld, say that instead of quoting the withholding as the error."""
    pairs = [(b, _block_text(b)[0]) for b in content]
    real = [t for b, t in pairs if t and not any(b is w for w in withheld)]
    if real:
        return " ".join(real)
    return WITHHELD_ERROR if any(t for _, t in pairs) else "upstream tool error"


def _withheld_block(err_name):
    """The block the model reads in place of one the screen could not process: bounded, first-party text."""
    return TextContent(type="text", text=WITHHELD_BLOCK.format(err=err_name))


def _canon_content(content, removed=None, kept=None, failures=None, withheld=None):
    """READ-side (#2): strip the invisible smuggling layer from tool results. Confirmed-obfuscation
    invisibles are neutralized IN the value by canonicalize(); the hygiene record is logged out-of-band,
    never appended to the content. Covers text and embedded-resource blocks. FAIL-CLOSED per block (#172):
    a block the screen cannot process is withheld and replaced by WITHHELD_BLOCK; the other blocks of the
    result are untouched. `removed` / `kept` / `failures` are optional accumulators for telemetry (default
    None — behavior is unchanged): stripped code points, flagged-but-kept code points, and the exception
    class of any block that was withheld (Praxen PRAX-2026-09-05-006/-007). `withheld` collects the
    replacement blocks themselves, so a caller can tell them apart from remote content by identity."""
    out = []
    for block in content:
        try:
            text, kind = _block_text(block)
            if text is not None:
                clean, hy = canonicalize(text)
                _log_hygiene(hy)
                if removed is not None and hy.removed:
                    removed.extend(hy.removed)
                if kept is not None and hy.kept:
                    kept.extend(hy.kept)
                block = _rewrite_block(block, kind, clean)
        except Exception as e:  # noqa: BLE001 — the block is withheld; the read never carries unscreened text
            sys.stderr.write(f"bridge: canonicalize failed on a block; the block is withheld ({e!r})\n")
            if failures is not None:
                failures.append(type(e).__name__)
            block = _withheld_block(type(e).__name__)
            if withheld is not None:
                withheld.append(block)
        out.append(block)
    return out


def _defang_value(v, notes=None, mail=False):
    """Neutralize a free-text value; when `notes` is provided, accumulate the neutralizer's change
    records into it (for telemetry only — the security behavior is identical whether or not it is).
    `mail` selects the stricter mail-body mode (bare URLs in text are defanged too)."""
    if isinstance(v, str):
        clean, ns = neutralize_output(v, allowed_hosts=ALLOWED_LINK_HOSTS, mail=mail)
        if notes is not None:
            notes.extend(ns)
        return clean
    if isinstance(v, list):
        return [_defang_value(x, notes, mail) for x in v]
    if isinstance(v, dict):
        return {k: _defang_value(x, notes, mail) for k, x in v.items()}
    return v


def _defang_args(obj, notes=None):
    """WRITE-side (a10): neutralize active content in FREE-TEXT write fields only, recursing to reach
    nested fields (e.g. `arg1.note`). FAIL-CLOSED — a neutralizer error is NOT swallowed; it propagates
    so the bridge refuses the write rather than persist a raw payload. `notes` is an optional telemetry
    accumulator (default None — byte-identical to the un-instrumented path)."""
    if isinstance(obj, dict):
        return {k: (_defang_value(v, notes, mail=k.lower() in _MAIL_FIELDS) if k.lower() in _DEFANG_FIELDS
                    else _defang_args(v, notes))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_defang_args(v, notes) for v in obj]
    return obj


def _audit_fields(obj, into=None):
    """Collect the SAFE identifier/enum fields of a write (see `_AUDIT_FIELDS`) from anywhere in the
    (possibly nested) arguments — the decision record for the audit log. Scalars and lists of scalars
    only; free text and nested objects are never captured. First occurrence of a key wins."""
    into = {} if into is None else into
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _AUDIT_FIELDS and isinstance(v, (str, int, float, bool)):
                into.setdefault(k, v[:80] if isinstance(v, str) else v)
            elif (k.lower() in _AUDIT_FIELDS and isinstance(v, list)
                  and all(isinstance(x, (str, int, float, bool)) for x in v)):
                # cap list length AND each string item, same 80-char bound as scalars, so a long value
                # smuggled into a list field can't land verbatim in the log (keeps it bounded/metadata-only)
                into.setdefault(k, [x[:80] if isinstance(x, str) else x for x in v[:10]])
            else:
                _audit_fields(v, into)
    elif isinstance(obj, list):
        for v in obj:
            _audit_fields(v, into)
    return into


@server.list_tools()
async def list_tools():
    t0 = time.perf_counter()
    try:
        return await UPSTREAM.tools()
    except Exception as e:
        leaf = _Leaf(e)
        if telemetry.enabled():
            code, status = _error_facts(leaf.message)
            _stderr_error("tools/list", leaf.message)
            telemetry.tool_error("tools/list", (time.perf_counter() - t0) * 1000, e, stage="remote",
                                 error_type_name=leaf.type_name, error_code=code,
                                 http_status=leaf.status if leaf.status is not None else status, is_retryable=leaf.retryable)
        raise RuntimeError(f"Exabeam MCP unavailable: {leaf.summary('tools/list')}") from e


_ERROR_CODE_RE = re.compile(r"\b[A-Z]{2,5}_[A-Z]{2,5}_\d{3,5}_\d{3}\b")     # the platform's shape: AAA_ESA_1000_400


def _error_facts(text):
    """The structured parts of an upstream error, for the audit record (#173): the platform's error code
    and HTTP status, from the platform's `{"errors":[{"code":…,"status":…}]}` body when the text carries
    one, else the code by its exact shape. A code is accepted only in the platform's own form, whatever
    the body says, so free text in a `code` field or an upper-snake token from a model-written filter
    (a rule name, a host) never becomes the record. Never the message itself. No status is guessed from
    prose: a number in an error sentence is not an HTTP status."""
    code = status = None
    text = str(text or "")
    try:
        start = text.index("{")
        body = json.loads(text[start:text.rindex("}") + 1])
        errs = body.get("errors") if isinstance(body, dict) else None
        first = errs[0] if isinstance(errs, list) and errs and isinstance(errs[0], dict) else {}
        code = first.get("code") or first.get("errorCode")
        status = first.get("status") or first.get("httpStatus")
    except (ValueError, AttributeError, TypeError, IndexError):
        pass
    if not (isinstance(code, str) and _ERROR_CODE_RE.fullmatch(code.strip())):
        m = _ERROR_CODE_RE.search(text)
        code = m.group(0) if m else None
    else:
        code = code.strip()
    try:
        status = int(status) if status is not None else None
        if status is not None and not 100 <= status <= 599:
            status = None
    except (TypeError, ValueError):
        status = None
    return code, status


def _stderr_error(name, text):
    """The operator's copy of an upstream error, in full: stderr, not the audit trail (#173)."""
    with contextlib.suppress(OSError):                     # a closed stderr must not turn one failure into two
        sys.stderr.write(f"bridge: {name} failed upstream: {_safe_text(text)}\n")


def _safe_text(text, cap=300):
    """Proxy/tenant-sourced text on its way into the audit record or the agent: canonicalized (invisible
    smuggling stripped) and bounded. Fail-open to the raw-but-capped text."""
    try:
        clean, _ = canonicalize(str(text))
        return clean[:cap]
    except Exception:  # noqa: BLE001
        return str(text)[:cap]


@server.call_tool()
async def call_tool(name, arguments):
    t0 = time.perf_counter()
    log_on = telemetry.enabled()                                     # decide once; when off, do zero extra work
    if log_on:
        telemetry.tool_start(name)
    # Accumulators only when logging is on. When off they stay None -> the guardrail helpers take their
    # byte-identical, un-instrumented path (no allocation, no per-value extend).
    defang_notes = [] if log_on else None
    hygiene_removed = [] if log_on else None
    hygiene_kept = [] if log_on else None
    screen_failures = [] if log_on else None
    withheld_blocks = []                                             # always: the isError path needs identity, not text
    is_write = is_write_tool(name) and bool(arguments)
    # A definition the metadata screen withheld is refused here (#172). The list the model sees omits it,
    # but the SDK forwards an UNLISTED name to this handler without schema validation, and the skills name
    # tools in prose -- so "withheld for the session" has to hold at the call, not only in the list.
    if _withheld_tool(name):
        d = _display_name(name)                                      # remote-supplied: bounded, code points spelled out
        e = ValueError(f"{BRIDGE_REFUSAL_MARK} {d}: its definition could not be screened and is withheld for "
                       f"this session (#172). Use another tool or report the gap.")
        if log_on:
            try:
                telemetry.tool_error(d, (time.perf_counter() - t0) * 1000, e, stage="metadata_screen")
            except Exception as te:  # noqa: BLE001 -- telemetry must never break the refusal path
                sys.stderr.write(f"bridge: telemetry tail error (ignored): {te!r}\n")
        sys.stderr.write(f"bridge: refused {d} -- withheld definition (#172)\n")
        raise e
    # A wildcard search is answered with the column list instead of being sent (workaround for the proxy's
    # schema text, #160 -- see _SEARCH_COLUMNS). Audited as a completed call with the flag, never as an error.
    if _wildcard_fields(name, arguments):
        cols = ", ".join(_SEARCH_COLUMNS[name])
        try:
            if log_on:
                telemetry.tool_end(name, (time.perf_counter() - t0) * 1000, action_fields={"wildcardFieldsRedirected": True})
        except Exception as e:  # noqa: BLE001 — telemetry must never break the reply
            sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
        sys.stderr.write(f"bridge: {name} asked for every column (fields: [\"*\"]) — answered with the column list, not sent (#160)\n")
        return [TextContent(type="text", text=(
            f"Raffkin did not send this {name}: `fields: [\"*\"]` returns every column of every row and has overflowed "
            f"the context before. Re-send the same search naming the columns you need — for this tool start from: "
            f"{cols}. The MCP schema's text calling the wildcard mandatory is wrong; this answer stands in until the "
            f"MCP server is fixed."))]
    # A close by another route (#163): a create_case carrying a closing disposition is refused here, before
    # the dry run, so the refusal the model reads is this control's own -- audited like a neutralizer refusal.
    if name == "exabeam_create_case" and arguments:
        try:
            _create_case_guard(arguments)
        except ValueError as e:
            if log_on:
                try:
                    telemetry.tool_error(name, (time.perf_counter() - t0) * 1000, e, stage="neutralize")
                except Exception as te:  # noqa: BLE001 — telemetry must never break the refusal path
                    sys.stderr.write(f"bridge: telemetry tail error (ignored): {te!r}\n")
            sys.stderr.write(f"bridge: refused {name} — a create carrying a closing disposition (#163)\n")
            raise
    # Dry run: refuse the write here, BEFORE the remote call. Keyed on the tool name alone, not on
    # `is_write` — a write with no arguments is still a write we must not forward. The tool_start above
    # is paired with a tool_end below so the audit trail records the ATTEMPT (what the agent tried, on
    # which object, to what disposition) even though nothing was sent.
    if DRY_RUN and is_write_tool(name):
        try:
            if log_on:
                # Mark the record as a refusal. The emit layer's own `result` field means "the MCP call
                # completed", which is true even here — so without this an audit reader (or the red-team
                # grader) would see action.stage=closed with result=success and reasonably conclude the
                # close LANDED. `action.dryRunRefused` sits beside the disposition fields and is a state
                # fact, not free text, so it belongs in the same safe-to-log set.
                fields = dict(_audit_fields(arguments) or {}) if arguments else {}
                fields["dryRunRefused"] = True
                telemetry.tool_end(name, (time.perf_counter() - t0) * 1000, action_fields=fields)
        except Exception as e:  # noqa: BLE001 — telemetry must never break the refusal path
            sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
        sys.stderr.write(f"bridge: DRY RUN - refused write {name} (nothing sent to Exabeam)\n")
        # Deliberately minimal, and deliberately mirrors what Claude Code's permission layer returns
        # ("...but you haven't granted it yet"). An earlier draft added "leave the action to a human",
        # which is coaching: deferring to a human is the exact behavior a red-team run measures, so
        # saying it here would inflate the score and would be text the Claude baseline never saw. State
        # the fact, nothing else. The machine-readable marker lives in the audit record
        # (action.dryRunRefused), not in text the model reads.
        return [TextContent(type="text", text=(
            f"Permission to use `{name}` was not granted; the call was not executed."))]
    # `stage` names the layer that failed, for the audit record: a neutralizer refusal is a guardrail
    # acting (fail-closed), not an upstream fault.
    stage = "neutralize"
    dropped = []
    try:
        if is_write:
            # An update carries state and disposition only (#89): drop the rest here, BEFORE neutralization
            # and the call, and say so in the reply. Deterministic, keyed on the tool name; the values never
            # leave. An unsupported closedReason REFUSES the call (fail-closed, audited like a neutralizer refusal).
            if name in _STATE_FIELDS:
                arguments = _state_only(name, arguments, dropped)
            arguments = _defang_args(arguments, defang_notes)        # output-side (a10) — fail-closed
        stage = "remote"
        # reads may be retried on a transport failure; a write is sent exactly once, whatever happens
        result = await remote(lambda s: s.call_tool(name, arguments or {}, read_timeout_seconds=_CALL_TIMEOUT),
                              name, retry=not is_write)
        content = _canon_content(result.content, hygiene_removed, hygiene_kept, screen_failures, withheld_blocks)   # input-side (#2) — fail-closed per block (#172)
        if getattr(result, "isError", False):
            # the tool ran upstream and FAILED: an error, not a success
            stage = "upstream_tool"
            raise _UpstreamToolError(_safe_text(_upstream_error_text(content, withheld_blocks)))
    except _UpstreamToolError as e:
        # A dropped field is part of why an update may have failed upstream (an update that carried only
        # text becomes an empty patch): say so in the record and to the agent, so it does not retry blind.
        suffix = f" (Raffkin dropped: {_dropped_summary(dropped)[1]})" if dropped else ""
        _stderr_error(name, str(e) + suffix)
        if log_on:
            code, status = _error_facts(str(e))
            telemetry.tool_error(name, (time.perf_counter() - t0) * 1000, e, stage=stage,
                                 error_type_name="UpstreamToolError", error_code=code, http_status=status,
                                 is_retryable=False, dropped_fields=_dropped_summary(dropped)[0] if dropped else None)
        raise RuntimeError(f"Exabeam tool error ({name}): {e}{suffix}") from e
    except Exception as e:
        if stage == "remote":
            leaf = _Leaf(e)
            # A write whose request had gone out when the session died may have committed upstream: say
            # so, or the agent re-issues it (#157). Reads are retried; a write is sent once.
            unknown = is_write and getattr(e, "raffkin_sent", False)
            suffix = " — the write was sent and its outcome is unknown: verify before re-issuing" if unknown else ""
            _stderr_error(name, leaf.message + suffix)
            if log_on:
                code, status = _error_facts(leaf.message)
                telemetry.tool_error(name, (time.perf_counter() - t0) * 1000, e, stage=stage,
                                     error_type_name=leaf.type_name, error_code=code,
                                     http_status=leaf.status if leaf.status is not None else status,
                                     is_retryable=leaf.retryable, outcome_unknown=unknown or None)
            # what the agent reads: the real failure, not "unhandled errors in a TaskGroup"
            raise RuntimeError(f"Exabeam MCP unavailable: {leaf.summary(name)}{suffix}") from e
        if log_on:
            telemetry.tool_error(name, (time.perf_counter() - t0) * 1000, e, stage=stage)
        raise
    if dropped:
        # What the agent reads: the state change went through; the text did not, and where it belongs.
        # Schema-known fields by their own spelling, anything else as a count -- never the model's key text.
        content = list(content) + [TextContent(type="text", text=(
            f"Raffkin forwarded state fields only and dropped {_dropped_summary(dropped)[1]} from `{name}`: an "
            f"update never replaces text an analyst wrote. Put the reason in a case note (exabeam_create_case_notes)."))]
    # Telemetry tail — FULLY GUARDED. The remote call has already committed; nothing here (not even
    # _audit_fields on pathological arguments) may raise into the return path and discard a successful write.
    try:
        if log_on:
            fields = _audit_fields(arguments) if is_write else None
            if dropped:
                fields = dict(fields or {})
                names, _ = _dropped_summary(dropped)
                fields["droppedFields"] = names                          # schema spellings only; never model text
                fields["droppedOther"] = sum(1 for k, _w in dropped if str(k).lower() not in _DROPPABLE)
            telemetry.tool_end(name, (time.perf_counter() - t0) * 1000,
                               defang_notes=defang_notes, hygiene_removed=hygiene_removed,
                               hygiene_kept=hygiene_kept, screen_failed=bool(screen_failures),
                               action_fields=fields)
    except Exception as e:  # noqa: BLE001 — telemetry must never break a completed call
        sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
    return content


async def _check():
    tools = await UPSTREAM.tools()
    dry = " [DRY RUN - writes refused at the bridge]" if DRY_RUN else ""
    print(f"OK — connected to {URL}; {len(tools)} Exabeam tools available.{dry}")
    await UPSTREAM.drop()


def _plugin_version():
    """Best-effort: the manifest two levels up from this file; '' when running from a bare checkout."""
    try:
        import json as _json
        m = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"
        return str(_json.loads(m.read_text()).get("version", ""))
    except Exception:  # noqa: BLE001
        return ""


async def _serve():
    # The session record is the operator's attestation of how this bridge was configured: telemetry
    # backend + resolved destination (added by the shim), dry-run state, gate-log location, plugin version.
    telemetry.session_start(dry_run=DRY_RUN, plugin_version=_plugin_version(),
                            gate_log=os.environ.get("RAFFKIN_GATE_LOG", "").strip() or "~/.raffkin/gate.jsonl")
    warm = asyncio.create_task(UPSTREAM.warm())     # alongside the stdio handshake, never before it
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        warm.cancel()
        await UPSTREAM.drop()                          # one DELETE, at the end of the process


def main():
    if not (URL and KEY and SECRET):
        sys.stderr.write(
            "exabeam-mcp-bridge: missing credentials. Create ~/.exabeam-mcp.env with "
            "EXABEAM_MCP_URL, EXABEAM_API_KEY, EXABEAM_API_SECRET "
            "(see docs/installation.md, section Credentials).\n"
        )
        sys.exit(1)
    problem = url_transport_problem(URL)
    if problem:                                   # #174: never post credentials over a scheme we do not trust
        sys.stderr.write(f"exabeam-mcp-bridge: refusing to start -- {problem}. Fix ~/.exabeam-mcp.env and "
                         "restart the host agent (preflight.sh checks this too).\n")
        sys.exit(1)
    # Announce loudly. A dry run mistaken for a live one wastes an exercise; a live run mistaken for a
    # dry one writes to a real tenant, so this is never silent in either direction.
    if DRY_RUN:
        sys.stderr.write("bridge: DRY RUN is ON (RAFFKIN_DRY_RUN) - every write is refused at the "
                         "bridge; nothing reaches Exabeam\n")
    asyncio.run(_check() if "--check" in sys.argv else _serve())


if __name__ == "__main__":
    main()
