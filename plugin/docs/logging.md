<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Logging (structured audit trail) — on by default

**What it is:** a structured, durable, machine-parseable record of what the agent did on every
investigation — which Exabeam tools it called, how long they took, whether they succeeded, **the gated
action it took** (which alert/case, to what disposition), and **when the [security
guardrails](security-guardrails.md) fired**. A good agent keeps an audit trail; Raffkin keeps one **by
default**, so a production tenant can reconstruct a session or drive anomaly detection instead of relying
on the free-form investigation report alone.

It runs inside the bundled connector (the local MCP bridge, the one place that sees every Exabeam call)
and is built on
[**observra**](https://open-agent-ai-security.github.io/observra/), an open-source agent-telemetry SDK.
Events are written as newline-delimited JSON (one object per line) in the CIM-normalized observra schema.

The bridge installs the observra library it needs (1.1 or newer); nothing for you to set up.

## Exactly what is recorded

**One event per tool call**, plus a session marker at each end:

| `event_type` | When | Key fields |
|---|---|---|
| `mcp_session_start` / `mcp_session_end` | bridge process start / exit | `session_id`, host context; on start also the configuration attestation: `telemetry_backend`, `telemetry_destination` (resolved file path, or scheme + host of the endpoint), `dry_run` (writes simulated; test runs only), `plugin_version`, `gate_log` |
| `tools_list` | the remote's tool definitions arrive (once per session) | `tool_count` (the definitions the model sees), `metadata_stripped` / `metadata_flagged` (hidden code points removed or flagged in tool descriptions — counts only), `withheld_tools` (definitions the screen could not read, so the model never saw them), `tool_shas` (a hash per definition, so a changed definition is visible across sessions) |
| `tool_start` | a tool call begins | `tool_name` |
| `tool_end` with `action.wildcardFieldsRedirected: true` | a search asked for every column (`fields: ["*"]`) and was answered with the column list instead of being sent — a workaround for the MCP server's schema text, kept until the server is fixed | `tool_name` |
| `tool_end` | a tool call succeeds | `tool_name`, `duration_ms`, + the fields below |
| `tool_error` | a tool call fails | `tool_name`, `duration_ms`, `error_class`, `stage` (`neutralize` = the write-side guardrail refused to forward, with `guardrail_refused: true`; `metadata_screen` = a definition the screen withheld was called by name and the bridge refused it, also with `guardrail_refused: true`; `remote` = the upstream call failed; `upstream_tool` = the tool ran on the proxy and reported an error), and for a remote failure the structured parts of what failed: `error_type_name`, `error_code` (the platform's own code, e.g. `AAA_ESA_1000_400`, when it sent one), `http_status` when there was one, `is_retryable`; `outcome_unknown: true` when a write's request had gone out before the session died (verify before re-issuing); `dropped_fields` naming, by the schema's spelling, the fields the bridge dropped from an update. Never the error message itself: it quotes the request. A failed `tools/list` at startup is recorded under `tool_name: tools/list`. |

Every event also carries: `framework: "mcp"`, `agent_name` (the plugin's name from its `identity.json`
— `raffkin` here; a copy shipped under another name logs under that name), `skill_name: "soc-investigate"`,
ULID `session_id` / `trace_id` / `span_id` for correlation, a `timestamp`, and host context
(`host`, `user`, `os`, `arch`, `library_version`) for accountability.

On a `tool_end`, three extra kinds of field appear when relevant:

**1. The decision record** — for a gated write (`update_alert`, `update_case`, `create_case`,
`create_case_notes`), the safe identifier/enum fields of the action, namespaced `action.*`:

```json
"action.alertId": "4471", "action.alertStatus": "closed", "action.disposition": "false_positive"
```

Captured fields: `alertId`, `caseId`, `alertStatus`, `caseStatus`, `stage`, `priority`, `severity`,
`queue`, `disposition`, `useCases`. This is *what the agent decided, on which object* — the audit-grade
core of the trail.

**2. Guardrail firings** — proof the [defenses](security-guardrails.md) acted, correlated to the exact
call:

```json
"defang_formula": 1, "defang_link": 1          // output neutralizer defanged a formula / phishing link on a write
"hygiene_stripped": 3, "hygiene_classes": "U+200B,U+202E"   // input canonicalizer stripped smuggling code points on a read
"hygiene_kept": 2, "hygiene_kept_classes": "U+200D,U+200F"   // joiners / directional marks were present — kept verbatim, flagged here
"hygiene_screen_failed": true                                 // screening threw on a block; the block was withheld (fail-closed)
```

`hygiene_kept` is the only place that signal exists: the text is never altered and no marker is ever
written in-band (a marker in alert data would be forgeable). A right-to-left mark or a zero-width joiner in
a value is not proof of anything — Persian, Arabic and emoji use them legitimately — but on a homoglyph or
bidi-shaped investigation it is the field to query.

## The gate's own record

The bundled Claude Code hook keeps a second, smaller log beside the telemetry: `~/.raffkin/gate.jsonl`
(`RAFFKIN_GATE_LOG=off` disables it and says so on stderr; another path overrides; rotates at ~5 MB with
three backups). One line per decision:

```json
{"ts": "2026-09-05T16:01:26+00:00", "tool": "mcp__plugin_raffkin_exabeam__exabeam_update_alert",
 "decision": "ask", "reason": "Raffkin gate: exabeam_update_alert dismisses or closes. It needs the analyst's explicit yes — ask, and wait.",
 "target": {"alertId": "4471", "alertStatus": "DISMISSED"}}
```

The same hook runs again after the call. An ask-tier call that **completed** is recorded as `approved`,
beside the `ask` line — inferred from completion: an ask completes only when a human answered yes. When
the session ran in a mode where nobody could answer (`bypassPermissions`, `dontAsk`) the line says
`ran_unasked` instead, because the ask did not hold for that call. That line should never appear; it
exists so that a gate that somehow did not hold is visible in the record rather than silent. Both lines
carry the host's `permission_mode` and `tool_use_id` when present, so a post line ties to its ask:

```json
{"ts": "2026-09-05T16:01:41+00:00", "tool": "mcp__plugin_raffkin_exabeam__exabeam_update_alert",
 "decision": "approved", "reason": "an ask-tier call completed after the gate asked: inferred from completion, an ask completes only on a yes",
 "permission_mode": "default", "tool_use_id": "toolu_01ABC",
 "target": {"alertId": "4471", "alertStatus": "DISMISSED"}}
```

A deny-tier tool that ran anyway is recorded as `ran_despite_deny`. Allow-tier reads leave no post-call
line: this file records decisions, and the telemetry records every call. The host runs the post-call
hook only when the tool succeeded, so an approved write that failed upstream leaves the `ask` line and
the bridge's `tool_error` event, and no `approved` line.

`target` carries the same safe identifier and disposition fields the telemetry's `action.*` record uses,
and nothing else — so a refused attempt reads as *tried to dismiss alert 4471 as dismissed*, which is the
near-miss a SOC wants to see, while the note, description or reason text a payload can ride in never
enters the file. This is also the only record of an attempt the gate stopped **before** it reached the
bridge; the telemetry sees only calls that got that far.

## What is deliberately NOT recorded (privacy by construction)

The log stores **metadata about** the agent's actions — never the raw evidence. Specifically **excluded**:

- **Free-text field values** — `note`, `alertDescription`, `alertName`, `supportingReason`,
  `closedReason`, `tags`. The case-note text and alert prose never enter the log.
- **Tool arguments and results** in general — `tool_args` / `tool_result` are always `null`.
- **The neutralized payloads themselves** — a defanged formula or phishing URL is counted, never quoted.
- **Upstream error text** — a failed call is recorded by its error code, HTTP status and class; the
  platform's message, which quotes the request that failed, goes to stderr for the operator and to the
  agent, not to the log.

The whole point of the guardrails is to neutralize hostile content; the audit log must not become a second
copy of it. observra additionally applies its own PII redaction over everything above.

> `assignee` is intentionally not in the decision record. Operator identity is already captured once per
> session as host context (`user`/`host`), which is the accountability signal; the per-action assignee is
> omitted to avoid scattering it across every write.

## Where it goes, and how it stays bounded

Default backend is a **local, rotating JSON-lines file** — no network egress:

| Setting | Env var | Default |
|---|---|---|
| Backend | `RAFFKIN_OBSERVRA` | `jsonl` (set `off` to disable) |
| File path | `RAFFKIN_OBSERVRA_PATH` | `~/.raffkin/telemetry.jsonl` |
| Rotate at size | `RAFFKIN_OBSERVRA_MAX_BYTES` | `10485760` (10 MB) |
| Backups kept | `RAFFKIN_OBSERVRA_BACKUPS` | `5` |
| Webhook destination | `RAFFKIN_OBSERVRA_URL` | — (required for `webhook`) |
| OTLP endpoint | `RAFFKIN_OBSERVRA_ENDPOINT` | — (else `OTEL_EXPORTER_OTLP_ENDPOINT` / `..._LOGS_ENDPOINT`, else `http://localhost:4318`) |

Whatever the backend, the bridge prints the **resolved destination** on stderr at startup (a path, or the
scheme + host of the endpoint — never a URL path or query, which can carry a token) and records the same on
the `mcp_session_start` event, so the trail itself attests where it was shipped. One disclosure cannot go
into the log: if telemetry disables itself (a misconfigured backend, a missing library) that fact is
printed to stderr only, because there is no longer a log to write it to.

So the log **rotates** (`telemetry.jsonl` → `.1` → … → `.5`, oldest deleted) and is bounded to roughly
**60 MB** by default. It never grows without limit.

Other backends (opt-in via `RAFFKIN_OBSERVRA=`): `exabeam` (routes telemetry back into Exabeam using the
bridge's own creds), `otel` / `otel_log` (OpenTelemetry), `webhook`. These make network calls, so `jsonl`
is the default. On first enable, the bridge prints one line to stderr naming the destination and how to
turn it off — disclosed, not silent.

> **Enabling a network backend is an egress decision you own.** The default (`jsonl`) never leaves the
> host. `exabeam`/`otel`/`webhook` send events off-box — action *metadata* and safe IDs only, never
> case-note text, evidence, or payloads (the same privacy rules apply) — but you are choosing to route
> telemetry to that destination. Point them only at systems you control.

## Finding and reading your log

By default it's at **`~/.raffkin/telemetry.jsonl`** (rotated backups are `telemetry.jsonl.1` … `.5`). It's
one JSON object per line — read it with anything that speaks JSON lines:

```bash
tail -f ~/.raffkin/telemetry.jsonl                      # watch events live

# the gated actions this session took (which alert, to what disposition):
jq -c 'select(.event_type=="tool_end" and (.data|has("action.disposition")))
       | {tool: .tool_name, alert: .data."action.alertId", disp: .data."action.disposition"}' \
   ~/.raffkin/telemetry.jsonl

# every time a guardrail fired:
jq -c 'select(.data.defang_formula or .data.defang_link or .data.hygiene_stripped)
       | {tool: .tool_name, defang_formula: .data.defang_formula, defang_link: .data.defang_link,
          hygiene: .data.hygiene_stripped}' ~/.raffkin/telemetry.jsonl
```

Events from one investigation share a `session_id`, so you can reconstruct a run by grouping on it.

## Fail-open

Logging is best-effort and can never break or slow an investigation. Two different failures, two
different responses:

- **Configuration-level** — observra is unavailable or a backend is misconfigured. Telemetry
  **disables itself** (a one-line stderr note) and the bridge carries on exactly as if logging were off.
- **A single event failing to emit** — that one event is **dropped and the trail stays on**. A transient
  fault must not silently switch off a mandatory audit log for the rest of the session, so only a
  configuration-level failure disables. The drop is disclosed on stderr, never swallowed.

observra's own **backend write errors** are routed to stderr too, prefixed `bridge: observra …`, so a
failed write is visible rather than vanishing into a library logger. One gap worth knowing for an audit
trail: if its internal queue fills, observra drops the oldest event and counts the drop rather than
announcing it. The security guardrails are independent and keep running throughout.

## Turning it off

```bash
export RAFFKIN_OBSERVRA=off
```

Off means *off*: no file, and observra is never imported. The bridge says so on stderr when it starts —
`bridge: observra logging is OFF (RAFFKIN_OBSERVRA=off) — this session is not recorded` — so an unrecorded
session is never a silent one.

## Known limitation

The trail records the **gated action and its disposition deterministically at the write sink**, and because
the gate ships on, an `update_alert` / `update_case` write only reaches the bridge *after* the human
approves it — so the write
event is evidence the approval happened. On Claude Code the bundled hook also records the approval,
as the `approved` line in `gate.jsonl` above — inferred from the call completing after an ask, not
observed. Neither record names **who** answered: that lives in the host agent's approval layer, which
neither the hook nor the bridge can see. The operator is carried on every event as host context
(`user`/`host`). Codex has no hook, so there the write event is the only
approval record.
