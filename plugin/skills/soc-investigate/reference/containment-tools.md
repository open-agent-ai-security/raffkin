<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Containment-class actions — recommend only (defense-in-depth deny-list)

> **The Exabeam MCP does not expose any of these.** Per the official MCP docs, the server's surface is
> Threat Center (cases/alerts/notes/timelines), Search, Attack Surface Insights (entity context),
> Context tables, and Detection rules — all read or triage-workflow. There is **no host isolation,
> account disable, or blocking capability.** So this list isn't gating tools you have; it's
> **defense-in-depth** — a standing `deny` that costs nothing and catches the day a response tool
> *is* added (by Exabeam or another MCP) before it can fire unreviewed.

Because containment isn't an MCP capability, the skill always **recommends** it in the report; the
analyst performs it in their EDR/IAM. The *real* human gate for this MCP is on **dismiss/close**
(`update_alert` / `update_case`) — see the `ask` tier in `permissions.json` — because a wrong suppression is
the actual way an AI verdict does harm here.

Additions to this list are fine; removals need a maintainer's review.

## The list

**Host isolation**
- `isolate_host`
- `quarantine_host`
- `isolate_device`

**Account actions**
- `disable_account`
- `disable_user`
- `lock_account`
- `revoke_session`
- `force_mfa_reset`
- `revoke_oauth_grant`

**Network / firewall**
- `block_ip`
- `block_url`
- `block_domain`
- `add_firewall_rule`
- `modify_firewall_rule`

**Endpoint actions**
- `kill_process`
- `delete_file`
- `run_script_on_host`

## Also denied: detection-content writes

Not containment, but the same posture — actions Raffkin **must never perform**, only propose. The live
Exabeam MCP grew `exabeam_create_analytics_rule` (2026-09: builds and creates a detection rule
server-side from one of six canned names) and the proxy defines `exabeam_update_analytics_rule`. The
`rule-tuning` skill's contract is *proposals for detection engineering to act on*, and `SKILL.md`
forbids applying or claiming to have applied a rule change, so both are denied on both hosts, under
both spellings, exactly like the containment verbs. A future rule-write tool under a new name lands on
the hook's unknown-tool rule (ask), which is the safety net until it is classified here.

**Detection content** — every verb the Worker Remit names: create, update, enable, disable or delete a
detection rule, a correlation rule or an exclusion rule, and create, update, delete or add records to a
context table. Only `create_analytics_rule` is live today; the rest are denied ahead of the MCP exposing
them, so a new detection-content write lands on a deny, not on the unknown-tool rule (Praxen 2026-09-07-005).
- `create_analytics_rule`
- `update_analytics_rule`
- `enable_analytics_rule`
- `disable_analytics_rule`
- `delete_analytics_rule`
- `create_correlation_rule`
- `update_correlation_rule`
- `enable_correlation_rule`
- `disable_correlation_rule`
- `delete_correlation_rule`
- `create_exclusion_rule`
- `update_exclusion_rule`
- `delete_exclusion_rule`
- `create_context_table`
- `update_context_table`
- `delete_context_table`
- `add_context_table_records`
- `delete_context_table_records`

## Why these and not `create_case` / `update_alert`

Opening a case or dismissing an alert is **workflow** — it routes and documents, and is easily
reversed. The actions above touch production systems and user access directly: isolating the wrong
host takes a service down; disabling the wrong account locks out a real user; `delete_file` and
`run_script_on_host` are effectively arbitrary endpoint control. That asymmetry is the entire reason
for the human gate, so the line is drawn here.

## Note on exact names

These are normalized names with any server prefix stripped. Every tool the Exabeam MCP exposes today follows
the `exabeam_<verb>` convention (see `tool-map.md`), so a containment tool would most likely arrive as
`exabeam_isolate_host`. The tier file therefore denies **both spellings** of every name here
— bare and `exabeam_`-prefixed — in **both namespaces** (the bundled plugin's
`mcp__plugin_raffkin_exabeam__` — the prefix derives from `name` in `plugin/identity.json`, from which the snippet is generated — and the manual-wiring `mcp__exabeam__`), and a repo invariant test
(`test_deny_list_matches_containment_doc`) keeps this file and the snippet in sync. If a live tool list ever shows a containment tool under a *different* name, add
it here and the test will demand the matching deny rules.
