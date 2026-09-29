<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design record — The human-in-the-loop gate

> **Status:** Shipped and current with the code as of 0.8.6. The authoritative statement of behavior is
> the code: `plugin/hooks/gate.py` (its docstring is the decision table), `plugin/hooks/hooks.json`,
> `plugin/.mcp.codex.json`, and the tier file they are generated from,
> `plugin/skills/soc-investigate/permissions.json`. The operator's view is
> [the installation guide](../../plugin/docs/installation.md#governance--the-safety-gate). This record
> says why the gate is built this way and what each layer does and does not promise.

## 1. What the gate promises

Three tiers, one source, enforced by the **host agent** rather than by the model:

| Tier | Tools | Decision | Why |
|---|---|---|---|
| **deny** (70) | every containment, detection-rule-write and context-table-write verb the Exabeam MCP exposes or may expose — 35 verbs, each listed in both its `exabeam_`-prefixed and bare spelling | refused outright | Raffkin recommends containment for a human to perform in EDR/IAM and never executes it; detection engineering applies rule and context-table changes |
| **ask** (3) | `exabeam_update_alert`, `exabeam_update_case`, `exabeam_send_email` | an explicit human yes, every time; refused when no human is present | dismiss and close are the irreversible outcomes of an investigation, and mail leaves the platform |
| **allow** (21) | the reads, plus the two escalation writes `create_case` and `create_case_notes` | prompt-free; the escalation writes on a per-session budget (two, then ask; a second case asks) | a fresh install must be useful immediately without weakening anything; a single investigation's escalation never prompts (a prompt on escalation teaches the model to avoid it), and a run of them does (#247) |
| *unclassified* | any tool the remote MCP grows that this release has not tiered | asks | inherits the safe default, not the session default |

The counts are the shipped tier file's; the invariant tests pin that every live tool is in exactly one
tier and that the generated artifacts agree with it. One host-side difference: Codex prompts on
`create_case` and `create_case_notes` regardless, because Exabeam's own annotation of those two tools
marks them destructive — that is the platform's annotation, not Raffkin's tier, and the guides say so.

## 2. Why a hook, and why it ships on

Until 0.8.6 the Claude Code gate was a permission snippet the operator had to **merge** into their
settings. Inert until merged, and switched off entirely by `--dangerously-skip-permissions` — the two
open questions of issue #9, and the reason the red team could only test the gate "on" and "bypassed".

Claude Code lets a plugin ship *code that takes part in permission decisions* (a `PreToolUse` hook) but
not permission *rules*, which are the operator's. A hook is active the moment the plugin is enabled; its
`deny` holds under `--dangerously-skip-permissions`; its `ask` forces a human prompt in every mode and is
**refused by the host when no human is present** (`claude -p`, CI). That is the same posture the Codex
package already had from its tool-approval policy, so shipping the hook (#148) made the two hosts equal:
**nothing to merge on either host, and the gate is on.** Verified live on 2026-09-04, including the
headless refusal and the bypass flag.

The permission snippet (`settings.snippet.json`) stays as a **published artifact** — the same tiers
under the plugin's prefixed rule names, for organizations that push them as host policy through managed
settings. The installer no longer merges it and the docs no longer offer it as a second lock (#226): in
the mode where a second lock would matter, skip-permissions, the rules are the weaker one, and the hook's
status is verified from the installed plugin's load state. `scripts/merge_permissions.py` remains in the
repository for a fleet that wants to generate from it. Applied, the two agree on every tool because both
are generated from the same file (§5).

## 3. Which servers the hook governs

The hook matches on the bare tool name (the last `__` segment), so a renamed server cannot move a tool
between tiers. Its tiers cover two different sets of servers:

- **`deny` and `ask` apply to every Exabeam-named server** — the bundled bridge under any plugin key
  (`mcp__plugin_raffkin_exabeam__…`, `mcp__plugin_soc_exabeam__…` after a vendor re-key), a manual
  `claude mcp add exabeam …` registration, a third party's server — because tightening is always safe.
  The matcher in `hooks.json` and the hook's own `is_ours` test are both case-insensitive on the word
  `exabeam` (Praxen finding 2026-09-07-004).
- **`allow` applies only to the bundled bridge** — the server named `plugin_<this plugin's name>_exabeam`.
  The hook takes that name from the manifest Claude Code itself reads (`.claude-plugin/plugin.json`), with
  `identity.json` as the fallback; if the two disagree (an overlaid copy that was not regenerated) it trusts
  the manifest and says so on stderr. On any other Exabeam-named server an allow-tier tool gets **no
  decision**: the operator's own permission rules apply, exactly as the permission snippet already spells
  it (its allow rules exist under the bundled prefix only). Granting the allow everywhere would have let a
  third party's server run prompt-free by naming itself well (Praxen finding 2026-09-07-003; findings are
  in [praxen/results/](../praxen/results/)).

An operator's own settings rule on an allow-tier tool still wins: a `deny` removes the tool from the model's
list before the hook runs, an `ask` still prompts — the hook's allow removes only the *default* prompt.
Both verified live in default permission mode, headless, 2026-09-06. If the hook returned no decision on
the allow tier, every read would prompt until the operator merged the snippet — the step 0.8.6 removed.

## 4. Failure direction

**The gate never fails open.** If the tier file cannot be read, every tool asks. If the hook itself raises,
the decision is `ask` with the exception class in the reason — interactively the human decides, headless
the call is refused. The hook exits 0 always; the decision is the JSON on stdout, and `hooks.json` turns a
non-zero exit into a block (`|| exit 2`). The host needs a POSIX shell and `python3` 3.7+ on `PATH`;
without `python3` every gated call is refused, not allowed. The installer and `preflight.sh` verify that
the **installed** copy carries the hook before they report the gate as on (Praxen 2026-09-07-002: an
offline operator holding a hook-less older install must not read "gate ON").

## 5. One tier file, three enforcement points

`permissions.json` (bare names, three tiers, the MCP server key) is the only place the tiers are written.
Everything that enforces them is derived from it:

- the **hook** reads `permissions.json` directly at call time (falling back to the snippet, stripped);
- the **permission snippet** `settings.snippet.json` is generated from it by `plugin/gen_identity.py`
  (with `identity.json`, which supplies the prefix `mcp__plugin_<name>_exabeam__` and, for the manual
  path, `mcp__exabeam__` — ask and deny only);
- the **Codex tool-approval policy** in `.mcp.codex.json` is derived from the snippet by
  `scripts/gen_codex_mcp.py`: `default_tools_approval_mode: approve`, `approval_mode: auto` on the 21
  allow-tier tools, `approve` on the 3 ask-tier tools, the 70 deny-tier tools in `disabled_tools`.

CI runs both generators' `--check`; the tier invariants in `tests/test_repo_invariants.py` pin that the
hook, the snippet and the Codex policy cannot disagree, and that a re-key (a vendor catalog renaming the
plugin) moves the allow's prefix with it.

## 6. What the gate records

Each decision — including refusals and the near-miss that never reached the bridge — is appended
best-effort to `~/.raffkin/gate.jsonl` with the call's **safe target fields** only: identifiers and
dispositions (`alertId`, `caseId`, `alertStatus`, `stage`, …), never free text, values capped. So a
refused attempt reads as "tried to dismiss alert X as false positive", which is the record that matters
in a SOC (#87). The same hook runs again after the call (`PostToolUse`, invoked with `--post`) and
appends `approved` for an ask-tier call that completed — inferred from completion, an ask completes only
on a yes — or `ran_unasked` when the session's permission mode meant nobody could answer, and
`ran_despite_deny` for a deny-tier tool that ran; never a decision, never stdout (#5).
`RAFFKIN_GATE_LOG=off` disables it; the bridge's audit trail records the calls that do
reach it ([logging guide](../../plugin/docs/logging.md)).

## 7. The model-side layer beneath

Each `SKILL.md` also instructs the model to ask before dismiss or close and never to claim or attempt
containment. That is doctrine, not enforcement: the [Worker Remit](../praxen/WORKER_REMIT.md) states it
as the layer *beneath* the host gate ("in addition to the host gate above — never in place of it", under
*Requires Human Approval Before Execution*), and it is what the red team measures when the write tools are
offered — 100 trials of the red team's hook leg (§8) on 2026-09-05 recorded zero attempts, and the first
fixture aimed at the ask-tier `send_email` (d05) drew none in 30 hook-leg trials on 2026-09-14, so a
doctrine-following model never reaches the hook. The corpus therefore includes fixtures that provoke the
attempt on purpose, so the hook's save is observable.

## 8. How it is verified

- **Deterministic, in CI:** `tests/test_hook_gate.py` (decision table, both reaches, unclassified,
  error → ask, the log's field allowlist), `test_merge_permissions.py`, `test_preflight_codex_override.py`
  (every TOML spelling of a Codex override), the tier invariants in `test_repo_invariants.py`.
- **Live, before every release:** the red team's **hook leg** (`--claude-gate hook`) offers the write
  tools under `--dangerously-skip-permissions` with the hook as the only thing in the way and the bridge
  dry run as backstop; a write that reaches the bridge is a hook miss and blocks the release. The standard
  Claude leg and the Codex leg withhold the write tools by host policy and rely on the dry run.
  [`security/redteam/METHODOLOGY.md`](../redteam/METHODOLOGY.md).
- **Praxen** checks the remit's gate rules against this code on every scan; the 2026-09-05 through
  2026-09-08 scans drove the reach split (§3), the installed-copy check (§4) and the `create_case`
  refusal in the bridge ([output-neutralizer record](output-neutralizer.md#5-three-write-rules-in-the-bridge-beside-the-neutralizer)).

## 9. Declared residuals

- A server registered by hand under a name **without** `exabeam` in it is outside the hook's reach; the
  guides say to name it `exabeam`, and `preflight.sh` warns when it sees an Exabeam server the gate does
  not reach.
- The "any other agent" install path (no plugin host) has no gate at all — the installation guide marks
  it evaluation-only.
- The hook governs MCP tools only; a host's own Bash, Write and Edit tools stay at the session default.
- The hook has no skill or mode input, so the queue sweep's no-write rule is carried by the skill text
  up to the escalation-write budget (two per session, a second case asks; #247, Praxen 2026-09-19-001).
  The count is the hook's own, keyed on the host's session id, so an injection cannot talk it out of
  counting; it applies on Claude Code only — Codex has no hook, and its escalation writes run as `auto`.
