<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design record — The human-in-the-loop gate

> **Status:** Shipped and current with the code as of 1.1.0 (Antigravity added, #306). The authoritative
> statement of behavior is the code: `plugin/hooks/gate.py` (its docstring is the decision table),
> `plugin/hooks/hooks.json` (Claude Code), `plugin/hooks.json` (Antigravity),
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

Google Antigravity (#306) has the same mechanism and takes the same file, in its own envelope: a
`PreToolUse` hook whose `{"decision": "deny"}` is a hard block, with `ask` and `force_ask` for a prompt.
Three differences are worth recording, because each one is a way the gate could ship inert:

- **It reads `hooks.json` from the plugin ROOT**, and stages `hooks/hooks.json` there only when importing
  a Claude Code or Gemini CLI extension — never for a native plugin, which is what a payload carrying
  `.antigravity-plugin/plugin.json` is. The file in the wrong directory is a gate that silently does not
  run.
- **Its matcher keys on the step type, not the tool name.** Every MCP call on the machine arrives as
  `mcp_tool` whatever server it belongs to, with the real tool name nested in the payload. Claude Code's
  server-name regex cannot work here, so `gate.py` does the identification itself (`agy_call()`) — which
  is the posture it was written for: the hook, not the matcher, decides whether a call is ours.
- **The host bundles no `python3`.** A hook command that cannot start emits no JSON, which this host reads
  as no objection: a fail-open that no test of ours would see. The command falls back to `uv`, which the
  bridge already requires, and `preflight.sh` fails rather than reporting a gate when neither is present.

What is NOT verified on that host, and is recorded as an evidence gap rather than a control: no release
has been red-teamed on a Gemini model, and nobody has watched a `deny` hold under
`--dangerously-skip-permissions` there (it does on Claude Code). Both need the desktop app and a Google
sign-in; #305.

The permission snippet (`settings.snippet.json`) stays as a **published artifact** — the same tiers
under the plugin's prefixed rule names, for organizations that push them as host policy through managed
settings. The installer no longer merges it and the docs no longer offer it as a second lock (#226): in
the mode where a second lock would matter, skip-permissions, the rules are the weaker one, and the hook's
status is verified from the installed plugin's load state. `scripts/merge_permissions.py` remains in the
repository for a fleet that wants to generate from it. Applied, the two agree on every tool because both
are generated from the same file (§5).

### What makes a step ours on Antigravity

Claude Code hands the hook a tool name (`mcp__plugin_<name>_exabeam__<tool>`) and the server is right
there in it. Antigravity hands over a step whose tool name is always `mcp_tool`, with the real call
nested inside, so the adapter in `plugin/hooks/gate.py` has to reconstruct the same two facts — which
server, which tool — from a payload shape read off the host's contract rather than a live call.

**The server decides whether a step is ours; the tool name only decides which tier it lands in.** Getting
that the wrong way round is the defect review caught in the first cut: it tested the tool name against
`^exabeam_` first, so a containment call spelled `isolate_host` on our own server was classified as
somebody else's and got no decision at all, while Claude Code denied the identical call. That is not a
corner: the deny tier carries the bare spellings deliberately, because a hand-wired server exposes
containment under its bare verb, and every one of them was unenforced here.

Three further spellings are normalised to the bare tool the tiers are written in: `<server>/<tool>`,
`mcp__<server>__<tool>`, and the plain name. Where the server is ours but no tool name can be read, the
step **asks** — it is the one case where standing aside would mean declining to judge a call on our own
bridge. Where nothing at all can be read, it also asks, with a different reason, because the two are
genuinely different failures and an operator reading the log should not be told the server was unnamed
when it was not.

**Both namespace separators are accepted, and the live one is now known to be the underscore.** The
host's guide spells a plugin's server `<plugin>-<server>`; a payload captured from a live `agy` 1.4.5
session sends `ServerName: "raffkin_exabeam"`. Both stay accepted because the cost of guessing wrong is
not symmetric: review measured the deny tier still holding while the bundled allow tier, the ask tier and
the #247 write budget were all silently lost — healthy on the loudest tier, not governing the rest.

**The documented payload shape was wrong, and that is how this adapter's assumptions were caught.** The
hook documentation states that "All JSON keys in the hook payloads use camelCase (protojson encoding)",
which holds for the common fields (`conversationId`, `stepIdx`) and not for the tool call beside them. A
real `call_mcp_tool` step carries:

```json
{"toolCall": {"name": "call_mcp_tool",
              "args": {"ServerName": "raffkin_exabeam", "ToolName": "exabeam_get_case_details",
                       "Arguments": {"arg0": {"caseId": "ABC-123"}}}}}
```

Three differences, each of which disabled part of the gate when the payload was read the documented way:
the keys are PascalCase, so the server was never seen — the bundled allow tier went inert and a bare
deny-tier name got **no decision at all**; the tool name sits beside the server rather than nested under
`toolCall`, while the step's own `name` is the dispatcher and not the tool; and arguments arrive
positionally wrapped (`Arguments.arg0`), so a record kept its decision and lost its target. Key lookup is
therefore case-insensitive and positional wrappers are unwrapped, with the captured payload pinned as a
fixture in `tests/test_hook_gate.py`. The lesson is the one the release bar already encodes: a contract
read from documentation is a hypothesis, and this one was wrong in three places at once.

**What each decision is worth under `--dangerously-skip-permissions`, measured rather than read.** A
stub hook was wired in place of the gate so the probe tested the HOST's contract and not this adapter,
once per decision, with a fake case id so nothing could change either way (agy 1.4.5, 2026-10-22):

| decision | result |
|---|---|
| `deny` | **honoured** — the call was blocked |
| `force_ask` | overridden — the tool ran |
| `ask` | overridden — the tool ran |

So the deny tier, which carries the containment guarantee, survives an operator turning permissions off.
The ask tier does not, and neither does `force_ask` — which matters because `force_ask` is documented as
"always prompt the user, ignoring cached permissions" and was the obvious candidate fix. There is no
hook-level way to force a prompt on this host once that flag is set. The control that still holds is the
API key's entitlements, which no host can override, and that is what the install guide now points an
unattended operator at.

**On this host the gate's `allow` restricts rather than entitles.** Antigravity's own permission system
applies on top of the hook's decision: a headless `agy -p` session cannot prompt for the `mcp` permission
and auto-denies the call even after the gate has allowed it (observed). On Claude Code the plugin ships a
permission snippet that grants the allow tier; there is no equivalent here yet. The host's `PreToolUse`
contract carries a `permissionOverrides` field that may be the mechanism — a design question, not a
defect in the tiers.

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
the call is refused. The hook exits 0 always; the decision is the JSON on stdout.

**A gate that cannot start must still refuse, and each host needs a different mechanism for that.** On
Claude Code `hooks/hooks.json` turns a non-zero exit into a block (`|| exit 2`, with a message naming the
component — #296). Antigravity has no equivalent: a `deny` object on stdout is its only hard block, and
the host's own changelog records its permission manager being fixed to handle "empty decision strings
returned by pre-tool hooks" safely rather than erroring — so there, a hook that produces nothing is a
hook that is never heard. `plugin/hooks.json` therefore ends its command with a refusal written by the
shell, which fires only when neither `python3` nor `uv` could run the gate; every path through `main()`
returns 0, so the fallback can never append itself to a decision already on stdout, and a test asserts
that property of `main()` rather than trusting it.

That refusal is **scoped to our own server, and the scoping is what makes it survivable.** The matcher is
the step type, so with no interpreter the fallback is handed every MCP call on the machine — another
server's `create_pull_request` included. A control that denies a developer's pull requests is a control
they switch off, so the shell reads the step with `grep`, the only test available without an interpreter.
Only grep's exit **1** — ran cleanly, our server is not in this step — stands aside. `0` is ours and
refuses; anything above 1 (127 when grep itself is missing, 2 on an error) means the step could not be
*read*, which is not the same as reading that it belongs to someone else, so that refuses too. The first
cut of this keyed on success versus failure and so failed open exactly when the machine was most broken:
no interpreter and no grep answered `{}` to a containment call.

**An empty payload is refused before any interpreter is tried, because `python3` succeeds on empty
input.** The chain reads stdin once into `_in` so a later stage can still see a payload an earlier one
consumed, which means `_in` is empty whenever something upstream failed to deliver it — review found
`cat` missing is enough. With an interpreter present the gate was then reached with nothing to read, its
catch-all answered `ask`, and on Antigravity `ask` is the one decision `--dangerously-skip-permissions`
overrides: a containment call dropped silently from refused to permitted, in the one state where no log
line explains why. So the empty test now comes first in the chain, and `gate.py --antigravity` denies an
empty payload on its own account as well, for the case where it is run directly. The two refusals are
worded to share no phrase, because `preflight.sh` proves the gate is live by matching the words of the
tier refusal — had the empty-payload deny borrowed them, an install that delivers nothing to its hook
would have *passed* its own diagnostic. Claude Code is deliberately unchanged: `ask` there already
refuses when nobody can answer. The
host needs a POSIX shell and `python3` 3.7+ (or `uv`) on `PATH`; without one, every gated call is refused
on both hook hosts, not allowed. The installer and `preflight.sh` verify that
the **installed** copy carries the hook before they report the gate as on (Praxen 2026-09-07-002: an
offline operator holding a hook-less older install must not read "gate ON").

## 5. One tier file, four enforcement points

`permissions.json` (bare names, three tiers, the MCP server key) is the only place the tiers are written.
Everything that enforces them is derived from it:

- the **hook** reads `permissions.json` directly at call time (falling back to the snippet, stripped).
  One file serves both hook hosts: Claude Code and Antigravity run the same `gate.py` and differ only in
  the envelope it is handed and answers in, so there is no second copy of the tiers to drift;
- the **Antigravity hook file** `plugin/hooks.json` is generated by `plugin/gen_identity.py`, keyed on the
  plugin's own name (`<name>-gate`) so two installed copies of this payload do not collide in the host's
  merged hook map;
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
appends what the gate can vouch for: `approved` for an ask-tier call that completed under an attended
permission mode, `ran_unasked` where the mode meant nobody could answer, `ran_consent_unconfirmed` where
the host reports no mode at all (Antigravity), and `ran_despite_deny` for a deny-tier tool that ran;
never a decision, never stdout (#5). The third of those was added after a session with
`--dangerously-skip-permissions` was observed completing an ask-tier write a second after the gate asked
it: an `approved` line there would have been a consent in the record that no human gave, and a log that
overstates what it saw is worse than one that says less.
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
  counting; it applies on the two hook hosts — Claude Code and Antigravity, the latter keyed on
  `conversationId` — and not on Codex, which has no hook and runs its escalation writes as `auto`.
- The shell-written refusal on Antigravity is the one decision the gate takes that it cannot record: the
  interpreter that would write the log line is the thing that is missing. The operator sees it (the host
  shows the reason, the shell's own `command not found` goes to stderr) but the decision log does not. The
  alternative was saying nothing, which is worse.
- Neither host's fallback covers the hook being killed at its `timeout` — the shell dies with the command,
  so nothing writes a decision. Unmeasured, but the gate reads one JSON object, compares a name against a
  static file and appends a line; the 20s budget is three orders of magnitude clear of that.
- The refusals the shell writes, and the gate's `AGY_NO_GATE` / `AGY_NO_INPUT` reasons, name the product
  in prose that a re-key does not rewrite, so a vendored `soc` build refuses in Raffkin's words. One
  upside, found in review: `preflight.sh`'s reason matching is therefore re-key-safe and a re-keyed copy
  passes it unchanged. Tracked for the re-vendor rather than fixed here.
- Antigravity does not tell a hook which permission mode the session is in, so the gate log cannot
  distinguish an ask a human answered from one that completed unattended there, as the Claude Code record
  can. Records carry `"host"` so the log is never ambiguous about which guarantee applied.
