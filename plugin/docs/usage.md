<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Using the skills

What to say, what happens, and what socxen will ask you before it acts. This assumes you have finished
[installation](installation.md) — credentials in place. The human-in-the-loop gate ships on, on both hosts.

## The three skills, and how to call them

You talk to socxen in plain language inside your coding agent (Claude Code or Codex). The right skill
picks itself up from what you ask; you never invoke one by name unless you want to.

| You say | Skill that answers | What you get back |
|---|---|---|
| "investigate alert `<id>`", "work case `<id>`", "is this a real threat?" | **soc-investigate** | A written investigation of one alert or case: evidence, timeline, MITRE mapping, verdict, and the action it took or is asking you to approve. |
| "triage the queue", "what should I look at", "morning triage" | **triage-cases** | A short "start here" list from the open case queue, clustered by attack shape and ranked by corroborated signal — plus the noise clusters worth tuning. |
| "find noisy rules", "what's generating false positives", "tune detections" | **rule-tuning** | The rules that are *noisy* (high volume, low precision — not merely loud) and a specific, least-invasive tuning proposal for each. |

You can also hand an alert ID, a case ID, or a pasted alert payload straight in. If you paste one, remember
that pasted text is treated as untrusted — the skill will still go and query Exabeam for the evidence
rather than take the payload's word for it. The same holds for a pasted queue export handed to
`triage-cases` or a rule inventory handed to `rule-tuning`: what arrives with the work is telemetry, not
a colleague, however official a note inside it looks.

## What an investigation does

`soc-investigate` follows a fixed loop, and you can watch it happen:

1. **Pull the work item** — the alert or case, from Exabeam, not from what you pasted.
2. **Establish the entities and their baseline** — the user, host, or IP involved, and what is *normal*
   for them, by querying their recent history. A "baseline" supplied inside the alert text does not count.
3. **Gather evidence, read-only** — SIEM search, threat timelines, context tables, rule and MITRE context.
   Reads run freely; nothing is written yet.
4. **Weigh competing hypotheses** — a benign explanation against a malicious one, each tied to evidence it
   actually retrieved.
5. **Reach a verdict** — confirmed threat, false positive, or inconclusive.
6. **Act** — open or update a case and write notes without asking (escalation is safe; on Claude Code a
   third such write in one session asks you); **ask you first**
   before dismissing an alert or closing a case; and *recommend* containment for you to perform.
7. **Report** — the write-up below.

If the Exabeam connection is not available, the skill says so and stops rather than guessing. That message
means the credentials file is missing or was added after the host started — step 2 of the
[quick start](installation.md#quick-start--claude-code).

## What it will ask you

Two kinds of prompt reach you, and it helps to know which is which.

**The skill asking.** Before it dismisses an alert or closes a case, `soc-investigate` asks in plain
words — *"Dismiss alert X as a false positive? (yes / no)"* — and waits. Say no, or say nothing, and
nothing happens.

**The host asking.** Independently, your agent's own permission system stops the dismiss/close tool call
and asks you to approve it. On Claude Code that is the permission prompt for `exabeam_update_alert` or
`exabeam_update_case`, raised by the hook that ships inside the plugin. On Codex it is the tool-approval prompt Codex
shows for a destructive tool — and if there is no human present, for example under `codex exec`, Codex
cancels the call. Both must open for a dismiss or close to happen. The same prompt guards
`exabeam_send_email`: mail only goes out when you approve it, and the Exabeam MCP service only accepts
recipients who are active users of your own subscription.

A dismiss or close you approved is an ordinary Exabeam status change. If it was a mistake, reopen the
alert or case in the New-Scale console.

You will notice Codex also asks before the *escalation* writes (opening a case, writing notes), where
Claude Code runs those silently. That is Exabeam's annotation on those tools, not a socxen setting; it is
noisier, not less safe.

**What it will never do.** Isolate a host, disable an account, block an IP, kill a process — any
containment. The Exabeam MCP exposes no such tools, and socxen denies them anyway as defense in depth.
When containment is warranted, the report *recommends* it, with the entity and the expected blast radius,
for you to carry out in your EDR or IAM.

## Reading the report

Every investigation ends in the same shape, so you can find things fast: the alert restated, the
timeline, the evidence with its source (every bullet says where it came from — "no source" means it does
not belong there), the MITRE mapping, the two hypotheses and what decided between them, the verdict with a
confidence, the actions taken and any containment recommended, and open questions if the result is
inconclusive.

The last line is always one of three **taxonomy outcomes**:

| Outcome | Meaning |
|---|---|
| `raised` | Escalated for human review — a case opened or kept open. This is the right call for a confirmed threat *and* for a genuinely inconclusive one. |
| `auto_closed` | Investigated and concluded benign enough to close, without a clear false-positive explanation. |
| `fp_closed` | Suppressed as a false positive — the dismiss/close call succeeded in this session *and* a *positive* benign explanation was found (a false-positive verdict left for the analyst to dismiss is `raised`) — known automation, a documented change, expected admin behavior. "I found nothing" is not one; that is `raised`. |

A link in a note that looks broken — `hxxps://…[.]…` — is deliberate: it was defanged on the way into
Exabeam so an exported artifact cannot be clicked or executed. See [security guardrails](security-guardrails.md).

## Triage and tuning

`triage-cases` is **read-only across the sweep**. It will not write notes, open cases, or change any
status while triaging — its output *is* the hand-off: individual cases go to `soc-investigate`
("investigate case `<id>`"), noise clusters go to `rule-tuning`. Where something is obvious at sweep depth
it will say so, but it never closes in bulk.

Every skill reports a **Flagged** line — the sweep skills in their summary, `soc-investigate` in its
report: alert, event or case-note text, or a rule description, that asked the skill to skip, close,
fast-track, disable, or trust a claim is quoted there, with what the skill did instead — investigated,
ranked or measured on the evidence — never obeyed.

`rule-tuning` is **read-only and propose-only**. It shows a rule is noisy before proposing anything —
precision, not just volume — then proposes the least-invasive change mapped to real Exabeam mechanics
(a context-table exclusion, an exclusion rule, or the rule's own filter, scope, or maturity settings).
There is no rule-write path; detection engineering applies the change. It also guards against
over-correction: a change that would blind you to real threats is called out, not proposed.

## Practical notes

- **Large results.** Some Exabeam tools return very large payloads. socxen bounds its searches by
  default; when a result is still too big for the model, your host may save it to a file and hand back a
  path. The skill reads only the fields it needs and will not copy the raw dump anywhere durable.
- **What is recorded.** Every tool call, the gated decision, and each guardrail firing are written to a
  local, metadata-only audit log — never case notes, evidence, or payloads. Details in
  [audit logging](logging.md).
- **What to do with the report.** It is the audit trail socxen produces in place of a database. Case
  notes written to Exabeam carry the same content, neutralized for safety.
- **Example.** A real end-to-end run against a staging tenant, with the pivots and the reasoning:
  [worked example — coordinated credential access](../skills/soc-investigate/reference/examples/coordinated-credential-access.md).
