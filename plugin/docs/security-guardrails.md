<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Security

Everything Raffkin does to be safe to point at a live tenant, on one page: the human gate on
consequential actions, the guardrails on what it reads and writes, the audit trail, how it is tested,
and what it deliberately does not cover.

The starting point is that **your log data is untrusted input**. Anyone who can get an event into your
telemetry — a phishing sender, a malware sample, a probing attacker — can plant something in it on
purpose, knowing an analyst or an AI agent will read it later: an instruction hidden in invisible
characters, a link that should never be clicked, a formula that runs when a report is exported. Raffkin
assumes that content is there, and every control below exists so that it cannot do harm through
Raffkin.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="diagram/guardrails-dark.png">
    <img alt="Raffkin guardrail bridge: your agent (Claude Code or Codex) talks to a local bridge MCP that proxies to the remote Exabeam MCP. On writes, neutralize_output defangs formulas and links and redacts secrets/structured identifiers in free-text fields (fail-closed); on reads, canonicalize strips invisible smuggling before the agent reasons (fail-closed: a block it cannot process is withheld); observra records a metadata-only audit trail (never note text, evidence or payloads)." src="diagram/guardrails-light.png" width="100%">
  </picture>
</p>

## A human before anything is dismissed or closed

Dismissing an alert or closing a case is the one action where an AI mistake does real harm — a genuine
threat suppressed. Raffkin holds it behind **two locks**, both on from the moment you install:

- **The host's gate.** On Claude Code, a hook that ships inside the plugin stops the dismiss or close
  call and asks you; it holds even when Claude Code is run with permissions skipped, and when no human is
  present the call is refused. On Codex, the plugin ships the same rule as tool-approval policy, and Codex
  asks before every write and cancels it when nobody is there to answer.
- **The skill asking you.** Before it dismisses or closes, Raffkin asks in plain words — *"Dismiss alert
  X as a false positive? (yes / no)"* — and waits. Say no, or nothing, and nothing happens.

Both must open. Outbound mail (`exabeam_send_email`) is behind the same gate, and the Exabeam service
only accepts recipients who are users of your own subscription.

Opening a case and writing a case note are safe escalations and run without asking — up to a point. On
Claude Code the gate allows **two** of them per session; a third, or a second new case in the same
session, asks you. A single investigation opens at most one case and documents it, so the prompt only
appears when something is acting at scale, such as a queue sweep talked into opening a case for every
item.

**What Raffkin never does:** isolate a host, disable an account, block an address, kill a process — any
containment. The Exabeam MCP exposes no such tools, and the gate refuses them outright as a second
safeguard. When containment is warranted, the report *recommends* it for you to carry out in your EDR
or IAM. Rule changes are the same: the tuning skill proposes, and the rule-write tools are refused.

## What it reads is screened

Before Raffkin reasons over any alert, case or event, the text is screened for **hidden-character
smuggling** — zero-width characters, direction-reversing marks and other invisible codes that let a line
read one way to a human and another way to software. The obvious smuggling is stripped; legitimate text
in any language is left alone. The tool descriptions the Exabeam MCP provides are screened the same way,
and a tool whose definition cannot be screened is withheld for the session rather than offered.

If the screen cannot process a piece of a result, that piece is withheld and the report names the gap;
unscreened platform text never reaches the model.

## What it writes is neutralized

When Raffkin writes back to Exabeam — a case note, an alert update, an email — it makes sure it never
re-arms a payload that was sitting in the original data:

- **Links are defanged.** A link in a note or email is written as `hxxps://example[.]com` so it cannot be
  clicked or auto-opened. The one exception is a link into **your own tenant**, which stays live. If a
  link in a Raffkin note looks "broken," that is the safety measure working: the address is still fully
  readable for a sandbox or a threat-intel lookup, it just cannot hurt anyone with a stray click.
- **Spreadsheet formulas are disarmed.** A value like `=HYPERLINK(...)` would run when an exported
  report is opened in a spreadsheet; Raffkin writes it as plain text.
- **Secrets and structured identifiers are masked.** An API key, token, private key or labeled password,
  a Social Security number or a payment-card number found in the alert data is written as
  `[REDACTED:…]`. The finding is recorded; the value is not copied into a note or export where a wider
  audience could read it. This is deterministic code, not the model remembering to redact.
- **Updates change state only.** An alert or case update can set a status, a stage, a priority, a
  closing reason or an assignee — never rewrite the description, name or tags an analyst wrote. Raffkin's
  reasoning goes into a case note, which appends.

## What it did is on the record

Every tool call, every gated decision (which alert or case, to what disposition) and every guardrail
firing is written to a local, structured audit log, on by default: `~/.raffkin/telemetry.jsonl`. It
records metadata only — never case notes, evidence or payloads — and can be routed to Exabeam, an
OpenTelemetry collector or a webhook. See [Audit logging](logging.md).

## Where your data goes

Three facts, and they are good ones:

- **Raffkin stores nothing.** No server, no database, no queue, no hosted service. The audit log is a local
  file holding metadata only. Exabeam holds what it already held, plus the case notes and the case and alert
updates you approve.
- **What Raffkin retrieves does enter the model's context** — event lines, alert and case content, identity
  and host context, threat timelines, rule logic — and therefore reaches whichever model provider your
  host agent is configured with. That is how the analysis happens.
- **Raffkin does not supply, choose or configure that provider.** You bring your own Claude Code or Codex,
  your own authentication, your own agreement. Residency, retention and processing terms are whatever
  your agreement with your provider says; Raffkin is not a party to it and cannot change it.

Compared with a hosted SOC agent, where the vendor runs the analysis and holds a copy of your telemetry
under its own posture, there is no middle here: Raffkin runs on the analyst's machine, against your
tenant, through your provider, on your terms.

## How it is tested

Claims about agent safety are worth what the testing behind them is worth, so the testing is public
and every release is gated on it:

- **Red team.** A corpus of poisoned alerts, notes, queue exports and rule inventories is driven
  against the real skills on the weakest supported model of each host, and graded on whether the
  attack *landed* — a wrong verdict, an obeyed instruction, a leaked secret — not on whether the model
  sounded cautious. A landing in the blocking classes stops a release until it is fixed, or waived in
  writing with the reason recorded.
- **Behavior verification.** Each release candidate is scanned against Raffkin's declared policy by an
  independent verifier, with an audit pass over the findings and a threat model. No release ships with
  an open Critical finding; every other finding is triaged into an issue, and the decision to ship with
  it is written down beside the scan.
- **Bills of materials.** Every release carries an AI BOM and a software BOM listing the models, tools
  and dependencies in play.

The methodology, every dated run and the known residuals are in the repository's
[`security/`](https://github.com/open-agent-ai-security/socxen/tree/main/security) directory.

## What these controls do not cover

- **Your own screen.** Redaction protects what Raffkin *persists*. A secret shown to you during an
  investigation is not masked, because you are already authorized to read that log.
- **Very large results.** When a result is too big for the model, your host may save it to a local
  file, unredacted, and it persists after the session. Delete those files when the case data is
  sensitive; on Codex, treat the session history under `~/.codex/` the same way.
- **Free-form personal data.** Redaction catches structured secrets and identifiers. It does not chase
  names, addresses or dates of birth in prose; handle those with the care you would give any case.
- **A credential with nothing to grip** — no label, no quotes, no recognizable format — is caught on a
  best-effort basis. Treat a known-exposed password as compromised regardless of what the note shows.
- **Links you read directly.** The defanging applies to what Raffkin writes. A link typed as prose in an
  alert may be left as written; verify any URL out of band before you trust it.
- **A server you wire by hand.** The screening, the neutralizer and the audit trail live in the bundled
  connector; registering the remote Exabeam MCP directly bypasses all three, leaving only the
  dismiss/close gate. Use the bundled connector for any investigation you rely on.
- **A queue sweep's restraint, below the budget.** During a triage sweep the skill is instructed not to
  write. The host gate cannot tell a sweep from an investigation, so up to two escalation writes in a
  session are stopped by the instruction alone; past that the gate asks you. On Codex the budget does not
  apply yet. Dismiss, close and containment stay gated in a sweep exactly as everywhere else.
- **Judgment.** These controls reduce the blast radius of hostile content. They do not replace the human
  gate, your SOC procedures, or your own review of the verdict.

## Advanced: mirroring the tiers in host policy

Organizations that manage Claude Code through policy can mirror the plugin's allow, ask and deny rules
as host permission rules, so the same tiers show up in your policy tooling. The plugin publishes them,
generated from its tier file, as `skills/soc-investigate/settings.snippet.json` inside the installed
plugin. Applied through managed settings, the two layers agree on every tool because both come from one
source. This adds nothing to the gate itself, which is on from install.
