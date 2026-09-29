<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Raffkin Documentation

**Raffkin** is an agentic SOC analyst for **Exabeam New-Scale**, delivered as a plugin for Claude Code and
OpenAI Codex. Hand it an alert or a case and it investigates the way a careful analyst would: gathers the
evidence itself, builds the timeline, reaches a threat / false-positive verdict, and acts — with the
human-in-the-loop gate on dismiss and close **shipped on**, containment **recommended, never executed**, and
every call on an audit trail.

> *Every claim traceable to a call it made. Every irreversible action behind a human's yes.*

<!-- community-only -->
*Raffkin is an open-source project sponsored by [Exabeam](https://www.exabeam.com/), published by the
[Open Agent and AI Security community](https://open-agent-ai-security.github.io/).*
<!-- /community-only -->
<!-- distribution-only
*The software in this copy is Raffkin, open source under the Apache License 2.0; see [Support](support.md)
for the terms this copy is distributed and supported under.*
/distribution-only -->

## Where to start

| If you are… | Read this first |
|---|---|
| Installing Raffkin for the first time | [Installation & setup](installation.md) — a five-minute quick start for Claude Code or Codex: install, credentials, check, first investigation |
| About to run your first investigation | [Using the skills](usage.md) — what to say, what happens, what Raffkin asks you before it acts, and how to read the report |
| Wanting to see a real one end to end | [Example investigation](../skills/soc-investigate/reference/examples/coordinated-credential-access.md) — a coordinated credential-access case, from intake to verdict |
| Wondering what keeps this safe, or why a link in a note looks "broken" | [Security](security-guardrails.md) — the human gate, the guardrails on what Raffkin reads and writes, the audit trail, how it is tested, and what it does not cover |
| Asked "what did the agent actually do?" | [Audit logging](logging.md) — the on-by-default audit trail: what is recorded, what deliberately is not, where it lives |
| Looking for help | [Support](support.md) — where to ask for help, and the terms this copy is supported under |

## The three skills

| Skill | Ask it | What it does |
|---|---|---|
| **`soc-investigate`** | *"Investigate alert 4821."* · *"Is this a real threat?"* | One alert or case at depth: evidence, timeline, MITRE ATT&CK mapping, verdict, then the non-destructive action — open a case, dismiss an alert, write notes — and a containment recommendation for a human to carry out. |
| **`triage-cases`** | *"What should I look at first?"* · *"Morning triage."* | Sweeps the open queue, clusters cases by attack shape, ranks them by corroborated signal, and returns a short "start here" list plus the noise clusters worth tuning. Read-only. |
| **`rule-tuning`** | *"Which rules waste our time?"* · *"Reduce alert noise."* | Separates loud rules from noisy ones and proposes specific tuning mapped to real Exabeam mechanics — a context table, an exclusion, the rule's own settings. Proposes; never changes a rule. |

## How Raffkin works (in 90 seconds)

1. **You hand it the work** — an alert ID, a case ID, or a pasted payload — in your Claude Code or Codex session.
2. **It gathers evidence through the Exabeam MCP**, via a bundled connector that screens what comes back, and reasons only over what it retrieved. Content in your telemetry is evidence, never instructions.
3. **It reaches a verdict and acts within the gate.** Escalating and annotating pass the gate (on Codex the host still asks — Exabeam's annotation of those tools, not Raffkin's); dismissing an alert or closing a case asks you first, every time; containment is written up for you to perform.
4. **Everything is on the record** — the calls, the gated decision, the guardrail firings — in a local audit trail, on by default.

```mermaid
flowchart LR
  A["Analyst<br/>alert · case · payload"] --> S{{"Raffkin skill"}}
  S --> C["Bundled connector<br/>screen · neutralize · audit"]
  C <--> X["Exabeam New-Scale MCP"]
  S --> G{"Human-in-the-loop gate"}
  G --> W["Escalate · annotate<br/>(passes the gate)"]
  G --> H["Dismiss · close<br/>(asks you first)"]
  S --> R["Report<br/>verdict · timeline · outcome"]
```

## The guardrails, in brief

- **The gate ships on.** A dismiss or close always asks the analyst; containment tools are refused outright; any tool the gate has not classified asks rather than runs. It holds even when the host runs with permission prompts switched off.
- **What it reads is screened.** Hidden-character smuggling is stripped from telemetry before the model sees it; the tool definitions the Exabeam MCP hands it are hashed and screened too.
- **What it writes is de-activated.** Spreadsheet formulas, clickable links and secrets are neutralized in anything Raffkin persists — case notes, updates, outbound mail.
- **What it did is recorded.** Tool calls, gated decisions and guardrail firings, never case content, in `~/.raffkin/telemetry.jsonl`.

Details, how it is tested, and what these do not cover: [Security](security-guardrails.md).

## Quick reference

- Install: `claude plugin marketplace add open-agent-ai-security/plugins` then `claude plugin install raffkin@open-agent-ai-security` (Codex: `codex plugin marketplace add open-agent-ai-security/plugins` then `codex plugin add raffkin@open-agent-ai-security`)
- Credentials: `~/.exabeam-mcp.env` — the Exabeam MCP URL, API key and secret; see [Installation](installation.md)
- Skills: `soc-investigate` · `triage-cases` · `rule-tuning`
- Audit trail: `~/.raffkin/telemetry.jsonl` — see [Audit logging](logging.md)
- Check your setup: `preflight.sh` in the installed plugin — see [Installation](installation.md)
- Windows: not supported natively — use WSL (Git Bash cannot protect the credentials file)
- Help: [Support](support.md)

For version history see the [CHANGELOG](https://github.com/open-agent-ai-security/socxen/blob/main/CHANGELOG.md). Working on the code? The developer material lives in the [repository](https://github.com/open-agent-ai-security/socxen#working-on-raffkin).
