<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Raffkin
**An agentic SOC skill suite for Exabeam New-Scale — a plugin for Claude Code and OpenAI Codex.**

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-v0.9.0-blue)](.claude-plugin/plugin.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

> 📘 **The user guide is at [open-agent-ai-security.github.io/socxen](https://open-agent-ai-security.github.io/socxen/)** —
> installation, your first investigation, security, logging and support. This file is the same guide's
> front door for readers arriving from the plugin itself.

> ⚠️ **Pre-release software — for evaluation only.** Raffkin is under active development. Expect
> breaking changes between versions, and do not rely on it for production SOC operations or point it
> at alerts whose disposition matters without a human reviewing every action.

Raffkin gives your AI coding agent the job of a SOC analyst on an Exabeam New-Scale tenant. Three
skills work the tenant through the Exabeam MCP — one case, the whole queue, or the rules behind it —
each named for the person whose job it does. No server, no database, no approval queue: the analyst at
the terminal is the human in the loop, and dismissing or closing anything is held behind **two locks
out of the box** — a gate the plugin ships and your host enforces, and the skill asking you first.

## The three skills

| Skill | Whose work it is | What it does |
|---|---|---|
| **`soc-investigate`** | the analyst | One alert or case, first look to written verdict: gathers the evidence itself, pivots on the entities, weighs a benign explanation against a malicious one, and acts — opens or updates a case, writes notes, escalates. Asks you before any dismiss or close. |
| **`triage-cases`** | the shift lead | The open queue rather than one case: clusters by attack shape, ranks by corroborated signal, hands back a short "start here" list. Read-only across the sweep. |
| **`rule-tuning`** | the detection engineer | Finds rules that are *noisy*, not merely loud, and proposes the specific change mapped to real Exabeam mechanics. Propose-only: the MCP's rule-write tools are refused on both hosts. |

Each hands off to the others: a single case to `soc-investigate`, a noise cluster to `rule-tuning`.

## What it does

- 🔍 **Investigates** on the real Exabeam read surface — events, alerts, cases, threat timelines, rule
  details, MITRE coverage, context tables.
- ⚖️ **Decides** against a disciplined bar — a false-positive close requires a *positive* benign
  explanation, never merely "I found nothing"; in doubt it escalates rather than silently suppressing.
- 🗂️ **Prioritizes the queue** so the urgent cases are impossible to miss.
- 🔧 **Tunes the source of the noise** so the fix lands on the detection instead of on the analyst.
- ✍️ **Acts** — opens or updates a case, writes notes, dismisses true false positives (gated), and
  **recommends** containment for you to perform in EDR or IAM. It never executes containment.
- 🔒 **Stops where it should** — dismiss and close sit behind a host-enforced gate that ships on, on
  both hosts. No settings to edit.
- 🛡️ **Treats telemetry as hostile** — hidden-character smuggling is stripped from what it reads;
  formulas and links are disarmed and secrets and structured identifiers masked in what it writes.
- 🧾 **Logs what it did** — a structured, local, privacy-preserving audit record, on by default.

## Get started

1. Install: `claude plugin marketplace add open-agent-ai-security/plugins` then
   `claude plugin install raffkin@open-agent-ai-security` (Codex: `codex plugin marketplace add …`,
   `codex plugin add …`).
2. Add your Exabeam API key and secret to `~/.exabeam-mcp.env`.
3. Run `preflight.sh` from the installed plugin to check the connection and the gate.
4. Say *"investigate alert `<id>`"*.

The full five-minute quick start, with what to expect at each step, is in
**[Installation & setup](docs/installation.md)**.

## Documentation

| Page | What's in it |
|---|---|
| **[Installation & setup](docs/installation.md)** | quick starts for Claude Code and Codex, credentials, troubleshooting, updating (**start here**) |
| **[Using the skills](docs/usage.md)** | what to say, what happens, what Raffkin asks you, how to read the report |
| **[Example investigation](skills/soc-investigate/reference/examples/coordinated-credential-access.md)** | a real run, from alert to verdict |
| **[Security](docs/security-guardrails.md)** | the human gate, the guardrails, the audit trail, how it is tested, what it does not cover |
| **[Audit logging](docs/logging.md)** | exactly what is recorded, where the log lives, how to route or disable it |
| **[Support](docs/support.md)** | where to ask for help, and the terms this copy is supported under |

## Status

Pre-release, for evaluation. Every release is red-teamed on the weakest supported model of each host and
behavior-verified before it ships; the runs, the findings and any waivers are public in the repository's
[`security/`](https://github.com/open-agent-ai-security/socxen/tree/main/security) directory. The version
badge above and the [changelog](https://github.com/open-agent-ai-security/socxen/blob/main/CHANGELOG.md)
track the current release; `claude plugin list` (or `codex plugin list`) shows your installed version.

## Project sponsor

Raffkin is sponsored by [Exabeam](https://www.exabeam.com/). Exabeam contributed the initial code and
continues to provide ongoing support and contributions to the project as part of its commitment to
security in an increasingly agentic world.

## License

<!-- community-only -->
Apache-2.0 — see `LICENSE` / `NOTICE`. Raffkin is community supported, as is; see
[Support](docs/support.md).
<!-- /community-only -->
<!-- distribution-only
This copy is distributed under the terms in `LICENSE`; the software it includes is open source under the
Apache License 2.0 — see `LICENSE-APACHE` and `NOTICE`. Support: [Support](docs/support.md).
/distribution-only -->
