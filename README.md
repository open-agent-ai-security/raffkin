<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Raffkin
**an agentic SOC skill suite for Exabeam New-Scale**

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

> ## 📘 Looking to install or use Raffkin? Start at the user guide.
> ### **[open-agent-ai-security.github.io/socxen](https://open-agent-ai-security.github.io/socxen/)**
>
> How to install on Claude Code or Codex, credentials, the safety gate, your first investigation,
> what gets logged. Everything on this page below the line is about how Raffkin is **built** —
> it is for people working on the code.

---

Raffkin gives an AI coding agent — **Claude Code or OpenAI Codex** — the job of a SOC analyst on an
Exabeam New-Scale tenant, with the guardrails and governance that make that safe to do. Three skills,
named for the person whose work they do:

| Skill | Whose work | What it does |
|---|---|---|
| **`soc-investigate`** | the analyst | one alert or case, from first look to written verdict — evidence, entity pivots, a benign hypothesis tested against a malicious one, then the write-up and the action |
| **`triage-cases`** | the shift lead | the open queue — clustered by attack shape, ranked by corroborated signal, a "start here" list; read-only across the sweep |
| **`rule-tuning`** | the detection engineer | the rules quietly wasting analyst attention, with the specific fix proposed — never applied |

**Dismissing an alert or closing a case is held behind two locks**: a gate the plugin ships and the
host enforces (a bundled hook on Claude Code, tool-approval policy on Codex), and the skill asking you
first. Containment is recommended for a human to perform in EDR or IAM; the plugin never executes it.
Nothing is hosted by us: Raffkin runs on the analyst's machine, against your tenant, through your own
model provider.

> ⚠️ **Pre-release software — for evaluation only.** Expect breaking changes between versions, and do
> not point it at alerts whose disposition matters without a human reviewing every action.

**See what it produces:** a worked investigation, from alert to verdict —
[coordinated credential access](plugin/skills/soc-investigate/reference/examples/coordinated-credential-access.md).

## How it's built

Five separable layers. A capable model with tool access is not, by itself, something you can let
near a SOC queue; the layers below are what make it one.

| Layer | Where | What it contributes |
|---|---|---|
| **Methodology** | [`plugin/skills/`](plugin/skills/) | the procedures the model follows: [`soc-investigate`](plugin/skills/soc-investigate/SKILL.md), [`triage-cases`](plugin/skills/triage-cases/SKILL.md), [`rule-tuning`](plugin/skills/rule-tuning/SKILL.md), sharing one safety spine |
| **Capability** | [`.mcp.json`](plugin/.mcp.json) · [`.mcp.codex.json`](plugin/.mcp.codex.json) | the Exabeam New-Scale MCP — search, alerts and cases, threat timelines, rules and MITRE context — bundled for each host |
| **Authority** | [`permissions.json`](plugin/skills/soc-investigate/permissions.json) | which calls run unattended, which stop for a human, which are denied — enforced by the host, not the model; one tier file drives the Claude Code hook and the Codex policy |
| **Guardrails** | [`plugin/connector/`](plugin/connector/) | a local bridge that treats telemetry as hostile input on the way in, neutralizes what the agent writes on the way out, and keeps an audit trail |
| **Evidence** | [`security/`](security/) · [`evals/`](evals/) | the red-team program and the agent-behavior verification that gate every release, the AI BOM and the SBOM, the regression harness |

## Repository layout

```
plugin/        the distributable plugin — the only directory installed on a user's machine
  skills/      the three skills and their reference material
  connector/   the MCP bridge and its guardrails
  hooks/       the Claude Code safety gate
  docs/        the user guide, published to the site by docs_build.py
security/      release gates: red team (redteam/), behavior verification (praxen/), design records, BOMs
evals/         regression harness for the skills
tests/         deterministic invariants, run in CI
scripts/       release tooling
```

## Working on Raffkin

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — branching (`dev` → `main`), tests, review, cutting a release.
- **[tests/end-to-end-testing.md](tests/end-to-end-testing.md)** — testing real code against a live tenant, and the post-promotion install test.
- **[security/](security/)** — how a release is red-teamed and behavior-verified, with the ledgers.
- **[SECURITY.md](SECURITY.md)** — reporting a vulnerability.

## Project sponsor

Raffkin is sponsored by [Exabeam](https://www.exabeam.com/), which contributed the initial code and
continues to support the project as part of its commitment to security in an increasingly agentic world.

## License

[Apache-2.0](LICENSE). Contributions require a DCO sign-off — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
