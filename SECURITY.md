<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

Raffkin is a security tool that investigates real alerts and can take gated actions
against a SOC platform. We take vulnerabilities in Raffkin itself seriously. This
document describes how to report one privately, what is in scope, and what to expect.

## Scope

**In scope** — vulnerabilities in Raffkin itself:

- The three skills — the methodology, governance rules, and reference material in
  `plugin/skills/soc-investigate/`, `triage-cases/` and `rule-tuning/` (`SKILL.md`, `reference/`).
- The **human-in-the-loop gate**, on both hosts: the bundled Claude Code hook
  (`plugin/hooks/gate.py`, `hooks.json`), the Codex tool-approval policy (`plugin/.mcp.codex.json`),
  the tier file they are derived from (`plugin/skills/soc-investigate/permissions.json`) and the
  generators (`plugin/gen_identity.py` with `identity.json`; `scripts/gen_codex_mcp.py`) — anything
  that could silently un-gate a dismiss/close, mail or containment-class tool, let a gated call through
  headless, or regenerate a gate that doesn't take effect.
- The **published permission snippet** (`settings.snippet.json`, the same tiers for organizations that
  push them as host policy) and `reference/containment-tools.md` (the deny-list) — a generated rule
  that loosens a tier.
- The connector bridge `plugin/connector/exabeam-mcp-bridge.py` and its two filters — the
  **input canonicalizer** (`canonicalize.py`, including the screen over the remote's tool
  definitions) and the **output neutralizer** (`neutralize_output.py`) — plus the bridge's own
  write rules: updates carry state only, a `create_case` with a closing disposition is refused, a
  tool this release has not classified as a read is treated as a write. Also OAuth token/secret
  handling and the stdio forwarding path.
- The **audit trail** (`plugin/connector/observra_logging.py`, the hook's `gate.jsonl`) — a way to
  make it record case content, or to make a gated decision or guardrail firing go unrecorded.
- The eval harness `evals/` and its HARD safety gates; the red-team runner and grader
  (`security/redteam/run.py`).
- The plugin manifests (`plugin/.claude-plugin/`, `plugin/.codex-plugin/`), the bundled
  `plugin/.mcp.json` / `.mcp.codex.json`, `plugin/install.sh` and `plugin/preflight.sh`.
- The connector's dependency pinning — the bounded PEP 723 header and the hash-pinned
  `plugin/connector/exabeam-mcp-bridge.py.lock` (supply-chain integrity of what a fresh install
  resolves).

Examples of in-scope issues:

- a prompt-injection carried in ingested alert/event data that flips a verdict or **bypasses the
  human dismiss/close gate**;
- hidden-character smuggling that survives the canonicalizer;
- a formula, link or credential that survives the neutralizer into a persisted note, update or mail;
- a close by another route — a create that lands closed, an update that overwrites analyst text;
- a flaw that lets the bridge log or leak the Exabeam OAuth token or API secret;
- a governance drift that lets a close/containment tool run un-gated, or makes the hook fail *open*;
- a way to make the skill claim or execute containment, or auto-close a case, without the human
  approval the model promises;
- a tampered install path.

**Out of scope:**

- **Findings Raffkin produces about *your* alerts.** If Raffkin investigates an alert
  and reaches a verdict you disagree with, that's tool output (or a tuning issue),
  not a vulnerability. It is also expected that Raffkin surfaces suspicious activity —
  that's its job.
- **The Exabeam New-Scale platform or its MCP server.** Raffkin is a client of the
  Exabeam MCP; issues in the platform, its API, or the MCP server belong with
  Exabeam support/security, not here.
- **General LLM behavior** (hallucination, refusals) not tied to a Raffkin-specific
  defect. Raffkin's own mitigations — evidence-grounding, the gate, the two bridge filters,
  untrusted-input handling — *are* in scope; a way to defeat them is a vulnerability.
- **The residuals each control declares** — listed on the
  [guardrails page](plugin/docs/security-guardrails.md#what-these-guardrails-do-not-do) and in
  [`security/design/`](security/design/). A report that one of them is real is welcome as an
  issue; it is not a vulnerability until it defeats something the control claims to do.

## Reporting a vulnerability

**Do not file a public GitHub issue for a security vulnerability.**

Use GitHub's private security advisory:

1. Go to the **Security** tab on this repository.
2. Click **Report a vulnerability**.
3. Include enough detail to reproduce — the crafted alert/case or event payload, the
   observed behavior (e.g. the gate that was bypassed), and what should have happened.

GitHub creates a private advisory thread between you and the maintainers; we respond
there. If private advisories are unavailable to you, email **developer@exabeam.com**
with the subject **`Raffkin security report`** and the same level of detail.

Please **do not** include live credentials, real customer data, or unredacted PII in
a report — a synthetic repro against a test tenant is preferred.

## What to expect

- **Initial acknowledgement:** within 3 business days.
- **First substantive reply** (scope, severity, plan): within 10 business days.
- **Fix timeline:** severity-dependent; gate-bypass and credential-leak classes are
  prioritized.
- **Coordinated disclosure:** we prefer to ship the fix, then publish an advisory
  (crediting you unless you ask otherwise) and coordinate public-disclosure timing.

## Supported versions

Raffkin is pre-`1.0`; security fixes ship in the **latest** release. Upgrade to the
newest version (`claude plugin update raffkin@open-agent-ai-security`) before reporting. There is no
back-port or LTS branch while pre-`1.0`.
