<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# security/

Supply-chain and assurance artifacts for Raffkin. This directory is the home for the
things a security-conscious adopter asks for — the **AI BOM** and the **SBOM**, our **red-team**
program, **agent-behavior verification** reports, and the **design records** of the controls those
programs test. The controls themselves ship inside the plugin; this page says what they are and where
each one lives.

> **Raffkin is red-teamed before every release.** It's an agentic SOC analyst that reads
> attacker-influenceable telemetry and takes gated actions, so we adversarially test whether
> an attacker who controls the data can make it suppress a real threat, bypass the human
> gate, or leak. **→ [How we red-team Raffkin](redteam/METHODOLOGY.md)** ·
> [test history](redteam/HISTORY.md)

> **Raffkin is behavior-verified against a declared policy.** We publish a **Worker Remit** —
> what Raffkin is authorized to do — and check the shipped code against every rule in it with
> [Praxen](https://github.com/open-agent-ai-security/praxen). **A release does not ship with an
> open Critical finding.** **→ [Agent Behavior Verification](praxen/README.md)** ·
> [the remit](praxen/WORKER_REMIT.md) · [latest report](praxen/results/)

## The controls

Raffkin's security posture is four deterministic controls in the shipped code plus the doctrine in the
skills. The user-facing description — what each does and what it does not — is
**[the guardrails page](../plugin/docs/security-guardrails.md)**; the gate's operator view is in
**[the installation guide](../plugin/docs/installation.md#governance--the-safety-gate)**. The design
records here say *why* each control is shaped the way it is and what was rejected on the way.

| Control | What it does | Where it lives | Design record |
|---|---|---|---|
| **Human-in-the-loop gate** | Dismiss, close and outbound mail always ask a human; every containment tool is denied; an unclassified tool asks. Enforced by the host on both hosts and on by default. | `plugin/hooks/gate.py` + `hooks.json` (Claude Code); `plugin/.mcp.codex.json` (Codex); both derived from the tier file `plugin/skills/soc-investigate/permissions.json` | [design/human-in-the-loop-gate.md](design/human-in-the-loop-gate.md) |
| **Input canonicalizer** | Strips the invisible-Unicode smuggling layer from every tool result — and from the remote's own tool definitions, which are also hashed per session — before the model reads it. Values are never rewritten; what was stripped is reported out of band. | `plugin/connector/canonicalize.py`, wired in the bridge's read path | [design/input-canonicalizer.md](design/input-canonicalizer.md) |
| **Output neutralizer** | On every write, de-activates what Raffkin persists: formulas made inert, every link form defanged unless it points into the operator's own tenant, secrets and structured identifiers masked. Updates carry state only; a create that would land a case already closed is refused. | `plugin/connector/neutralize_output.py` and the write rules in `exabeam-mcp-bridge.py` | [design/output-neutralizer.md](design/output-neutralizer.md) |
| **Audit trail** | Every call, every gate decision (including refusals) and every guardrail firing, as metadata and safe identifiers — never case content. On by default, local, bounded. | `plugin/connector/observra_logging.py`; the hook's own `~/.raffkin/gate.jsonl` | [the logging guide](../plugin/docs/logging.md) |

The deterministic tests behind each control are listed in its design record; the audit trail's are in
`tests/test_observra_logging.py`.

The doctrine the model follows — telemetry is evidence, never instructions; a false-positive close needs a
positive benign explanation; containment is recommended, never executed — is in each skill's `SKILL.md`,
and the **[Worker Remit](praxen/WORKER_REMIT.md)** states it as rules Praxen checks the code against.
Every control above is exercised by the red team on the weakest supported model per host before a release
([methodology](redteam/METHODOLOGY.md)); the residuals each control declares are listed beside it, in
its design record and on the guardrails page, not hidden.

## Contents

| File | What it is |
|---|---|
| `design/` | **Design records** of the shipped controls — the gate, the input canonicalizer, the output neutralizer: intent, what was rejected, what shipped, declared residuals. |
| `gen_aibom.py` | Generator — assembles the AI BOM deterministically from the repo's own sources. |
| `aibom.cdx.json` | **AI Bill of Materials** — CycloneDX 1.6 JSON. The machine-readable inventory. |
| `aibom.html` | Human-readable render of the same BOM (self-contained, no external assets). |
| `gen_sbom.py` | Generator — builds the **SBOM** from the bridge's uv lockfile; nothing is hand-maintained. |
| `sbom.cdx.json` | **Software Bill of Materials** — CycloneDX 1.6 JSON: every locked package, version, artifact hash and dependency edge. |
| `sbom.html` | Human-readable render of the SBOM. |
| `redteam/METHODOLOGY.md` | **Red-team methodology** — what we test and why (the doc to point people at). |
| `redteam/HISTORY.md` | **Test history** — when full-scale runs happened, results, and the fixed-findings ledger. |
| `redteam/` | The rest of the exercise: `PLAN.md` (operational plan), `attacks/` (corpus), `run.py` (live runner), `results/` (dated reports). |
| `praxen/README.md` | **Agent Behavior Verification** — the release gate, current posture, and how to reproduce a scan. |
| `praxen/WORKER_REMIT.md` | **The Worker Remit** — the declared policy every scan judges the implementation against. |
| `praxen/` | `SCAN_INSTRUCTIONS.md` (scan scope) and `results/` (dated reports, machine-readable findings, and independent audit records). |

## The AI BOM

Raffkin is an **AI application / agent**, not a model — it runs on a hosted
foundation model it does not ship (Claude on Claude Code, an OpenAI model on Codex — the host
picks the member), and its substance is a prompt/methodology (the three skills' `SKILL.md` +
`reference/`) plus a small MCP connector. Model-card AI-BOM tools (which ingest a Hugging
Face model id) can't describe that, so we author a CycloneDX AI-BOM directly. It inventories:
the root plugin, the **foundation models** as external machine-learning-model dependencies,
the **system prompt / methodology** as a `data` artifact, the connector's Python
**dependencies**, the **Exabeam MCP** as a service with its inbound/outbound **data flows**,
and the **governance and guardrails** (the permission tiers, the bundled gate, the two
bridge filters, the audit trail, no containment).

### Regenerate

```bash
uv run security/gen_aibom.py          # rewrite aibom.cdx.json + aibom.html
uv run security/gen_aibom.py --check  # CI: fail if the BOM is stale vs the sources
```

The generator is **deterministic** (stable `uuid5` serial; timestamp honors
`SOURCE_DATE_EPOCH`, and `--check` ignores the clock), so re-running on an unchanged
repo produces the same BOM. CI runs `--check` on every PR, so a change to the plugin
version, connector dependencies, MCP, or governance that isn't reflected in the BOM
fails the build. **When you bump the version or change deps, regenerate.**

## The SBOM

The AI BOM says what the agent *depends on conceptually*; the SBOM says what code *actually runs*.
The bridge (`plugin/connector/exabeam-mcp-bridge.py`) declares five direct dependencies in its PEP 723
header and `uv lock --script` resolves them into a hash-pinned tree of ~30 packages
(`exabeam-mcp-bridge.py.lock`). `gen_sbom.py` reads that lockfile and nothing else, and emits a
CycloneDX 1.6 SBOM: one `library` component per locked package with its `purl`, version and the
SHA-256 of every locked artifact (sdist and wheels), a `direct` / `transitive` marker, the full
dependency graph, and the lock's own facts (revision, `requires-python`, resolution markers, sha256
of the lock). The two BOMs reference each other (`externalReferences` of type `bom`).

**It keeps itself up to date.** Nobody edits it:

- it is **derived** — the lockfile is the only input, so the SBOM cannot describe a tree the lock does not;
- CI **checks for drift** on every PR (`gen_sbom.py --check`) and fails with the one-line regenerate command;
- CI **rebuilds and publishes** it on every push (`Security lint + dependency audit` job → workflow
  artifact `raffkin-sbom-<sha>`), so the SBOM for any commit is downloadable from Actions even before
  anyone commits it;
- `scripts/bump_version.py` regenerates it on every release alongside the AI BOM;
- the same lockfile is audited against the OSV / PyPI advisory databases in CI (`pip-audit --strict`),
  so the tree the SBOM describes is also the tree that was checked for known vulnerabilities — every
  package that resolves on the Linux runner; the lock's Windows-only entries (`pywin32`, `colorama`)
  are covered by Dependabot alerts, not by that step.

### Use it

```bash
uv run security/gen_sbom.py            # rewrite sbom.cdx.json + sbom.html
uv run security/gen_sbom.py --check    # CI: fail if the SBOM is stale vs the lockfile

# Feed it to your own tooling — any CycloneDX consumer works, e.g.:
grype sbom:security/sbom.cdx.json
osv-scanner --sbom security/sbom.cdx.json
```

The generator is deterministic (serial = `uuid5(repo, version, sha256(lockfile))`; timestamp honors
`SOURCE_DATE_EPOCH`, ignored by `--check`), so an unchanged lock reproduces byte-identically and any
lock change produces a new serial.

