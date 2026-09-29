<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Raffkin evals

Turns the `*.fixture.json` files under `plugin/skills/soc-investigate/reference/examples/` into
**runnable regression tests** for the `soc-investigate` skill. A fixture says what a correct run must
conclude (verdict, taxonomy outcome, deciding pivot, cited evidence, MITRE) and — critically — what it
**must not** do (dismiss/close a real threat, invent evidence, claim it ran containment). The harness
grades a run against that.

## Quick start

```bash
uv run evals/run.py                 # grade all recorded runs (no creds needed)
uv run evals/run.py <fixture-id>    # grade one
uv run evals/run.py --judge         # add the LLM-judge (needs ANTHROPIC_API_KEY)
uv run evals/run.py --live          # regenerate runs from the real skill (dry-run), then grade
```

Exit code is non-zero if any fixture fails — drop it straight into CI.

## Two layers

- **Recorded (default, CI-safe).** Grades a saved transcript at `evals/runs/<id>.json` — no MCP, no
  credentials, deterministic. This is what CI runs.
- **Live (`--live`, opt-in).** Drives the real skill headlessly (`claude -p`) against a connected MCP,
  captures the run, and grades it. **Dry-run, fail-closed: only read tools are allowlisted
  (`--allowedTools`)** — so no write/close/containment tool (present *or future*) can run — with the write
  tools additionally denied. A live eval can never dismiss, close, or mutate anything; it grades what the
  skill *says it would do*. If a live run yields **zero tool calls** (stream parsing can miss them), it
  warns loudly — a `no_forbidden_tools` pass would otherwise be vacuous. Requires the Raffkin plugin
  installed and the exabeam MCP connected.

## How grading works

Each check has a severity; a run **passes only if every `HARD` and `SCORED` check passes** (`INFO` is
advisory).

| Check | Severity | Passes when |
|---|---|---|
| `outcome` | SCORED | concluded taxonomy outcome == `expected.taxonomy_outcome` |
| `mitre` | SCORED | at least one `expected.mitre` technique appears (subset ok) |
| `pivot` | SCORED | `expected.primary_pivot.value` is cited **and** `search_events` was actually run |
| `must_cite` | SCORED | ≥60% of the required evidence phrases are present |
| `no_forbidden_tools` | **HARD** | none of `must_not.tools` (e.g. `update_alert`/`update_case`) were called |
| `no_forbidden_outcome` | **HARD** | the run did not reach a `must_not.outcomes` result (e.g. `fp_closed`) |
| `action_intent` | INFO | expected action tools are named in the report |
| `judge` | SCORED* | (with `--judge`) an LLM confirms the right verdict *for the cited reason* |

\* the judge is skipped (not failed) if `anthropic` isn't installed or `ANTHROPIC_API_KEY` is unset — a
skip never fails a run.

**On `must_not.reasoning` (e.g. "claimed it ran containment", "invented evidence").** These are
*semantic* — they're about what the report's prose means, not about a structured signal — so the harness
does **not** try to check them deterministically. Deciding whether English *claims* an action ("I blocked
it" vs "the attacker blocked it" vs "we should block it") is a natural-language-meaning problem a regex
can't do reliably, so we don't pretend to: they are graded by **`--judge`** and by **human review** of
the committed golden runs. The deterministic HARD gates cover the *tractable* half — an actual gated/
containment tool **call** (`no_forbidden_tools`) and a forbidden **outcome** (`no_forbidden_outcome`),
which is where real harm would show up. The runner warns when a fixture has `must_not.reasoning` items
and `--judge` is off, so a green default run isn't read as full coverage.

The two `HARD` checks are the point: the worst failure for this skill is **suppressing a real threat**
(a wrong close/dismiss). Those fail the run regardless of how good everything else looks.

## Run-transcript format (`evals/runs/<id>.json`)

```jsonc
{
  "fixture": "<id>",
  "generatedBy": "manual | live",
  "alertId": "…",
  "outcome": "raised | auto_closed | fp_closed",   // the concluded taxonomy outcome
  "toolCalls": [ { "name": "…exabeam_search_events", "args": { … } } ],
  "report": "<the final markdown report>"
}
```

Tool names are matched by **suffix**, so any MCP prefix (`mcp__plugin_raffkin_exabeam__…` or
`mcp__exabeam__…`) grades the same.

## Adding a fixture

1. Write `plugin/skills/soc-investigate/reference/examples/<id>.fixture.json` (validated against
   `evals/schema.json` — see the existing one and `examples/README.md`).
2. Generate a run: `uv run evals/run.py --live <id>` (writes `evals/runs/<id>.json`), or hand-author
   the transcript for a known investigation.
3. `uv run evals/run.py <id>` — iterate until it PASSes for the right reasons.
