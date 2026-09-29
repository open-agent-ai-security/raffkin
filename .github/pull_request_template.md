<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

<!--
  Thanks for sending a PR to Raffkin.

  Base branch: target `dev`, not `main`. `main` is the live install channel and
  only receives release PRs. If GitHub defaulted the base to `main`, switch it to
  `dev` (unless you are specifically cutting a release).

  Sign off your commits under the Developer Certificate of Origin (`git commit -s`).
  See CONTRIBUTING.md. Fill in the sections below; if one doesn't apply, say so
  explicitly rather than deleting it — it tells reviewers you considered it.
-->

## Summary

<!-- What does this PR change, and why (motivating problem, linked issue/RFE, field
report)? One or two sentences. Link issues with `Closes #N` / `Refs #N`. -->

## Testing

<!-- How did you verify it?
  - `uv run --with pytest pytest -q tests/` — paste the one-line result.
  - For eval changes: which fixtures/recorded runs you ran and that the HARD gates pass.
  - Docs-only: "n/a — docs only" is fine. -->

## Governance impact

<!-- REQUIRED — a wrong answer here is how a safety gate silently regresses.

Does this PR touch permissions.json (or its generated settings.snippet.json / .mcp.codex.json),
hooks/gate.py, reference/containment-tools.md,
reference/tool-map.md, the SKILL.md Governance section, the connector bridge, or
the eval HARD gates?

  - No  → write "None."
  - Yes → describe the change and confirm the dual-lock still holds: dismiss/close
          stays in `ask` (never `allow`), containment stays denied and in sync with
          the doc, and no new path can auto-close or execute containment un-gated.
          The invariant tests check the mechanical parts; explain the intent. -->

## Notes for reviewers

<!-- Anything to look at first, design choices worth flagging, deferred follow-up. Optional. -->
