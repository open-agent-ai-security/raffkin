<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Contributing to Raffkin

Thanks for helping improve Raffkin. Contributions are welcome via pull request.
Raffkin is a small, safety-sensitive project — an agentic SOC skill suite whose
whole value is a disciplined investigation and a **human-gated** dismiss/close.
So the bar for changes that touch the governance surface is high, and a couple of
conventions below exist specifically to keep that gate real.

## License

Raffkin is licensed under the [Apache License, Version 2.0](plugin/LICENSE). By
contributing, you agree that your contributions are licensed under the same terms.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA — a lightweight way to certify you wrote the contribution, or
otherwise have the right to submit it under the project's license.

Add a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git adds it for you with `-s`:

```
git commit -s -m "Your commit message"
```

The name and email must be a known identity — your real name, or an established
identity you're known by in the community (a long-standing handle counts),
reachable at the address you sign with. Anonymous or throwaway identities aren't
accepted. Sign-off is **required**, and CI
enforces it: the `DCO` workflow checks every commit in your PR and tells you
exactly which commits to amend if one is missing. The rule is the same for
maintainers and Exabeam employees; only bot commits are exempt.

<details><summary>Full DCO text</summary>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this license
document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications, whether
    created in whole or in part by me, under the same open source license
    (unless I am permitted to submit under a different license), as indicated in
    the file; or

(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public and
    that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may be
    redistributed consistent with this project or the open source license(s)
    involved.
```
</details>

## Branching

Branch from and target **`dev`**, not `main`.

`main` is the **live install channel**: a fresh
`claude plugin marketplace add open-agent-ai-security/plugins && claude plugin install raffkin@open-agent-ai-security`
pulls `main` at HEAD (the community marketplace pins this repo's `main` branch), so
anything merged to `main` reaches installers immediately.
`main` therefore receives only deliberate, re-verified releases — everyday work
lands on `dev` first.

When you open a PR, GitHub pre-selects the base as the repository default (`main`);
confirm it's **`dev`** unless you are specifically cutting a release. A PR into `main`
from anything but `dev` fails the **`PRs into main come from dev`** check, which tells
you how to fix it. If you get it, you don't need to close anything: click **Edit** next to
the PR title and change the base to `dev`. Commits and review history carry over.

### If your checks look missing rather than failing

On your **first** contribution from a fork, GitHub holds the workflow runs until a
maintainer approves them. Until that happens the PR shows *no checks at all* — which
looks like "nothing to do" but actually means **nothing has run yet**, including the
DCO sign-off check. It is not a failure and it is not something you can fix from your
side; a maintainer will approve the run. Don't read an empty check list as a pass.

No write access? **Fork** Raffkin, branch from `dev` in your fork, and open the PR
against `dev` here — fork PRs run the same CI and DCO checks.

The invariant we hold: **`main` is always an ancestor of `dev`** — `dev` is `main`
plus the unreleased work, never a divergent history.

- **Feature work → `dev`: squash-merge.** Short-lived branches, deleted on merge.
- **Release `dev → main`: merge commit, never squash** (`gh pr merge <n> --merge`).
  A squash discards the shared-parent link and drifts the branches apart. Author
  the version bump + `CHANGELOG` on `dev` first, promote with a merge commit, then
  **fast-forward `dev` back up** so `main` stays an ancestor:
  ```
  git fetch origin && git checkout dev && git merge --ff-only origin/main && git push origin dev
  ```

A scheduled CI check (`.github/workflows/branch-drift.yml`) asserts the invariant
daily and fails the day the histories diverge — catching a missed fast-forward or
an accidental squash promotion before it accumulates.

### Release gates

Two assurance gates run before a release. Both are **documented gates a human runs**, not CI
checks — each is an agentic, judgment-based analysis rather than a deterministic test, so
neither belongs in a workflow that must go green on every push.

| Gate | Blocks a release when | Where |
|---|---|---|
| **Red team** | Any class-A unsafe suppression, class-C gate bypass, or class-D secret/PII leak on the weakest supported model | [`security/redteam/PLAN.md`](security/redteam/PLAN.md#release-bar) |
| **Agent Behavior Verification** | Any **Critical** finding in a Praxen scan of the release candidate | [`security/praxen/README.md`](security/praxen/README.md#the-release-gate) |

A blocking finding from either gate is **fixed, or explicitly waived in writing by a
maintainer with a rationale recorded in the PR**, before the release merge. High / Medium / Low
Praxen findings do not block; they are triaged into issues and carried in the backlog.

Both gates want a **dated artifact** committed alongside the result — `security/redteam/results/`
and `security/praxen/results/` respectively — so a reader can tell which release was
actually verified, and when.

### If the histories have already diverged

Don't squash-paper-over it — reconcile so the invariant holds again. Rebuild on a
**temporary branch** off `origin/main` (never `reset --hard` `dev` in place, or
you lose the commit hashes you still need):

```
git checkout -b dev-rebuild origin/main
git cherry-pick --signoff <the unreleased commits>   # the new work only
git diff origin/dev dev-rebuild                       # MUST be empty (byte-identical)
git push --force-with-lease origin dev-rebuild:dev
```

We deliberately keep the rest of the release machinery light for now: **no
tag-driven release automation**. Dependabot opens weekly pin bumps for the GitHub
Actions workflows against `dev` (label `dependencies`); the connector's Python
dependencies are locked by `uv` and audited in CI, not bumped by bot. Tagged
releases arrive when Raffkin has a real release cadence; until then the rules above
are the whole model.

## Releasing and rolling back

*(Maintainers.)* Raffkin cuts releases as `dev → main` merge commits — no tags, no
release artifacts. Because fresh installs pull `main@HEAD`, **`main` is the live
release channel**: whatever lands there reaches new installers immediately.

**Cutting a release**

1. Land all changes on `dev`. Run `uv run scripts/bump_version.py X.Y.Z`: it edits
   `plugin/identity.json`, regenerates both host manifests and `identity.sh` from it, rewrites
   the README pill, and regenerates the AI BOM and the SBOM. Date the `CHANGELOG.md` entry by
   hand, commit to `dev`.
2. Open the release PR `dev → main`; promote with a **merge commit** (never
   squash), then fast-forward `dev` back up (see Branching above). `main` is
   branch-protected: the merge needs the `Repo invariants (no inference)` and
   `signoff` checks green and every review conversation resolved.
3. Run the **post-release install smoke**: `scripts/release/plugin-smoke.sh <prior-release-ref>`.
   It runs two legs in throwaway scratch `$CLAUDE_CONFIG_DIR`s, never touching
   your live install: a **clean install** of the new release and an **upgrade** from
   the prior release. Each leg asserts the installed version *and* that the plugin
   **loads** (`plugin list --json` reports an empty `errors[]`, with a positive
   control that re-injects a known bad manifest field and expects the check to
   fail). Pass the prior release explicitly. It is deliberately *not* in CI: the
   `claude` CLI doesn't run in GitHub Actions, so this stays a maintainer-run
   check.
4. Run the **real-install test**, section C of
   [`tests/end-to-end-testing.md`](tests/end-to-end-testing.md): install the
   release from the catalog that serves it on each host, preflight from the
   install path, drive a skill with a separate agent session, and record the
   run in `security/redteam/HISTORY.md`. The release is done when steps 3 and
   4 have both run.

**Rolling back a bad release**

1. **Stop the bleed first.** Revert the offending change on `main` with a *new
   forward commit* (`git revert`), then fast-forward `dev`. Installs track
   `main@HEAD`, so the revert reaches new installers as soon as it lands.
2. **Cut a patch release** with the real fix when ready, via the normal flow.
3. **Never force-push `main` or `dev`** to "undo" a release — rewriting history
   breaks every clone and the `main`-ancestor-of-`dev` invariant. Forward revert
   plus a patch release is the only safe path.
4. Record the incident and the fix in `CHANGELOG.md`.

## Making a change

- **One logical change per PR.** Easier to review, easier to revert.
- **Run the tests before you push:**
  ```
  uv run --with pytest --with jsonschema --with observra --with typing_extensions pytest -q tests/
  ```
  These are deterministic, no-credential invariant checks; CI runs them on every
  PR and **must be green** to merge.
- **Governance-sensitive changes get extra scrutiny.** If you touch the tier file
  `plugin/skills/soc-investigate/permissions.json` (from which `settings.snippet.json` and
  `.mcp.codex.json` are generated — never edit those by hand), the hook `plugin/hooks/gate.py` /
  `hooks.json`, the generators `plugin/gen_identity.py` / `scripts/gen_codex_mcp.py`,
  `plugin/skills/soc-investigate/reference/containment-tools.md`,
  `plugin/skills/soc-investigate/reference/tool-map.md`, or the Governance section of
  `plugin/skills/soc-investigate/SKILL.md`, keep the permission tiers and the containment deny-list in
  sync — the invariant tests enforce this (dismiss/close and mail stay in `ask`, containment stays
  denied and matches the doc, the generated artifacts match the tier file). Call out the governance
  impact in your PR description.
- **A guard added to the neutralizer needs a witness and a mutation.** For any change to
  `plugin/connector/neutralize_output.py`: add the test that observes the new rule (a sample only that
  rule can catch — see `tests/test_neutralize_coverage.py` for the pattern), then add a mutation to
  `scripts/mutation_check.py` that deletes or loosens the rule, and run it: the suite must fail with
  the rule gone. CI runs the gate on every PR (#120).
- **Version bumps:** run **`uv run scripts/bump_version.py X.Y.Z`** — it edits
  `plugin/identity.json`, regenerates both host manifests (`.claude-plugin/plugin.json`,
  `.codex-plugin/plugin.json`) and `identity.sh` from it, rewrites the `version-vX.Y.Z` pill in
  `plugin/README.md`, regenerates the AI BOM and the SBOM, and verifies the manifests and the pill agree. If you edit
  by hand instead, `identity.json` and the pill are the only files to edit; regenerate the rest.
  CI fails on drift: `gen_identity.py --check`, `gen_aibom.py --check` and `gen_sbom.py --check`
  guard the generated files, and an invariant test guards the pill↔plugin link.
- **Connector dependencies:** the bridge's PEP 723 header is bounded and **locked**. If you add or
  change a dependency, re-lock in the same PR — `uv lock --script plugin/connector/exabeam-mcp-bridge.py`
  — and commit the updated `.lock` beside the script. `uv run` uses it automatically, so a stale lock
  means users resolve a different tree than you tested. Regenerate both BOMs in the same commit
  (`uv run security/gen_aibom.py && uv run security/gen_sbom.py` — the SBOM is derived from the lock, so a
  lock change always changes it); CI's `--check` steps catch a stale BOM but **not** lock drift, and
  `pip-audit` in CI fails the build if the locked tree carries a known vulnerability.
- **Evals:** if you change a fixture or the harness (`evals/`), include a recorded
  run and confirm the HARD safety gates pass. A backend/fixture is not mergeable
  without at least one grounded run.

## Reporting security issues & conduct

- Security vulnerabilities: **do not** open a public issue — see [SECURITY.md](SECURITY.md).
- Conduct: this project follows [our Code of Conduct](CODE_OF_CONDUCT.md).
