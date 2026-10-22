<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation & setup

Raffkin is a plugin for **Claude Code**, **OpenAI Codex** and **Google Antigravity** that works your
**Exabeam New-Scale** tenant through the Exabeam MCP, Exabeam's tool interface for AI agents. Setup is the
same shape on all three hosts: install the plugin, add one credentials file, check, and run your first
investigation. Five minutes.

On **all three hosts** the safety gate is on from the moment the plugin is installed: dismissing an
alert or closing a case always asks you first, and containment is never executed. Nothing to configure for
that. On Claude Code and Antigravity the gate is a hook inside the plugin; on Codex it comes from the
approval policy the package sets. On Claude Code it runs even when you start with permission prompts turned
off: containment is still refused, and a dismiss or close still needs a yes. Its deny on containment and
its ask on dismiss and close still fire in those modes, and if nobody is there to give one, the call is
refused.

**Antigravity differs in what has been *tested*, not in what is enforced** — no release has been
red-teamed on a Gemini model. Read
[What is different on this host](#what-is-different-on-this-host) before you install there.

## Before you start

- **A host agent:** the `claude` CLI (Claude Code), the `codex` CLI (Codex) or the `agy` CLI
  (Google Antigravity), signed in.
- **On Antigravity, a Google account that Antigravity accepts.** Sign-in and eligibility are two separate
  gates: `agy` will complete the OAuth flow and then refuse the session with *"Your current account is not
  eligible for Antigravity. Try signing in with another personal Google account."* We hit this with a
  Google Workspace account on a managed domain, which is what most analysts will be using. Check this
  **before** you install anything — the plugin, the gate and `preflight.sh` all work without a session, so
  nothing else in this guide will warn you. If `agy -p "hi"` answers, you are eligible.
- **A supported model.** On Claude Code, Sonnet 4.6 or newer, or Opus; on Codex, GPT-5.6 Terra or Sol.
  Smaller models (Haiku, Luna) are not supported. See [Security](security-guardrails.md#how-it-is-tested)
  for how the supported models are validated. **The Gemini models Antigravity runs are not in that
  validation set** — no release has been red-teamed on one, so treat Antigravity as unvalidated on the
  model axis. The gate itself runs there; it is the model behind it that is untested.
- **[`uv`](https://docs.astral.sh/uv/) 0.5.23 or newer** on your `PATH`. It runs the bundled Exabeam
  connector and installs the connector's own Python dependencies; there is nothing to `pip install`.
  Those dependencies are pinned by hash, and uv refuses to start the connector if the pin cannot be
  honored, which is why the version matters (`uv self update` brings an older uv current).
- **`python3` (3.7 or newer) on your `PATH`** — Claude Code and Antigravity. The safety gate is a small
  Python script the host runs before each Exabeam call. On Claude Code, without `python3` every gated call
  is refused. On Antigravity the hook falls back to `uv`, which you need anyway, so the gate still runs —
  and if neither is present, every Exabeam call is refused there too, with a message naming what is
  missing. Either way you lose the plugin, not the control. macOS and most Linux distributions already
  have `python3` (`python3 --version`). Codex does not need it.
- **An Exabeam New-Scale API key and secret**, created under **Settings → API Keys** in your New-Scale
  console. Keys don't carry a role — you grant them **access entitlements**, and Raffkin gets exactly what
  the key was issued with. Entitle the key to read alerts, cases, events, threat summaries, MITRE
  coverage and detection content (rules, parsers, context tables), and to create cases and write case
  notes; a read-only key
  investigates fine but cannot record an outcome. The exact list is under
  [Key entitlements](#key-entitlements) below.
- **Your New-Scale region.** It is the `<region>` part of `https://api.<region>.exabeam.cloud/mcp`, for example
  `us-west`. Most tenant console URLs contain it — read it from the address bar. Some named environments
  (for example a demo or a dedicated tenant) have no region in the URL; ask your Exabeam administrator
  which region hosts them. The **Region Deployed** field under *Service Health and Consumption → License
  View* is **not** reliable for this — it may show a country rather than the hosting region.
- **Windows:** Raffkin is not supported natively on Windows; use **WSL**. The diagnostics and the safety
  gate are shell scripts and Python, and the credentials file below is protected by Unix file
  permissions, which Git Bash on NTFS does not enforce — so Git Bash can run the scripts but leaves your
  key and secret unprotected. There is no PowerShell path.
<!-- community-only -->
- **Exabeam customers:** the supported build is delivered through the
  [Exabeam Plug-in Catalog](https://plugins.exabeam.com/), with its own install command. These
  instructions cover the community release; see [Support](support.md).
<!-- /community-only -->
<!-- distribution-only
- **This copy is a distribution.** It is provided under the terms in its `LICENSE` file by the
  organization that distributes it, which also provides its support; see [Support](support.md).
/distribution-only -->
- **Your own subscription.** Raffkin runs inside your Claude Code or Codex plan. An investigation is a long
  agent session and is billed by your provider like any other.

## Quick start — Claude Code

**1. Install the plugin.**

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install raffkin@open-agent-ai-security
claude plugin list      # expect a block for raffkin@open-agent-ai-security ending in: Status: ✔ enabled
```

If the block shows an error line under it, the plugin installed but did not load — see
[Troubleshooting](#troubleshooting).

**2. Add your credentials.** One file, in your home directory:

```bash
cat > ~/.exabeam-mcp.env <<'ENV'
EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
EXABEAM_API_KEY=your-key
EXABEAM_API_SECRET=your-secret
ENV
chmod 600 ~/.exabeam-mcp.env
```

Replace `<region>` with your region. The URL must be `https://`. Then restart Claude Code, or run
`/reload-plugins` inside it — the connector reads this file when it starts.

**3. Check the setup.** The plugin ships a read-only diagnostic that tells you what, if anything, is
missing. It lives in the installed plugin. Run it with the exact version step 1 showed (not a wildcard:
the cache keeps earlier versions, and a wildcard would run the oldest one):

```bash
bash ~/.claude/plugins/cache/open-agent-ai-security/raffkin/<version>/preflight.sh
```

Expect `✓` on every line, including **`Exabeam MCP reachable`** and **`Human-in-the-loop gate ON`**. A
`!` or `✗` line names what to fix; a `↷` line was skipped because an earlier line failed, so fix that one
first. If you see `No credentials yet`, go back to step 2.

**4. Run your first investigation.** Start Claude Code and hand it an alert:

> investigate alert `<alert id>`

You can find an alert ID in the New-Scale console under **Threat Center → Alerts**; or ask Raffkin
*"triage the queue"* first and pick one from the list it returns. Raffkin loads the `soc-investigate`
skill, queries Exabeam for the evidence (you will see the tool calls go by), and ends with a written
report: the timeline, the evidence with its source, a MITRE mapping, a verdict, and a last line of
`Taxonomy outcome: raised`, `auto_closed` or `fp_closed`. If it concludes the alert is a false
positive, it **asks you** — *"Dismiss alert X as a false positive? (yes / no)"* — and waits. Nothing is
dismissed or closed until you say yes.

That is the whole setup. [Using the skills](usage.md) covers what else you can ask.

## Quick start — Codex

**1. Install the plugin.**

```bash
codex plugin marketplace add open-agent-ai-security/plugins
codex plugin add raffkin@open-agent-ai-security
codex plugin list      # expect: raffkin@open-agent-ai-security  installed, enabled  <version>
```

**2. Add your credentials** — the same file as for Claude Code, above (`~/.exabeam-mcp.env`, `https://`,
`chmod 600`). Then start a new Codex session.

**3. Check the setup.** `codex plugin list` prints the plugin's path in its last column. Run the
diagnostic from there:

```bash
bash <that path>/preflight.sh --platform codex
```

Expect `✓` on every line, including **`Exabeam MCP reachable`** and **`Human-in-the-loop gate ON`**. A
`!` or `✗` line names what to fix; a `↷` line was skipped because an earlier line failed, so fix that one
first. If you see `No credentials yet`, go back to step 2.

**4. Run your first investigation.** In a Codex session:

> investigate alert `<alert id>`

Same report, same last line, same question before any dismissal. One difference on Codex: it also asks
you before Raffkin *opens* a case or writes a note, because Exabeam marks those tools as writes and Codex
asks before every write. Noisier, not less safe. And if you script Raffkin with `codex exec`, where
nobody is at the keyboard, Codex cancels any write that needs an approval rather than letting it
through — the gate does not evaporate when the human does.

## Quick start — Google Antigravity

**1. Install the plugin.** Antigravity installs from a GitHub subpath into `~/.gemini/config/plugins/`:

<!-- community-only -->
```bash
agy plugin install https://github.com/open-agent-ai-security/raffkin/tree/main/plugin
```
<!-- /community-only -->
<!-- distribution-only
```bash
agy plugin install {{antigravity_install}}
```
/distribution-only -->

Read what it prints, because this is the earliest point at which a missing piece is visible:

<!-- community-only -->
```
  [ok]    raffkin
          ✔ skills      : 3 processed
          - agents      : skipped (not found)
          - commands    : skipped (not found)
          ✔ mcpServers  : 1 processed
          ✔ hooks       : 1 processed
```
<!-- /community-only -->
<!-- distribution-only
```
  [ok]    {{plugin_name}}
          ✔ skills      : 3 processed
          - agents      : skipped (not found)
          - commands    : skipped (not found)
          ✔ mcpServers  : 1 processed
          ✔ hooks       : 1 processed
```
/distribution-only -->

`mcpServers : 1` is the Exabeam connection and `hooks : 1` is the safety gate. If either says `skipped`,
stop: the skills will load and have nothing to call, or they will load with no gate in front of them.
`agy plugin list --json` shows the same thing afterwards, and names the gate
(`"hooks": ["<this plugin's name>-gate"]`).

**2. Add your credentials** — the same file as the other hosts (`~/.exabeam-mcp.env`, `https://`,
`chmod 600`).

**3. Check the setup.**

```bash
bash ~/.gemini/config/plugins/raffkin/preflight.sh
```

Expect `✓` on every line, the gate included. The script detects Antigravity from its own install path, so
`--platform antigravity` is only needed if you run a copy from somewhere else. If the gate line reports a
`!`, read it: the likeliest cause is that neither `python3` nor `uv` is on the PATH the host launches hooks
with, and the gate cannot run without one of them.

**4. Run your first investigation.** In an Antigravity session:

> investigate alert `<alert id>`

### Where this install comes from

Antigravity has a Marketplace, but no catalog you add yourself: there is no `agy plugin marketplace add`,
so `agy` installs the directory the URL points at, and the plugin lands in `~/.gemini/config/plugins/`
under its manifest name.

<!-- community-only -->
This is the **community build**, from the plugin's own source repository. The Exabeam-supported build is a
vendored copy of the same tree, served from the [Exabeam Plug-in Catalog](https://plugins.exabeam.com/)
under its own terms and support, and it has its own install command.
<!-- /community-only -->
<!-- distribution-only
This is a **distribution copy** of the plugin, provided under {{terms}} by {{vendor}}, with {{support}}. It
is a vendored copy of the community source tree, re-keyed to this distribution's own name; the command
above is the one for *this* copy, and the community build has its own.
/distribution-only -->


### What is different on this host

Raffkin's three skills, the Exabeam connection and the human-in-the-loop gate all work here. The gate
is the same file as on Claude Code — the deny tier, the ask tier and the per-session write budget are
in force, and every decision lands on the same audit trail. Antigravity reads it from `hooks.json` at
the plugin root, and its documented hook contract makes a `deny` a hard block. A fresh install reports
the gate (`hooks : 1`), and `preflight.sh` proves the gate's own answer by making it refuse a containment
call — what no release has yet watched is this host calling the hook in a live session.

Two differences are worth knowing before you run an investigation on this host.

**No release has been red-teamed on a Gemini model.** Every Raffkin release is adversarially tested on the
weakest supported model of each host before it ships, and that work has been done on Claude and GPT models
only. The gate is a control on the *tool call*, so it does not depend on the model's good behaviour — but
prompt-injection resistance, refusal discipline and how the skills hold up under pressure are all model
properties, and on this host they are untested. That is a gap in our evidence, not a known weakness.

**The gate needs an interpreter, and this host bundles neither.** The hook runs under `python3`, falling
back to `uv`, which the Exabeam connector already requires. If both are missing the hook refuses the call
outright — the refusal is written by the shell, not by the gate, and says which interpreters it looked
for. That is deliberate and it is host-specific: on Claude Code a hook whose command fails blocks the
call by exiting 2, but Antigravity reads a decision on standard output and nothing else, so a gate that
cannot start would otherwise be a gate that is never heard. `preflight.sh` checks for an interpreter and
says so, and it is worth running once after you install.

The one case the refusal does not cover is the host killing the hook at its 20-second timeout, which
takes the shell with it. Nothing has been observed to take that long: the gate reads one JSON object,
compares a tool name against a static tier file and writes a line.

One smaller difference shows up in the log rather than in what is enforced: Antigravity does not tell a
hook which permission mode the session is running in. On Claude Code that lets the audit trail
distinguish an ask a human answered from one that completed in an unattended mode; here a completed
ask-tier call is recorded as `approved` without that distinction. Records written on this host carry
`"host": "antigravity"` so the log never has to be guessed at.

What runs identically on every host, because it lives in the connector rather than the host: what the
model reads is screened for injected instructions, what it writes back is neutralized and masked, a
`create_case` carrying a closing disposition is refused, and every call is on the audit trail.

**Your key is still the limit worth setting.** Entitlements are enforced by Exabeam, not by the host, so
they hold even if a host control is misconfigured — the gate denies a rule write, and an unentitled key
means there is no rule-write tool to deny in the first place. `rule-tuning` only ever needs reads, so
there is no reason to entitle the key for detection-content *writes*. See
[Key entitlements](#key-entitlements).

<!-- community-only -->
Three things about the gate on this host have not been exercised against a live `agy` session, because
doing so needs the desktop app and a Google sign-in. We have not confirmed that a `deny` holds when a
session runs with `--dangerously-skip-permissions` (it does on Claude Code), nor watched the host prompt
on an `ask`. The third is the one worth understanding: the shape of the payload the host hands a hook is
read from its documented contract, not from a live call, so the gate could in principle be handed a step
it cannot read. It is built to ask in that case rather than stand aside — an MCP call it cannot identify
at all gets a prompt, which is the wrong-way-round failure that costs you a question rather than a silent
ungated close. All three are tracked in
[raffkin#305](https://github.com/open-agent-ai-security/raffkin/issues/305). Moving the deny tier into the
connector as well, so it holds without depending on any host, is
[raffkin#308](https://github.com/open-agent-ai-security/raffkin/issues/308).
<!-- /community-only -->
<!-- distribution-only
Three things about the gate on this host have not been exercised against a live Antigravity session:
whether a `deny` holds under `--dangerously-skip-permissions`, what the host's own prompt looks like on an
`ask`, and whether the payload the host hands a hook matches the documented shape the gate reads. On that
last one the gate is built to ask rather than stand aside if it is handed a call it cannot identify.
{{support}} can tell you where that verification stands for your release.
/distribution-only -->


## Updating

```bash
# Claude Code
claude plugin marketplace update open-agent-ai-security
claude plugin update raffkin@open-agent-ai-security

# Codex
codex plugin marketplace upgrade open-agent-ai-security
codex plugin add raffkin@open-agent-ai-security
```

On Antigravity there is no catalog to refresh — re-run the install command, which re-reads the source:

<!-- community-only -->
```bash
agy plugin install https://github.com/open-agent-ai-security/raffkin/tree/main/plugin
```
<!-- /community-only -->
<!-- distribution-only
```bash
agy plugin install {{antigravity_install}}
```
/distribution-only -->

Both commands matter on Claude Code: the first refreshes the catalog, the second installs from it.
Restart or `/reload-plugins` to apply. Auto-update on Claude Code is per marketplace and off by default
for marketplaces you add yourself; turn it on under `/plugin` → **Marketplaces** → `open-agent-ai-security`,
or fleet-wide in a managed `settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "open-agent-ai-security": {
      "source": { "source": "github", "repo": "open-agent-ai-security/plugins" },
      "autoUpdate": true
    }
  }
}
```


## Troubleshooting

Run `preflight.sh` first (step 3 above); it checks the CLI, `uv`, the credentials file, the connection
to your tenant, and the safety gate, and names the failing step.

- **`Exabeam MCP reachable` fails.** The region in `EXABEAM_MCP_URL` is the first thing to check: it
  must be the region from your console address, not the country shown in License View. Then check that
  the URL starts with `https://` and that the key and secret are the ones your console shows. The
  connector refuses to start over `http://`, on purpose.
- **Investigations work but rule-tuning returns nothing.** The key is entitled for alerts and cases but
  not for detection content. An under-entitled key installs and connects cleanly, and the reads it
  lacks may come back empty rather than failing. See [Key entitlements](#key-entitlements).
- **The skill says the Exabeam MCP is not connected.** The credentials file is missing or was added
  after the host started; add it and restart the host.
- **`claude plugin list` shows an error beside Raffkin.** The plugin installed but did not load; run
  `claude plugin update raffkin@open-agent-ai-security` to get the current release, then restart.
- **On Codex, no `exabeam` server appears.** Codex drops a bundled server silently if any part of its
  configuration is invalid; run `codex plugin add raffkin@open-agent-ai-security` again and re-check.

## Advanced: wiring the Exabeam MCP by hand (not recommended)

You can register the remote Exabeam MCP in your host directly (`claude mcp add … exabeam …`) with a
bearer token you mint yourself. Two things to know: the token expires in about four hours, and, more
importantly, Raffkin's guardrails — the screening of what it reads, the neutralizing and masking of what
it writes, and the audit trail — live in the bundled connector, so
none of them run when Claude Code talks to the remote MCP directly. Only the dismiss/close gate
survives, and only if the server is named `exabeam`. Use this for a connectivity check, not for investigations you rely on.

## Key entitlements

Whoever grants the key's access entitlements can check against this list rather than guessing. These are
the Exabeam MCP tools Raffkin calls, shown without their `exabeam_` prefix. Any tool not on this list asks
you first, and on every host each containment or rule-writing tool is refused by the gate before it
reaches your tenant. Entitling the key to nothing beyond this list is the control that holds even if a host
control is misconfigured, so do it whichever host you use.

| Needed for | Tools |
|---|---|
| Investigating alerts and cases | `search_alerts`, `get_alert_details`, `get_alert_threat_timeline`, `search_cases`, `get_case_details`, `get_case_notes`, `get_case_threat_timeline`, `search_events`, `threat_summary`, `get_mitre_coverage`, `get_correlation_rule_details` |
| Rule tuning | `analytics_rule_list`, `analytics_rule_details`, `correlation_rule_list`, `parser_list`, `get_parser_details`, `context_table_list`, `get_context_table_records`, `get_use_case_score` |
| Recording an outcome | `create_case`, `create_case_notes` (allowed as escalation); `update_alert`, `update_case` (always ask you first) |
| Optional | `send_email` (always asks you first; everything else works without it) |

## Uninstalling

```bash
# Claude Code
claude plugin uninstall raffkin@open-agent-ai-security
claude plugin marketplace remove open-agent-ai-security   # optional; also removes other plugins from this catalog

# Codex
codex plugin remove raffkin@open-agent-ai-security
codex plugin marketplace remove open-agent-ai-security   # optional; same caveat
```

On Antigravity the plugin is named, not keyed to a marketplace:

<!-- community-only -->
```bash
agy plugin uninstall raffkin
```
<!-- /community-only -->
<!-- distribution-only
```bash
agy plugin uninstall {{plugin_name}}
```
/distribution-only -->

Removing the plugin removes the gate it shipped, on every host. None of the three commands
touches `~/.exabeam-mcp.env`; delete that yourself when you are done with the credentials.
