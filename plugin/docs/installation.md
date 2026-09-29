<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation & setup

Raffkin is a plugin for **Claude Code** and **OpenAI Codex** that works your **Exabeam New-Scale** tenant
through the Exabeam MCP, Exabeam's tool interface for AI agents. Setup is the same shape on both hosts: install the plugin, add one credentials
file, check, and run your first investigation. Five minutes.

The safety gate is on from the moment the plugin is installed: dismissing an alert or closing a case
always asks you first, and containment is never executed. Nothing to configure for that. On Claude Code
the gate is a hook inside the plugin. It runs even when you start Claude Code with permission prompts
turned off: containment is still refused, and a dismiss or close still needs a yes. Its deny on
containment and its ask on dismiss and close still fire in those modes, and if nobody is there to give
one, the call is refused.

## Before you start

- **A host agent:** the `claude` CLI (Claude Code) or the `codex` CLI (Codex), signed in.
- **A supported model.** On Claude Code, Sonnet 4.6 or newer, or Opus; on Codex, GPT-5.6 Terra or Sol.
  Smaller models (Haiku, Luna) are not supported. See [Security](security-guardrails.md#how-it-is-tested)
  for how the supported models are validated.
- **[`uv`](https://docs.astral.sh/uv/) 0.5.23 or newer** on your `PATH`. It runs the bundled Exabeam
  connector and installs the connector's own Python dependencies; there is nothing to `pip install`.
  Those dependencies are pinned by hash, and uv refuses to start the connector if the pin cannot be
  honored, which is why the version matters (`uv self update` brings an older uv current).
- **`python3` (3.7 or newer) on your `PATH`** — Claude Code only. The safety gate is a small Python script
  the host runs before each Exabeam call; without `python3` every gated call is refused. macOS and most
  Linux distributions already have it (`python3 --version`). Codex does not need it.
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
  [Exabeam Plug-in Forge](https://exabeam-labs.github.io/plugins/), with its own install command. These
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

## Updating

```bash
# Claude Code
claude plugin marketplace update open-agent-ai-security
claude plugin update raffkin@open-agent-ai-security

# Codex
codex plugin marketplace upgrade open-agent-ai-security
codex plugin add raffkin@open-agent-ai-security
```

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
the Exabeam MCP tools Raffkin calls, shown without their `exabeam_` prefix. Every containment or
rule-writing tool is refused before it reaches your tenant, and any tool not on this list asks you first.

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

Removing the plugin removes the gate it shipped. Neither command touches `~/.exabeam-mcp.env`; delete
that yourself when you are done with the credentials.
