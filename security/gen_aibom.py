# /// script
# requires-python = ">=3.9"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate Raffkin's AI Bill of Materials (CycloneDX 1.6) from the repo's own sources.

Raffkin is an AI *agent/application*, not a model: a plugin of three skills (prompt + methodology) plus a
small MCP connector, running on a hosted foundation model the host agent picks (Claude on Claude Code, an
OpenAI model on Codex) and calling the Exabeam New-Scale
MCP. Model-card AI-BOM tools (which ingest a Hugging Face model id) can't describe that, so we assemble
a CycloneDX AI-BOM directly from what Raffkin actually ships:

  - the root component (this plugin) from plugin/.claude-plugin/plugin.json,
  - the foundation models (Claude; OpenAI on Codex) as external machine-learning-model components,
  - the system prompt / methodology (SKILL.md + reference corpus) as a `data` component,
  - the connector's Python dependencies (PEP 723) as `library` components,
  - the Exabeam MCP as a `service` with its inbound/outbound data flows,
  - governance/guardrails (permission tiers, human-in-the-loop) as metadata properties.

Deterministic: same repo state -> byte-identical output (stable uuid5 serial; timestamp from
SOURCE_DATE_EPOCH if set, else current UTC — `--check` ignores the timestamp so CI can verify freshness).

Usage:
    uv run security/gen_aibom.py            # (re)write security/aibom.cdx.json + security/aibom.html
    uv run security/gen_aibom.py --check    # non-zero exit if the on-disk BOM is stale vs. the sources
"""
import datetime
import json
import os
import re
import sys
import uuid
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEC = ROOT / "security"
JSON_OUT = SEC / "aibom.cdx.json"
HTML_OUT = SEC / "aibom.html"


# ---------- read the sources ----------

def _json(rel):
    return json.loads((ROOT / rel).read_text())

def _pep723(pyfile):
    """(dependencies, requires-python) from a script's PEP 723 header. The block IS TOML, so it is parsed
    as TOML where the interpreter has tomllib (3.11+); the regex fallback matches the list to the `]` that
    ends its line, not the first `]` — an extras marker like "mcp[cli]" truncated the old non-greedy
    match and silently dropped every dependency after it (found in review)."""
    txt = (ROOT / pyfile).read_text()
    block = re.search(r"# /// script\n(.*?)\n# ///", txt, re.S).group(1)
    toml_text = "\n".join(line[2:] if line.startswith("# ") else line[1:] for line in block.splitlines())
    try:
        import tomllib
        meta = tomllib.loads(toml_text)
        return list(meta.get("dependencies", [])), meta.get("requires-python")
    except ImportError:
        dm = re.search(r"dependencies\s*=\s*\[(.*?)\][ \t]*$", block, re.S | re.M)
        deps = re.findall(r'"([^"]+)"', dm.group(1)) if dm else []
        py = re.search(r'requires-python\s*=\s*"([^"]+)"', block)
        return deps, (py.group(1) if py else None)

def _split_dep(spec):
    m = re.match(r"([A-Za-z0-9_.\-]+)\s*(.*)", spec)
    return m.group(1), (m.group(2).strip() or None)

# SPDX ids for the connector's PyPI deps, verified against PyPI/upstream 2026-07-30.
# A dep added to the bridge without an entry here ships with no license claim rather
# than a guessed one.
# Raffkin is published via the community marketplace (open-agent-ai-security/plugins);
# the supplier is pinned here since the in-repo marketplace.json (the previous
# source of owner metadata) was retired in the #58 hard cutover.
SUPPLIER = {"name": "Open Agent AI Security",
            "url": ["https://github.com/open-agent-ai-security"]}

DEP_LICENSES = {
    "mcp": "MIT",
    "httpx": "BSD-3-Clause",
    "certifi": "MPL-2.0",
    "observra": "Apache-2.0",
    "typing_extensions": "PSF-2.0",
}


# ---------- build the BOM ----------

def build_bom(timestamp):
    plugin = _json("plugin/.claude-plugin/plugin.json")
    identity = _json("plugin/identity.json")                  # the marketplace key follows a re-key (review, #144)
    marketplace_url = f"https://github.com/{identity['marketplace']['repo']}"
    marketplace_key = f"{identity['name']}@{identity['marketplace']['name']}"
    mcp = _json("plugin/.mcp.json")
    perms = _json("plugin/skills/soc-investigate/settings.snippet.json")["permissions"]
    deps, requires_python = _pep723("plugin/connector/exabeam-mcp-bridge.py")
    toolmap = (ROOT / "plugin/skills/soc-investigate/reference/tool-map.md").read_text()
    names = set(re.findall(r"\bexabeam_[a-z_]+", toolmap))
    # The count is what the LIVE MCP exposes, which is what tool-map.md's own header states
    # (cross-checked below). Two kinds of name in the map are not that, and each is marked by a
    # phrase on its own line: a tool denied "ahead of the MCP exposing it" is proxy-only, and one
    # "answered by the bridge" is local -- the bridge handles it and never forwards it, so the MCP
    # does not expose it and never will.
    not_live = set()
    for line in toolmap.splitlines():                   # every name on a line that carries a phrase
        if "ahead of the MCP exposing it" in line or "answered by the bridge" in line.lower():
            not_live |= set(re.findall(r"`(exabeam_[a-z_]+)`", line))
    tool_count = len(names - not_live)
    header_count = int(re.search(r"The (\d+) tools exposed by the live MCP", toolmap).group(1))
    if header_count != tool_count:
        sys.exit(f"tool-map.md header says {header_count} tools, the map lists {tool_count} live names — fix the map")
    mcp_server = next(iter(mcp["mcpServers"]))  # "exabeam"
    skills = sorted(d.name for d in (ROOT / "plugin/skills").iterdir() if (d / "SKILL.md").is_file())
    hook = (ROOT / "plugin/hooks/hooks.json").is_file() and (ROOT / "plugin/hooks/gate.py").is_file()
    tiers = _json("plugin/skills/soc-investigate/permissions.json")["tiers"]   # the one tier file (bare names)
    tier_n = {t: len(tiers[t]["tools"]) for t in ("allow", "ask", "deny")}
    codex_map = _json("plugin/.mcp.codex.json")                 # Codex spells the map without a mcpServers wrapper
    codex_policy = codex_map.get("mcpServers", codex_map)[mcp_server]

    name, version = plugin["name"], plugin["version"]
    repo = plugin["repository"]
    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{repo}@{version}"))
    lic = [{"license": {"id": plugin["license"]}}]

    root = {
        "bom-ref": f"{name}@{version}",
        "type": "application",
        "name": name,
        "version": version,
        "description": plugin["description"],
        "licenses": lic,
        "supplier": SUPPLIER,
        "publisher": plugin["author"]["name"],
        "externalReferences": [
            {"type": "vcs", "url": repo},
            {"type": "website", "url": plugin["homepage"]},
            {"type": "distribution", "url": marketplace_url, "comment": f"Claude Code plugin marketplace: {marketplace_key}"},
{"type": "bom", "url": "sbom.cdx.json",
             "comment": "The software bill of materials for the same release — the bridge's full locked dependency tree with artifact hashes (security/gen_sbom.py)"},
        ],
        "properties": [
            {"name": "ai:systemType", "value": "agent"},
            {"name": "ai:platform", "value": "plugin for Claude Code and OpenAI Codex (skills + bundled MCP connector)"},
            {"name": "ai:skillName", "value": ", ".join(skills)},
        ],
    }

    components = [
        {
            "bom-ref": "model:anthropic-claude",
            "type": "machine-learning-model",
            "name": "Claude (Anthropic)",
            "description": ("Foundation model the skill runs on. Hosted API — weights are not distributed "
                            "with Raffkin. The specific member (e.g. Opus / Sonnet) is selected at runtime "
                            "by Claude Code, not pinned by Raffkin."),
            "supplier": {"name": "Anthropic", "url": ["https://www.anthropic.com"]},
            "externalReferences": [{"type": "website", "url": "https://www.anthropic.com/claude"}],
            "properties": [
                {"name": "ai:hosting", "value": "external-hosted-api"},
                {"name": "ai:weightsDistributed", "value": "false"},
                {"name": "ai:pinnedByThisProject", "value": "false"},
            ],
        },
        {
            "bom-ref": "model:openai-codex",
            "type": "machine-learning-model",
            "name": "OpenAI model (via Codex)",
            "description": ("Foundation model the skills run on when the host is OpenAI Codex. Hosted API — "
                            "weights are not distributed with Raffkin. The specific model and reasoning effort "
                            "are selected by Codex, not pinned by Raffkin; the red-team floor is recorded per run "
                            "in security/redteam/HISTORY.md."),
            "supplier": {"name": "OpenAI", "url": ["https://openai.com"]},
            "externalReferences": [{"type": "website", "url": "https://openai.com/codex/"}],
            "properties": [
                {"name": "ai:hosting", "value": "external-hosted-api"},
                {"name": "ai:weightsDistributed", "value": "false"},
                {"name": "ai:pinnedByThisProject", "value": "false"},
            ],
        },
        {
            "bom-ref": "artifact:soc-investigate-methodology",
            "type": "data",
            "name": "skill methodology (system prompts + reference corpus)",
            "description": ("The agent's instructions: the three skills' SKILL.md (" + ", ".join(skills) + " — "
                            "investigation methodology, queue sweep, rule tuning; governance; output discipline) "
                            "plus reference/ (tool map, EQL search cookbook, enrichment playbook, report template, "
                            "triage taxonomy, containment list, worked examples). This prompt corpus — not a "
                            "model — is the primary AI artifact Raffkin ships."),
            "licenses": lic,
            "properties": [
                {"name": "ai:artifactKind", "value": "system-prompt/methodology"},
                {"name": "ai:untrustedInputHandling",
                 "value": "treats tool output (alerts/events/case notes) as data, never instructions"},
            ],
        },
        {
            "bom-ref": "component:exabeam-mcp-bridge",
            "type": "application",
            "name": "exabeam-mcp-bridge",
            "description": ("Bundled local stdio MCP connector (plugin/connector/exabeam-mcp-bridge.py). Forwards "
                            "to the remote Exabeam New-Scale MCP and auto-refreshes the OAuth token. "
                            "Read-through; handles the API key/secret."),
            "licenses": lic,
            "properties": [
                {"name": "runtime", "value": "python"},
                {"name": "requires-python", "value": requires_python or "unspecified"},
                {"name": "pep723", "value": "true"},
            ],
        },
    ]

    for spec in deps:
        dep_name, constraint = _split_dep(spec)
        comp = {
            "bom-ref": f"pkg:pypi/{dep_name}",
            "type": "library",
            "name": dep_name,
            "version": constraint or "unspecified",
            "purl": f"pkg:pypi/{dep_name}",
            "description": f"Connector dependency ({spec}), resolved by uv at runtime (PEP 723).",
        }
        if dep_name in DEP_LICENSES:
            comp["licenses"] = [{"license": {"id": DEP_LICENSES[dep_name]}}]
        components.append(comp)

    service = {
        "bom-ref": f"service:{mcp_server}-mcp",
        "name": "Exabeam New-Scale MCP",
        "description": (f"External tool surface reached through the bundled connector: {tool_count} tools "
                        "(Threat Center, Search, detection rules, context tables) and NO containment "
                        "capability. Registered via plugin/.mcp.json as a bundled MCP server."),
        "endpoint": "https://api.<region>.exabeam.cloud/mcp",
        "authenticated": True,
        "x-trust-boundary": True,
        "data": [
            {"flow": "inbound", "classification": "security-telemetry (alerts, events, cases — attacker-influenceable)"},
            {"flow": "outbound", "classification": "case-management actions (create/notes: free; dismiss/close: human-gated)"},
        ],
        "externalReferences": [
            {"type": "documentation",
             "url": "https://docs.exabeam.com/en/new-scale-soc-platform/all/administration-guide/get-started-with-the-new-scale-security-operations-platform/connect-to-exabeam-mcp-server.html"}
        ],
        "properties": [
            {"name": "mcp:toolCount", "value": str(tool_count)},
            {"name": "mcp:toolCountBasis", "value": "tools the live MCP exposes per tool-map.md; names denied ahead of exposure excluded"},
            {"name": "mcp:containmentCapability", "value": "none"},
            {"name": "mcp:transport", "value": "stdio bridge -> streamable-http"},
        ],
    }

    metadata = {
        "component": root,
        "supplier": SUPPLIER,
        "authors": [{"name": plugin["author"]["name"]}],
        "properties": [
            {"name": "ai:foundationModel", "value": "Claude (Anthropic) on Claude Code; OpenAI model on Codex — external hosted APIs, chosen by the host"},
            {"name": "ai:humanInTheLoop",
             "value": "required for dismiss/close and outbound mail (update_alert/update_case/send_email) — enforced by the host: "
                      + ("a bundled PreToolUse hook on Claude Code (holds under --dangerously-skip-permissions; a headless ask is refused)"
                         if hook else "no bundled hook found on Claude Code")
                      + f"; tool-approval policy on Codex (default {codex_policy.get('default_tools_approval_mode')!s}, "
                      + f"{len(codex_policy.get('disabled_tools', []))} tools disabled)"},
            {"name": "ai:autonomousActions", "value": "read/search + create_case/case_notes (escalation) — prompt-free on both hosts"},
            {"name": "ai:containmentCapability", "value": "none — recommend-only, performed by a human in EDR/IAM; every containment tool is denied by the gate"},
            {"name": "ai:guardrails",
             "value": f"permission tiers {tier_n['allow']} allow / {tier_n['ask']} ask / {tier_n['deny']} deny "
                      "from one tier file (permissions.json → hook, Codex policy, published permission snippet for fleet policy); "
                      "input canonicalizer on every read and on the remote's tool definitions (hashed per session); "
                      "output neutralizer on every write (formulas inert, links de-fanged unless into the operator's tenant, "
                      "secrets and structured identifiers masked); updates carry state only; a create_case with a closing "
                      "disposition is refused; in-prompt ask-before-close as the model-side layer"},
            {"name": "ai:auditTrail", "value": "on by default, local, bounded: every call, gate decision and guardrail firing as metadata and safe identifiers, never case content (~/.raffkin/)"},
            {"name": "ai:secretsHandling", "value": "Exabeam OAuth key/secret from ~/.exabeam-mcp.env; never logged; posted over https only (the bridge refuses a cleartext URL)"},
            {"name": "aibom:generator", "value": "security/gen_aibom.py (deterministic, from repo sources)"},
        ],
    }
    if timestamp:
        metadata["timestamp"] = timestamp

    dependencies = [
        {"ref": root["bom-ref"],
         "dependsOn": ["model:anthropic-claude", "model:openai-codex", "artifact:soc-investigate-methodology",
                       "component:exabeam-mcp-bridge", f"service:{mcp_server}-mcp"]},
        {"ref": "component:exabeam-mcp-bridge",
         "dependsOn": [f"pkg:pypi/{_split_dep(s)[0]}" for s in deps]},
        {"ref": "artifact:soc-investigate-methodology", "dependsOn": ["model:anthropic-claude", "model:openai-codex"]},
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "services": [service],
        "dependencies": dependencies,
    }


# ---------- render HTML ----------

_CATEGORY = {
    "machine-learning-model": "Foundation model",
    "data": "AI artifact (prompt / methodology)",
    "application": "Connector",
    "library": "Software dependency",
}
_CSS = """
:root{--ink:#0f1e2e;--sub:#4a5b6b;--line:#e2e8f0;--accent:#0aa5a5;--bg:#f7f9fb;--chip:#eef4f7}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:960px;margin:0 auto;padding:0 24px 64px}
header{background:var(--ink);color:#fff;padding:34px 0;margin-bottom:28px}
header .wrap{padding-bottom:0}
h1{margin:0 0 4px;font-size:26px}h1 .sc{color:var(--accent)}
.tag{color:#b9c6d2;font-size:14px;margin:0}
.badges{margin-top:14px}.badge{display:inline-block;background:#183041;color:#cfe;border:1px solid #2a4a5f;border-radius:20px;padding:3px 11px;font-size:12px;margin:0 6px 6px 0}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--sub);border-bottom:1px solid var(--line);padding-bottom:6px;margin:34px 0 14px}
.lead{color:var(--sub)}
table{width:100%;border-collapse:collapse;margin:8px 0 4px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line);font-size:14px}
th{color:var(--sub);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.k{white-space:nowrap;font-weight:600}
.cat{font-size:12px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.05em;padding-top:16px}
code{background:var(--chip);padding:1px 5px;border-radius:4px;font-size:13px}
.flow{display:inline-block;font-size:12px;font-weight:700;border-radius:4px;padding:1px 7px;margin-right:6px}
.in{background:#e6f6f0;color:#0a7a55}.out{background:#fdeee6;color:#b5561e}
.meta{font-size:13px;color:var(--sub)}
.prop{font-size:14px;padding:7px 0;border-bottom:1px solid var(--line)}.prop b{color:var(--ink)}
footer{margin-top:40px;color:var(--sub);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
a{color:#0a7d99}
"""

def render_html(bom):
    m = bom["metadata"]; root = m["component"]
    def props_of(x): return {p["name"]: p["value"] for p in x.get("properties", [])}

    def esc(s): return escape(str(s))

    badges = "".join(f'<span class="badge">{esc(t)}</span>' for t in (
        f'v{root["version"]}', f'CycloneDX {bom["specVersion"]}', root["licenses"][0]["license"]["id"],
        f'serial {bom["serialNumber"].split(":")[-1][:8]}…'))

    # components grouped by category, in a stable, sensible order
    order = ["machine-learning-model", "data", "application", "library"]
    rows = []
    for cat_type in order:
        first = True
        for c in bom["components"]:
            if c["type"] != cat_type:
                continue
            if first:
                rows.append(f'<tr><td class="cat" colspan="2">{esc(_CATEGORY[cat_type])}</td></tr>')
                first = False
            ver = f' <code>{esc(c["version"])}</code>' if c.get("version") else ""
            purl = f'<div class="meta"><code>{esc(c["purl"])}</code></div>' if c.get("purl") else ""
            extra = ""
            pr = props_of(c)
            if pr:
                extra = '<div class="meta">' + " · ".join(f'{esc(k)}: {esc(v)}' for k, v in pr.items()) + "</div>"
            rows.append(f'<tr><td class="k">{esc(c["name"])}{ver}</td>'
                        f'<td>{esc(c.get("description",""))}{purl}{extra}</td></tr>')
    comp_rows = "\n".join(rows)

    svc_rows = []
    for s in bom["services"]:
        flows = "".join(
            f'<span class="flow {"in" if d["flow"]=="inbound" else "out"}">{esc(d["flow"])}</span>{esc(d["classification"])}<br>'
            for d in s.get("data", []))
        sp = props_of(s)
        spx = '<div class="meta">' + " · ".join(f'{esc(k)}: {esc(v)}' for k, v in sp.items()) + "</div>" if sp else ""
        svc_rows.append(f'<tr><td class="k">{esc(s["name"])}<div class="meta"><code>{esc(s.get("endpoint",""))}</code>'
                        f'{" · authenticated" if s.get("authenticated") else ""}</div></td>'
                        f'<td>{esc(s.get("description",""))}<div style="margin-top:6px">{flows}</div>{spx}</td></tr>')
    svc_html = "\n".join(svc_rows)

    gov = "".join(f'<div class="prop"><b>{esc(p["name"].split(":")[-1])}</b> — {esc(p["value"])}</div>'
                  for p in m.get("properties", []) if p["name"].startswith("ai:"))

    refs = "".join(f'<li><a href="{esc(r["url"])}">{esc(r["type"])}</a> — {esc(r["url"])}</li>'
                   for r in root.get("externalReferences", []))
    ts = m.get("timestamp", "(reproducible build — timestamp omitted)")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Copyright 2026 Exabeam, Inc. SPDX-License-Identifier: Apache-2.0 -->
<title>Raffkin — AI Bill of Materials</title><style>{_CSS}</style></head>
<body>
<header><div class="wrap">
  <h1><span class="sc">Raffkin</span> — AI Bill of Materials</h1>
  <p class="tag">{esc(root["description"])}</p>
  <div class="badges">{badges}</div>
</div></header>
<div class="wrap">
  <p class="lead">This is an <b>AI application / agent</b> BOM, not a model card. Raffkin runs on a
  hosted foundation model it does not ship (Claude on Claude Code, an OpenAI model on Codex), and its
  substance is a <b>prompt/methodology</b> plus a small <b>MCP connector</b> carrying the guardrails. The inventory below is generated deterministically from the repo's
  own sources by <code>security/gen_aibom.py</code>.</p>
  <p class="meta">Supplier: {esc(m["supplier"]["name"])} · Generated: {esc(ts)} · Serial: <code>{esc(bom["serialNumber"])}</code></p>

  <h2>Components</h2>
  <table><tbody>{comp_rows}</tbody></table>

  <h2>Services &amp; data flows</h2>
  <table><tbody>{svc_html}</tbody></table>

  <h2>Governance &amp; guardrails</h2>
  {gov}

  <h2>Provenance</h2>
  <ul>{refs}</ul>

  <footer>CycloneDX {esc(bom["specVersion"])} · {esc(bom["serialNumber"])}<br>
  Regenerate with <code>uv run security/gen_aibom.py</code>. Raw BOM: <code>security/aibom.cdx.json</code>.</footer>
</div></body></html>
"""


# ---------- main ----------

def _timestamp():
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    dt = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
          else datetime.datetime.now(datetime.timezone.utc))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _dumps(bom):
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"

def main(argv):
    check = "--check" in argv
    bom = build_bom(_timestamp())

    if check:
        if not JSON_OUT.exists():
            print("aibom.cdx.json missing — run: uv run security/gen_aibom.py", file=sys.stderr)
            return 1
        cur = json.loads(JSON_OUT.read_text())
        fresh = json.loads(_dumps(bom))
        committed_ts = cur.get("metadata", {}).get("timestamp", "")
        cur.get("metadata", {}).pop("timestamp", None)      # ignore the clock
        fresh.get("metadata", {}).pop("timestamp", None)
        if cur != fresh:
            print("security/aibom.cdx.json is STALE vs the repo sources — regenerate with "
                  "`uv run security/gen_aibom.py`.", file=sys.stderr)
            return 1
        # The HTML render is what people read and what ships as the CI artifact: check it too, rendered
        # with the committed timestamp so only real content drift fails (found in review).
        bom["metadata"]["timestamp"] = committed_ts
        if not HTML_OUT.exists() or HTML_OUT.read_text() != render_html(bom):
            print("security/aibom.html is STALE vs aibom.cdx.json — regenerate with `uv run security/gen_aibom.py`.",
                  file=sys.stderr)
            return 1
        print("AI BOM is current.")
        return 0

    SEC.mkdir(exist_ok=True)
    JSON_OUT.write_text(_dumps(bom))
    HTML_OUT.write_text(render_html(bom))
    print(f"wrote {JSON_OUT.relative_to(ROOT)} and {HTML_OUT.relative_to(ROOT)} "
          f"({len(bom['components'])} components, {len(bom['services'])} service)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
