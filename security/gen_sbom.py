# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate Raffkin's SBOM — the *software* bill of materials — from the bridge's lockfile.

The AI BOM (`gen_aibom.py`) answers "what models, services and AI artifacts does this agent depend
on". This answers the other question a supply-chain reader asks: **what code actually runs**. The
bridge's PEP 723 header names five direct dependencies; `uv lock --script` resolves them into a
hash-pinned tree of ~30 packages (`plugin/connector/exabeam-mcp-bridge.py.lock`). That lockfile is the
single source of truth here — every component, version, hash and dependency edge below is read from
it, so the SBOM can never say something the lock does not.

Outputs (CycloneDX 1.6):
  security/sbom.cdx.json   machine-readable — feed it to pip-audit, grype, osv-scanner, or a procurement portal
  security/sbom.html       human-readable render, self-contained

Deterministic: the serial number is a uuid5 of (repo, version, lockfile sha256), so an unchanged lock
reproduces byte-identically and any lock change produces a new serial; the timestamp honors
SOURCE_DATE_EPOCH and `--check` ignores it. Cross-linked with the AI BOM in both directions
(`externalReferences` of type `bom`).

Usage:
    uv run security/gen_sbom.py            # rewrite sbom.cdx.json + sbom.html
    uv run security/gen_sbom.py --check    # non-zero exit if the on-disk SBOM is stale vs the lockfile
"""
import hashlib
import importlib.util
import json
import re
import sys
import tomllib
import uuid
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEC = ROOT / "security"
LOCK = ROOT / "plugin" / "connector" / "exabeam-mcp-bridge.py.lock"
SCRIPT = ROOT / "plugin" / "connector" / "exabeam-mcp-bridge.py"
PLUGIN = ROOT / "plugin" / ".claude-plugin" / "plugin.json"
AIBOM = SEC / "aibom.cdx.json"
JSON_OUT = SEC / "sbom.cdx.json"
HTML_OUT = SEC / "sbom.html"

# Share the AI BOM generator's timestamp / serializer / stylesheet so the two documents stay a pair.
_spec = importlib.util.spec_from_file_location("gen_aibom", SEC / "gen_aibom.py")
_aibom = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_aibom)
_timestamp, _dumps, _CSS, SUPPLIER = _aibom._timestamp, _aibom._dumps, _aibom._CSS, _aibom.SUPPLIER


def _norm(name):
    """PEP 503 normalization — the lockfile already uses it; the PEP 723 header may not."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _direct_specifiers():
    """{normalized name: specifier} from the bridge's PEP 723 header (parsed as TOML by gen_aibom)."""
    deps, _ = _aibom._pep723(str(SCRIPT.relative_to(ROOT)))
    out = {}
    for spec in deps:
        name = re.split(r"[<>=!~\[; ]", spec, maxsplit=1)[0]
        out[_norm(name)] = spec[len(name):].strip()
    return out


def _versions(lock):
    """{name: version} for every locked package. A lock that resolves one name to two versions (a
    resolution fork) cannot be flattened into one dependency graph honestly, so it is an error here
    rather than a first-match guess that --check would bless."""
    versions = {}
    for p in lock.get("package", []):
        if p["name"] in versions and versions[p["name"]] != p["version"]:
            sys.exit(f"lockfile resolves {p['name']} to both {versions[p['name']]} and {p['version']} — "
                     "the SBOM cannot pick one; split the resolution before regenerating")
        versions[p["name"]] = p["version"]
    return versions


def build_sbom(timestamp):
    lock_text = LOCK.read_text()
    lock = tomllib.loads(lock_text)
    lock_sha = hashlib.sha256(lock_text.encode()).hexdigest()
    plugin = json.loads(PLUGIN.read_text())
    name, version, repo = plugin["name"], plugin["version"], plugin["repository"]
    direct = {_norm(r["name"]): r.get("specifier", "") for r in lock.get("manifest", {}).get("requirements", [])}
    direct.update({k: v for k, v in _direct_specifiers().items() if k in direct and v})
    aibom_serial = json.loads(AIBOM.read_text()).get("serialNumber", "") if AIBOM.exists() else ""
    versions = _versions(lock)

    def ref_of(n):
        if n not in versions:
            sys.exit(f"lockfile names a dependency it does not lock: {n}")
        return f"pkg:pypi/{n}@{versions[n]}"

    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{repo}@{version}#sbom#{lock_sha}"))
    root_ref = f"{name}@{version}"
    root = {
        "bom-ref": root_ref,
        "type": "application",
        "name": name,
        "version": version,
        "description": ("Raffkin plugin — the bundled Exabeam MCP bridge (plugin/connector/exabeam-mcp-bridge.py) "
                        "and its locked Python dependency tree. The skills themselves are prompt/markdown and "
                        "carry no runtime dependencies."),
        "licenses": [{"license": {"id": plugin["license"]}}],
        "supplier": SUPPLIER,
        "publisher": plugin["author"]["name"],
        "externalReferences": [
            {"type": "vcs", "url": repo},
            {"type": "bom", "url": "aibom.cdx.json",
             "comment": "The AI bill of materials for the same release (models, services, AI artifacts)"
                        + (f" — {aibom_serial}" if aibom_serial else "")},
        ],
    }

    components, dependencies = [], []
    for pkg in sorted(lock.get("package", []), key=lambda p: p["name"]):
        pname, pver = pkg["name"], pkg["version"]
        ref = f"pkg:pypi/{pname}@{pver}"
        hashes = []
        for art in ([pkg["sdist"]] if pkg.get("sdist") else []) + list(pkg.get("wheels", [])):
            h = art.get("hash", "")
            if h.startswith("sha256:"):
                hashes.append({"alg": "SHA-256", "content": h.split(":", 1)[1]})
        registry = (pkg.get("source") or {}).get("registry", "")
        props = [{"name": "raffkin:dependencyKind", "value": "direct" if pname in direct else "transitive"}]
        if pname in direct and direct[pname]:
            props.append({"name": "raffkin:specifier", "value": direct[pname]})
        props.append({"name": "raffkin:artifactsLocked", "value": str(len(hashes))})
        comp = {
            "bom-ref": ref, "type": "library", "name": pname, "version": pver, "purl": ref,
            "scope": "required", "hashes": hashes, "properties": props,
        }
        if registry:
            comp["externalReferences"] = [{"type": "distribution", "url": registry, "comment": "resolved from this index"}]
        components.append(comp)
        deps = sorted({ref_of(d["name"]) for d in pkg.get("dependencies", [])})
        dependencies.append({"ref": ref, "dependsOn": deps})

    dependencies.insert(0, {"ref": root_ref, "dependsOn": sorted(ref_of(n) for n in direct)})

    metadata = {
        "timestamp": timestamp,
        "tools": {"components": [{"type": "application", "name": "gen_sbom.py",
                                  "description": "Raffkin's SBOM generator — reads the uv lockfile, writes CycloneDX",
                                  "supplier": SUPPLIER}]},
        "component": root,
        "supplier": SUPPLIER,
        "properties": [
            {"name": "raffkin:lockfile", "value": str(LOCK.relative_to(ROOT))},
            {"name": "raffkin:lockfileSha256", "value": lock_sha},
            {"name": "raffkin:lockRevision", "value": str(lock.get("revision", ""))},
            {"name": "raffkin:requiresPython", "value": lock.get("requires-python", "")},
            {"name": "raffkin:resolutionMarkers", "value": "; ".join(lock.get("resolution-markers", []))},
            {"name": "raffkin:directDependencies", "value": str(len(direct))},
            {"name": "raffkin:lockedPackages", "value": str(len(components))},
        ],
    }
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial, "version": 1,
        "metadata": metadata, "components": components, "dependencies": dependencies,
    }


# ---------- render HTML ----------

def render_html(bom):
    m = bom["metadata"]; root = m["component"]
    props = {p["name"]: p["value"] for p in m.get("properties", [])}
    esc = lambda s: escape(str(s))  # noqa: E731
    badges = "".join(f'<span class="badge">{esc(t)}</span>' for t in (
        f'v{root["version"]}', f'CycloneDX {bom["specVersion"]}', f'{props.get("raffkin:lockedPackages", "?")} packages',
        f'serial {bom["serialNumber"].split(":")[-1][:8]}…'))
    dep_of = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    rows = []
    for kind in ("direct", "transitive"):
        first = True
        for c in bom["components"]:
            cp = {p["name"]: p["value"] for p in c.get("properties", [])}
            if cp.get("raffkin:dependencyKind") != kind:
                continue
            if first:
                label = "Direct dependencies (declared in the bridge's PEP 723 header)" if kind == "direct" else "Transitive dependencies (resolved by the lockfile)"
                rows.append(f'<tr><td class="cat" colspan="2">{esc(label)}</td></tr>'); first = False
            spec = f' <span class="meta">{esc(cp["raffkin:specifier"])}</span>' if cp.get("raffkin:specifier") else ""
            deps = ", ".join(esc(d.split("/", 1)[1]) for d in dep_of.get(c["bom-ref"], [])) or "—"
            hashes = "".join(f'<div class="meta"><code>sha256:{esc(h["content"])}</code></div>' for h in c.get("hashes", [])[:1])
            more = f'<div class="meta">+ {len(c["hashes"]) - 1} more locked artifact hash(es)</div>' if len(c.get("hashes", [])) > 1 else ""
            rows.append(f'<tr><td class="k">{esc(c["name"])} <code>{esc(c["version"])}</code>{spec}'
                        f'<div class="meta"><code>{esc(c["purl"])}</code></div></td>'
                        f'<td><div>depends on: {deps}</div>{hashes}{more}</td></tr>')
    refs = "".join(f'<li><a href="{esc(r["url"])}">{esc(r["type"])}</a> — {esc(r["url"])}'
                   + (f' <span class="meta">{esc(r["comment"])}</span>' if r.get("comment") else "") + "</li>"
                   for r in root.get("externalReferences", []))
    ts = m.get("timestamp", "(reproducible build — timestamp omitted)")
    facts = "".join(f'<div class="prop"><b>{esc(k.split(":")[-1])}</b> — <code>{esc(v)}</code></div>' for k, v in props.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Copyright 2026 Exabeam, Inc. SPDX-License-Identifier: Apache-2.0 -->
<title>Raffkin — Software Bill of Materials</title><style>{_CSS}</style></head>
<body>
<header><div class="wrap">
  <h1><span class="sc">Raffkin</span> — Software Bill of Materials</h1>
  <p class="tag">{esc(root["description"])}</p>
  <div class="badges">{badges}</div>
</div></header>
<div class="wrap">
  <p class="lead">This is the <b>software</b> BOM: every Python package the bundled Exabeam MCP bridge runs,
  at the exact version and artifact hashes pinned in <code>{esc(props.get("raffkin:lockfile", ""))}</code>.
  It is generated from that lockfile by <code>security/gen_sbom.py</code> and checked for drift in CI, so it
  cannot describe a tree the lock does not. The companion <a href="aibom.html">AI Bill of Materials</a>
  covers the model, the services and the AI artifacts.</p>
  <p class="meta">Supplier: {esc(m["supplier"]["name"])} · Generated: {esc(ts)} · Serial: <code>{esc(bom["serialNumber"])}</code></p>

  <h2>Packages</h2>
  <table><tbody>{"".join(rows)}</tbody></table>

  <h2>Lock facts</h2>
  {facts}

  <h2>Provenance</h2>
  <ul>{refs}</ul>

  <footer>CycloneDX {esc(bom["specVersion"])} · {esc(bom["serialNumber"])}<br>
  Regenerate with <code>uv run security/gen_sbom.py</code>. Raw SBOM: <code>security/sbom.cdx.json</code>.
  Verify: <code>uv run --with pip-audit pip-audit --strict -r &lt;(uv export --script plugin/connector/exabeam-mcp-bridge.py --format requirements-txt --no-hashes)</code></footer>
</div></body></html>
"""


# ---------- main ----------

def main(argv):
    check = "--check" in argv
    bom = build_sbom(_timestamp())
    if check:
        if not JSON_OUT.exists():
            print("sbom.cdx.json missing — run: uv run security/gen_sbom.py", file=sys.stderr)
            return 1
        cur = json.loads(JSON_OUT.read_text())
        fresh = json.loads(_dumps(bom))
        committed_ts = cur.get("metadata", {}).get("timestamp", "")
        cur.get("metadata", {}).pop("timestamp", None)
        fresh.get("metadata", {}).pop("timestamp", None)
        if cur != fresh:
            print("security/sbom.cdx.json is STALE vs the lockfile — regenerate with `uv run security/gen_sbom.py`.",
                  file=sys.stderr)
            return 1
        # The HTML render ships as the CI artifact: checked too, with the committed timestamp so only
        # real content drift fails.
        bom["metadata"]["timestamp"] = committed_ts
        if not HTML_OUT.exists() or HTML_OUT.read_text() != render_html(bom):
            print("security/sbom.html is STALE vs sbom.cdx.json — regenerate with `uv run security/gen_sbom.py`.",
                  file=sys.stderr)
            return 1
        print(f"SBOM is current ({len(bom['components'])} locked packages).")
        return 0
    JSON_OUT.write_text(_dumps(bom))
    HTML_OUT.write_text(render_html(bom))
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    print(f"wrote {JSON_OUT.relative_to(ROOT)} and {HTML_OUT.relative_to(ROOT)} "
          f"({len(bom['components'])} locked packages, {props['raffkin:directDependencies']} direct)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
