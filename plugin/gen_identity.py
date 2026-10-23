#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate every artifact that carries the plugin's identity from ONE source: plugin/identity.json.

    python3 plugin/gen_identity.py            # (re)write the artifacts
    python3 plugin/gen_identity.py --check    # exit 1 if any committed artifact differs (CI)

Generated:
  .claude-plugin/plugin.json                    Claude Code manifest
  .codex-plugin/plugin.json                     Codex manifest (same skills, Codex-only fields)
  .antigravity-plugin/plugin.json               Google Antigravity manifest. ONLY the fields its loader
                                                reads: name, displayName, version, description, logo,
                                                suggestedPrompts (see build())
  mcp_config.json                               the same launch command as .mcp.json, derived from it with
                                                ${CLAUDE_PLUGIN_ROOT} swapped for the ${PLUGIN_ROOT} Antigravity
                                                resolves, and the `type` key dropped (not in its schema). At
                                                the plugin ROOT: that is the only place Antigravity reads it
  hooks.json                                    the same gate as hooks/hooks.json, in Antigravity's own hook
                                                format, at the plugin ROOT. Antigravity stages hooks/hooks.json
                                                only for an IMPORTED Claude Code extension, never for a native
                                                plugin like this one, so the root file is the one it reads
  skills/soc-investigate/settings.snippet.json  the permission gate — every rule spelled out under the
                                                bundled-MCP prefix mcp__plugin_<name>_<server>__ and/or the
                                                manual prefix mcp__<server>__, from the bare-name tiers in
                                                skills/soc-investigate/permissions.json
  identity.sh                                   the same identity as shell variables, sourced by install.sh
                                                and preflight.sh — so a host with no python3 still installs
                                                the right plugin from the right marketplace (a literal
                                                fallback in the scripts would install the UPSTREAM plugin
                                                after a re-key)

`mcpServer` is cross-checked, not consumed: it must equal permissions.json's `server` and the one server
key in .mcp.json / .mcp.codex.json, so an edit to any of the three that is not mirrored fails --check.

Why: `name` is load-bearing. It is the plugin key, and Claude Code namespaces the skills (`<name>:<skill>`)
and the bundled MCP (`mcp__plugin_<name>_<server>__<tool>`) with it — which is what the permission rules
match on. Before this file, re-keying the plugin meant editing two manifests and 92 rules by hand and
hoping nothing drifted; now it is one field here plus a regenerate, and CI fails on drift. A vendor
catalog that ships this payload under its own name (see the Exabeam marketplace) patches identity.json
and regenerates — nothing else in the payload is touched.

Stdlib only; the payload ships this file, so an installed copy can regenerate itself.
"""
import json
import os
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
IDENTITY = HERE / "identity.json"
PERMISSIONS = HERE / "skills" / "soc-investigate" / "permissions.json"
OUT = {
    "claude": HERE / ".claude-plugin" / "plugin.json",
    "codex": HERE / ".codex-plugin" / "plugin.json",
    "antigravity": HERE / ".antigravity-plugin" / "plugin.json",
    "antigravity_mcp": HERE / "mcp_config.json",
    "antigravity_hooks": HERE / "hooks.json",
    "snippet": HERE / "skills" / "soc-investigate" / "settings.snippet.json",
    "shell": HERE / "identity.sh",
}
# The HAND-MAINTAINED MCP files, which is what `mcpServer` is cross-checked against. Deliberately not
# mcp_config.json: that file is GENERATED from .mcp.json below, so reading its key here would make a
# server-key rename self-blocking — check_server would see the stale generated key, disagree, and exit
# before the regeneration that would have fixed it (review of #306).
MCP_FILES = (".mcp.json", ".mcp.codex.json")


def load(p):
    d = json.loads(p.read_text())
    d.pop("_comment", None)
    return d


def prefixes(identity, server):
    return {"plugin": f"mcp__plugin_{identity['name']}_{server}__", "manual": f"mcp__{server}__"}


def server_keys():
    """The MCP server key(s) the shipped .mcp*.json files declare."""
    keys = set()
    for f in MCP_FILES:
        p = HERE / f
        if p.is_file():
            d = json.loads(p.read_text())
            d = d.get("mcpServers", d)
            keys |= {k for k in d if not k.startswith("_")}
    return keys


def check_server(identity, perms):
    got = {perms["server"]} | server_keys()
    if got != {identity["mcpServer"]}:
        sys.exit(f"identity.json mcpServer={identity['mcpServer']!r} does not match permissions.json server "
                 f"/ the .mcp*.json server key ({sorted(got)}) — the three must agree; nothing was written")


def product_name(identity):
    """The product's name as English prose uses it, mid-sentence, article included when the name needs one
    ("Raffkin"; a distribution's "the Exabeam Agentic SOC plugin"). Defaults to the upstream name."""
    return identity.get("productName") or "Raffkin"     # the upstream project's name, never the bare plugin key


def shell_include(identity, perms):
    lines = ["# Copyright 2026 Exabeam, Inc.", f"# SPDX-License-Identifier: {identity['license']}",
             "# GENERATED by gen_identity.py from identity.json — do not edit; CI fails if this drifts.",
             "# Sourced by install.sh and preflight.sh so the identity is read without python3.",
             f"RAFFKIN_ID_NAME={shlex.quote(identity['name'])}",
             f"RAFFKIN_ID_VERSION={shlex.quote(identity['version'])}",
             f"RAFFKIN_ID_LICENSE={shlex.quote(identity['license'])}",
             f"RAFFKIN_ID_MCP_SERVER={shlex.quote(perms['server'])}",
             f"RAFFKIN_ID_MARKETPLACE_REPO={shlex.quote(identity['marketplace']['repo'])}",
             f"RAFFKIN_ID_MARKETPLACE_NAME={shlex.quote(identity['marketplace']['name'])}",
             f"RAFFKIN_ID_PRODUCT_NAME={shlex.quote(product_name(identity))}"]
    return "\n".join(lines) + "\n"


DOC_GLOBS = ("README.md", "docs/**/*.md", "skills/**/*.md")      # prose: rewritten on a re-key
SHELL_FILES = ("install.sh", "preflight.sh")                        # take their identity from identity.sh —
                                                                    # never rewritten; a literal key fails --check


def previous_identity():
    """The identity the shipped prose was last generated for: the committed identity.sh (#180).
    A vendor catalog re-keys the plugin by patching identity.json and regenerating; the guides then
    still name the previous distribution's install key. Reading the previous key from identity.sh lets
    the generator rewrite exactly that key (and the marketplace repo) in the prose — a no-op for the
    distribution that wrote it, a clean rename for a re-keyed copy, and reproducible from a fresh export."""
    sh = OUT["shell"]
    if not sh.exists():
        return None
    vals = {}
    for line in sh.read_text().splitlines():
        if line.startswith("RAFFKIN_ID_") and "=" in line:
            k, v = line.split("=", 1)
            vals[k] = shlex.split(v)[0] if v else ""
    if not all(k in vals for k in ("RAFFKIN_ID_NAME", "RAFFKIN_ID_MARKETPLACE_REPO", "RAFFKIN_ID_MARKETPLACE_NAME")):
        return None
    return {"key": f"{vals['RAFFKIN_ID_NAME']}@{vals['RAFFKIN_ID_MARKETPLACE_NAME']}", "repo": vals["RAFFKIN_ID_MARKETPLACE_REPO"],
            "name": vals["RAFFKIN_ID_NAME"], "marketplace": vals["RAFFKIN_ID_MARKETPLACE_NAME"],
            "license": vals.get("RAFFKIN_ID_LICENSE", ""),      # absent in copies generated before the license followed
            "product": vals.get("RAFFKIN_ID_PRODUCT_NAME") or "Raffkin"}  # copies generated before the prose name followed were Raffkin


def install_key(identity):
    return f"{identity['name']}@{identity['marketplace']['name']}"


def doc_files():
    seen = set()
    for g in DOC_GLOBS:
        for f in sorted(HERE.glob(g)):
            if f.is_file() and f not in seen and f != OUT["shell"]:
                seen.add(f); yield f


_AFTER = r"[A-Za-z0-9_-]"      # a character that continues an identifier: the previous key or repo followed by
_BEFORE = r"[A-Za-z0-9_]"      # one is a longer, different name (`…-dev`) and is not ours to rewrite. A leading
                               # hyphen is allowed: the shell's `${VAR:-default}` puts one right before a default.


def _replace_bounded(text, subs):
    """Exact-string replacement at identifier boundaries. Returns (text, lines) — the 1-based lines where an
    occurrence survived because it continues into a longer identifier."""
    kept = []
    for a, b in subs:
        text = re.sub(rf"(?<!{_BEFORE}){re.escape(a)}(?!{_AFTER})", lambda _m, b=b: b, text)
        kept += [text.count("\n", 0, m.start()) + 1 for m in re.finditer(re.escape(a), text)]
    return text, kept


# The bare marketplace name stands alone in `claude plugin marketplace update <name>`, `/plugin → Marketplaces →
# <name>`, and the settings key `"<name>":`. It also opens the community site (`<name>.github.io`) and the
# source repo path (`github.com/<name>/raffkin`), which a re-keyed copy must keep pointing at the source — so
# the bare-name rewrite stops at a `.` or `/` on either side, unlike the key and repo rewrites.
_BARE_AFTER = r"[A-Za-z0-9_./-]"
_BARE_BEFORE = r"[A-Za-z0-9_./@-]"   # `@`: a name after an @ is part of an install key, which the key rewrite owns

# Prose that is true of the community distribution only, or of a distribution copy only, sits between these
# markers in the shipped docs (#256). A copy re-keyed WITH a `distribution` block drops the community-only
# blocks and unwraps the distribution-only ones; the upstream tree keeps both as HTML comments, which the
# guide builder and GitHub render as nothing.
_MARK_OPEN, _MARK_CLOSE = "<!-- community-only -->", "<!-- /community-only -->"
_DIST_OPEN, _DIST_CLOSE = "<!-- distribution-only", "/distribution-only -->"
_MARKER_LINE = re.compile(r"^[ \t]*(<!-- community-only -->|<!-- /community-only -->|<!-- distribution-only|/distribution-only -->)[ \t]*$")
_COMMUNITY_BLOCK = re.compile(r"^[ \t]*<!-- community-only -->[ \t]*\n.*?^[ \t]*<!-- /community-only -->[ \t]*\n", re.S | re.M)
_DISTRIBUTION_WRAP = re.compile(r"^[ \t]*(<!-- distribution-only|/distribution-only -->)[ \t]*\n", re.M)
_BADGE_LINK = re.compile(r"(\[!\[License: [^\]]+\]\([^)]*badge/license-[^)]+\)\]\()LICENSE\)")
_BADGE = re.compile(r"\[!\[License: [^\]]+\]\(https://img\.shields\.io/badge/license-[^)]+\)\]\(LICENSE\)")


def check_markers(text):
    """The marked blocks a distribution copy switches must be well formed, or a stray marker ships prose it
    should not. Returns a list of problems: a marker sharing a line with prose, opens and closes that do not
    alternate or balance, or a marker of one kind closed by the other."""
    problems, stack = [], []
    for n, line in enumerate(text.split("\n"), 1):
        if not any(m in line for m in (_MARK_OPEN, _MARK_CLOSE, _DIST_OPEN, _DIST_CLOSE)):
            continue
        m = _MARKER_LINE.match(line)
        if not m:
            problems.append(f"line {n}: a marker must stand alone on its line"); continue
        tok = m.group(1)
        if tok in (_MARK_OPEN, _DIST_OPEN):
            if stack: problems.append(f"line {n}: {tok} opened inside an open block")
            stack.append((tok, n))
        else:
            want = _MARK_OPEN if tok == _MARK_CLOSE else _DIST_OPEN
            if not stack or stack[-1][0] != want:
                problems.append(f"line {n}: {tok} closes nothing (or the wrong kind)")
            else:
                stack.pop()
    problems += [f"line {n}: {tok} never closed" for tok, n in stack]
    return problems


def terms_name(dist):
    """The distribution's terms as a badge names them: "the Exabeam Enterprise Agreement" -> "Exabeam Enterprise
    Agreement". Empty when the distribution names none."""
    return re.sub(r"^the\s+", "", (dist or {}).get("terms", ""), flags=re.I)


def terms_slug(terms):
    """The terms as a shields.io badge path spells them: '--' is a literal hyphen, '_' a space."""
    return terms.replace("-", "--").replace(" ", "_")


def _switch_distribution_prose(text, dist=None, name=""):
    """Drop community-only blocks, unwrap distribution-only blocks, fill that prose's {{vendor}}, {{terms}} and
    {{support}} from the distribution block, point the license badge at the Apache text (LICENSE holds the
    distribution's terms in such a copy), and tidy the blank lines the removals leave. Idempotent: a second
    pass finds nothing."""
    text = _COMMUNITY_BLOCK.sub("", text)
    text = _DISTRIBUTION_WRAP.sub("", text)
    for token, value in _distribution_tokens(dist or {}, name).items():
        text = text.replace(token, value)
    terms = terms_name(dist)
    if terms:       # the package's own terms lead: "License: Exabeam Enterprise Agreement", linked to its LICENSE
        text = _BADGE.sub(lambda _m: f"[![License: {terms}](https://img.shields.io/badge/license-{terms_slug(terms)}-blue.svg)](LICENSE)", text)
    else:           # no terms named: the badge still names the software's license, so it links the Apache text
        text = _BADGE_LINK.sub(r"\1LICENSE-APACHE)", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.rstrip("\n") + "\n" if text.strip() else text


# The product's English name in prose (#261 follow-up). A distribution that ships this payload under its own
# product name must never name the upstream project in its prose: "How Raffkin works" becomes "How the Exabeam
# Agentic SOC plugin works". Identifiers stay: paths (~/.raffkin), variables (RAFFKIN_*), URLs and the messages
# the code prints ("Raffkin gate:", "Raffkin bridge refused") are what the payload really uses, so the prose
# that documents them keeps them. Code is skipped too, except diagram source (mermaid), whose labels are prose.
_PROSE_BEFORE = r"[A-Za-z0-9_./@\-]"
_PROSE_AFTER = r"(?:[A-Za-z0-9_/]|-(?=[A-Za-z0-9]))"
_MESSAGE_AFTER = re.compile(r" (?:gate:|gate could|bridge refused|bridge:)")
# The attribution form names the included open-source project itself and keeps it, the way a product says it
# "includes Linux": "It includes Raffkin, open-source software licensed under the Apache License 2.0".
_ATTRIBUTION_AFTER = re.compile(r",\s+open[- ]source\b")
_ENDS_SENTENCE = (".", "!", "?", "|", "—", "=", "{", "[")


def _rename_prose(text, old, new):
    """Replace the product name `old` with `new` in prose only: outside inline code and code fences other than
    diagram source, not inside an identifier, a path or a URL, and not where it opens one of the code's own
    messages.

    `new` carries its own article when it needs one ("the Exabeam Agentic SOC plugin"). Where the prose already
    puts a determiner before the name ("not a Raffkin setting", "every Raffkin skill"), that word is kept, fixed
    to agree ("an Exabeam Agentic SOC plugin setting"), and the name goes in without its own article. A name
    that starts a sentence, heading, list item, table cell, attribute value or diagram label is capitalized; a
    name opening a hard-wrapped continuation line is not."""
    if not old or old == new:
        return text
    bare = new[4:] if new.lower().startswith("the ") else new       # the name without its own article
    pat = re.compile(rf"(?:(?<![A-Za-z])(?P<det>[Aa]n?|[Tt]he|THE|[Nn]o|[Ee]very|[Tt]his|[Yy]our|[Ee]ach|[Aa]ny)\s+)?"
                     rf"(?<!{_PROSE_BEFORE}){re.escape(old)}(?!{_PROSE_AFTER})")

    def sub(seg, done, prev_line):
        out, last = [], 0
        for m in pat.finditer(seg):
            if _MESSAGE_AFTER.match(seg, m.end()) or _ATTRIBUTION_AFTER.match(seg, m.end()):
                continue
            det = m.group("det")
            if det:
                if det.lower() in ("a", "an"):
                    vowel = bare[:1].lower() in "aeiou"
                    det = ("An" if det[0].isupper() else "an") if vowel else ("A" if det[0].isupper() else "a")
                rep = f"{det} {bare}"
            else:
                rep = new
                before = re.sub(r"[\s*_(\"“']+$", "", done + seg[:m.start()])
                opener = re.sub(r"^[\s#>|\-*+\d.)\[\]]*", "", before)
                if opener:
                    cap = before.endswith(_ENDS_SENTENCE) and not before.lower().endswith(("e.g.", "i.e.", "etc.", "vs."))
                else:        # the name opens the line: a new sentence unless it continues a wrapped one
                    p = prev_line.strip()
                    cap = (not p or p.startswith(("#", "|", "-", "*", ">", "<")) or p.endswith(_ENDS_SENTENCE + (":",))
                           or bool(re.match(r"^\s*([#>|]|[-*+]\s|\d+[.)]\s)", done + seg[:m.start()])))
                if cap:
                    rep = rep[:1].upper() + rep[1:]
            out.append(seg[last:m.start()] + rep); last = m.end()
        return "".join(out) + seg[last:]

    lines, fence, prev = [], None, ""
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            mark = stripped[:3]
            if fence is None:
                fence = (mark, stripped[3:].strip().lower() or "code")
            elif stripped.startswith(fence[0]) and not stripped[3:].strip():
                fence = None
            lines.append(line); prev = line; continue
        if fence is not None and fence[1] != "mermaid":
            lines.append(line); prev = line; continue
        parts, done = re.split(r"(`[^`]*`)", line), ""       # odd indexes are inline code, left alone
        for i, part in enumerate(parts):
            done += part if i % 2 else sub(part, done, prev)
        lines.append(done); prev = line
    return "\n".join(lines)


def rewrite_docs(prev, identity):
    """Replace the previous install key, marketplace repo, marketplace name and plugin cache path with the
    current ones in the shipped prose and the shell fallbacks. Exact strings at identifier boundaries;
    nothing else in the prose is touched. An occurrence that continues into a longer identifier
    (`raffkin@open-agent-ai-security-dev`) names something else and is left alone — and reported, so the
    maintainer sees what did not move. A copy with a `distribution` block also switches the marked
    community-only / distribution-only prose (#256)."""
    new_key, new_repo = install_key(identity), identity["marketplace"]["repo"]
    prev_mkt, new_mkt = prev.get("marketplace", ""), identity["marketplace"]["name"]
    prev_path, new_path = f"plugins/cache/{prev_mkt}/{prev.get('name', '')}/", f"plugins/cache/{new_mkt}/{identity['name']}/"
    # Antigravity installs by MANIFEST NAME, into ~/.gemini/config/plugins/<name>/ — so the re-keyed copy's
    # preflight lives under its own name, and the Claude cache rewrite above does not reach that path. Left
    # out, the `soc` docs sent the operator to .../plugins/raffkin/preflight.sh, which does not exist on
    # their machine (review of #306).
    # NO trailing slash, deliberately. _replace_bounded refuses a match that continues into a longer
    # identifier, and _AFTER includes the alphanumerics a NEXT PATH SEGMENT starts with -- so
    # "config/plugins/raffkin/" never matched ".../config/plugins/raffkin/preflight.sh", the one place the
    # path appears. Ending the pattern at the name puts a `/` in the lookahead instead, which is not an
    # identifier character, and `raffkin-dev` is still correctly left alone because `-` is.
    prev_agy = f"config/plugins/{prev.get('name', '')}"
    new_agy = f"config/plugins/{identity['name']}"
    subs = [(prev_path, new_path), (prev_agy, new_agy), (prev["key"], new_key), (prev["repo"], new_repo)]
    subs = [(a, b) for a, b in subs if a and a != b
            and not a.startswith("plugins/cache//") and a != "config/plugins/"]
    bare = (prev_mkt, new_mkt) if prev_mkt and prev_mkt != new_mkt else None
    # Only the keys that mean "this copy is redistributed under other terms" switch the prose. The
    # listing keys do not: an `icon` plus a `supportUrl` describe a DIRECTORY ENTRY, and this repo wants
    # its own entry without telling its own README that it is somebody else's redistribution. Switching on
    # the block's mere presence stripped the Project sponsor section and every community-only block from
    # four docs, and re-pointed the licence badge at a LICENSE-APACHE this repo does not ship -- which made
    # the fields unusable for the community listing they were added for (review of #302).
    dist_block = identity.get("distribution") or {}
    switch = is_redistribution(identity)
    prose = (prev.get("product", ""), product_name(identity))
    prefix = (f"mcp__plugin_{prev['name']}_", f"mcp__plugin_{identity['name']}_") if prev.get("name") and prev["name"] != identity["name"] else None
    changed, kept = [], []
    for f in doc_files():
        text = f.read_text()
        new, lines = _replace_bounded(text, subs)
        kept += [f"{f.relative_to(HERE.parent)}:{n}" for n in lines]
        if bare:
            new = re.sub(rf"(?<!{_BARE_BEFORE}){re.escape(bare[0])}(?!{_BARE_AFTER})", bare[1], new)
        if prefix:      # the tool names the host really shows follow the plugin key (mcp__plugin_<name>_<server>__…)
            new = new.replace(prefix[0], prefix[1])
        if switch:
            new = _switch_distribution_prose(new, dist_block, identity["name"])
        new = _rename_prose(new, *prose)
        if new != text:
            f.write_text(new); changed.append(f)
    return changed, kept


# An SPDX header line anywhere in the payload: an SPDX-shaped identifier (letters, digits, . + -), optionally
# closed by a comment terminator. The shape matters: this generator's own source spells the tag in code.
SPDX_RE = re.compile(r"(?m)^(?P<lead>.*SPDX-License-Identifier:[ \t]*)(?P<id>[A-Za-z0-9.+-]+)(?P<tail>[ \t]*(?:-->|\*/)?[ \t]*)$")


def badge_slug(license_id):
    """The license as the README's shields.io badge path spells it: '-' separates the badge's own fields,
    so the identifier's hyphens become underscores (rendered as spaces)."""
    return license_id.replace("-", "_")


def payload_files():
    for f in sorted(HERE.rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            yield f


def spdx_headers():
    """(file, identifier) for every SPDX header line in the payload."""
    for f in payload_files():
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for m in SPDX_RE.finditer(text):
            yield f, m.group("id")


def rewrite_license(prev_license, identity):
    """A re-key may also relicense the copy: a vendor catalog serving the payload under its own terms sets
    `license` in identity.json (the manifests already follow it). Then every SPDX header in the payload
    and the README's license badge and License section follow too, so an installed copy says one thing
    about its terms in every file, and a license scanner reads the same answer its LICENSE file gives.
    The README is the only prose touched, and only where it names the identifier as THIS copy's license
    (the badge, the License section) — the invariant tests pin that those are its only mentions. The
    LICENSE / NOTICE texts are not the generator's to write; a catalog overlays them as whole files."""
    new = identity["license"]
    if not prev_license or prev_license == new:
        return []
    changed = []
    for f in payload_files():
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        out = SPDX_RE.sub(lambda m: m.group("lead") + (new if m.group("id") == prev_license else m.group("id"))
                          + m.group("tail"), text)
        if f == HERE / "README.md":
            out, _ = _replace_bounded(out, [(prev_license, new)])
            out = out.replace(f"badge/license-{badge_slug(prev_license)}-", f"badge/license-{badge_slug(new)}-")
        if out != text:
            f.write_text(out); changed.append(f)
    return changed


DISTRIBUTION_KEYS = ("homepage", "repository", "license")      # manifest key order, unchanged from before the block
DISTRIBUTION_LISTING_KEYS = ("documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl")
# Anthropic's plugin directory reads these from .claude-plugin/plugin.json for the listing; Claude Code
# ignores them at load time and `claude plugin validate` rejects them in a marketplace entry, so the
# manifest is the only place they can go. They describe the LISTING, which is per-distribution -- the
# community listing and a vendor's are different entries -- so they live in the distribution block and
# are emitted only when set.
#
# `icon` is NOT one of them. The mark has ONE home, the top-level `logo`, and both manifests are emitted
# from it (review of the merge with #306, which moved `logo` up here). Two reasons it cannot be a listing
# key. It is required for Antigravity, so it is always set -- letting `distribution.icon` win would mean
# a per-copy listing key overriding a product-identity key. And the catalog overlay merges dotted keys
# into whatever `distribution` block the payload already carries, so a `distribution.icon` set upstream
# for the community listing would be INHERITED by a vendor copy unless that overlay remembered to
# override it: #307's leak from the other side. A top-level `logo` is replaced the way `displayName`
# is. One field, two emitters.
DISTRIBUTION_PROSE_KEYS = ("vendor", "terms", "support", "antigravityInstall")   # prose only, filled into the distribution-only text:
# the distributor's name, the name of the terms the copy is licensed under, and its support page (a URL)
_VENDOR_FALLBACK = "the organization that distributes it"


def is_redistribution(identity) -> bool:
    """Is this copy somebody else's redistribution, as opposed to this repo carrying its own listing?

    One predicate, because asking the question two different ways is how the two halves of the
    distribution block drifted apart. `any(k in block)` was the first answer and it was wrong: a block
    holding only `documentationUrl` and `supportUrl` describes a DIRECTORY ENTRY, not a change of terms,
    and reading it as one stripped the sponsor section out of four docs. Review of the merge with #306
    then found the same test still live in the --check path, where a listing-only block demanded an
    `antigravityInstall` no listing needs. The terms keys are the question; the listing keys are not.
    """
    dist = identity.get("distribution") or {}
    # Truthiness, not membership: review found `{"license": null}` switched every doc into
    # redistribution prose and wrote `"license": null` into both manifests. A key present and empty is a
    # key nobody filled in.
    return any(dist.get(k) for k in DISTRIBUTION_KEYS + DISTRIBUTION_PROSE_KEYS)


def logo_path(identity):
    """The listing's mark, as the manifests should spell it: one validated path, two emitters.

    `payload_image` does the checking -- there is one image validator, not two. Review proved the two had
    converged on identical answers for every path tried, and that the branch unique to this one
    (`p.resolve().parent != p.parent.resolve()`) could never be true: `is_symlink()` returns first, and
    for a non-symlink the two sides are equal by construction. A symlinked PARENT is caught by the
    `is_relative_to` test both shared."""
    if not identity.get("logo"):
        sys.exit("identity.json needs a `logo`: the Marketplace listing needs one, and a missing logo is "
                 "not an error on the card, just an empty one")
    return payload_image(identity["logo"], "logo")


def _distribution_tokens(dist, name=""):
    """The distribution-only prose's placeholders, from the distribution block, with generic fallbacks so a
    distribution that sets none of them still reads correctly."""
    vendor = dist.get("vendor") or _VENDOR_FALLBACK
    terms = f"{dist['terms']} (see `LICENSE`)" if dist.get("terms") else "the terms in its `LICENSE` file"
    support = f"[{dist.get('vendor') or 'its'} support]({dist['support']})" if dist.get("support") else f"the support path of {vendor}"
    # Antigravity installs from a GitHub subpath, not from a marketplace key, so rewrite_docs's
    # key/repo substitutions cannot re-point it: the source repo is not the marketplace repo. A
    # distribution sets its own URL here, or the prose says to ask rather than naming the community
    # build -- which is what an un-rewritten URL would otherwise do.
    agy = dist.get("antigravityInstall") or "<the subpath URL for this distribution — ask its maintainer>"
    # `agy plugin uninstall <name>` names the plugin BARE -- not as an install key, a repo or a path, so
    # none of rewrite_docs's substitutions reach it, and the literal upstream name shipped in the
    # distribution's own uninstall instructions (review of #306). The token lives only inside the
    # distribution-only block, which stays an HTML comment upstream, so it survives a regeneration the way
    # {{antigravity_install}} does.
    return {"{{vendor}}": vendor, "{{terms}}": terms, "{{support}}": support,
            "{{antigravity_install}}": agy, "{{plugin_name}}": name or "<this copy's plugin name>"}


def manifest_fields(identity):
    """The manifest describes the plugin AS DISTRIBUTED. A catalog that serves this payload under its own
    terms (Exabeam-Labs/plugins) sets an optional `distribution` block in identity.json — `license`, `homepage`,
    `repository` — and the manifests take those values. The top-level `license` keeps meaning the
    software's license: it drives the SPDX headers, the README badge and identity.sh, and is untouched by
    the block, so the source stays under its own license while the package states the distribution's."""
    dist = identity.get("distribution") or {}
    unknown = sorted(set(dist) - set(DISTRIBUTION_KEYS) - set(DISTRIBUTION_PROSE_KEYS) - set(DISTRIBUTION_LISTING_KEYS))
    if unknown:
        sys.exit(f"identity.json distribution block accepts only {DISTRIBUTION_KEYS + DISTRIBUTION_PROSE_KEYS + DISTRIBUTION_LISTING_KEYS}, got {unknown}")
    # `dist.get(k) or identity[k]`, not `dist.get(k, …)`: a key present and empty (`{"license": null}`,
    # which an overlay can produce by patching a value it does not have yet) wrote `"license": null`
    # straight into both manifests. An empty value falls back to the plugin's own, same as an absent one.
    return {k: (dist.get(k) or identity[k]) for k in DISTRIBUTION_KEYS}


IMAGE_SUFFIXES = (".svg", ".png", ".jpg", ".jpeg", ".webp")
# Enough of each format to tell an image from a README someone renamed. SVG is text, so it is recognised
# by its root element rather than a magic number -- an XML declaration or a comment may come first, which
# is why the whole head is searched rather than only its start.
_IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff")   # the suffixes we accept, minus WEBP (two parts) and SVG (text)


def _looks_like_image(p: Path) -> bool:
    """Does the file's CONTENT match its suffix? Review verified that a text file and a 0-byte file named
    `.png` both passed, and both render nothing on a listing rather than failing anything."""
    head = p.read_bytes()[:1024]
    if not head:
        return False
    if head.startswith(_IMAGE_MAGIC):
        return True
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return True
    try:
        text = head.decode("utf-8", "strict").lstrip().lower()
    except UnicodeDecodeError:
        return False
    return text.startswith(("<svg", "<?xml", "<!doctype svg", "<!--"))


def payload_image(raw, label):
    """A path to an image that SHIPS IN THE PAYLOAD, checked rather than copied through.

    This is overlay-supplied input: a distribution points its listing at its own mark by patching
    identity.json, and the generator runs inside the vendoring pipeline. A path that leaves the payload
    either 404s on the listing or ships whatever the path landed on, and neither is visible in a diff of
    identity.json. Every branch below was a path that passed the first version of this check (review of
    #302): `.//etc/hosts`, because pathlib treats the remainder as absolute and drops HERE; a symlink out
    of the tree, whose target is not in the payload the user installed; and `./README.md`, which is not an
    image at all. Returns the path as the manifest should spell it.

    NOTHING HERE RAISES ON THE HOST. Both loaders fail SILENTLY on a bad value: Antigravity's own
    documentation, which ships inside the `agy` binary, says "URLs and absolute paths are rejected
    silently -- a bad value renders no logo rather than erroring", and an unsupported suffix does the
    same. So every check below is the only chance to see the fault: past this function the symptom is an
    empty card that nothing in CI can observe (#306, verified against agy 1.4.4).

    REQUIREMENT ON A VENDORING CATALOG. The file has to be there when this runs. Exabeam-Labs/plugins
    currently regenerates the payload BEFORE applying its `overlay_files`, in both vendor_plugin.py and
    verify_upstream -- so a mark delivered as a file overlay (`assets/icon.png`, Exabeam-Labs/plugins#47)
    is not yet on disk and vendoring aborts here with "not a file in the payload". The fix belongs there,
    applying file overlays before regenerating; the check stays here, because the alternative is a
    listing whose mark 404s and nothing to tell anyone it will."""
    if not isinstance(raw, str) or not raw.strip():
        sys.exit(f"identity.json {label} must be a non-empty string, got {raw!r}")
    raw = raw.strip()
    if "://" in raw:
        sys.exit(f"identity.json {label} must be a path to an image inside the payload, not a URL: {raw!r}. "
                 "Both hosts reject a URL silently and render nothing")
    rel = raw[2:] if raw.startswith("./") else raw
    parts = Path(rel).parts
    if not rel or rel.startswith("/") or ".." in parts or "" in parts:
        sys.exit(f"identity.json {label} must be a relative path inside the plugin, with no '..' segment, got {raw!r}")
    p = HERE / rel
    if p.is_symlink():
        sys.exit(f"identity.json {label} is a symlink ({raw!r}) — the image must be a real file in the payload")
    if not p.is_file():
        sys.exit(f"identity.json {label} names {raw!r}, which is not a file in the payload (looked for {p})")
    if not p.resolve().is_relative_to(HERE.resolve()):
        sys.exit(f"identity.json {label} resolves outside the plugin: {p.resolve()}")
    if p.suffix.lower() not in IMAGE_SUFFIXES:
        sys.exit(f"identity.json {label} is not an image ({', '.join(IMAGE_SUFFIXES)}), got {raw!r} — "
                 "an unsupported suffix is another value that renders nothing rather than erroring")
    # macOS is case-INSENSITIVE and case-preserving, so `./ASSETS/LOGO.SVG` opens the real file here and
    # 404s everywhere the listing is actually served. Review verified it was accepted on APFS; Linux CI
    # would reject it, so it only bites a vendoring run done locally on a Mac -- which is how the
    # supported build gets made. Each component is matched against what the directory really holds.
    probe = HERE
    for part in parts:
        if part not in os.listdir(probe):
            sys.exit(f"identity.json {label} is spelled {raw!r}, but the payload holds {part!r} with "
                     "different capitalisation. This machine's filesystem does not care and the server "
                     "that hosts the listing will")
        probe = probe / part
    if not _looks_like_image(p):
        sys.exit(f"identity.json {label} names {raw!r}, whose contents are not an image: no PNG, JPEG, "
                 "WEBP or SVG/XML signature in the first bytes. A suffix is a claim, not evidence, and a "
                 "0-byte or text file with an image suffix renders nothing on either host")
    # The NORMALISED spelling, so `./assets//icon.svg` and `./assets/./icon.svg` cannot reach a manifest
    # verbatim: review verified both were emitted as written. `as_posix()` because a manifest path is a
    # URL-ish path on every platform, never a Windows one.
    return Path(rel).as_posix()


def listing_url(raw, label, schemes=("https",)):
    """A URL fit for a directory listing. Everything it rejects renders as a dead link rather than
    failing anything, which is why each case is checked here instead:

      - a bare `https://` passed a prefix test (review of #302);
      - `https://[` raised an uncaught ValueError traceback out of `urlsplit` instead of a labelled exit;
      - `https://exa mple.com` and a URL with an embedded newline were accepted, and the newline went
        into the manifest;
      - `https://@/` and `https://:443` have a netloc but no HOST, so `.hostname` is the test, not
        `.netloc`."""
    if not isinstance(raw, str) or not raw.strip():
        sys.exit(f"identity.json {label} must be a non-empty string, got {raw!r}")
    raw = raw.strip()
    bad = [c for c in raw if c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F]
    if bad:
        sys.exit(f"identity.json {label} contains whitespace or a control character ({bad[0]!r}), which "
                 f"would be written into the manifest verbatim: {raw!r}")
    try:
        parts = urlsplit(raw)
    except ValueError as e:
        sys.exit(f"identity.json {label} is not a URL ({e}): {raw!r}")
    if parts.scheme not in schemes:
        sys.exit(f"identity.json {label} must be a {' or '.join(s + '://' for s in schemes)} URL, got {raw!r}")
    if parts.scheme == "mailto":
        if "@" not in parts.path or parts.path.startswith("@") or parts.path.endswith("@"):
            sys.exit(f"identity.json {label} must be mailto: an address, got {raw!r}")
        return raw
    try:
        host = parts.hostname
    except ValueError as e:
        sys.exit(f"identity.json {label} has no readable host ({e}): {raw!r}")
    if not host:
        sys.exit(f"identity.json {label} must be an https:// URL with a host, got {raw!r}")
    return raw


def https_url(raw, label):
    """Back-compatible name for the https-only case."""
    return listing_url(raw, label)


def listing_fields(identity):
    """The directory-listing fields, for the Claude manifest only, omitted when unset.

    `supportUrl` accepts `mailto:` as well, because `claude plugin validate` does and a vendor whose
    support contact is an address had no way to set it. It also defaults from the distribution block's
    `support`, which the catalog overlay already fills for the prose: a distribution that named its
    support page once should not have to name it twice to be listed."""
    dist = identity.get("distribution") or {}
    out = {}
    for k in DISTRIBUTION_LISTING_KEYS:
        schemes = ("https", "mailto") if k == "supportUrl" else ("https",)
        if k in dist:
            # PRESENT is the test here, not truthy -- unlike the terms keys, which fall back to the
            # plugin's own value when empty. A listing key has nothing to fall back to, so an empty one
            # is a value an overlay meant to fill and didn't, and saying so beats a quietly missing link.
            out[k] = listing_url(dist[k], f"distribution.{k}", schemes=schemes)
        elif k == "supportUrl" and dist.get("support"):
            out[k] = listing_url(dist["support"], "distribution.support (used as supportUrl)", schemes=schemes)
    return out
# Antigravity's PreToolUse hook is the SAME gate as Claude Code's, in a different envelope: the host
# calls the hook with the pending call on stdin and honours `{"decision": "deny"}` as a hard block, plus
# "ask" and "force_ask" for a prompt. So the deny tier, the ask tier and the per-session write budget are
# all in force here -- which is why none of the documentation may say otherwise.
#
# Three details of this file are not interchangeable with hooks/hooks.json:
#
#   WHERE. The plugin ROOT, not hooks/. Antigravity stages hooks/hooks.json into the root only when it
#   IMPORTS a Claude Code or Gemini CLI extension; a native plugin -- any directory carrying plugin.json or
#   .antigravity-plugin/plugin.json, which is us -- gets no staging and "must place hooks.json directly at
#   the plugin root". A gate in the wrong directory is a gate that silently does not run: #212 again.
#
#   THE MATCHER. Antigravity matches on the STEP TYPE, not the tool name: every MCP call, whichever server
#   it belongs to, arrives as `mcp_tool` (CORTEX_STEP_TYPE_MCP_TOOL, lowercased with the prefix stripped),
#   with the real tool name inside the payload. So the matcher cannot select the Exabeam server the way
#   Claude Code's regex does -- it has to catch every MCP call and let the gate decide, which is the
#   posture the gate was written for anyway ("the hook, not the matcher, decides whether a call is ours").
#
#   THE INTERPRETER. `python3` is not bundled with Antigravity, and a hook command that cannot start
#   produces no JSON, which the host reads as "no opinion" -- a fail-OPEN that no test of ours would see.
#   `uv` is what the bridge already needs, and it brings its own Python, so it is the fallback: if python3
#   is missing the same gate runs under uv. The one case left is neither being present, and there the
#   bridge cannot start either, so there is no Exabeam tool to gate.
HOOK_TIMEOUT = 20

# The refusal the shell writes when no interpreter could run the gate at all.
#
# On Claude Code a hook command that exits 2 blocks the call, so there a failure IS a refusal (#296).
# Antigravity has no such contract: the only hard block on this host is a `deny` object on stdout, and the
# host's own changelog records the permission manager being FIXED to handle "empty decision strings returned
# by pre-tool hooks" safely instead of erroring -- so a gate that cannot start does not stop the call, it
# just goes unheard. That is the #212 shape ("0 HOOK MISS") on a new host, so the refusal has to be written
# by the shell rather than left to an exit code nothing reads.
#
# Chaining is safe because every path through gate.py returns 0, including the broad `except`, so a
# non-zero exit means the interpreter never ran the gate TO COMPLETION and printed no decision -- the `||`
# cannot append a second object to a decision already on stdout. It does NOT mean the gate read nothing:
# a python3 that consumes the payload and then dies leaves the next stage with an empty stdin, which is
# why the chain buffers the payload in `_in` rather than re-reading it. What nothing here covers is the
# host killing the command at `timeout`, since the shell dies with it (a residual in
# security/design/human-in-the-loop-gate.md).
AGY_NO_GATE = ("Raffkin gate could not run, so this call cannot be checked against the permission tiers: "
               "no python3 and no uv on PATH, or the gate script itself could not be executed. The gate "
               "fails closed, so the call is refused. See the installation guide for this host.")

# A separate refusal for an empty payload, because it is a different fault with a different fix and
# naming the wrong one sends whoever reads it looking for an interpreter that is already there. It also
# shares no phrase with the tier refusal preflight matches on, so an install that delivers nothing to the
# hook fails preflight instead of satisfying it.
AGY_NO_INPUT = ("Raffkin gate received no payload on standard input, so it could read nothing about this "
                "step and refuses rather than standing aside. Something between the host and the hook is "
                "dropping the payload: check that cat, printf and grep are on the PATH the host launches "
                "hooks with.")


def antigravity_hooks(identity, server):
    gate = "./hooks/gate.py"           # cwd for a hook command is the directory holding hooks.json
    deny = json.dumps({"decision": "deny", "reason": AGY_NO_GATE}, separators=(",", ":"))
    no_input = json.dumps({"decision": "deny", "reason": AGY_NO_INPUT}, separators=(",", ":"))
    if "'" in deny or "'" in no_input:  # the fallback is a single-quoted shell word; an apostrophe ends it
        sys.exit("AGY_NO_GATE and AGY_NO_INPUT must not contain an apostrophe: it would terminate the "
                 "shell string early and the hook would emit broken JSON instead of a refusal")
    # The matcher is the STEP type, so with no interpreter this fallback is handed every MCP call on the
    # machine -- another server's `create_pull_request` included. Denying all of them protects nothing of
    # ours and is how a control gets switched off by whoever it annoys, so the shell reads the step it was
    # given and refuses only the ones naming our server. `grep` on stdin is the whole test available
    # without an interpreter; a free-text argument mentioning Exabeam on somebody else's call is refused
    # too, which is the conservative direction and only while the gate is already broken.
    # Only grep's exit 1 -- "ran fine, our server is not in this step" -- stands aside. 0 is ours, and
    # anything above 1 (127 when grep itself is missing, 2 on an error) means the step could not be READ,
    # which is not the same as reading that it is somebody else's. Those refuse. Written this way round
    # because the first cut keyed on success/failure and failed open exactly when the machine was most
    # broken: no interpreter AND no grep answered {} on a containment call.
    # No input is NOT "somebody else's call". The chain reads the payload ONCE into `_in` and feeds every
    # stage from it, because a later stage cannot re-read a stdin an earlier one consumed: review built a
    # python3 that reads the payload and exits 1, and the fallback then handed `grep` nothing, which
    # exited 1 ("not ours") and answered {} to a containment call. That is the shape of every crash in
    # gate.py AFTER it has read stdin. An empty `_in` now refuses.
    refuse_if_ours = (f'if [ -z "$_in" ]; then printf \'%s\' \'{no_input}\'; '
                      f'else printf \'%s\' "$_in" | grep -qi {server}; _rc=$?; '
                      f"if [ $_rc -eq 1 ]; then printf '%s' '{{}}'; else printf '%s' '{deny}'; fi; fi")
    # An empty payload is answered BEFORE any interpreter is tried, because python3 SUCCEEDS on empty
    # input: review ran the chain with `cat` missing and the gate answered `ask` (its own catch-all for an
    # unreadable event) instead of denying, which is the one decision this host overrides under
    # --dangerously-skip-permissions. The fallback keeps its own empty test as well, so the refusal is
    # still correct if that snippet is ever reached or read on its own.
    def run(*flags, fallback, empty):
        args = " ".join(("", *flags)).rstrip()
        return (f'_in=$(cat); if [ -z "$_in" ]; then printf \'%s\' \'{empty}\'; '
                f'else printf \'%s\' "$_in" | python3 {gate}{args}'
                f' || printf \'%s\' "$_in" | uv run --quiet --no-project {gate}{args}'
                # a brace group needs the terminating semicolon; `{ cmd }` is a syntax error in sh
                f" || {{ {fallback}; }}; fi")
    group = lambda *flags, fallback, empty: [{"matcher": "mcp_tool|call_mcp_tool",
                             "hooks": [{"type": "command",
                                        "command": run(*flags, fallback=fallback, empty=empty),
                                        "timeout": HOOK_TIMEOUT}]}]
    # Keyed on the plugin's own name: hook files from several plugins are merged into one map, so a fixed
    # key would collide with another copy of this payload (the vendored one installs alongside, #306).
    # Pre refuses; post answers with the empty object its contract asks for. A post hook that cannot run
    # loses an audit record, which is a real loss, but it is not a decision to make -- and this host marks
    # the tool call failed if the hook says anything else.
    return {f"{identity['name']}-gate": {"PreToolUse": group("--antigravity", fallback=refuse_if_ours,
                                                             empty=no_input),
                                         "PostToolUse": group("--antigravity", "--post",
                                                              fallback="printf '%s' '{}'", empty="{}")}}


def build(identity, perms):
    common = {k: identity[k] for k in ("name", "version", "description", "author")} | manifest_fields(identity)
    # `icon` comes from the top-level `logo`, the one home of the mark, so the community listing gets an
    # icon with no distribution block at all and a vendor copy gets its own by overriding `logo` -- the
    # same key the overlay already patches for `displayName`. Claude spells a payload-relative path with
    # the leading `./`; Antigravity does not.
    claude = {**common, "keywords": identity["keywords"] + identity["hostKeywords"]["claude"], "skills": "./skills/",
              "icon": f"./{logo_path(identity)}", **listing_fields(identity)}
    # The bundled PreToolUse hook (#148) is deliberately NOT declared here. Claude Code loads
    # hooks/hooks.json from the standard path automatically, so declaring that same path makes the loader
    # see the file twice and fail the WHOLE plugin load -- skills, MCP server and gate together (#197).
    # Not a host regression: every Claude Code back to 2.1.200 fails the same way. The live checks that
    # cleared it ran through --plugin-dir, which reports the error and continues, so the install path
    # was never exercised with the field. The gate is registered by shipping the file, not by naming it. What keeps a
    # regeneration from silently unregistering it is test_repo_invariants, which asserts the payload
    # carries hooks/hooks.json AND that no manifest names it.
    codex = {**common, "keywords": identity["keywords"] + identity["hostKeywords"]["codex"], "skills": "./skills/",
             "mcpServers": "./.mcp.codex.json",
             "interface": {"displayName": identity["displayName"], "shortDescription": identity["shortDescription"],
                           "category": identity["category"]}}
    pre = prefixes(identity, perms["server"])
    tiers = {}
    for tier, spec in perms["tiers"].items():
        tiers[tier] = [pre[p] + t for p in spec["prefixes"] for t in spec["tools"]]
    snippet = {"permissions": tiers}
    # Antigravity resolves components from the plugin ROOT, and takes the manifest from
    # .antigravity-plugin/plugin.json when a repo already keeps provider manifests in dot-folders --
    # which is what its own guide recommends for a layout like ours.
    #
    # EVERY FIELD HERE IS LOAD-BEARING, AND NOTHING ELSE MAY BE ADDED. The loader's own documentation
    # (shipped inside the `agy` binary; the published PDF is behind it) lists exactly seven accepted
    # top-level fields -- name, description, logo, suggestedPrompts, displayName, version, disabled -- and
    # then says: "Do not add any other top-level field. `author` and `homepage` are silently discarded by
    # the loader -- they neither take effect nor error out."
    #
    # So this manifest is built field by field instead of spreading `common`, which carries author,
    # homepage, repository and license. Three earlier keys are gone for the same reason, and each one was
    # doing nothing:
    #   mcpServers  -- NOT a manifest field. Antigravity reads the servers from mcp_config.json at the
    #                  plugin root, and ignored this pointer silently: `agy plugin validate` reported
    #                  "unknown field mcpServers is ignored" and "mcpServers 0", i.e. the whole Exabeam
    #                  tool surface absent on this host. This is the bug that made #306 ship a plugin with
    #                  no tools (verified against agy 1.4.4).
    #   skills      -- unnecessary. skills/<name>/SKILL.md is discovered from the tree; the validator
    #                  counted all three with the key removed.
    #   category,   -- not in the accepted set, so both are dropped on load. `keywords` earned its place on
    #   keywords       the other two hosts and stays in identity.json for them; Marketplace search matches
    #                  on `description` here, which is why the short one is used.
    #
    # The listing's own description, NOT the long one: 120-160 characters for a Marketplace card, and the
    # long description ends "dismiss/close gated by the host agent's tool-approval rules", which reads as a
    # promise about a prompt we do not control. The gate's own guarantee is carried by hooks.json below.
    # The logo comes from identity.json so a distribution's overlay can point its listing at its own mark.
    antigravity = {"name": identity["name"],
                   "displayName": identity["displayName"],
                   "version": identity["version"],
                   "description": identity["shortDescription"],
                   "logo": logo_path(identity),
                   "suggestedPrompts": identity["suggestedPrompts"]}
    # Antigravity resolves ${PLUGIN_ROOT}, not ${CLAUDE_PLUGIN_ROOT}: pointing it at .mcp.json would
    # hand it a command with an unresolved variable and the bridge would never start. So the Antigravity
    # MCP file is generated FROM .mcp.json with the variable swapped -- one source for the launch command,
    # so a change there (the --locked flag, #255) cannot reach one host and miss the other.
    #
    # One thing is dropped in the derivation, and only this one. `type` is not a field in Antigravity's MCP
    # schema: the loader's documented stdio transport is `command` + optional `args`/`env`, and the only
    # other transport is `url`. A strict reader would reject the server and the skills would load with no
    # Exabeam tools, which is the failure this whole file exists to prevent; a lenient reader ignores it.
    # Dropping it is correct either way, and the transport is still unambiguous: a `command` IS stdio.
    #
    # The server key matters beyond this file: Antigravity namespaces a plugin's servers as
    # `<plugin>_<server>`, so the bundled bridge arrives as `<name>_exabeam` here where Claude Code calls it
    # `plugin_<name>_exabeam`. The gate knows both (is_bundled).
    mcp = json.loads((HERE / ".mcp.json").read_text())
    antigravity_mcp = json.loads(
        json.dumps(mcp).replace("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}"))
    for server in antigravity_mcp.get("mcpServers", {}).values():
        if isinstance(server, dict):
            server.pop("type", None)
    return {"claude": claude, "codex": codex, "antigravity": antigravity,
            "antigravity_mcp": antigravity_mcp, "antigravity_hooks": antigravity_hooks(identity, perms["server"]),
            "snippet": snippet, "shell": shell_include(identity, perms)}


def render(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    check = "--check" in argv
    identity, perms = load(IDENTITY), load(PERMISSIONS)
    check_server(identity, perms)
    want = {k: (v if isinstance(v, str) else render(v)) for k, v in build(identity, perms).items()}
    stale = [k for k, text in want.items() if (OUT[k].read_text() if OUT[k].exists() else "") != text]
    prev = previous_identity()
    if check:
        names = [str(OUT[k].relative_to(HERE.parent)) for k in stale]
        guide = HERE / "docs" / "installation.md"
        if guide.exists() and install_key(identity) not in guide.read_text():
            names.append(str(guide.relative_to(HERE.parent)) + " (does not name this distribution's install key)")
        # An Antigravity install has no marketplace key to rewrite — it is a GitHub subpath URL, which only
        # the distribution knows. Unset, the guide shipped "<the subpath URL for this distribution — ask its
        # maintainer>" to real users (review of #306). Fail loudly instead, and only where it matters: a
        # distribution copy that actually ships the Antigravity manifest. A distribution that is not listing
        # on this host drops .antigravity-plugin/ and this never fires.
        if is_redistribution(identity) and OUT["antigravity"].exists() \
                and not ((identity.get("distribution") or {}).get("antigravityInstall") or "").strip():
            names.append("plugin/identity.json (ships .antigravity-plugin/plugin.json but its distribution block "
                         "sets no `antigravityInstall`, so the install guide would tell users to ask its "
                         "maintainer for the URL — set it, or drop .antigravity-plugin/ to skip this host)")
        lic = identity["license"]
        wrong = sorted({str(f.relative_to(HERE.parent)) for f, i in spdx_headers() if i != lic})
        if wrong:
            names.append(f"{len(wrong)} file(s) whose SPDX header does not name this distribution's license "
                         f"{lic!r}: {', '.join(wrong[:4])}{', …' if len(wrong) > 4 else ''}")
        readme = HERE / "README.md"
        terms = terms_name(identity.get("distribution"))
        named, badge = (terms, terms_slug(terms)) if terms else (lic, badge_slug(lic))
        if readme.exists() and (named not in readme.read_text() or f"badge/license-{badge}-" not in readme.read_text()):
            names.append("plugin/README.md (does not name this distribution's license)")
        bad = [f"{f.relative_to(HERE.parent)} ({'; '.join(p)})" for f in doc_files() for p in [check_markers(f.read_text())] if p]
        if bad:
            names.append("malformed community-only / distribution-only markers in " + ", ".join(bad))
        key = install_key(identity)
        literal = [f for f in SHELL_FILES if (HERE / f).is_file()
                   and re.search(rf"(?<!{_BEFORE}){re.escape(key)}(?!{_AFTER})", (HERE / f).read_text())]
        if literal:
            names.append(", ".join(f"plugin/{f}" for f in literal) + " (carries the install key as a literal — the shell "
                         "scripts read the identity from identity.sh; a literal is what a re-key would leave behind)")
        if names:
            print("stale (run python3 plugin/gen_identity.py): " + ", ".join(names), file=sys.stderr)
            return 1
        print(f"identity artifacts in sync with plugin/identity.json (name={identity['name']!r}, "
              f"prefix={prefixes(identity, perms['server'])['plugin']!r})")
        return 0
    changed, kept = rewrite_docs(prev, identity) if prev else ([], [])   # before identity.sh is rewritten below
    relicensed = rewrite_license(prev["license"], identity) if prev else []
    for k, text in want.items():
        OUT[k].write_text(text)
    n = sum(len(v) for v in json.loads(want["snippet"])["permissions"].values())
    dist = identity.get("distribution") or {}
    print(f"wrote {', '.join(str(OUT[k].relative_to(HERE.parent)) for k in OUT)} — name={identity['name']!r}, "
          f"version {identity['version']}, {n} permission rules"
          # Only the MANIFEST keys here. `antigravityInstall` and the other prose keys never reach a
          # manifest, and naming them on this line said they did.
          + (f"; manifests carry the distribution's {', '.join(sorted(set(dist) & set(DISTRIBUTION_KEYS)))}"
             if set(dist) & set(DISTRIBUTION_KEYS) else "")
          + (f"; distribution prose filled from {', '.join(sorted(set(dist) & set(DISTRIBUTION_PROSE_KEYS)))}"
             if set(dist) & set(DISTRIBUTION_PROSE_KEYS) else "")
          + (f"; install key {prev['key']} → {install_key(identity)} in {len(changed)} file(s)" if changed else "")
          + (f"; left {len(kept)} longer identifier(s) untouched: {', '.join(kept)}" if kept else "")
          + (f"; license {prev['license']} → {identity['license']} in {len(relicensed)} file(s)" if relicensed else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
