#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown>=3.5"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Build the styled documentation site (guide/) for GitHub Pages from the repo's markdown.

BUILD-ONLY: not part of the shipped plugin. Mirrors praxen/docs_build.py so the sister sites read as one
family (same left-nav shell, same theme inlined per page, same SEO/GEO head), with one difference:
Raffkin's docs live in several places — the docs front page is plugin/docs/index.md (the operator
README stays on GitHub), the guides are plugin/docs/*.md, the methodology is each skill's SKILL.md, and the assurance record is security/ —
so PAGES lists (source path, output name, nav label) and links are rewritten per source directory.
The guide is USER documentation only: install, use, what happens to your data, the audit trail, and a
worked example. Methodology (SKILL.md), the red-team program, the Praxen remit and results, the evals and
the AI BOM are developer/assurance material and stay in the repository (linked from the landing page).

    uv run docs_build.py          # regenerate guide/*.html + sitemap.xml
"""
import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import markdown

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "guide"
THEME_CSS = ROOT / "assets" / "raffkin-theme.css"
REPO = "https://github.com/open-agent-ai-security/raffkin"
RAW = "https://raw.githubusercontent.com/open-agent-ai-security/raffkin/main"
SITE_URL = "https://open-agent-ai-security.github.io/raffkin/"
SOCIAL_IMAGE = "graphics/raffkin-social.png"
SITE_NAME = "Raffkin"

# (source path from repo root, output name in guide/, nav label)
PAGES = [
    ("plugin/docs/index.md",                                                        "index",               "Overview"),
    ("plugin/docs/installation.md",                                                 "installation",        "Installation & setup"),
    ("plugin/docs/usage.md",                                                        "usage",               "Using the skills"),
    ("plugin/skills/soc-investigate/reference/examples/coordinated-credential-access.md", "example",        "Example investigation"),
    ("plugin/docs/security-guardrails.md",                                          "security-guardrails", "Security"),
    ("plugin/docs/logging.md",                                                      "logging",             "Audit logging"),
    ("plugin/docs/support.md",                                                      "support",             "Support"),
]
BY_SOURCE = {src: out for src, out, _ in PAGES}

LEADING_COMMENT = re.compile(r"^\s*<!--.*?-->\s*", re.DOTALL)
FRONT_MATTER = re.compile(r"^---\n.*?\n---\n", re.DOTALL)
MERMAID_BLOCK = re.compile(r'<pre><code class="language-mermaid">(.*?)</code></pre>', re.DOTALL)
MERMAID_VERSION = "11.15.0"
MERMAID_SRI = "sha384-yQ4mmBBT+vhTAwjFH0toJXNYJ6O4usWnt6EPIdWwrRvx2V/n5lXuDZQwQFeSFydF"
MERMAID_SCRIPT = f"""<script src="https://cdn.jsdelivr.net/npm/mermaid@{MERMAID_VERSION}/dist/mermaid.min.js"
        integrity="{MERMAID_SRI}" crossorigin="anonymous"></script>
<script>
mermaid.initialize({{ startOnLoad: false, theme: 'dark', fontFamily: '"Inter", system-ui, sans-serif',
  themeVariables: {{ primaryColor: '#13233b', primaryBorderColor: '#2a3b57', primaryTextColor: '#e8eef7', lineColor: '#8aa0bd', fontSize: '14px' }} }});
document.fonts.ready.then(() => mermaid.run({{ querySelector: '.prose pre.mermaid' }}));
</script>"""


def render_mermaid_blocks(body):
    found = False
    def repl(m):
        nonlocal found; found = True
        return f'<pre class="mermaid">{html.unescape(m.group(1))}</pre>'
    return MERMAID_BLOCK.sub(repl, body), found


def resolve(src_dir: Path, href: str) -> str:
    """Repo-relative path a doc's relative link points at (normalized, no '..')."""
    parts = list((src_dir / href).parts)
    out = []
    for p in parts:
        if p == "..":
            if out: out.pop()
        elif p != ".":
            out.append(p)
    return "/".join(out)


def rewrite_links(body: str, src: str) -> str:
    """Links between docs that are site pages → guide/*.html; any other repo file → GitHub blob view;
    images → raw.githubusercontent so the diagrams render on the site; anchors/absolute URLs untouched."""
    src_dir = Path(src).parent
    def fix(href):
        if urlparse(href).scheme or href.startswith(("#", "//")):
            return href
        path, _, frag = href.partition("#")
        target = resolve(src_dir, path) if path else src
        if target in BY_SOURCE:
            # GitHub's heading slug keeps a hyphen run where punctuation was dropped ("governance--turn-on");
            # python-markdown's toc collapses the run. The sources are written for GitHub; the site is not.
            frag = re.sub(r"-{2,}", "-", frag)
            return BY_SOURCE[target] + ".html" + (("#" + frag) if frag else "")
        return f"{REPO}/blob/main/{target}" + (("#" + frag) if frag else "")
    def repl_a(m):
        q, href = m.group(1), m.group(2)
        return f"href={q}{fix(href)}{q}"
    def raw_url(srcv):
        srcv = srcv.strip()
        if not srcv or urlparse(srcv).scheme or srcv.startswith("//"):
            return srcv
        return f"{RAW}/{resolve(src_dir, srcv)}"
    def repl_img(m):
        attr, q, val = m.group(1), m.group(2), m.group(3)
        if attr == "srcset":                                  # "url [descriptor], url [descriptor]"
            cands = []
            for cand in val.split(","):
                url, _, desc = cand.strip().partition(" ")
                cands.append((raw_url(url) + " " + desc).strip())
            return f"srcset={q}{', '.join(cands)}{q}"
        return f"src={q}{raw_url(val)}{q}"
    body = re.sub(r"""href=(["'])(.*?)\1""", repl_a, body)
    body = re.sub(r"""\b(src|srcset)=(["'])(.*?)\2""", repl_img, body)
    return body


def onpage_toc(toc_tokens):
    items = []
    def collect(tokens):
        for t in tokens:
            if t.get("level") == 2: items.append(t)
            collect(t.get("children") or [])
    collect(toc_tokens)
    if not items: return ""
    return '<ul class="docs-subnav">' + "".join(f'<li><a href="#{t["id"]}">{t["name"]}</a></li>' for t in items) + "</ul>"


TAG_RE = re.compile(r"<[^>]+>"); WS = re.compile(r"\s+")
def meta_description(body, fallback, limit=155):
    m = re.search(r"<p[^>]*>(.*?)</p>", body, re.DOTALL)
    text = html.unescape(TAG_RE.sub("", m.group(1))).strip() if m else ""
    text = WS.sub(" ", text) or fallback
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0].rstrip(",;:.") + "…"


def left_nav(active_out, active_toc):
    out = ['<nav class="docs-nav"><div class="docs-nav-title">Documentation</div><ul>']
    for _, name, label in PAGES:
        cls = ' class="active"' if name == active_out else ""
        out.append(f'<li><a href="{name}.html"{cls}>{html.escape(label)}</a>')
        if name == active_out and active_toc: out.append(active_toc)
        out.append("</li>")
    return "".join(out) + "</ul></nav>"


def _jsonld_str(v): return json.dumps(v).replace("</", "<\\/")


def page_html(theme_css, title, nav, body, src, out_name, description, body_end=""):
    edit_url = f"{REPO}/blob/main/{src}"
    full_title = f"{html.escape(title)} · Raffkin Docs"
    canonical = f"{SITE_URL}guide/{out_name}.html"
    desc_attr = html.escape(description, quote=True)
    image_url = f"{SITE_URL}{SOCIAL_IMAGE}"
    json_ld = f"""<script type="application/ld+json">
{{ "@context": "https://schema.org", "@type": "TechArticle", "headline": {_jsonld_str(title)}, "description": {_jsonld_str(description)},
  "url": {_jsonld_str(canonical)}, "isPartOf": {{ "@type": "WebSite", "name": "Raffkin", "url": {_jsonld_str(SITE_URL)} }},
  "publisher": {{ "@type": "Organization", "name": "Exabeam", "url": "https://www.exabeam.com/" }} }}
</script>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{full_title}</title>
<meta name="description" content="{desc_attr}">
<meta name="robots" content="index, follow">
<link rel="canonical" href="{canonical}">
<link rel="icon" type="image/png" sizes="32x32" href="../graphics/web/favicon-32.png">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Raffkin">
<meta property="og:title" content="{full_title}">
<meta property="og:description" content="{desc_attr}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{image_url}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{full_title}">
<meta name="twitter:description" content="{desc_attr}">
<meta name="twitter:image" content="{image_url}">
{json_ld}
<style>{theme_css}</style>
<script data-goatcounter="https://open-agent-ai-security.goatcounter.com/count" async src="../assets/count.js"></script>
</head>
<body class="docs-page">
<header class="docs-top">
  <div class="docs-top-inner">
    <a class="docs-brand" href="../"><img src="../graphics/brand/raffkin-wordmark-dark-background.svg" alt="Raffkin" width="117" height="30"></a>
    <div class="docs-top-links">
      <a href="../">Home</a>
      <a class="btn btn-ghost" href="{REPO}" target="_blank" rel="noopener"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9.6.1.8-.2.8-.6v-2c-3.2.7-3.9-1.4-3.9-1.4-.5-1.3-1.3-1.7-1.3-1.7-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.6-.3-5.3-1.3-5.3-5.7 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.4-2.7 5.4-5.3 5.7.4.4.8 1.1.8 2.2v3.3c0 .4.2.7.8.6 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z"/></svg>GitHub</a>
    </div>
  </div>
</header>
<div class="docs-shell">
  <aside class="docs-sidebar">{nav}</aside>
  <main class="docs-main">
    <article class="prose">{body}</article>
    <p class="docs-edit"><a href="{edit_url}" target="_blank" rel="noopener">Edit this page on GitHub ↗</a></p>
  </main>
</div>
{body_end}
</body>
</html>
"""


def render_all():
    """{repo-relative path: content} for every generated file -- the guide pages and the sitemap."""
    theme_css = THEME_CSS.read_text(encoding="utf-8")
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"], output_format="html5")
    out, sitemap = {}, [""]
    for src, out_name, label in PAGES:
        text = (ROOT / src).read_text(encoding="utf-8")
        text = LEADING_COMMENT.sub("", text, count=1)
        text = FRONT_MATTER.sub("", text, count=1)          # SKILL.md YAML front matter
        md.reset(); body = md.convert(text)
        body = rewrite_links(body, src)
        body, has_mermaid = render_mermaid_blocks(body)
        m = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.DOTALL)
        title = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else label
        nav = left_nav(out_name, onpage_toc(md.toc_tokens))
        out[f"guide/{out_name}.html"] = page_html(theme_css, title, nav, body, src, out_name, meta_description(body, label),
                                                  MERMAID_SCRIPT if has_mermaid else "")
        sitemap.append(f"guide/{out_name}.html")
    entries = "\n".join(f"  <url><loc>{html.escape(SITE_URL + p, quote=True)}</loc></url>" for p in sitemap)
    out["sitemap.xml"] = ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                          + entries + "\n</urlset>\n")
    return out


def build():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for rel, content in render_all().items():
        (ROOT / rel).write_text(content, encoding="utf-8")
        print(f"docs_build.py: wrote {rel}")


def check():
    """Exit 1 if any committed generated file differs from what the sources render to -- the same gate
    every other generator in the repo has (gen_aibom, gen_identity, gen_sbom), because guide/ is the
    PUBLIC copy of the install and guardrails docs and must never quietly go stale (review, 2026-09-06)."""
    stale = [rel for rel, content in render_all().items()
             if not (ROOT / rel).is_file() or (ROOT / rel).read_text(encoding="utf-8") != content]
    if stale:
        print("docs_build.py: STALE — regenerate with `uv run docs_build.py`: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("docs_build.py: guide/ and sitemap.xml are current with the sources.")
    return 0


if __name__ == "__main__":
    sys.exit(check() if "--check" in sys.argv[1:] else build())
