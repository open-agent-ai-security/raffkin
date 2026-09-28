<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Raffkin graphics

Brand and site assets for Raffkin. Same convention as [praxen/graphics](https://github.com/open-agent-ai-security/praxen/tree/main/graphics)
so the sister sites stay one family.

> **Placeholder status.** The Raffkin-specific assets are concept artwork for review and are meant to be
> **replaced by Lauren's finished artwork from Exabeam Creative**. The wordmark uses live `<text>` rather
> than outlined paths, and the hero is a generated raster illustration. The community and Exabeam logos
> are the production assets copied from Praxen.

**Convention**
- **`graphics/brand/`** — the brand source set: SVG masters referenced directly by the site (nav, footer, docs top bar).
  Named by the background the asset sits on: `-dark-background` = light art for dark backgrounds, `-light-background` = dark ink for light.
- **`graphics/`** — other masters (the mascot, the social card) and the sponsor logo.
- **`graphics/web/`** — raster copies for the surfaces that need them (favicons). Social/OG cards stay PNG for scraper compatibility.

## The mascot: raccoon investigator

A raccoon SOC investigator in the community's black hoodie works at a laptop with a magnifying glass,
four abstract evidence panels, and a small robot companion. The illustration uses warm amber-gold against
graphite black. `raffkin-investigator.webp` is a site-specific crop of the wider concept master: the unused
headline space was removed so the character's visible center aligns with the site's right-hand hero column.

The brand mark follows the sister-project system rather than depicting the mascot literally. A four-point
signal star, two angular wedges, and a single symmetrical mask form suggest a raccoon's markings through
negative space. That keeps it close to Praxen's geometric fox and Observra's geometric owl.

| File | Form | Used by |
|---|---|---|
| `brand/raffkin-mark.svg` | geometric raccoon-mask signal mark | source mark |
| `brand/raffkin-favicon.svg` | mark on a graphite tile | master for `web/favicon-{32,180,256}.png` |
| `brand/raffkin-wordmark-dark-background.svg` | mark + "raffkin" | landing nav + footer, docs top bar |
| `brand/raffkin-wordmark-light-background.svg` | same, dark ink | available |
| `brand/community-logo-{dark,light}-background.svg` | parent-org logo | footer "Part of the…" |
| `raffkin-investigator.webp` | centered hero mascot crop | landing hero |
| `raffkin-social.png` | 1280×640 OG / Twitter card | `<meta property="og:image">` |
| `exabeam-logo-white.svg` | sponsor logo | footer sponsor band |
| `web/favicon-*.png` | 32 / 180 / 256 | `<link rel="icon">`, apple-touch-icon |

## Raster notes

The favicon PNGs, social card, and WebP hero are checked-in exports for predictable GitHub Pages and
social-crawler behavior. Regenerate them from Exabeam Creative's final masters when those arrive.
