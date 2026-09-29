<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design record — Input Telemetry Canonicalizer

> **Status:** Shipped and wired; this header is current with the code as of 0.8.6. The authoritative
> statement of behaviour is `plugin/connector/canonicalize.py` (87 lines, stdlib only) and the read path
> in `plugin/connector/exabeam-mcp-bridge.py`. The user-facing description is
> [the guardrails page](../../plugin/docs/security-guardrails.md#1-screening-what-raffkin-reads-hidden-character-smuggling).
> **Addresses:** RFE #2 (the code-layer half). **Supersedes:** the inbound-*defang* approach in PR #31,
> which two independent reviews blocked for mutating pivotable values ([§2](#2-why-this-is-not-the-pr-31-approach)).
> **Companion:** the write side is the [output neutralizer](output-neutralizer.md).

## What shipped (authoritative)

The core landed in PR #32 and was **narrowed** on the way to what the design proposed. Where §1–§13
below say otherwise, this section and the code win.

- **A curated list of ranges, not a Unicode property.** The design's `\p{Cf} ∪ \p{DI}` via the `regex`
  library was dropped for a hand-curated set in stdlib `unicodedata`, on the do-no-harm rule: a property
  class sweeps in characters with legitimate use inside a value. Corrupting a legitimate value — and
  breaking an exact-match pivot — is worse than missing an exotic smuggle.

  | | Code points | Why |
  |---|---|---|
  | **Stripped** | C0/C1 controls (except `\t` `\n` `\r`); zero-width space; word joiner and the invisible math operators `U+2060–2064`; the deprecated format controls `U+206A–206F`; bidi embeddings, overrides and isolates `U+202A–202E`, `U+2066–2069`; the BOM `U+FEFF`; interlinear annotation `U+FFF9–FFFB`; the tag block `U+E0000–E007F`; the variation-selector supplement `U+E0100–E01EF` | no legitimate place inside a telemetry value |
  | **Kept** (the design's §4 listed some as strip) | ZWNJ/ZWJ; LRM/RLM/ALM; the emoji variation selectors `U+FE00–FE0F`; the soft hyphen; the Mongolian, Khmer and Hangul-filler format characters; NBSP and every other space | real linguistic use |
  | **Normalized** | `U+2028/2029` (invisible line and paragraph separators) → a visible newline; then NFC (never NFKC) | nothing visible is rewritten |
- **Hygiene record:** `removed` (what was stripped) and `kept` (flagged-but-kept invisibles), logged by
  the bridge **out of band** — to stderr and the audit trail — never appended to the content the model
  reads (the design's §9 decision, kept). The richer per-offset forensic record and `escapedRaw` in §9
  were **not built**; the homoglyph/mixed-script flag in §5 was **not built** (advisory and
  false-positive-prone on localized hostnames).
- **Wired in the bridge on every tool result** — text and embedded-resource blocks — **fail-closed per
  block** (#172): a block that raises is withheld and replaced by a bounded message that names the
  exception class and asks for the evidence gap to be reported; the other blocks of the result are
  untouched, the exception class goes to stderr, and a `hygiene_screen_failed` flag on the call's audit
  record says a block was withheld (Praxen findings 2026-09-05-006/-007; findings are in
  [praxen/results/](../praxen/results/)). The tool-definition screen has the same direction: a definition
  it cannot process is withheld for the session, counted and named in the startup line and the audit trail. The design's OQ-4 (arguments) resolved *no*: reads are never argument-mutated; writes
  are the neutralizer's.
- **The remote's tool definitions are screened too** (#159, #164 — Praxen finding 2026-09-07-001, #6).
  Once per session:
  - descriptions and schema text are canonicalized like any result;
  - a **name is never rewritten** — one carrying a hidden code point is reported instead;
  - every definition is **hashed**, and the surface hash is recorded in the audit trail so a definition
    that changes between sessions shows up;
  - a definition that *talks to the model* (instruction-shaped phrases) is reported, never changed — the
    skill counters it in prose;
  - a tool the shipped tier file does not classify is treated as a write.
- **Accepted residuals** (stated in the module docstring): a kept invisible spliced into an ASCII word,
  emoji variation-selector byte channels, NBSP keyword-splitting, and NFC folding of compatibility
  singletons (`U+212A` KELVIN → K) / NFD recomposition — a rare, bounded exact-match-pivot miss. The
  screen fails closed per block (#172).
- **Verified:** `tests/test_canonicalize.py` (the clean-corpus invariant of §11 — a clean value passes
  through unchanged except NFC — plus one fixture per strip channel) and the read-path wiring in
  `tests/test_bridge_wiring.py`; live, red-team fixture a07 (a zero-width-space smuggle) on every
  release. Fixtures a06 (encoded) and a08 (homoglyph) run beside it but measure the model's handling,
  not this control — an encoded payload has no invisible code points, and homoglyphs are kept by design.

> **§1–§13 below are the original design intent (2026-08), kept for the reasoning and the references.**
> They describe a fuller build than shipped; the section above is what runs.

## 1. Purpose

Untrusted telemetry (alert fields, event text, prior case notes) reaches the agent through the bridge. Attackers control that text, and a documented class of attacks hides payloads from the model's — and a human's — perception using **invisible / obfuscating Unicode**: tag-block "ASCII smuggling," zero-width characters, bidirectional overrides, variation-selector byte channels, and homoglyphs. Empirically these bypass *detection*-based guardrails at near-100% rates ([Mindgard/Lancaster, arXiv:2504.11168](https://arxiv.org/abs/2504.11168)), so the durable defense is **deterministic canonicalization that removes the obfuscation layer before anything reads the text** — not a classifier that tries to spot injections.

This canonicalizer does exactly three things:

1. **Strip** the invisible smuggling layer (characters with no legitimate place in a value).
2. **Flag** visible-but-suspicious constructs (homoglyphs, abnormal hidden-char counts) — never rewrite them.
3. **Normalize** to NFC, and **annotate** every change so nothing is silent.

### Non-goals (explicitly out of scope)

- **Not** active-content defanging. Neutralizing `=HYPERLINK(...)` formulas and phishing URLs so they can't fire on export is the **a10 output-side fix** (Option A), a separate layer. This spec does **not** touch URLs, emails, or formula cells. (That conflation is exactly what broke PR #31.)
- **Not** semantic injection detection. No "ignore previous instructions" phrase-matching, no LLM classifier. Detection-based defenses are what the smuggling attacks defeat.
- **Not** decoding or interpreting. base64/hex blobs are *flagged*, never decoded-and-acted-on.
- **Not** homoglyph rewriting. Mixed-script is flagged; the value is preserved (a Cyrillic hostname may itself be the IOC).

## 2. Why this is NOT the PR #31 approach

PR #31 defanged URLs/emails/formulas **on inbound tool results**. Both reviewers (adversarial agent + Codex) rated that a P1 blocker: it *mutated pivotable values* — `user@CORP.EXAMPLE` → `user[@]CORP[.]EXAMPLE`, `https://evil.example/x` → `hxxps://evil[.]example/x` — so any follow-up `search_events` on the visible value missed the raw telemetry, silently degrading investigations.

The distinction that makes **this** design safe where that one wasn't:

| | PR #31 defang (withdrawn) | This canonicalizer |
|---|---|---|
| Operates on | legitimate **visible** values | the **invisible** smuggling layer |
| A clean value (`user@corp.example`) | **mutated** → breaks pivot | **untouched** (has no invisibles) |
| Homoglyph / IOC domain | mutated | **flagged, preserved** |
| Result for search pivots | broken | preserved |

**Invariant:** a legitimate value that contains no smuggling characters passes through **unchanged except for NFC** (which is canonical-equivalent). Only the crap is removed. This is what keeps it pivot-safe.

## 3. Where it runs

Same interception point the withdrawn defang used — the bridge's `call_tool`, over each text content block returned from the remote MCP — but doing strip/flag/NFC instead of defang.

```
remote MCP → call_tool result → [canonicalize per text block] → agent context
```

- **Text blocks only.** Non-text content (images, embedded resources) passes through untouched. (Open question OQ-6: do we also canonicalize `EmbeddedResource` text?)
- **Fail-open per block** *(v1 — superseded by #172: the block is withheld; see the status section above)*. A raised exception passes the *original* block through unchanged with a stderr note. This sits in the path of every tool call; a canonicalizer bug must never break an investigation.
- **Reads only, not arguments** (v1). See OQ-4.
- Pure function, no I/O, deterministic → unit-tested in CI with no model.

## 4. The strip set (curated deny-list)

Removed unconditionally and annotated. **Driven by an explicit list — NOT by the `Default_Ignorable_Code_Point` property**, which includes ZWJ/ZWNJ and variation selectors we must keep (UTS #39; see [§5](#5-the-flag-set-detect-annotate-never-rewrite)).

| Codepoint(s) | Name | Why strip | Source |
|---|---|---|---|
| `U+E0000–E007F` | Unicode **Tag block** | The canonical LLM "ASCII smuggling" channel; mirrors ASCII invisibly; no legit use in telemetry | Goodside 2024; AWS; CSA; OWASP LLM01 |
| `U+E0100–E01EF` | **Variation Selectors Supplement** (VS17–256) | Maps to raw bytes — arbitrary-data smuggling channel | Rehberger 2025 |
| `U+202A–202E` | Bidi embeddings/overrides (LRE/RLE/PDF/LRO/RLO) | Trojan-Source visual reordering | Boucher & Anderson (CVE-2021-42574) |
| `U+2066–2069` | Bidi **isolates** (LRI/RLI/FSI/PDI) | Same; naive filters miss the isolates | Boucher & Anderson; UTS #55 |
| `U+200B` | Zero-width space | Splits keywords to evade filters / hide text | UTS #39 |
| `U+2060` | Word joiner | Invisible; smuggling | Rehberger |
| `U+2061–2064` | Function application, invisible times/separator/plus | "Sneaky Bits" binary encoding | Rehberger 2025 |
| `U+FEFF` | BOM / ZWNBSP (mid-string) | Invisible; smuggling | UTS #39 |
| `U+00AD` | Soft hyphen | Invisible in most renderers | UTS #39 |
| `U+180E` | Mongolian vowel separator | Deprecated format char, invisible | Unicode |
| `U+0000–001F` except `\t \n \r` | C0 controls | Non-printable control smuggling / parser confusion | OWASP |
| `U+0080–009F` | C1 controls | Same | OWASP |
| `U+D800–DFFF` | Lone/orphaned surrogates | Can recombine into tag chars; also crash JSON serialization | AWS; Python bug #17906 |

**Note on lone surrogates:** in well-formed UTF-8 these can't occur (they'd raise on `json.dumps`), so for our Python/UTF-8 pipeline this is *defensive* — but upstream UTF-16 SIEM components can emit them, so we strip at the decode boundary regardless.

## 5. The flag set (detect, annotate, NEVER rewrite)

Surfaced as a hygiene annotation; the value is left intact so pivots and legitimate multilingual/emoji content are preserved.

| Construct | Codepoints / test | Why flag-not-strip |
|---|---|---|
| **ZWJ / ZWNJ** | `U+200C`, `U+200D` | **Required** in Persian/Arabic/Indic and emoji sequences — stripping corrupts legitimate text (UTS #39 §5.1; PR-96). v1: flag + count. |
| **Emoji variation selectors** | `U+FE00–FE0F` (esp. `U+FE0F`) | `FE0F` is the ubiquitous emoji-presentation selector; legit. Flag only if count is abnormal. |
| **Directional marks** | `U+200E`, `U+200F`, `U+061C` (LRM/RLM/ALM) | Legitimate in mixed-direction text; weaker than the stripped overrides. |
| **Mixed-script / homoglyph** | UTS #39 resolved-script-set = ∅; `Identifier_Status=Restricted` | Confusable domains are often the IOC itself; rewriting destroys evidence + pivot. Flag the token + rationale. |
| **base64 / hex blob** | length/charset heuristic, pre-decode | Never decode-and-act; flag so downstream treats decoded content as untrusted too. |
| **Exotic whitespace** | NBSP `U+00A0`, `U+2028/2029` (line/para sep), `U+3000`, other `Zs` | Can spoof line structure; but legitimate. v1: flag (OQ-5: flag vs normalize-to-space). |
| **Combining-mark runs (Zalgo)** | run of `Mn` above threshold | Obfuscation/DoS vector but legitimate in many scripts — count/flag, don't strip. NFC won't remove. |
| **Hidden-char budget** | total stripped+flagged per field/message > threshold | A legit note has ~0; dozens = smuggling. Per-message flag signal (Rehberger). |

## 6. Normalization

- **NFC only.** Applied **last** (strip → NFC → done). NFC is canonical-equivalent (preserves the visible value → pivot-safe).
- **Never NFKC on searchable values** — it rewrites full-width/ligatures/`U+212A`→K etc., mutating legitimate indicators. (NFKC may be used only for a *derived, flagged-for-analysis* view, never the value the agent pivots on.)
- **Order matters — and strip-before-NFC is safe *here* specifically because our strip is identity-based, not content-based.** The Special-K bypass hits *allow/deny decisions on content*: a compatibility character slips past a filter, then normalizes into the dangerous form. We make no such decision — we remove a **fixed set of code points by identity**, and NFC neither creates nor destroys any code point in that set (NFC won't turn a visible character into a tag-block/zero-width/bidi control, nor vice-versa). So strip→NFC and NFC→strip yield the same result for our set; we pick strip-first so offset accounting is on the raw input. Combining marks (`Mn`) are preserved. This is a test bucket (order-independence over the strip set) — [§11](#11-test-corpus-deterministic-ci--no-model).

## 7. Idempotence & the fixpoint question

- On **decoded Unicode code points** (Python `str`, UTF-8), a single well-ordered pass is idempotent — removing whole code points cannot recombine into a new tag char the way split UTF-16 surrogate *pairs* can (that's the AWS/Java concern, UTF-16-specific).
- **Cheap insurance, adopted:** after strip→NFC, assert a second pass is a no-op; if not, re-run, **capped at 3 iterations** (bounded, no DoS). This gives the AWS "recursive-until-stable" guarantee without assuming single-pass is safe.

## 8. Keep-raw-for-pivots

The reviewers' pivot break came from *mutating visible values*. This design doesn't: it **strips only invisibles** (never part of a searchable value) and **flags** everything that would otherwise require mutation. NFC is the sole value transform and is canonical-equivalent. So the visible/searchable content the agent sees still matches the SIEM — the **value** carries no raw copy, while the out-of-band hygiene metadata retains an *escaped* raw form for the one edge below.

- **The dirty-stored-value edge, and how we preserve pivot/IR ability:** if an attacker planted an invisible char *inside* a stored value (e.g. a username), the sanitized value won't match the dirty raw record. We do **not** drop that raw context — the [§9](#9-annotation--hygiene-metadata-out-of-band) hygiene record's **`escapedRaw`** carries a safe **escaped** reconstruction (e.g. `alice\u200b@example.com`, invisible char shown only as `\uXXXX`) so IR can rebuild an exact search / containment scope / vendor-support artifact. We never render the raw invisible literally into the value, but we never lose it either.

## 9. Annotation & hygiene metadata (out-of-band)

**Decision (resolves OQ-1, previously blocking):** the canonicalizer emits its findings as **structured, namespaced hygiene metadata carried out-of-band — never as prose mixed into the sanitized telemetry text.** Appending commentary into the tool-result text would (a) let trusted canonicalizer output be read as *evidence*, (b) create a **new injection surface** (the annotation is derived from attacker-controlled input), and (c) get re-analyzed by the fixpoint pass. So:

- The **tool-result text** is the sanitized value only (stripped + NFC) — nothing else.
- A separate **hygiene record** travels alongside it: either a dedicated content block prefixed with a reserved sentinel that the canonicalizer **skips on any re-pass** and the skill renders as *metadata, not evidence*, or the MCP result's `_meta` / structured channel if the SDK surfaces it (implementation choice — see OQ-6). Namespaced `raffkin.hygiene`.

**Record shape** (per content block):

```json
{
  "schema": "raffkin.hygiene/v1",
  "removed": [{"cp": "U+200B", "name": "ZERO WIDTH SPACE", "offset": 12, "byteOffset": 12, "class": "strip", "reason": "zero-width"}],
  "flagged": [{"token": "аpple.com", "offset": 40, "class": "mixed-script", "severity": "high", "reason": "Latin+Cyrillic confusable"}],
  "counts": {"stripped": 3, "flagged": 1},
  "escapedRaw": {"40": "аpple.com", "12": "alice\\u200b@example.com"}
}
```

- **Offset semantics (resolves the §4 Codex note):** offsets are **original code-point indices** into the *pre-normalization* input, plus original **byte offset** when available. Accounting happens *before* NFC, so an index never refers to the normalized form — a consumer can always reconcile a finding back to raw tool output.
- **Severity** per flag (`info` | `suspicious` | `high`) so ordinary multilingual/emoji content (`info`) doesn't drown the real smuggling signal (`high`) — the alert-fatigue concern.
- **`escapedRaw`** carries a safe, escaped reconstruction of any value we stripped (e.g. `alice\u200b@example.com`) so IR can rebuild an exact query / containment scope for a *dirty stored value*. Invisible chars appear **only** as escaped `\uXXXX` sequences, never literally (that's a test bucket — [§11](#11-test-corpus-deterministic-ci--no-model)).
- The skill summarizes the hygiene record separately (a "data hygiene" line in the report) and it must **never** influence the verdict as if it were evidence.
- **The hygiene record is itself untrusted.** Its `token` / `escapedRaw` fields are attacker-derived substrings, so: they are **length-bounded** (per-field cap, summarized with an ellipsis if longer — *without* dropping any per-codepoint accounting entry); serialized **inertly** (plain JSON string escaping only — no markdown/HTML the skill would render as active); and the skill treats the whole record as **untrusted metadata, never authoritative analysis**. The out-of-band channel must not become a smaller, more-trusted injection surface.

## 10. Fail-open & performance *(fail-open is the v1 record — superseded by #172, which withholds the block)*

- Per-block `try/except` → original block passes through on any error (availability > canonicalization).
- **Observable fail-open.** A fail-open is **not silent**: it emits a bounded diagnostic to **stderr** (never stdout — that's the stdio MCP protocol channel) and increments a per-process `canonicalize_failopen` counter. The hygiene record for that block is marked `{"status": "failopen", "error": "<class>"}` so a downstream consumer can tell "canonicalized clean" from "passed through unchecked." A deterministic test asserts: a raising block → original returned **and** a bounded diagnostic emitted **and** counter incremented.
- Linear time; stripping **shrinks** text (no `[.]`-style inflation — that was the defang; not present here). Metadata is out-of-band and bounded.
- Perf budget: multi-MB Exabeam dumps must stay well under a second (research probes: ~1s on 5–11 MB). Optional size guard: above N MB, still fail-open (and mark it).

## 11. Test corpus (deterministic, CI — no model)

- **Positive (must strip/flag):** one fixture per channel — tag block, zero-width, bidi override + isolate, variation-selector byte channel, sneaky-bits (`U+2062/2064`), homoglyph domain; plus red-team payloads a06 (base64), a07 (zero-width), a08 (homoglyph).
- **Negative — the clean-corpus invariant (§2 made executable):** for a curated corpus of clean UPNs, emails, URLs, domains, hostnames, filenames, IPs, hashes, paths, and multilingual text (Persian/Indic ZWNJ/ZWJ, emoji `ZWJ`/`FE0F`, legit NBSP, combining marks): `canonicalize(v).text == NFC(v)` **and** `hygiene.removed == [] and hygiene.flagged == []`. This is the regression gate that stops PR #31 returning under a new name.
- **Accounting completeness (oracle = original input, not a diff):** `len(hygiene.removed) == sum(1 for c in input if c in STRIP_SET)` — counted over the *original input string*, so it never depends on post-deletion position shifts or a diff algorithm; every entry maps to its original input index and carries a full record (offset, cp, class, reason, severity).
- **Annotation safety (Codex bucket 1):** stripped invisible characters appear in the hygiene record **only** as escaped `\uXXXX` / code-point names — assert no literal invisible from the strip set is present anywhere in `text` or the rendered hygiene block.
- **Pivot reconstruction (Codex bucket 2):** for a dirty value, `hygiene.escapedRaw` contains an escaped form sufficient to rebuild an exact follow-up query; round-trip un-escape → equals the original dirty value.
- **Order-independence over the strip set:** `strip(NFC(x)) == NFC(strip(x))` for the fixed strip set (justifies strip-before-NFC, §6).
- **Metadata bounds & inertness:** a very long suspicious `token` / `escapedRaw` is truncated to the field cap **without dropping any per-codepoint accounting entry**; every attacker-derived field round-trips through serialization inertly (no unescaped invisibles, no active markup) — the hygiene channel can't itself smuggle.
- **Structural:** idempotence (second pass = no-op; sentinel block skipped); fail-open (raising block → original returned + diagnostic + counter + `failopen` status); NFC-not-NFKC (full-width preserved as a `flag`, not folded); MCP block-shape fixtures (`TextContent`, `EmbeddedResource`, `structuredContent`) each handled-or-documented.

## 12. Open questions (red-pen targets)

- **OQ-1 — Annotation surfacing. ✅ RESOLVED** (§9): structured, out-of-band hygiene metadata, namespaced, severity-tagged; the skill summarizes it separately and it never influences the verdict as evidence. Remaining sub-decision folded into OQ-6.
- **OQ-2 — ZWJ/ZWNJ policy.** v1 flag-only (safe). Do we ever want *contextual* stripping (strip only when NOT adjacent to script letters/emoji)? Adds complexity; defer to a corpus-tuned v2. *(Codex: start conservative.)*
- **OQ-3 — Hidden-char budget threshold.** What count per field/message trips the `suspicious` flag? (Proposal: >3 stripped, or any tag-block/bidi = `high` regardless; tune with corpus.) *(Codex: start conservative.)*
- **OQ-4 — Arguments too? ⛔ GATE.** v1 canonicalizes tool *results* only. Do we also canonicalize outbound tool *arguments*? This intersects the a10 output-side write neutralization — decide *with* the Option-A spec so the two layers don't overlap or gap. Blocks coding.
- **OQ-5 — Exotic whitespace.** Flag (v1) vs normalize exotic `Zs` → `U+0020`? Normalizing mutates the value (only for a detection copy). *(Codex: start conservative → flag.)*
- **OQ-6 — Content-block coverage + hygiene transport. ⛔ GATE.** (a) Handle `EmbeddedResource`/`structuredContent` text or document text-only residual (validated against real MCP SDK shapes, §11); (b) **transport mechanism** for the out-of-band record — a reserved-sentinel content block the canonicalizer skips, vs the MCP result `_meta`/structured channel if the SDK exposes it through the bridge. Blocks coding.
- **OQ-7 — Layer / hook.** Bridge `call_tool` (this design) vs a Claude Code `PostToolUse` hook shipped in `settings.snippet.json`? Bridge = on-by-default for every user; hook = user-configurable.
- **OQ-8 — Relationship to a10 output-side fix. ⛔ GATE.** This spec + the separate Option-A output neutralization = the full #2 (input) / #4-successor (output) code layer. Cross-reference and reconcile the boundary once Option A is specced. Blocks coding.

**Pre-implementation gate (per Codex):** resolve **OQ-4, OQ-6, OQ-8** (⛔) before writing the bridge hook. OQ-1 is resolved. OQ-2/3/5 start conservative and tune with corpus data.

## 13. References

- [UTS #39: Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/) · [UTS #55: Unicode Source Code Handling](https://www.unicode.org/reports/tr55/) · [UAX #31 / PR-96 (joiners in identifiers)](http://unicode.org/review/pr-96.html)
- [Trojan Source — Boucher & Anderson, arXiv:2111.00169 (CVE-2021-42574)](https://arxiv.org/abs/2111.00169)
- [Bypassing LLM Guardrails — Mindgard/Lancaster, arXiv:2504.11168](https://arxiv.org/abs/2504.11168)
- [AWS: Defending LLM applications against Unicode character smuggling](https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/)
- [Rehberger: Sneaky Bits and ASCII Smuggler (2025)](https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/)
- [CSA: Hidden Unicode Instruction Injection in AI Agent Skills](https://labs.cloudsecurityalliance.org/research/csa-research-note-unicode-instruction-injection-ai-skills-20/)
- [AppCheck: Unicode Normalization Vulnerabilities & the Special-K Polyglot](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- Libraries: Python `unicodedata` (core), `regex`/`unicodedata2` (`\p{}` + current UCD), [`confusable_homoglyphs`](https://pypi.org/project/confusable-homoglyphs/) (flag path), `ftfy` (reference only — mutates).
