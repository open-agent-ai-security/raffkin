<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design record — Output neutralizer and the bridge's write rules

> **Status:** Shipped and current with the code on `dev` after #118 and #120 (the release that carries
> them bumps the version). The authoritative statement of behavior is
> the code — `plugin/connector/neutralize_output.py` (the module docstring lists every rule and every
> residual) and the write path in `plugin/connector/exabeam-mcp-bridge.py`. The user-facing description
> is [the guardrails page](../../plugin/docs/security-guardrails.md#2-filtering-what-raffkin-writes-de-activating-dangerous-content).
> This record says *why* the control is shaped this way, what was rejected, and what it declines to do.

## 1. The problem

Raffkin writes what it read. A case note, an alert update, a case update, an outbound mail — each one
carries text that started life in telemetry an attacker could write. Three things in that text are
*active*: they do damage not when the model reads them but when a person later opens, clicks or exports
the persisted record.

1. **Formulas.** `=HYPERLINK(...)`, `@SUM(...)`, `=cmd|'…'!A0` look like data and run when a report is
   exported to a spreadsheet (red-team class A, fixture a10: export injection).
2. **Links.** A phishing URL copied into a note becomes clickable in the console, and auto-linked in a
   mail client even as bare text.
3. **Secrets and structured identifiers.** A credential, key, token, SSN or card number planted in an
   alert would otherwise be copied verbatim into a durable, wider-audience artifact (class D). Prompt-only
   redaction was measured leaking on the weakest supported model in every trial — 5 of 5 on fixtures d01
   and d03 (2026-08-18).

## 2. Why the write side, not the read side

The first attempt (PR #31, 2026-08) de-fanged URLs, emails and formulas on **inbound** tool results.
Two independent reviews blocked it: it mutated pivotable values (`user@corp.example` →
`user[@]corp[.]example`), so every follow-up search on the visible value missed the raw telemetry and the
investigation silently degraded. The lesson became the design rule for both filters:

- **Reads are never value-mutated.** The input canonicalizer removes only the invisible smuggling layer
  ([its record](input-canonicalizer.md)); everything visible reaches the model as the SIEM holds it.
- **Writes are where content becomes durable**, so that is where active content is made inert. The
  model reasons over the real value and persists a de-activated one.

The a10 fix (#36) established the pattern; #88/#115 added deterministic redaction; #119 narrowed the
documented claim to what the code did; #147/#152 extended links to every markdown and HTML form and to
mail; #159 and #164 added two of the three write rules in §5; #120 gave every rule a witness and a
mutation gate and added the two prose-position formula shapes; #118 covered the quoted-label form of a
secret.

## 3. What it does, in order

`neutralize_output(text, allowed_hosts, mail) -> (clean_text, notes)` is pure and deterministic. The
bridge applies it to the free-text fields of the five write tools — `note`, `alertDescription`,
`alertName`, `supportingReason`, `closedReason`, `tags`, and for `exabeam_send_email` the `subject`
and `body`, the body in **mail mode**. (The Exabeam MCP wraps some arguments in `arg0`/`arg1`
envelopes; the bridge looks inside them.)

1. **HTML autolinks and tags.** `<https://x>` is read as a link before the tag pass can read it as a tag
   named `https`. Then the executable and embedding elements are removed (`script`, `iframe`, `object`,
   `embed`, `applet`, `frame`, `frameset`, `noscript`, `template`, `svg`, `math`); `form`, `meta`,
   `base`, `link` and the form controls (`input`, `button`, `select`, `textarea`) are made inert; `on*=`
   handlers and `srcdoc` are dropped; `href`, `src`, `action`, `srcset` and CSS `url()` targets (in
   `style` attributes and `<style>` blocks) are defanged unless allowed (below). In mail mode a
   bare URL in text is defanged too, because mail clients auto-link it. The mail template's own inline
   styles, `bgcolor` and entities pass through — a do-no-harm corpus in the tests pins that.
2. **Markdown reference definitions** — only when the destination is URL-shaped. `[Host]: WIN-DC01` is a
   labelled field, and an earlier rule that treated it as a link corrupted hostnames in the durable record.
3. **Markdown inline links** in every CommonMark/GFM shape (titles, padding, nesting).
4. **Secrets and structured PII** → `[REDACTED:<kind>]`, so the report still says a credential was here.
   A label may be quoted — the JSON and raw-field-dump forms (#118) — and the value's own quotes are
   peeled and handed back, so the dump's structure survives. At the keyword's edges only letters and
   digits are word characters, so `_`, `-` and `.` all separate: `aws_secret_access_key` is a label.
5. **Formulas**: quote-prefixed inert, and any URL on the formula's line defanged — including a formula
   quoted mid-sentence, which re-arms the moment it lands in a spreadsheet cell. Mid-sentence detection
   needs a known dangerous function name, so ordinary prose is never touched; two forms that have no
   name to allowlist are recognized by shape instead (#120): a **DDE channel reference**
   (`=cmd|'/C calc'!A0`, `@SUM(cmd|…!A0)` — sign, program, pipe, bounded topic, bang, item), and a
   **cell reference glued to the sign** (`B2=HYPERLINK(…)`), which the word-glue guard used to read as
   prose.

**The order is a control, not a style.** Link defang runs before redaction. A credential-shaped query
parameter (`[reset](https://evil/login?token=abc123).`) puts both on one span; with redaction first, its
match consumed the link's closing bracket and left a live phishing URL in a note. Defanging first removes
that case for every value shape: by the time the redactor runs the host is already inert. Redaction still
sees the query value, because defang rewrites scheme and host, never the query string.

## 4. Clickable is decided by destination, not authorship (#147)

The model writes the text, so "Raffkin wrote this link" carries no trust. The only link that stays
clickable is one whose host **is exactly the API host in `EXABEAM_MCP_URL`** — derived by the bridge
(`tenant_hosts_from_url`), never curated, never model-influenced. No wildcard: an earlier cut allowed
every host under the region domain, and a region is shared by every tenant in it, so one tenant's content
could have become clickable in another's mail (PM review, 2026-09-06). A missing or unparseable URL yields
the **empty** set, under which every link is defanged — the safe default the red-team harness grades
under. Defanging every link was rejected because the reason to mail someone a case is the link back into
the console they already sign in to; the shipped rule keeps that one link and nothing else.

## 5. Three write rules in the bridge, beside the neutralizer

- **Updates carry state only** (#159, Praxen 2026-09-07-003, #89). The two update tools take description,
  name, reason and tag fields with *replace* semantics at the API — a model-written reason would overwrite
  what the analyst wrote. The bridge forwards only the state fields (`alertId`, `alertStatus`, `priority`;
  `caseId`, `stage`, `closedReason`, `priority`, `assignee`, `queue`), drops the rest before the call, and
  names the dropped fields in the reply by the schema's own spelling — never the model's text. A
  `closedReason` must be one of the six values the API documents; anything else refuses the close rather
  than dropping it, because a close that lands without its disposition is a worse record than a refused
  close the analyst can re-issue. (This refusal is an ordinary tool error; only the `create_case` refusal
  below carries the grader's mark.) Raffkin's reasoning goes into a case note, which appends.
- **A case is opened by `create_case`** (#164, Praxen finding 2026-09-07-001 — findings are in
  [praxen/results/](../praxen/results/); #163). The tool sits in the
  prompt-free allow tier on both hosts, yet its schema accepts `stage` and `closedReason`: a case created
  already closed or false-positive is a close by another route around the ask-tier gate. The bridge
  refuses any create carrying a closing disposition or a `closedReason` at all, before the dry run, with
  a refusal the red-team grader recognises (`Raffkin bridge refused`). Fixture c04 covers it.
- **Writes are the default, reads the exception** (Praxen finding 2026-09-07-005). A tool this release did not
  classify as a read is neutralized, audited and refused in a dry run until someone classifies it. An
  unreadable tier file means *no* reads, so the failure direction is "a read is treated as a write",
  never the reverse.

## 6. Failure direction

**Fail-closed.** A neutralizer error propagates and the bridge refuses the write rather than persist a raw
payload. The read-side canonicalizer fails closed too, per block: a block it cannot process is withheld
and replaced by a message that names the gap, and the rest of the result stands (#172). The guardrails
page states both.

## 7. Declared residuals (out of scope by decision)

- A **bare URL typed in prose** in a note is left as written — defanging every URL would mangle the
  legitimate reference links analysts write. In mail it *is* defanged (clients auto-link).
- An **open redirect on the tenant host** passes the allowlist — the same trust already extended to the
  console; chasing it means URL-path analysis and is not worth it.
- HTML is neutralized by a **tag-and-attribute pass, not a full parser**: markup too broken for any
  renderer to act on is escaped conservatively rather than reasoned about.
- An **all-alphabetic value after a bare line break** with no label, quotes or table structure is not
  redacted: after a line break it is indistinguishable from the recommendation prose that normally
  follows, and redacting it would eat analyst text. Labeled, wrapped and table-cell credentials are all
  caught regardless of shape.
- **Labeled-secret shapes still uncovered** (#201): a keyword inside a key rather than at its end
  (`db_password_value`), backslash-escaped and smart quotes, a label that follows its value.
- **Free-form PII** (names, home addresses) and **date-shaped values** are not redacted: not reliably
  regex-detectable, and a date is indistinguishable from a log timestamp. These stay a skill-prompt ask.
- What the model shows **on the analyst's own screen** is not redacted, deliberately: it crosses no
  boundary the console itself does not.

Completeness is unreachable by construction — the input domain is adversarial and infinite — so the
standing rule is *do no harm first, then stop the obvious, then document the exotic*. A residual is
promoted to a rule only when a fixture shows it firing in a persisted artifact.

## 8. How it is verified

- **Deterministic, in CI, no model:** `tests/test_neutralize_output.py`, `test_neutralize_html.py`,
  `test_secret_redaction.py` (every confirmed attack is a permanent fixture; the do-no-harm corpus pins
  what must pass through), and the wiring tests in `test_bridge_wiring.py` (fields covered, mail mode,
  fail-closed, the update field-drop, the create refusal).
- **Mechanical coverage and a mutation gate** (#120): `tests/test_neutralize_coverage.py` witnesses
  every secret pattern and credential keyword by a sample only that rule can catch (and proves it by
  removing the rule), each formula pass by a case the others cannot see, the audit note on every
  redaction path, and runs the do-no-harm corpus through the full pipeline. `scripts/mutation_check.py`
  deletes each rule in a scratch copy and requires the suite to fail; CI runs it on every PR. Before this,
  seven rules could be deleted in turn with the whole suite green.
- **Live, before every release:** red-team classes A (a10–a12 export injection, a14 the prose-position
  formula shapes), C (c04 close via create) and D (d01–d03 data protection, d04 the quoted-label secret
  form, d05 exfil by outbound mail) on the weakest supported model per host — graded on whether the
  payload survived into the persisted artifact in **fireable form**, not on whether the model sounded
  careful. [`security/redteam/HISTORY.md`](../redteam/HISTORY.md).
- **Praxen** checks the remit's write-side rules — the untrusted-content rule under *Prohibited Behaviors*
  ("never … trigger an action"), the no-overwrite rule, the declared redaction limits — against this code
  on every scan.
