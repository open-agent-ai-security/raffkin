<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# The coverage read — turning "no hits" into one of three findings

**What this answers.** A search that returns nothing means one of three different things, and
without the coverage read all three print as "no hits":

| | Finding | What it means | What to say |
|---|---|---|---|
| 1 | **Covered and quiet** | The technique has detection content, enabled, and nothing fired. | A meaningful negative, bounded by the window and the sources. |
| 2 | **Not covered** | The technique is in the model with score `0` / rank `None`, or has no enabled rules. | Absence proves nothing. *That* is the finding. |
| 3 | **Not in the model** | The technique id is absent from the coverage payload entirely. | The platform has no opinion; the SIEM cannot answer for this technique. |

`intel-sweep` runs this read whenever the input is low-specificity (an actor, a technique list, a CVE,
prose with no indicators) and whenever a sweep comes back empty. `detection-coverage` is this read as
a skill in its own right. Both cite this file so the logic lives once.

**Measured 2026-11-17** on a production New-Scale tenant via `exabeam_get_mitre_coverage`. The tool
returns the data behind **Outcomes Navigator** (confirmed by the product team, 2026-11-19), so when the
report tells an analyst where to look in the UI, that is the page.

---

## 1. The payload

`exabeam_get_mitre_coverage` takes **no arguments** and returns one JSON object of roughly 93 KB — it
will spill to a file on every host; read it from the file, do not paste it into the conversation.

```
subscriptionCode        string
lastUpdateTimestamp     "2026-11-17T04:35:40.341"   — when the platform last recomputed coverage
tactics      { "TA0001": { name, externalId, techniques: ["T1078", …], score } … }   12 tactics
techniques   { "T1078":  { name, externalId,
                            score: { value: 0–100, rank: "None" | "Good" | "Better" | "Best" },
                            hasEnabledRules: true | false,
                            subTechniques: [ { name, externalId, score } … ] | null } … }   227 techniques
subTechniques{ "T1071.004": { name, externalId, score } … }   479 sub-techniques (score was null on the ones inspected)
```

Measured distribution (this tenant, this date):

| | count |
|---|---|
| techniques in the model | 227 |
| rank `None` | 114 |
| rank `Good` / `Better` / `Best` | 7 / 17 / 89 |
| `hasEnabledRules: false` | 97 |

**The two flags disagree, in one direction only.** 114 techniques have rank `None` but only 97 have
no enabled rules: **exactly 17 techniques carry `rank: None` with `hasEnabledRules: true`**, and none
carry a rank with no enabled rules. That combination is the signature of **enabled but unsatisfied**
content — detection logic switched on that very likely can never fire because the data source it needs
is not ingested (Outcomes Navigator shows these as unsatisfied rules; the API payload measured here
carries no explicit flag for it, so the inference is from the two fields together). Treat it as its own
gap class, distinct from *not covered*: the fix is a data source, not content. Report both values;
never collapse them into one word. Rank is the platform's scored opinion of detection *quality*;
`hasEnabledRules` is a plain fact about rule state.

---

## 2. The read, step by step

1. **Resolve the input to technique ids.** From an advisory: the techniques it names. From an actor:
   ATT&CK Groups, fetched at runtime — never from model memory (the design validation caught a
   months-stale recollection). From a CVE: the techniques the exploit enables, from the advisory or the
   CVE's ATT&CK mapping where one exists — and say that *exposure to the CVE itself* is a vulnerability
   scanner's question.
2. **Look each id up in `techniques`** (and `subTechniques` for a dotted id). Absent → finding 3, *not
   in the model*.
3. **Read `score.rank`, `score.value` and `hasEnabledRules`.** `hasEnabledRules: false` → finding 2,
   *not covered*. Rank `None` **with** `hasEnabledRules: true` → finding 2 in its *enabled but
   unsatisfied* form: content is on and almost certainly starved of its data source; say so and name the
   source class the technique's rules would need. Otherwise → the technique is covered; a clean search
   is finding 1, *covered and quiet*. Quote all three values every time.
4. **For a covered technique that fired, scope the population and rank within it.** Alerts are
   filterable by `mitres.technique_key`, but broad techniques are useless alone: T1078 "Valid Accounts"
   returned 14 of 15 results attached to benign profiling rules ("First activity on this platform for
   this user"), because nearly every identity-touching rule maps to it. **The technique list scopes the
   population; corroboration across distinct rules on one entity ranks within it.** One rule firing
   once is noise until a second, different rule names the same entity.
5. **Cross-check what feeds the rules.** A rule that is enabled but whose source is not ingested is
   not coverage. Establish the ingested stack from `exabeam_parser_list` with `type: "Custom"` (the
   tenant-built parsers carry `vendor` / `product`) plus context-table names, and **report it as
   partial** — `type: "Default"` does not return through the MCP, and a 500-row event sample found 4
   vendors where the tenant had 81. Never derive the stack from an event sample.
6. **Check the context tables the rules depend on.** A rule keyed on a watchlist that is `Error`, or
   `Healthy` with zero items, is a rule that cannot fire. Nineteen such tables were measured on one
   tenant. Name them.

---

## 3. What this read may and may not conclude

- It answers **"would we see it?"** It never answers **"are we patched?"** or **"are we protected?"**
  A SIEM has no asset inventory, patch state or scanner results. Use the word *detectable*, and when
  the input is a CVE say explicitly that patch exposure is out of scope.
- A rank of `Best` is the platform's score, not a guarantee. Say "scored Best (value 78), 4 enabled
  rules" — checkable — rather than "well covered".
- "Covered and quiet" is bounded by the window searched and the sources ingested. Carry both
  bounds into the sentence that states it.
- Coverage is an **input to relevance**, not an afterthought: "exploited in the wild, in our stack,
  and uncovered" ranks above "exploited, in our stack, scored Best". When a briefing or a sweep ranks,
  the coverage read supplies that factor.

---

## 4. Reading the spilled file

The payload is one line of JSON; slice it with a script, not with a line-oriented reader:

```python
import json
d = json.load(open(path))
if isinstance(d, list): d = json.loads(d[0]["text"])          # some hosts wrap tool output
tech = d["techniques"]
for tid in wanted:
    t = tech.get(tid) or d["subTechniques"].get(tid)
    if t is None:            print(tid, "not in the model")
    else:                    print(tid, t["name"], t["score"]["rank"], round(t["score"]["value"]), "enabled:", t.get("hasEnabledRules"))
```

Record `lastUpdateTimestamp` in the report: it is the date of the coverage opinion, and it may be
older than the sweep.
