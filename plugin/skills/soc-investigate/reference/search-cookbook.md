<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Search cookbook — `exabeam_search_events`

`search_events` is the evidence workhorse, and it is only as good as the query you hand it. This file
is the query craft the skill leans on: the request shape, the filter grammar, the **real field names**
an analyst pivots on, and copy-paste recipes for each step of the investigation loop.

Everything here is grounded in the **live** Exabeam New-Scale API — the `/search/v2/events` request
schema and its own worked examples — and the **Common Information Model** field catalog
([`ExabeamLabs/CIMLibrary` → `Fields_Descriptions.md`](https://github.com/ExabeamLabs/CIMLibrary/blob/main/Fields_Descriptions.md)),
which is the authoritative list of field names for building searches and correlation rules. Use the
exact field names below; **do not invent fields** — if you need one that isn't here, discover it with a
Field Summary query (last section) rather than guessing.

> Names, not shapes, are what break first. If a call fails schema validation, it's almost always the
> `arg0`/`arg1` wrapper (see `tool-map.md`), not the filter — fix the wrapper first.

## The request shape (`SearchDetails`)

`exabeam_search_events` wraps its argument under **`arg0`**. The object is the API's `SearchDetails`:

| Field | Required | What it does |
|---|---|---|
| `filter` | ✅ | The query string (grammar below). May be empty `""` to match everything in the window. |
| `fields` | ✅ | Columns to return. **Always name specific fields.** The tool schema tells you to send `["*"]` (all fields) and to ignore field requests — don't: `["*"]` can return millions of chars in one result and overflow the context window. Name what you need. |
| `startTime` | ✅ | ISO-8601, e.g. `2024-04-01T00:00:00Z`. |
| `endTime` | ✅ | ISO-8601. Keep windows tight — search spans years; a wide window is slow and noisy. |
| `limit` | | Max rows. **Always set it explicitly** (REST default is 3000; the MCP events tool's default isn't documented — `search_alerts` documents 10). Low (25–100) while pivoting, high only when counting. |
| `orderBy` | | e.g. `["time DESC"]`, `["riskScore DESC"]`, `["app ASC"]`. |
| `groupBy` | | Fields to GROUP BY. **REST only — dropped by the MCP tool** (see the tested-reality note). |
| `distinct` | | `true` → DISTINCT on the selected fields. **REST only — dropped by the MCP tool.** |

Minimal call:

```json
{"arg0": {
  "filter": "user:\"jsmith\"",
  "fields": ["time","activity_type","src_host","dest_host","src_ip","result"],
  "startTime": "2024-04-01T00:00:00Z",
  "endTime":   "2024-04-08T00:00:00Z",
  "orderBy":   ["time DESC"],
  "limit": 100
}}
```

Response is `{ rows: [...], totalRows, timeStartedMillis, timeCompletedMillis }`. **`totalRows` is
itself evidence** — "how many times did this happen?" is often the whole triage question.

## Filter grammar (EQL)

The query language is **Exabeam Query Language (EQL)** — the same language the Search UI parses. The
grammar below is confirmed from the [official EQL
docs](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-syntax.html)
and from the live `/search/v2/events` examples; a few forms are additionally shown as they appear in
real in-product queries.

> **Per-endpoint rules — read these before the grammar (#160, measured on 1,000+ live searches).**
> - **`search_alerts` and `search_cases` take NO free text.** Every clause is `field:"value"`, joined with
>   `AND` / `OR`. A bare word, a bare name, or a quoted phrase on its own (`phishing`, `t.novak`,
>   `"svc-backup"`) is rejected with *"Field rawLogs is unknown"* — those endpoints have no raw-log field
>   to search. Name the field: `user:"t.novak"`, `rules.rule_name:"…"`, `stage:"NEW"`, `name:"token"`.
> - **`search_events`: quote everything.** `field:"value"` for a field, `"free text"` (in double quotes)
>   to search raw logs. **Never send bare unquoted text** — `HR-LT-88`, `svc_deploy`, `group membership
>   change` are rejected the moment they carry a hyphen, an underscore, a digit or a second word
>   (*"Field value cannot be a free text"* / *"Please check the syntax"*).
> - **Never send `fields: ["*"]`** (see the request-shape table above). The bridge does not forward a
>   wildcard search: you get the endpoint's column list back as the result, and you re-send naming the
>   columns you need. That stands in for the MCP schema text that wrongly calls the wildcard mandatory,
>   until the MCP server is fixed.
> - **A `"Syntax error while query using fields"` (`AAA_ESA_1003_400`) on a well-formed events query is
>   NOT your filter.** It is a backend failure that affects a whole session from its first search;
>   rewriting the query will not help. Say so in the report and move on to the alerts/cases evidence.

- **Field match:** `field:"value"` — quote the value. `:` and `=` are **interchangeable**
  (`vendor:"Exabeam"` ≡ `vendor="Exabeam"`); Exabeam recommends `=`. Match modes:
  - loose keyword `product:"web application"` (words matched independently),
  - exact keyword `` product="`web application`" `` (backticks),
  - exact full `product=="web application"` (double `==`).
- **Boolean:** `AND`, `OR`, `NOT`, `TO` — upper- or lower-case (uppercase recommended). **Parentheses
  group:** `((subject:"user" OR subject:"app") AND product:"Windows")`.
- **Value sets** (match any of a list — cleaner than chained `OR`): `field:("a","b","c")`. Real example:
  `activity_type:("app-login","authentication-successful","vpn-login","remote-logon")`.
- **Comparisons / ranges** (numeric & date): `>`, `<`, `>=`, `<=`, and inclusive `TO` ranges —
  `num_pages:>50`, `logon_date:[2018-10-31 TO 2018-12-31]`.
- **Wildcards:** `*` (multi-char) and `?` (single) *inside* a value — `subject:"W*b"`. `*` can't stand
  alone; for keyword wildcard matching use `WLD("MiCrO*")` (case-sensitive) / `WLDi("micro*")` (insensitive).
- **Regex:** `field = RGX("<regex>")`. Powerful for threat hunts — e.g.
  `dns_query = RGX(".*katz-stealer\.com.*")`, `file_path = RGX("\\\.library\\-ms$")`.
- **Null / exists:** `field:null` (or `= NULL`); exists = `NOT field:null`. `caseId:null` = "not yet
  triaged into a case" (see Queue sweep).
- **Context-table membership:** the form depends on whether you match the table's **key** field or one
  of its other columns (measured 2026-11 against a live tenant):
  - **Key field — NO qualifier:** `src_ip IN "CISA_AA26-097A_IP_IOCs"`. Adding one fails with **404**
    *"Context table non-key field : &lt;column&gt; not found"* — and it names a column that really does
    exist, so the error reads as a missing field when the *form* is what is wrong.
  - **Non-key column — qualifier required:** `src_ip IN "Admin Users"."IP Address"`,
    `category IN "AI/LLM Proxy Categories"."Key"`.

  Combine with `AND` to intersect tables. **Context-table queries are capped below 90 days**: a longer
  span returns **400** *"Context Table does not support time range queries 90 days or more"*, so hunt a
  long window in sub-90-day slices.
- **Entity-attribute accessor:** `user(<attr>, "<value>")` pins an identity by a specific attribute
  rather than the loose `user:"…"` — `user(username, "gary.hardin")`,
  `user(email, "gary.hardin@ktenergy.com")`. Nested/derived fields use dotted paths:
  `geo_src_ip.country:("ru","kp","ir")`.
- **Aggregation:** `COUNT`/`SUM`/`AVG`/`MIN`/`MAX`, aliased with `AS`. In SQL-style filters the clause
  keywords are **hyphenated**: `GROUP-BY`, `ORDER-BY` (… `ASC`/`DESC`). `COUNT` counts non-null on any
  field; `SUM`/`AVG` need numeric.
- **SQL-style filter** (put the whole query in `filter`; clause order
  `[SELECT] [WHERE] [GROUP-BY] [ORDER-BY] [LIMIT]`):
  `SELECT app, COUNT(*) AS app_count WHERE product:"Audit Log" GROUP-BY app ORDER-BY app_count DESC`.
- **Pipe** `|` chains statements, feeding results forward (**max 5 pipes / 6 statements**):
  `SELECT product, AVG(raw_log_size) AS avgLogSize GROUP-BY product ORDER-BY avgLogSize DESC | avgLogSize > 2000`.
  The API's own examples also show a table-materialize form
  (`SELECT * WHERE … as rt_table | from rt_table WHERE NOT rawLogIds:null`); it appears in the
  `/search/v2/events` examples but not the general EQL UI docs, so treat `from <table>` as
  API-example-sourced rather than broadly documented.

> **Object form vs. SQL form.** Simple filters go in `filter` with `fields`/`orderBy` as object keys
> (below). The EQL aggregation grammar above (SQL-style `SELECT … GROUP-BY …`, `groupBy`, `distinct`) is
> real and valid — but read the tested-reality note next: **through the MCP `search_events` tool it does
> not reach the engine.**

> ⚠️ **Tested reality — aggregation isn't available *through the MCP tool*** (verified against a live
> Exabeam MCP, 2026-06; reproduce by sending any `groupBy` and watching it get dropped). The limitation
> is the **MCP layer, not the API**:
> - The MCP `search_events` tool forwards only `filter`, `fields`, `limit`, `startTime`, `endTime`,
>   `orderBy`. **`groupBy` and `distinct` are silently dropped** — so an object-form aggregate becomes
>   `SELECT col, COUNT(col) …` with no GROUP BY and the engine rejects it: **400** *"select list
>   expression references column(s) which is neither grouped nor aggregated."*
> - A SQL-style `SELECT … GROUP-BY …` placed in `filter` **500s** through the tool as well.
> - **The pipe form reaches the engine but is useless for a breakdown** (measured 2026-11). A filter
>   like `NOT vendor:null | select count(id) as cnt group-by vendor, product` returns **200**, one row
>   per group — but the response carries **only the aggregate column, with the group-by keys stripped**,
>   so 81 groups come back as 81 bare `{"cnt": N}` objects naming nothing. It also requires every
>   referenced column to appear in `fields` (**400** *"Column id not selected in previous query"*), and
>   it is capped below **7** days (**400** *"Pipe Query does not support time range queries 7 days or
>   more"*) — a tighter limit than the 90-day cap on context-table queries. Useful only for a total
>   count you can already attribute; never for discovering *what* the groups are.
> - Plain searches (`filter` + `fields` + `orderBy` + `limit`) work perfectly.
> - **The underlying REST `POST /search/v2/events` *does* support full aggregation** (`groupBy`,
>   `COUNT/SUM/AVG`, `distinct`, SQL-form) — confirmed returning correct counts when called directly.
>   The gap is only in what the MCP tool forwards.
>
> **So, through this skill (which uses the MCP tool): don't aggregate server-side — run the targeted
> filter and read `totalRows`, then break down by pulling the rows and counting client-side.** The
> recipes below use that pattern. (If your integration can call the REST endpoint directly, the
> aggregation grammar above works there as written.)
>
> **Coming:** MCP-side aggregation support (forwarding `groupBy`/`distinct` through the search tool) is
> **planned but blocked on an MCP-server change**. Once it ships, the aggregation grammar documented
> above will work through the skill directly and these recipes can use server-side `groupBy` instead of
> client-side counting. Until then, the `totalRows`/client-side pattern is the supported path.

## Field vocabulary (what to pivot on)

Canonical CIM names. These are the ones triage actually turns on — filter and `fields` both use them.

**Identity / user**
`user` (the actor) · `src_user` (initiator) · `dest_user` (target) · `account`, `account_name`
(the account operated on) · `domain`, `src_domain`, `dest_domain` · `email_address` · `sender`,
`recipient` (mail).

**Host / network**
`host` (machine that logged it — hostname *or* IP) · `src_host`, `dest_host` · `src_ip`, `dest_ip` ·
`src_port`, `dest_port` · `url` · `user_agent` · `country`, `city`, `src_location` (geo).

**Process / endpoint**
`process` (path) · `process_name` · `process_id` (PID) · `parent_process` · `command` · `file_hash`.

**Auth / outcome**
`auth_method` · `logon_type` · `mfa` · `action` (allowed/blocked/quarantined…) · `result` · `outcome`.

> ⚠️ **`result` is NOT normalised across vendors — never read it as a verdict without a per-vendor
> map.** Measured in a single query, 2026-11: Zscaler Internet Access returns `Allowed`; Zscaler
> **Private** Access returns `open` / `close` / `active`, which is session *state* and not a verdict
> (`close` does **not** mean blocked); Cisco Network Security returns `allow`, `allow all`,
> `Group Policy Allow` and bare `1`; Palo Alto NGFW omits the field entirely on `network-session` rows.
> Deciding "was this blocked or did it succeed?" needs the vendor's own vocabulary, and for some
> vendors needs `activity_type` instead. `result` is also missing from the MCP tool's documented field
> list while being perfectly valid in `fields`. **The measured per-vendor map — which field carries the
> verdict for each product, every value seen, and the rule for values not on it — is
> `reference/result-normalization.md`. Read a hit's blocked/succeeded status from that file, never from
> `outcome`, which is the parser's event-type suffix and was measured wrong on three enforcement products.**

**Event classification**
`activity_type` · `activity` · `app` · `product` · `vendor` · `platform` · `time`.
Real `activity_type` values seen live include `authentication-successful`, `vpn-login`,
`endpoint-login`, `password-checkout` (CyberArk PAM), `process-create`, `http-session`, `app-login`,
`remote-logon`, and `rule-trigger` (the Analytics detections). Confirm exact values per data source —
detections also key on entity-id fields like `source_user_entity_id` (`"UAN<user>@<domain>"`).

> **Raw events behind an AA detection.** Analytics rule-triggers ride the same index as raw logs. To
> read the *raw* activity a detection keyed on (not the trigger itself), exclude the analytics product —
> real detections do this: `… AND NOT (product:"NG Analytics" AND activity_type:"rule-trigger")`.

**Analytics (Exabeam AA rule-trigger events)** — how you see *why* a risk score moved:
`rule`, `rule_reason`, `original_risk_score`, `rawLogIds` (the raw logs behind the trigger).

## Recipes — mapped to the investigation loop

### Step 2 — baseline: "is this normal for this entity?"
There is no entity-lookup tool; you baseline with search. Since server-side aggregation is unreliable
(above), pull the entity's recent rows and count/cluster them yourself.

```jsonc
// What does jsmith normally do? Pull a wide sample; read the activity_type spread client-side.
{"arg0": {"filter": "user:\"jsmith\"",
  "fields": ["time","activity_type","src_ip","dest_host","result"],
  "orderBy": ["time DESC"], "startTime": "<t-7d>", "endTime": "<t>", "limit": 1000}}

// Baseline sign-in origins: pull auth events over 30d and eyeball the src_ip / country set.
{"arg0": {"filter": "user:\"jsmith\" AND activity_type:\"authentication-successful\"",
  "fields": ["time","src_ip","geo_src_ip.country"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 1000}}

// Cheap "does it ever happen?" check — read totalRows, not the rows.
{"arg0": {"filter": "user:\"jsmith\" AND geo_src_ip.country:\"ru\"",
  "fields": ["time"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 1}}
```

A country/IP that appears for the first time in the alert window, against a 30-day baseline where
`totalRows` is 0, is a real signal. A country the user hits weekly is not. **`totalRows` is the count**
— you don't need aggregation to answer "how many / ever?"

### Step 3 — pivot the entity chain (user → host → IP → process)
Each answer feeds the next filter.

```jsonc
// User's activity in the alert window — the spine of the timeline
{"arg0": {"filter": "user:\"jsmith\"",
  "fields": ["time","activity_type","src_host","dest_host","src_ip","dest_ip","result"],
  "orderBy": ["time DESC"], "startTime": "<alert-start>", "endTime": "<alert-end>", "limit": 200}}

// Everything on the host the alert named (who else touched it?)
{"arg0": {"filter": "(src_host:\"FIN-LT-014\" OR dest_host:\"FIN-LT-014\")",
  "fields": ["time","user","activity_type","process_name","dest_ip"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}

// What ran on the host (process/endpoint view)
{"arg0": {"filter": "host:\"FIN-LT-014\" AND NOT process_name:null",
  "fields": ["time","user","process_name","parent_process","command","file_hash"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}

// Fan-out from an IP (who else, what destinations)
{"arg0": {"filter": "src_ip:\"203.0.113.7\"",
  "fields": ["time","user","dest_host","dest_ip","dest_port","action"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}
```

### Step 3 — see *why* a rule/model fired (the fastest FP/TP tell)
For Exabeam Advanced Analytics risk, go straight to the rule-trigger events and their raw logs — it
often decides the verdict before any correlation-rule reading.

```jsonc
{"arg0": {"filter": "activity_type:\"rule-trigger\" AND platform:\"Exabeam AA\" AND user:\"jsmith\"",
  "fields": ["time","rule","rule_reason","original_risk_score","rawLogIds"],
  "orderBy": ["original_risk_score DESC"],
  "startTime": "<alert-start>", "endTime": "<alert-end>", "limit": 50}}
```

`rule_reason` is the model's own explanation; `rawLogIds` links to the underlying logs to corroborate
(or debunk) it. A high score built entirely on one noisy rule is an FP hypothesis, not a verdict.

### Auth-failure / brute-force shape
```jsonc
{"arg0": {"filter": "dest_user:\"jsmith\" AND activity_type:\"authentication\" AND result:\"failed\"",
  "fields": ["time","src_ip","auth_method","logon_type","result"],
  "orderBy": ["time DESC"], "startTime": "<t-6h>", "endTime": "<t>", "limit": 500}}
```
Then tell spray from a single fat-fingered client: pull the failed attempts and count `src_ip`
client-side (server-side `groupBy` is unreliable). `totalRows` gives the volume; the rows give the
spread of sources:
```jsonc
{"arg0": {"filter": "dest_user:\"jsmith\" AND result:\"failed\"",
  "fields": ["time","src_ip","auth_method"],
  "orderBy": ["time DESC"], "startTime": "<t-6h>", "endTime": "<t>", "limit": 1000}}
```

### Watchlist / allowlist test (context tables)
```jsonc
// Is the source IP cataloged in a watchlist context table? (column qualifier is required)
{"arg0": {"filter": "src_ip IN \"Threat Intel IPs\".\"IP Address\"",
  "fields": ["time","user","src_ip","dest_host","action"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 100}}
```
Use `exabeam_context_table_list` to find the exact table **and column** names; membership via `IN`
beats hand-listing values and keeps the query honest as the table changes.

### Threat hunting (regex, geo, value-sets)
When you're hunting a known TTP rather than triaging one alert, EQL's `RGX()`, dotted geo fields, and
value-sets do the heavy lifting (patterns below are real in-product query shapes):

```jsonc
// Malicious-domain beaconing across all DNS (regex over dns_query)
{"arg0": {"filter": "(dns_query = RGX(\".*katz-stealer\\.com.*\") OR dns_query = RGX(\".*twist2katz\\.com.*\"))",
  "fields": ["time","user","src_host","dns_query"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 500}}

// Logins from sanctioned/high-risk geographies (dotted geo field + value-set + activity value-set)
{"arg0": {"filter": "geo_src_ip.country:(\"ru\",\"kp\",\"ir\",\"sy\",\"cu\") AND activity_type:(\"app-login\",\"authentication-successful\",\"vpn-login\",\"remote-logon\")",
  "fields": ["time","user","src_ip","geo_src_ip.country","activity_type","result"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 500}}

// Rare-process hunt (regex on process_name)
{"arg0": {"filter": "process_name = RGX(\".*(mimikatz|psexec|rundll32).*\")",
  "fields": ["time","user","host","process_name","parent_process","command"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 200}}
```
> **Regex escaping:** the `RGX("…")` argument is a regex; when it rides inside the JSON `filter`
> string, every backslash must be JSON-escaped (`\.` → `\\.`). For Windows-path patterns
> (`\\host\share`, `.library-ms`) the backslashes stack up fast — build and test the pattern in the
> Search UI first, then escape it for the API call.

## Queue sweep & reporting

**Untriaged alerts** — this is an *alert* search, not events, but it's the queue-sweep entry point
(`exabeam_search_alerts`, same `SearchDetails` shape; real alert fields:
`alertId, alertName, caseId, caseNumber, creationTimestamp, mitres, priority, product, riskScore,
rules, tags, useCases, user, vendor`). **Verified live** — this exact query returns real alerts:

```jsonc
{"arg0": {"filter": "caseId:null",
  "fields": ["alertId","alertName","priority","riskScore","user","mitres","rules","creationTimestamp"],
  "orderBy": ["riskScore DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 500}}
```
`caseId:null` = alerts not yet pulled into a case. Order by `riskScore DESC`, then cluster by
`user`/`rules` **client-side** and prioritize — remember (per SKILL Modes) a sweep *prioritizes*, it
does not *conclude*.

**"What's in this data?" / field discovery** — orient before you filter. Server-side aggregation is
unreliable (see the tested-reality note), so pull a recent sample and read the `product`/`activity_type`
spread off the rows.

> ⚠️ **A time-ordered sample under-reports the estate badly.** Measured 2026-11: a 500-row
> `approxLogTime DESC` sample surfaced **4 distinct vendors where the aggregate counted 81 groups** —
> the highest-volume sources crowd out everything else, and an `IN`-style hunt later turned up Palo
> Alto, Cisco, LogRhythm and Zscaler Private Access that the sample never showed. Use this recipe to
> see *what a busy source looks like*, **never as an inventory of what is ingested**. For a real source
> inventory read `parser_list` with `type: "Custom"` (the tenant's own parsers, each carrying `vendor`
> and `product`) plus the context-table names — and still report the list as partial.

The sample query:

```jsonc
{"arg0": {"filter": "",
  "fields": ["time","product","vendor","activity_type"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}
```
Requested fields that are empty are simply omitted from a row — so a field that never appears across a
healthy sample is either unpopulated in this data or misspelled. Confirm exact field values in the
Search UI when in doubt rather than guessing.

**Reporting caution** (per SKILL Modes): counts *amplify* data-quality artifacts. A number that alarms
mainly by its size is a noise hypothesis before it's a scale story — verify the underlying rows before
it goes in a brief. (And since you're counting client-side from a capped `limit`, note when a count is
a floor, not a total: `totalRows` is the true count even when you only pulled `limit` rows.)

## Quality bar for a query

- **Tight window.** Start narrow (the alert window ± hours); widen only with a reason.
- **Named fields over `*`** — skimmable evidence, cheaper calls (the bridge does not forward a wildcard search).
- **Count with `totalRows`, not aggregation.** A targeted filter + `totalRows` turns "I saw some" into a
  number — and it works through the MCP tool, which drops `groupBy`/`distinct` (see tested-reality note).
- **Cite it.** Every row that lands in the report names the query/tool that produced it (report-template).
