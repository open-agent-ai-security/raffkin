<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Blocked or succeeded? — the per-vendor verdict map

**What this answers.** When a search returns a hit on an indicator, the next question is *did the
control stop it, or did it go through?* That decides whether a sweep lands in band 2 (targeted,
control held) or band 3 (potential impact), and whether an investigation reads an event as an attempt
or as an outcome. Exabeam's Common Information Model has three fields that look like they answer it —
`action`, `result`, `outcome` — and **none of them is a verdict on its own.** This file is the map
from what each vendor actually writes to what it means, measured against a live tenant, and the rule
for every value that is *not* on the map.

> **Scope of this map.** Every row below was measured on **one** tenant — the parsers it runs, the
> products it ingests, the window that was open. It is a starting vocabulary, not a property of Zscaler
> or Palo Alto in general: another tenant's parser version writes other values, and a product this
> tenant does not ingest is not here at all. Before trusting a row on a different tenant, run the
> exclusion loop in §6 for the vendors that appear in your hits. An unmapped value already fails safe
> (UNDETERMINED, never band 2); the risk of a stale map is a *missed* block that reads as allowed, which
> over-escalates rather than suppresses.

**Measured 2026-11-17** on a production New-Scale tenant, 7-day window (2026-11-10 → 11-17), with
`exabeam_search_events` only. Every value below was observed in a returned row, not inferred. A value
set is marked **complete** when an exclusion loop (§6) returned zero rows after excluding it, and
**partial** when the loop was stopped early.

---

## 1. The three fields, and what each one really is

| Field | What it actually carries | Verdict? |
|---|---|---|
| `action` | The control's own action word, in the control's own vocabulary: Palo Alto `allow`/`deny`/`block-url`, Zscaler Internet Access `Allowed`/`Drop`, Proofpoint `Sent`/`Deferred`, Microsoft 365 `FileDownloaded`/`Blocked`. For audit sources it is an operation name, not a decision (VMware `list-attached-tags`, GitHub `sandbox.create`). | **Yes for enforcement points** (firewall, proxy, mail gateway) once mapped. Meaningless as a verdict for audit/API sources. |
| `result` | A grab-bag. For Cisco and GCP Cloud Armor it is the decision; for Zscaler Private Access it is **session state**; for Proofpoint it is an **SMTP status code** (`2.6.0`, `4.4.1`, `5.4.14`); for CrowdStrike SaaS audit it is the boolean `true`; for Salesforce it is the login failure *reason*; for Windows it is the Keywords bitmask `0x8020000000000000`. | **Only per vendor.** Never read it generically. |
| `outcome` | `success` or `fail`, and nothing else (exclusion loop over all vendors: complete). It is the `:success` / `:fail` suffix of the **parser's event type** — a parser author's decision about whether *the event* succeeded, not whether *the control* blocked. Measured counterexamples: Palo Alto `action:allow` + `outcome:fail` (allowed session, app `incomplete`, ended by `tcp-fin`); ZPA `close` + `outcome:success` where the raw reason is `BRK_MT_SETUP_FAIL_NO_POLICY_FOUND` (that is a *denied* connection); GCP `result:ACCEPT` + `outcome:fail` (Cloud Armor accepted, backend returned HTTP 401/503). | **No.** Useful as a tie-breaker on authentication sources (`endpoint-authentication` / `app-login` fail) and nowhere else. |

**Consequence:** a hit's verdict is `f(vendor, product, activity_type, action, result)`, read off the
table in §3. Where the table says UNDETERMINED, that is the verdict — report it as such.

---

## 2. The verdict classes

| Class | Meaning | Band effect (intel-sweep) |
|---|---|---|
| **BLOCKED** | The control stopped it: dropped, denied, reset, blocked, quarantined, bounced. | Band 2, *if every hit for the entity is BLOCKED* |
| **ALLOWED** | The control let it through, or the action completed. The thing happened. | **Band 3** |
| **STATE** | The value describes session or delivery state, not a decision (`open`, `close`, `active`, `Deferred`, `retry`). | UNDETERMINED until resolved from another field or the raw log |
| **OBSERVED** | The source only watches (alert-only IDS, NetMon, Zeek, audit logs). It cannot block, so "allowed" is the only thing it can mean — but it is not a control holding. | Counts as ALLOWED for banding, say "observed, no enforcement point" in the report |
| **UNDETERMINED** | Value absent, unmapped, or ambiguous. | Never band 2. Report the raw value and that the verdict is unresolved. |

---

## 3. The map

Match is **exact and case-sensitive**, and two Cisco values carry a **trailing space** (`"deny tcp "`,
`"deny "`) that an exact-match filter must include. Vendors are listed by the field that carries the
verdict.

### Read `action`

| Vendor · product | `activity_type` | `action` value | Class | Notes |
|---|---|---|---|---|
| Palo Alto Networks · Palo Alto NGFW | network-session | `allow` | ALLOWED | **Ignore `outcome`** here — 37 of 396 `allow` rows carried `outcome:fail` (app `incomplete`). The session was permitted. |
| | network-session | `deny` | BLOCKED | |
| | network-session | `reset-both` | BLOCKED | |
| | alert-trigger | `reset-server` | BLOCKED | Threat log; the server side was reset. |
| | http-session, alert-trigger | `block-url` | BLOCKED | URL filtering block. |
| | http-session, alert-trigger | `alert` | OBSERVED | Threat/URL log in alert-only mode. Not a block. |
| | — | *(null on network-session rows)* | see `result` → none | Palo Alto writes **no `result`** on session rows; `action` is the only verdict field. Set **complete** (6 values). |
| Zscaler · Zscaler Internet Access | http-session | `Allowed` | ALLOWED | `result` mirrors it (`Allowed`). |
| | network-session | `Allow` | ALLOWED | Firewall log; note the different casing from the proxy log. |
| | network-session | `Drop` | BLOCKED | |
| | http-session | `Blocked` | BLOCKED | `result` is **null** on these rows — a `result`-only query misses every ZIA proxy block. |
| | network-session | `Bypassed due to missing config` | ALLOWED | Traffic that skipped inspection. Treat as allowed *and* flag the gap. Set **complete** (5 values). |
| Proofpoint · Proofpoint Email Protection | email-send / email-receive | `Sent` | ALLOWED | Delivered. `result` is the SMTP code (`2.0.0`, `2.6.0`). |
| | | `accept` | ALLOWED | |
| | | `Deferred` | STATE | Temporary failure (`4.x.x`), will retry. Not blocked, not delivered. |
| | | *(null)* with `result` `5.x.x` | BLOCKED | Permanent rejection; the verdict is in `result` when `action` is empty. |
| | | *(null)* with `result` `retry` / `continue` | STATE | |
| Proofpoint · Targeted Attack Platform | email-send / email-receive | *(null)* with `result` `messagesBlocked` | BLOCKED | TAP writes the verdict to `result`. |
| Microsoft · Microsoft 365 | email-receive | `Blocked` (+ `result` `Phish`) | BLOCKED | `result` is the threat *type*, not the decision. |
| | alert-trigger | `Delivered` (+ `result` `Phish`) | **ALLOWED** | A delivered phish. The canonical "delivery without execution" band-3 promotion: the file arrived. |
| | file-download, app-activity | operation names (`FileDownloaded`, `FileSyncDownloadedFull`, `SearchQueryPerformed`, …) | OBSERVED | Audit operations; the action *is* the thing happening. |
| Unix · Unix | network-traffic | `BLOCK` | BLOCKED | Host firewall. Partial — only `BLOCK` observed. |
| Infoblox · Infoblox NIOS | dns-response | `denied` | BLOCKED | DNS RPZ / policy denial. Partial. |

### Read `result`

| Vendor · product | `activity_type` | `result` value | Class | Notes |
|---|---|---|---|---|
| Cisco · Cisco Network Security | network-traffic | `allow` · `allow all` | ALLOWED | Meraki MX firewall syslog (`pattern: allow all`). |
| | | `deny` · `deny all` · `deny tcp ` *(trailing space)* · `deny ` *(trailing space)* · `blocked` | BLOCKED | Five spellings of one verdict. Filter for all of them. |
| | | `1` · `0` | **UNDETERMINED** | Meraki numeric `pattern: 1 all` / `pattern: 0 all`. Both are parsed `outcome:fail`; the raw rule-number semantics were **not** verified in this run. Do not read as a verdict until confirmed against the Meraki rule table. Seen again 2026-11-23 as `firewall src=… dst=… protocol=tcp sport=… dport=1433 pattern: 1 all`, eight flows in one second across a public /29: a port sweep whose disposition the row does not state. |
| | network-notification | *(null)* | OBSERVED | Set **complete** for the window (9 non-null values). An earlier run (2026-11, different window) also saw `Group Policy Allow` → ALLOWED. |
| Google · Google Cloud Platform (Cloud Armor / HTTP LB) | http-session | `ACCEPT` | ALLOWED | The WAF decision. **`outcome:fail` on an `ACCEPT` row means the backend returned 4xx/5xx** (`http_response_code` 401, 503 observed) — a split outcome inside one event: the edge allowed, the application refused. Report both. |
| | http-session | `DENY` | BLOCKED | |
| | alert-trigger | `Pass` · `Fail` | OBSERVED | Security Command Center finding state, not traffic. |
| | app-activity | `EVENT_RESULT_WARNED` · `EVENT_RESULT_BYPASSED` | STATE | Workspace / DLP event result. Partial set (loop stopped at 200 rows). |
| Zscaler · Zscaler Private Access | network-traffic | `open` · `active` | STATE | Session lifecycle. Not a verdict. |
| | | `close` | STATE → raw log | **The verdict is `InternalReason` in the raw JSON and it is not parsed to any searchable column** (`failure_reason`, `additional_info` both null). Observed: `BRK_MT_SETUP_FAIL_NO_POLICY_FOUND` (denied, no policy matched) carried `outcome:success`; `APP_NOT_REACHABLE` carried `outcome:fail`. To resolve a ZPA hit, pull `rawLogs` for the row and read `InternalReason`. Set **complete** (3 values). |
| Salesforce · Salesforce | app-login | `Success` | ALLOWED | |
| | | `Invalid Password` · `Multi-factor required` · `User is Inactive` · `Failed: InResponseTo Invalid` · `No community access` | BLOCKED | Login refused; the value is the reason. Set **complete** (6 values). |
| CrowdStrike · Falcon (SaaS audit) | app-login / app-logout / app-activity | `true` | OBSERVED | Console audit success flag. Not an EDR verdict. Falcon *detection* events carry the pattern name in `action` (`ModifyServiceBinaryV2`) and no result — EDR disposition is **not yet mapped**. |
| Exabeam · Observra / Agent Sensor | ai_agent-response | `success` | OBSERVED | |
| OpenAI · ChatGPT | app-activity | `SUCCESS` | OBSERVED | |
| Lenel · S2 Netbox | physical_location-access | `Access granted` | ALLOWED | Physical access; the fail variant was not observed in-window. |
| Microsoft · Event Viewer - Security | policy-modify | `0x8020000000000000` (+ `action` `Permit`) | OBSERVED | Windows Keywords bitmask; `0x8020…` = Audit Success. Not a control verdict. |

### Sources with no verdict field at all (observed in-window)

`Squid` (http-session, `outcome` only — `fail` is an HTTP error, not a block), `LogRhythm NetMon`
(network-close), `Zeek`, `F5 NGINX`, `Citrix Gateway / Web App Firewall`, `VMware ESXi / vCenter`,
`GitHub`, `Infoblox BloxOne DDI` (dns-request/response), `Auth0`, `Unix` login/process events. For
these, a hit is **OBSERVED**: the indicator was seen, and nothing in the row says it was stopped.

---

## 4. Rules the sweep and the investigation both follow

1. **Resolve the verdict per row from the table, never from `outcome` alone.** `outcome` is the
   parser's opinion about the event type. It has been measured wrong, in both directions, on three
   enforcement products in one afternoon.
2. **Unmapped means UNDETERMINED, and UNDETERMINED is never band 2.** A value that is not in §3 is
   reported verbatim with the vendor and product, and the entity is treated as *at least* band 2 with
   the verdict unresolved. Say so in the report; do not round it to "blocked".
3. **Band 2 requires every hit for the entity to be BLOCKED.** One ALLOWED or OBSERVED hit on the
   same entity promotes to band 3 — this is the design's "success after the blocks" rule made
   mechanical. The other two promotions are also mechanical: a split verdict across controls
   (BLOCKED at the firewall, ALLOWED at the proxy, or GCP `ACCEPT` + HTTP 2xx after a `DENY`
   elsewhere) is band 3; and an email `Delivered` / `Sent` on an indicator is band 3 even when
   endpoint telemetry shows nothing executed.
4. **Report which field carried the verdict.** "Blocked (Palo Alto `action:deny`)" is checkable;
   "blocked" is not. The same discipline that `search-cookbook.md` asks for on *which IP field
   matched* applies to *which verdict field decided*.
5. **Match exactly, including whitespace and case.** `deny tcp ` ≠ `deny tcp`. `Allow` (ZIA
   firewall) ≠ `Allowed` (ZIA proxy) ≠ `allow` (Palo Alto, Cisco). Build the OR-list from this file;
   do not normalise by lowercasing a filter the engine evaluates verbatim.
6. **A STATE value is a prompt to look at the next field, not a verdict.** ZPA → `rawLogs`
   `InternalReason`. Proofpoint `Deferred` → the later `Sent` or `5.x.x` row for the same message.
   GCP `ACCEPT` → `http_response_code`.
7. **The raw log is the last word, and it is expensive.** `rawLogs` is a valid field and returns the
   original line; pull it with `limit` ≤ 5 on the specific rows that need it, never on the sweep.

---

## 5. Not yet mapped (honest gaps)

- **EDR disposition.** CrowdStrike Falcon detection rows carry a pattern name in `action` and no
  result; whether the sensor *prevented* or only *detected* is not in any column measured here. Hash
  hunting cannot separate band 2 from band 3 until this is resolved.
- **Cisco Meraki numeric patterns** `1` / `0` — semantics unverified (see §3).
- **Vendor inventory is partial.** The three vendor-level exclusion loops (`result`, `action`,
  `outcome`) were each stopped while still returning full pages. Vendors seen only through `outcome`
  (Zeek, Citrix, F5, Squid, LogRhythm, VMware) have no verdict row because they expose none; vendors
  not yet reached by any loop are not in this file at all.
- **GCP `result` set is partial** (loop stopped at 200 rows).
- **Only a 7-day window.** Values a vendor emits rarely (Palo Alto `drop`, `reset-client`, ZIA
  `Quarantined`) may exist and were not observed. Absence from this table is not evidence they do not
  occur — it is a reason to extend the table with the recipe below.

---

## 6. How this was measured, and how to extend it

Server-side aggregation is unusable through the MCP (see the tested-reality note in
`search-cookbook.md`: group-by keys are stripped, pipe queries cap at 7 days). The distinct-value
set per vendor was enumerated with an **exclusion loop**, which is exact and needs no aggregation:

```jsonc
// Round 1 — what values does this vendor write?
{"arg0": {"filter": "vendor:\"Cisco\" AND NOT result:null",
  "fields": ["vendor","product","activity_type","action","result","outcome"],
  "limit": 500, "orderBy": [], "startTime": "<7 days ago>", "endTime": "<now>"}}
// Tally the distinct result values off the rows, then:
// Round 2 — exclude everything seen so far; whatever comes back is new
{"arg0": {"filter": "vendor:\"Cisco\" AND NOT result:null AND NOT result:\"allow\" AND NOT result:\"1\" AND NOT result:\"allow all\"",
  "fields": ["vendor","product","activity_type","action","result","outcome"],
  "limit": 500, "orderBy": [], "startTime": "<7 days ago>", "endTime": "<now>"}}
// Repeat until totalRows is 0. The set is then complete for the window.
```

Three details that matter when extending:

- **Copy values from the rows byte-for-byte**, including trailing spaces, into the exclusion
  filter — an exclusion that trims the space fails to exclude and the loop never converges.
- **A round that returns fewer rows than `limit` is the last round**; everything remaining was in
  it, so the set is complete without a zero-row confirmation.
- **To learn what a value means, pull one raw log**: `"fields": ["result","rawLogs"], "limit": 1`
  on a filter that pins the value. That is how `1` was traced to a Meraki `pattern:` field and ZPA
  `close` to `InternalReason`. Record the meaning here with the date; do not infer it from the word.

To add a vendor: run the loop over `action` and `result` for it, pull a raw log per distinct value,
classify each value in §2 terms, add the rows to §3 with the date, and note whether the set is complete.
