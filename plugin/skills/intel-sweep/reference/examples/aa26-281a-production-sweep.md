<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example — a 515-address advisory swept against a production tenant in 30-day chunks

This is a real run of `intel-sweep` against a live **production** tenant on 2026-11-21 to 2026-11-23, on
CISA **AA26-281A — Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking
Tools to Steal Sensitive Data** (published 2026-10-08). It is kept here for three reasons the SafePay
example could not show: the indicator set is large (515 IPv4, 218 domains, 32 MD5, 32 SHA-256, 26 tool
names), the tenant has real volume, and the run produced the **30-day chunk rule**, the **tool-match**
reading and the **stale, shared** reading now in the skill. Entity names, hostnames and the tenant's own
address ranges are masked. Nothing was written to the tenant: 337 read calls, 0 writes.

## 0 — Intake

The advisory page was fetched and read as data. Indicators came from its Appendix A tables: Table 10
domains with first/last-seen, Table 11 IP addresses with first/last-seen, Table 14 "leveraged binaries
and scripts" (hashes and names, undated), Table 15 "potentially dropped files". Fifteen ATT&CK ids as
printed (two parents, thirteen sub-techniques) resolve to eleven parents. Eight CVEs were listed as
out of scope for the sweep: exposure is the scanner's question.

Two things in the source needed a rule. **80 of 218 domains carried a starred last-seen** that the
appendix defines as the WHOIS registry expiration date (2026–2027): a registration claim, not an
observation, so it does not extend the window. **Every IP's last-seen was on or before 2025-06-20**,
most in 2021 to 2024, so only the final five months of the 22-month span this run searched overlap any IP's
validity. Both facts went into the scope line before a search ran.

**Flagged in the source:** nothing read as an instruction to the agent.

## 1 — The window, and what it cost to get wrong

**The window was the run's biggest mistake, and the reason this example exists.** The skill's rule at
the time was "indicator validity intersected with retention". With indicators dated back to 2021 that
meant every day the tenant kept: **2025-02-01 → 2026-11-22, 22 months, 22 chunks × 15 field groups, 330
production BigQuery scans over three hours**, run without the figure ever being said to the analyst.
When it was — *22 months?!* — the rule was withdrawn on the spot and replaced by the one now at the top
of step 3: **a 30-day window by default, 90 when the notice gives a dated reason, anything earlier only
as an analyst-approved window of 30 to 90 days at a stated period, and a flat refusal to search all
retained data or to derive a window from retention or validity.** The behavioural check, begun over the
same 22 months, was stopped by the analyst after its first 90-day window. Nothing below should be read
as a method; the 30-day chunks were the right size for a call, and the wrong number of them.

The first search attempt had already shown the other half of the problem. It followed the rule of the
time — *whole window in one call, slice on timeout* — and sent eight whole-window searches in parallel.
**All eight timed out and the hosted connector then refused every call with `403 mcp_request_blocked`**,
including a one-row probe, until the analyst reconnected it. A 90-day call answered sometimes; 30-day
calls answered every time.

Three more budget rules came out of the same hour:

- **One value-list field per filter.** `hash_sha256:(…32…) OR hash_md5:(…32…)` timed out on a 30-day
  chunk where each list alone answered in seconds.
- **Do not merge lists to save calls.** Two 130-address IP lists joined into one 258-address clause
  timed out; the originals answered.
- **Two calls in flight, not four.** Four at once produced two timeouts; a pair answered every time, 330
  chunk × group calls in a row with two chunk timeouts, both fine on retry alone.

Fifteen field groups per chunk: `web_domain` (two lists), `dns_query` (two), `hash_sha256`,
`hash_md5`, `file_name == "x" OR process_name == "x"` (26 names), and the 515 addresses split four ways
against `dest_ip` and again against `src_ip`. Every call was appended to a ledger as it returned; every
response with rows was written to a file. That discipline paid for itself: after the last chunk the
connector blocked again, and the report was built from the files.

## 2 — What matched

**Domains: nothing.** 218 domains, both fields, all 22 chunks, zero rows. `web_domain` and `dns_query`
both carry values on this tenant, so this is a real negative for the span the run searched.

**MD5: nothing. SHA-256: one.** The hash the advisory gives for `wpscan` was written to one user's
endpoint (CrowdStrike Falcon `file-write`) on 2025-06-16, alongside a second write of a file by the same
name with a different hash. Eleven months later the same user wrote `wpscan` twice more, by `bsdtar` and
`ruby`: the shape of a gem install of the public WordPress scanner.

**Names: two more tools from the actor's kit.** `secretsdump.py` — Impacket's credential dumper —
deleted twice by one user in February 2025 and written by `cp` on that user's endpoint and a second
user's in February 2026, two hashes, neither the advisory's. `sqlmap.py` opened once in Microsoft 365
(`FileAccessed`, 2025-05-17) with no user or host on the row. Twenty-three other names, fscan and
JuicyPotato and the web shells among them, returned nothing.

**IP addresses: seven of 515, every one stale.** The table is what the run reported, with the owner
from the regional registry and the advisory's own last-seen beside the tenant's date.

| Indicator | Advisory last seen | Seen here | Tenant's own rows | Owner |
|---|---|---|---|---|
| 138.199.62.148 | 2024-12-14 | 2026-11-16 | one successful login to the customer community portal (Salesforce) by an external portal user | Datacamp / CDNEXT, Hong Kong |
| 156.146.45.194 | 2024-09-19 | 2026-09-17 | 7 inbound sessions denied (Palo Alto NGFW); 12 Meraki flows to three public /24s, verdict `pattern: 1` unmapped | Datacamp / CDNEXT, Hong Kong |
| 89.187.163.216 | 2024-09-19 | 2025-10-21, 2025-11-11 | 6 HTTP responses from a Cloudflare-fronted public site | CDN77, Singapore |
| 119.13.79.145 | 2023-03-21 | 2026-05-17/18 | 3 inbound sessions denied (Palo Alto NGFW) | Huawei Cloud, Hong Kong |
| 120.36.255.105 | 2021-11-01 | 2025-06-17 | 8 Meraki flows in one second to all eight addresses of a public /29, every one to TCP 1433; raw `pattern: 1 all` | China Telecom Fujian |
| 125.229.172.48 | 2024-05-23 | 2025-06-11 | 1 Meraki flow to the same /29, same verdict value | Chunghwa Telecom, Taiwan |
| 167.172.33.16 | 2023-04-14 | 2026-05-24 | one `GET /` to an internal NGINX host, answered HTTP 400 | DigitalOcean |

The NGINX row is a parser finding: the client address sat in `dest_ip`, and only the raw access log
showed the direction. The taxonomy now says to search NGINX against both fields.

## 3 — Verdicts, and two readings the skill did not have

The map in `result-normalization.md` classed the Palo Alto rows BLOCKED and the Meraki `1` rows
UNDETERMINED, as it should: the raw `pattern: 1 all` was pulled on two rows and still does not state a
disposition. The Cloudflare and Salesforce rows are OBSERVED; the NGINX 400 is the application
refusing, not a control.

None of that decides anything, because of the dates. Twelve to forty-three months separate each match
from the advisory's own last sighting of the address, and the registry puts four of seven in commercial
hosting that consumer VPN services exit through and three in national carrier space. The shared-
infrastructure rule the SafePay run produced covered addresses whose own rows name a CDN or code host; it
did not cover an address that is simply *old* and *reassigned*. The skill now reads both the same way:
**stale, shared — not attributable**, outside the bands, no "hit".

The wpscan hash was the harder call. An exact SHA-256 match on an advisory hash is what band 3 is
written for. But the file is the public release of an open-source scanner, which the advisory lists
because the actor uses it, and so does every web application tester. The match proves the tool was on
that endpoint on that day; it says nothing about who ran it or why. The skill now carries a heading for
this — *tools from the actor's kit on staff endpoints* — reported with user, host, `activity_type` and
dates, outside the bands, and handed to `soc-investigate` with the first question already written:
*does this user have a reason to run it?*

## 4 — Behaviour, not indicators

The behavioural check ran as alerts by parent technique and was stopped by the analyst after the first
90-day window, which is all the published report uses. Its result is summarised there and is not
repeated here; the pattern it showed is the one the SafePay run also
showed — the broad techniques (Command and Scripting Interpreter, External Remote Services, Drive-by)
return at least 100 alerts per window from generic profiling rules and are not evidence of this actor,
and the narrow ones are where a human looks.

## Report, as handed back

**Impacted?** No evidence that this actor's activity reached the environment. No match is attributable
to the actor. Seven of 515 addresses matched, each a year or more after the advisory last saw it and
all in shared or carrier space, all inbound and denied, undetermined or refused. The domains never
appeared. Three open-source tools the advisory lists in the actor's kit were found on staff endpoints,
one by exact hash: present, owner's reason unknown, handed to investigation. **Confidence: Medium** —
most IP indicators stopped being observed before the span this run searched, which was itself far wider
than the skill now allows.

**Positioned to detect?** Deferred to the `detection-coverage` run of 2026-11-19 on the same advisory,
linked rather than repeated: nine of eleven parents detectable, Active Scanning not covered, Automated
Exfiltration enabled with no telemetry.

**Terminal action:** none offered. No band-3 entity existed. Separately, and on the analyst's
instruction, the threat-briefing of 2026-11-19 was sent to two roster members from the same tenant:
the first measured send (`recipients: []` returns the roster without sending; a partial name is rejected;
success returns a `messageId`).

## What this run changed

Step 3, rewritten: a 30-day window, 90 with a dated reason, analyst-approved 30-to-90-day windows
beyond that, and a refusal to search all retained data or to reason from retention at all. The query
budget: 30-day calls, one value-list field per filter, two calls in flight, ledger and hit files written
as they arrive because the connector can block after a long run. Step 5: the tool-match and stale-shared readings. The taxonomy: NGINX client
in `dest_ip`. The normalization reference: the raw Meraki row. `threat-briefing` and the tool map: the
measured send path.
