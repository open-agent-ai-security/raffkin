<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example — a CISA ransomware advisory swept against a live tenant

A real end-to-end run of `intel-sweep` on 2026-11-19 against a live Exabeam New-Scale tenant, with the
source chosen by the agent because the analyst left the choice open: CISA advisory **AA26-293A,
#StopRansomware: SafePay Ransomware** (published 2026-10-20). It is kept here because the run found the
thing the skill had not yet said: **four of the advisory's nine "intrusion" IP addresses are shared
infrastructure**, and a literal reading of the band table would have offered a case on developers
pulling from GitHub. The rule that now sits in step 5 of the skill came out of this run.

> Identifiers from the tenant are **masked**: internal users as `<developer-n>`, internal addresses as
> `10.x.x.x`, hostnames omitted. The indicators are CISA's, published and public. Every tool call,
> field name and query is real and ran as shown. Counts of `500` are the per-query cap, so they are
> lower bounds, and the sample they return is not spread across the window.

---

## 0 — Intake: the typed indicator list, shown before any search

Fetched with the host's web tool and read as data. Indicators observed by CISA "between November 2024
and August 2026".

| Type | Count | Values (defanged) | Searchable here? |
|---|---|---|---|
| IPv4 | 9 | `104.26.2[.]223` `140.82.114[.]4` `185.199.108[.]133` `77.37.49[.]40` (victim intrusion) · `173.194.194[.]94` (hosting victim data) · `167.235.225[.]149` (client login panels) · `5.255.11[.]134` `37.10.71[.]188` (exfiltration) · `88.119.167[.]239` (`soc.dll` C2) | yes — `src_ip` / `dest_ip` |
| SHA-256 | 6 | `921df888…17eae` (`soc.dll`), `6c1d36df…20a6a`, `e79608cf…dc346`, `327b8b61…67917`, `a0dc80a3…ff526` (`locker.dll`), `bbdd3620…c6f41` (`SharpShares.exe`) | yes — `hash_sha256` (CrowdStrike) |
| SHA-1 | 4 | `07353237…f62b` (`1.exe`), `b498a268…797d`, `bbfed53e…d081` (`locker.dll`), `d711a5af…f7a2` (`nxc`) | yes — `hash_sha1` (Zeek file-read) |
| Hostnames | 4 | `WIN-SBOE3CPNAL` `WIN-3IUUOFVTQAR` `WIN-DK18BI83M0S` `WIN-I1HRRJHCEIV` | yes — `host` / `src_host` / `dest_host` |
| File names | 6 | `soc.dll` `locker.dll` `1.exe` `SharpShares.exe` `ShareFinder.ps1` `nxc` | yes — `file_name` / `process_name`, **exact form only** (see §4) |
| Domains / URLs / emails | 0 | none published | — |
| CVEs | 5 | CVE-2020-3259, CVE-2023-20269 (Cisco ASA), CVE-2023-27532, CVE-2024-40711 (Veeam), CVE-2024-40766 (SonicWall) | routed to visibility + coverage, not searched |
| ATT&CK | 26 | T1133, T1190, T1059(.001/.003), T1569.002, T1098, T1548.002, T1027.002, T1070.004, T1218, T1685 (T1562.001 in older ids), T1110, T1021(.001/.002/.006), T1560(.001/.002), T1048, T1567, T1486, T1490, T1136, T1134.001, T1550.002 | coverage read |

**Flagged in the source:** nothing in the advisory read as an instruction to the agent. The page's
own contact address and `.onion` reference were not treated as indicators.

## 1 — Step zero: the context tables

`exabeam_context_table_list` (spills; 134 tables, 3 in `Error`, 19 healthy but empty). No table named
for SafePay or AA26-293A. The tenant does carry `CISA_AA26-097A_IP_IOCs` (21 items, last updated
2026-08-03) from an earlier advisory, so the loading recipe exists here. `Exabeam Threat Intelligence
IPs` (10,696 items, updated today) is the obvious place these nine might already live — but the
membership form `dest_ip IN "Exabeam Threat Intelligence IPs"` returned `500 Internal Application
error` three times, alone and combined, so **membership could not be checked through this surface**
and is reported as a gap, not as "not present".

## 2 — What was visible

`exabeam_parser_list` `{state: "Enabled", type: "Custom"}` → 21 custom parsers (Annex, OpenClaw, GCP
alerts, Sysmon, Zscaler Internet Access DLP, Falco, S2 Netbox …). The hit rows themselves named the
enforcement and observation points that matter for IPs: Palo Alto NGFW, Zscaler Private Access, Zscaler
Internet Access, CrowdStrike Falcon, LogRhythm NetMon, Zeek. **Partial**, as the skill requires.

Vendor presence for the exploited edge products, last 30 days: `vendor:"SonicWall"` → 0 rows;
`vendor:"Veeam" OR product:("Veeam Backup", "ASA", …)` → 0 rows; `vendor:"Cisco"` → Cisco Network
Security only (web/DNS security, not ASA). **The advisory's initial-access vector is not visible on
this tenant.** That is a scope statement, not a negative.

**Visibility ledger** (added when the ledger became a step, from the same day's `exabeam_get_use_case_score`
read — `datasourceCategories` with `enabled` products; `enabled` is configured, not emitting):

| Stage / indicator type | Category that would carry it | Enabled products | Searched |
|---|---|---|---|
| SSL-VPN entry (SonicWall, Cisco ASA) | `vpn` · `firewall` | 4 · 4 (Citrix Gateway, OpenVPN, GlobalProtect, ZPA; Cisco, Huawei, IPTables, Palo Alto) — **not the advisory's vendors** | IPs yes; vendor rows 0 |
| Veeam exploitation | `backup & recovery` | **none** | not searchable |
| Credential access, account creation | `endpoint auditing` (Windows Security) · `directory service auditing` | 14 · **none** — AD events arrive through Windows Security | techniques → coverage |
| RDP / SMB lateral movement | `endpoint auditing` · `edr` | 14 · 1 (Falcon) | techniques → coverage |
| C2 and hosting IPs | `firewall` · `security services edge` · `network analyzer` | 4 · 3 · 6 | yes |
| Hostnames | `network analyzer` (DNS, Zeek) · `edr` | 6 · 1 | yes |
| Hashes, file names | `edr` · `endpoint auditing` | 1 · 14 | yes |
| Exfiltration (web, FTP) | `security services edge` · `dlp` · `file transfer` | 3 · **none** · 1 | techniques → coverage |
| Impact (shadow copies, encryption) | `edr` · `endpoint auditing` | 1 · 14 | techniques → coverage |

Reading: every stage that carries an *indicator* lands in a category with enabled products, so the
searches below mean something. The one visibility hole is `backup & recovery` — a Veeam exploitation
stage would be invisible here. SonicWall and ASA are **exposure notes** inside present categories: the
tenant can see VPN authentication, just not from the appliances this actor exploits. `directory service
auditing` and `dlp` empty are noted; the former is served by Windows Security on this tenant.

## 3 — The window

Indicator validity November 2024 → August 2026 reaches before retention, so the search ran over what is
retained: **2026-02-19 → 2026-11-19**, in 90-day slices. One nine-month query on five IPs **timed
out**; the same filter in three slices returned in seconds. Retry narrower, never report the timeout.

## 4 — Search, per type

IPs, both directions in one filter, fields including `vendor`, `product`, `activity_type`, `action`,
`result`, `web_domain`, `url`:

```json
{"arg0": {"filter": "dest_ip:(\"104.26.2.223\",\"140.82.114.4\",…) OR src_ip:(\"104.26.2.223\",…)",
          "fields": ["approxLogTime","vendor","product","activity_type","user","src_ip","dest_ip","dest_port","action","result","web_domain","url"],
          "limit": 500, "orderBy": [], "startTime": "2026-08-21T00:00:00Z", "endTime": "2026-11-19T23:59:59Z"}}
```

Both 90-day slices came back at the 500 cap, every row on `140.82.114.4` or `185.199.108.133`. The five
dedicated addresses were then searched **on their own** across all three slices: **0 rows, every
slice.** The two remaining addresses (`104.26.2.223`, `173.194.194.94`) surfaced only once the two
GitHub addresses were excluded.

Hashes: `hash_sha256:(…6 values…)` → 0 rows; `hash_sha1:(…4 values…)` → 0 rows (90 days).
Hostnames: `host:(…) OR src_host:(…) OR dest_host:(…)` → 0 rows.

File names taught a grammar lesson. `file_name:("soc.dll","locker.dll","1.exe","SharpShares.exe","nxc")`
returned 500 rows of Windows Defender delta patches — `1.exe` had matched the token `1` in
`am_delta_patch_1.463.342.0.exe`. The single-`=` form did the same. The field is **tokenised on dots**;
`nxc` matched `__PSScriptPolicyTest_xxxx.nxc.ps1` on 100 hosts. The exact form from the cookbook,
`file_name == "soc.dll" OR …`, returned **0 rows**. Only the exact form counts as a negative.

## 5 — Verdicts, from the map

| Entity | Field matched | Vendor · product · activity | Verdict field → raw value | Class | Tenant's own naming of the address |
|---|---|---|---|---|---|
| `140.82.114[.]4` | `dest_ip` | Zscaler Private Access · network-traffic | `result` → `open` / `close` | STATE | — |
| | `dest_ip` | Palo Alto NGFW · alert-trigger, http-session | `action` → `alert` | OBSERVED | `web_domain` **`github.com`**, `url` `github.com/`, `app` `github-base`, `alert_name` "TLS Encrypted Client Hello Extension Detection", severity informational, rule `Allow_https-to-Internet` |
| | `dest_ip` | Palo Alto NGFW · network-session (May–Aug) | `action` → `allow` | ALLOWED | — |
| | `dest_ip` | Zscaler Internet Access | `action` → `Allowed` / `Allow` | ALLOWED | — |
| | `dest_ip` | LogRhythm NetMon, CrowdStrike Falcon | none | OBSERVED | — |
| `185.199.108[.]133` | `dest_ip` | Palo Alto NGFW · alert-trigger | `action` → `alert` | OBSERVED | `web_domain` **`githubusercontent.com`**, `url` `raw.githubusercontent.com/`, `alert_name` "Modified From ssl To github-base" |
| | `dest_ip` | Palo Alto NGFW · network-session | `action` → `allow` | ALLOWED | — |
| | `dest_ip` | CrowdStrike Falcon, NetMon, ZPA | none / STATE | OBSERVED | — |
| `104.26.2[.]223` | `dest_ip` | Zscaler Internet Access · http-session, network-session | `action` → `Allowed` / `Allow` | ALLOWED | `web_domain` **`axis.readytech.com`**, `app` `ReadyTech`, category Professional Services (a Cloudflare-fronted SaaS) |
| | `src_ip` | CrowdStrike Falcon · network-traffic to `100.64.0.1:60697` | none | OBSERVED | — |
| `173.194.194[.]94` | `dest_ip`, `src_ip` | Zscaler Internet Access `Allowed`; CrowdStrike Falcon | `action` → `Allowed` | ALLOWED | no domain row pulled; the address sits in Google's `173.194.0.0/16` (external knowledge, labelled as such) |
| five dedicated addresses | — | — | — | **no rows, Feb–Nov 2026** | — |

Users on the GitHub rows were ordinary named developers (`<developer-1>` 179 rows, `<developer-2>` 23)
and service traffic on port 22 and 443. Time range of the capped sample: 2026-11-18 19:17 → 2026-11-19
08:56 UTC for the recent slice; 2026-08-20 for the older one.

## 6 — Banding, and where the skill needed a rule

By the band table as it stood, the entity `140.82.114.4` is **band 3**: ALLOWED at Palo Alto and
Zscaler Internet Access, OBSERVED everywhere else. The terminal action would be to show the activity
and offer a case.

The activity, shown plainly, is **developers reaching `github.com` and `raw.githubusercontent.com`**
over HTTPS and SSH, with the firewall's own app-id calling it `github-base`, and a workforce SaaS on a
Cloudflare address. CISA's label "SafePay victim intrusion" on `140.82.114.4` describes a victim's
logs, where an actor pulled tooling from GitHub; it says nothing about this tenant's traffic to the
same anycast address. The advisory label is **not evidence**; the tenant's own `web_domain`, `url` and
`app` fields are.

So the honest read is:

- **Shared infrastructure — not attributable:** `140.82.114.4`, `185.199.108.133`, `104.26.2.223`,
  `173.194.194.94`. Reported under Hits, kept out of bands 2 and 3.
- **Band 1** for the five dedicated addresses, all hashes, all hostnames and the exact file names, with
  the scope above.
- **The case offer:** per the skill's letter it was due on `140.82.114.4`; per the evidence the
  recommendation is **no**. It was put to the analyst as "Open a case on 140.82.114.4 for allowed
  traffic to github.com from named developers? Recommend no — shared infrastructure." The analyst was
  not at the terminal; the offer stands open; **no case was created, no note written, no mail sent.**

The step-5 rule now in the skill ("an IP hit whose own rows name shared infrastructure is not
attributable") is what this run was missing. It is deliberately evidence-bound: the exclusion applies
only when the tenant's own rows name the CDN, code host or SaaS, never on the agent's recollection
that an address "looks like" a CDN.

## 7 — Coverage read, for the negatives

`exabeam_get_mitre_coverage` (spills, 93 KB; `lastUpdateTimestamp` 2026-11-19T04:36). The 26 techniques
split three ways:

- **Covered and quiet (rank Best/Better, `hasEnabledRules: true`):** T1133 (Best 97), T1190 (Better
  67), T1059 (Best 85), T1098 (Better 72), T1218 (Best 97), T1110 (Best 78), T1021 (Better 62), T1048
  (Best 87), T1567 (Best 87), T1486 (Best 100), T1490 (Best 100), T1136 (Best 100).
- **Unscored in the model:** every sub-technique the advisory names — T1059.001, T1059.003, T1569.002,
  T1548.002, T1027.002, T1070.004, T1021.001/.002/.006, T1560.001/.002, T1134.001, T1550.002. The
  `subTechniques` map carries no `score` and no `hasEnabledRules` on any of its 479 entries; the parent's
  score does the work, and `detection-coverage` is the skill that resolves what sits under it.
- **Covered under a renamed key:** the advisory lists *T1685 Disable or Modify Tools*; the model carries
  T1685 (Best 81, `hasEnabledRules: true`) under tactic TA0112 *Defense Impairment*, and the legacy id
  T1562.001 is absent. Resolve both ids before calling anything "not in the model" — the first draft of
  this run called T1685 a typo, and it was the current ATT&CK key.
- **Enabled but unsatisfied:** none of these 26.

## 7b — The behaviour, not the indicators

The indicator search answers "did this actor's infrastructure touch us"; it does not answer "did the
thing this actor does happen here". `exabeam_search_alerts` with `mitres.technique_key:"<id>"` for each
of the 13 parent ids, 2026-02-19 → 2026-11-19, `limit` 100, fields `name`, `priority`,
`creation_timestamp`, `src_host`, `user`:

| Technique | Window answered | Result | Reading |
|---|---|---|---|
| **T1490 Inhibit System Recovery** | nine months **timed out**; 90-day slice answered | **9 alerts, all CRITICAL**, 2026-08-27 → 2026-11-14, one service account, two servers (`<server-1>`, `<server-2>`), every alert name "shadow copy deletion via vssadmin.exe", three of them bundled with host enumeration, permission modification or registry changes | **Observed activity.** The advisory's impact stage, monthly, on servers. Not an indicator hit, not attributable to SafePay — handed to `soc-investigate` |
| T1685 Disable or Modify Tools | 90-day slice | 67: *Disable history collection* on developer workstations, two `setenforce` SELinux disables, two `auditd` disables | Developer behaviour on Linux endpoints; the two SELinux and two auditd rows are the ones worth a look |
| T1486, T1059, T1021, T1098, T1136, T1048, T1567, T1110, T1218, T1133, T1190 | nine months | **100 of 100 each** — `total` caps at `limit`; mostly *Multiple Anomalies* and generic volume rules (*Abnormal number of unique files written*, *Abnormal number of PowerShell executions*, *First successful RDP connection*) | At least 100 each, generic, not attributable. The population is large; it is not evidence either way, and the 100-row sample is the latest eleven hours, not the window |

The T1490 row is what the first draft of this run missed: nine months of empty indicator searches were
reported as the "impacted?" answer while the advisory's own impact behaviour was firing CRITICAL on two
servers. Whether it is a backup job, a misconfigured agent or an intrusion is `soc-investigate`'s
question (the same alerts, from the `detection-coverage` run, are already with it); the sweep's job is
to say it is there.

## Report, as handed back

Written for a manager or a detection engineer; no band numbers, every term defined where it appears.

**Impacted?** No evidence this actor's infrastructure reached the environment: none of the advisory's
attributable indicators — five dedicated IPs, ten hashes, four hostnames, six file names — appears in
nine months of retained telemetry, and the four addresses that did match are the tenant's own traffic
to GitHub, a Cloudflare-fronted SaaS and Google, which is shared infrastructure and not attributable.
**One behaviour the advisory describes was observed:** shadow-copy deletion with `vssadmin.exe` by a
service account on two servers, nine CRITICAL alerts between 2026-08-27 and 2026-11-14, handed to
investigation. Confidence **Medium**: the indicators are valid over 22 months and only nine are
retained here, and the threat-intelligence table could not be checked.

**Positioned to detect?** From the `detection-coverage` run on the same advisory: all 13 parent
techniques are detectable here, 12 scored *Best* or *Better* out of a four-step scale; the content for
seven sub-techniques lives in correlation rules; six sub-techniques have no content; the initial-access
stage (SonicWall, Veeam, Cisco ASA) is not ingested at all; and *Data Encrypted for Impact*'s top score
rests on a single rule.

- **Scope.** Source `hxxps://www.cisa[.]gov/news-events/cybersecurity-advisories/aa26-293a`. Window
  2026-02-19 → 2026-11-19 in 90-day slices (validity reaches before retention). Stack partial: 21 custom
  parsers plus Palo Alto, Zscaler ZPA/ZIA, CrowdStrike, NetMon, Zeek seen on the rows. SonicWall, Veeam,
  Cisco ASA **not ingested** — the exploited products are invisible here. Context tables: no SafePay
  table; TI-table membership unqueryable (server 500).
- **What matched.** Four addresses, all shared infrastructure, each with the field that matched and the
  field that carried the verdict (§5). Not attributable; no case recommended.
- **Behaviour observed.** §7b: nine shadow-copy deletions on two servers under one service account;
  67 Linux tool-disable alerts, mostly developer history-collection toggles; the eleven broad
  techniques at the 100-row cap with generic anomaly rules, not evidence either way.
- **Negatives with scope.** Dedicated IPs, hashes, hostnames, exact file names: no rows; sub-techniques
  unscored in the model (parents carry the score); every parent covered.
- **Recommendations.** (1) `soc-investigate` on the service account and the two servers — the first
  pivot is whether a backup product owns the account. (2) Load the **five dedicated IPs and ten hashes**
  as a context table, key columns `ti_ip_address` / `value`, valid 2024-11-01 → 2026-08-31 — and leave
  the four shared addresses out. (3) Patch exposure on the five CVEs is the vulnerability scanner's
  question; this tenant cannot see those products. (4) Fix the three `Error` context tables found at
  step zero.
- **Flagged.** Nothing in the advisory, the records or the events read as an instruction. The
  advisory's own IOC labels were the thing most likely to mislead, and were treated as data.
- **Visibility ledger.** §2: every indicator-carrying stage has an enabled telemetry category;
  `backup & recovery` has none (a Veeam stage would be invisible); SonicWall and Cisco ASA are
  exposure notes inside present `vpn` / `firewall` categories.

**Terminal action:** the emailed record was offered and not sent (ask tier, analyst absent). No write
of any kind was made to the tenant.

## What this run changed

- `SKILL.md` step 5: the shared-infrastructure rule, and band 3 qualified to *attributable*
  infrastructure.
- `SKILL.md` step 4b: the behavioural check — alerts by technique key, reported as observed activity
  — after this run's first draft answered "impacted?" from indicators alone while the advisory's
  impact stage was firing on two servers.
- `SKILL.md` Output: the two questions first, in plain words, for a reader who has not read the skill.
- `indicator-taxonomy.md`: `file_name` tokenises on dots — use `==` for an exact match; `threat_name`
  is not a field; `IN "<Exabeam TI table>"` fails server-side through the MCP on this tenant.
