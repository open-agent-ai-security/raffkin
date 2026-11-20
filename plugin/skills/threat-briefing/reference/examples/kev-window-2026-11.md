<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example — what should this organisation be watching this month?

A real end-to-end run of `threat-briefing` on 2026-11-19 against a live Exabeam New-Scale tenant. The
analyst answered the skill's opening question in one line: *a cybersecurity / SIEM / SecOps software
company, SaaS and on-prem, B2B, US-based with worldwide customers and worldwide cloud hosting.* Nothing
else was supplied; the default feed and the default 30-day window applied.

It is kept for three things it settled: the KEV file has to be **downloaded and filtered**, not
page-read; a **vendor-only match is not "in our stack"**; and the emailed copy can be **refused by the
roster** even when the analyst is the recipient.

> Tenant identifiers are masked: hosts as `<vcenter-n>`, no users appear. Tool calls, fields and counts
> are real and ran as shown. One write was attempted — the emailed briefing — and the tool refused it;
> nothing else was written.

---

## 0 — The organisation and its stack

Sector, geography and business model from the analyst, above. The stack from the tenant:

- `exabeam_get_use_case_score` (no arguments; 1 MB, spilled) → `datasourceCategories` across the 22 use
  cases name **41 enabled vendors**: CrowdStrike Falcon, Palo Alto NGFW / GlobalProtect / WildFire,
  Zscaler ZIA / ZPA / AI Guard, Cisco (IOS, ISE, Network Security, Web Security), VMware (ESXi, vCenter,
  Horizon), F5 (BIG-IP DNS, NGINX), Okta, Microsoft (Azure AD, Event Viewer family), Google (GCP,
  Workspace, Gemini), GitHub, Proofpoint, Unix / Auditd, Zeek, LogRhythm NetMon, and others.
- `exabeam_parser_list` `{state: "Enabled", type: "Custom"}` → 21 tenant-built parsers (Sysmon, Windows
  Security, Falco, GCP alerts, ZIA DLP, AI-governance JSON, GitHub public-repo alerts).
- `exabeam_context_table_list` → 134 tables, 3 in `Error`.

Reported as **partial**: these are the names the tenant knows, not an asset inventory.

## 1 — Feeds

**CISA KEV.** The first attempt was a page fetch of the JSON. It returned entries in the window and
looked complete — and was not: the file is 1.8 MB and the fetch stopped at 100 KB. The file happens to
run newest first, so the truncated read covered the window by luck, and that is not a method. Second
attempt: `curl` to a scratch directory, then

```python
w = [v for v in d["vulnerabilities"] if "2026-10-20" <= v["dateAdded"] <= "2026-11-19"]
```

under `python3 -I`. Result: `catalogVersion 2026.11.18`, `dateReleased 2026-11-18T19:17Z`, `count 1786`,
**38 entries in the window**, every one with `knownRansomwareCampaignUse: Unknown`.

**CISA alerts index**, two pages (ten items each) to reach 2026-10-20: the KEV-addition notices, one
alert on PHP (2026-10-21), one on Oracle Java CVE-2026-114938 "Java4Shell" (2026-11-17, exploitation
*not* stated, not in KEV), the SafePay advisory AA26-293A at the window's edge (already swept and
assessed — see the companion examples under `intel-sweep` and `detection-coverage`).

## 2 — Candidates

Matched against the 41 vendor names, the 21 parser names and — where a name was absent — a presence
search on the tenant's own rows for the 30 days:

| Entry | Match | How it was established |
|---|---|---|
| CVE-2026-41709 Broadcom VMware ESX | **product** | `product == "VMware ESXi"` → 500 rows in 7 days on `<vcenter-1>`, `<vcenter-2>`: app-login / logout / activity |
| CVE-2026-123158 OpenSSH on Linux | **product** (OS) | Unix Auditd enabled in the use-case payload; `process_name == "java"` rows from Falcon show Linux hosts under EDR |
| CVE-2026-125350 Google Chromium | **product** | `process_name == "chrome.exe"` on Falcon process-create rows |
| CVE-2026-124194 Microsoft Outlook | vendor | Microsoft present as Event Viewer / Azure AD; Proofpoint carries mail; no `OUTLOOK.EXE` row in the 200 checked (cap — not decidable) |
| CVE-2026-111497 Google Brotli | library | NGINX, Node and Chromium are all carriers; a correlation rule *Node Brotli RCE* exists |
| CVE-2026-46300 Linux kernel | vendor (OS) | Unix in stack |
| CVE-2026-76418 Cisco ASA / FTD | vendor | Cisco Network Security enabled; `product:"ASA"` 0 rows in 30 days |
| CVE-2026-20320 Cisco BroadWorks | vendor only | carrier VoIP platform; no row |
| CVE-2026-114938 Oracle Java (alert) | product | `java.exe` and `java` on Falcon process-create rows |
| CVE-2026-109618 / -109619 PHP | none, **but content exists** | correlation rule *PHP memory-corruption RCE*, enabled, never fired |
| CVE-2026-19868 SonicWall SSLVPN | none | 0 rows; SafePay's initial-access vector |
| CVE-2026-118527 / -111357 Ivanti Connect Secure | none | 0 rows |
| CVE-2026-123039 Check Point | none | the `product:("Security Gateway")` search matched *Huawei Unified Security Gateway* — tokenisation; no Check Point row |
| CVE-2026-111560 / -116606 Barracuda | none | 0 rows |
| CVE-2026-97229 GitLab | none (sector) | GitHub is the code host in stack |
| CVE-2026-40217 BerriAI LiteLLM | none (sector) | AI-governance parsers and Zscaler AI Guard exist; an LLM proxy is plausible for the business, not observed |
| CVE-2024-27834 Apple multiple | none (sector) | endpoints likely, not observed by name |

**19 candidates. 19 dropped** — Synology, REDCap, Apache Axis, Puppet Enterprise, UnrealIRCd, Openwave,
GPUStack, FreeSwitch, IBM Aspera, WordPress, Adobe Commerce, Arista VeloCloud, Collabora, SiteGuard,
Plex ×4, Siemens Software Center: no vendor, product or sector match in the observed stack.

## 3 — Techniques and coverage

KEV entries carry no ATT&CK mapping and neither CISA alert did, so every technique below is a **class
inferred from the entry's own description** and marked so. `exabeam_get_mitre_coverage` (93 KB, spilled;
`lastUpdateTimestamp` 2026-11-19T04:36) gave:

| Class | Technique | Rank · value · enabled rules |
|---|---|---|
| unauthenticated RCE on a service | T1190 Exploit Public-Facing Application | Better · 67 · yes |
| authentication bypass | T1078 Valid Accounts · T1133 External Remote Services · T1021 Remote Services | Better 67 · Best 97 · Better 62 (T1021.004 SSH unscored) |
| client-side (browser, mail) | T1203 Exploitation for Client Execution · T1566 Phishing | Best 100 · Best 78 |
| local privilege | T1068 Exploitation for Privilege Escalation | Best 80 |
| logging suppressed | T1685 Disable or Modify Tools (model's current key) | Best 81 |

## 4 — Ranking

Every factor shown; the one that set the band in **bold**.

| Band | Entry · added | Exploited | In stack | Precision | Exposure | Coverage | Why this band |
|---|---|---|---|---|---|---|---|
| **Act** | CVE-2026-41709 VMware ESX · 10-28 (due 11-11, past) | yes | product | exact | internal, admin required | T1685 Best 81 *(inferred)* | **the flaw's effect is a host that stops logging — no rule detects a silent source** |
| **Act** | CVE-2026-123158 OpenSSH · 11-09 | yes | product (OS) | exact | **unknown** | T1078 Better 67, T1133 Best 97 *(inferred)* | exploited, in stack, exposure unknown |
| **Act** | CVE-2026-76418 Cisco ASA/FTD · 10-29 | yes | vendor; **ASA rows absent** | vendor | **internet-facing** | unknown — no source | exploited edge device, no telemetry either way; confirm whether ASA is run |
| Watch | CVE-2026-125350 Chromium · 11-10 | yes | product | exact | user-driven | **T1203 Best 100** | covered |
| Watch | CVE-2026-124194 Outlook · 11-10 | yes | vendor | **vendor only** | user-driven | T1566 Best 78 | vendor-only match, covered |
| Watch | CVE-2026-111497 Brotli · 10-27 | yes | library | carrier only | unknown | **correlation rule exists, never fired** | content named, untested |
| Watch | CVE-2026-46300 Linux kernel · 10-28 | yes | OS | vendor | local | T1068 Best 80 | covered, local |
| Watch | CVE-2026-114938 Java4Shell · alert 11-17 | **not stated** | product | exact | internet-facing JVMs | T1190 Better 67 *(inferred)* | in stack, not yet exploited |
| Watch | CVE-2026-20320 BroadWorks · 11-10 | yes | **vendor only** | vendor | internet-facing | unknown | vendor-only match drops it from Act |
| Note | CVE-2026-109618/9 PHP · 10-26 | yes | no | — | internet-facing | correlation rule exists, never fired | not in stack; content present |
| Note | SonicWall · Ivanti ×2 · Check Point · Barracuda ×2 | yes | no | — | internet-facing | — | edge appliances not in the observed stack; the SafePay link makes SonicWall the one to confirm |
| Note | GitLab · LiteLLM · Apple | yes | no (sector) | — | mixed | — | plausible for a software company, not observed |

Two rules came out of this table and went into the skill: a **vendor-only match drops one band**
(otherwise every Microsoft, Google and Cisco entry would have ranked top), and a **technique the briefing
inferred is marked *inferred***, never shown as if the feed supplied it.

## 5 — The emailed copy

The analyst had said *yes, email me*. The body was built from the tenant reads — the 10-row table above,
the scope line, the defanged source URL — and came to 17,017 characters on the first build with the
tool's mandated inline styles. Three cuts (three columns instead of five, shorter styles, a shorter
narrative) brought it to **7,663**.

`exabeam_send_email` then refused the recipient: the analyst's address **is not a user of this tenant**,
and the refusal returned the subscription's 24-member roster. The skill's rule is to never work around
the roster, so the send stopped there and the analyst was shown the roster to pick from or decline.
Outcome recorded as **not sent**. The briefing is still complete — it is the text above.

## Report, as handed back

**Three items to act on this week, all exploited and all touching products the tenant actually logs:
VMware ESX (CVE-2026-41709, whose effect is a host that stops logging), OpenSSH on Linux
(CVE-2026-123158), and Cisco ASA/FTD (CVE-2026-76418) — the last with no ASA telemetry at all.**

- **Scope.** US-based B2B cybersecurity software company, SaaS and on-prem, worldwide (analyst-stated).
  CISA KEV 2026.11.18 fetched 2026-11-19T09:25Z, 38 entries 2026-10-20 → 2026-11-19; CISA alerts index,
  two pages. Observed stack: 41 enabled vendors, 21 custom parsers (partial). Coverage model
  2026-11-19T04:36. *Ranking reflects detectability and stated exposure; this tool has no asset or
  patch inventory.*
- **Ranked items.** §4, with handoffs: *has it already happened?* → `intel-sweep` on CVE-2026-41709
  (vCenter administrative sessions on `<vcenter-1>`, `<vcenter-2>`) and CVE-2026-123158 (sshd logons on
  Linux hosts); *would we see it?* → `detection-coverage` on T1078, T1133, T1021.004, T1685, T1190;
  detection gaps, proposed not applied: a silent-source alert for the ESXi/vCenter feed, ASA log
  onboarding if the appliance is run, a test fire of the Brotli and PHP correlation rules.
- **Dropped.** 19 of 38 KEV entries: no vendor, product or sector match in the observed stack.
- **Flagged.** none — no feed entry or page read as an instruction.
- **Nothing was written.** One send was attempted on the analyst's yes and refused by the roster; no
  other write.

## What this run changed

- `threat-briefing` SKILL.md: download-and-filter for the KEV JSON (page reads truncate at 100 KB); the
  alerts index is paginated; vendor-only match drops a band; inferred technique classes are marked;
  the roster can refuse the analyst's own address and that is a recorded outcome; the 8,000-character
  body holds about ten three-column rows.
