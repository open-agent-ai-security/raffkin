<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example — would this tenant detect SafePay's tradecraft?

A real end-to-end run of `detection-coverage` on 2026-11-19 against a live Exabeam New-Scale tenant,
taking as input the technique set CISA published in advisory **AA26-293A, #StopRansomware: SafePay
Ransomware** (2026-10-20). It followed the `intel-sweep` run on the same advisory
(`../../../intel-sweep/reference/examples/safepay-advisory-sweep.md`), which answered *has it already
happened* — this run answers *would we see it*.

It is kept because it found two things the coverage model does not say on its face: **sub-techniques
are unscored**, not "not covered", and the content for several of them lives in correlation rules the
model never mentions; and the model's **Best 100** on *Data Encrypted for Impact* rests on a single
behavioural rule plus a vendor correlation that last fired in March 2025.

> Identifiers from the tenant are **masked**: hosts as `<server-n>` / `<workstation-n>`, accounts as
> roles. Rule names are the platform's shipped content names and are shown as returned. Every tool call
> and field is real and ran as shown. No write of any kind was made.

---

## 0 — Scope

*Would this tenant detect SafePay's current tradecraft — resolved to 26 technique ids from CISA
AA26-293A, published 2026-10-20?* The advisory also names five CVEs (Cisco ASA, Veeam, SonicWall);
patch exposure is out of scope, and only the techniques an exploit enables are assessed.

## 1 — Techniques, as the source gives them

13 parents: T1133, T1190, T1059, T1098, T1218, T1685, T1110, T1021, T1048, T1567, T1486, T1490, T1136.
13 sub-techniques: T1059.001, T1059.003, T1569.002, T1548.002, T1027.002, T1070.004, T1021.001,
T1021.002, T1021.006, T1560.001, T1560.002, T1134.001, T1550.002. Source and date recorded; T1685 is
the current key for *Disable or Modify Tools* (legacy T1562.001).

## 2 — The coverage model

`exabeam_get_mitre_coverage` (no arguments; 93 KB, spilled; `lastUpdateTimestamp` 2026-11-19T04:36).
Read from the file with the snippet in `reference/coverage-read.md` §4.

| Class | Techniques |
|---|---|
| **Covered** (rank, value, `hasEnabledRules`) | T1133 Best 97 ✓ · T1190 Better 67 ✓ · T1059 Best 85 ✓ · T1098 Better 72 ✓ · T1218 Best 97 ✓ · T1685 Best 81 ✓ · T1110 Best 78 ✓ · T1021 Better 62 ✓ · T1048 Best 87 ✓ · T1567 Best 87 ✓ · T1486 Best 100 ✓ · T1490 Best 100 ✓ · T1136 Best 100 ✓ |
| **Enabled but unsatisfied** (rank None + `hasEnabledRules: true`) | none of the 26 (17 such techniques exist elsewhere on the tenant) |
| **Not covered** (`hasEnabledRules: false`) | none of the 13 parents |
| **Unscored** (present in `subTechniques`, `score: null`, no flag) | all 13 sub-techniques — true of every one of the map's 479 entries |
| **Not in the model** | T1562.001 (legacy id; T1685 is present) |

The first draft of this run classified the sub-techniques "not covered" because `rank` was None and
`hasEnabledRules` was None. That is wrong: the payload does not score dotted ids at all. The honest
class is *unscored*, and the question moves to step 3.

## 3 — The rules, by name

`exabeam_analytics_rule_list` `{filter: "isEnabled=true", limit: 1000}` → 951 rules, `hasNext: false`,
all `state: Active`; 717 carry `mitre[].techniqueKey`. `exabeam_correlation_rule_list` `{limit: 500}` →
308 rules, 260 enabled; the technique id appears only in `name`, beside `enabled`, `timesTriggered`
and `lastTriggeredAt`. `exabeam_get_use_case_score` (1 MB, spilled) → 22 use cases with `score` and
per-vendor `datasourceCategories`.

| Technique | Analytics rules mapped (all enabled) | Correlation rules naming it (enabled · fires · last) | Use case |
|---|---|---|---|
| T1133 External Remote Services | 33 — VPN session, failed-VPN-login and VPN-upload profiles | — | Compromised Credentials Best 81 |
| T1190 Exploit Public-Facing App | 4 — shell user-agent, one CVE signature, first externally-initiated connection to port (endpoint / zone) | 2 — Node Brotli RCE, PHP memory-corruption RCE · 0 · never | — |
| T1059 Command & Scripting | 45 — `certutil`/`bitsadmin`/`mshta`/`rundll32` spawned-by-shell family | T1059.001 ×4 (malicious PowerShell, RSAT install/usage, script as service) · 0 · never; T1059.003 RSAT execution · 151 · 2026-10-12 | Malware Best 88 |
| T1098 Account Manipulation | 36 — `authorized_keys`, IAM policy, mailbox permissions, account switch | 1 — user added to many groups · 0 · never | Account Manipulation Best 90 |
| T1218 System Binary Proxy | 27 — `cmstp`/`csc`/`cdb`/`bginfo`/`certutil` family | 1 — Diskshadow execution · 0 · never | Evasion Best 85 |
| T1685 Disable or Modify Tools | mapped under the model's key (count not pulled) | T1562.001 ×2 — Defender disabled via Defender Control · 56 · 2026-11-14; Defender threat detection disabled · 0 · never | Audit Tampering Better 74 |
| T1110 Brute Force | 19 — failed-login profiles by endpoint, zone, application | 13 — internal/external brute force with and without login, account guessing, Okta failures, disabled/expired accounts (16,828 fires, last today); two disabled, one of them at 36,073 fires | Brute Force Attack Better 64 |
| T1021 Remote Services | 8 — admin-share redirect, Kerberos service counts, first RDP source→destination | T1021.001 RDP by unapproved admin · 0 · never; T1021.002 IPC$ share across hosts · 170 · 2026-11-18 | Lateral Movement Best 79 |
| T1048 Exfil, Alternative Protocol | 21 — `dnscat`/`iodine`, DNS byte volumes, outgoing-mail bytes | — | Data Exfiltration Best 75 |
| T1567 Exfil, Web Service | 15 — file-sharing uploads by user / department / organisation | — | Data Exfiltration Best 75 |
| **T1486 Data Encrypted for Impact** | **1** — *Abnormal number of distinct files written by a single user* | 1 — *Crowdstrike Ransomware Detection* · 2 · **2025-03-13** | Ransomware Best 93 |
| T1490 Inhibit System Recovery | 5 — `vssadmin` / `wmic` shadow-copy deletion, `bcdedit` ×2, `wbadmin` | 1 — shadow copies deleted with vssadmin · 0 · never | Ransomware Best 93 · Destruction of Data Best 100 |
| T1136 Create Account | 21 — group creation, `net.exe` user and admin-group additions | — | Account Manipulation Best 90 |
| T1569.002 Service Execution *(unscored)* | — | 1 enabled — C2 default service installation · 0 · never; 1 disabled | — |
| T1134.001 Token Impersonation *(unscored)* | — | 2 — Okta OAuth2 token revocation · 72 · 2026-10-26; Defender stopped via TrustedInstaller token · 0 · never | — |
| T1550.002 Pass the Hash *(unscored)* | — | 1 — possible pass the hash · 0 · never | — |
| T1548.002, T1027.002, T1070.004, T1021.006, T1560.001, T1560.002 *(unscored)* | — | **none found by name** | — |

## 4 — What feeds the rules

`exabeam_parser_list` `{state: "Enabled", type: "Custom"}` → 21 tenant-built parsers (Sysmon event
3/10, Windows Security 4985/5449, Falco, GCP alerts, Zscaler Internet Access DLP, AI-governance JSON,
GitHub public-repo alerts). The use-case payload's `datasourceCategories` confirms Unix/auditd
enabled under *endpoint auditing*. Vendors seen on event rows in the companion sweep: CrowdStrike
Falcon, Palo Alto NGFW, Zscaler ZPA and ZIA, LogRhythm NetMon, Zeek, Cisco web security, Proofpoint
(by correlation-rule names). **Partial.**

Absent, by a 30-day presence search: `vendor:"SonicWall"` 0 rows; `vendor:"Veeam"` 0; Cisco ASA 0.
The telemetry SafePay's initial access would land in **is not ingested**. The T1190 rules above watch
web shells and first-seen inbound ports, not edge-appliance authentication.

## 5 — Context tables the rules lean on

`exabeam_context_table_list` → 134 tables; **3 in `Error`**, 19 `Healthy` with zero items. Two of the
three errors are the Exabeam-fed domain threat-intelligence tables (`av-domain`, 13,438 items;
`AlienVault STIX/TAXII`, 12,396), both last updated 2025-08-11 — any domain-TI rule keyed on them has
been running on a frozen list for three months. The third is `All Okta Users` (1,394 items, User type):
an identity-context table in `Error` degrades every rule that enriches on Okta attributes. The empty
tables are the usual unpopulated Exabeam-source lists.

## 6 — Has any of it fired? (90-day sanity window)

`exabeam_search_alerts` on `mitres.technique_key`, one id per query, `limit` 100, newest first:

- **T1490 — 9 alerts, all CRITICAL, all one shape:** a service account deleting volume shadow copies
  via `vssadmin.exe` on two servers (`<server-1>`, `<server-2>`), 2026-08-23 → 2026-11-14, on a roughly
  monthly cadence. The analytics rule fires; the EXASOC correlation rule for the same behaviour has
  never fired. Monthly, two hosts, one service account reads like a backup job — **not asserted**;
  handed to `soc-investigate`.
- **T1218 — 100 (cap):** ~70 are *'msiexec.exe' was used to execute a remote script* on five
  workstations, every few days since September, priorities LOW→CRITICAL for the same behaviour. A
  noisy-rule candidate for `rule-tuning`, not evidence of SafePay.
- **T1486 — 100 (cap):** file-write-volume anomalies, mostly `root` on Unix hosts. The one mapped rule
  fires constantly on administrators; that is profiling noise, not ransomware precision.
- **T1133 — 98 of the first 100 alerts on the whole technique set** carried it: VPN profiling attaches
  to nearly every identity alert. Corroboration across distinct rules is the discriminator.
- T1110, T1021, T1059, T1098, T1136, T1048, T1567, T1190: each at the 100 cap, each a recognisable
  population (brute-force stories, first RDP pairs, PowerShell WMI enumeration, `sshd_config` writes,
  `net.exe` user creation, DNS-NX volumes, AI/LLM uploads, first inbound ports). Covered and loud.
- **Enabled correlation rules that have never fired, in scope:** 12 (Node Brotli RCE, PHP RCE, four
  T1059.001 PowerShell rules, Diskshadow, Defender threat detection disabled, C2 default service,
  RDP by unapproved admin, pass the hash, shadow copies via vssadmin, user added to many groups). Quiet
  or broken is not decidable from here; each is a candidate for a test fire.

## Report, as handed back

**26 techniques in scope; 13 parents detectable here, 7 sub-techniques detectable only through named
correlation rules the model does not score, 6 sub-techniques with no content found, and the single
most important gap is upstream of all of them: SafePay's initial-access telemetry (SonicWall, Veeam,
Cisco ASA) is not ingested.**

- **Scope.** CISA AA26-293A, 2026-10-20, 26 ids. Stack partial as in §4. Model `lastUpdateTimestamp`
  2026-11-19T04:36. *This assesses what the SIEM could detect; it says nothing about patch state or
  exposure.*
- **Covered.** The 13 parents in the §3 table, each with rank, value, mapped rule count, named
  correlation rules, source telemetry present, and the 90-day alert population.
- **Gaps, in priority order.**
  1. *Enabled but unsatisfied:* none in scope.
  2. *Initial access not visible:* no SonicWall, Veeam or Cisco ASA source. Proposal: onboard
     appliance authentication and VPN logs from whichever of these the organisation runs; until then
     T1133/T1190 coverage is for web apps and the Zscaler edge only.
  3. *Unscored, no content found:* T1560.001/.002 (archive via 7-Zip/WinRAR — SafePay stages with
     both), T1070.004, T1027.002, T1548.002, T1021.006 (WinRM). Proposal: process-create content on
     `7z.exe`/`rar.exe`/`winrm`/`wsmprovhost.exe` with volume profiles, and UAC-bypass signatures.
  4. *Covered but thin:* T1486 Best 100 rests on one behavioural file-write rule plus a CrowdStrike
     correlation last fired 2025-03-13. Proposal: confirm the EDR's ransomware detections still reach
     the tenant; add file-rename / entropy content if the endpoint source carries it.
  5. *Covered but never fired:* the 12 enabled correlation rules above. Proposal: test-fire each.
  6. *Context tables:* `av-domain` and `AlienVault STIX/TAXII` in `Error` since 2025-08-11, and
     `All Okta Users` in `Error` — repair the feeds or retire the rules keyed on them.
  7. *Noise masking signal:* `msiexec` remote-script rule (T1218) and *Disabled/Expired Accounts
     Activity* (T1110, 16,828 fires) — `rule-tuning`.
- **Flagged.** none — nothing in the advisory, the rule lists or the alert names asked for a coverage
  assumption.
- **Handoffs.** *Has it already happened?* → `intel-sweep` (done: band 1 with four shared-infrastructure
  hits). The monthly shadow-copy deletions by a service account on two servers → `soc-investigate`.
  The two noisy rules → `rule-tuning`.

## What this run changed

- `coverage-read.md` and `detection-coverage/SKILL.md`: *unscored* is a class of its own for dotted
  ids; `T1685`/`TA0112` are the model's current keys and `T1562.001` is absent; analytics rules carry
  `mitre[].techniqueKey`, correlation rules carry the id only in `name` with `timesTriggered` /
  `lastTriggeredAt` beside it.
- The `intel-sweep` example's "T1685 is a typo" line was wrong and is corrected there.
