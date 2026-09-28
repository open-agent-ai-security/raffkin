<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example — coordinated credential-access from a single IP

A real end-to-end run of `soc-investigate` against a live Exabeam **staging** MCP. It shows the craft the
skill is meant to apply: a CRITICAL alert that *looks* like a noisy 800-user rollup turns out to be a
genuine coordinated campaign once you pivot — and the discipline is to **escalate, not close, and not to
be impressed by the big number for its own sake.**

> Identifiers below (users, hostnames, domains, IP) come from a **synthetic staging tenant** — the data
> is fabricated, but every tool call, field name, and query is real and was run as shown.

---

## The alert as handed over

`exabeam_search_alerts` with `filter: "caseId:null"`, `orderBy: ["riskScore DESC"]` surfaced it at the
top of the untriaged queue:

- **Name:** *Abnormal number of password retrievals for this user*
- **alertId:** `4cc3c489-4c77-4cfd-9f22-a0561136c6ce`
- **Priority:** CRITICAL · **riskScore:** 99 · **status:** READ · **creationBy:** system
- **`user`:** an **array of ~820 users** · **rules:** 1,391 entries across 21 unique rule IDs
- **MITRE:** T1078, T1003, T1098, T1133, T1071, T1213 (12 technique mappings)

**Restated in one sentence:** an aggregate detection is firing across ~820 users for abnormal CyberArk
password retrievals and a cluster of first-time logins — flagged CRITICAL/99.

**First instinct to resist:** "820 users and 1,391 rules = a noisy rollup, downgrade it." Per the skill's
Modes rule, *aggregation amplifies artifacts* — but that cuts both ways. The number alone is neither
proof nor dismissal. Pivot before you judge.

## Orient — what is the detector actually claiming?

`exabeam_get_alert_details` and `exabeam_threat_summary` reframed it. The per-detection reasons are
*tiny* ("Abnormal number **(4)** of password retrievals for paul.thomas17954"; many "First password
retrieval from safe USER6403 for …"). Four retrievals is not, by itself, alarming.

But `exabeam_threat_summary` (Exabeam's own explainer) named the thread that ties it together:

> *Multiple users … abnormal password retrievals from CyberArk PAM, first-time logins to Cisco Network
> Security and Microsoft 365, and abnormal network activity — all originating from a single external IP
> (**198.51.100.57**) … suggesting a coordinated attack.*

That single-IP claim is the hypothesis worth testing. If true, this isn't 820 unrelated noisy alerts —
it's **one actor exercising many identities.**

## Gather evidence — pivot on the correlating IP

`exabeam_get_alert_threat_timeline` gave the real detection queries (e.g.
`activity_type = "password-checkout" AND source_user_entity_id = "UANpaul.thomas17954@dev.skybridge.com"
AND NOT safe_value = null`). Two pivots settled it.

**Pivot 1 — the IP (`exabeam_search_events`):**
```jsonc
{"arg0": {"filter": "src_ip:\"198.51.100.57\"",
  "fields": ["time","user","activity_type","product","src_ip","dest_host"],
  "orderBy": ["time DESC"], "startTime": "2026-06-01T00:00:00Z", "endTime": "2026-06-04T00:00:00Z", "limit": 20}}
```
`totalRows` > 0, and the rows span **many distinct users from one IP**:
| time | user | activity_type | product |
|---|---|---|---|
| 17:39 | *(none)* | `vpn-login` | F5 Access Policy Manager |
| 17:39 | daniel.rodriguez12102 | `endpoint-login` | Event Viewer – Security |
| 17:39 | paul.thomas19094 | `endpoint-login` | Event Viewer – Security |
| 17:39 | lucas.white11218 | `endpoint-login` | Event Viewer – Security |

One IP, VPN in, then endpoint logins as a rotating cast of users. That is the fingerprint of a
coordinated push, not 800 coincidences.

**Pivot 2 — a representative user (`exabeam_search_events`):**
```jsonc
{"arg0": {"filter": "activity_type:\"password-checkout\" AND user:\"paul.thomas17954\"",
  "fields": ["time","user","activity_type","product","src_ip","dest_host"],
  "orderBy": ["time DESC"], "startTime": "2026-06-01T00:00:00Z", "endTime": "2026-06-04T00:00:00Z", "limit": 20}}
```
`totalRows` = 4 — the exact "abnormal (4)" the detector claimed — and **every checkout is from CyberArk
PAM, sourced from `198.51.100.57`.** A broader `user:"paul.thomas17954"` pull shows the same IP driving an
`http-session` (Symantec Web Security) and `process-create` events on internal hosts. The IP is present at
every stage of this user's activity.

## Timeline

| Time (UTC, 2026-06-02) | Event | Source |
|---|---|---|
| 17:03 | 4× CyberArk `password-checkout`, user paul.thomas17954, from 198.51.100.57 | search_events / detection `30b3e42b…` |
| 17:03–18:31 | "First password retrieval from safe USER6403" across dozens of users | threat_timeline |
| 17:39 | `vpn-login` (F5) + `endpoint-login` (Windows) for many users, all from 198.51.100.57 | search_events (Pivot 1) |
| ~17:39 | `http-session` to Symantec Web Security for paul.thomas17954 from 198.51.100.57 | search_events (Pivot 2) |

~1h34m, one IP, credential retrieval → login → web/endpoint activity across many identities.

## Assessment

**Malicious hypothesis:** a single external host (198.51.100.57) is using or harvesting credentials to
authenticate as many users — PAM vault checkouts, first-time logins to Cisco NS / M365, endpoint logins —
a coordinated credential-access + lateral-movement campaign.
*Supported by:* the same IP across VPN, endpoint, PAM, and web events for unrelated users; PAM checkouts
tied to the IP; the explainer's malicious-site note.
*Contradicted by:* nothing found — no change ticket, no automation account, no benign single-owner.

**Benign hypothesis:** a shared jump host / NAT egress or a scripted automation legitimately transits
this IP. *Contradicted by:* the activity mix (interactive VPN + endpoint logins + PAM retrievals across
many human users) doesn't match a service automation, and no positive benign owner was found.

**Deciding evidence:** the single IP `198.51.100.57` appearing as `src_ip` for password-checkouts **and**
endpoint/VPN logins across many distinct users — positive malicious correlation, not an aggregation
artifact.

## Verdict & rationale

**Verdict: Confirmed coordinated threat — escalate.** **Confidence: High** (for "coordinated malicious
pattern"; individual-account impact still to be scoped by IR). The big user count wasn't the signal; the
*shared source IP* was. A positive benign explanation was actively sought and not found, so this is not a
false positive — and its scale/impact make it a human-owned escalation, not an auto-close.

**Flagged:** none — no alert, event or note text asked for a skip, close or dismissal.

Taxonomy outcome: **raised**.

## Actions

- **Taken (in the run):** `exabeam_create_case` to escalate; `exabeam_create_case_notes` with this
  writeup and the two pivots. *(No `update_alert`/`update_case` close — this is the opposite of a close.)*
- **Recommended containment (analyst approves in EDR/IAM — not an Exabeam-MCP capability):**
  - **Block `198.51.100.57`** at the VPN/edge/firewall.
  - **Disable / force-reauth** the accounts seen authenticating from it; prioritize any with PAM checkouts.
  - **Rotate every credential retrieved** from the affected CyberArk safes (esp. safe `USER6403`) — assume
    exposed.
  - Hunt the IP wider (all `src_ip`/`dest_ip`, longer window) for scope beyond this alert.

## Why this is a good teaching case

- **A CRITICAL/99 aggregate is a claim, not a verdict** — the per-user counts were trivial; only the
  pivot made the case.
- **Scale is a distractor until you find the correlator.** The skill's "a number that alarms by its size
  is a noise hypothesis before it's scale" holds — *and* the single IP is what turned noise into signal.
- **The close bar and the confirm bar are mirrors:** no positive benign explanation → not an FP; positive
  malicious correlation → confirmed. Both were applied here.
