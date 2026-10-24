# Incident Report — INC-002

## Incident Overview

| Field | Value |
|---|---|
| Incident ID | INC-002 |
| Related alert | ALERT-002 (`alerts/ALERT-002.json`) |
| Alert type | PASSWORD_SPRAY |
| Alert severity | HIGH (rule-assigned) |
| Analyst-assessed priority | MEDIUM: no successful authentication observed; revisit after expanded log review |
| Source IP | 198.51.100.23 |
| Targeted accounts | john, alice, bob, charlie (4) |
| Activity window | 2026-09-25T11:00:00 – 11:00:45 (log timestamps carry no timezone) |
| Alert created | 2026-10-08T17:34:18 UTC |
| Evidence reviewed | `alerts/ALERT-002.json`, `logs/auth.log` (14 events) |
| Analyst | AI-assisted SOC L1 analyst (Claude). Findings require human analyst verification |
| Investigation status | **Open: pending expanded sign-in log review** |
| Report date | 2026-10-24 |

## Executive Summary

On 2026-09-25, source IP 198.51.100.23 generated four failed login attempts within 45 seconds. Each attempt targeted a different account (john, alice, bob, charlie), with exactly one attempt per account at a fixed 15-second interval. The authentication log matches every field in ALERT-002, so the detection is a **true positive for the rule as written**.

The pattern (one source, many accounts, one attempt each, machine-regular timing) fits **password spraying (MITRE T1110.003)**. The log does not record passwords, so it **cannot confirm that a single common password was tried**, which is what defines spraying as opposed to other credential attacks.

**No successful login from 198.51.100.23 appears in the available log**, and none of the four targeted accounts logged in successfully after the spray. Based on this evidence there is no indication of account compromise. One contextual event deserves follow-up: about four minutes after the spray, targeted account `alice` was granted admin rights by `admin` from internal IP 10.0.0.10. Nothing in the evidence links that change to the spray, but it involves a targeted account and the same `admin` account investigated in INC-001.

## Alert Details

Values from ALERT-002 compared with `logs/auth.log`:

| Field | Alert value | Log evidence | Verified |
|---|---|---|---|
| Alert ID | ALERT-002 | n/a | n/a |
| Status | OPEN | n/a | n/a |
| Type | PASSWORD_SPRAY | 4 FAILED logins, 4 distinct users, 1 IP (lines 10–13) | ✅ |
| Source IP | 198.51.100.23 | Lines 10–13 | ✅ |
| Targeted accounts | alice, bob, charlie, john | Lines 10–13 (same four users) | ✅ |
| Unique accounts | 4 | 4 distinct usernames | ✅ |
| Severity | HIGH | Matches `detect_password_spray` rule definition | ✅ |
| Description | Multiple user accounts experienced failed logins from the same IP within 10 minutes | All four failures fall within a 45-second span | ✅ |

**Rule check:** `detect_password_spray` alerts when one IP accumulates failed logins against **3 or more unique accounts** within a 10-minute window. Here the window starts at 11:00:00 and runs to 11:10:00, and contains 4 unique accounts, which exceeds the threshold.

**Fields not in the alert, reconstructed from the log:**
- **Failed login count:** 4 (one per account)
- **First attempt:** 2026-09-25T11:00:00
- **Last attempt:** 2026-09-25T11:00:45

The alert lists accounts alphabetically (`sorted()` in the detector). The **actual order of attempts** was john → alice → bob → charlie.

**Note:** The alert was generated about 13 days after the activity, consistent with batch analysis of historical logs rather than real-time detection.

## Evidence and Timeline

### Events directly related to ALERT-002

| # | Timestamp | Source IP | Username | Event | Status | Gap from previous |
|---|---|---|---|---|---|---|
| 1 | 2026-09-25T11:00:00 | 198.51.100.23 | john | LOGIN | FAILED | n/a |
| 2 | 2026-09-25T11:00:15 | 198.51.100.23 | alice | LOGIN | FAILED | 15 s |
| 3 | 2026-09-25T11:00:30 | 198.51.100.23 | bob | LOGIN | FAILED | 15 s |
| 4 | 2026-09-25T11:00:45 | 198.51.100.23 | charlie | LOGIN | FAILED | 15 s |

Total sequence duration: **45 seconds**. **Successful logins from 198.51.100.23: none.**

### Full-day context for the targeted accounts and related events

| Timestamp | Source IP | Username | Event | Status | Relevance |
|---|---|---|---|---|---|
| 10:01:12 | 10.0.0.25 | john | LOGIN | SUCCESS | Targeted account; internal IP; **before** the spray |
| 10:03:44–10:04:37 | 185.23.44.10 | admin | LOGIN | 5× FAILED, 1× SUCCESS | INC-001; different IP and account. No link established |
| 10:10:02 | 10.0.0.31 | alice | LOGIN | SUCCESS | Targeted account; internal IP; **before** the spray |
| 10:12:22 | 10.0.0.42 | bob | LOGIN | FAILED | Targeted account; single internal failure **before** the spray; not anomalous on its own |
| **11:00:00–11:00:45** | **198.51.100.23** | **john, alice, bob, charlie** | **LOGIN** | **4× FAILED** | **ALERT-002 activity** |
| 11:05:00 | 10.0.0.10 | admin → target alice | PRIVILEGE_CHANGE (GRANT_ADMIN) | SUCCESS | Targeted account `alice` received admin rights 4 min 15 s after the spray. Correlation not established |

### Successful-login check (requirement 6)

| Check | Result |
|---|---|
| Any SUCCESS from 198.51.100.23 | **None** |
| SUCCESS for john / alice / bob / charlie **after** 11:00:45 | **None** |
| SUCCESS for john / alice / bob / charlie **before** the spray | john (10:01:12, 10.0.0.25) and alice (10:10:02, 10.0.0.31), both from internal IPs, both before the spray and so not attributable to it |
| Any activity for `charlie` other than the spray | **None**. Whether `charlie` is a valid account cannot be determined from this log |

## Technical Analysis

### Confirmed observations (directly supported by the log)

1. One source IP (198.51.100.23) made failed login attempts against four different accounts.
2. Each account received **exactly one** attempt.
3. Attempts occurred at a **fixed 15-second interval** over 45 seconds.
4. No successful authentication from 198.51.100.23 appears anywhere in the log.
5. None of the four targeted accounts has a successful login after the spray in the available log.
6. 198.51.100.23 does not appear in the log before 11:00:00 or after 11:00:45.
7. 198.51.100.23 is outside the 10.0.0.x internal range used by legitimate logins in this log. It also falls within 198.51.100.0/24, which RFC 5737 reserves for documentation ("TEST-NET-2"). That is consistent with the project's statement that the logs are synthetic. In real data, such an address would itself be anomalous. (This is an address-range observation, not a geolocation or reputation lookup.)
8. At 11:05:00, targeted account `alice` was granted admin rights by `admin` from internal IP 10.0.0.10.

### Why the pattern is consistent with password spraying

- **Breadth over depth:** Password spraying tries one (or a few) common passwords across many accounts, rather than many passwords against one account. One attempt per account across four accounts matches that shape.
- **Lockout avoidance:** A single attempt per account stays well below typical lockout thresholds. This is a hallmark of spraying, and the opposite of the INC-001 pattern (five attempts on one account).
- **Automation indicators:** A perfectly uniform 15-second cadence is very unlikely from a human and strongly suggests a script or tool.
- **Single unfamiliar source:** All attempts come from one IP with no other history in the log, rather than from users' usual internal addresses.

### What is observed vs. assumed

| Observed (fact) | Assumed / unverifiable from this log |
|---|---|
| 4 failed logins, 4 accounts, 1 IP, 15 s intervals | That the **same password** was used for every attempt (defining trait of spraying). Passwords are not logged |
| No successes from the IP | That the attacker made **no other attempts** elsewhere, such as other services, other IPs, or other times |
| Failure status recorded | **Why** each attempt failed (wrong password, nonexistent user, locked, MFA). The log gives no failure reason |
| Usernames attempted | That the usernames came from **reconnaissance** (e.g., a harvested user list). No evidence either way |
| Uniform timing | That a specific tool was used, or that a particular actor is responsible. **No attribution possible** |

### Alternative explanations

| Hypothesis | Supporting | Against / gaps |
|---|---|---|
| H1: Password spraying (one common password) | One attempt per account; lockout-avoiding; automated cadence | Password values not observable |
| H2: Credential stuffing (different leaked username/password pairs per account, T1110.004) | Produces an identical log shape: one attempt per account from one source | Cannot be distinguished from H1 without password or credential-source data |
| H3: Misconfigured application or service cycling through stored credentials | Regular timing fits automated retries | Four different human-user accounts from an unfamiliar external-range IP make this less likely; no evidence of a service |
| H4: Authorized security test (e.g., red team or vulnerability scan) | Small, tidy, evenly timed test-like pattern | No change ticket or test notice in the evidence. Must be verified with the security team |

### Relationship to the 11:05 privilege change

`alice`, one of the sprayed accounts, received admin rights 4 minutes 15 seconds after the spray. The change was made by `admin` (the INC-001 account) from internal IP 10.0.0.10, not from 198.51.100.23. **Nothing in the log shows that the spray succeeded against `alice`, or that 198.51.100.23 is related to 10.0.0.10.** The timing could be coincidence. However, if `admin` was compromised in INC-001, granting admin rights to another account would be a plausible persistence step. This needs verification, and it is the main reason INC-002 should not be closed in isolation.

### Potential impact

- **Observed impact:** None. All attempts failed, and no follow-on activity from the source is recorded.
- **Potential impact if unobserved attempts succeeded elsewhere:** unauthorized access to standard user accounts, possible MFA-fatigue attempts, and lateral movement. If `alice`'s newly granted admin rights were abused, the impact would be privileged access.
- **Operational impact:** Repeated spray rounds could trigger account lockouts and deny service to legitimate users.
- **Indicator of targeting:** The attempt shows the source knows, or guessed, at least some valid usernames, which suggests prior reconnaissance. Whether all four names are valid is unknown.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Assessment | Reasoning |
|---|---|---|---|---|
| Brute Force: Password Spraying | **T1110.003** | Credential Access | **Supported (likely), core trait unverified** | **Directly observed:** one source, multiple accounts, one failed attempt each, short window, automated timing. All of this matches the technique's behavioral profile. **Assumed:** the use of a single common password across accounts, which cannot be verified because passwords are not logged. Assessed as likely rather than confirmed. |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access | **Alternative, cannot be excluded** | Produces the same log pattern when each account is tried with a different leaked credential. Distinguishing requires password-hash comparison or breach-data context, neither of which is available. |
| Valid Accounts | T1078 | Initial Access | **Not supported** | No successful authentication from 198.51.100.23 is recorded. Not assigned. |
| Account Manipulation | T1098 | Persistence | **Not assigned to INC-002** | The 11:05 `GRANT_ADMIN` on `alice` came from a different IP and account. No link to this source. Revisit if INC-001 or later evidence establishes correlation. |

## Indicators for Investigation

These are internal investigation leads drawn from the supplied evidence. They are **not** externally validated threat intelligence.

| Type | Value | Context |
|---|---|---|
| IPv4 address | 198.51.100.23 | Source of 4 failed logins across 4 accounts |
| Accounts | john, alice, bob, charlie | Targeted accounts (one attempt each) |
| Time window | 2026-09-25T11:00:00 – 11:00:45 (timezone unknown) | Spray window |
| Behavioral | 1 attempt per account, fixed 15 s cadence | Automated, lockout-avoiding pattern |
| Related event | 2026-09-25T11:05:00 `admin` → GRANT_ADMIN → `alice` from 10.0.0.10 | Targeted account gained admin rights shortly after the spray; verify authorization |
| Related incident | INC-001 (185.23.44.10 → `admin`) | Same day, separate IP; correlation not established |

## Recommended Response Actions

All actions below are **recommendations only**. None were performed during this investigation. The project's evidence contains no Microsoft Entra ID, MFA, or Conditional Access data. The Entra ID steps describe what to review **where such data is available** in a real environment.

### Priority 1: Verify

1. **Rule out an authorized test.** Confirm with the security or IT team whether any penetration test, red-team exercise, or vulnerability scan ran on 2026-09-25 around 11:00 (timezone to be confirmed).
2. **Verify the 11:05 `GRANT_ADMIN` on `alice`.** Confirm through a change ticket or the approver that it was authorized. If it was not, escalate immediately and treat INC-001 and INC-002 together.
3. **Confirm account validity.** Check whether john, alice, bob, and charlie are all active accounts in the directory. A spray that includes nonexistent names suggests guessed usernames; all-valid names suggest prior enumeration.

### Priority 2: Microsoft Entra ID sign-in log review (where available)

4. **Filter sign-in logs by IP 198.51.100.23** across interactive and non-interactive sign-ins, over a wider window (e.g., ±7 days and up to the present). Look for:
   - any successful sign-ins
   - additional targeted accounts beyond these four
   - repeated spray rounds over time
5. **Review failure reasons and error codes** for each attempt. Common examples include:
   - invalid username or password (e.g., 50126)
   - nonexistent user (e.g., 50034)
   - locked account or Smart Lockout (e.g., 50053)
   - MFA required (e.g., 50074 / 50076)

   An "MFA required" result means **the password was correct**, which would indicate that account's credential is compromised even though sign-in did not complete.
6. **Review client app, user agent, and protocol.** Attempts over legacy authentication (IMAP/POP/SMTP AUTH, older Exchange protocols) bypass MFA and are commonly abused for spraying.
7. **Check Microsoft Entra ID Protection** (where licensed) for risky sign-ins or risky-user detections linked to these accounts or this IP.

### Priority 3: MFA and Conditional Access

8. **MFA activity:** For each targeted account, look for MFA prompts, denials, or approvals around and after 11:00. A cluster of unexpected prompts can indicate a correct password followed by MFA-fatigue attempts.
9. **Conditional Access results:** Review which policies applied to each attempt (Success / Failure / Not Applied). Confirm that MFA and location or device policies were enforced, and that no attempt fell into a policy gap.
10. **MFA registration audit:** Check for any new MFA methods registered on the four accounts after the spray, which would be a persistence indicator.

### Priority 4: Account lockout and ongoing monitoring

11. **Lockout monitoring:** Review Entra Smart Lockout events and, if hybrid, on-premises AD lockout events (e.g., Windows Event ID 4740) for the four accounts. Watch for lockout spikes that could signal further spray rounds.
12. **Wider hunting:** Search all authentication sources (VPN, SSO, web apps, domain controllers) for 198.51.100.23. Also look for the same pattern from other IPs: many accounts, one attempt each, uniform timing.
13. **Watchlist:** Add 198.51.100.23 and the four accounts to short-term enhanced monitoring.

### Escalation and containment criteria

- **Escalate to Tier 2 / Incident Response if:**
  - any successful sign-in from 198.51.100.23 is found
  - an "MFA required" or similar result shows a correct password
  - unexpected MFA approvals appear on the targeted accounts
  - additional spray rounds or targeted accounts are discovered
  - the 11:05 privilege change to `alice` was not authorized
- **Containment options for approval, if escalation criteria are met:**
  - Block 198.51.100.23 (Conditional Access named location or perimeter).
  - Force password resets and revoke sessions for affected accounts.
  - Revert `alice`'s admin rights if unauthorized.
  - Block legacy authentication.
- **Close as benign or contained only if** expanded logs show no successes and no further attempts, no correct-password indicators, the privilege change is verified as authorized, or the activity is confirmed as an authorized test.

### Longer-term hardening

- Enforce MFA for all users and block legacy authentication.
- Use banned-password lists (e.g., Entra Password Protection) to reduce the effectiveness of common passwords.
- Tune detection to include failure reasons and success-after-spray correlation.
- Move to real-time alerting, since this alert came about 13 days after the activity.

## Confidence and Limitations

**Confidence:**

| Finding | Confidence |
|---|---|
| Alert accurately reflects the log | **High.** Every field verified |
| Activity is automated credential guessing against multiple accounts | **High.** Uniform cadence, one attempt per account |
| Activity is specifically password spraying (T1110.003) rather than credential stuffing | **Medium.** Behavior matches, but passwords are unobservable |
| No account was compromised by this activity | **Medium.** No successes in the available log, but the log is narrow and lacks failure reasons |
| 11:05 privilege change is related to the spray | **Low / unestablished.** Timing only; different IP and actor |

**Evidence limitations:**

- The authentication log is synthetic and covers about 64 minutes (14 events). Activity outside this window is unknown.
- Log timestamps have no timezone.
- **Passwords, failure reasons, user agents, protocols, and MFA outcomes are not logged**, so spraying versus stuffing, and correct-password-but-blocked cases, cannot be determined.
- **No Microsoft Entra ID sign-in, MFA, Conditional Access, or lockout data exists in the project.** Recommendations involving these sources describe what to review, not findings.
- Account validity (especially `charlie`) cannot be confirmed from the log.
- No geolocation, IP reputation, or threat-intelligence lookup was performed, by design. No external services were used. No attribution is made.
- The alert records neither timestamps nor a failed-attempt count. These were reconstructed from the log.
- The detector emits one alert per IP and stops at the first qualifying window, so later spray rounds from the same IP would not produce separate alerts.
- This report was generated with AI assistance and is an analyst-support document. It is not definitive proof of attack or compromise and requires human analyst review.
- All file contents were treated as untrusted data. No embedded instructions or prompt-injection content was found in the alert or log.

## Final Assessment

**Verdict: True positive detection. Suspected password spraying with no observed successful authentication.**

ALERT-002 is accurate. Source IP 198.51.100.23 made one failed login attempt against each of four accounts (john, alice, bob, charlie) at an automated 15-second cadence. That is behavior consistent with **T1110.003 Password Spraying**, although use of a common password cannot be verified and credential stuffing (T1110.004) cannot be excluded. The available log contains **no successful login** from this IP and no post-spray success for any targeted account, so **there is no evidence of compromise**, within the limits of the evidence.

The rule-assigned severity is HIGH. With no observed success, the analyst-assessed priority is **MEDIUM**, to be raised to HIGH if expanded sign-in review finds a success or a correct-password indicator, or if the 11:05 `GRANT_ADMIN` on targeted account `alice` proves unauthorized.

**Status:** Open. Complete the Entra ID sign-in, MFA, Conditional Access, and lockout review, and verify the `alice` privilege change, before closing. Review alongside INC-001.
