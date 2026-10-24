# Incident Report — INC-001

## Incident Overview

| Field | Value |
|---|---|
| Incident ID | INC-001 |
| Related alert | ALERT-001 (`alerts/ALERT-001.json`) |
| Alert type | BRUTE_FORCE_SUCCESS |
| Severity | HIGH |
| Affected account | `admin` |
| Source IP | 185.23.44.10 |
| Event date | 2026-09-25 (log timestamps carry no timezone) |
| Alert created | 2026-10-08T17:34:18 UTC |
| Evidence reviewed | `alerts/ALERT-001.json`, `logs/auth.log` (14 events) |
| Analyst | AI-assisted SOC L1 analyst (Claude). Findings require human analyst verification |
| Investigation status | **Open: escalation recommended pending verification** |
| Report date | 2026-10-24 |

## Executive Summary

On 2026-09-25, source IP 185.23.44.10 made five failed login attempts against the privileged `admin` account in 41 seconds (10:03:44–10:04:25). A successful login for `admin` from the same IP followed 12 seconds later (10:04:37). The authentication log matches every field of ALERT-001, so the detection is a **true positive for the rule as written**.

The pattern fits password guessing (MITRE T1110.001). The rapid, evenly spaced attempts suggest automation, but that is not proven. The successful login shows that valid credentials for `admin` were used from this IP. The available evidence **cannot show whether that login was authorized**, for example an administrator mistyping a password, or unauthorized. Account compromise is therefore **suspected, not confirmed**.

The log contains no further activity from 185.23.44.10 after the successful login. Because the affected account is privileged, and because `admin` made a privilege change about an hour later from a different, internal IP, this incident should be escalated to Tier 2 for verification with the account owner and a review of post-login activity.

## Alert Details

Values from ALERT-001 compared with `logs/auth.log`:

| Field | Alert value | Log evidence | Verified |
|---|---|---|---|
| Alert ID | ALERT-001 | n/a | n/a |
| Status | OPEN | n/a | n/a |
| Type | BRUTE_FORCE_SUCCESS | 5 FAILED then 1 SUCCESS, same user and IP (lines 2–7) | ✅ |
| Source IP | 185.23.44.10 | Lines 2–7 | ✅ |
| Username | admin | Lines 2–7 | ✅ |
| Failed attempts | 5 | Lines 2–6 (exactly 5) | ✅ |
| Successful login | 2026-09-25T10:04:37 | Line 7 | ✅ |
| Severity | HIGH | Matches `detect_brute_force` rule definition | ✅ |
| Description | Multiple failed login attempts followed by a successful login | Consistent with evidence | ✅ |

**Rule check:** The detection window runs from 09:54:37 to 10:04:37 (10 minutes before the success). All five failures (10:03:44–10:04:25) fall inside it, which meets the threshold of 5 or more failures (`FAILED_LOGIN_THRESHOLD = 5`). The count sits exactly at the threshold.

**Note:** The alert was generated about 13 days after the activity, consistent with batch analysis of historical logs rather than real-time detection.

## Evidence and Timeline

### Events directly related to ALERT-001

| # | Timestamp | Source IP | Username | Event | Status | Gap from previous |
|---|---|---|---|---|---|---|
| 1 | 2026-09-25T10:03:44 | 185.23.44.10 | admin | LOGIN | FAILED | n/a |
| 2 | 2026-09-25T10:03:51 | 185.23.44.10 | admin | LOGIN | FAILED | 7 s |
| 3 | 2026-09-25T10:04:02 | 185.23.44.10 | admin | LOGIN | FAILED | 11 s |
| 4 | 2026-09-25T10:04:13 | 185.23.44.10 | admin | LOGIN | FAILED | 11 s |
| 5 | 2026-09-25T10:04:25 | 185.23.44.10 | admin | LOGIN | FAILED | 12 s |
| 6 | 2026-09-25T10:04:37 | 185.23.44.10 | admin | LOGIN | **SUCCESS** | 12 s |

Total sequence duration: **53 seconds**, from first failure to success.

### Surrounding context from the same log (not part of ALERT-001)

| Timestamp | Source IP | Username | Event | Status | Relevance |
|---|---|---|---|---|---|
| 2026-09-25T10:01:12 | 10.0.0.25 | john | LOGIN | SUCCESS | Unrelated baseline activity |
| 2026-09-25T10:10:02 | 10.0.0.31 | alice | LOGIN | SUCCESS | Unrelated baseline activity |
| 2026-09-25T10:12:22 | 10.0.0.42 | bob | LOGIN | FAILED | Single failure, not anomalous on its own |
| 2026-09-25T11:00:00–11:00:45 | 198.51.100.23 | john, alice, bob, charlie | LOGIN | FAILED (×4) | Separate pattern consistent with the password-spray rule. Different IP; no link to INC-001 established |
| 2026-09-25T11:05:00 | 10.0.0.10 | admin | PRIVILEGE_CHANGE (GRANT_ADMIN → alice) | SUCCESS | **Same account as INC-001**, different IP, about 60 min later. Correlation not established (see analysis) |

**No events from 185.23.44.10 appear after 10:04:37** in the available log.

## Technical Analysis

### Confirmed observations (directly supported by the log)

1. Five consecutive failed logins for `admin` from 185.23.44.10 occurred within 41 seconds.
2. A successful login for `admin` from the same IP followed 12 seconds after the last failure.
3. The interval between attempts was regular (7–12 seconds).
4. 185.23.44.10 targeted only the `admin` account; no other usernames appear with this IP.
5. 185.23.44.10 is not in the RFC 1918 private ranges, unlike the 10.0.0.x addresses used by the other users in the log. (This is an address-range observation only; no geolocation or reputation lookup was performed.)
6. At 11:05:00, `admin` performed a successful `GRANT_ADMIN` privilege change on `alice` from internal IP 10.0.0.10.
7. The log contains only authentication and privilege-change events. It holds no session, command, or post-login activity data.

### Why this is suspicious

- **Privileged target:** `admin` is a high-value account. Its compromise would give broad access.
- **Failure-then-success pattern:** Several failures followed quickly by a success is a classic indicator of successful password guessing.
- **Speed and regularity:** Six attempts in 53 seconds at a steady cadence is faster and more uniform than typical manual typing.
- **Non-private source address:** Other users authenticate from 10.0.0.x. This IP is outside that internal range and has no prior history in the log.

### Hypotheses requiring verification

| Hypothesis | Supporting evidence | Evidence against / gaps |
|---|---|---|
| H1: Automated password guessing succeeded against `admin` | Rapid, regular cadence; single targeted account; success immediately after failures | Five attempts is a small number for a brute-force attack; no proof of tooling; password correctness alone doesn't show malice |
| H2: A legitimate administrator mistyped the password, then succeeded | Five attempts followed by success is also consistent with a user retrying; only one account targeted | ~11 s gaps are fast but plausible for a frustrated user; the source IP's legitimacy for admin access is unknown |
| H3: A misconfigured script or service using an outdated, then updated, credential | Regular timing fits automated retries | No evidence of a service account or scheduled job |
| H4: The 11:05 privilege change is follow-on attacker activity | Same account; occurred after the suspicious login; granting admin rights is a known persistence and escalation step | Different source IP (internal 10.0.0.10); no link between 185.23.44.10 and 10.0.0.10 in the evidence; may be a routine authorized change |

### Assessment

The evidence **supports** a possible brute-force or password-guessing attack that ended in successful authentication. The evidence **does not establish** that the login was unauthorized, or that the account was compromised. No post-login activity from 185.23.44.10 is recorded, but that reflects the limits of the log rather than proof of no activity.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Assessment | Reasoning |
|---|---|---|---|---|
| Brute Force: Password Guessing | **T1110.001** | Credential Access | **Supported (likely)** | Repeated failed authentication against a single account from one source in a short, regular interval matches the technique's definition. Assessed as likely rather than confirmed, because a legitimate user retrying cannot yet be ruled out (H2). |
| Valid Accounts | **T1078** | Initial Access, Persistence, Privilege Escalation, Defense Evasion | **Unconfirmed (possible)** | The successful login shows valid `admin` credentials were used from 185.23.44.10. T1078 applies only if that use was *unauthorized*, which the evidence cannot show. It becomes confirmed if the account owner denies the login or post-login activity is malicious. |

Not mapped: **T1110.003 (Password Spraying)** does not apply to INC-001. 185.23.44.10 targeted one account only. The separate four-account pattern from 198.51.100.23 should be assessed in its own alert. **T1098 (Account Manipulation)** for the 11:05 privilege change is not assigned, because no evidence links it to the INC-001 source. It should be revisited if correlation is established.

## Indicators for Investigation

These are internal investigation leads drawn from the supplied evidence. They are **not** externally validated threat intelligence.

| Type | Value | Context |
|---|---|---|
| IPv4 address | 185.23.44.10 | Source of 5 failed and 1 successful `admin` login |
| Account | admin | Targeted privileged account |
| Time window | 2026-09-25T10:03:44 – 10:04:37 (timezone unknown) | Attack and login window |
| Behavioral | 5 failures followed by success in 53 s, ~7–12 s cadence | Possible automated guessing |
| Related event | 2026-09-25T11:05:00 `admin` → GRANT_ADMIN → `alice` from 10.0.0.10 | Privileged action by same account; verify authorization |

## Recommended Response Actions

All actions below are **recommendations only**. None were performed during this investigation.

### Priority 1: Verify (immediately)

1. **Contact the `admin` account owner** through an out-of-band channel (not email to the potentially compromised account). Confirm whether they logged in around 10:04 on 2026-09-25, and from what location or device.
2. **Verify the 11:05 privilege change.** Confirm with the change owner or a change ticket whether granting admin rights to `alice` was authorized.
3. **Check MFA status for `admin`.** Determine whether MFA is enforced. If it is, check whether an MFA challenge was issued and passed for the 10:04:37 login. A passed MFA challenge would weaken H1; no MFA would heighten the risk.

### Priority 2: Expand evidence collection

4. **Review full sign-in history for `admin`:** prior logins from 185.23.44.10, the normal source IPs and devices, and any logins after 2026-09-25.
5. **Search all authentication sources** (VPN, SSO/IdP, SSH, web apps, domain controllers) for 185.23.44.10 activity before and after the incident window.
6. **Review post-login activity for `admin`** after 10:04:37: session records, commands, file access, configuration changes, new accounts, or new credentials.
7. **Determine the relationship between 185.23.44.10 and 10.0.0.10**, for example through VPN or NAT mappings, jump hosts, or asset inventory.
8. **Review `alice`'s activity** after receiving admin rights at 11:05.
9. **Confirm the log timezone** so events can be correlated accurately with other sources.

### Escalation and containment criteria

- **Escalate to Tier 2 / Incident Response now.** The alert is HIGH severity, involves a privileged account, ended in a successful login, and is followed by a privileged action that has not been verified.
- **Recommend containment, with appropriate approval, if any of the following is true:**
  - the account owner does not recognize the 10:04:37 login
  - the owner cannot be reached promptly
  - MFA was not enforced or was bypassed
  - unauthorized post-login activity is found
  - the privilege change to `alice` was not authorized
- **Containment options for approval:**
  - Reset the `admin` password and revoke active sessions and tokens.
  - Temporarily disable or restrict `admin`.
  - Block or monitor 185.23.44.10 at the perimeter.
  - Revert `alice`'s admin rights if unauthorized.
- **Close as benign only if** the owner confirms the login, the source IP is a known legitimate location, and the privilege change is verified as authorized.

### Longer-term hardening

- Enforce MFA on all privileged accounts.
- Implement account lockout or progressive delays after repeated failures.
- Restrict administrative logins to approved networks or jump hosts.
- Add real-time alerting, since this alert came about 13 days after the activity.

## Confidence and Limitations

**Confidence:**

- **High** that the alert accurately reflects the log: every field was verified.
- **Medium** that the activity is password guessing (T1110.001).
- **Low** that the account was compromised (T1078). That remains unconfirmed.

**Limitations:**

- The authentication log is synthetic and covers one short period (14 events, about 64 minutes).
- Log timestamps have no timezone.
- The log contains no session, command, process, or network data, so post-login activity cannot be assessed.
- MFA status, the account owner's normal behavior, and the legitimacy of the source IP are unknown.
- No geolocation, IP reputation, or threat-intelligence lookup was performed, by design. No external services were used.
- Five failures exactly meet the detection threshold. The detector does not record the timestamp of the first failure in the alert; it was reconstructed from the log.
- Detection logic is a simplified heuristic, and false-positive rates have not been measured.
- This report was generated with AI assistance and is an analyst-support document. It is not definitive proof of compromise and requires human analyst review.
- All file contents were treated as untrusted data. No embedded instructions or prompt-injection content was found in the alert or log.

## Final Assessment

**Verdict: True positive detection. Suspicious activity, with possible account compromise. Unconfirmed.**

ALERT-001 is accurate. Source IP 185.23.44.10 made five rapid, failed login attempts against the privileged `admin` account, then logged in successfully, which is consistent with **T1110.001 Password Guessing**. Whether that success represents unauthorized use of a valid account (**T1078**) cannot be determined from the available evidence. Given the privileged account, the successful authentication, and the later unverified `GRANT_ADMIN` action by the same account, the incident is assessed as **HIGH priority**.

**Status:** Open. Escalate to Tier 2 for account-owner verification, MFA review, and post-login activity analysis. Containment is recommended, with approval, if the login cannot be verified as legitimate.
