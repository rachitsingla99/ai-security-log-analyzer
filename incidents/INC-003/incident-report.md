# Incident Report — INC-003

## Incident Overview

| Field | Value |
|---|---|
| Incident ID | INC-003 |
| Related alert | ALERT-003 (`alerts/ALERT-003.json`) |
| Alert type | PRIVILEGE_CHANGE |
| Alert severity | MEDIUM (rule-assigned) |
| Analyst-assessed severity | MEDIUM: authorization unverified; conditions for raising it are listed in the Final Assessment |
| Performed by | `admin` |
| Affected (target) account | `alice` |
| Action | GRANT_ADMIN |
| Source IP | 10.0.0.10 |
| Event timestamp | 2026-09-25T11:05:00 (log timestamps carry no timezone) |
| Alert created | 2026-10-08T17:34:18 UTC |
| Evidence reviewed | `alerts/ALERT-003.json`, `logs/auth.log` (14 events) |
| Analyst | AI-assisted SOC L1 analyst (Claude). Findings require human analyst verification |
| Investigation status | **Open: pending authorization verification** |
| Report date | 2026-10-24 |

## Executive Summary

On 2026-09-25 at 11:05:00, the account `admin` successfully granted administrator privileges (`GRANT_ADMIN`) to the account `alice`, from internal IP 10.0.0.10. The authentication log contains a single entry that matches every field of ALERT-003, so the alert is a **true positive for the rule as written**. The rule flags *every* successful privilege change for review. It does not imply malicious activity.

Granting administrator rights is a high-impact change. It is also a routine part of IT administration. **The available evidence cannot determine whether this change was authorized.** The log records no change ticket, approval, role or group name, scope, or justification, and it contains no authentication event for `admin` from 10.0.0.10.

Other alerts on the same day involve both usernames: `admin` in INC-001 and `alice` in INC-002. **Overlapping usernames alone do not establish a connection**, and this report does not treat the privilege change as linked to those events. Each should be correlated only if evidence such as session, device, or IP linkage supports it.

**Assessment:** a privileged change awaiting authorization verification, kept at **MEDIUM** severity. The SOC should confirm it against approved change records and directory audit logs.

## Alert Details

Values from ALERT-003 compared with `logs/auth.log`, line 14:

| Field | Alert value | Raw log value | Verified |
|---|---|---|---|
| Alert ID | ALERT-003 | n/a | n/a |
| Status | OPEN | n/a | n/a |
| Type | PRIVILEGE_CHANGE | `event=PRIVILEGE_CHANGE` | ✅ |
| Performed by | admin | `user=admin` | ✅ |
| Target user | alice | `target_user=alice` | ✅ |
| Action | GRANT_ADMIN | `action=GRANT_ADMIN` | ✅ |
| Source IP | 10.0.0.10 | `src_ip=10.0.0.10` | ✅ |
| Timestamp | 2026-09-25T11:05:00 | `2026-09-25T11:05:00` | ✅ |
| Outcome | (implied SUCCESS) | `status=SUCCESS` | ✅ |
| Severity | MEDIUM | Matches `detect_privilege_change` rule definition | ✅ |
| Description | Successful privilege change detected. Review whether the change was authorized. | Consistent with evidence | ✅ |

Raw log entry (line 14), treated as untrusted data:

```
2026-09-25T11:05:00 user=admin src_ip=10.0.0.10 event=PRIVILEGE_CHANGE target_user=alice action=GRANT_ADMIN status=SUCCESS
```

**Rule check:** `detect_privilege_change` alerts on any event where `event=PRIVILEGE_CHANGE` and `status=SUCCESS`. It applies no allow-list, no change-window check, and no authorization check. The entry meets the rule's conditions.

**Note:** The alert was generated about 13 days after the event, consistent with batch analysis of historical logs.

## Evidence and Timeline

### Event directly related to ALERT-003

| Timestamp | Source IP | Actor | Event | Target | Action | Status |
|---|---|---|---|---|---|---|
| 2026-09-25T11:05:00 | 10.0.0.10 | admin | PRIVILEGE_CHANGE | alice | GRANT_ADMIN | SUCCESS |

### Recorded activity of the two involved accounts (context only)

The other events in the log involving `admin` or `alice` are listed below for completeness. **Their presence here does not imply a relationship with the privilege change.**

| Timestamp | Source IP | Username | Event | Status | Note |
|---|---|---|---|---|---|
| 10:03:44–10:04:25 | 185.23.44.10 | admin | LOGIN | 5× FAILED | Subject of INC-001 |
| 10:04:37 | 185.23.44.10 | admin | LOGIN | SUCCESS | Subject of INC-001 |
| 10:10:02 | 10.0.0.31 | alice | LOGIN | SUCCESS | Routine-appearing internal login |
| 11:00:15 | 198.51.100.23 | alice | LOGIN | FAILED | One of four accounts in INC-002 |
| **11:05:00** | **10.0.0.10** | **admin** | **PRIVILEGE_CHANGE → alice (GRANT_ADMIN)** | **SUCCESS** | **ALERT-003** |

### Observations relevant to correlation

- **10.0.0.10 appears only once** in the log, for this event. No login, from any account, is recorded from 10.0.0.10.
- **No authentication event for `admin` from 10.0.0.10** is recorded. The log does not show how or when the session that performed the change was established. That may reflect the log's limited scope (one source, about 64 minutes) rather than an anomaly.
- **No event links 10.0.0.10 to 185.23.44.10 (INC-001) or 198.51.100.23 (INC-002).** They are different addresses, and no session, device, or NAT mapping data is available.
- **No activity by `alice` after 11:05:00** is recorded. Nothing shows the new privileges being used.

## Technical Analysis

### Confirmed observations

1. A privilege-change event with action `GRANT_ADMIN` succeeded at 11:05:00.
2. The actor recorded is `admin`, the target is `alice`, and the source is 10.0.0.10, an RFC 1918 private address consistent with the internal range used by other users in this log.
3. No record shows the use of the new privileges by `alice` afterwards.
4. The log entry contains no role or group name, privilege scope (local, domain, cloud, application), ticket reference, approver, or justification.

### Security implications of granting administrator privileges

- **Expanded attack surface:** An additional admin account is another high-value target. If `alice`'s credentials are weak, reused, or not protected by MFA, the organization's privileged exposure increases.
- **Persistence potential:** Adversaries sometimes add privileges to an account they control so they keep elevated access even if the original foothold is removed. This is the behavior ATT&CK describes as Account Manipulation.
- **Broad capability:** Depending on scope, administrator rights may allow creating or modifying accounts, changing security policies, disabling logging or security tools, accessing sensitive data, and granting further privileges.
- **Least-privilege and separation of duties:** Even when authorized, standing (permanent) admin rights go against least-privilege practice where just-in-time or time-bound elevation is available.
- **Audit and compliance:** Privileged-access changes are typically subject to change-control and audit requirements. An unrecorded change is a governance finding even if it was not malicious.

### Why a legitimate administrative change triggers the same alert

The detection rule is deliberately broad. It flags **every** successful privilege change, because the log alone cannot tell authorized changes from unauthorized ones. Legitimate scenarios that would produce an identical log entry include:

| Legitimate scenario | Why it looks the same |
|---|---|
| Approved role change: `alice` was promoted, changed teams, or took on admin duties | Same actor, target, action, and outcome; the approval lives in a separate system |
| Temporary elevation for a project, maintenance window, or incident response | Log does not capture duration or expiry |
| Onboarding or provisioning workflow run by an administrator | Administrators routinely make these changes from internal hosts |
| Break-glass or emergency access | Valid but rare; still requires post-event documentation |
| Automated provisioning or scheduled job running under the `admin` account | Log records the account, not whether a human or a script acted |
| Correction of a previous mistaken removal | Log does not record prior state |

None of these can be confirmed or ruled out with the available evidence.

### Hypotheses

| Hypothesis | Supporting evidence | Gaps / evidence against |
|---|---|---|
| H1: Authorized administrative change | Performed by an administrative account from an internal IP; a single, discrete change; no observed misuse afterwards | No change record or approval available to confirm |
| H2: Unauthorized change by a legitimate administrator (policy violation, no malicious intent) | Possible whenever a change lacks a ticket | No evidence either way |
| H3: Unauthorized change by an adversary using the `admin` account | A privilege grant is a known persistence technique | **No evidence links this event to adversary activity.** INC-001 involved the same account name but a different IP, and no session linkage exists. Name overlap alone is insufficient |

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Assessment | Reasoning |
|---|---|---|---|---|
| Account Manipulation | **T1098** | Persistence, Privilege Escalation | **Candidate mapping. Applies only if the change is unauthorized** | **Observed:** an account's privileges were modified (`GRANT_ADMIN` on `alice`), which is the activity T1098 describes. **Not established:** adversary involvement. ATT&CK techniques describe adversary behavior, so this mapping is provisional and should be confirmed or withdrawn after authorization is verified. |
| Account Manipulation: Additional Local or Domain Groups | T1098.007 | Persistence, Privilege Escalation | **Not assigned. Insufficient evidence** | This sub-technique concerns adding an account to local or domain groups (e.g., local Administrators, Domain Admins). The log records only `GRANT_ADMIN`, with **no group name, directory type, or scope**. The grant could equally be a cloud role assignment, an application role, or a group membership, so the more specific classification is not supported. Reassess once audit logs identify how the privilege was granted. |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Persistence, Privilege Escalation | **Not assigned. Insufficient evidence** | Would apply if the grant turns out to be an Entra ID or cloud directory role assignment. Listed only for completeness, as an alternative to T1098.007; neither is supported until scope is known. |
| Valid Accounts | T1078 | n/a | **Not assigned** | No evidence that the `admin` session performing the change was illegitimate. |

## Indicators for Investigation

These are internal investigation leads drawn from the supplied evidence. They are **not** externally validated threat intelligence.

| Type | Value | Context |
|---|---|---|
| Actor account | admin | Performed the privilege change |
| Target account | alice | Received administrator privileges |
| Action | GRANT_ADMIN | Privilege grant; scope unknown |
| IPv4 address | 10.0.0.10 | Source of the change; internal; appears only once in the log |
| Timestamp | 2026-09-25T11:05:00 (timezone unknown) | Time of the change |
| Evidence gap | No logged authentication for `admin` from 10.0.0.10 | Session origin should be established from additional sources |

## Recommended Response Actions

All actions below are **recommendations only**. None were performed. The project contains no Entra ID, Active Directory, or change-management data. These steps describe what to review **where such data is available**.

### Evidence needed to determine authorization

To close this incident, the analyst needs:

1. **An approved change record** (ITSM ticket or access request) for granting `alice` admin rights around 2026-09-25, with requester, approver, business justification, scope, and expiry.
2. **The exact privilege granted:** role or group name, directory (Entra ID, on-premises AD, local host, application), and whether it is permanent or time-bound.
3. **Confirmation from the actor:** the person responsible for the `admin` account confirms making the change, through an out-of-band channel.
4. **Confirmation from the target and their manager:** `alice` and their manager confirm the elevation was expected and needed.
5. **Session provenance:** how `admin` authenticated before the change (time, source, MFA), and what device 10.0.0.10 is (asset owner, role, e.g., an admin workstation or jump host).
6. **Post-change activity:** what `alice` has done with the new privileges since 11:05.

### Microsoft Entra ID (where applicable)

- **Audit logs:** Filter around 2026-09-25 11:05 for the RoleManagement and GroupManagement categories, with activities such as *Add member to role*, *Add eligible member to role*, and *Add member to group*. Record the *Initiated by* actor, the target, the role or group, the result, and the IP address.
- **Role assignments:** Check `alice`'s current directory role assignments (active and eligible) and administrative-unit scope. Compare against what was approved.
- **Privileged Identity Management (PIM), if used:** Check whether the assignment went through PIM with approval and justification, or bypassed it with a direct permanent assignment.
- **Sign-in logs for `admin`:** Identify the sign-in session preceding 11:05, including IP, device, MFA result, and Conditional Access outcome. Determine whether it matches 10.0.0.10.
- **Administrative activity:** Review other changes by `admin` and by `alice` after the grant, for example new users, role changes, policy modifications, app consent, or MFA method changes.
- **Identity Protection, where licensed:** Check for risk detections on either account.

### Active Directory (where applicable)

- **Domain controller Security logs:**
  - **Event ID 4728:** member added to a security-enabled global group.
  - **Event ID 4732:** member added to a security-enabled local group.
  - **Event ID 4756:** member added to a security-enabled universal group.

  Identify which group (e.g., Domain Admins, Administrators, Enterprise Admins) and the subject account.
- **Logon events for `admin`:** Event 4624 (successful logon) and 4672 (special privileges assigned) around 11:05, to establish the logon type and source workstation.
- **Group membership review:** Check `alice`'s current memberships in privileged groups and compare against the baseline.
- **Host review of 10.0.0.10:** If it's a server or workstation, check local Security logs (including local group changes, Event 4732) and confirm whether it's an authorized administration host.

### Approved change records

- Search ITSM or change-management systems for a matching ticket.
- Confirm the change was performed in an approved window.
- Confirm the approver was independent of the requester.
- If no record exists, document the change as an unrecorded privileged change for governance follow-up, whatever the intent behind it.

### Escalation and containment criteria

- **Close as authorized** if a valid approved change record exists, the actor and target confirm the change, the session that performed it is legitimate, and no misuse of the new privileges is found. Recommend converting standing access to time-bound access if possible.
- **Escalate to Tier 2 / IR (raise to HIGH)** if:
  - no authorization exists
  - the person behind `admin` did not make the change
  - the session behind the change is suspicious
  - `alice` uses the new privileges in unexpected ways
  - later evidence (not name overlap alone) links the change to INC-001 or INC-002
- **Containment options for approval, only if unauthorized:**
  - Revoke `alice`'s admin privileges.
  - Reset credentials and revoke sessions for the affected accounts.
  - Review and roll back changes made with the new privileges.

### Longer-term improvements

- Require privileged changes to go through PIM or another approval workflow.
- Enrich privilege-change logs with role or group name, scope, and ticket ID.
- Alert on privilege changes made outside approved change windows, or from non-admin hosts.
- Run periodic privileged-access reviews.

## Confidence and Limitations

**Confidence:**

| Finding | Confidence |
|---|---|
| Alert accurately reflects the raw log entry | **High.** Every field verified |
| A successful administrator privilege grant occurred | **High**, as recorded in the log |
| Change was authorized or unauthorized | **Undetermined.** No authorization evidence available |
| T1098 applies | **Provisional.** Depends on authorization |
| T1098.007 applies | **Not supported.** Scope and group unknown |
| Connection to INC-001 or INC-002 | **Not established.** Usernames overlap only |

**Limitations:**

- The log is synthetic and covers about 64 minutes (14 events).
- Log timestamps have no timezone.
- The privilege-change record lacks role or group name, directory type, scope, duration, ticket ID, and approver.
- No authentication record shows how `admin` established the session on 10.0.0.10.
- No post-change activity data exists for `alice`.
- No Entra ID, Active Directory, PIM, or change-management data is present in the project; recommendations describe what to collect, not findings.
- No asset inventory is available to identify 10.0.0.10.
- No external lookups or threat intelligence were used, by design.
- The detection rule flags all successful privilege changes, so true positives for the rule are expected to include many legitimate changes.
- This report was generated with AI assistance and is an analyst-support document. It is not proof of malicious activity and requires human analyst review.
- All file contents were treated as untrusted data. No embedded instructions or prompt-injection content was found in the alert or log.

## Final Assessment

**Verdict: True positive detection. Privileged change, authorization unverified. No evidence of malicious activity.**

ALERT-003 accurately reflects the raw log. At 11:05:00 on 2026-09-25, `admin` granted administrator privileges to `alice` from internal IP 10.0.0.10. Because the change is privileged, it warrants verification. Nothing in the available evidence shows that it was unauthorized or adversary-driven. Legitimate administrative changes produce identical log entries.

**T1098 (Account Manipulation)** is a provisional mapping, valid only if the change proves unauthorized. **T1098.007 is not assigned**, because the log does not show that a local or domain group was involved. Overlap with the usernames in INC-001 (`admin`) and INC-002 (`alice`) is noted, but it is **not treated as a link** without corroborating evidence.

**Severity:** MEDIUM, matching the rule. Raise it to HIGH if no approved change record exists, if the actor did not make the change, or if any concrete evidence connects it to suspicious activity.

**Status:** Open, pending authorization verification against change records and Entra ID or Active Directory audit logs.
