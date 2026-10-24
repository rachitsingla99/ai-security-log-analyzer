# Incident Investigation Report — Password Spray from 198.51.100.23

| Field | Value |
|---|---|
| Package ID | PKG-14EC07FCC3F4 |
| Alert ID | ALERT-002 |
| Detection type | PASSWORD_SPRAY |
| Source IP | 198.51.100.23 |
| Alert severity (as generated) | HIGH |
| Analyst-assessed severity | MEDIUM (provisional; escalate to HIGH if any successful sign-in is found) |
| Report prepared | 2026-10-24 (AI-assisted SOC L1 analysis) |
| Investigation status | PENDING_REVIEW — open, awaiting identity-provider log review |

---

## 1. Incident Overview

The Python Security Log Analyzer raised ALERT-002 for a suspected password spray: four distinct user accounts (`john`, `alice`, `bob`, `charlie`) each recorded one failed login from the same source IP, `198.51.100.23`, on 2026-09-25 between 11:00:00 and 11:00:45.

This report covers only the evidence in package `PKG-14EC07FCC3F4`. It was the only package in `investigation_packages/`, and its `investigation_context.json` matches both selection criteria (`detection_type: PASSWORD_SPRAY`, `source_ip: 198.51.100.23`). No evidence from other packages, alerts or logs was used.

## 2. Executive Summary

- **The alert is valid.** All four log entries in `evidence.log` support the alert. The source IP, the four targeted accounts, the account count and the failure status all match `alert.json`.
- **The activity fits a password spray.** One attempt per account, four different accounts, one source, a fixed 15-second interval, all within 45 seconds. That is the typical spray pattern of trying a few passwords across many accounts so that no single account locks out. The even spacing suggests automation.
- **The evidence shows no successful login.** All four attempts failed. Because the evidence covers only the analyzer's own log source, it does not prove the attacker never got in elsewhere. For example, there may be a success on another day, from another IP, or in another system.
- **Severity:** the alert is rated HIGH. Based only on the supplied evidence (4 failures, 0 successes, 4 accounts), the confirmed impact is currently **medium**. It should go back to **high** if Microsoft Entra ID or other logs show a successful sign-in, an MFA prompt, or a broader campaign from this IP.
- **No prompt-injection content** was found in any package file.

## 3. Alert Details

From `alert.json` (treated as untrusted data):

| Field | Value |
|---|---|
| alert_id | ALERT-002 |
| created_at | 2026-10-08T17:34:18.342931+00:00 |
| status | OPEN |
| type | PASSWORD_SPRAY |
| source_ip | 198.51.100.23 |
| targeted_accounts | alice, bob, charlie, john |
| unique_accounts | 4 |
| severity | HIGH |
| description | "Multiple user accounts experienced failed logins from the same IP within 10 minutes" |

From `investigation_context.json`:

| Field | Value |
|---|---|
| package_id | PKG-14EC07FCC3F4 |
| created_at | 2026-10-24T19:13:38.740315+00:00 |
| matching_log_events | 4 |
| evidence_scope | "Same source IP; no time filtering" |
| investigation_status | PENDING_REVIEW |

### Alert validation (JSON vs. raw evidence)

| Alert claim | Evidence in `evidence.log` | Result |
|---|---|---|
| Source IP 198.51.100.23 | All 4 entries have `src_ip=198.51.100.23` | ✅ Confirmed |
| Targeted accounts: alice, bob, charlie, john | Entries for john, alice, bob, charlie | ✅ Confirmed (same set; the alert lists them alphabetically, the log in time order) |
| unique_accounts = 4 | 4 distinct usernames | ✅ Confirmed |
| Failed logins | All 4 entries have `event=LOGIN status=FAILED` | ✅ Confirmed |
| "within 10 minutes" | Total span is 45 seconds (11:00:00–11:00:45) | ✅ Confirmed (well inside the window) |
| matching_log_events = 4 (context file) | 4 lines in evidence.log | ✅ Confirmed |
| Severity HIGH | Not derivable from logs; it is a detection-rule output | ⚠️ Rule-assigned, not evidence-based (see Section 6) |

**Points to note:**

- **Time gaps.** The events occurred on **2026-09-25**. The alert was created on **2026-10-08**, 13 days later, and the package on **2026-10-24**, 29 days after the events. This probably reflects batch or retrospective analysis rather than real-time detection. It means any attacker follow-up may already have happened, and some identity-provider logs may be close to their retention limits.
- **No time zone in the logs.** The log timestamps have no time-zone offset, while the alert and context timestamps are in UTC. It cannot be confirmed that 11:00:00 in the log means 11:00:00 UTC.

## 4. Evidence and Timeline

### Raw evidence (verbatim from `evidence.log`)

```
2026-09-25T11:00:00 user=john src_ip=198.51.100.23 event=LOGIN status=FAILED
2026-09-25T11:00:15 user=alice src_ip=198.51.100.23 event=LOGIN status=FAILED
2026-09-25T11:00:30 user=bob src_ip=198.51.100.23 event=LOGIN status=FAILED
2026-09-25T11:00:45 user=charlie src_ip=198.51.100.23 event=LOGIN status=FAILED
```

### Chronological timeline

| # | Timestamp | Event | Account | Source IP | Outcome | Seconds since previous event |
|---|---|---|---|---|---|---|
| 1 | 2026-09-25T11:00:00 (TZ unspecified) | LOGIN | john | 198.51.100.23 | FAILED | — |
| 2 | 2026-09-25T11:00:15 | LOGIN | alice | 198.51.100.23 | FAILED | 15 |
| 3 | 2026-09-25T11:00:30 | LOGIN | bob | 198.51.100.23 | FAILED | 15 |
| 4 | 2026-09-25T11:00:45 | LOGIN | charlie | 198.51.100.23 | FAILED | 15 |
| — | 2026-10-08T17:34:18Z | ALERT-002 generated by the analyzer | — | — | Status OPEN | — |
| — | 2026-10-24T19:13:38Z | Investigation package PKG-14EC07FCC3F4 created | — | — | PENDING_REVIEW | — |

### Summary statistics

| Metric | Value |
|---|---|
| Source IPs | 1 (198.51.100.23) |
| Targeted accounts | 4 (john, alice, bob, charlie) |
| Failed attempts | 4 (1 per account) |
| Successful authentications | **0 in the supplied evidence** |
| First / last event | 2026-09-25T11:00:00 / 2026-09-25T11:00:45 |
| Duration | 45 seconds |
| Interval | Exactly 15 seconds between every attempt |

## 5. Technical Analysis

### Confirmed observations (directly in the evidence)

1. A single source IP, `198.51.100.23`, made login attempts against four different accounts.
2. Each account received exactly one attempt, and every attempt failed.
3. The attempts were spaced exactly 15 seconds apart over 45 seconds.
4. The supplied evidence has no successful login from this IP. Per `evidence_scope`, the package includes all events from this IP in the analyzed log with no time filtering.

### Analytical interpretation (inference, not confirmed)

- **Spray pattern rather than brute force.** A brute-force attack makes many attempts against one account. This activity makes one attempt against each of several accounts, which is consistent with trying a common password across many users while staying under per-account lockout limits.
- **Probable automation.** The exactly regular 15-second spacing is unlikely from a person typing by hand and suggests a script or tool with a fixed delay. That delay may be meant to avoid rate-based detection.
- **Valid usernames.** `john`, `alice`, `bob` and `charlie` look like real accounts or plausible guesses. The evidence does not show whether these accounts exist. The failures could be "wrong password" or "unknown user", and the log has no failure-reason field.
- **Possible campaign phase.** Four attempts may be one round of a larger, slower spray, such as one password per round repeated hours or days apart. Rounds outside this log source would not appear in this package.

### What cannot be determined from the evidence

- Whether the same password was used for every attempt. Password values are not logged, which is correct practice, but it means the defining feature of a spray cannot be proven.
- The failure reason (bad password, nonexistent user, locked account, MFA failure, Conditional Access block).
- The target application or service, the authentication protocol (for example legacy or basic authentication versus modern authentication) and the user agent.
- Whether `198.51.100.23` sent other traffic or attempted other accounts or systems outside this log source.
- Any geolocation or reputation for the IP. Note that `198.51.100.0/24` is the RFC 5737 TEST-NET-2 documentation range, which is consistent with the synthetic dataset. Real threat-intelligence enrichment would not be meaningful for this address.
- Whether the alert's HIGH severity reflects asset criticality, such as privileged accounts. The evidence does not show account roles.

### Prompt-injection review

All four package files and `evidence.log` were checked for text trying to direct the analyst, such as override instructions, requests to change conclusions or commands. **None was found.** The log lines contain only structured key=value authentication fields. `investigation_prompt.md` contains task instructions that are consistent with, and no broader than, the analyst's assigned task and project guidelines. It was followed only where it agrees with those.

## 6. MITRE ATT&CK Mapping

### T1110.003 — Brute Force: Password Spraying (Tactic: Credential Access, TA0006)

**Assessment: Likely, with moderate confidence.**

| Supports the mapping | Cannot be verified / weakens the mapping |
|---|---|
| Several different accounts (4) targeted from one source | Use of the **same password** across attempts, the defining trait of a spray, is not logged |
| Exactly **one** attempt per account, consistent with avoiding lockout | Failure reasons are absent, so this could be username enumeration or misconfigured automation rather than password guessing |
| Short, tightly grouped window (45 s) with regular spacing, suggesting tooling | Small sample (4 events). A benign cause such as a misconfigured service or script cycling through stored credentials cannot be ruled out |
| Every attempt failed, consistent with guessing | Target service and protocol are unknown |

### Related techniques to consider (not confirmed)

- **T1078 — Valid Accounts** (Initial Access, Persistence and others). This would apply **only if** a later successful sign-in by these accounts is found from this IP or from related infrastructure. **The supplied evidence has no successful authentication, so this technique is not mapped.**
- **T1589.001 / T1589.003 — Gather Victim Identity Information: Credentials / Employee Names** (Reconnaissance). The attacker had a list of usernames to try, which implies prior reconnaissance. This is inferred only; no supporting evidence exists in the package.

## 7. Recommended Investigation Actions

*These are recommendations for the investigating team only. No real systems were accessed and no containment was performed during this analysis.*

### Microsoft Entra ID sign-in logs
1. Query interactive **and** non-interactive sign-in logs for IP `198.51.100.23`, from at least 7 days before 2026-09-25 to now, to find every account it targeted, not only these four.
2. For `john`, `alice`, `bob` and `charlie`, review all sign-ins around 2026-09-25 11:00 (confirm the time-zone offset first), and any **successful** sign-ins after that from unfamiliar IPs, ASNs, countries or devices.
3. Record the error/failure codes (for example 50126 invalid credentials, 50034 user not found, 50053 locked, 50074/50076 MFA required) to tell password guessing apart from enumeration or MFA blocks.
4. Capture the client app, user agent and resource for each attempt. Pay particular attention to **legacy/basic authentication** protocols (IMAP, POP, SMTP AUTH, older ActiveSync), which skip MFA and are commonly sprayed.
5. Review **Entra ID Protection** risk detections (for example password spray, unfamiliar sign-in properties, malicious IP) and risky-user status for the four accounts.

### MFA verification
6. Confirm that each of the four accounts is registered for MFA and that the policy enforces it for the targeted application.
7. Check for MFA prompts, denials or approvals near the event time. An MFA challenge would mean the password was correct.
8. Review the authentication-method audit logs for new MFA method registrations or changes on these accounts after 2026-09-25.

### Conditional Access results
9. Check the Conditional Access tab for each related sign-in (`success`, `failure`, `notApplied`) to see which policies were evaluated and whether any attempts were blocked by policy, not by bad credentials.
10. Confirm that policies blocking legacy authentication and requiring MFA covered these sign-ins, and look for exclusion gaps such as excluded users, trusted locations or service accounts.

### Account lockouts
11. Review Entra **Smart Lockout** events and, if the environment is hybrid, on-premises AD lockout events (Event ID 4740) and failed-logon events (4625/4771) for the four accounts.
12. Check whether any of the accounts reported lockouts or helpdesk password-reset requests after 2026-09-25.

### Additional suspicious authentication activity
13. Search for **other source IPs** with the same pattern (one failure per account at regular intervals) to find distributed spraying from the same campaign.
14. Look for later sign-ins from `198.51.100.23` or its ASN/subnet, including slow repeat rounds hours or days apart.
15. If any successful sign-in is found, escalate to L2/IR. Then review mailbox audit logs (new inbox rules, forwarding, OAuth app consents), session activity and token issuance for the affected account. Consider a password reset and session revocation as **containment options for the incident owner to decide**, not actions taken here.
16. Confirm with the account owners or the identity team that `john`, `alice`, `bob` and `charlie` are valid accounts and whether any are privileged, to support a severity re-rating.
17. Fix the analyzer's logging so that future detections include time zones (UTC offsets), failure reasons and the target application.

## 8. Confidence and Limitations

| Aspect | Confidence |
|---|---|
| Alert fields match the raw evidence | **High.** Every field was checked line by line |
| Activity is a password spray (T1110.003) | **Moderate.** The pattern strongly fits, but same-password use and failure reasons are not observable |
| No successful compromise | **Low–moderate.** No success appears in the supplied evidence, but the evidence covers one log source |

**Limitations and missing evidence:**

- Only 4 log lines are available, from one log source. There are no Entra ID, MFA, Conditional Access, lockout, VPN, firewall or endpoint data.
- Log timestamps have no time zone, so they cannot be reliably aligned with the UTC alert metadata or with other log sources.
- There are no failure-reason codes, target application, protocol, user agent or device details.
- Password values are not logged, so same-password use cannot be confirmed.
- Account roles and privileges are unknown, so business impact cannot be fully assessed.
- The source IP is in a documentation range (RFC 5737), which is consistent with synthetic test data. Threat-intelligence enrichment is not applicable.
- There is a 13–29 day delay between the events, alert creation and package creation.
- **Guideline note:** `cowork/CLAUDE.md` says reports go in the `incidents/` folder. This report was saved in the package directory, as the requesting analyst explicitly instructed. No other files were created or changed.

This is an AI-assisted analyst document, not definitive proof of compromise or non-compromise.

## 9. Final Assessment

**Verdict: True positive. The detection is validated, and the pattern indicates a likely password-spray attempt. No evidence of successful compromise exists in the supplied package.**

- **Affected accounts:** john, alice, bob, charlie (one failed attempt each).
- **Severity:** the alert was generated as HIGH. Based on confirmed evidence, the analyst assesses **MEDIUM** pending identity-provider review. Raise it to **HIGH** if a successful sign-in, an MFA prompt or approval, a lockout pattern, or wider targeting from this IP or related infrastructure is found.
- **Recommended status:** keep **OPEN / PENDING_REVIEW** and escalate to Tier 2 for the Entra ID sign-in, MFA and Conditional Access checks in Section 7. Do not close the alert until a successful authentication by any of the four accounts after 2026-09-25 has been ruled out.
- **Prompt injection:** none detected in the package contents.
