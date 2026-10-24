# Consolidated SOC Investigation Summary

| Field | Value |
|---|---|
| Scope | INC-001, INC-002, INC-003 |
| Source alerts | `alerts/ALERT-001.json`, `alerts/ALERT-002.json`, `alerts/ALERT-003.json` |
| Supporting evidence | `logs/auth.log` (14 events, 2026-09-25 10:01:12 – 11:05:00, no timezone) |
| Reports reviewed | `incidents/INC-001/incident-report.md`, `incidents/INC-002/incident-report.md`, `incidents/INC-003/incident-report.md` |
| Prepared by | AI-assisted SOC L1 analyst (Claude). Requires human analyst review |
| Summary date | 2026-10-24 |
| Overall status | **All three incidents open.** No confirmed compromise; key verifications outstanding |

---

## 1. Executive Summary

On 2026-09-25 the Python Security Log Analyzer raised three alerts from one authentication log covering about 64 minutes. All three alerts were cross-checked field by field against the raw log and are **accurate true positives for their detection rules**.

- **INC-001: Brute-force success (HIGH).** IP 185.23.44.10 failed five logins to the privileged `admin` account in 41 seconds, then logged in successfully at 10:04:37. This is consistent with password guessing (T1110.001). **Whether the successful login was authorized is unknown.** Compromise is suspected, not confirmed.
- **INC-002: Password spray (HIGH by rule; MEDIUM analyst priority).** IP 198.51.100.23 made one failed login against each of four accounts (john, alice, bob, charlie) at a fixed 15-second interval between 11:00:00 and 11:00:45. This is consistent with password spraying (T1110.003), but the shared-password trait cannot be verified. **No successful login from this IP, or by the targeted accounts afterwards, appears in the log.**
- **INC-003: Privilege change (MEDIUM).** At 11:05:00, `admin` granted administrator rights to `alice` from internal IP 10.0.0.10. **Authorization is unverified.** A legitimate administrative change would produce an identical record.

**Relationship between incidents:** The incidents share a date, a one-hour window, and two account names (`admin`, `alice`). **No evidence-backed link exists between them**: each uses a different source IP, and the log contains no session, device, or network data connecting them. They should not be treated as a single campaign on current evidence.

**Most important next step:** verify (a) whether the 10:04:37 `admin` login was legitimate and (b) whether the 11:05:00 `GRANT_ADMIN` was authorized. These two answers decide whether INC-001 is a compromise, whether INC-003 is malicious, and whether any relationship exists between the incidents.

---

## 2. Incident Comparison

| Incident | Alert | Alert type | Rule severity | Analyst priority | Source IP | Affected accounts | Outcome observed | MITRE ATT&CK (assessment) | Status |
|---|---|---|---|---|---|---|---|---|---|
| INC-001 | ALERT-001 | BRUTE_FORCE_SUCCESS | HIGH | HIGH | 185.23.44.10 | `admin` (target) | 5 failed, then 1 **successful** login | **T1110.001** Password Guessing: *likely*<br>**T1078** Valid Accounts: *unconfirmed* | Open: escalate for verification |
| INC-002 | ALERT-002 | PASSWORD_SPRAY | HIGH | MEDIUM | 198.51.100.23 | `john`, `alice`, `bob`, `charlie` (targets) | 4 failed logins; **no success** | **T1110.003** Password Spraying: *likely, core trait unverified*<br>T1110.004 Credential Stuffing: *cannot be excluded* | Open: expanded sign-in review |
| INC-003 | ALERT-003 | PRIVILEGE_CHANGE | MEDIUM | MEDIUM | 10.0.0.10 | `admin` (actor), `alice` (target) | Admin rights **granted** | **T1098** Account Manipulation: *provisional, only if unauthorized*<br>T1098.007 / T1098.003: *not assigned* | Open: authorization verification |

Technique status across the set:

| Technique | INC-001 | INC-002 | INC-003 |
|---|---|---|---|
| T1110.001 Password Guessing | Likely | n/a | n/a |
| T1110.003 Password Spraying | Not applicable (one account) | Likely | n/a |
| T1110.004 Credential Stuffing | n/a | Possible alternative | n/a |
| T1078 Valid Accounts | Unconfirmed | Not supported (no success) | Not assigned |
| T1098 Account Manipulation | Not assigned | Not assigned | Provisional |

---

## 3. Consolidated Timeline

All timestamps from `logs/auth.log`, date 2026-09-25, **timezone unknown**. The log is reproduced in full; events outside any alert are marked as context.

| # | Time | Source IP | Account | Event | Status | Incident | Note |
|---|---|---|---|---|---|---|---|
| 1 | 10:01:12 | 10.0.0.25 | john | LOGIN | SUCCESS | Context | Internal login |
| 2 | 10:03:44 | 185.23.44.10 | admin | LOGIN | FAILED | INC-001 | Attempt 1 |
| 3 | 10:03:51 | 185.23.44.10 | admin | LOGIN | FAILED | INC-001 | +7 s |
| 4 | 10:04:02 | 185.23.44.10 | admin | LOGIN | FAILED | INC-001 | +11 s |
| 5 | 10:04:13 | 185.23.44.10 | admin | LOGIN | FAILED | INC-001 | +11 s |
| 6 | 10:04:25 | 185.23.44.10 | admin | LOGIN | FAILED | INC-001 | +12 s |
| 7 | **10:04:37** | 185.23.44.10 | admin | LOGIN | **SUCCESS** | INC-001 | +12 s; last event from this IP |
| 8 | 10:10:02 | 10.0.0.31 | alice | LOGIN | SUCCESS | Context | Internal login |
| 9 | 10:12:22 | 10.0.0.42 | bob | LOGIN | FAILED | Context | Single internal failure |
| 10 | 11:00:00 | 198.51.100.23 | john | LOGIN | FAILED | INC-002 | Spray attempt 1 |
| 11 | 11:00:15 | 198.51.100.23 | alice | LOGIN | FAILED | INC-002 | +15 s |
| 12 | 11:00:30 | 198.51.100.23 | bob | LOGIN | FAILED | INC-002 | +15 s |
| 13 | 11:00:45 | 198.51.100.23 | charlie | LOGIN | FAILED | INC-002 | +15 s; last event from this IP |
| 14 | **11:05:00** | 10.0.0.10 | admin → alice | PRIVILEGE_CHANGE (GRANT_ADMIN) | **SUCCESS** | INC-003 | Only event from this IP |

Intervals between incidents (factual, not implying causation):

- End of INC-001 (10:04:37) → start of INC-002 (11:00:00): **55 min 23 s**
- End of INC-002 (11:00:45) → INC-003 (11:05:00): **4 min 15 s**
- INC-001 success (10:04:37) → INC-003 (11:05:00): **60 min 23 s**

---

## 4. Independently Confirmed Observations

"Confirmed" here means directly supported by the raw log **and** matching the JSON alert. It does not mean a conclusion about intent or compromise.

### Alert-to-log verification

| Alert | Fields checked | Result |
|---|---|---|
| ALERT-001 | type, source IP, username, failed count (5), success timestamp, severity | All match log lines 2–7 ✅ |
| ALERT-002 | type, source IP, 4 targeted accounts, unique count, severity | All match log lines 10–13 ✅ |
| ALERT-003 | type, actor, target, action, source IP, timestamp, severity | All match log line 14 ✅ |

### Confirmed facts

1. Five failed logins and one successful login for `admin` came from 185.23.44.10 within 53 seconds.
2. Four failed logins, one per account (john, alice, bob, charlie), came from 198.51.100.23 at exact 15-second intervals.
3. No successful login from 198.51.100.23 appears, and none of the four sprayed accounts logged in successfully after 11:00:45.
4. A successful `GRANT_ADMIN` privilege change by `admin` on `alice` came from 10.0.0.10 at 11:05:00.
5. Each incident involves a **different source IP**. No IP appears in more than one incident.
6. 185.23.44.10 and 198.51.100.23 each appear only during their own incident. 10.0.0.10 appears only once.
7. No authentication event for `admin` from 10.0.0.10 is recorded.
8. No activity is recorded for any account after 11:05:00, including use of `alice`'s new privileges.
9. 185.23.44.10 and 198.51.100.23 lie outside RFC 1918 private ranges. 198.51.100.0/24 is the RFC 5737 documentation range (TEST-NET-2), consistent with synthetic data. These are address-range facts only; no geolocation or reputation data was used.

### Not confirmed (requires additional evidence)

- Whether the 10:04:37 `admin` login was authorized.
- Whether a single common password was used in INC-002.
- Whether the 11:05:00 privilege change was authorized, and how `admin`'s session on 10.0.0.10 was established.
- Whether any account was compromised.
- Any attacker identity, tooling, or attribution.

### Report cross-check

The three incident reports are consistent with the alerts and the log on all factual points: timestamps, IPs, accounts, counts, and MITRE assessments. One **difference in emphasis** was found:

- **INC-001 and INC-002** cite the 11:05 privilege change as a reason for escalation or for not closing in isolation. INC-002 also notes that granting admin rights "would be a plausible persistence step" if `admin` were compromised. Both reports state that correlation is *not established*.
- **INC-003**, written under a stricter instruction, treats the overlapping usernames as **not a link** without corroborating evidence.

**Consolidated position:** this summary adopts the INC-003 standard. The privilege change is a reason to *verify* the incidents together, not evidence that they are connected. INC-001's HIGH priority stands on its own merits: a successful login to a privileged account after repeated failures. It does not depend on INC-003.

No embedded instructions or prompt-injection content were found in any alert, the log, or the three reports. All were treated as untrusted data.

---

## 5. Relationship Assessment

### Evidence-backed conclusions

| Conclusion | Basis |
|---|---|
| All three incidents occurred on the same date within about 61 minutes | Log timestamps |
| The incidents involve three different source IPs, with no IP shared between them | Log entries |
| `admin` appears in INC-001 (as login target) and INC-003 (as actor) | Log entries |
| `alice` appears in INC-002 (as spray target) and INC-003 (as privilege recipient) | Log entries |
| No event in the log connects any session, device, or IP across incidents | Absence in the log, within its limited scope |
| **No relationship between the incidents is established by the available evidence** | All of the above |

### Possible relationships (hypotheses only)

| # | Hypothesis | What would make it plausible | Evidence against / gaps | What would confirm or refute it |
|---|---|---|---|---|
| R1 | The INC-001 `admin` login was unauthorized, and the same actor used `admin` to make the INC-003 change | Same account; INC-003 follows INC-001; privilege grants are a known persistence step | Different IPs (external 185.23.44.10 vs internal 10.0.0.10); no session or NAT/VPN linkage; 60-minute gap; change may be routine | `admin` owner confirmation; sign-in session behind the 11:05 change; VPN or NAT mapping; change ticket |
| R2 | INC-002 targeted `alice` because of, or in coordination with, the INC-003 grant | `alice` was sprayed 4 min 15 s before receiving admin rights | The spray against `alice` **failed**; the grant was made by a different account from a different IP; `alice` was one of four targets, so nothing singles her out | Entra or IdP sign-in data for `alice`; change ticket for the grant |
| R3 | INC-001 and INC-002 were performed by the same actor | Same day; both are credential attacks | Different IPs, different techniques (depth vs breadth), 55-minute gap, no shared indicators | Wider log hunting across both IPs; network or infrastructure correlation (outside this dataset) |
| R4 | The incidents are unrelated: separate events, possibly including a legitimate admin change | Consistent with all observed facts; no linking evidence | Cannot be confirmed without the verifications above | Same verifications as R1–R3 |

**Assessment:** R4 (unrelated) is fully consistent with the evidence. R1 is the hypothesis with the **highest potential impact** and is therefore the priority to rule in or out, but it is **not supported** by current evidence. R2 and R3 are weak. **There is no basis to describe these events as a coordinated attack campaign.**

---

## 6. Recommended Investigation Priorities

All items are recommendations. No containment or external actions were taken.

| Priority | Action | Incident(s) | Why first |
|---|---|---|---|
| **P1** | Verify the 10:04:37 `admin` login with the account owner through an out-of-band channel. Check MFA status and outcome for that login. | INC-001 | Successful login to a privileged account after repeated failures; highest standalone risk |
| **P1** | Verify authorization of the 11:05:00 `GRANT_ADMIN`: change ticket, approver, exact role or group, and scope. Confirm with the `admin` operator and `alice`'s manager. | INC-003 | Privileged change; outcome determines whether T1098 applies and whether R1 is viable |
| **P2** | Establish session provenance for the 11:05 change: `admin` sign-in before 11:05, the identity of host 10.0.0.10, and any VPN or NAT mapping to 185.23.44.10. | INC-001, INC-003 | Only evidence that can confirm or refute R1 |
| **P2** | Review post-event activity: `admin` after 10:04:37 and `alice` after 11:05 (Entra or AD audit logs, role and group changes, policy changes, new MFA methods). | INC-001, INC-003 | Determines actual impact if either event was unauthorized |
| **P3** | Expanded Entra ID or IdP sign-in review for 198.51.100.23 over a wider window. Check failure codes (e.g., MFA-required results indicating a correct password), Conditional Access outcomes, legacy-auth use, and lockout events for the four accounts. | INC-002 | No success observed; confirms whether any credential was valid |
| **P3** | Confirm whether an authorized security test ran on 2026-09-25. | INC-001, INC-002 | Could explain the credential-attack patterns |
| **P4** | Confirm the log timezone, and collect authentication sources beyond this log (VPN, SSO, DCs). | All | Required for any accurate cross-source correlation |
| **P4** | Address the detection-engine gaps in Section 7. | All | Improves future alert quality |

**Escalation triggers** (any one escalates to Tier 2 / IR as HIGH):

- the `admin` owner does not recognize the 10:04:37 login, or cannot be reached
- the privilege change has no valid authorization
- a successful or correct-password sign-in from 198.51.100.23 is found
- misuse of `admin` or `alice` privileges is found
- concrete evidence, not username overlap, links any two incidents

**Containment options**, applied only on approval and only when triggers are met: reset credentials and revoke sessions for affected accounts; revoke `alice`'s admin rights if unauthorized; block the relevant source IPs; block legacy authentication.

---

## 7. Limitations

### Synthetic dataset

- **Synthetic and very small:** 14 events over about 64 minutes from a single log source. Activity before, after, or outside this log is unknown.
- **No timezone** on log timestamps. Cross-source correlation and comparison with alert `created_at` (UTC) is approximate.
- **Minimal fields.** There are no failure reasons, user agents, protocols, MFA results, session IDs, device IDs, or Conditional Access outcomes. As a result, the log cannot show:
  - whether failures were wrong passwords or nonexistent users
  - spraying versus credential stuffing
  - whether a password was correct but blocked
  - session continuity between events
- **Privilege-change records** lack role or group name, directory type, scope, duration, ticket ID, and approver.
- **No context data**: asset inventory, user directory (e.g., whether `charlie` exists), change records, or baseline behavior.
- **Documentation-range IP** (198.51.100.23) confirms the data is synthetic. Real-world infrastructure conclusions cannot be drawn.
- **No external enrichment** (geolocation, reputation, threat intelligence) was performed, by design.

### Python detection engine (`src/analyzer.py`, `src/detector.py`)

**Brute-force rule:**
- Events are sorted by timestamp **string**, which is correct only if every timestamp uses an identical ISO format.
- The failure history is reset after any success, and failures older than the window are never pruned (a memory concern only at scale).
- The alert omits the first-failure timestamp and the attempt cadence. These had to be reconstructed from the log.

**Password-spray rule:**
- Emits **at most one alert per IP** (`break` after the first qualifying window), so later spray rounds are not reported.
- Does not check for successes after the spray, which is the most important follow-up question.
- The alert omits timestamps and the failed-attempt count.
- The 10-minute window is hard-coded rather than using `TIME_WINDOW_MINUTES`.

**Privilege-change rule:**
- Flags **every** successful privilege change, with no allow-list, change-window, or approval context. A high rate of legitimate true positives is expected.

**No cross-rule correlation:**
- Each rule runs independently. Relationships such as a success following a spray, or a privileged action following a suspicious login, are not evaluated.

**Parser robustness (`parse_log_line`):**
- Splits on whitespace and `=`. A malformed line or a value containing spaces raises an unhandled exception and stops the run.
- Duplicate keys silently overwrite earlier ones. A field value controlled by an attacker (e.g., a crafted username) could therefore alter parsed fields.
- Log input should be validated before it is trusted for detection.

**Operational:**
- Batch-only. Alerts were created about 13 days after the activity.
- Alert filenames are reused on each run (per README), so earlier alerts can be overwritten.
- Detection thresholds are simplified heuristics, and false-positive rates have not been measured.

**Not reviewed for this summary:** `src/incident_creator.py` and `tests/test_detector.py`. No code or tests were executed. The README's statement that six tests pass was not independently verified.

### Analysis

- All three reports and this summary are **AI-assisted analyst-support documents**, not proof of compromise. They require human analyst review.
- MITRE ATT&CK mappings describe adversary behavior. Where intent is unverified, mappings are marked *likely*, *unconfirmed*, or *provisional* accordingly.

---

## Overall Assessment

| Question | Answer |
|---|---|
| Are the alerts accurate? | **Yes.** All three verified against the raw log |
| Is any account confirmed compromised? | **No.** INC-001 is suspected but unconfirmed; INC-002 shows no success; INC-003 authorization is unknown |
| Are the incidents related? | **Not established.** Account-name overlap and timing only; three distinct IPs; no linking evidence |
| Is this a coordinated campaign? | **No evidence supports that conclusion** |
| Highest-priority item | INC-001 `admin` login verification, alongside INC-003 authorization verification |

**Status:** All three incidents remain open, pending the P1 and P2 verifications above.
