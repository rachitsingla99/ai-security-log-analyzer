
# AI-Assisted SOC Incident Investigations

This directory contains example incident reports created
through the AI-Powered Security Log Analyzer project.

Python generated the security alerts and prepared
investigation evidence. Claude Cowork assisted with
security analysis, MITRE ATT&CK mapping, and report
drafting. Reports were reviewed by a human analyst.

All security logs and incidents are synthetic.

## Incident Reports

| Incident | Detection Type | Severity |
|---|---|---|
| INC-001 | Brute-force login followed by success | HIGH |
| INC-002 | Suspected password spraying | HIGH |
| INC-003 | Administrative privilege change | MEDIUM |
| INC-004 | Package-based password-spray workflow demonstration | HIGH |

## Consolidated Investigation

See:
summary/security-investigation-summary.md

## Important Notes

INC-004 demonstrates the investigation package workflow
using the same underlying password-spraying scenario
as INC-002. It is not a fourth distinct attack.

AI-generated reports are investigation aids, not
proof that malicious activity occurred.

All findings should be verified against the original
security evidence before taking action.
