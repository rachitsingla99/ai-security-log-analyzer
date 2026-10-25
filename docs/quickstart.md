
# Quick Start Guide

## Requirements

- Python 3
- Git
- Windows PowerShell or equivalent terminal
- Claude Desktop with Cowork access
  (optional for AI-assisted investigations)

## 1. Clone the Repository

```powershell
git clone https://github.com/rachitsingla99/ai-security-log-analyzer.git
cd ai-security-log-analyzer
```

## 2. Run the Security Analyzer

```powershell
python src/analyzer.py
```

The analyzer processes synthetic authentication
events and generates JSON security alerts.

## 3. Run Automated Tests

```powershell
python -m unittest discover -s tests -v
```

Expected result for the current implementation:

11 tests passing.

## 4. Generate an Investigation Package

First, identify an available alert file:

```powershell
Get-ChildItem alerts -Filter *.json
```

Select one of the alert files and run:

```powershell
python src/package_generator.py alerts/ALERT-001.json
```

Replace ALERT-001.json with another existing
JSON alert filename if desired.

## 5. Review the Investigation Package

Find the newly created folder inside:

investigation_packages/

It contains:

- alert.json
- evidence.log
- investigation_context.json
- investigation_prompt.md

## 6. Investigate with Claude Cowork

Open Claude Desktop and start a Cowork task.

Connect the project folder.

Ask Claude to review the investigation package,
validate the evidence, and generate a Markdown
incident report.

Review Claude's conclusions before accepting them.

## 7. Security Notice

Use synthetic or sanitized test data only.

Do not upload confidential company logs, secrets,
or credentials to AI systems.

This project is an educational prototype and
is not intended for production security monitoring.
```
