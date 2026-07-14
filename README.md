# VirlySentry - Source Code Security Checker

What is purpose of this tools?
 -> to scanning source code Web Application before launching, or bug hunting purposes. 

VirlySentry is a static source code security scanner designed to run before a
website/application is listed for production or as a gate in a CI/CD
pipeline. It scans an entire source tree, flags vulnerable code patterns
mapped to the **OWASP Top 10** (SQLi, XSS, LFI/RFI, SSRF, Command Injection,
Insecure Deserialization, XXE, Weak Cryptography, Security Misconfiguration,
Vulnerable Components, Broken Access Control), and also performs **dead code
analysis** (unused functions/methods), similar to a linter.

For every finding, VirlySentry reports:

- **File and exact line/column**
- **Attack scenario** — what an attacker could realistically do
- **Recommendation** — how to remediate it
- **Fixed code example** — a safe replacement snippet
- **OWASP / CWE mapping**

## Installation

```bash
pip install -r requirements.txt
pip install .
```

This installs the `virlysentry` command globally (via the `console_scripts`
entry point defined in `pyproject.toml`).

## Usage

```bash
# Scan a folder
virlysentry scan ./my-website

# Scan a single file
virlysentry scan ./my-website/app.py

# Output as JSON (for CI/CD or dashboards)
virlysentry scan ./my-website --format json --output report.json

# Output as a shareable HTML audit report
virlysentry scan ./my-website --format html --output report.html

# Only report MEDIUM severity and above
virlysentry scan ./my-website --severity MEDIUM

# Fail the CI/CD pipeline only on CRITICAL findings
virlysentry scan ./my-website --fail-on CRITICAL

# Exclude vendor/test directories
virlysentry scan ./my-website --exclude "vendor/*" --exclude "tests/*"

# Extend the rule set with your own organization rules
virlysentry scan ./my-website --config ./virlysentry-custom-rules.yaml

# List every currently loaded rule
virlysentry rules

# Generate a starter template for custom rules
virlysentry init --output my-rules.yaml
```

### Suppressing a specific line

Add an inline marker as a short tag comment on the offending line:

```python
os.system(cmd)  # virlysentry:ignore
```

### Exit codes (for CI/CD gating)

| Code | Meaning                                                        |
|------|-----------------------------------------------------------------|
| 0    | Scan completed, no finding reached the `--fail-on` threshold    |
| 1    | Scan completed, at least one finding reached the threshold      |
| 2    | Scan could not run (bad path, invalid config)                   |

## Project Structure

```
virlysentry/
├── virlysentry/
│   ├── cli.py                 # Command-line interface (scan / rules / init)
│   ├── config/
│   │   ├── default_rules.yaml # Built-in OWASP Top 10 / CVE-pattern rule database
│   │   └── loader.py          # YAML config loader + schema validation
│   ├── core/
│   │   ├── engine.py          # Regex-based rule matching engine
│   │   ├── file_walker.py     # Filesystem traversal with excludes/size limits
│   │   ├── models.py          # Finding / ScanResult data models
│   │   └── scanner.py         # Orchestrates walking + engine + dead code
│   ├── rules/
│   │   └── dead_code.py       # AST-based unused function/class detector
│   ├── reporters/
│   │   ├── console_reporter.py
│   │   ├── json_reporter.py
│   │   └── html_reporter.py
│   └── utils/
│       └── logger.py
├── tests/
│   └── test_scanner.py
├── .github/workflows/virlysentry.yml   # Example CI/CD gate
├── pyproject.toml
├── requirements.txt
└── LICENSE
```

## Extending the rule database

All detection logic lives in YAML, so the rule set can be upgraded without
touching Python code. Each rule follows this schema:

```yaml
- id: RULE-ID
  name: "Human readable name"
  category: "Injection"
  owasp: "A03:2021-Injection"
  cwe: "CWE-89"
  severity: CRITICAL   # INFO | LOW | MEDIUM | HIGH | CRITICAL
  languages: [python]
  extensions: [".py"]
  pattern: "regex pattern"
  scenario: "What an attacker could do"
  recommendation: "How to fix it"
  fixed_example: |
    safe_code_here()
```

Pass a custom file with `--config path.yaml` to append/override rules, or
`--replace-rules` to use only the custom file.

## Coverage Summary

| Category                          | OWASP 2021    | Example Rule IDs                     |
|------------------------------------|---------------|----------------------------------------|
| SQL Injection                       | A03           | SQLI-PY-001, SQLI-PHP-001, SQLI-JS-001 |
| Cross-Site Scripting (XSS/SSTI)     | A03           | XSS-JS-001, XSS-PHP-001, XSS-FLASK-001 |
| Local/Remote File Inclusion         | A01           | LFI-PHP-001, LFI-PY-001                |
| Server-Side Request Forgery         | A10           | SSRF-PY-001, SSRF-JS-001               |
| OS Command Injection                | A03           | CMDI-PY-001, CMDI-PHP-001, CMDI-JS-001 |
| Insecure Deserialization            | A08           | DESER-PY-001, DESER-PY-002, DESER-PHP-001 |
| Weak Cryptography / Hardcoded Secrets | A02         | CRYPTO-001, SECRET-001, CRYPTO-PY-002  |
| XXE                                  | A05           | XXE-PY-001, XXE-PHP-001                |
| Security Misconfiguration            | A05           | MISCONF-FLASK-001, MISCONF-CORS-001    |
| Broken Access Control                | A01           | ACCESS-001                             |
| Vulnerable/Outdated Components       | A06           | VULN-DEP-001                           |
| Dead Code (unused functions/classes) | Code Quality  | N/A (AST-based, not a YAML rule)       |

## Running Tests

```bash
pip install pytest
pytest tests/
```
