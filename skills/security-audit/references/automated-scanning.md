# Automated Scanning Tools Reference

Configuration, custom rules, CI integration, and best practices for semgrep, trivy, and gitleaks.

## Tool Comparison

| Tool | Purpose | Scans | Best For |
|------|---------|-------|----------|
| **semgrep** | SAST (Static Application Security Testing) | Source code patterns | Injection, XSS, insecure crypto, code quality |
| **trivy** | Vulnerability scanner | Dependencies, containers, IaC | Known CVEs, outdated packages, misconfigurations |
| **gitleaks** | Secret detection | Git history, staged files | API keys, passwords, tokens, private keys |

**Run order in audits:**

1. **gitleaks** -- fast, catches critical secrets immediately
2. **trivy** -- scans dependencies and infrastructure
3. **semgrep** -- deep code analysis, takes longest

---

## semgrep - Static Analysis (SAST)

### Configuration (.semgrep.yml)

Place in project root for custom rules alongside community rulesets:

```yaml
# .semgrep.yml
rules:
  - id: no-eval-user-input
    patterns:
      - pattern: eval($INPUT)
      - pattern-not: eval("static string")
    message: "eval() with dynamic input is a code injection risk (CWE-95)"
    languages: [php, python, javascript]
    severity: ERROR
    metadata:
      cwe: ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"]
      owasp: ["A03:2021 - Injection"]

  - id: no-md5-passwords
    pattern: md5($PASSWORD)
    message: "MD5 is not suitable for password hashing. Use password_hash() with PASSWORD_ARGON2ID"
    languages: [php]
    severity: WARNING
    metadata:
      cwe: ["CWE-328: Use of Weak Hash"]

  - id: no-unserialize-user-input
    patterns:
      - pattern: unserialize($INPUT)
      - pattern-where-python: "INPUT != 'static_value'"
    message: "unserialize() with user input leads to object injection (CWE-502). Use json_decode() instead."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ["CWE-502: Deserialization of Untrusted Data"]
```

### Ignoring False Positives

```python
# nosemgrep: rule-id
some_safe_code()
```

Or use `.semgrepignore` (follows .gitignore syntax):

```
# .semgrepignore
tests/
vendor/
node_modules/
*.min.js
```

### Key Rulesets

| Ruleset | Command | Coverage |
|---------|---------|----------|
| Auto (recommended) | `--config auto` | Language-detected community rules |
| OWASP Top 10 | `--config p/owasp-top-ten` | All OWASP categories |
| PHP Security | `--config p/php-security` | PHP-specific patterns |
| JavaScript | `--config p/javascript` | JS/TS patterns |
| Secrets | `--config p/secrets` | Hardcoded credentials |
| Docker | `--config p/dockerfile` | Dockerfile misconfigurations |
| Supply chain | `--config p/supply-chain` | Dependency confusion, typosquatting |

### CI Integration

```yaml
# GitHub Actions
- name: Semgrep SAST
  uses: semgrep/semgrep-action@v1
  with:
    config: >-
      p/owasp-top-ten
      p/php-security
      .semgrep.yml
  env:
    SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

---

## trivy - Vulnerability Scanner

### Configuration (trivy.yaml)

Place in project root:

```yaml
# trivy.yaml
severity:
  - HIGH
  - CRITICAL

scan:
  # Skip directories
  skip-dirs:
    - vendor
    - node_modules
    - .git

  # Skip specific files
  skip-files:
    - "composer.lock.bak"

# Ignore specific CVEs (document why!)
ignore:
  # CVE-YYYY-NNNNN: Not exploitable in our context because...
  unfixed: false
```

### Ignore File (.trivyignore)

```
# .trivyignore
# CVE-2024-12345: False positive - function not reachable from user input
CVE-2024-12345

# CVE-2024-67890: Accepted risk - mitigated by WAF rules, fix ETA Q2 2026
CVE-2024-67890
```

**Important:** Always document WHY a CVE is ignored. Revisit ignored CVEs quarterly.

### Scan Types

```bash
# Filesystem scan (dependencies)
trivy fs --severity HIGH,CRITICAL .

# Docker image scan
trivy image --severity HIGH,CRITICAL myapp:latest

# IaC scan (Terraform, Kubernetes, CloudFormation, Dockerfile)
trivy config --severity HIGH,CRITICAL .

# SBOM generation
trivy fs --format cyclonedx --output sbom.json .

# License scanning
trivy fs --scanners license .
```

### CI Integration

```yaml
# GitHub Actions
- name: Trivy vulnerability scan
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: fs
    severity: HIGH,CRITICAL
    format: table
    exit-code: 1
    ignore-unfixed: true

- name: Trivy Docker scan
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: image
    image-ref: ${{ env.IMAGE }}
    severity: HIGH,CRITICAL
    exit-code: 1
```

---

## gitleaks - Secret Detection

### Configuration (.gitleaks.toml)

```toml
# .gitleaks.toml
title = "Custom gitleaks config"

# Extend default rules (recommended)
[extend]
useDefault = true

# Allowlist specific paths or patterns
[allowlist]
  description = "Allowed patterns"
  paths = [
    '''vendor/.*''',
    '''node_modules/.*''',
    '''tests/fixtures/.*''',
    '''\.env\.example''',
  ]
  regexes = [
    '''EXAMPLE_API_KEY''',
    '''test[_-]?key''',
    '''dummy[_-]?secret''',
  ]

# Custom rules
[[rules]]
  id = "custom-internal-token"
  description = "Internal service token"
  regex = '''NR-[A-Za-z0-9]{32}'''
  secretGroup = 0
  entropy = 3.5
  keywords = ["NR-"]
```

### Allowlisting Specific Findings

For inline allowlisting (when a "secret" is actually safe):

```toml
# .gitleaks.toml
[allowlist]
  commits = [
    "abc123def456",  # Commit that added test fixtures with dummy keys
  ]
  regexes = [
    '''AKIAIOSFODNN7EXAMPLE''',  # AWS example key from documentation
  ]
```

### Pre-commit Hook Setup

```bash
# Install pre-commit hook
cat > .git/hooks/pre-commit << 'HOOK'
#!/bin/bash
gitleaks protect --staged --verbose
if [ $? -ne 0 ]; then
    echo "gitleaks detected secrets in staged files. Commit blocked."
    echo "If this is a false positive, add to .gitleaks.toml allowlist."
    exit 1
fi
HOOK
chmod +x .git/hooks/pre-commit
```

Or with the `pre-commit` framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.22.1
    hooks:
      - id: gitleaks
```

### CI Integration

```yaml
# GitHub Actions
- name: Gitleaks secret scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Combined CI Pipeline

A complete security scanning pipeline combining all three tools:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    # Weekly full scan (catches newly disclosed CVEs)
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  secret-detection:
    name: Secret Detection (gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git log scanning

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dependency-scan:
    name: Dependency Scan (trivy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
          format: sarif
          output: trivy-results.sarif
          exit-code: 1
          ignore-unfixed: true

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

  sast:
    name: Static Analysis (semgrep)
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep scan
        run: semgrep --config auto --sarif --output semgrep-results.sarif .

      - name: Upload Semgrep SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep-results.sarif

  iac-scan:
    name: IaC Scan (trivy)
    runs-on: ubuntu-latest
    if: hashFiles('**/Dockerfile') != '' || hashFiles('**/*.tf') != '' || hashFiles('**/k8s/**') != ''
    steps:
      - uses: actions/checkout@v4

      - name: Trivy config scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          severity: HIGH,CRITICAL
          exit-code: 1
```

### Pipeline Design Notes

- **secret-detection** runs first and independently -- secrets are always critical
- **dependency-scan** and **sast** run in parallel for speed
- **iac-scan** only runs when infrastructure files exist
- SARIF output integrates with GitHub Security tab (Code Scanning alerts)
- Weekly scheduled scan catches newly disclosed CVEs in existing dependencies
- `fetch-depth: 0` for gitleaks ensures full git history is scanned

### Local Development Workflow

Run all three tools locally before pushing:

```bash
#!/bin/bash
# scripts/security-check.sh - Run before push

set -euo pipefail

echo "=== Secret Detection (gitleaks) ==="
gitleaks detect --source . --verbose
echo "PASS: No secrets detected"

echo ""
echo "=== Dependency Scan (trivy) ==="
trivy fs --severity HIGH,CRITICAL .
echo "PASS: No high/critical CVEs"

echo ""
echo "=== Static Analysis (semgrep) ==="
semgrep --config auto --error .
echo "PASS: No security findings"

echo ""
echo "All security checks passed."
```
