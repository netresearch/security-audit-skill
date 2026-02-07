# CI/CD Security Pipeline for PHP Projects

A comprehensive reference for integrating security scanning tools into CI/CD pipelines for PHP applications.

## Overview

A defense-in-depth CI pipeline catches different vulnerability classes at different stages. No single tool covers everything.

```
Source Code ──> Dependencies ──> Static Analysis ──> Secrets ──> Container ──> SBOM
   │                │                  │                │           │            │
   ▼                ▼                  ▼                ▼           ▼            ▼
 Semgrep      composer audit       PHPStan          Gitleaks    Trivy      CycloneDX
 CodeQL       Trivy (deps)         Psalm (taint)    TruffleHog  Hadolint
              npm audit            Semgrep
```

## Dependency Scanning

### composer audit (Built-in)

Available since Composer 2.4. Checks installed dependencies against the PHP Security Advisories Database (Packagist).

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 06:00 UTC

jobs:
  composer-audit:
    name: Composer Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          tools: composer

      - name: Install dependencies
        run: composer install --no-interaction --no-progress

      - name: Run composer audit
        run: composer audit --format=json | tee audit-results.json

      - name: Upload audit results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: composer-audit
          path: audit-results.json
```

**Key options:**
- `composer audit` - Check for known vulnerabilities
- `composer audit --format=json` - Machine-readable output
- `composer audit --locked` - Check against lock file (faster, no install needed)
- `composer audit --abandoned` - Also report abandoned packages

### Trivy (Multi-Purpose Scanner)

Trivy scans dependencies, containers, IaC files, and checks licenses. It is a strong starting point because a single tool covers multiple categories.

```yaml
  trivy-scan:
    name: Trivy Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

**Trivy scan types:**
- `fs` - Filesystem (composer.lock, package-lock.json, Dockerfile, Terraform, etc.)
- `image` - Container images
- `repo` - Remote git repository
- `config` - IaC misconfigurations only

### npm audit (Frontend Assets)

If your PHP project includes frontend assets managed by npm.

```yaml
  npm-audit:
    name: npm Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Install dependencies
        run: npm ci

      - name: Run npm audit
        run: npm audit --audit-level=high
```

## SAST (Static Application Security Testing)

### Semgrep with PHP Rules

Semgrep is a fast, pattern-matching SAST tool with community-maintained PHP rulesets. It finds injection flaws, insecure configurations, and framework-specific issues.

```yaml
  semgrep:
    name: Semgrep SAST
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config "p/php" \
            --config "p/owasp-top-ten" \
            --config "p/security-audit" \
            --sarif \
            --output semgrep-results.sarif \
            .

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep-results.sarif
```

**Custom Semgrep rules for PHP:**

```yaml
# .semgrep/custom-rules.yml
rules:
  - id: php-dangerous-unserialize
    pattern: unserialize($INPUT)
    message: >
      unserialize() with untrusted input can lead to object injection attacks.
      Use json_decode() or implement allowed_classes parameter.
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']
      owasp: ['A08:2021']

  - id: php-missing-htmlspecialchars-flags
    pattern: htmlspecialchars($INPUT)
    fix: htmlspecialchars($INPUT, ENT_QUOTES | ENT_HTML5, 'UTF-8')
    message: >
      htmlspecialchars() called without ENT_QUOTES flag. Single quotes will not be encoded.
    languages: [php]
    severity: WARNING

  - id: php-sql-concat
    patterns:
      - pattern: |
          $QUERY = "..." . $INPUT . "...";
          ...
          $DB->query($QUERY);
      - metavariable-regex:
          metavariable: $QUERY
          regex: .*(SELECT|INSERT|UPDATE|DELETE).*
    message: String concatenation in SQL query. Use prepared statements.
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']
```

### CodeQL for PHP

GitHub's CodeQL provides deep semantic analysis. It understands data flow and can trace taint from sources (user input) to sinks (dangerous functions).

```yaml
  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: javascript  # CodeQL PHP support via extractors
          # For PHP: CodeQL has experimental PHP support
          # Consider using Semgrep as primary PHP SAST instead

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
```

**Note:** CodeQL's PHP support is less mature than its support for JavaScript, Python, and Java. For PHP projects, Semgrep and Psalm taint analysis typically provide better coverage.

### PHPStan (Security-Focused Rules)

PHPStan at higher rule levels catches type-safety issues that have security implications. Combine with security-focused extensions.

```yaml
  phpstan:
    name: PHPStan Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-interaction

      - name: Run PHPStan
        run: vendor/bin/phpstan analyse --error-format=sarif > phpstan-results.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: phpstan-results.sarif
```

**Security-relevant PHPStan configuration:**

```neon
# phpstan.neon
parameters:
    level: max  # Level 9: strictest type checking

    # Security-sensitive checks enabled at higher levels:
    # Level 5+: Checks argument types in function calls (prevents type confusion)
    # Level 6+: Reports missing typehints (forces explicit contracts)
    # Level 7+: Checks union type handling (prevents null reference)
    # Level 8+: Reports nullable method calls
    # Level 9:  Strict mixed type checking (prevents untyped data flow)

includes:
    - vendor/phpstan/phpstan-strict-rules/rules.neon
    # - vendor/phpstan/phpstan-deprecation-rules/rules.neon
```

### Psalm (Taint Analysis)

Psalm's taint analysis tracks data flow from user-controlled sources to security-sensitive sinks. This is one of the most powerful PHP-specific security analysis capabilities.

```yaml
  psalm-taint:
    name: Psalm Taint Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-interaction

      - name: Run Psalm taint analysis
        run: vendor/bin/psalm --taint-analysis --output-format=sarif > psalm-taint.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: psalm-taint.sarif
```

**Psalm taint sources and sinks:**

```php
<?php

// Psalm automatically recognizes these as taint sources:
// $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, file_get_contents('php://input')

// And these as taint sinks:
// echo, print, PDO::query, mysqli_query, shell_exec, header, file_put_contents

// Custom taint annotations:
/**
 * @psalm-taint-source input
 */
function getUserInput(): string
{
    return file_get_contents('php://input');
}

/**
 * @psalm-taint-sink sql $query
 */
function executeQuery(string $query): void
{
    // ...
}

/**
 * @psalm-taint-escape sql
 */
function sanitizeForSql(string $input): string
{
    // Psalm trusts this function removes SQL taint
    return addslashes($input);
}
```

### SARIF Upload to GitHub

All tools that output SARIF (Static Analysis Results Interchange Format) can upload findings to GitHub's Security tab.

```yaml
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()  # Upload even if scan found issues
        with:
          sarif_file: results.sarif
          category: tool-name  # Distinguishes findings from different tools
```

**Requirements:**
- Repository must have GitHub Advanced Security enabled (free for public repos)
- Workflow needs `security-events: write` permission
- SARIF file must be valid (max 10 MB, max 5000 results)

## Secret Scanning

### GitHub Native Secret Scanning + Push Protection

GitHub's built-in secret scanning detects leaked credentials in commits. Push protection blocks pushes containing detected secrets before they reach the repository.

**Setup (via repository settings):**
1. Settings > Code security and analysis
2. Enable "Secret scanning"
3. Enable "Push protection"

No workflow configuration needed -- this runs automatically on all pushes.

**Custom patterns (organization-level):**
```
# Settings > Code security > Secret scanning > Custom patterns
Pattern name: Internal API Key
Pattern: INTERNAL_[A-Z]+_KEY_[a-zA-Z0-9]{32,}
```

### Gitleaks (Pre-commit and CI)

Gitleaks scans git history for secrets. Use it as both a pre-commit hook and a CI check.

```yaml
  gitleaks:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for scanning

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Pre-commit hook configuration:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
```

**Custom Gitleaks rules:**

```toml
# .gitleaks.toml
title = "Custom Gitleaks Config"

[[rules]]
id = "typo3-encryption-key"
description = "TYPO3 Encryption Key"
regex = '''encryptionKey\s*=\s*['"][a-f0-9]{96}['"]'''
secretGroup = 0

[[rules]]
id = "php-database-password"
description = "PHP Database Password in Configuration"
regex = '''(?i)(db_password|database_password|DB_PASS)\s*=\s*['"][^'"]{8,}['"]'''
secretGroup = 0

[allowlist]
paths = [
    '''\.gitleaks\.toml$''',
    '''tests/fixtures/''',
]
```

### TruffleHog

TruffleHog provides deep scanning with verification -- it checks whether detected secrets are actually valid.

```yaml
  trufflehog:
    name: TruffleHog Secret Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
```

## SBOM Generation

### CycloneDX for PHP

Software Bill of Materials (SBOM) documents all dependencies in your project for compliance and vulnerability tracking.

```yaml
  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          tools: composer

      - name: Install dependencies
        run: composer install --no-interaction

      - name: Install CycloneDX Composer plugin
        run: composer require --dev cyclonedx/cyclonedx-php-composer

      - name: Generate SBOM
        run: composer make-bom --output-file=sbom.json --spec-version=1.5

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### SPDX Format

For organizations requiring SPDX format instead of CycloneDX.

```yaml
      - name: Generate SPDX SBOM with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'spdx-json'
          output: 'sbom-spdx.json'
```

## Container Security

### Hadolint for Dockerfile Linting

Hadolint checks Dockerfiles for best practices and security issues.

```yaml
  hadolint:
    name: Dockerfile Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: warning
```

**Security-relevant Hadolint rules:**
- `DL3002` - Do not switch to root USER (last user should not be root)
- `DL3003` - Use WORKDIR instead of `cd`
- `DL3006` - Always tag the image version (no `FROM php:latest`)
- `DL3008` - Pin package versions in apt-get
- `DL3018` - Pin package versions in apk add
- `DL3047` - Avoid `wget`; use `ADD` or `curl` with checksum verification

### Trivy Container Scanning

```yaml
  container-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t myapp:scan .

      - name: Run Trivy container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:scan'
          format: 'sarif'
          output: 'container-scan.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload container scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'container-scan.sarif'
```

### Distroless/Slim Base Images

Minimize the attack surface by using minimal base images.

```dockerfile
# VULNERABLE: Full OS image with unnecessary packages
FROM php:8.4-apache

# BETTER: Alpine-based minimal image
FROM php:8.4-fpm-alpine

# BEST: Multi-stage build with minimal runtime
FROM php:8.4-cli-alpine AS builder
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader

FROM php:8.4-fpm-alpine AS runtime
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder /app/vendor /app/vendor
COPY . /app
USER appuser
```

## Recommended Minimal Pipeline

For projects just starting with CI security, this three-tool combination provides strong baseline coverage with minimal setup.

```yaml
# .github/workflows/security.yml
name: Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly

permissions:
  contents: read
  security-events: write

jobs:
  # 1. Known vulnerabilities in dependencies
  dependency-check:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-interaction --no-progress

      - name: Composer audit
        run: composer audit

  # 2. Code quality and type safety
  static-analysis:
    name: PHPStan Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-interaction --no-progress

      - name: Run PHPStan
        run: vendor/bin/phpstan analyse

  # 3. Multi-purpose vulnerability scan
  trivy:
    name: Trivy Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'sarif'
          output: 'trivy.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy.sarif'
```

### Why These Three?

| Tool | Covers | False Positive Rate | Setup Effort |
|------|--------|---------------------|--------------|
| composer audit | Known CVEs in PHP dependencies | Very low | Minimal |
| PHPStan (level max) | Type safety, null reference, logic errors | Low | Needs config |
| Trivy | Dependencies, containers, IaC, licenses | Low | Minimal |

### Expanding the Pipeline

Add these tools as your security posture matures:

| Stage | Add | When |
|-------|-----|------|
| 2 | Semgrep | When you need pattern-based vulnerability detection |
| 2 | Psalm taint analysis | When you need data flow analysis |
| 3 | Gitleaks | When you need secret scanning in git history |
| 3 | CycloneDX SBOM | When compliance requires dependency inventory |
| 4 | Container scanning | When deploying containerized applications |
| 4 | SLSA provenance | When you need supply chain attestations |

## Detection Patterns for CI Configuration Audit

```
# Find workflows missing security scanning
# Check: .github/workflows/*.yml should contain at least one security job

# Find unpinned GitHub Actions (use SHA instead of tags)
uses:\s+\w+/\w+@v\d+

# Find overly permissive workflow permissions
permissions:\s*write-all
permissions:\s*\n\s+contents:\s+write

# Find missing schedule trigger (should run periodic scans)
# Workflows should have: schedule: - cron:

# Find missing SARIF upload (findings should go to GitHub Security tab)
# Security scan jobs should include: github/codeql-action/upload-sarif
```

## Related References

- `supply-chain-security.md` - SLSA, Sigstore, OpenSSF Scorecard
- `owasp-top10.md` - Vulnerability patterns these tools detect
- `php-security-features.md` - Language features PHPStan/Psalm enforce
