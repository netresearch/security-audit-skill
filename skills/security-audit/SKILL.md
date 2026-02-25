---
name: security-audit
description: "Use when conducting security assessments, CVSS scoring, or auditing PHP/TYPO3 projects against OWASP Top 10 and CWE Top 25."
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for any project. Deep automated PHP/TYPO3 code scanning with 80+ checkpoints and 19 reference guides.

## Expertise Areas

- **Vulnerabilities**: XXE, SQL injection, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, type juggling, SSTI, JWT flaws
- **Risk Scoring**: CVSS v3.1 and v4.0 methodology
- **Secure Coding**: Input validation, output encoding, cryptography, session management, authentication
- **Standards**: OWASP Top 10, CWE Top 25, OWASP ASVS, Proactive Controls

## Reference Files

### Core
- `references/owasp-top10.md` - OWASP Top 10 patterns and mitigations
- `references/cwe-top25.md` - CWE Top 25 (2025) coverage map with PHP examples
- `references/xxe-prevention.md` - XXE detection and prevention
- `references/cvss-scoring.md` - CVSS v3.1 and v4.0 scoring methodology
- `references/api-key-encryption.md` - API key encryption at rest (sodium)

### Vulnerability Prevention
- `references/deserialization-prevention.md` - Insecure deserialization prevention
- `references/path-traversal-prevention.md` - Path traversal / directory traversal prevention
- `references/file-upload-security.md` - Secure file upload handling
- `references/input-validation.md` - Input validation, CSP nonces, CORS, encoding

### Secure Architecture
- `references/authentication-patterns.md` - Authentication, session, JWT, MFA patterns
- `references/security-headers.md` - HTTP security headers (HSTS, CSP, etc.)
- `references/security-logging.md` - Security logging and audit trails
- `references/cryptography-guide.md` - PHP sodium, key management, common mistakes

### Framework Security
- `references/framework-security.md` - TYPO3, Symfony, Laravel security patterns

### Modern Threats
- `references/modern-attacks.md` - SSRF, mass assignment, race conditions
- `references/cve-patterns.md` - CVE-derived patterns (type juggling, PHAR, SSTI, JWT, LDAP injection)
- `references/php-security-features.md` - PHP 8.x security features

### DevSecOps
- `references/ci-security-pipeline.md` - SAST, dependency scanning, SBOM, container security
- `references/supply-chain-security.md` - SLSA, Sigstore, OpenSSF Scorecard
- `references/automated-scanning.md` - semgrep, trivy, gitleaks configuration and CI integration

## Quick Patterns

**XML parsing (prevent XXE):**
```php
$doc->loadXML($input, LIBXML_NONET);
```

**SQL (prevent injection):**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
```

**Output (prevent XSS):**
```php
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
```

**API keys (encrypt at rest):**
```php
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encrypted = 'enc:' . base64_encode($nonce . sodium_crypto_secretbox($apiKey, $nonce, $key));
```

**Password hashing:**
```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

## Automated Scanning Tools

Complement manual review with automated scanners. Run these BEFORE manual code review.

### semgrep - Static Analysis (SAST)

Find security vulnerabilities with pre-built rulesets (OWASP, CWE).

```bash
# Auto-detect language, use community rulesets
semgrep --config auto .

# Specific rulesets
semgrep --config p/owasp-top-ten .
semgrep --config p/php-security .
semgrep --config p/javascript .

# CI-friendly output
semgrep --config auto --json --output results.json .

# Scan specific directory
semgrep --config auto src/
```

**When to use:** Every security audit. Catches injection, XSS, hardcoded secrets, insecure crypto patterns automatically.

### trivy - Vulnerability Scanner

Scan dependencies, containers, and IaC for known CVEs.

```bash
# Scan project dependencies (composer.lock, package-lock.json, go.sum)
trivy fs .

# Scan only for HIGH and CRITICAL
trivy fs --severity HIGH,CRITICAL .

# Scan Docker image
trivy image myapp:latest

# Scan IaC (Terraform, Kubernetes)
trivy config .

# JSON output for CI
trivy fs --format json --output trivy-results.json .
```

**When to use:** Before releases, when updating dependencies, when reviewing Dockerfiles or IaC.

### gitleaks - Secret Detection

Detect leaked secrets in git history and staged files.

```bash
# Scan current state
gitleaks detect .

# Scan git history
gitleaks detect --source . --log-opts="--all"

# Pre-commit check (staged files only)
gitleaks protect --staged

# JSON output
gitleaks detect --report-format json --report-path gitleaks.json .
```

**When to use:** Before every commit. Catches API keys, passwords, tokens, private keys.

## Security Checklist

- [ ] `semgrep --config auto` passes with no high-severity findings
- [ ] `trivy fs --severity HIGH,CRITICAL` reports no unpatched CVEs
- [ ] `gitleaks detect` finds no leaked secrets
- [ ] bcrypt/Argon2 for passwords, CSRF tokens on state changes
- [ ] All input validated server-side, parameterized SQL
- [ ] XML external entities disabled (LIBXML_NONET only)
- [ ] Context-appropriate output encoding, CSP configured
- [ ] API keys encrypted at rest (sodium_crypto_secretbox)
- [ ] TLS 1.2+, secrets not in VCS, audit logging
- [ ] No unserialize() with user input, use json_decode()
- [ ] File uploads validated, renamed, stored outside web root
- [ ] Security headers: HSTS, CSP, X-Content-Type-Options
- [ ] Dependencies scanned (composer audit), Dependabot enabled

## Verification

```bash
# PHP project security audit
./scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./scripts/github-security-audit.sh owner/repo
```

---

> **Contributing:** https://github.com/netresearch/security-audit-skill
