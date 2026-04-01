---
name: security-audit
description: "Use when conducting security assessments, OWASP/CWE audits, CVSS scoring, auditing PHP/TYPO3 projects for vulnerabilities, scanning dependencies, or reviewing code for security concerns."
license: "(MIT AND CC-BY-SA-4.0). See LICENSE-MIT and LICENSE-CC-BY-SA-4.0"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: Netresearch DTT GmbH
  version: "2.5.0"
  repository: https://github.com/netresearch/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks. Deep PHP/TYPO3 code scanning with 80+ checkpoints and 19 reference guides.

## Expertise Areas

- **Vulnerabilities**: XXE, SQLi, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, type juggling, SSTI, JWT flaws, insecure randomness
- **Risk Scoring**: CVSS v3.1 and v4.0
- **Secure Coding**: Input validation, output encoding, cryptography, session management, authentication, error sanitization
- **Standards**: OWASP Top 10, CWE Top 25, OWASP ASVS, Proactive Controls
- **Container/Docker**: Root user detection, file permissions, image pinning, non-root users

## Reference Files

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `xxe-prevention.md`, `cvss-scoring.md`, `api-key-encryption.md`
- **Vulnerability Prevention**: `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`
- **Error Handling**: `error-message-sanitization.md` (API key redaction, exception hierarchy)
- **Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Framework Security**: `framework-security.md` (TYPO3, Symfony, Laravel)
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `php-security-features.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md`, `gha-security.md`
- **Incident Response**: `supply-chain-incident-response.md`

All files located in `references/`.

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

**Secure randomness (NOT mt_rand/rand):**
```php
$token = bin2hex(random_bytes(32));
```

For scanning tools (semgrep, trivy, gitleaks), see `references/automated-scanning.md`.

## Security Checklist

- [ ] `semgrep --config auto` — no high-severity findings
- [ ] `trivy fs --severity HIGH,CRITICAL` — no unpatched CVEs
- [ ] `gitleaks detect` — no leaked secrets
- [ ] bcrypt/Argon2 for passwords, CSRF tokens on state changes
- [ ] All input validated server-side, parameterized SQL
- [ ] XML external entities disabled (LIBXML_NONET only)
- [ ] Context-appropriate output encoding, CSP configured
- [ ] API keys encrypted at rest (sodium_crypto_secretbox)
- [ ] Exception messages sanitized (no API keys, paths, or SQL in responses)
- [ ] TLS 1.2+, secrets not in VCS, audit logging
- [ ] No unserialize() with user input, use json_decode()
- [ ] File uploads validated, renamed, stored outside web root
- [ ] Security headers: HSTS, X-Content-Type-Options set
- [ ] Dependencies scanned (composer audit), Dependabot enabled

## GitHub Actions Security

- **NEVER** interpolate `${{ inputs.* }}` or `${{ github.event.* }}` in `run:` blocks — use `env:` instead
- Dependency triage: upgrade > override > dismiss with rationale
- See `references/gha-security.md` for patterns and examples

## Verification

```bash
# PHP project security audit
./scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./scripts/github-security-audit.sh owner/repo
```

---

> **Contributing:** https://github.com/netresearch/security-audit-skill
