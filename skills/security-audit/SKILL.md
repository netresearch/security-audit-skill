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

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `xxe-prevention.md`, `cvss-scoring.md`, `api-key-encryption.md`
- **Vulnerability Prevention**: `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`
- **Secure Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Framework Security**: `framework-security.md` (TYPO3, Symfony, Laravel)
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `php-security-features.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md`

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

For automated scanning tools (semgrep, trivy, gitleaks), see `references/automated-scanning.md`.

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
