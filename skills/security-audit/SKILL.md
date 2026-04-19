---
name: security-audit
description: "Use when conducting security assessments — OWASP Top 10, OWASP API Top 10, OWASP LLM Top 10, CWE Top 25, or CVSS scoring — auditing PHP/TYPO3, REST/GraphQL APIs, frontend, Terraform/Kubernetes/Docker IaC, AWS/Azure/GCP cloud, or AI agent configs (SKILL.md/AGENTS.md/CLAUDE.md/mcp.json/hooks.json) for vulnerabilities, or scanning dependencies."
license: "(MIT AND CC-BY-SA-4.0). See LICENSE-MIT and LICENSE-CC-BY-SA-4.0"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: Netresearch DTT GmbH
  version: "2.6.0"
  repository: https://github.com/netresearch/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, LLM Top 10 2025, CWE Top 25 2025, CVSS v4.0), cloud & IaC checks, GitHub project security. 80+ PHP/TYPO3 checkpoints. See `references/`.

## Expertise Areas

- **Vulnerabilities**: XXE, SQLi, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, type juggling, SSTI, JWT
- **Secure Coding**: input validation, output encoding, cryptography, authentication, error sanitization
- **Standards**: OWASP Top 10 / API / LLM (2025), CWE Top 25, CVSS v3.1/v4.0, OWASP ASVS
- **Cloud & IaC**: AWS, Azure, GCP; Terraform, Kubernetes, Docker, Helm, Pulumi
- **API & Frontend**: REST/GraphQL authZ, rate limits, mass assignment, CSP, SRI, DOM-XSS
- **AI Agents**: SKILL.md/AGENTS.md/CLAUDE.md/mcp.json/hooks.json audit; prompt injection; excessive agency

## Reference Files (in `references/`)

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `xxe-prevention.md`, `cvss-scoring.md`, `api-key-encryption.md`
- **Prevention**: `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`, `error-message-sanitization.md`
- **Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Framework**: `framework-security.md` (TYPO3, Symfony, Laravel)
- **API & Frontend**: `api-security.md`, `frontend-security.md`
- **Cloud & IaC**: `aws-security.md`, `azure-security.md`, `gcp-security.md`, `iac-security.md`
- **AI Agent**: `llm-security.md` (OWASP LLM Top 10 2025)
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `php-security-features.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md`, `gha-security.md`
- **Incident**: `supply-chain-incident-response.md`

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

**Secure randomness:**
```php
$token = bin2hex(random_bytes(32));
```

Scanners (semgrep/opengrep, trivy, gitleaks): see `references/automated-scanning.md`.

## Security Checklist

- [ ] `semgrep --config auto` (or `opengrep`), `trivy fs --severity HIGH,CRITICAL`, `gitleaks detect` all clean
- [ ] bcrypt/Argon2 passwords, CSRF tokens on state changes
- [ ] Input validated server-side, parameterized SQL
- [ ] XML external entities disabled (LIBXML_NONET only)
- [ ] Output encoding, CSP configured
- [ ] API keys encrypted at rest (sodium_crypto_secretbox); exception messages sanitized
- [ ] TLS 1.2+, secrets not in VCS, audit logging
- [ ] No unserialize() with user input
- [ ] File uploads validated, renamed, outside web root
- [ ] Headers: HSTS, X-Content-Type-Options; dependencies scanned

## GitHub Actions Security

- **NEVER** interpolate `${{ inputs.* }}` or `${{ github.event.* }}` in `run:` — use `env:`
- Dependency triage: upgrade > override > dismiss with rationale
- See `references/gha-security.md`

## Verification

```bash
./scripts/security-audit.sh /path/to/project       # PHP project
./scripts/github-security-audit.sh owner/repo      # GitHub repo
```

---

> **Contributing:** https://github.com/netresearch/security-audit-skill
