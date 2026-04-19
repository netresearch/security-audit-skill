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

Security audit patterns (OWASP Top 10, LLM Top 10 2025, CWE Top 25 2025, CVSS v4.0), cloud/IaC checks, GitHub project security. 80+ PHP/TYPO3 checkpoints.

## Expertise Areas

- **Vulnerabilities**: XXE, SQLi, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, SSTI, JWT
- **Standards**: OWASP Top 10 / API / LLM (2025), CWE Top 25, CVSS v3.1/v4.0, OWASP ASVS
- **Cloud & IaC**: AWS, Azure, GCP; Terraform, Kubernetes, Docker, Helm, Pulumi
- **API & Frontend**: REST/GraphQL authZ, rate limits, mass assignment, CSP, SRI, DOM-XSS
- **AI Agents**: SKILL.md/AGENTS.md/CLAUDE.md/mcp.json/hooks.json audit; prompt injection; excessive agency

## Reference Files (in `references/`, `.md` implied)

- **Core**: owasp-top10, cwe-top25, xxe-prevention, cvss-scoring, api-key-encryption
- **Prevention**: deserialization-prevention, path-traversal-prevention, file-upload-security, input-validation, error-message-sanitization
- **Architecture**: authentication-patterns, security-headers, security-logging, cryptography-guide
- **Language features** (`*-security-features`): php, python, javascript-typescript, nodejs, java, csharp, go, rust, ruby
- **Frameworks** (`*-security`): typo3, typo3-fluid, typo3-typoscript, symfony, laravel, django, flask, fastapi, spring, dotnet, blazor, rails, gin, react, vue, angular, nextjs, nuxt, express, nestjs
- **Mobile**: android-sdk-security, ios-sdk-security
- **Cloud & IaC**: aws-security, azure-security, gcp-security, iac-security
- **API & Frontend**: api-security, frontend-security
- **AI Agent**: llm-security (OWASP LLM Top 10 2025)
- **Shared**: framework-security
- **Modern Threats**: modern-attacks, cve-patterns
- **DevSecOps**: ci-security-pipeline, supply-chain-security, automated-scanning, gha-security
- **Incident**: supply-chain-incident-response

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

**Password hashing + randomness:**
```php
$hash  = password_hash($password, PASSWORD_ARGON2ID);
$token = bin2hex(random_bytes(32));   // never mt_rand/rand
```

Scanners (semgrep/opengrep, trivy, gitleaks): see `references/automated-scanning.md`.

## Security Checklist

- [ ] `semgrep` (or `opengrep`), `trivy fs --severity HIGH,CRITICAL`, `gitleaks detect` clean
- [ ] bcrypt/Argon2 passwords, CSRF tokens on state changes, TLS 1.2+
- [ ] Input validated server-side; parameterized SQL; XML entities off (LIBXML_NONET)
- [ ] Output encoding + CSP; no unserialize() on user input
- [ ] API keys encrypted (sodium_crypto_secretbox); exception messages sanitized
- [ ] Secrets out of VCS; audit logging enabled
- [ ] File uploads validated, renamed, outside web root
- [ ] Headers: HSTS, X-Content-Type-Options; dependencies scanned

## GitHub Actions Security

- **NEVER** interpolate `${{ inputs.* }}` / `${{ github.event.* }}` in `run:` — use `env:`
- Dependency triage: upgrade > override > dismiss with rationale
- See `references/gha-security.md`

## Verification

```bash
./scripts/security-audit.sh /path/to/project    # PHP
./scripts/github-security-audit.sh owner/repo   # GitHub
```

---

> Contributing: https://github.com/netresearch/security-audit-skill
