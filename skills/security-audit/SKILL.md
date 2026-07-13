---
name: security-audit
description: "Use when conducting security assessments — OWASP Top 10 / API / LLM, CWE Top 25, CVSS scoring — auditing PHP/TYPO3, APIs, frontend, Terraform/K8s/Docker IaC, AWS cloud, AI agent configs, or scanning dependencies."
license: "(MIT AND CC-BY-SA-4.0). See LICENSE-MIT and LICENSE-CC-BY-SA-4.0"
compatibility: "Requires grep, jq, gh CLI."
metadata:
  author: Netresearch DTT GmbH
  version: "2.10.5"
  repository: https://github.com/netresearch/security-audit-skill
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Read Glob Grep
---

# Security Audit Skill

Security audit patterns (OWASP Top 10, LLM Top 10 2025, CWE Top 25 2025, CVSS v4.0), cloud/IaC, GitHub security. 80+ PHP/TYPO3 checkpoints (v14.3 LTS in `typo3-security.md`).

## Expertise Areas

- **Vulnerabilities**: XXE, SQLi, XSS, CSRF, command injection, path traversal, file upload, deserialization, SSRF, SSTI, JWT, type juggling
- **Standards**: OWASP Top 10 / API / LLM (2025), CWE Top 25, CVSS v3.1/v4.0, OWASP ASVS
- **Cloud & IaC**: AWS; Terraform, Kubernetes, Docker, Helm
- **API & Frontend**: REST/GraphQL authZ, rate limits, mass assignment, CSP, DOM-XSS
- **AI Agents**: SKILL.md/AGENTS.md/CLAUDE.md/mcp.json/hooks.json audit; prompt injection; excessive agency

## Reference Files (in `references/`, `.md` implied)

- **Core**: owasp-top10, cwe-top25, xxe-prevention, cvss-scoring, api-key-encryption
- **Prevention**: deserialization-prevention, path-traversal-prevention, file-upload-security, input-validation, error-message-sanitization
- **Architecture**: authentication-patterns, security-headers, security-logging, cryptography-guide, security-invariants
- **Language features** (`*-security-features`): php, python, javascript-typescript, nodejs, go
- **Frameworks** (`*-security`): typo3, typo3-fluid, typo3-typoscript, symfony, react, vue
- **Cloud & IaC**: aws-security, iac-security
- **API & Frontend**: api-security, frontend-security
- **AI Agent**: llm-security (OWASP LLM Top 10 2025)
- **Threats**: modern-attacks, cve-patterns
- **DevSecOps**: ci-security-pipeline, supply-chain-security, automated-scanning, gha-security, git-history-secrets
- **Incident**: supply-chain-incident-response

## Security Checklist

- [ ] `semgrep`/`opengrep`, `trivy fs --severity HIGH,CRITICAL`, `gitleaks` clean
- [ ] bcrypt/Argon2 passwords, CSRF on state changes, TLS 1.2+
- [ ] Server-side input validation; parameterized SQL; XML entities off
- [ ] Output encoding + CSP; no unserialize() on user input
- [ ] API keys encrypted; exception messages sanitized
- [ ] Secrets out of VCS; audit logging on
- [ ] Uploads validated, renamed, outside web root
- [ ] Headers HSTS + X-Content-Type-Options; dependencies scanned

## GitHub Actions Security

- **NEVER** interpolate `${{ inputs.* }}` / `${{ github.event.* }}` in `run:` — use `env:`
- Dependency triage: upgrade > override > dismiss. Full patterns: `references/gha-security.md`.

## Verification

```bash
./scripts/security-audit-dispatcher.sh /path/to/project  # auto-detect stack
./scripts/security-audit.sh /path/to/project             # PHP-only
./scripts/github-security-audit.sh owner/repo            # GH repo
```

Dispatcher detects the stack from indicator files and runs matching `scripts/scanners/*.sh` (13 ecosystems; see `references/` index).

---

> Contributing: https://github.com/netresearch/security-audit-skill
