# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for **any project**. Deep automated PHP/TYPO3 code scanning with 80+ checkpoints, 19 reference guides, and PreToolUse warnings.

## Compatibility

This is an **Agent Skill** following the [open standard](https://agentskills.io) originally developed by Anthropic and released for cross-platform use.

**Supported Platforms:**
- Claude Code (Anthropic)
- Cursor
- GitHub Copilot
- Other skills-compatible AI agents

> Skills are portable packages of procedural knowledge that work across any AI agent supporting the Agent Skills specification.


## Features

- **Vulnerability Assessment**: XXE injection, SQL injection, XSS, CSRF, command injection, path traversal, file upload vulnerabilities, insecure deserialization, SSRF, type juggling, SSTI, JWT flaws, LDAP injection, email header injection, session fixation
- **Risk Scoring**: CVSS v3.1 and v4.0 scoring methodology, risk matrix assessment, impact and likelihood analysis, prioritization frameworks
- **Secure Coding**: Input validation, output encoding, cryptographic best practices (sodium), session management, authentication patterns, security headers
- **Standards Compliance**: OWASP Top 10, CWE Top 25 (2025), OWASP ASVS v4.0, Proactive Controls — applicable to any project
- **PHP/TYPO3 Deep Scanning**: 80+ automated checkpoints, PHP 8.x security features, framework patterns (TYPO3, Symfony, Laravel)
- **DevSecOps**: CI/CD security pipeline, SAST, dependency scanning, supply chain security, SLSA

## Installation

### Option 1: Via Netresearch Marketplace (Recommended)

```bash
/plugin marketplace add netresearch/claude-code-marketplace
```

### Option 2: Download Release

Download the [latest release](https://github.com/netresearch/security-audit-skill/releases/latest) and extract to `~/.claude/skills/security-audit-skill/`

### Option 3: Composer (PHP projects)

```bash
composer require netresearch/agent-security-audit-skill
```

**Requires:** [netresearch/composer-agent-skill-plugin](https://github.com/netresearch/composer-agent-skill-plugin)

## Usage

This skill is automatically triggered when:

- Conducting security assessments
- Identifying vulnerabilities (XXE, SQL injection, XSS, CSRF, command injection)
- Scoring security risks with CVSS v3.1 or v4.0
- Implementing secure coding practices
- Auditing PHP applications for security issues
- Reviewing code for OWASP Top 10 vulnerabilities
- Setting up CI/CD security pipelines

Example queries:
- "Audit this code for XXE vulnerabilities"
- "Check for SQL injection risks"
- "Score this vulnerability using CVSS v4.0"
- "Review authentication implementation for security flaws"
- "Implement secure XML parsing"
- "What security headers should this application set?"

## Structure

```
security-audit-skill/
├── SKILL.md                              # Skill metadata and core patterns
├── SECURITY.md                           # Security policy
├── hooks/
│   └── hooks.json                        # PreToolUse hook configuration
├── scripts/
│   └── check_risky_command.py            # Risky command detection hook
├── skills/security-audit/
│   ├── SKILL.md                          # Skill definition
│   ├── checkpoints.yaml                  # 80+ automated security checkpoints
│   ├── scripts/
│   │   ├── security-audit.sh             # PHP project security audit
│   │   └── github-security-audit.sh      # GitHub repo security audit
│   └── references/
│       ├── cwe-top25.md                  # CWE Top 25 (2025) coverage map
│       ├── owasp-top10.md                # OWASP Top 10 patterns
│       ├── xxe-prevention.md             # XXE detection and prevention
│       ├── cvss-scoring.md               # CVSS v3.1 & v4.0 scoring
│       ├── api-key-encryption.md         # API key encryption (sodium)
│       ├── deserialization-prevention.md  # Insecure deserialization
│       ├── path-traversal-prevention.md  # Path traversal prevention
│       ├── file-upload-security.md       # File upload security
│       ├── authentication-patterns.md    # Auth, session, JWT, MFA
│       ├── security-headers.md           # HTTP security headers
│       ├── security-logging.md           # Security logging & monitoring
│       ├── input-validation.md           # Input validation & encoding
│       ├── cryptography-guide.md         # Cryptographic best practices
│       ├── framework-security.md         # TYPO3/Symfony/Laravel security
│       ├── modern-attacks.md             # SSRF, mass assignment, race conditions
│       ├── cve-patterns.md              # CVE-derived patterns (15 vulnerability types)
│       ├── php-security-features.md      # PHP 8.x security features
│       ├── ci-security-pipeline.md       # CI/CD security tooling
│       └── supply-chain-security.md      # SLSA, signing, OpenSSF
└── .github/
    ├── dependabot.yml                    # Automated dependency updates
    └── workflows/
        ├── release.yml                   # Release automation
        └── ci.yml                        # ShellCheck, Python lint, tests
```

## Expertise Areas

### Vulnerability Assessment
- XXE (XML External Entity) injection detection
- SQL injection pattern recognition
- XSS (Cross-Site Scripting) analysis
- CSRF protection verification
- Command injection detection
- Path traversal prevention
- File upload security
- Insecure deserialization
- SSRF detection
- Authentication/authorization flaws

### Risk Scoring
- CVSS v3.1 scoring methodology
- CVSS v4.0 scoring methodology
- Risk matrix assessment
- Impact and likelihood analysis
- Prioritization frameworks

### Secure Coding
- Input validation patterns
- Output encoding strategies
- Secure configuration
- Cryptographic best practices (sodium)
- Session management
- Authentication patterns (Argon2, JWT, MFA)
- Security headers (HSTS, CSP)

### DevSecOps
- SAST integration (PHPStan, Semgrep, CodeQL)
- Dependency scanning (composer audit, Trivy)
- Supply chain security (SLSA, Sigstore)
- Container security (Hadolint, Trivy)
- SBOM generation (CycloneDX)

## Security Audit Checklist

### Authentication & Authorization
- Password hashing uses bcrypt/Argon2 (PASSWORD_ARGON2ID)
- Session tokens are cryptographically random (random_bytes)
- Session fixation protection enabled (session_regenerate_id)
- CSRF tokens on all state-changing operations
- Authorization checks on all protected resources
- Rate limiting on authentication endpoints

### Input Handling
- All input validated server-side
- Parameterized queries for all SQL
- XML parsing with external entities disabled (LIBXML_NONET only)
- File uploads restricted by type (MIME validation) and size
- Path traversal prevention on file operations
- No unserialize() with user input

### Output Handling
- Context-appropriate output encoding (htmlspecialchars)
- Content-Type headers set correctly
- X-Content-Type-Options: nosniff
- Content-Security-Policy configured
- X-Frame-Options or CSP frame-ancestors set
- Strict-Transport-Security (HSTS) enabled

### Data Protection
- Sensitive data encrypted at rest (sodium_crypto_secretbox)
- TLS 1.2+ for data in transit
- Secrets not in version control
- PII handling compliant with regulations
- Audit logging for sensitive operations

## Related Skills

- **enterprise-readiness-skill**: References this skill for security assessment
- **php-modernization-skill**: Type safety enhances security
- **typo3-testing-skill**: Security test patterns

## License

MIT License - See [LICENSE](LICENSE) for details.

## Credits

Developed and maintained by [Netresearch DTT GmbH](https://www.netresearch.de/).

---

**Made with love for Open Source by [Netresearch](https://www.netresearch.de/)**
