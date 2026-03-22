# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25, CVSS v4.0) and deep PHP/TYPO3 code scanning with 80+ checkpoints.

## Repo Structure

```
security-audit-skill/
├── skills/security-audit/       # Skill definition, checkpoints, scripts, references
│   ├── SKILL.md                 # Skill metadata and trigger patterns
│   ├── checkpoints.yaml         # 80+ automated security checkpoints
│   ├── scripts/                 # Audit scripts (security-audit.sh, github-security-audit.sh)
│   ├── references/              # 19 reference guides (OWASP, CWE, CVSS, etc.)
│   └── evals/                   # Skill evaluation tests
├── hooks/                       # PreToolUse hook configuration (hooks.json)
├── scripts/                     # Utility scripts (check_risky_command.py)
├── Build/                       # Build utilities
├── .github/workflows/           # CI (ci.yml, lint.yml, release.yml, auto-merge-deps.yml)
├── composer.json                # PHP package definition
├── SECURITY.md                  # Security policy
└── docs/                        # Architecture and planning docs
    └── ARCHITECTURE.md          # Architecture overview
```

## Commands

No Makefile or build scripts defined. Key operations:

- Install PHP dependencies: run `composer` with `install`
- Run PHP project security audit: `bash skills/security-audit/scripts/security-audit.sh`
- Run GitHub repo security audit: `bash skills/security-audit/scripts/github-security-audit.sh`
- Verify harness maturity: `bash scripts/verify-harness.sh --format=text --status`

## Rules

- All vulnerabilities must be scored using CVSS v3.1 or v4.0 methodology
- XML parsing must disable external entities (use `LIBXML_NONET` only)
- Password hashing must use bcrypt or Argon2 (`PASSWORD_ARGON2ID`)
- All SQL must use parameterized queries
- Secrets must never be committed to version control
- File uploads must validate MIME type, not just extension
- Security headers (HSTS, CSP, X-Content-Type-Options) are mandatory
- Follow OWASP Top 10 and CWE Top 25 (2025) standards

## References

- [SKILL.md](skills/security-audit/SKILL.md) -- skill definition and trigger patterns
- [checkpoints.yaml](skills/security-audit/checkpoints.yaml) -- 80+ automated checkpoints
- [references/](skills/security-audit/references/) -- 19 security reference guides
- [SECURITY.md](SECURITY.md) -- security policy
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) -- architecture overview
