<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->

# Security Audit Skill

Security audit patterns (OWASP Top 10, CWE Top 25 2025, CVSS v4.0) and GitHub project security checks for **any project**. Deep automated PHP/TYPO3 code scanning with 80+ checkpoints, 41 reference guides, and PreToolUse warnings.

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

### Marketplace (Recommended)

Add the [Netresearch marketplace](https://github.com/netresearch/claude-code-marketplace) once, then browse and install skills:

```bash
# Claude Code
/plugin marketplace add netresearch/claude-code-marketplace
/plugin install security-audit@netresearch-claude-code-marketplace
```

### Without a marketplace

Since Claude Code 2.1.157 a plugin directory under your personal skills directory loads on its own, including the hooks this repo ships:

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/netresearch/security-audit-skill.git \
  ~/.claude/skills/security-audit
```

It loads as `security-audit@skills-dir` on the next session. Update with `git -C ~/.claude/skills/security-audit pull` and start a new session; remove it by deleting the directory. This route has no `claude plugin update`.

### npx ([skills.sh](https://skills.sh))

Install with any [Agent Skills](https://agentskills.io)-compatible agent:

```bash
npx skills add https://github.com/netresearch/security-audit-skill --skill security-audit
```

> **Limitation:** `npx skills` installs `SKILL.md`-based skills only. This repo also ships `hooks`, which it does not install — use the marketplace or the skills directory for those.

### Download Release

Download the [latest release](https://github.com/netresearch/security-audit-skill/releases/latest) and extract to your agent's skills directory.

### Git Clone

```bash
git clone https://github.com/netresearch/security-audit-skill.git
```

### Composer (PHP Projects)

```bash
composer require netresearch/security-audit-skill
```

Requires [netresearch/composer-agent-skill-plugin](https://github.com/netresearch/composer-agent-skill-plugin).

### npm (Node Projects)

```bash
npm install --save-dev \
  @netresearch/agent-skill-coordinator \
  github:netresearch/security-audit-skill
```

Requires [@netresearch/agent-skill-coordinator](https://github.com/netresearch/node-agent-skill-coordinator), which discovers the skill in `node_modules` and registers it in `AGENTS.md` via a `postinstall` hook. For pnpm, also allowlist the coordinator's postinstall:

```json
{
  "pnpm": {
    "onlyBuiltDependencies": ["@netresearch/agent-skill-coordinator"]
  }
}
```

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
├── SECURITY.md                           # Security policy
├── hooks/
│   └── hooks.json                        # PreToolUse hook configuration
├── scripts/
│   ├── check_risky_command.py            # Risky command detection hook
│   ├── validate_checkpoints.py           # checkpoints.yaml structure check
│   └── test_*.py                         # Tests (run by ci.yml)
├── skills/security-audit/
│   ├── SKILL.md                          # Skill definition
│   ├── checkpoints.yaml                  # 80+ automated security checkpoints
│   ├── scripts/
│   │   ├── security-audit-dispatcher.sh  # Detects the stack, runs the matching scanners
│   │   ├── scanners/                     # Per-ecosystem scanner modules
│   │   ├── security-audit.sh             # PHP project security audit
│   │   └── github-security-audit.sh      # GitHub repo security audit
│   └── references/                       # 41 reference guides
└── .github/
    └── workflows/
        ├── ci.yml                        # Python tests
        ├── lint.yml                      # Skill validation, linters, ShellCheck
        ├── security.yml                  # Secret, workflow, dependency and SAST scans
        └── release.yml                   # Release automation
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

## Development

Run the tests from the repository root with [uv](https://docs.astral.sh/uv/):

```bash
uv run scripts/test_risky_patterns.py      # hook patterns: expected matches and non-matches
uv run scripts/test_check_risky_command.py # hook input and output as Claude Code uses them
uv run scripts/test_audit_scripts.py       # audit scripts against fixtures (needs bash 4+, GNU grep, jq)
uv run scripts/validate_checkpoints.py     # checkpoints.yaml structure and unique IDs
pre-commit run --all-files                 # the linters CI runs in Skill Validation
```

CI runs the three test scripts on Python 3.12 and 3.13 (`.github/workflows/ci.yml`). A failing test prints its name and the assertion that failed; the test scripts exit non-zero. A change to the hook or the audit scripts comes with a test in these files.

## Dependencies

- **Using the skill:** the audit scripts need bash 4+, GNU grep (for `grep -P`) and `find`; `github-security-audit.sh` needs the `gh` CLI. The hook needs `python3` and uses only its standard library. `composer`, `npm`, `govulncheck` and `trufflehog` are optional: a scanner calls them only when `command -v` finds them, and the skill does not install them.
- **Installing the skill:** `composer.json` requires `netresearch/composer-agent-skill-plugin` (`^2.0`); `package.json` declares `@netresearch/agent-skill-coordinator` as a peer dependency. The repository commits no lock file for either; the consuming project resolves them.
- **Development and CI:** `scripts/validate_checkpoints.py` declares PyYAML as inline script metadata, which `uv run` installs; the test scripts use the standard library. The pre-commit hooks are pinned by `rev:` in `.pre-commit-config.yaml`. The workflows call reusable workflows from `netresearch/skill-repo-skill`, `netresearch/.github` and `netresearch/typo3-ci-workflows` at `@main`; the third-party actions inside those are pinned to commit SHAs there.
- **Tracking:** Renovate (`renovate.json`, `config:recommended` with pre-commit updates enabled) opens update pull requests, and `.github/workflows/auto-merge-deps.yml` hands them to the organisation's auto-merge workflow. On pull requests, dependency review and Composer Audit check the dependencies (`.github/workflows/security.yml`). New dependencies must meet the licence and vulnerability rules of the organisation's security policy linked below.

## Governance and policies

This repository follows the Netresearch organisation policies:

- [Governance](https://github.com/netresearch/.github/blob/main/GOVERNANCE.md): ownership, roles, how decisions are made and disputes resolved, and continuity.
- [Roadmap](https://github.com/netresearch/.github/blob/main/ROADMAP.md): planned and explicitly excluded work for the coming year.
- [Handling of dependency and code analysis findings](https://github.com/netresearch/.github/blob/main/SECURITY.md#handling-of-dependency-and-code-analysis-findings): thresholds, deadlines and the exception process for dependency (SCA) and static analysis (SAST) findings.
- [Secret management](https://github.com/netresearch/.github/blob/main/SECURITY.md#secret-management): how CI and release credentials are stored, accessed and rotated.
- [Access roster](https://github.com/netresearch/.github/blob/main/docs/access-roster.md): who holds administrative access to this repository and the organisation.

The architecture of this skill (actors, components, data flows) is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and its security assurance case (threat model, trust boundaries, countermeasures and limits) in [docs/SECURITY-ASSURANCE.md](docs/SECURITY-ASSURANCE.md). Supported versions and vulnerability reporting: [SECURITY.md](SECURITY.md).

Checks that run on every pull request to `main` in this repository:

- **Security** (`.github/workflows/security.yml`): Betterleaks secret scanning, zizmor workflow analysis, dependency review, and, through the `typo3-ci-workflows` security reusable, Composer Audit and Opengrep SAST (`--config auto --error --severity WARNING`).
- **Skill Validation** (`.github/workflows/lint.yml`): skill structure, plugin manifest sync, markdownlint, yamllint, actionlint, JSON syntax, version checks, ShellCheck at the validator's default severity `error`, ruff and the checkpoint schema. The pre-commit hook runs ShellCheck at `style`.
- **CI** (`.github/workflows/ci.yml`): the tests listed under Development.
- **Eval Validation**, **Harness Verification**, the template drift check and **PR Quality Gates**.
- **CodeQL** through GitHub's default setup, a repository setting.

Which of these checks must pass before a merge is set in the repository's branch protection, not in this repository.

## License

This project uses split licensing:

- **Code** (scripts, workflows, configs): [MIT](LICENSE-MIT)
- **Content** (skill definitions, documentation, references): [CC-BY-SA-4.0](LICENSE-CC-BY-SA-4.0)

See the individual license files for full terms.
## Credits

Developed and maintained by [Netresearch DTT GmbH](https://www.netresearch.de/).

---

**Made with love for Open Source by [Netresearch](https://www.netresearch.de/)**
