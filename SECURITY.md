# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (current) | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in
this project, please report it responsibly.

### Preferred Method: GitHub Private Vulnerability Reporting

Report vulnerabilities through [GitHub Private Vulnerability Reporting](https://github.com/netresearch/security-audit-skill/security/advisories/new).
This creates a private advisory visible only to repository maintainers until a
fix is available.

### Security Contact

For sensitive disclosures or if GitHub PVR is unavailable, contact us directly:

**Email:** security@netresearch.de

Encrypt sensitive reports using our PGP key if available on the Netresearch website.

## Response SLAs

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours of report |
| Initial assessment | Within 5 business days |
| Fix development | Based on severity (see below) |
| Public disclosure | Coordinated, up to 90 days |

### Severity-Based Fix Timelines

| Severity | Target Fix Timeline |
|----------|---------------------|
| Critical | 72 hours |
| High | 1 week |
| Medium | 2 weeks |
| Low | Next release cycle |

## Coordinated Disclosure

We follow a 90-day coordinated disclosure timeline:

1. **Day 0:** Vulnerability reported.
2. **Day 1-2:** Report acknowledged.
3. **Day 1-5:** Initial assessment and severity classification.
4. **Day 5-90:** Fix developed, tested, and released.
5. **Day 90:** Public disclosure, regardless of fix status (with reporter agreement).

If we need additional time beyond 90 days, we will communicate this to the
reporter with a clear justification and revised timeline.

## Scope

### In Scope

The following components are covered by this security policy:

- **Skill definitions** (`skills/security-audit/SKILL.md`, reference documents)
- **Scripts** (`scripts/check_risky_command.py`, `scripts/security-audit.sh`)
- **Hooks** (`hooks/hooks.json`, PreToolUse hook configuration)
- **CI/CD workflows** (`.github/workflows/`)
- **Package metadata** (`composer.json`)

### Out of Scope

The following are NOT covered by this security policy:

- **Third-party dependencies** (report to upstream maintainers)
- **The AI agent itself** (Claude, Cursor, Copilot -- report to the respective vendor)
- **User-generated content** from using the skill in audits
- **Infrastructure** where the skill is deployed (your local machine, CI runners)

## Security Measures in Place

This project implements the following security measures:

### PreToolUse Hook

A `PreToolUse` hook (`scripts/check_risky_command.py`) inspects commands before
execution, detecting patterns associated with:

- Destructive file operations (`rm -rf /`, `chmod 777`)
- Network exfiltration (`curl | sh`, `wget` with suspicious targets)
- Credential exposure (hardcoded secrets in commands)
- Privilege escalation (`sudo` with dangerous arguments)

### OWASP-Aligned Detection Patterns

Reference documents and audit scripts are aligned with:

- OWASP Top 10 (2021)
- CWE Top 25
- OWASP Application Security Verification Standard (ASVS)

### Secure Defaults

- All PHP code examples use `declare(strict_types=1)`.
- Vulnerable code examples are clearly marked with `// VULNERABLE - DO NOT USE`.
- Secure alternatives are provided with `// SECURE:` annotations.

### Known Limitations

- **Hook integrity:** The PreToolUse hook script (`scripts/check_risky_command.py`) has
  no post-installation integrity verification. If an attacker gains write access to the
  installed skill directory, they could modify the hook to suppress warnings. Users
  should monitor file modifications in their skill installation directory.
- **Hook scope:** The PreToolUse hook only intercepts the `Bash` tool. Commands executed
  via other tool types (e.g., writing a script file and executing it separately) are not
  inspected by the hook.

## Recognition

We credit responsible reporters in release notes (unless anonymity is requested).
If you report a valid vulnerability, we will:

- Acknowledge your contribution in the release notes for the fix.
- Add your name (or alias) to a CONTRIBUTORS section if desired.
- Provide a reference letter or public acknowledgment upon request.

## Questions

For non-vulnerability security questions about this project, open a
[GitHub Discussion](https://github.com/netresearch/security-audit-skill/discussions)
or contact info@netresearch.de.
