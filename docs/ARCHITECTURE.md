# Architecture

## Overview

The security-audit-skill is an AI agent skill that provides security audit capabilities following the [Agent Skills](https://agentskills.io) open standard. It delivers vulnerability detection, risk scoring, and secure coding guidance through skill definitions, automated checkpoints, and reference documentation.

## Components

### Skill Definition (`skills/security-audit/`)

- **SKILL.md**: Entry point loaded by AI agents. Contains trigger patterns, procedural instructions, and links to references.
- **checkpoints.yaml**: 80+ security checkpoints organized by category (authentication, input handling, output encoding, data protection, DevSecOps). Each checkpoint has severity, detection patterns, and remediation guidance.
- **references/**: 19 standalone reference guides covering OWASP Top 10, CWE Top 25, CVSS scoring, framework-specific security (TYPO3/Symfony/Laravel), and supply chain security.

### Audit Scripts (`skills/security-audit/scripts/`)

- **security-audit.sh**: Automated PHP project security audit. Scans source code for vulnerability patterns, checks dependencies, and produces a structured report.
- **github-security-audit.sh**: GitHub repository security audit. Checks branch protection, Dependabot configuration, secret scanning, and CI/CD security posture.

### Hooks (`hooks/`)

- **hooks.json**: PreToolUse hook configuration that intercepts risky operations (file writes, command execution) and warns the agent before proceeding.
- **check_risky_command.py**: Python script invoked by the hook to detect potentially dangerous commands.

## Data Flow

1. AI agent loads `SKILL.md` based on user query matching trigger patterns
2. Skill instructions guide the agent to relevant checkpoints and references
3. For automated scans, audit scripts are executed against the target project
4. Results are scored using CVSS methodology and prioritized by severity

## Integration

- **composer.json**: Enables installation via Composer with `netresearch/composer-agent-skill-plugin`
- **CI/CD**: GitHub Actions workflows handle linting, testing, and release automation
