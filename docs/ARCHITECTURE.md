# Architecture

## Overview

The security-audit-skill is an AI agent skill that provides security audit capabilities following the [Agent Skills](https://agentskills.io) open standard. It delivers vulnerability detection, risk scoring, and secure coding guidance through skill definitions, automated checkpoints, reference documentation, shell audit scripts and a PreToolUse hook. It has no server component and stores no data.

## Actors

- **User**: installs the skill (marketplace, skills directory, `npx skills`, Composer or npm; see [README.md](../README.md#installation)) and asks the agent for an audit.
- **AI agent**: loads `SKILL.md`, reads references, and runs the audit scripts with the user's privileges.
- **Claude Code**: runs the PreToolUse hook before each Bash command when the plugin's hooks are installed.
- **Target project**: the code and repository being audited. Its files, and for `github-security-audit.sh` its GitHub settings, are the input of the audit scripts.
- **Contributors and CI**: change the skill through pull requests; the workflows in `.github/workflows/` check and release it.

## Components

### Skill Definition (`skills/security-audit/`)

- **SKILL.md**: Entry point loaded by AI agents. Contains trigger patterns, procedural instructions, and links to references.
- **checkpoints.yaml**: 80+ security checkpoints (`mechanical` pattern checks and `llm_reviews`) with severity, detection pattern and description, read by assessment tooling.
- **references/**: 41 reference guides covering OWASP Top 10, CWE Top 25, CVSS scoring, language and framework security (PHP, Python, Go, Node.js, TYPO3, Symfony, React, Vue), cloud and IaC, and supply chain security. They contain deliberately vulnerable example code for teaching; nothing runs it.
- **evals/evals.json**: evaluation scenarios for the skill, checked by the Eval Validation workflow.

### Audit Scripts (`skills/security-audit/scripts/`)

- **security-audit-dispatcher.sh**: detects the target's stack from indicator files (`composer.json`, `package.json`, `go.mod`, `pom.xml`, `*.csproj`, `AndroidManifest.xml`, `*.tf`, `wp-config.php`, …), runs the matching modules in `scanners/`, always runs `scanners/secrets.sh`, and exits 1 when any module exits non-zero. A module exits non-zero when it reports errors; warnings alone do not change its exit status.
- **scanners/*.sh**: one module per ecosystem (android, aws, csharp, drupal, go, ios, java, javascript, joomla, nodejs, php, python, wordpress) plus `secrets.sh`. Each greps the target's source files for vulnerability patterns and prints the matching lines. Some call a tool when it is installed: `composer audit`, `npm audit`, `govulncheck`, `trufflehog`. `scanners/common.sh` holds helper functions.
- **security-audit.sh**: standalone PHP audit over `src/` and `Classes/`, plus `composer audit` when a `composer.lock` exists.
- **github-security-audit.sh**: reads a repository's security settings through the `gh` CLI (secret scanning, push protection, branch protection, Dependabot, default workflow permissions, code scanning, private vulnerability reporting, `SECURITY.md`, `CODEOWNERS`, signed commits) and exits 1 when a CRITICAL finding exists.

### Hook (`hooks/hooks.json`, `scripts/check_risky_command.py`)

- **hooks.json**: registers a PreToolUse hook for the `Bash` tool that runs `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/check_risky_command.py` with a two-second timeout.
- **check_risky_command.py**: reads the tool call from stdin, matches `tool_input.command` against a list of regular expressions (destructive deletes, `curl | sh`, credentials in commands, force pushes, raw block device writes, …) and, on a match, prints a warning as `hookSpecificOutput.additionalContext`. It never blocks the command.

### Repository tooling

- **scripts/test_*.py**: tests for the hook and the audit scripts, run by `.github/workflows/ci.yml`.
- **scripts/validate_checkpoints.py**: checks the structure of `checkpoints.yaml` and duplicate IDs.
- **scripts/verify-harness.sh**: checks the agent harness (AGENTS.md and related files).
- **Build/hooks/pre-push**, **Build/Scripts/check-plugin-version.sh**: when `.envrc` sets `core.hooksPath` to `Build/hooks`, a push fails if a semver tag at HEAD does not match the version in `.claude-plugin/plugin.json`.

## Data Flow

1. The agent loads `SKILL.md` when the user's request matches its description, and reads the references and checkpoints it needs.
2. For automated scans, the agent runs the dispatcher, a scanner or `security-audit.sh` against a directory of the target project. The scripts read files there and print findings to stdout; they write no files. The optional tools they call run in the target directory.
3. `github-security-audit.sh owner/repo` sends read requests to the GitHub API through `gh`, with the user's `gh` credentials, and prints findings.
4. The agent interprets the output, scores findings with the CVSS guidance in `references/cvss-scoring.md` and reports them to the user.
5. Independently of the skill's use, Claude Code passes every Bash tool call to the hook; the hook's warning, if any, is added to the agent's context before the command runs.

## Integration

- **composer.json** and **package.json**: installation via `netresearch/composer-agent-skill-plugin` or `@netresearch/agent-skill-coordinator`.
- **plugin.json** and **.claude-plugin/plugin.json**: plugin manifests with the skill path and version.
- **CI/CD**: GitHub Actions workflows run skill validation and linters (`lint.yml`), tests (`ci.yml`), security scans (`security.yml`), eval and harness checks, and signed releases (`release.yml`).

The security properties and limits of these components are described in [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md).
