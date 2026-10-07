<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->

# Security assurance case — security-audit-skill

This document states what a user can expect from this repository in terms of security, and argues why that expectation holds. Every claim names the file that implements it. Reporting a vulnerability and supported versions: [SECURITY.md](../SECURITY.md). Components and data flows: [ARCHITECTURE.md](ARCHITECTURE.md).

## What the repository ships

| Part | Files | Runs where |
| --- | --- | --- |
| Skill instructions for an AI agent | `skills/security-audit/SKILL.md`, `skills/security-audit/references/*.md`, `skills/security-audit/checkpoints.yaml` | Read by the agent or by assessment tooling; not executed. The references contain deliberately vulnerable example code for teaching. |
| Eval scenarios | `skills/security-audit/evals/evals.json` | Checked in CI; not executed. |
| Audit scripts | `skills/security-audit/scripts/*.sh`, `skills/security-audit/scripts/scanners/*.sh` | On the user's machine, started by the agent or the user, against a target directory or GitHub repository. |
| PreToolUse hook | `hooks/hooks.json`, `scripts/check_risky_command.py` | In Claude Code, before every Bash tool call, when the plugin's hooks are installed. |
| Repository checks | `.github/workflows/*.yml`, `.pre-commit-config.yaml`, `scripts/test_*.py`, `scripts/validate_checkpoints.py`, `scripts/verify-harness.sh`, `Build/` | In this repository's CI and on contributors' machines. |

The repository ships no server component, no container image and no library code. It stores nothing and holds no credentials of its own; `github-security-audit.sh` uses the credentials of the user's `gh` CLI.

## Security requirements

1. The audit scripts only read the target: they write no files, and the only network access they start themselves is `github-security-audit.sh`'s read requests to the GitHub API, apart from the optional tools the scanners call when installed (`composer audit`, `npm audit`, `govulncheck`, `trufflehog`).
2. The target path and repository name are passed to commands as quoted arguments; no script builds a command string from them or runs `eval`.
3. The audit scripts report findings through their exit status: a scanner module exits non-zero when it reports errors, the dispatcher exits 1 when any module did, and `github-security-audit.sh` exits 1 on a CRITICAL finding.
4. The hook reads the Bash command Claude Code passes, adds a warning to the agent's context when the command matches a risky pattern, never blocks the command, and does not fail on malformed input.
5. Nothing committed to this repository contains a real secret.
6. A release carries the version that `.claude-plugin/plugin.json` states, and its archives can be verified against the build that produced them.

## Actors and trust boundaries

- **User and agent.** The agent reads `SKILL.md` and the references and runs commands with the user's privileges; what it runs is decided by the agent and the user, not by this repository. `allowed-tools` in `SKILL.md` pre-approves `grep`, `jq`, `gh`, `Read`, `Glob` and `Grep`; it does not take any tool away from the agent.
- **Target project.** The files of the audited project are untrusted input. The scanners pass them to `grep` as data and print matching lines, so the output the agent reads contains text written by the target's authors. When they are installed, `composer audit`, `npm audit`, `govulncheck` and `trufflehog` run in the target directory (`security-audit.sh`, `scanners/php.sh`, `scanners/javascript.sh`, `scanners/nodejs.sh`, `scanners/go.sh`, `scanners/secrets.sh`).
- **GitHub API.** `github-security-audit.sh` trusts what `gh api` returns for the named repository; a user without admin access gets a warning that results may be incomplete.
- **Claude Code.** It starts the hook with the tool call on stdin (`hooks/hooks.json`) and decides what to do with the hook's output.
- **Contributors and CI.** Changes are proposed as pull requests and checked by the workflows in `.github/workflows/`, which run on GitHub-hosted runners. Every workflow sets `permissions: {}` at the top level and grants its jobs only the scopes the called reusable workflow needs. `auto-merge-deps.yml`, `labeler.yml` and `pr-quality.yml` run on `pull_request_target` and only call reusable workflows; `auto-merge-deps.yml` passes exactly two secrets (the organisation merge App's ID and private key) rather than `secrets: inherit`, and both it and `pr-quality.yml` state that they do not check out pull request code. `release.yml` runs only on pushed `v*` tags.

## Threats and countermeasures

| Threat | Countermeasure | Evidence |
| --- | --- | --- |
| A target path with spaces or shell metacharacters is split or executed by the shell (CWE-78) | `PROJECT_DIR` and `REPO` are used only in quoted expansions and passed as single arguments to `grep`, `find`, `bash` and `gh`; no script uses `eval` | `security-audit-dispatcher.sh`, `scanners/*.sh`, `security-audit.sh`, `github-security-audit.sh` |
| An audit modifies the project it audits | The scripts only read: `grep`, `find` and read-only tools; no redirection into files | `skills/security-audit/scripts/` |
| A failed check is reported as a pass | Scanner modules exit non-zero on errors, the dispatcher counts failing modules and exits 1; `github-security-audit.sh` exits 1 on CRITICAL findings | `security-audit-dispatcher.sh`; `scripts/test_audit_scripts.py` ("unprotected default branch is critical", "trufflehog finding is counted") |
| A tool the scanners call runs code or configuration from the audited project (CWE-829) | `composer audit` runs with `--locked --no-plugins --no-scripts`, so it reads `composer.lock` and loads nothing from `vendor/`; `govulncheck` runs with `GOTOOLCHAIN=local` and `GOFLAGS` set to `-mod=readonly` (`-mod=vendor` for a vendored module) and `-buildvcs=false`, so `go` does not switch toolchains and does not run `git` in the project to stamp version-control data (downloading a module in direct mode still uses `git`, in the module cache, not in the project); TruffleHog's history scan runs with `GIT_ALLOW_PROTOCOL=file`, `GIT_NO_LAZY_FETCH=1`, `GIT_CONFIG_NOSYSTEM=1` and without inherited repository-location variables; a `composer audit` or `govulncheck` run that could not check (for example because `go.mod` needs a newer Go than the local one) is reported as an error, not as a clean result | `security-audit.sh`, `scanners/php.sh`, `scanners/go.sh`, `scanners/secrets.sh`; `scripts/test_audit_scripts.py` (`ComposerAuditTest`, `GoVulncheckTest`, `TruffleHogVerificationTest`; `test_a_run_that_could_not_check_is_an_error`) |
| Candidate secrets from the audited project are sent to third parties | TruffleHog runs with `--no-verification` unless `SECURITY_AUDIT_VERIFY_SECRETS=1` is set | `scanners/secrets.sh`; `test_verification_is_off_by_default`, `test_verification_can_be_requested` |
| A protected repository is misreported, or a count check misfires | Regression tests for branch-protection detection, the TruffleHog and tsconfig counts and a scanner heading | `scripts/test_audit_scripts.py`, run by `.github/workflows/ci.yml` |
| A risky Bash command runs without the agent being warned | The hook matches `tool_input.command` against the patterns in `RISKY_PATTERNS` and returns the warning as `additionalContext` | `scripts/check_risky_command.py`; `scripts/test_check_risky_command.py`, `scripts/test_risky_patterns.py` |
| Malformed hook input breaks the agent's Bash tool | Empty, non-JSON and non-object input is handled without an exception; the hook has a two-second timeout and never returns a blocking decision | `scripts/check_risky_command.py`, `hooks/hooks.json`; `scripts/test_check_risky_command.py` ("empty and non-object input is silent") |
| A real secret is committed | GitHub secret scanning with push protection (a repository setting) rejects pushes containing a recognised secret; Betterleaks scans every pull request and push to `main`; the fake credentials in the reference examples are listed with a reason in `.gitleaksignore` | `.github/workflows/security.yml`, `.gitleaksignore` |
| A vulnerable or insecure change to the repository's own code or workflows | Opengrep (findings handled under the [organisation's static analysis rule](https://github.com/netresearch/.github/blob/main/SECURITY.md#static-analysis-sast)) and Composer Audit via the `typo3-ci-workflows` security reusable, zizmor for the workflows, dependency review on pull requests, ShellCheck, ruff and actionlint in Skill Validation; CodeQL through GitHub's default setup, a repository setting | `.github/workflows/security.yml`, `.github/workflows/lint.yml`, `.pre-commit-config.yaml`, `.github/template.yaml` (CodeQL note) |
| An outdated linter, hook or action | Renovate proposes updates for the pinned pre-commit hook revisions; they reach `main` through pull requests checked like any other | `renovate.json`, `.pre-commit-config.yaml` |
| A released archive is tampered with | The release workflow checks that the tag is annotated and signed, then publishes a Cosign-signed `SHA256SUMS.txt` and build-provenance attestations for the archives; a local pre-push hook checks the plugin version against the tag | `.github/workflows/release.yml` (calls the skill-repo-skill release reusable), `Build/hooks/pre-push`, `Build/Scripts/check-plugin-version.sh` |

Which checks must pass before a change reaches `main` is set in the repository settings, not in this repository.

## Secure design principles applied

- **Least privilege:** the audit scripts read and never write; `github-security-audit.sh` issues only GET requests. Workflows start from `permissions: {}` and grant permissions per job.
- **Fail-safe defaults:** the scanners run under `set -e` and exit non-zero on errors. The hook is informational by design: when it cannot parse its input it stays silent and lets Claude Code proceed.
- **Economy of mechanism:** the scanners are `grep` patterns over files, the hook is a list of regular expressions; both can be read in full.
- **Open design:** everything the skill tells an agent to do is plain text in `SKILL.md` and `references/`, reviewable before use.

## What a user cannot expect

- The scanners find patterns, not vulnerabilities. They produce false positives and miss anything a pattern does not describe, for example data flows through variables (`security-audit.sh` says so for SQL injection). A clean run is not a security sign-off.
- The output of the scanners contains lines from the target project. Treat it as untrusted text: the agent reads it, and text in it can try to steer the agent.
- The optional tools the scanners call (`composer audit`, `npm audit`, `govulncheck`, `trufflehog`) run in the target directory with the user's privileges and may use the network: `composer audit` and `npm audit` send the package list to their advisory services, `govulncheck` downloads modules and its vulnerability database. Beyond the flags above, their behaviour is theirs. With `SECURITY_AUDIT_VERIFY_SECRETS=1`, TruffleHog sends each candidate secret to the service it belongs to, or to a URL it contains.
- `github-security-audit.sh` reads the classic branch protection endpoint (`branches/<branch>/protection`) and, when that reports none, the ruleset rules that apply to the default branch (`rules/branches/<branch>`). Any applicable rule counts as protection; the script does not judge which rules a ruleset contains, apart from the signed-commit check.
- The hook warns; it does not prevent anything. It only sees Bash tool calls, it matches text patterns that can be evaded, and it has no integrity check after installation (see the Known Limitations in [SECURITY.md](../SECURITY.md)).
- The reference guides contain vulnerable example code. Copying an example marked `VULNERABLE` into a project copies the vulnerability.
- The skill gives guidance; it does not enforce it. The agent runs commands with the user's privileges, and `allowed-tools` only removes the confirmation prompt for the tools it lists.
- Security fixes follow the supported-versions rules in [SECURITY.md](../SECURITY.md); older releases may not receive them.
