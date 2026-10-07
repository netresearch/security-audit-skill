#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Behavioural tests for the shell audit scripts under skills/security-audit/scripts/."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "skills" / "security-audit" / "scripts"


def run(
    script: Path, *args: str, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=60,
    )


class WordPressScannerTest(unittest.TestCase):
    def test_sql_injection_heading_names_wpdb(self) -> None:
        with tempfile.TemporaryDirectory() as project:
            Path(project, "wp-config.php").write_text("<?php\n$table_prefix = 'nr_';\n")
            result = run(SCRIPTS / "scanners" / "wordpress.sh", project)
        self.assertIn(
            "=== Checking for SQL Injection ($wpdb without prepare) ===", result.stdout
        )


def with_stub(tmp: str, name: str, body: str) -> dict:
    """Return an environment whose PATH starts with a stub command `name`."""
    bin_dir = Path(tmp, "bin")
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / name
    stub.write_text(body)
    stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    return env


class SecretsScannerTest(unittest.TestCase):
    def scan(self, trufflehog_output: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            project.mkdir()
            env = with_stub(
                tmp, "trufflehog", f"#!/bin/sh\nprintf '%s' '{trufflehog_output}'\n"
            )
            return run(SCRIPTS / "scanners" / "secrets.sh", str(project), env=env)

    def test_clean_trufflehog_run_reports_no_secrets_without_errors(self) -> None:
        result = self.scan("")
        self.assertIn("OK: TruffleHog found no secrets", result.stdout)
        self.assertNotIn("syntax error", result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_trufflehog_finding_is_counted(self) -> None:
        result = self.scan('{"SourceMetadata":{}}\n')
        self.assertIn("ERROR: TruffleHog found 1 secret(s):", result.stdout)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_256_findings_still_fail(self) -> None:
        # An exit status is taken modulo 256: exiting with the count reported
        # success for exactly 256 findings.
        result = self.scan('{"SourceMetadata":{}}\n' * 256)
        self.assertIn("ERROR: TruffleHog found 256 secret(s):", result.stdout)
        self.assertEqual(result.returncode, 1, result.stderr)


class JavaScriptScannerTest(unittest.TestCase):
    def scan(self, tsconfig: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as project:
            Path(project, "tsconfig.json").write_text(tsconfig)
            return run(SCRIPTS / "scanners" / "javascript.sh", project)

    def test_strict_mode_enabled(self) -> None:
        result = self.scan('{"compilerOptions": {"strict": true}}')
        self.assertIn("OK: TypeScript strict mode is enabled", result.stdout)
        self.assertNotIn("syntax error", result.stderr)

    def test_strict_mode_not_configured(self) -> None:
        result = self.scan('{"compilerOptions": {}}')
        self.assertIn("WARNING: TypeScript strict mode not configured", result.stdout)
        self.assertNotIn("syntax error", result.stderr)


# Stand-in for the gh CLI: answers `gh api <endpoint> [--jq <filter>]` from a
# fixture file per endpoint. Without a fixture it behaves like gh on a 404:
# the error body goes to stdout (through --jq, if given) and it exits 1.
GH_STUB = """#!/usr/bin/env bash
[[ "$1" == "api" ]] || exit 2
endpoint="$2"; shift 2
filter=""
while [[ $# -gt 0 ]]; do
    [[ "$1" == "--jq" ]] && filter="$2" && shift
    shift
done
fixture="$GH_FIXTURES/${endpoint//\\//__}"
status=0
if [[ ! -f "$fixture" ]]; then
    fixture="$GH_FIXTURES/not-found"
    echo "gh: Not Found (HTTP 404)" >&2
    status=1
fi
if [[ -n "$filter" && -s "$fixture" ]]; then
    jq -r "$filter" "$fixture"
else
    cat "$fixture"
fi
exit "$status"
"""

REPO = "acme/widget"
FULLY_CONFIGURED = {
    "repos/acme/widget": (
        '{"default_branch":"main","permissions":{"admin":true},'
        '"security_and_analysis":{"secret_scanning":{"status":"enabled"},'
        '"secret_scanning_push_protection":{"status":"enabled"},'
        '"dependabot_security_updates":{"status":"enabled"}}}'
    ),
    "repos/acme/widget/branches/main/protection": '{"url":"x","required_signatures":{"enabled":true}}',
    "repos/acme/widget/branches/main/protection/required_signatures": '{"enabled":true}',
    "repos/acme/widget/vulnerability-alerts": "",
    "repos/acme/widget/actions/permissions/workflow": '{"default_workflow_permissions":"read"}',
    "repos/acme/widget/code-scanning/analyses": '[{"id":1}]',
    "repos/acme/widget/private-vulnerability-reporting": '{"enabled":true}',
    "repos/acme/widget/contents/SECURITY.md": '{"name":"SECURITY.md"}',
    "repos/acme/widget/contents/.github/CODEOWNERS": '{"name":"CODEOWNERS"}',
}


class GitHubSecurityAuditTest(unittest.TestCase):
    def audit(self, fixtures: dict[str, str]) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            env = with_stub(tmp, "gh", GH_STUB)
            fixture_dir = Path(tmp, "fixtures")
            fixture_dir.mkdir()
            Path(fixture_dir, "not-found").write_text(
                '{"message":"Not Found","status":"404"}'
            )
            for endpoint, body in fixtures.items():
                Path(fixture_dir, endpoint.replace("/", "__")).write_text(body)
            env["GH_FIXTURES"] = str(fixture_dir)
            return run(SCRIPTS / "github-security-audit.sh", REPO, env=env)

    def test_protected_default_branch_is_reported_as_protected(self) -> None:
        result = self.audit(FULLY_CONFIGURED)
        self.assertIn("[OK] Branch protection configured on main", result.stdout)
        self.assertIn("[OK] Signed commits are required on main", result.stdout)
        self.assertNotIn("[CRITICAL]", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_unprotected_default_branch_is_critical(self) -> None:
        fixtures = {
            endpoint: body
            for endpoint, body in FULLY_CONFIGURED.items()
            if "/protection" not in endpoint
        }
        result = self.audit(fixtures)
        self.assertIn(
            "[CRITICAL] No branch protection on default branch (main)", result.stdout
        )
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_branch_protected_by_rulesets_only_is_reported_as_protected(self) -> None:
        fixtures = {
            endpoint: body
            for endpoint, body in FULLY_CONFIGURED.items()
            if "/protection" not in endpoint
        }
        fixtures["repos/acme/widget/rules/branches/main"] = (
            '[{"type":"deletion"},{"type":"required_signatures"}]'
        )
        result = self.audit(fixtures)
        self.assertIn(
            "[OK] Branch protection configured on main (repository rulesets)",
            result.stdout,
        )
        self.assertIn("[OK] Signed commits are required on main", result.stdout)
        self.assertNotIn("[CRITICAL]", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_empty_ruleset_rules_are_no_protection(self) -> None:
        fixtures = {
            endpoint: body
            for endpoint, body in FULLY_CONFIGURED.items()
            if "/protection" not in endpoint
        }
        fixtures["repos/acme/widget/rules/branches/main"] = "[]"
        result = self.audit(fixtures)
        self.assertIn(
            "[CRITICAL] No branch protection on default branch (main)", result.stdout
        )
        self.assertEqual(result.returncode, 1, result.stdout)


RECORDER = (
    "#!/bin/sh\n"
    'printf "%s\\n" "$*" >> "$RECORD_DIR/$(basename "$0").args"\n'
    'printf -- "---call---\\n" >> "$RECORD_DIR/$(basename "$0").env"\n'
    'env >> "$RECORD_DIR/$(basename "$0").env"\n'
    'printf "%s" "${STUB_OUTPUT:-}"\n'
    'exit "${STUB_EXIT:-0}"\n'
)


def recording_env(tmp: str, *names: str) -> dict:
    """PATH stubs for `names` that record their arguments and environment."""
    for name in names:
        with_stub(tmp, name, RECORDER)
    env = dict(os.environ)
    env["PATH"] = f"{Path(tmp, 'bin')}{os.pathsep}{env['PATH']}"
    env["RECORD_DIR"] = tmp
    return env


def recorded(tmp: str, name: str, kind: str = "args") -> str:
    path = Path(tmp, f"{name}.{kind}")
    return path.read_text() if path.exists() else ""


class ComposerAuditTest(unittest.TestCase):
    """composer audit runs without the audited project's plugins and scripts."""

    def audit(self, script: Path) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            project.mkdir()
            Path(project, "composer.json").write_text("{}\n")
            Path(project, "composer.lock").write_text("{}\n")
            env = recording_env(tmp, "composer")
            run(script, str(project), env=env)
            return recorded(tmp, "composer")

    def test_php_scanner(self) -> None:
        args = self.audit(SCRIPTS / "scanners" / "php.sh")
        self.assertIn("audit", args)
        self.assertIn("--no-plugins", args)
        self.assertIn("--no-scripts", args)

    def test_security_audit_script(self) -> None:
        args = self.audit(SCRIPTS / "security-audit.sh")
        self.assertIn("audit", args)
        self.assertIn("--no-plugins", args)
        self.assertIn("--no-scripts", args)


class TruffleHogVerificationTest(unittest.TestCase):
    """Candidate secrets are verified with their services only on request."""

    def scan(self, **extra: str) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            Path(project, ".git").mkdir(parents=True)
            env = {**recording_env(tmp, "trufflehog"), **extra}
            env["GIT_DIR"] = "/elsewhere/.git"
            run(SCRIPTS / "scanners" / "secrets.sh", str(project), env=env)
            return recorded(tmp, "trufflehog"), recorded(tmp, "trufflehog", "env")

    def test_verification_is_off_by_default(self) -> None:
        args, _env = self.scan()
        calls = args.splitlines()
        self.assertEqual(len(calls), 2, args)
        for call in calls:
            self.assertIn("--no-verification", call)

    def test_verification_can_be_requested(self) -> None:
        args, _env = self.scan(SECURITY_AUDIT_VERIFY_SECRETS="1")
        self.assertEqual(len(args.splitlines()), 2, args)
        self.assertNotIn("--no-verification", args)

    def test_history_scan_limits_git(self) -> None:
        _args, env = self.scan()
        calls = env.split("---call---\n")[1:]
        self.assertEqual(len(calls), 2)
        history = calls[1].splitlines()
        self.assertIn("GIT_ALLOW_PROTOCOL=file", history)
        self.assertIn("GIT_NO_LAZY_FETCH=1", history)
        self.assertFalse([line for line in history if line.startswith("GIT_DIR=")])


class GoVulncheckTest(unittest.TestCase):
    """govulncheck runs with the local toolchain, no VCS stamping, no go.mod edits."""

    def scan(self, **extra: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            project.mkdir()
            Path(project, "go.mod").write_text("module example.com/p\n\ngo 1.22\n")
            Path(project, "go.sum").write_text("")
            Path(project, "main.go").write_text("package main\n\nfunc main() {}\n")
            env = {**recording_env(tmp, "govulncheck"), **extra}
            return run(SCRIPTS / "scanners" / "go.sh", str(project), env=env)

    def test_a_run_that_could_not_check_is_an_error(self) -> None:
        result = self.scan(
            STUB_EXIT="1",
            STUB_OUTPUT="go: go.mod requires go >= 1.99 (GOTOOLCHAIN=local)",
        )
        self.assertIn(
            "ERROR: govulncheck could not check the dependencies", result.stdout
        )
        self.assertNotIn("OK: No known vulnerable dependencies", result.stdout)
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_a_finding_is_a_warning(self) -> None:
        result = self.scan(STUB_EXIT="3", STUB_OUTPUT="Vulnerability #1: GO-2026-0001")
        self.assertIn("WARNING: Vulnerable dependencies found:", result.stdout)

    def test_a_clean_run_is_ok(self) -> None:
        result = self.scan()
        self.assertIn("OK: No known vulnerable dependencies", result.stdout)

    def check(self, vendored: bool) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            project.mkdir()
            Path(project, "go.mod").write_text("module example.com/p\n\ngo 1.22\n")
            Path(project, "go.sum").write_text("")
            Path(project, "main.go").write_text("package main\n\nfunc main() {}\n")
            if vendored:
                Path(project, "vendor").mkdir()
                Path(project, "vendor", "modules.txt").write_text("")
            env = recording_env(tmp, "govulncheck")
            env["GOFLAGS"] = "-mod=mod"
            env["GOTOOLCHAIN"] = "auto"
            run(SCRIPTS / "scanners" / "go.sh", str(project), env=env)
            return recorded(tmp, "govulncheck", "env").splitlines()

    def test_toolchain_and_flags(self) -> None:
        env = self.check(vendored=False)
        self.assertIn("GOTOOLCHAIN=local", env)
        self.assertIn("GOFLAGS=-mod=readonly -buildvcs=false", env)

    def test_vendored_module(self) -> None:
        self.assertIn("GOFLAGS=-mod=vendor -buildvcs=false", self.check(vendored=True))


if __name__ == "__main__":
    unittest.main()
