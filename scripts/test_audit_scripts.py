#!/usr/bin/env python3
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
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(GH_STUB)
            gh.chmod(0o755)
            fixture_dir = Path(tmp, "fixtures")
            fixture_dir.mkdir()
            Path(fixture_dir, "not-found").write_text(
                '{"message":"Not Found","status":"404"}'
            )
            for endpoint, body in fixtures.items():
                Path(fixture_dir, endpoint.replace("/", "__")).write_text(body)
            env = dict(os.environ)
            env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
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


if __name__ == "__main__":
    unittest.main()
