#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Behavioural tests for the shell audit scripts under skills/security-audit/scripts/."""

import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
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

    def audit(self, script: Path, **extra: str) -> str:
        return self.run_audit(script, **extra)[0]

    def run_audit(
        self, script: Path, **extra: str
    ) -> tuple[str, subprocess.CompletedProcess]:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            project.mkdir()
            Path(project, "composer.json").write_text("{}\n")
            Path(project, "composer.lock").write_text("{}\n")
            env = {**recording_env(tmp, "composer"), **extra}
            result = run(script, str(project), env=env)
            return recorded(tmp, "composer"), result

    def test_the_lock_file_is_audited(self) -> None:
        for script in (SCRIPTS / "scanners" / "php.sh", SCRIPTS / "security-audit.sh"):
            with self.subTest(script=script.name):
                self.assertIn("--locked", self.audit(script))

    def test_a_run_that_could_not_check_is_an_error(self) -> None:
        for script in (SCRIPTS / "scanners" / "php.sh", SCRIPTS / "security-audit.sh"):
            with self.subTest(script=script.name):
                _args, result = self.run_audit(
                    script, STUB_EXIT="1", STUB_OUTPUT="Could not read composer.lock"
                )
                self.assertIn(
                    "composer audit could not check the dependencies", result.stdout
                )
                self.assertNotIn("No known vulnerable dependencies", result.stdout)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_a_finding_is_a_warning(self) -> None:
        _args, result = self.run_audit(
            SCRIPTS / "scanners" / "php.sh",
            STUB_EXIT="1",
            STUB_OUTPUT="Found 6 security vulnerability advisories affecting 1 package:",
        )
        self.assertIn("Vulnerable dependencies found:", result.stdout)

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


NPM_STUB = (
    "#!/bin/sh\n"
    'if [ "$1" = config ]; then\n'
    '  if [ -n "$STUB_CONFIG_EXIT" ]; then\n'
    '    echo "The globalconfig option is protected" >&2; exit "$STUB_CONFIG_EXIT"\n'
    "  fi\n"
    '  echo "npm warn Unknown user config \\"always-auth\\"" >&2\n'
    '  printf "%s\\n" "${STUB_CONFIG_OUTPUT:-/etc/npmrc}"; exit 0\n'
    "fi\n"
    'printf "%s\\n" "$*" > "$RECORD_DIR/npm.args"\n'
    'pwd > "$RECORD_DIR/npm.cwd"\n'
    'ls -A > "$RECORD_DIR/npm.files"\n'
    'printf "%s" "${STUB_OUTPUT:-}"\n'
    'exit "${STUB_EXIT:-0}"\n'
)

NPM_CLEAN = '{"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}'
NPM_FINDING = (
    '{"vulnerabilities":{"minimist":{}},"metadata":{"vulnerabilities":{"total":1}}}'
)
NPM_FAILED = '{"message":"request failed","error":{"summary":"","detail":""}}'

NPM_SCANNERS = (
    SCRIPTS / "scanners" / "javascript.sh",
    SCRIPTS / "scanners" / "nodejs.sh",
)


def npm_project(tmp: str) -> Path:
    """A project whose .npmrc points npm at its own registry."""
    project = Path(tmp, "project")
    project.mkdir()
    Path(project, "src").mkdir()
    Path(project, "src", "index.js").write_text("module.exports = {};\n")
    Path(project, "package.json").write_text('{"name":"p","version":"1.0.0"}\n')
    Path(project, "package-lock.json").write_text(
        '{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{}}\n'
    )
    Path(project, ".npmrc").write_text(
        "registry=http://127.0.0.1:9/\n//127.0.0.1:9/:_authToken=${NPM_PROBE}\n"
    )
    return project


class NpmAuditTest(unittest.TestCase):
    """npm audit reads the audited project's lock file but not its .npmrc."""

    def scan(
        self, script: Path, **extra: str
    ) -> tuple[Path, str, str, subprocess.CompletedProcess]:
        with tempfile.TemporaryDirectory() as tmp:
            project = npm_project(tmp)
            env = {**with_stub(tmp, "npm", NPM_STUB), "RECORD_DIR": tmp, **extra}
            result = run(script, str(project), env=env)
            return (
                project,
                recorded(tmp, "npm", "cwd").strip(),
                recorded(tmp, "npm", "files"),
                result,
            )

    def test_npm_runs_outside_the_project_without_its_npmrc(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name):
                project, cwd, files, _result = self.scan(script, STUB_OUTPUT=NPM_CLEAN)
                self.assertTrue(cwd, "npm was not called")
                self.assertNotEqual(Path(cwd).resolve(), project.resolve())
                self.assertEqual(
                    sorted(files.split()),
                    ["package-lock.json", "package.json"],
                )

    def test_a_failed_globalconfig_lookup_is_an_error(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name):
                result = self.scan(script, STUB_CONFIG_EXIT="1", STUB_OUTPUT=NPM_CLEAN)[
                    3
                ]
                self.assertIn(
                    "ERROR: npm audit could not check the dependencies", result.stdout
                )
                self.assertIn("could not read npm's globalconfig", result.stdout)
                self.assertNotIn("No known vulnerable dependencies", result.stdout)
                self.assertEqual(result.returncode, 1, result.stdout)

    def test_a_globalconfig_that_is_not_one_absolute_path_is_an_error(self) -> None:
        for script in NPM_SCANNERS:
            for output in ("etc/npmrc", "Usage:\n/etc/npmrc", "/etc/npmrc\nextra"):
                with self.subTest(script=script.name, output=output):
                    result = self.scan(
                        script, STUB_CONFIG_OUTPUT=output, STUB_OUTPUT=NPM_CLEAN
                    )[3]
                    self.assertIn("could not read npm's globalconfig", result.stdout)
                    self.assertNotIn("No known vulnerable dependencies", result.stdout)
                    self.assertEqual(result.returncode, 1, result.stdout)

    def test_the_global_config_path_is_passed_on(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                env = {**with_stub(tmp, "npm", NPM_STUB), "RECORD_DIR": tmp}
                env["STUB_OUTPUT"] = NPM_CLEAN
                run(script, str(project), env=env)
                args = recorded(tmp, "npm", "args")
                self.assertIn("--globalconfig /etc/npmrc", args)
                self.assertNotIn("warn", args)

    def test_a_shrinkwrap_file_is_copied(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, "npm-shrinkwrap.json").write_text("{}\n")
                env = {**with_stub(tmp, "npm", NPM_STUB), "RECORD_DIR": tmp}
                env["STUB_OUTPUT"] = NPM_CLEAN
                run(script, str(project), env=env)
                self.assertIn("npm-shrinkwrap.json", recorded(tmp, "npm", "files"))

    def test_the_temporary_directory_is_removed_when_a_copy_fails(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, "package.json").chmod(0)
                scratch = Path(tmp, "scratch")
                scratch.mkdir()
                env = {**with_stub(tmp, "npm", NPM_STUB), "RECORD_DIR": tmp}
                env["TMPDIR"] = str(scratch)
                result = run(script, str(project), env=env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(list(scratch.iterdir()), [])

    def test_a_clean_run_is_ok(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name):
                result = self.scan(script, STUB_OUTPUT=NPM_CLEAN)[3]
                self.assertIn("OK: No known vulnerable dependencies", result.stdout)
                self.assertNotIn("Vulnerable dependencies found", result.stdout)

    def test_a_finding_is_a_warning(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name):
                result = self.scan(script, STUB_EXIT="1", STUB_OUTPUT=NPM_FINDING)[3]
                self.assertIn(
                    "WARNING: Vulnerable dependencies found: 1", result.stdout
                )

    def test_a_run_that_could_not_check_is_an_error(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name):
                result = self.scan(script, STUB_EXIT="1", STUB_OUTPUT=NPM_FAILED)[3]
                self.assertIn(
                    "ERROR: npm audit could not check the dependencies", result.stdout
                )
                self.assertNotIn("No known vulnerable dependencies", result.stdout)
                self.assertEqual(result.returncode, 1, result.stdout)


LEFT_PAD_ADVISORY = (
    b'{"left-pad":[{"id":1,"url":"https://example.invalid/1","title":"probe",'
    b'"severity":"high","vulnerable_versions":"<=1.3.0","cwe":[],'
    b'"cvss":{"score":0,"vectorString":null}}]}'
)

MONOREPO_LOCK = (
    '{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,'
    '"packages":{"":{"name":"root","version":"1.0.0","workspaces":["packages/*"],'
    '"devDependencies":{"right-pad":"1.0.1"}},'
    '"node_modules/a":{"resolved":"packages/a","link":true},'
    '"node_modules/left-pad":{"version":"1.3.0",'
    '"resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},'
    '"node_modules/right-pad":{"version":"1.0.1","dev":true,'
    '"resolved":"https://registry.npmjs.org/right-pad/-/right-pad-1.0.1.tgz"},'
    '"packages/a":{"name":"a","version":"1.0.0",'
    '"dependencies":{"left-pad":"1.3.0"}}}}\n'
)

LEFT_PAD_LOCK = (
    '{"name":"p","version":"1.0.0","lockfileVersion":3,"requires":true,'
    '"packages":{"":{"name":"p","version":"1.0.0",'
    '"dependencies":{"left-pad":"1.3.0"}},'
    '"node_modules/left-pad":{"version":"1.3.0",'
    '"resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}\n'
)


@unittest.skipUnless(shutil.which("npm"), "npm is not installed")
class NpmAuditRegistryTest(unittest.TestCase):
    """End to end with npm: only the auditor's own registry gets the audit request."""

    def setUp(self) -> None:
        self.requests: dict[int, list[tuple[str, str | None]]] = {}
        requests = self.requests

        class Registry(http.server.BaseHTTPRequestHandler):
            def handle_one(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                port = self.server.server_address[1]
                requests.setdefault(port, []).append(
                    (self.path, self.headers.get("authorization"))
                )
                name = self.path.strip("/")
                body = json.dumps(
                    {
                        "name": name,
                        "dist-tags": {"latest": "1.3.0"},
                        "versions": {"1.3.0": {"name": name, "version": "1.3.0"}},
                    }
                ).encode()
                if self.path.endswith("/advisories/bulk"):
                    body = LEFT_PAD_ADVISORY
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = handle_one

            def log_message(self, *args: object) -> None:
                pass

        self.servers = [
            http.server.HTTPServer(("127.0.0.1", 0), Registry) for _ in range(2)
        ]
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.attacker, self.own = (s.server_address[1] for s in self.servers)

    def tearDown(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def attacker_npmrc(self) -> str:
        return (
            f"registry=http://127.0.0.1:{self.attacker}/\n"
            f"//127.0.0.1:{self.attacker}/:_authToken=${{NPM_PROBE}}\n"
        )

    def plant_workspace_root(self, tmp: str) -> Path:
        shared = Path(tmp, "shared-tmp")
        shared.mkdir()
        Path(shared, "package.json").write_text(
            '{"name":"root","version":"1.0.0","workspaces":["*"]}\n'
        )
        Path(shared, "package-lock.json").write_text(
            '{"name":"root","version":"1.0.0","lockfileVersion":3,'
            '"packages":{"":{"name":"root","workspaces":["*"]}}}\n'
        )
        Path(shared, ".npmrc").write_text(self.attacker_npmrc())
        return shared

    def audit(
        self,
        script: Path,
        tmp: str,
        project: Path,
        user_registry: bool = True,
        keep_manifest: bool = True,
        write_fixture: bool = True,
        **extra: str,
    ) -> subprocess.CompletedProcess:
        if write_fixture:
            # A dependency, so that npm sends the bulk advisory request.
            Path(project, "package.json").write_text(
                '{"name":"p","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}\n'
            )
            if not keep_manifest:
                Path(project, "package.json").unlink()
            Path(project, "package-lock.json").write_text(LEFT_PAD_LOCK)
        userconfig = Path(tmp, "user.npmrc")
        userconfig.write_text(
            f"registry=http://127.0.0.1:{self.own}/\n"
            if user_registry
            # An unknown key makes npm print a warning on every command.
            else "always-auth=true\n"
        )
        # npm settings from the caller's environment outrank a project's
        # .npmrc and would let the unfixed scanner pass.
        env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_")}
        env["NPM_PROBE"] = "probe-value"
        env["NPM_CONFIG_USERCONFIG"] = str(userconfig)
        env["NPM_CONFIG_CACHE"] = str(Path(tmp, "cache"))
        env["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
        env.update(extra)
        self.requests.clear()
        result = run(script, str(project), env=env)
        self.assertEqual(self.requests.get(self.attacker, []), [])
        paths = [path for path, _auth in self.requests.get(self.own, [])]
        self.assertIn("/-/npm/v1/security/advisories/bulk", paths)
        return result

    def test_the_global_npmrc_is_read(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, ".npmrc").write_text(self.attacker_npmrc())
                global_prefix = Path(tmp, "global")
                Path(global_prefix, "etc").mkdir(parents=True)
                Path(global_prefix, "etc", "npmrc").write_text(
                    f"registry=http://127.0.0.1:{self.own}/\n"
                )
                self.audit(
                    script,
                    tmp,
                    project,
                    user_registry=False,
                    NPM_CONFIG_PREFIX=str(global_prefix),
                )

    def test_a_lock_file_only_project_under_a_workspace_root(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, ".npmrc").unlink()
                shared = self.plant_workspace_root(tmp)
                self.audit(
                    script, tmp, project, keep_manifest=False, TMPDIR=str(shared)
                )

    def test_a_workspace_dependency_is_audited(self) -> None:
        # The vulnerable package is needed only by a workspace, and the
        # root has a dependency of its own.
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, ".npmrc").unlink()
                Path(project, "package.json").write_text(
                    '{"name":"root","version":"1.0.0","workspaces":["packages/*"],'
                    '"devDependencies":{"right-pad":"1.0.1"}}\n'
                )
                Path(project, "package-lock.json").write_text(MONOREPO_LOCK)
                Path(project, "packages", "a").mkdir(parents=True)
                Path(project, "packages", "a", "package.json").write_text(
                    '{"name":"a","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}\n'
                )
                result = self.audit(script, tmp, project, write_fixture=False)
                self.assertIn(
                    "WARNING: Vulnerable dependencies found: 1", result.stdout
                )

    def test_the_project_npmrc_is_not_read(self) -> None:
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, ".npmrc").write_text(self.attacker_npmrc())
                self.audit(script, tmp, project)

    def test_a_workspace_root_above_the_temporary_directory_is_not_used(self) -> None:
        # Another user of a shared /tmp can plant a workspace root there.
        for script in NPM_SCANNERS:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                project = npm_project(tmp)
                Path(project, ".npmrc").unlink()
                shared = self.plant_workspace_root(tmp)
                self.audit(script, tmp, project, TMPDIR=str(shared))


if __name__ == "__main__":
    unittest.main()
