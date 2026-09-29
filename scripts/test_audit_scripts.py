#!/usr/bin/env python3
"""Behavioural tests for the shell audit scripts under skills/security-audit/scripts/."""

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


if __name__ == "__main__":
    unittest.main()
