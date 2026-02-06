#!/usr/bin/env python3
"""
PreToolUse hook to detect potentially risky command patterns before execution.
Warns about dangerous operations without blocking (informational only).
"""

import sys
import re
import json

# Risky patterns with severity and explanation
RISKY_PATTERNS = [
    # Destructive file operations
    {
        "pattern": r"rm\s+(-[rf]+\s+)?[/~]",
        "severity": "high",
        "message": "Recursive delete on root or home directory",
    },
    {
        "pattern": r"rm\s+-rf?\s+\*",
        "severity": "high",
        "message": "Recursive delete with wildcard",
    },
    # Insecure permissions
    {
        "pattern": r"chmod\s+(777|666|a\+rwx)",
        "severity": "medium",
        "message": "World-writable permissions (777/666) - consider more restrictive",
    },
    {
        "pattern": r"chown\s+-R\s+\w+:\w+\s+/",
        "severity": "medium",
        "message": "Recursive ownership change on root paths",
    },
    # Remote code execution patterns
    {
        "pattern": r"curl.*\|\s*(ba)?sh",
        "severity": "high",
        "message": "Piping remote content directly to shell - verify source first",
    },
    {
        "pattern": r"wget.*-O\s*-\s*\|\s*(ba)?sh",
        "severity": "high",
        "message": "Piping remote content directly to shell",
    },
    {
        "pattern": r"eval\s+\$\(",
        "severity": "medium",
        "message": "Dynamic eval of command substitution",
    },
    # Credential exposure
    {
        "pattern": r"(password|secret|token|api_key)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "high",
        "message": "Hardcoded credential in command - use environment variables",
    },
    {
        "pattern": r"echo\s+['\"]?(\$\{?(PASSWORD|SECRET|TOKEN|API_KEY)",
        "severity": "medium",
        "message": "Echoing sensitive variable - may appear in logs",
    },
    # SQL injection vectors (in shell commands)
    {
        "pattern": r"mysql.*-e\s*['\"].*\$",
        "severity": "medium",
        "message": "Variable interpolation in SQL - risk of injection",
    },
    # Git credential exposure
    {
        "pattern": r"git\s+(push|clone|pull).*https://[^@]+:[^@]+@",
        "severity": "high",
        "message": "Credentials in git URL - use credential helper instead",
    },
    # Docker privileged mode
    {
        "pattern": r"docker\s+run.*--privileged",
        "severity": "medium",
        "message": "Docker privileged mode - container has full host access",
    },
    # Force push to main
    {
        "pattern": r"git\s+push\s+(-f\b|--force\s).*\b(main|master)\b",
        "severity": "high",
        "message": "Force push to main/master - may lose commits",
    },
]


def check_command(command: str) -> list[dict]:
    """Check command against risky patterns."""
    warnings = []
    for entry in RISKY_PATTERNS:
        if re.search(entry["pattern"], command, re.IGNORECASE):
            warnings.append(
                {
                    "severity": entry["severity"],
                    "message": entry["message"],
                }
            )
    return warnings


def main():
    # Read tool input from stdin (Claude Code passes tool parameters)
    try:
        input_data = sys.stdin.read()
    except Exception:
        return

    if not input_data:
        return

    # Parse the tool input
    try:
        data = json.loads(input_data)
        command = data.get("command", "")
    except (json.JSONDecodeError, TypeError):
        command = input_data

    if not command:
        return

    # Check for risky patterns
    warnings = check_command(command)

    if warnings:
        severity_icons = {"high": "🔴", "medium": "🟡", "low": "🟢"}
        warning_lines = []
        for w in warnings:
            icon = severity_icons.get(w["severity"], "⚠️")
            warning_lines.append(f"  {icon} [{w['severity'].upper()}] {w['message']}")

        print(f"""<system-reminder>
Security warning for command:
{chr(10).join(warning_lines)}

Review the command carefully before proceeding.
The security-audit skill can help assess risks: /security-audit
</system-reminder>""")


if __name__ == "__main__":
    main()
