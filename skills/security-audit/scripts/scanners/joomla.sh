#!/bin/bash
# Joomla Security Scanner Module
# Detects Joomla projects via configuration.php
# Scans for common Joomla-specific vulnerability patterns

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Joomla project
JOOMLA_DETECTED=false
if [[ -f "$PROJECT_DIR/configuration.php" ]] && grep -q 'class JConfig' "$PROJECT_DIR/configuration.php" 2>/dev/null; then
    JOOMLA_DETECTED=true
fi

if [[ "$JOOMLA_DETECTED" != "true" ]]; then
    echo "--- Joomla Security Scanner ---"
    echo "No Joomla installation detected (looked for configuration.php with JConfig class)"
    exit 0
fi

# Determine scan directories
SCAN_DIRS=()
for dir in components administrator/components plugins modules templates; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Include root for configuration.php
SCAN_DIRS+=("$PROJECT_DIR")

# Helper: grep across Joomla source directories
scan_joomla() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.php" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

echo "--- Joomla Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-JOOMLA-01: SQL injection ===
echo "=== Checking for SQL Injection ==="
# shellcheck disable=SC2016
SQLI=$(scan_joomla '->where\s*\(.*["\x27].*\.\s*\$|setQuery\s*\(\s*["\x27].*\$' 10)
if [[ -n "$SQLI" ]]; then
    echo "ERROR: Database queries with string concatenation found:"
    echo "$SQLI" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SQL injection patterns detected"
fi

# === SA-JOOMLA-02: Input filtering ===
echo ""
echo "=== Checking for Unfiltered Input ==="
# shellcheck disable=SC2016
RAW_INPUT=$(scan_joomla "->get\s*\([^,)]+\s*,\s*[^,)]*\s*,\s*['\"]RAW['\"]" 10)
SUPERGLOBALS=$(scan_joomla '\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[' 10)
if [[ -n "$RAW_INPUT" || -n "$SUPERGLOBALS" ]]; then
    echo "ERROR: Unfiltered input detected:"
    [[ -n "$RAW_INPUT" ]] && echo "$RAW_INPUT" | head -5
    [[ -n "$SUPERGLOBALS" ]] && echo "$SUPERGLOBALS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: Input appears to use JInput filtering"
fi

# === SA-JOOMLA-04: configuration.php hardening ===
echo ""
echo "=== Checking configuration.php Hardening ==="
if [[ -f "$PROJECT_DIR/configuration.php" ]]; then
    DEBUG_ON=$(grep -n 'debug.*=.*1' "$PROJECT_DIR/configuration.php" 2>/dev/null || true)
    if [[ -n "$DEBUG_ON" ]]; then
        echo "WARNING: Debug mode enabled in configuration.php"
        WARNINGS=$((WARNINGS + 1))
    fi

    WEAK_SECRET=$(grep -n "secret.*=.*'joomla'" "$PROJECT_DIR/configuration.php" 2>/dev/null || true)
    if [[ -n "$WEAK_SECRET" ]]; then
        echo "ERROR: Weak/default secret in configuration.php"
        ERRORS=$((ERRORS + 1))
    fi

    MAX_ERRORS=$(grep -n "error_reporting.*=.*'maximum'" "$PROJECT_DIR/configuration.php" 2>/dev/null || true)
    if [[ -n "$MAX_ERRORS" ]]; then
        echo "WARNING: Maximum error reporting enabled in configuration.php"
        WARNINGS=$((WARNINGS + 1))
    fi

    FTP_PASS=$(grep -n "ftp_pass.*=.*'[^']'" "$PROJECT_DIR/configuration.php" 2>/dev/null | grep -v "ftp_pass.*=.*''" || true)
    if [[ -n "$FTP_PASS" ]]; then
        echo "ERROR: FTP password stored in configuration.php"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "OK: configuration.php not found in scan path"
fi

echo ""
echo "--- Joomla Scanner Summary ---"
echo "Errors: $ERRORS | Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
