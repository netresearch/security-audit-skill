#!/bin/bash
# Drupal Security Scanner Module
# Detects Drupal projects via sites/default/settings.php
# Scans for common Drupal-specific vulnerability patterns

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Drupal project
DRUPAL_DETECTED=false
if [[ -f "$PROJECT_DIR/sites/default/settings.php" ]] || [[ -f "$PROJECT_DIR/core/lib/Drupal.php" ]]; then
    DRUPAL_DETECTED=true
fi

if [[ "$DRUPAL_DETECTED" != "true" ]]; then
    echo "--- Drupal Security Scanner ---"
    echo "No Drupal installation detected (looked for sites/default/settings.php, core/lib/Drupal.php)"
    exit 0
fi

# Determine scan directories
SCAN_DIRS=()
for dir in modules/custom themes/custom src; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
# Also check sites/default for settings.php
if [[ -d "$PROJECT_DIR/sites/default" ]]; then
    SCAN_DIRS+=("$PROJECT_DIR/sites/default")
fi

if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "--- Drupal Security Scanner ---"
    echo "No custom module/theme directories found (looked for modules/custom/, themes/custom/, src/)"
    exit 0
fi

# Helper: grep across Drupal source directories
scan_drupal() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.php" --include="*.module" --include="*.install" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

scan_drupal_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.php" --include="*.module" --include="*.install" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Drupal Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-DRUPAL-01: SQL injection ===
echo "=== Checking for SQL Injection ==="
# shellcheck disable=SC2016
SQLI=$(scan_drupal 'db_query\s*\(\s*["\x27].*\$|->query\s*\(\s*["\x27].*\$' 10)
if [[ -n "$SQLI" ]]; then
    echo "ERROR: Database queries with string interpolation found:"
    echo "$SQLI" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SQL injection patterns detected"
fi

# === SA-DRUPAL-02/03: XSS via #markup ===
echo ""
echo "=== Checking for XSS via #markup ==="
# shellcheck disable=SC2016
MARKUP_XSS=$(scan_drupal '#markup.*\$' 10 | grep -v 'Html::escape\|Xss::filter\|check_plain\|->t(' || true)
if [[ -n "$MARKUP_XSS" ]]; then
    echo "ERROR: Render array #markup with unescaped variables:"
    echo "$MARKUP_XSS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious #markup XSS patterns detected"
fi

# === SA-DRUPAL-05: Entity query without accessCheck ===
echo ""
echo "=== Checking for Missing Entity Access Checks ==="
ENTITY_QUERY_COUNT=$(scan_drupal_count 'entityQuery\s*\(')
ACCESS_CHECK_COUNT=$(scan_drupal_count 'accessCheck\s*\(\s*TRUE\s*\)')
if [[ "$ENTITY_QUERY_COUNT" -gt 0 && "$ACCESS_CHECK_COUNT" -eq 0 ]]; then
    echo "ERROR: entityQuery() calls found but no accessCheck(TRUE) detected"
    ERRORS=$((ERRORS + 1))
elif [[ "$ENTITY_QUERY_COUNT" -gt "$ACCESS_CHECK_COUNT" ]]; then
    echo "WARNING: $ENTITY_QUERY_COUNT entityQuery() calls but only $ACCESS_CHECK_COUNT accessCheck(TRUE) calls"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: Entity queries appear to have access checks"
fi

# === SA-DRUPAL-06: settings.php misconfiguration ===
echo ""
echo "=== Checking settings.php Configuration ==="
if [[ -f "$PROJECT_DIR/sites/default/settings.php" ]]; then
    EMPTY_SALT=$(grep -n "hash_salt.*=\s*['\"]['\"]" "$PROJECT_DIR/sites/default/settings.php" 2>/dev/null || true)
    if [[ -n "$EMPTY_SALT" ]]; then
        echo "ERROR: Empty hash_salt in settings.php"
        ERRORS=$((ERRORS + 1))
    fi

    VERBOSE_ERRORS=$(grep -n "error_level.*verbose" "$PROJECT_DIR/sites/default/settings.php" 2>/dev/null || true)
    if [[ -n "$VERBOSE_ERRORS" ]]; then
        echo "WARNING: Verbose error reporting enabled"
        WARNINGS=$((WARNINGS + 1))
    fi

    UPDATE_ACCESS=$(grep -n "update_free_access.*TRUE" "$PROJECT_DIR/sites/default/settings.php" 2>/dev/null || true)
    if [[ -n "$UPDATE_ACCESS" ]]; then
        echo "ERROR: update_free_access is TRUE — allows unauthenticated access to update.php"
        ERRORS=$((ERRORS + 1))
    fi

    TRUSTED_HOST=$(grep -n "trusted_host_patterns" "$PROJECT_DIR/sites/default/settings.php" 2>/dev/null || true)
    if [[ -z "$TRUSTED_HOST" ]]; then
        echo "WARNING: No trusted_host_patterns configured — HTTP Host header attacks possible"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "OK: settings.php not in scan path"
fi

echo ""
echo "--- Drupal Scanner Summary ---"
echo "Errors: $ERRORS | Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
