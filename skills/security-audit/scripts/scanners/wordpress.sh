#!/bin/bash
# WordPress Security Scanner Module
# Detects WordPress projects via wp-config.php / wp-content/
# Scans for common WordPress-specific vulnerability patterns

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect WordPress project
WP_DETECTED=false
if [[ -f "$PROJECT_DIR/wp-config.php" ]] || [[ -d "$PROJECT_DIR/wp-content" ]]; then
    WP_DETECTED=true
fi

if [[ "$WP_DETECTED" != "true" ]]; then
    echo "--- WordPress Security Scanner ---"
    echo "No WordPress installation detected (looked for wp-config.php, wp-content/)"
    exit 0
fi

# Determine scan directories (plugins, themes, mu-plugins)
SCAN_DIRS=()
for dir in wp-content/plugins wp-content/themes wp-content/mu-plugins; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Also scan root for wp-config.php checks
SCAN_DIRS+=("$PROJECT_DIR")

# Helper: grep across all WordPress source directories
scan_wp() {
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

# Helper: count matches
scan_wp_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.php" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- WordPress Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-WP-01: SQL injection — $wpdb without prepare() ===
echo "=== Checking for SQL Injection ($wpdb without prepare) ==="
# shellcheck disable=SC2016
SQLI=$(scan_wp '\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(\s*["\x27]' 10)
if [[ -n "$SQLI" ]]; then
    echo "ERROR: \$wpdb queries without \$wpdb->prepare() found:"
    echo "$SQLI" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SQL injection patterns detected"
fi

# === SA-WP-03: Unescaped output ===
echo ""
echo "=== Checking for Unescaped Output (XSS) ==="
UNESCAPED=$(scan_wp 'echo\s+\$' 10 | grep -v 'esc_html\|esc_attr\|esc_url\|wp_kses\|absint\|intval' || true)
if [[ -n "$UNESCAPED" ]]; then
    echo "WARNING: Potential unescaped output found:"
    echo "$UNESCAPED" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obvious unescaped output detected"
fi

# === SA-WP-04: REST API without permission_callback ===
echo ""
echo "=== Checking for REST API Permission Issues ==="
REST_ISSUES=$(scan_wp 'register_rest_route' 20 | grep -v 'permission_callback' || true)
REST_TRUE=$(scan_wp 'permission_callback.*__return_true' 10)
if [[ -n "$REST_ISSUES" || -n "$REST_TRUE" ]]; then
    echo "ERROR: REST API routes without proper permission_callback:"
    [[ -n "$REST_ISSUES" ]] && echo "$REST_ISSUES" | head -5
    [[ -n "$REST_TRUE" ]] && echo "$REST_TRUE" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: REST API routes appear to have permission callbacks"
fi

# === SA-WP-06: Missing nonce verification ===
echo ""
echo "=== Checking for Missing Nonce Verification ==="
# shellcheck disable=SC2016
POST_USAGE=$(scan_wp_count '\$_POST\[')
NONCE_COUNT=$(scan_wp_count 'wp_verify_nonce|check_ajax_referer|check_admin_referer')
if [[ "$POST_USAGE" -gt 0 && "$NONCE_COUNT" -eq 0 ]]; then
    echo "ERROR: \$_POST usage found but no nonce verification detected"
    ERRORS=$((ERRORS + 1))
elif [[ "$POST_USAGE" -gt "$((NONCE_COUNT * 3))" ]]; then
    echo "WARNING: \$_POST used $POST_USAGE times but only $NONCE_COUNT nonce checks found"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: Nonce verification appears proportional to POST usage"
fi

# === SA-WP-07: Direct file upload handling ===
echo ""
echo "=== Checking for Unsafe File Uploads ==="
UPLOADS=$(scan_wp 'move_uploaded_file\s*\(' 5)
if [[ -n "$UPLOADS" ]]; then
    echo "ERROR: Direct move_uploaded_file() usage — use wp_handle_upload():"
    echo "$UPLOADS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No direct file upload handling detected"
fi

# === SA-WP-08: wp-config.php hardening ===
echo ""
echo "=== Checking wp-config.php Hardening ==="
if [[ -f "$PROJECT_DIR/wp-config.php" ]]; then
    DEBUG_ON=$(grep -n 'WP_DEBUG.*true' "$PROJECT_DIR/wp-config.php" 2>/dev/null || true)
    if [[ -n "$DEBUG_ON" ]]; then
        echo "WARNING: WP_DEBUG is enabled:"
        echo "$DEBUG_ON"
        WARNINGS=$((WARNINGS + 1))
    fi

    DEFAULT_PREFIX=$(grep -n "table_prefix.*=.*'wp_'" "$PROJECT_DIR/wp-config.php" 2>/dev/null || true)
    if [[ -n "$DEFAULT_PREFIX" ]]; then
        echo "WARNING: Default table prefix wp_ detected"
        WARNINGS=$((WARNINGS + 1))
    fi

    DEFAULT_SALTS=$(grep -n 'put your unique phrase here' "$PROJECT_DIR/wp-config.php" 2>/dev/null || true)
    if [[ -n "$DEFAULT_SALTS" ]]; then
        echo "ERROR: Default security salts detected — generate unique salts"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "OK: wp-config.php not in scan directory"
fi

# === SA-WP-02: unserialize with user input ===
echo ""
echo "=== Checking for Object Injection (unserialize) ==="
# shellcheck disable=SC2016
UNSERIALIZE=$(scan_wp 'unserialize\s*\(\s*\$' 5)
if [[ -n "$UNSERIALIZE" ]]; then
    echo "ERROR: unserialize() with variable input — potential object injection:"
    echo "$UNSERIALIZE" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No unsafe unserialize() calls detected"
fi

echo ""
echo "--- WordPress Scanner Summary ---"
echo "Errors: $ERRORS | Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
