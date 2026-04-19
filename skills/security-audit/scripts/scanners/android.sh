#!/bin/bash
# Android Security Scanner Module
# Scans Android projects for common vulnerability patterns
# Part of security-audit-skill multi-language scanning

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect: Android project must have AndroidManifest.xml
MANIFEST=$(find "$PROJECT_DIR" -name "AndroidManifest.xml" -not -path "*/build/*" 2>/dev/null | head -1)
if [[ -z "$MANIFEST" ]]; then
    echo "No AndroidManifest.xml found — not an Android project"
    exit 0
fi

MANIFEST_DIR=$(dirname "$MANIFEST")

# Auto-detect source directories
SCAN_DIRS=()
for dir in app/src/main src/main src app; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across Android source directories (Kotlin + Java)
scan_android() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.kt" --include="*.java" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: grep manifest
scan_manifest() {
    local pattern="$1"
    grep -n -P "$pattern" "$MANIFEST" 2>/dev/null || true
}

# Helper: grep gradle files
scan_gradle() {
    local pattern="$1"
    local limit="${2:-5}"
    grep -rn -P "$pattern" "$PROJECT_DIR" --include="*.gradle" --include="*.gradle.kts" 2>/dev/null | head -"$limit" || true
}

echo "--- Android Security Scanner ---"
echo "Manifest: $MANIFEST"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-ANDROID-01: Exported components ===
echo "=== Checking for Exported Components ==="
EXPORTED=$(scan_manifest 'android:exported\s*=\s*"true"')
if [[ -n "$EXPORTED" ]]; then
    echo "WARNING: Exported components found (SA-ANDROID-01):"
    echo "$EXPORTED" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No explicitly exported components detected"
fi

# === SA-ANDROID-02: SQL injection in ContentProvider ===
echo ""
echo "=== Checking for SQL Injection in ContentProvider ==="
SQLI=$(scan_android 'rawQuery\s*\(\s*"[^"]*\+\s*\w+|rawQuery\s*\(\s*"[^"]*\$\{?' 10)
if [[ -n "$SQLI" ]]; then
    echo "ERROR: SQL injection in rawQuery found (SA-ANDROID-02):"
    echo "$SQLI" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No SQL injection patterns detected"
fi

# === SA-ANDROID-03: WebView JavaScript interface ===
echo ""
echo "=== Checking for WebView JavaScript Interface ==="
JSIF=$(scan_android 'addJavascriptInterface\s*\(' 10)
if [[ -n "$JSIF" ]]; then
    echo "ERROR: addJavascriptInterface usage found (SA-ANDROID-03):"
    echo "$JSIF" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No addJavascriptInterface usage detected"
fi

# === SA-ANDROID-04: SharedPreferences with sensitive data ===
echo ""
echo "=== Checking for Insecure SharedPreferences ==="
WORLD_READ=$(scan_android 'MODE_WORLD_READABLE' 10)
if [[ -n "$WORLD_READ" ]]; then
    echo "ERROR: MODE_WORLD_READABLE SharedPreferences found (SA-ANDROID-04):"
    echo "$WORLD_READ" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No MODE_WORLD_READABLE usage detected"
fi

# === SA-ANDROID-05: Cleartext traffic ===
echo ""
echo "=== Checking for Cleartext Traffic ==="
CLEARTEXT=$(scan_manifest 'usesCleartextTraffic\s*=\s*"true"')
if [[ -n "$CLEARTEXT" ]]; then
    echo "ERROR: Cleartext traffic allowed (SA-ANDROID-05):"
    echo "$CLEARTEXT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No cleartext traffic flag detected"
fi

# === SA-ANDROID-06: Debug mode ===
echo ""
echo "=== Checking for Debug Mode ==="
DEBUG_MANIFEST=$(scan_manifest 'android:debuggable\s*=\s*"true"')
DEBUG_GRADLE=$(scan_gradle 'debuggable\s+true')
if [[ -n "$DEBUG_MANIFEST" ]] || [[ -n "$DEBUG_GRADLE" ]]; then
    echo "ERROR: Debug mode enabled (SA-ANDROID-06):"
    [[ -n "$DEBUG_MANIFEST" ]] && echo "$DEBUG_MANIFEST"
    [[ -n "$DEBUG_GRADLE" ]] && echo "$DEBUG_GRADLE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No debug mode enabled"
fi

# === SA-ANDROID-07: Insecure broadcast receivers ===
echo ""
echo "=== Checking for Insecure Broadcast Receivers ==="
RECV=$(scan_android 'registerReceiver\s*\(\s*\w+\s*,\s*\w+\s*\)\s*$' 10)
if [[ -n "$RECV" ]]; then
    echo "WARNING: Broadcast receiver without permission found (SA-ANDROID-07):"
    echo "$RECV" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unprotected broadcast receivers detected"
fi

# === SA-ANDROID-08: Insecure random ===
echo ""
echo "=== Checking for Insecure Random ==="
RAND=$(scan_android 'new\s+Random\s*\(|java\.util\.Random|kotlin\.random\.Random' 10)
if [[ -n "$RAND" ]]; then
    echo "WARNING: Insecure random usage found (SA-ANDROID-08):"
    echo "$RAND" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure Random usage detected"
fi

# === SA-ANDROID-09: Hardcoded encryption keys ===
echo ""
echo "=== Checking for Hardcoded Keys ==="
HARDKEY=$(scan_android 'SecretKeySpec\s*\(\s*"[^"]+"|private\s+(static\s+)?final\s+byte\[\]\s+\w*(KEY|key|SECRET|secret)' 10)
if [[ -n "$HARDKEY" ]]; then
    echo "ERROR: Hardcoded encryption key found (SA-ANDROID-09):"
    echo "$HARDKEY" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No hardcoded encryption keys detected"
fi

# === SA-ANDROID-10: Sensitive data in logs ===
echo ""
echo "=== Checking for Sensitive Log Output ==="
LOGS=$(scan_android 'Log\.(d|v|i)\s*\(\s*"[^"]*"\s*,\s*[^)]*?(password|token|secret|key|credential|session)' 10)
if [[ -n "$LOGS" ]]; then
    echo "WARNING: Sensitive data in logs found (SA-ANDROID-10):"
    echo "$LOGS" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No sensitive log output detected"
fi

# === SA-ANDROID-11: Signing config with hardcoded passwords ===
echo ""
echo "=== Checking for Hardcoded Signing Credentials ==="
SIGN=$(scan_gradle 'storePassword\s+["'"'"'][^"'"'"']+["'"'"']|keyPassword\s+["'"'"'][^"'"'"']+["'"'"']')
if [[ -n "$SIGN" ]]; then
    echo "ERROR: Hardcoded signing credentials found (SA-ANDROID-11):"
    echo "$SIGN" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No hardcoded signing credentials detected"
fi

# === Summary ===
echo ""
echo "--- Android Security Scan Summary ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
