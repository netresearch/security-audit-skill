#!/bin/bash
# iOS Security Scanner Module
# Scans iOS projects for common vulnerability patterns
# Part of security-audit-skill multi-language scanning

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect: iOS project must have Info.plist or *.xcodeproj
INFO_PLIST=$(find "$PROJECT_DIR" -name "Info.plist" -not -path "*/build/*" -not -path "*/Pods/*" -not -path "*/DerivedData/*" 2>/dev/null | head -1)
XCODEPROJ=$(find "$PROJECT_DIR" -name "*.xcodeproj" -not -path "*/Pods/*" 2>/dev/null | head -1)

if [[ -z "$INFO_PLIST" ]] && [[ -z "$XCODEPROJ" ]]; then
    echo "No Info.plist or .xcodeproj found — not an iOS project"
    exit 0
fi

# Auto-detect source directories
SCAN_DIRS=()
for dir in Sources src App app; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across Swift and Objective-C files
scan_ios() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.swift" --include="*.m" --include="*.mm" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: grep Info.plist
scan_plist() {
    local pattern="$1"
    if [[ -n "$INFO_PLIST" ]]; then
        grep -n -P "$pattern" "$INFO_PLIST" 2>/dev/null || true
    fi
}

# Helper: grep pbxproj files
scan_pbxproj() {
    local pattern="$1"
    local limit="${2:-5}"
    grep -rn -P "$pattern" "$PROJECT_DIR" --include="*.pbxproj" 2>/dev/null | head -"$limit" || true
}

echo "--- iOS Security Scanner ---"
[[ -n "$INFO_PLIST" ]] && echo "Info.plist: $INFO_PLIST"
[[ -n "$XCODEPROJ" ]] && echo "Xcode project: $XCODEPROJ"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-IOS-01: Insecure Keychain accessibility ===
echo "=== Checking for Insecure Keychain Accessibility ==="
KEYCHAIN=$(scan_ios 'kSecAttrAccessibleAlways[^T]|kSecAttrAccessibleAlways$' 10)
if [[ -n "$KEYCHAIN" ]]; then
    echo "ERROR: kSecAttrAccessibleAlways usage found (SA-IOS-01):"
    echo "$KEYCHAIN" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No insecure Keychain accessibility detected"
fi

# === SA-IOS-02: App Transport Security disabled ===
echo ""
echo "=== Checking for ATS Configuration ==="
ATS=$(scan_plist 'NSAllowsArbitraryLoads')
if [[ -n "$ATS" ]]; then
    ATS_TRUE=$(scan_plist 'NSAllowsArbitraryLoads' | grep -A1 'NSAllowsArbitraryLoads' | grep -i 'true' || true)
    if [[ -n "$ATS_TRUE" ]]; then
        echo "ERROR: NSAllowsArbitraryLoads is true (SA-IOS-02):"
        echo "$ATS"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: NSAllowsArbitraryLoads present but not set to true"
    fi
else
    echo "OK: No ATS override detected"
fi

# === SA-IOS-03: UIWebView usage ===
echo ""
echo "=== Checking for Deprecated UIWebView ==="
UIWEBVIEW=$(scan_ios 'UIWebView' 10)
if [[ -n "$UIWEBVIEW" ]]; then
    echo "ERROR: Deprecated UIWebView usage found (SA-IOS-03):"
    echo "$UIWEBVIEW" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No UIWebView usage detected"
fi

# === SA-IOS-04: Pasteboard with sensitive data ===
echo ""
echo "=== Checking for Pasteboard Sensitive Data ==="
PASTE=$(scan_ios 'UIPasteboard\.general\.(string|setString|setItems|setValue)' 10)
if [[ -n "$PASTE" ]]; then
    echo "WARNING: General pasteboard usage found — review for sensitive data (SA-IOS-04):"
    echo "$PASTE" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No general pasteboard usage detected"
fi

# === SA-IOS-05: UserDefaults for sensitive data ===
echo ""
echo "=== Checking for Sensitive Data in UserDefaults ==="
DEFAULTS=$(scan_ios 'UserDefaults\.(standard\.)?set\s*\([^,]+,\s*forKey:\s*"(token|password|secret|key|credential|session|auth)' 10)
NSDEFAULTS=$(scan_ios 'NSUserDefaults.*set(Object|Value).*forKey.*@"(token|password|secret)' 10)
if [[ -n "$DEFAULTS" ]] || [[ -n "$NSDEFAULTS" ]]; then
    echo "ERROR: Sensitive data in UserDefaults (SA-IOS-05):"
    [[ -n "$DEFAULTS" ]] && echo "$DEFAULTS" | head -5
    [[ -n "$NSDEFAULTS" ]] && echo "$NSDEFAULTS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No sensitive UserDefaults usage detected"
fi

# === SA-IOS-06: URL scheme handlers ===
echo ""
echo "=== Checking for URL Scheme Handlers ==="
URLSCHEME=$(scan_ios 'application\s*\(\s*_\s+app.*open\s+url:\s*URL|openURL:\s*\(NSURL\s*\*\)' 10)
if [[ -n "$URLSCHEME" ]]; then
    echo "WARNING: URL scheme handler found — verify validation (SA-IOS-06):"
    echo "$URLSCHEME" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No URL scheme handlers detected"
fi

# === SA-IOS-07: Insecure random ===
echo ""
echo "=== Checking for Insecure Random ==="
RAND=$(scan_ios 'arc4random\s*\(|arc4random_uniform\s*\(' 10)
if [[ -n "$RAND" ]]; then
    echo "WARNING: arc4random usage found — review for security context (SA-IOS-07):"
    echo "$RAND" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No arc4random usage detected"
fi

# === SA-IOS-08: Weak hash algorithms ===
echo ""
echo "=== Checking for Weak Hash Algorithms ==="
WEAKHASH=$(scan_ios 'CC_MD5\s*\(|CC_SHA1\s*\(|CC_MD5_DIGEST_LENGTH' 10)
if [[ -n "$WEAKHASH" ]]; then
    echo "WARNING: Weak hash algorithm found (SA-IOS-08):"
    echo "$WEAKHASH" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash algorithms detected"
fi

# === SA-IOS-09: Binary protection settings ===
echo ""
echo "=== Checking for Binary Protection Settings ==="
NO_PIE=$(scan_pbxproj 'GCC_GENERATE_POSITION_DEPENDENT_CODE\s*=\s*YES')
NO_ARC=$(scan_pbxproj 'CLANG_ENABLE_OBJC_ARC\s*=\s*NO')
if [[ -n "$NO_PIE" ]] || [[ -n "$NO_ARC" ]]; then
    echo "ERROR: Missing binary protections (SA-IOS-09):"
    [[ -n "$NO_PIE" ]] && echo "  PIE disabled: $NO_PIE"
    [[ -n "$NO_ARC" ]] && echo "  ARC disabled: $NO_ARC"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: Binary protections appear enabled"
fi

# === SA-IOS-10: Sensitive data in NSLog ===
echo ""
echo "=== Checking for Sensitive NSLog Output ==="
NSLOG=$(scan_ios 'NSLog\s*\(\s*@?"[^"]*%[@dfs][^"]*"\s*,\s*[^)]*?(password|token|secret|key|credential|session)' 10)
PRINT=$(scan_ios 'print\s*\(\s*"[^"]*\\?\(\s*(password|token|secret|key|credential|session)' 10)
if [[ -n "$NSLOG" ]] || [[ -n "$PRINT" ]]; then
    echo "WARNING: Sensitive data in log output (SA-IOS-10):"
    [[ -n "$NSLOG" ]] && echo "$NSLOG" | head -5
    [[ -n "$PRINT" ]] && echo "$PRINT" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No sensitive log output detected"
fi

# === Summary ===
echo ""
echo "--- iOS Security Scan Summary ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
