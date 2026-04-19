#!/bin/bash
# JavaScript/TypeScript Security Scanner Module
# Scans JS/TS projects for common vulnerability patterns
# Modeled after php.sh scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect JS/TS source directories
SCAN_DIRS=()
for dir in src lib app pages components; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# If no standard directories found, scan project root (excluding node_modules)
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

JS_INCLUDES="--include=*.js --include=*.ts --include=*.jsx --include=*.tsx --include=*.mjs --include=*.cjs"

# Helper: grep across all JS/TS source directories
scan_js() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        # shellcheck disable=SC2086
        matches=$(grep -rn -P "$pattern" "$dir" $JS_INCLUDES --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build --exclude-dir=.next --exclude-dir=coverage 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all JS/TS source directories
scan_js_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        # shellcheck disable=SC2086
        count=$(grep -rn -P "$pattern" "$dir" $JS_INCLUDES --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build --exclude-dir=.next --exclude-dir=coverage 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- JavaScript/TypeScript Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === Check for eval() usage (SA-JS-01) ===
echo "=== Checking for eval() Usage ==="
EVAL_HITS=$(scan_js 'eval\(' 10)
if [[ -n "$EVAL_HITS" ]]; then
    echo "ERROR: eval() usage detected (potential code injection):"
    echo "$EVAL_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No eval() usage detected"
fi

# === Check for innerHTML assignment (SA-JS-02) ===
echo ""
echo "=== Checking for innerHTML Assignment ==="
INNERHTML_HITS=$(scan_js '\.innerHTML\s*=' 10)
if [[ -n "$INNERHTML_HITS" ]]; then
    echo "ERROR: innerHTML assignment detected (potential DOM XSS):"
    echo "$INNERHTML_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No innerHTML assignments detected"
fi

# === Check for document.write (SA-JS-03) ===
echo ""
echo "=== Checking for document.write() ==="
DOCWRITE_HITS=$(scan_js 'document\.write\(' 10)
if [[ -n "$DOCWRITE_HITS" ]]; then
    echo "ERROR: document.write() detected (potential DOM XSS):"
    echo "$DOCWRITE_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No document.write() usage detected"
fi

# === Check for __proto__ access (SA-JS-06) ===
echo ""
echo "=== Checking for Prototype Pollution Vectors ==="
PROTO_HITS=$(scan_js '__proto__' 10)
if [[ -n "$PROTO_HITS" ]]; then
    echo "ERROR: __proto__ access detected (prototype pollution risk):"
    echo "$PROTO_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No __proto__ access detected"
fi

# === Check for Math.random() in security context (SA-JS-05) ===
echo ""
echo "=== Checking for Insecure Randomness ==="
RANDOM_HITS=$(scan_js 'Math\.random\(\)' 10)
if [[ -n "$RANDOM_HITS" ]]; then
    # Check if used for tokens/keys/secrets
    SECURITY_RANDOM=$(echo "$RANDOM_HITS" | grep -iE '(token|key|secret|session|csrf|nonce|password|auth|id)' || true)
    if [[ -n "$SECURITY_RANDOM" ]]; then
        echo "ERROR: Math.random() used in security-sensitive context:"
        echo "$SECURITY_RANDOM" | head -5
        ERRORS=$((ERRORS + 1))
    else
        echo "WARNING: Math.random() usage found (verify not used for security):"
        echo "$RANDOM_HITS" | head -3
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "OK: No Math.random() usage detected"
fi

# === Check for Function constructor (SA-JS-07) ===
echo ""
echo "=== Checking for Function Constructor ==="
FUNC_HITS=$(scan_js 'new\s+Function\(' 10)
if [[ -n "$FUNC_HITS" ]]; then
    echo "ERROR: Function constructor detected (equivalent to eval):"
    echo "$FUNC_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No Function constructor usage detected"
fi

# === Check for setTimeout/setInterval with string (SA-JS-08, SA-JS-15) ===
echo ""
echo "=== Checking for Implicit eval in Timers ==="
TIMER_HITS=$(scan_js "setTimeout\(\s*['\"\`]" 10)
INTERVAL_HITS=$(scan_js "setInterval\(\s*['\"\`]" 10)
if [[ -n "$TIMER_HITS" || -n "$INTERVAL_HITS" ]]; then
    echo "ERROR: Timer with string argument detected (implicit eval):"
    [[ -n "$TIMER_HITS" ]] && echo "$TIMER_HITS" | head -3
    [[ -n "$INTERVAL_HITS" ]] && echo "$INTERVAL_HITS" | head -3
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No string-form timer arguments detected"
fi

# === Check for postMessage without origin check (SA-JS-04) ===
echo ""
echo "=== Checking for postMessage Handlers ==="
POSTMSG_HANDLERS=$(scan_js_count "addEventListener\(.message")
if [[ "$POSTMSG_HANDLERS" -gt 0 ]]; then
    ORIGIN_CHECKS=$(scan_js_count "event\.origin|e\.origin|msg\.origin")
    if [[ "$ORIGIN_CHECKS" -eq 0 ]]; then
        echo "WARNING: postMessage handler(s) found without origin validation"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: postMessage handlers with origin checks detected"
    fi
else
    echo "OK: No postMessage handlers detected"
fi

# === Check for outerHTML assignment (SA-JS-09) ===
echo ""
echo "=== Checking for outerHTML Assignment ==="
OUTERHTML_HITS=$(scan_js '\.outerHTML\s*=' 10)
if [[ -n "$OUTERHTML_HITS" ]]; then
    echo "ERROR: outerHTML assignment detected (potential DOM XSS):"
    echo "$OUTERHTML_HITS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No outerHTML assignments detected"
fi

# === Check for debugger statements (SA-JS-10) ===
echo ""
echo "=== Checking for debugger Statements ==="
DEBUGGER_HITS=$(scan_js '\bdebugger\b' 10)
if [[ -n "$DEBUGGER_HITS" ]]; then
    echo "WARNING: debugger statements found (must not ship to production):"
    echo "$DEBUGGER_HITS" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No debugger statements detected"
fi

# === Check for wildcard postMessage (SA-JS-17) ===
echo ""
echo "=== Checking for Wildcard postMessage ==="
WILDCARD_PM=$(scan_js "postMessage\([^,]+,\s*['\"]\\*['\"]" 10)
if [[ -n "$WILDCARD_PM" ]]; then
    echo "ERROR: postMessage with wildcard '*' origin:"
    echo "$WILDCARD_PM" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No wildcard postMessage targets detected"
fi

# === Check for npm audit vulnerabilities ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/package-lock.json" ]] || [[ -f "$PROJECT_DIR/yarn.lock" ]]; then
    if command -v npm &> /dev/null && [[ -f "$PROJECT_DIR/package-lock.json" ]]; then
        AUDIT_OUTPUT=$(cd "$PROJECT_DIR" && npm audit --json 2>/dev/null | head -50 || true)
        VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -o '"vulnerabilities"' | wc -l || echo "0")
        if [[ "$VULN_COUNT" -gt 0 ]]; then
            echo "WARNING: Vulnerable dependencies found (run 'npm audit' for details)"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "OK: No known vulnerable dependencies"
        fi
    else
        echo "WARNING: npm not available or no package-lock.json for dependency audit"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "WARNING: No package-lock.json or yarn.lock found"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check TypeScript strict mode (SA-JS-19) ===
echo ""
echo "=== Checking TypeScript Strict Mode ==="
if [[ -f "$PROJECT_DIR/tsconfig.json" ]]; then
    STRICT_ENABLED=$(grep -c '"strict"\s*:\s*true' "$PROJECT_DIR/tsconfig.json" 2>/dev/null || echo "0")
    STRICT_DISABLED=$(grep -c '"strict"\s*:\s*false' "$PROJECT_DIR/tsconfig.json" 2>/dev/null || echo "0")
    if [[ "$STRICT_DISABLED" -gt 0 ]]; then
        echo "WARNING: TypeScript strict mode is explicitly disabled"
        WARNINGS=$((WARNINGS + 1))
    elif [[ "$STRICT_ENABLED" -gt 0 ]]; then
        echo "OK: TypeScript strict mode is enabled"
    else
        echo "WARNING: TypeScript strict mode not configured (defaults to false)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "INFO: No tsconfig.json found (not a TypeScript project)"
fi

# === Output results for dispatcher ===
echo ""
echo "--- JavaScript/TypeScript Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"
