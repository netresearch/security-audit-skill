#!/bin/bash
# Node.js Security Scanner Module
# Scans Node.js/TypeScript projects for common vulnerability patterns
# Part of the security-audit-skill scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Node.js source directories
SCAN_DIRS=()
for dir in src lib server api routes controllers middleware services handlers; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# If no standard dirs found, check for .js/.ts files in project root
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    if ls "$PROJECT_DIR"/*.{js,ts,mjs,cjs} 1>/dev/null 2>&1; then
        SCAN_DIRS+=("$PROJECT_DIR")
    fi
fi

# Helper: grep across all Node.js source directories
scan_node() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.js" --include="*.ts" --include="*.mjs" --include="*.cjs" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Node.js source directories
scan_node_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.js" --include="*.ts" --include="*.mjs" --include="*.cjs" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Node.js Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Node.js source directories found (looked for src/, lib/, server/, api/, routes/, controllers/, middleware/, services/, handlers/)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === Check for command injection via child_process.exec ===
echo "=== Checking for Command Injection (child_process.exec) ==="
CMD_INJECTION=$(scan_node 'child_process.*exec\(' 10)
EXEC_CALLS=$(scan_node '\bexec(Sync)?\s*\(' 10 | grep -v 'execFile' || true)
if [[ -n "$CMD_INJECTION" || -n "$EXEC_CALLS" ]]; then
    echo "ERROR: Potential command injection via exec():"
    [[ -n "$CMD_INJECTION" ]] && echo "$CMD_INJECTION"
    [[ -n "$EXEC_CALLS" ]] && echo "$EXEC_CALLS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No child_process.exec() calls detected"
fi

# === Check for path traversal via fs operations ===
echo ""
echo "=== Checking for Path Traversal (fs with user input) ==="
# shellcheck disable=SC2016
FS_USER=$(scan_node 'fs\.(readFile|writeFile|readdir|unlink|access|stat|createReadStream|createWriteStream)\s*\([^)]*req\.(query|params|body)' 10)
if [[ -n "$FS_USER" ]]; then
    echo "ERROR: fs operations with potential user input:"
    echo "$FS_USER"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious fs path traversal patterns detected"
fi

# === Check for vm/vm2 usage ===
echo ""
echo "=== Checking for vm/vm2 Sandbox Usage ==="
VM_USAGE=$(scan_node "require\s*\(\s*['\"]vm2?['\"]\s*\)" 10)
VM_IMPORT=$(scan_node "from\s+['\"]vm2?['\"]" 10)
if [[ -n "$VM_USAGE" || -n "$VM_IMPORT" ]]; then
    echo "ERROR: vm/vm2 module usage detected (not a security boundary):"
    [[ -n "$VM_USAGE" ]] && echo "$VM_USAGE"
    [[ -n "$VM_IMPORT" ]] && echo "$VM_IMPORT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No vm/vm2 sandbox usage detected"
fi

# === Check for Buffer.allocUnsafe ===
echo ""
echo "=== Checking for Buffer.allocUnsafe ==="
BUFFER_UNSAFE=$(scan_node 'Buffer\.(allocUnsafe|allocUnsafeSlow)\s*\(' 10)
if [[ -n "$BUFFER_UNSAFE" ]]; then
    echo "WARNING: Buffer.allocUnsafe usage (may leak memory contents):"
    echo "$BUFFER_UNSAFE"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No Buffer.allocUnsafe usage detected"
fi

# === Check for dynamic require ===
echo ""
echo "=== Checking for Dynamic require() ==="
DYN_REQUIRE=$(scan_node 'require\s*\(\s*[^'"'"'"]\s*[+`]' 10)
DYN_IMPORT=$(scan_node 'import\s*\(\s*[^'"'"'"]\s*[+`]' 10)
if [[ -n "$DYN_REQUIRE" || -n "$DYN_IMPORT" ]]; then
    echo "ERROR: Dynamic require/import with variable path:"
    [[ -n "$DYN_REQUIRE" ]] && echo "$DYN_REQUIRE"
    [[ -n "$DYN_IMPORT" ]] && echo "$DYN_IMPORT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No dynamic require/import patterns detected"
fi

# === Check for http.createServer without timeouts ===
echo ""
echo "=== Checking for Insecure HTTP Server Configuration ==="
HTTP_SERVER=$(scan_node 'http\.createServer\s*\(' 10)
if [[ -n "$HTTP_SERVER" ]]; then
    TIMEOUTS=$(scan_node_count '(headersTimeout|requestTimeout|keepAliveTimeout)\s*=')
    if [[ "$TIMEOUTS" -eq 0 ]]; then
        echo "WARNING: http.createServer without timeout configuration:"
        echo "$HTTP_SERVER"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: HTTP server with timeout configuration detected"
    fi
else
    echo "OK: No bare http.createServer usage"
fi

# === Check for header injection ===
echo ""
echo "=== Checking for HTTP Header Injection ==="
# shellcheck disable=SC2016
HEADER_INJECT=$(scan_node 'res\.(setHeader|writeHead)\s*\([^)]*req\.(query|params|body|headers)' 10)
if [[ -n "$HEADER_INJECT" ]]; then
    echo "ERROR: User input in HTTP response headers:"
    echo "$HEADER_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No header injection patterns detected"
fi

# === Check for Math.random in security context ===
echo ""
echo "=== Checking for Insecure Randomness ==="
MATH_RANDOM=$(scan_node 'Math\.random\s*\(' 10)
if [[ -n "$MATH_RANDOM" ]]; then
    echo "WARNING: Math.random() usage (not cryptographically secure):"
    echo "$MATH_RANDOM" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No Math.random() usage detected"
fi

# === Check for weak crypto algorithms ===
echo ""
echo "=== Checking for Weak Crypto Algorithms ==="
WEAK_CRYPTO=$(scan_node "createHash\s*\(\s*['\"]md5['\"]" 10)
WEAK_SHA1=$(scan_node "createHash\s*\(\s*['\"]sha1['\"]" 10)
if [[ -n "$WEAK_CRYPTO" || -n "$WEAK_SHA1" ]]; then
    echo "WARNING: Weak cryptographic hash algorithms:"
    [[ -n "$WEAK_CRYPTO" ]] && echo "$WEAK_CRYPTO"
    [[ -n "$WEAK_SHA1" ]] && echo "$WEAK_SHA1"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak crypto algorithms detected"
fi

# === Check for eval() usage ===
echo ""
echo "=== Checking for eval() Usage ==="
EVAL_USAGE=$(scan_node '\beval\s*\(' 10)
if [[ -n "$EVAL_USAGE" ]]; then
    echo "ERROR: eval() usage detected:"
    echo "$EVAL_USAGE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No eval() usage detected"
fi

# === Check for new Function() constructor ===
echo ""
echo "=== Checking for new Function() Constructor ==="
NEW_FUNC=$(scan_node 'new\s+Function\s*\(' 10)
if [[ -n "$NEW_FUNC" ]]; then
    echo "ERROR: new Function() constructor (equivalent to eval):"
    echo "$NEW_FUNC"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No new Function() usage detected"
fi

# === Check for SSRF via fetch ===
echo ""
echo "=== Checking for SSRF Patterns ==="
# shellcheck disable=SC2016
SSRF_FETCH=$(scan_node 'fetch\s*\(\s*req\.(query|params|body)' 10)
# shellcheck disable=SC2016
SSRF_HTTP=$(scan_node 'https?\.(get|request)\s*\([^)]*req\.(query|params|body)' 10)
if [[ -n "$SSRF_FETCH" || -n "$SSRF_HTTP" ]]; then
    echo "ERROR: Potential SSRF — user input in outgoing request URL:"
    [[ -n "$SSRF_FETCH" ]] && echo "$SSRF_FETCH"
    [[ -n "$SSRF_HTTP" ]] && echo "$SSRF_HTTP"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SSRF patterns detected"
fi

# === Check for prototype pollution ===
echo ""
echo "=== Checking for Prototype Pollution ==="
# shellcheck disable=SC2016
PROTO_POLL=$(scan_node '__proto__|Object\.assign\s*\([^,]+,\s*req\.(body|query|params)' 10)
if [[ -n "$PROTO_POLL" ]]; then
    echo "ERROR: Potential prototype pollution:"
    echo "$PROTO_POLL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious prototype pollution patterns detected"
fi

# === Check for npm audit ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/package-lock.json" || -f "$PROJECT_DIR/yarn.lock" || -f "$PROJECT_DIR/pnpm-lock.yaml" ]]; then
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
        echo "INFO: Lock file found but npm not available for audit"
    fi
else
    echo "WARNING: No lock file found (package-lock.json, yarn.lock, or pnpm-lock.yaml)"
    WARNINGS=$((WARNINGS + 1))
fi

# === Output results for dispatcher ===
echo ""
echo "--- Node.js Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"
