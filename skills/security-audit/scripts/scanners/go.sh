#!/bin/bash
# Go Security Scanner Module
# Scans Go projects for common vulnerability patterns
# Excludes vendor/ directory

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Go source directories
SCAN_DIRS=()
for dir in . cmd pkg internal api; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# If no standard dirs found, scan the project root
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all Go source directories, excluding vendor/
scan_go() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.go" --exclude-dir=vendor --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Go source directories
scan_go_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.go" --exclude-dir=vendor --exclude-dir=.git 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Go Security Scanner ---"
if [[ $(find "${SCAN_DIRS[@]}" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | head -1 | wc -l) -eq 0 ]]; then
    echo "No Go source files found"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === Check for unsafe package usage ===
echo "=== Checking for unsafe Package Usage ==="
UNSAFE=$(scan_go 'unsafe\.(Pointer|Sizeof|Slice|String|Offsetof|Alignof)' 10)
if [[ -n "$UNSAFE" ]]; then
    echo "WARNING: unsafe package usage found — audit required:"
    echo "$UNSAFE" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unsafe package usage detected"
fi

# === Check for text/template (XSS risk) ===
echo ""
echo "=== Checking for text/template Usage ==="
TEXT_TMPL=$(scan_go '"text/template"')
if [[ -n "$TEXT_TMPL" ]]; then
    echo "ERROR: text/template import found — use html/template for HTML output:"
    echo "$TEXT_TMPL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No text/template imports detected"
fi

# === Check for SQL injection patterns ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_CONCAT=$(scan_go '(Sprintf|"\s*\+).*(SELECT|INSERT|UPDATE|DELETE)' 5)
if [[ -n "$SQL_CONCAT" ]]; then
    echo "ERROR: SQL string concatenation found:"
    echo "$SQL_CONCAT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No SQL string concatenation detected"
fi

# === Check for command injection ===
echo ""
echo "=== Checking for Command Injection ==="
CMD_INJECT=$(scan_go 'exec\.Command\s*\(\s*"(sh|bash|cmd|powershell)"')
if [[ -n "$CMD_INJECT" ]]; then
    echo "ERROR: Shell invocation via exec.Command:"
    echo "$CMD_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No shell invocation patterns detected"
fi

# === Check for InsecureSkipVerify ===
echo ""
echo "=== Checking for Insecure TLS Configuration ==="
TLS_SKIP=$(scan_go 'InsecureSkipVerify\s*:\s*true')
if [[ -n "$TLS_SKIP" ]]; then
    echo "ERROR: TLS certificate verification disabled:"
    echo "$TLS_SKIP"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No InsecureSkipVerify found"
fi

# === Check for math/rand usage ===
echo ""
echo "=== Checking for Insecure Randomness ==="
MATH_RAND=$(scan_go '"math/rand"')
if [[ -n "$MATH_RAND" ]]; then
    echo "WARNING: math/rand imported — use crypto/rand for security-sensitive values:"
    echo "$MATH_RAND"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No math/rand imports detected"
fi

# === Check for hardcoded secrets ===
echo ""
echo "=== Checking for Hardcoded Secrets ==="
SECRETS=$(scan_go '(password|secret|apiKey|token)\s*[:=]\s*"[^"]{8,}"' 10)
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials found:"
    echo "$SECRETS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === Check for SSRF patterns ===
echo ""
echo "=== Checking for SSRF Patterns ==="
SSRF=$(scan_go 'http\.(Get|Post|Head)\s*\(.*\b(r\.|req\.|request\.|URL)')
if [[ -n "$SSRF" ]]; then
    echo "ERROR: HTTP request with user-controlled URL:"
    echo "$SSRF"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SSRF patterns detected"
fi

# === Check for path traversal ===
echo ""
echo "=== Checking for Path Traversal ==="
PATH_TRAV=$(scan_go 'filepath\.Join\s*\(.*\b(r\.|req\.|request\.|URL)')
if [[ -n "$PATH_TRAV" ]]; then
    echo "WARNING: filepath.Join with user input:"
    echo "$PATH_TRAV"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obvious path traversal patterns detected"
fi

# === Check for weak TLS versions ===
echo ""
echo "=== Checking for Weak TLS Versions ==="
WEAK_TLS=$(scan_go 'VersionTLS1[01]\b')
if [[ -n "$WEAK_TLS" ]]; then
    echo "ERROR: Weak TLS version configured:"
    echo "$WEAK_TLS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No weak TLS versions detected"
fi

# === Check for unstructured logging ===
echo ""
echo "=== Checking Logging Practices ==="
UNSTRUCTURED=$(scan_go_count 'log\.(Print|Fatal|Panic)(f|ln)?\s*\(')
STRUCTURED=$(scan_go_count 'slog\.(Info|Warn|Error|Debug)\s*\(')
if [[ "$UNSTRUCTURED" -gt 0 && "$STRUCTURED" -eq 0 ]]; then
    echo "WARNING: Only unstructured logging found ($UNSTRUCTURED calls) — consider log/slog"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: Logging practices look acceptable"
fi

# === Check dependencies for vulnerabilities ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/go.sum" ]]; then
    if command -v govulncheck &> /dev/null; then
        VULN_OUTPUT=$(cd "$PROJECT_DIR" && govulncheck ./... 2>&1 || true)
        if echo "$VULN_OUTPUT" | grep -q "Vulnerability"; then
            echo "WARNING: Vulnerable dependencies found:"
            echo "$VULN_OUTPUT" | head -20
            WARNINGS=$((WARNINGS + 1))
        else
            echo "OK: No known vulnerable dependencies"
        fi
    else
        echo "INFO: govulncheck not available — install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
else
    echo "INFO: No go.sum found — skipping dependency check"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Go Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"
