#!/bin/bash
# Rust Security Scanner Module
# Scans Rust projects for common vulnerability patterns
# Excludes target/ directory

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Rust source directories
SCAN_DIRS=()
for dir in src examples tests benches; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all Rust source directories, excluding target/
scan_rs() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.rs" --exclude-dir=target --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Rust source directories
scan_rs_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.rs" --exclude-dir=target --exclude-dir=.git 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Rust Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Rust source directories found (looked for src/, examples/, tests/, benches/)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === Check for unsafe blocks/fn/impl ===
echo "=== Checking for unsafe Usage ==="
UNSAFE_COUNT=$(scan_rs_count 'unsafe\s*\{|unsafe\s+fn\s|unsafe\s+impl\s')
if [[ "$UNSAFE_COUNT" -gt 0 ]]; then
    echo "WARNING: $UNSAFE_COUNT unsafe block/fn/impl found — audit required:"
    scan_rs 'unsafe\s*\{|unsafe\s+fn\s|unsafe\s+impl\s' 5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unsafe usage detected"
fi

# === Check for FFI boundaries ===
echo ""
echo "=== Checking for FFI Boundaries ==="
FFI=$(scan_rs 'extern\s+"C"\s*\{|#\[no_mangle\]' 10)
if [[ -n "$FFI" ]]; then
    echo "WARNING: FFI boundaries found — audit for null checks and lifetime safety:"
    echo "$FFI" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No FFI boundaries detected"
fi

# === Check for panic!/todo!/unimplemented! ===
echo ""
echo "=== Checking for Panic Macros ==="
PANICS=$(scan_rs 'panic!\s*\(|todo!\s*\(|unimplemented!\s*\(' 10)
if [[ -n "$PANICS" ]]; then
    echo "WARNING: panic!/todo!/unimplemented! found — can cause DoS:"
    echo "$PANICS" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No panic macros detected"
fi

# === Check for .unwrap()/.expect() ===
echo ""
echo "=== Checking for .unwrap()/.expect() ==="
UNWRAP_COUNT=$(scan_rs_count '\.unwrap\(\)|\.expect\(\s*"')
if [[ "$UNWRAP_COUNT" -gt 0 ]]; then
    echo "WARNING: $UNWRAP_COUNT .unwrap()/.expect() calls found — use ? in production paths:"
    scan_rs '\.unwrap\(\)|\.expect\(\s*"' 5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No .unwrap()/.expect() calls detected"
fi

# === Check for raw pointer casts ===
echo ""
echo "=== Checking for Raw Pointer Casts ==="
RAW_PTR=$(scan_rs 'as\s+\*const\s|as\s+\*mut\s')
if [[ -n "$RAW_PTR" ]]; then
    echo "WARNING: Raw pointer casts found:"
    echo "$RAW_PTR"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No raw pointer casts detected"
fi

# === Check for SQL injection ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_FMT=$(scan_rs 'sql_query\s*\(\s*format!|query.*&format!')
if [[ -n "$SQL_FMT" ]]; then
    echo "ERROR: SQL query with format! string:"
    echo "$SQL_FMT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No SQL injection patterns detected"
fi

# === Check for command injection ===
echo ""
echo "=== Checking for Command Injection ==="
CMD_INJECT=$(scan_rs 'Command::new\s*\(\s*"(sh|bash|cmd|powershell)"')
if [[ -n "$CMD_INJECT" ]]; then
    echo "ERROR: Shell invocation via Command::new:"
    echo "$CMD_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No shell invocation patterns detected"
fi

# === Check for mem::forget / ManuallyDrop ===
echo ""
echo "=== Checking for Memory Leak Patterns ==="
MEM_FORGET=$(scan_rs 'mem::forget\s*\(|ManuallyDrop::new\s*\(')
if [[ -n "$MEM_FORGET" ]]; then
    echo "WARNING: mem::forget/ManuallyDrop found — sensitive data may persist:"
    echo "$MEM_FORGET"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No mem::forget/ManuallyDrop patterns detected"
fi

# === Check for hardcoded secrets ===
echo ""
echo "=== Checking for Hardcoded Secrets ==="
SECRETS=$(scan_rs '(password|secret|api_key|token)\s*[:=]\s*"[^"]{8,}"' 10)
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials found:"
    echo "$SECRETS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === Check for timing-unsafe comparisons ===
echo ""
echo "=== Checking for Timing-Unsafe Comparisons ==="
TIMING=$(scan_rs '==\s*(token|secret|hmac|hash|key|password|mac|signature)')
if [[ -n "$TIMING" ]]; then
    echo "ERROR: Non-constant-time comparison of secret:"
    echo "$TIMING"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No timing-unsafe comparisons detected"
fi

# === Check for transmute ===
echo ""
echo "=== Checking for transmute Usage ==="
TRANSMUTE=$(scan_rs 'mem::transmute|std::mem::transmute')
if [[ -n "$TRANSMUTE" ]]; then
    echo "ERROR: transmute found — extremely dangerous, audit required:"
    echo "$TRANSMUTE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No transmute usage detected"
fi

# === Check dependencies with cargo audit ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/Cargo.lock" ]]; then
    if command -v cargo-audit &> /dev/null; then
        AUDIT_OUTPUT=$(cd "$PROJECT_DIR" && cargo audit 2>&1 || true)
        if echo "$AUDIT_OUTPUT" | grep -q "Vulnerability"; then
            echo "WARNING: Vulnerable dependencies found:"
            echo "$AUDIT_OUTPUT" | head -20
            WARNINGS=$((WARNINGS + 1))
        else
            echo "OK: No known vulnerable dependencies"
        fi
    else
        echo "INFO: cargo-audit not available — install with: cargo install cargo-audit"
    fi
else
    echo "INFO: No Cargo.lock found — skipping dependency check"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Rust Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"
