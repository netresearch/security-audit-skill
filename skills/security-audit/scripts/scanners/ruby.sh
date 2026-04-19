#!/bin/bash
# Ruby Security Scanner Module
# Scans Ruby projects for common vulnerability patterns
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Ruby source directories
SCAN_DIRS=()
for dir in app lib config; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all Ruby source directories
scan_ruby() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.rb" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Ruby source directories
scan_ruby_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.rb" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Ruby Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Ruby source directories found (looked for app/, lib/, config/)"
    exit 0
fi
echo "Scanning directories: ${SCAN_DIRS[*]}"
echo ""

# SA-RB-01: eval() code injection
count=$(scan_ruby_count '\beval\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-01: Found $count eval() call(s) — potential code injection"
    scan_ruby '\beval\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-02: send() method injection
count=$(scan_ruby_count '\.send\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-02: Found $count send() call(s) — potential method injection"
    scan_ruby '\.send\s*\('
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-03: system() command injection
count=$(scan_ruby_count '\bsystem\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-03: Found $count system() call(s) — verify no user input in command"
    scan_ruby '\bsystem\s*\('
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-03b: exec() command injection
count=$(scan_ruby_count '\bexec\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-03b: Found $count exec() call(s) — verify no user input in command"
    scan_ruby '\bexec\s*\('
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-04: Marshal.load insecure deserialization
count=$(scan_ruby_count 'Marshal\.load\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-04: Found $count Marshal.load() call(s) — insecure deserialization"
    scan_ruby 'Marshal\.load\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-05: YAML.load (not safe_load)
count=$(scan_ruby_count 'YAML\.load\b[^_]')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-05: Found $count YAML.load() call(s) — use YAML.safe_load instead"
    scan_ruby 'YAML\.load\b[^_]'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-06: ERB.new template injection
count=$(scan_ruby_count 'ERB\.new\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-06: Found $count ERB.new() call(s) — audit for template injection"
    scan_ruby 'ERB\.new\s*\('
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-07: find_by_sql SQL injection
count=$(scan_ruby_count 'find_by_sql\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-07: Found $count find_by_sql() call(s) — risk of SQL injection"
    scan_ruby 'find_by_sql\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-08: html_safe XSS bypass
count=$(scan_ruby_count '\.html_safe\b')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-08: Found $count html_safe call(s) — XSS escaping bypass"
    scan_ruby '\.html_safe\b'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-09: raw() XSS bypass
count=$(scan_ruby_count '\braw\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-09: Found $count raw() call(s) — XSS escaping bypass"
    scan_ruby '\braw\s*\('
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-10: Kernel.open pipe injection
count=$(scan_ruby_count '\bKernel\.open\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-10: Found $count Kernel.open() call(s) — pipe injection / SSRF risk"
    scan_ruby '\bKernel\.open\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-11: permit! mass assignment
count=$(scan_ruby_count '\.permit!\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-11: Found $count permit!() call(s) — mass assignment vulnerability"
    scan_ruby '\.permit!\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-RB-12: MD5 weak cryptography
count=$(scan_ruby_count 'Digest::MD5')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-12: Found $count Digest::MD5 usage(s) — use SHA-256 or bcrypt"
    scan_ruby 'Digest::MD5'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-13: SHA1 weak cryptography
count=$(scan_ruby_count 'Digest::SHA1')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-RB-13: Found $count Digest::SHA1 usage(s) — use SHA-256 or stronger"
    scan_ruby 'Digest::SHA1'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-RB-14: backtick command execution with interpolation
count=$(scan_ruby_count '`[^`]*#\{')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-RB-14: Found $count backtick command(s) with interpolation — command injection risk"
    scan_ruby '`[^`]*#\{'
    ERRORS=$((ERRORS + count))
    echo ""
fi

echo "--- Ruby Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS
