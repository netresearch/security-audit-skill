#!/bin/bash
# Python Security Scanner Module
# Scans Python projects for common vulnerability patterns
# Part of security-audit-skill Phase 4

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Python source directories
SCAN_DIRS=()
for dir in src lib app; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Also scan .py files in the project root
if ls "$PROJECT_DIR"/*.py 1>/dev/null 2>&1; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all Python source directories
scan_py() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        if [[ "$dir" == "$PROJECT_DIR" ]]; then
            # Only scan .py files in root, not recursively (subdirs handled separately)
            matches=$(grep -n -P "$pattern" "$dir"/*.py 2>/dev/null || true)
        else
            matches=$(grep -rn -P "$pattern" "$dir" --include="*.py" 2>/dev/null || true)
        fi
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Python source directories
scan_py_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        if [[ "$dir" == "$PROJECT_DIR" ]]; then
            count=$(grep -n -P "$pattern" "$dir"/*.py 2>/dev/null | wc -l || echo "0")
        else
            count=$(grep -rn -P "$pattern" "$dir" --include="*.py" 2>/dev/null | wc -l || echo "0")
        fi
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Python Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Python source files found (looked for src/, lib/, app/, and *.py in project root)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-PY-01: Insecure deserialization via pickle ===
echo "=== Checking for Insecure Deserialization (pickle/shelve/marshal) ==="
PICKLE_HITS=$(scan_py 'pickle\.(loads|load)\(' 10)
SHELVE_HITS=$(scan_py 'shelve\.open\(' 5)
MARSHAL_HITS=$(scan_py 'marshal\.loads\(' 5)
if [[ -n "$PICKLE_HITS" ]]; then
    echo "ERROR [SA-PY-01]: pickle.load/loads found — risk of arbitrary code execution:"
    echo "$PICKLE_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No pickle.load/loads calls detected"
fi
if [[ -n "$SHELVE_HITS" ]]; then
    echo "WARNING [SA-PY-17]: shelve.open found — uses pickle internally:"
    echo "$SHELVE_HITS"
    WARNINGS=$((WARNINGS + 1))
fi
if [[ -n "$MARSHAL_HITS" ]]; then
    echo "WARNING [SA-PY-18]: marshal.loads found — insecure deserialization:"
    echo "$MARSHAL_HITS"
    WARNINGS=$((WARNINGS + 1))
fi

# === SA-PY-02/03: eval() / exec() code injection ===
echo ""
echo "=== Checking for eval()/exec() Code Injection ==="
EVAL_HITS=$(scan_py 'eval\(' 10)
EXEC_HITS=$(scan_py 'exec\(' 10)
if [[ -n "$EVAL_HITS" ]]; then
    echo "ERROR [SA-PY-02]: eval() calls found — risk of code injection:"
    echo "$EVAL_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No eval() calls detected"
fi
if [[ -n "$EXEC_HITS" ]]; then
    echo "ERROR [SA-PY-03]: exec() calls found — risk of code injection:"
    echo "$EXEC_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No exec() calls detected"
fi

# === SA-PY-04/05/15: Command injection ===
echo ""
echo "=== Checking for Command Injection ==="
SHELL_TRUE=$(scan_py 'subprocess\.\w+\(.*shell\s*=\s*True' 10)
OS_SYSTEM=$(scan_py 'os\.system\(' 10)
OS_POPEN=$(scan_py 'os\.popen\(' 10)
if [[ -n "$SHELL_TRUE" ]]; then
    echo "ERROR [SA-PY-04]: subprocess with shell=True found:"
    echo "$SHELL_TRUE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No subprocess shell=True calls detected"
fi
if [[ -n "$OS_SYSTEM" ]]; then
    echo "ERROR [SA-PY-05]: os.system() calls found:"
    echo "$OS_SYSTEM"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No os.system() calls detected"
fi
if [[ -n "$OS_POPEN" ]]; then
    echo "ERROR [SA-PY-15]: os.popen() calls found:"
    echo "$OS_POPEN"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No os.popen() calls detected"
fi

# === SA-PY-06: Unsafe YAML loading ===
echo ""
echo "=== Checking for Unsafe YAML Loading ==="
YAML_LOAD=$(scan_py 'yaml\.load\(' 10)
if [[ -n "$YAML_LOAD" ]]; then
    # Check if safe_load is also used (might be a false positive context)
    SAFE_COUNT=$(scan_py_count 'yaml\.safe_load')
    echo "ERROR [SA-PY-06]: yaml.load() found — use yaml.safe_load() instead:"
    echo "$YAML_LOAD"
    ERRORS=$((ERRORS + 1))
    if [[ "$SAFE_COUNT" -gt 0 ]]; then
        echo "  Note: yaml.safe_load() also found ($SAFE_COUNT occurrences) — verify migration is complete"
    fi
else
    echo "OK: No unsafe yaml.load() calls detected"
fi

# === SA-PY-07/08: SQL injection ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_FSTRING=$(scan_py 'execute\(f"' 10)
SQL_FORMAT=$(scan_py 'execute\(.*\.format\(' 10)
if [[ -n "$SQL_FSTRING" ]]; then
    echo "ERROR [SA-PY-07]: SQL query with f-string found:"
    echo "$SQL_FSTRING"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No f-string SQL queries detected"
fi
if [[ -n "$SQL_FORMAT" ]]; then
    echo "ERROR [SA-PY-08]: SQL query with .format() found:"
    echo "$SQL_FORMAT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No .format() SQL queries detected"
fi

# === SA-PY-09/10: Weak hashing ===
echo ""
echo "=== Checking for Weak Hash Algorithms ==="
MD5_HITS=$(scan_py 'hashlib\.md5\(' 10)
SHA1_HITS=$(scan_py 'hashlib\.sha1\(' 10)
if [[ -n "$MD5_HITS" ]]; then
    echo "WARNING [SA-PY-09]: hashlib.md5() found — weak for security use:"
    echo "$MD5_HITS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No hashlib.md5() calls detected"
fi
if [[ -n "$SHA1_HITS" ]]; then
    echo "WARNING [SA-PY-10]: hashlib.sha1() found — weak for security use:"
    echo "$SHA1_HITS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No hashlib.sha1() calls detected"
fi

# === SA-PY-11: tempfile.mktemp race condition ===
echo ""
echo "=== Checking for tempfile Race Conditions ==="
MKTEMP_HITS=$(scan_py 'tempfile\.mktemp\(' 10)
if [[ -n "$MKTEMP_HITS" ]]; then
    echo "ERROR [SA-PY-11]: tempfile.mktemp() found — use mkstemp() instead:"
    echo "$MKTEMP_HITS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No tempfile.mktemp() calls detected"
fi

# === SA-PY-12: Dynamic import abuse ===
echo ""
echo "=== Checking for Dynamic Import Abuse ==="
IMPORT_HITS=$(scan_py '__import__\(' 10)
if [[ -n "$IMPORT_HITS" ]]; then
    echo "WARNING [SA-PY-12]: __import__() calls found — validate module names:"
    echo "$IMPORT_HITS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No __import__() calls detected"
fi

# === SA-PY-13: XML parsing without defusedxml ===
echo ""
echo "=== Checking for Unsafe XML Parsing ==="
XML_HITS=$(scan_py 'xml\.etree\.ElementTree' 10)
if [[ -n "$XML_HITS" ]]; then
    DEFUSED_COUNT=$(scan_py_count 'defusedxml')
    if [[ "$DEFUSED_COUNT" -eq 0 ]]; then
        echo "WARNING [SA-PY-13]: xml.etree.ElementTree used without defusedxml:"
        echo "$XML_HITS"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: defusedxml detected alongside standard XML library"
    fi
else
    echo "OK: No standard library XML parsing detected"
fi

# === SA-PY-14: SSTI via Jinja2/Mako Template ===
echo ""
echo "=== Checking for Template Injection (SSTI) ==="
TEMPLATE_HITS=$(scan_py 'Template\s*\(.*\w+.*\)' 10)
if [[ -n "$TEMPLATE_HITS" ]]; then
    echo "WARNING [SA-PY-14]: Template() with variable input found — risk of SSTI:"
    echo "$TEMPLATE_HITS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No Template() with variable input detected"
fi

# === SA-PY-16: compile() with dynamic input ===
echo ""
echo "=== Checking for compile() Code Injection ==="
COMPILE_HITS=$(scan_py 'compile\(.*,.*,' 10)
if [[ -n "$COMPILE_HITS" ]]; then
    echo "WARNING [SA-PY-16]: compile() with dynamic input found:"
    echo "$COMPILE_HITS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No suspicious compile() calls detected"
fi

# === Summary ===
echo ""
echo "=========================================="
echo "Python Security Scan Summary"
echo "=========================================="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [[ $ERRORS -gt 0 ]]; then
    echo "FAIL: $ERRORS error(s) found — review and fix before deployment"
else
    echo "PASS: No critical security errors detected"
fi

exit "$ERRORS"
