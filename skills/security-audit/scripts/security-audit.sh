#!/bin/bash
# Security Audit Script
# Performs security checks on PHP projects
# Scans both src/ and Classes/ directories (TYPO3, Symfony, custom)

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect PHP source directories
SCAN_DIRS=()
for dir in src Classes; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all PHP source directories
scan_php() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.php" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all PHP source directories
scan_php_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.php" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "=== Security Audit ==="
echo "Directory: $PROJECT_DIR"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "⚠️  No PHP source directories found (looked for src/ and Classes/)"
    WARNINGS=$((WARNINGS + 1))
else
    echo "Scanning: ${SCAN_DIRS[*]}"
fi
echo ""

# === Check for hardcoded secrets ===
echo "=== Checking for Hardcoded Secrets ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    SECRETS=$(scan_php "(password|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]" 10 | grep -v "getenv\|env(" || true)
    if [[ -n "$SECRETS" ]]; then
        echo "⚠️  Potential hardcoded secrets found:"
        echo "$SECRETS" | head -5
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No obvious hardcoded secrets detected"
    fi
fi

# === Check for SQL injection patterns ===
# NOTE: This grep-based check only catches direct superglobal-to-query flows and
# obvious string concatenation. It cannot track indirect data flows where user input
# is assigned to a variable first. For deeper taint analysis, use PHPStan (level 9+)
# with phpstan-strict-rules or Psalm with taint analysis (@psalm-taint-source).
echo ""
echo "=== Checking for SQL Injection Patterns ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # Direct superglobal to database method call (dollar signs are regex literals)
    # shellcheck disable=SC2016
    SQL_VULN=$(scan_php '\$_(GET|POST|REQUEST|COOKIE).*->(query|execute|prepare)')
    # String concatenation in SQL queries
    SQL_CONCAT=$(scan_php '"(SELECT|INSERT|UPDATE|DELETE)\s.*\.\s*\$' 5)
    if [[ -n "$SQL_VULN" || -n "$SQL_CONCAT" ]]; then
        echo "🔴 Potential SQL injection patterns found:"
        [[ -n "$SQL_VULN" ]] && echo "$SQL_VULN"
        [[ -n "$SQL_CONCAT" ]] && echo "$SQL_CONCAT"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious SQL injection patterns detected"
    fi
fi

# === Check for XXE vulnerabilities ===
echo ""
echo "=== Checking for XXE Vulnerabilities ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    XXE_PATTERNS=$(scan_php "(simplexml_load_string|DOMDocument|XMLReader)" 10)
    if [[ -n "$XXE_PATTERNS" ]]; then
        # Check for secure flags (LIBXML_NONET, libxml_disable_entity_loader)
        # WARNING: LIBXML_NOENT and LIBXML_DTDLOAD are NOT mitigations — they enable XXE
        SECURED=$(scan_php_count "LIBXML_NONET|libxml_disable_entity_loader")
        if [[ "$SECURED" -eq 0 ]]; then
            echo "⚠️  XML parsing found without obvious XXE protection:"
            echo "$XXE_PATTERNS" | head -5
            WARNINGS=$((WARNINGS + 1))
        else
            echo "✅ XML parsing with security flags detected"
        fi
        # Check for dangerous flags that ENABLE XXE
        DANGEROUS_FLAGS=$(scan_php "LIBXML_NOENT|LIBXML_DTDLOAD")
        if [[ -n "$DANGEROUS_FLAGS" ]]; then
            echo "🔴 DANGEROUS: LIBXML_NOENT/LIBXML_DTDLOAD found (these ENABLE XXE, not prevent it):"
            echo "$DANGEROUS_FLAGS"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "✅ No XML parsing detected"
    fi
fi

# === Check for command injection ===
echo ""
echo "=== Checking for Command Injection ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    CMD_INJECTION=$(scan_php "(exec|system|passthru|shell_exec|proc_open|popen)\s*\(.*\\\$")
    if [[ -n "$CMD_INJECTION" ]]; then
        echo "🔴 Potential command injection found:"
        echo "$CMD_INJECTION"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious command injection patterns detected"
    fi
fi

# === Check for dangerous functions ===
echo ""
echo "=== Checking for Dangerous Functions ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    DANGEROUS=$(scan_php "(eval|assert|create_function|preg_replace.*\/e|unserialize\s*\(\s*\\\$)")
    if [[ -n "$DANGEROUS" ]]; then
        echo "⚠️  Potentially dangerous functions found:"
        echo "$DANGEROUS"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No obviously dangerous functions detected"
    fi
fi

# === Check for file inclusion vulnerabilities ===
echo ""
echo "=== Checking for File Inclusion Vulnerabilities ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    INCLUDE_VULN=$(scan_php "(include|require|include_once|require_once)\s*\(\s*\\\$")
    if [[ -n "$INCLUDE_VULN" ]]; then
        echo "⚠️  Potential file inclusion vulnerabilities:"
        echo "$INCLUDE_VULN"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No obvious file inclusion vulnerabilities"
    fi
fi

# === Check for XSS patterns ===
echo ""
echo "=== Checking for XSS Patterns ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    XSS_PATTERNS=$(scan_php "echo\s+\\\$_(GET|POST|REQUEST)")
    if [[ -n "$XSS_PATTERNS" ]]; then
        echo "🔴 Potential XSS vulnerabilities:"
        echo "$XSS_PATTERNS"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious XSS patterns detected"
    fi
fi

# === Check for insecure password hashing ===
echo ""
echo "=== Checking for Insecure Password Hashing ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    INSECURE_HASH=$(scan_php "(md5|sha1)\s*\(.*\\\$(password|passwd|pass|pwd)")
    if [[ -n "$INSECURE_HASH" ]]; then
        echo "🔴 Insecure password hashing detected (use password_hash with PASSWORD_ARGON2ID):"
        echo "$INSECURE_HASH"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No insecure password hashing detected"
    fi
fi

# === Check for insecure randomness ===
echo ""
echo "=== Checking for Insecure Randomness ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    INSECURE_RAND=$(scan_php "\b(rand|mt_rand|srand|mt_srand)\s*\(")
    if [[ -n "$INSECURE_RAND" ]]; then
        echo "⚠️  Insecure random functions found (use random_int/random_bytes):"
        echo "$INSECURE_RAND"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No insecure random functions detected"
    fi
fi

# === Check for path traversal ===
echo ""
echo "=== Checking for Path Traversal ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    PATH_TRAV=$(scan_php "(file_get_contents|fopen|readfile|file_put_contents)\s*\(.*\\\$_(GET|POST|REQUEST)")
    if [[ -n "$PATH_TRAV" ]]; then
        echo "🔴 Potential path traversal vulnerability:"
        echo "$PATH_TRAV"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious path traversal patterns detected"
    fi
fi

# === Check for phpinfo() exposure ===
echo ""
echo "=== Checking for Information Disclosure ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    PHPINFO=$(scan_php "phpinfo\s*\(")
    if [[ -n "$PHPINFO" ]]; then
        echo "⚠️  phpinfo() calls found (remove in production):"
        echo "$PHPINFO"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No phpinfo() exposure detected"
    fi
fi

# === Check for missing strict_types ===
echo ""
echo "=== Checking for strict_types Declaration ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    TOTAL_PHP=0
    STRICT_PHP=0
    for dir in "${SCAN_DIRS[@]}"; do
        local_total=$(find "$dir" -name "*.php" 2>/dev/null | wc -l || echo "0")
        local_strict=$(grep -rl "declare(strict_types=1)" "$dir" --include="*.php" 2>/dev/null | wc -l || echo "0")
        TOTAL_PHP=$((TOTAL_PHP + local_total))
        STRICT_PHP=$((STRICT_PHP + local_strict))
    done
    if [[ "$TOTAL_PHP" -gt 0 ]]; then
        PERCENT=$((STRICT_PHP * 100 / TOTAL_PHP))
        if [[ "$PERCENT" -lt 50 ]]; then
            echo "⚠️  Only $STRICT_PHP/$TOTAL_PHP PHP files ($PERCENT%) use declare(strict_types=1)"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "✅ $STRICT_PHP/$TOTAL_PHP PHP files ($PERCENT%) use strict_types"
        fi
    fi
fi

# === Check for composer vulnerabilities ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/composer.lock" ]]; then
    if command -v composer &> /dev/null; then
        AUDIT_OUTPUT=$(cd "$PROJECT_DIR" && composer audit 2>&1 || true)
        if echo "$AUDIT_OUTPUT" | grep -q "Found"; then
            echo "⚠️  Vulnerable dependencies found:"
            echo "$AUDIT_OUTPUT" | head -20
            WARNINGS=$((WARNINGS + 1))
        else
            echo "✅ No known vulnerable dependencies"
        fi
    else
        echo "⚠️  Composer not available for dependency audit"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "⚠️  No composer.lock found"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check security headers ===
echo ""
echo "=== Checking Security Headers ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    HEADERS=$(scan_php_count "X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security")
    if [[ "$HEADERS" -gt 0 ]]; then
        echo "✅ Security headers configuration found ($HEADERS references)"
    else
        echo "⚠️  No security headers configuration detected"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

# === Check for CSRF protection ===
echo ""
echo "=== Checking CSRF Protection ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    CSRF=$(scan_php_count "(csrf|_token|CsrfToken|FormProtection)")
    if [[ "$CSRF" -gt 0 ]]; then
        echo "✅ CSRF protection references found ($CSRF occurrences)"
    else
        echo "⚠️  No CSRF protection detected"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

# === Check for SSRF patterns (CWE-918) ===
echo ""
echo "=== Checking for SSRF Patterns ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    SSRF_PATTERNS=$(scan_php '(file_get_contents|curl_init|curl_setopt.*CURLOPT_URL)\s*\([^)]*\$_(GET|POST|REQUEST)')
    if [[ -n "$SSRF_PATTERNS" ]]; then
        echo "🔴 Potential SSRF vulnerability (user-controlled URL in HTTP request):"
        echo "$SSRF_PATTERNS"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious SSRF patterns detected"
    fi
fi

# === Check for IDOR patterns (CWE-639) ===
echo ""
echo "=== Checking for IDOR Patterns ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    IDOR_PATTERNS=$(scan_php '->find\(\s*\$_(GET|POST|REQUEST)\[')
    if [[ -n "$IDOR_PATTERNS" ]]; then
        echo "⚠️  Potential IDOR pattern (direct DB lookup with user-supplied ID without auth check):"
        echo "$IDOR_PATTERNS"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No obvious IDOR patterns detected"
    fi
fi

# === Check for type juggling (CWE-843) ===
echo ""
echo "=== Checking for Type Juggling ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    TYPE_JUGGLE=$(scan_php '==\s*\$_(GET|POST|REQUEST|COOKIE)')
    if [[ -n "$TYPE_JUGGLE" ]]; then
        echo "🔴 Loose comparison (==) with user input (type juggling risk):"
        echo "$TYPE_JUGGLE"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No obvious type juggling patterns detected"
    fi
fi

# === Check for PHAR deserialization (CWE-502) ===
echo ""
echo "=== Checking for PHAR Deserialization ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    PHAR_PATTERNS=$(scan_php 'phar://')
    if [[ -n "$PHAR_PATTERNS" ]]; then
        echo "🔴 phar:// stream wrapper found (triggers deserialization):"
        echo "$PHAR_PATTERNS"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No phar:// usage detected"
    fi
fi

# === Check for email header injection (CWE-93) ===
echo ""
echo "=== Checking for Email Header Injection ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    EMAIL_INJECT=$(scan_php '\bmail\s*\([^)]*\$_(GET|POST|REQUEST)')
    if [[ -n "$EMAIL_INJECT" ]]; then
        echo "🔴 mail() with user input (header injection risk):"
        echo "$EMAIL_INJECT"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No email header injection patterns detected"
    fi
fi

# === Check for LDAP injection (CWE-90) ===
echo ""
echo "=== Checking for LDAP Injection ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    LDAP_INJECT=$(scan_php 'ldap_(search|bind)\s*\([^)]*\$_(GET|POST|REQUEST)')
    if [[ -n "$LDAP_INJECT" ]]; then
        echo "🔴 LDAP operation with user input (injection risk):"
        echo "$LDAP_INJECT"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No LDAP injection patterns detected"
    fi
fi

# === Check for insecure token generation (CWE-330) ===
echo ""
echo "=== Checking for Insecure Token Generation ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    INSECURE_TOKEN=$(scan_php '(md5|sha1)\s*\(\s*(time|microtime|uniqid|rand|mt_rand)\s*\(')
    if [[ -n "$INSECURE_TOKEN" ]]; then
        echo "🔴 Predictable token generation (use random_bytes instead):"
        echo "$INSECURE_TOKEN"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No insecure token generation detected"
    fi
fi

# === Check for session fixation (CWE-384) ===
echo ""
echo "=== Checking for Session Fixation ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    SESSION_FIX=$(scan_php 'session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)')
    if [[ -n "$SESSION_FIX" ]]; then
        echo "🔴 Session ID set from user input (session fixation risk):"
        echo "$SESSION_FIX"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ No session fixation patterns detected"
    fi
fi

# === Check for log injection (CWE-117) ===
echo ""
echo "=== Checking for Log Injection ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    # shellcheck disable=SC2016
    LOG_INJECT=$(scan_php 'error_log\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)')
    if [[ -n "$LOG_INJECT" ]]; then
        echo "⚠️  Unsanitized user input in log calls (log injection risk):"
        echo "$LOG_INJECT"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✅ No log injection patterns detected"
    fi
fi

# === Check for insecure cookie settings ===
echo ""
echo "=== Checking Cookie Security ==="
if [[ ${#SCAN_DIRS[@]} -gt 0 ]]; then
    INSECURE_COOKIES=$(scan_php "setcookie\s*\(" 10)
    if [[ -n "$INSECURE_COOKIES" ]]; then
        SECURE_COOKIES=$(scan_php_count "setcookie.*secure.*httponly|setcookie.*httponly.*secure|SameSite")
        if [[ "$SECURE_COOKIES" -eq 0 ]]; then
            echo "⚠️  setcookie() calls without secure flags (set Secure, HttpOnly, SameSite):"
            echo "$INSECURE_COOKIES" | head -3
            WARNINGS=$((WARNINGS + 1))
        else
            echo "✅ Cookie security flags detected"
        fi
    else
        echo "✅ No direct setcookie() calls"
    fi
fi

# === Summary ===
echo ""
echo "=== Summary ==="
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ $ERRORS -gt 0 ]]; then
    echo "❌ Security audit FAILED with $ERRORS error(s)"
    exit 1
elif [[ $WARNINGS -gt 3 ]]; then
    echo "⚠️  Security audit completed with significant warnings"
    exit 0
else
    echo "✅ Security audit PASSED"
    exit 0
fi
