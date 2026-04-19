#!/bin/bash
# C# Security Scanner Module
# Scans C# / .NET projects for common vulnerability patterns
# Part of security-audit-skill multi-language scanning

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect C# source directories
SCAN_DIRS=()
for dir in src app Controllers Services; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all C# source directories
scan_csharp() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.cs" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all C# source directories
scan_csharp_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.cs" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- C# Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No C# source directories found (looked for src/, app/, Controllers/, Services/)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-CS-01: BinaryFormatter deserialization ===
echo "=== Checking for Insecure Deserialization ==="
BF=$(scan_csharp 'new\s+BinaryFormatter\s*\(' 10)
if [[ -n "$BF" ]]; then
    echo "ERROR: BinaryFormatter usage found (SA-CS-01):"
    echo "$BF" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No BinaryFormatter usage detected"
fi

# === SA-CS-02: NetDataContractSerializer ===
NDCS=$(scan_csharp 'new\s+NetDataContractSerializer\s*\(' 10)
if [[ -n "$NDCS" ]]; then
    echo "ERROR: NetDataContractSerializer usage found (SA-CS-02):"
    echo "$NDCS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No NetDataContractSerializer usage detected"
fi

# === SA-CS-03: SQL injection via FromSqlRaw ===
echo ""
echo "=== Checking for SQL Injection ==="
SQL=$(scan_csharp 'FromSqlRaw\s*\(\s*\$' 10)
if [[ -n "$SQL" ]]; then
    echo "ERROR: FromSqlRaw with interpolation found (SA-CS-03):"
    echo "$SQL" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No FromSqlRaw interpolation detected"
fi

# === SA-CS-04: XXE via XmlDocument ===
echo ""
echo "=== Checking for XXE Vulnerabilities ==="
XXE=$(scan_csharp 'new\s+XmlDocument\s*\(' 10)
if [[ -n "$XXE" ]]; then
    SECURED=$(scan_csharp_count 'XmlResolver\s*=\s*null')
    if [[ "$SECURED" -eq 0 ]]; then
        echo "WARNING: XmlDocument without XmlResolver=null (SA-CS-04):"
        echo "$XXE" | head -5
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: XmlDocument with XmlResolver=null detected"
    fi
else
    echo "OK: No XmlDocument usage detected"
fi

# === SA-CS-05: Command injection via Process.Start ===
echo ""
echo "=== Checking for Command Injection ==="
CMD=$(scan_csharp 'Process\.Start\s*\(' 10)
if [[ -n "$CMD" ]]; then
    SHELL_EXEC=$(scan_csharp_count 'UseShellExecute\s*=\s*true')
    if [[ "$SHELL_EXEC" -gt 0 ]]; then
        echo "ERROR: Process.Start with UseShellExecute=true (SA-CS-05):"
        echo "$CMD" | head -5
        ERRORS=$((ERRORS + 1))
    else
        echo "WARNING: Process.Start found — verify UseShellExecute=false (SA-CS-05):"
        echo "$CMD" | head -5
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "OK: No Process.Start usage detected"
fi

# === SA-CS-06: Weak hash MD5 ===
echo ""
echo "=== Checking for Weak Cryptography ==="
MD5=$(scan_csharp 'MD5\.Create\s*\(' 10)
if [[ -n "$MD5" ]]; then
    echo "WARNING: MD5 usage found (SA-CS-06):"
    echo "$MD5" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No MD5 usage detected"
fi

# === SA-CS-07: Weak hash SHA-1 ===
SHA1=$(scan_csharp 'SHA1\.Create\s*\(' 10)
if [[ -n "$SHA1" ]]; then
    echo "WARNING: SHA-1 usage found (SA-CS-07):"
    echo "$SHA1" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No SHA-1 usage detected"
fi

# === SA-CS-08: Insecure random ===
RAND=$(scan_csharp 'new\s+Random\s*\(' 10)
if [[ -n "$RAND" ]]; then
    echo "WARNING: System.Random usage found (SA-CS-08):"
    echo "$RAND" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure Random usage detected"
fi

# === SA-CS-09: DES cryptography ===
DES=$(scan_csharp 'DESCryptoServiceProvider' 10)
if [[ -n "$DES" ]]; then
    echo "ERROR: DES usage found (SA-CS-09):"
    echo "$DES" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No DES usage detected"
fi

# === SA-CS-10: CORS AllowAnyOrigin ===
echo ""
echo "=== Checking for CORS Misconfiguration ==="
CORS=$(scan_csharp 'AllowAnyOrigin\s*\(' 10)
if [[ -n "$CORS" ]]; then
    echo "ERROR: AllowAnyOrigin found (SA-CS-10):"
    echo "$CORS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No AllowAnyOrigin detected"
fi

# === SA-CS-11: LDAP injection ===
echo ""
echo "=== Checking for LDAP Injection ==="
LDAP=$(scan_csharp 'DirectorySearcher\s*\(\s*\$' 10)
if [[ -n "$LDAP" ]]; then
    echo "ERROR: LDAP injection pattern found (SA-CS-11):"
    echo "$LDAP" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No LDAP injection patterns detected"
fi

# === SA-CS-12: UseShellExecute=true ===
SHELL=$(scan_csharp 'UseShellExecute\s*=\s*true' 10)
if [[ -n "$SHELL" ]]; then
    echo "WARNING: UseShellExecute=true found (SA-CS-12):"
    echo "$SHELL" | head -5
    WARNINGS=$((WARNINGS + 1))
fi

# === Summary ===
echo ""
echo "--- C# Security Scan Summary ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
