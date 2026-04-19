#!/bin/bash
# Java Security Scanner Module
# Scans Java projects for common vulnerability patterns
# Part of security-audit-skill multi-language scanning

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Java source directories
SCAN_DIRS=()
for dir in src app; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all Java source directories
scan_java() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="*.java" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Java source directories
scan_java_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="*.java" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Java Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Java source directories found (looked for src/ and app/)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-JAVA-01: ObjectInputStream deserialization ===
echo "=== Checking for Insecure Deserialization ==="
OIS=$(scan_java 'new\s+ObjectInputStream\s*\(' 10)
if [[ -n "$OIS" ]]; then
    echo "ERROR: ObjectInputStream usage found (SA-JAVA-01):"
    echo "$OIS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No ObjectInputStream usage detected"
fi

# === SA-JAVA-02: XMLDecoder deserialization ===
XMLDEC=$(scan_java 'new\s+XMLDecoder\s*\(' 10)
if [[ -n "$XMLDEC" ]]; then
    echo "ERROR: XMLDecoder usage found (SA-JAVA-02):"
    echo "$XMLDEC" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No XMLDecoder usage detected"
fi

# === SA-JAVA-03: JNDI injection ===
echo ""
echo "=== Checking for JNDI Injection ==="
JNDI=$(scan_java 'InitialContext\s*\(\s*\)' 10)
if [[ -n "$JNDI" ]]; then
    JNDI_LOOKUP=$(scan_java '\.lookup\s*\(' 10)
    if [[ -n "$JNDI_LOOKUP" ]]; then
        echo "ERROR: JNDI lookup with InitialContext found (SA-JAVA-03):"
        echo "$JNDI_LOOKUP" | head -5
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: InitialContext found but no dynamic lookup detected"
    fi
else
    echo "OK: No JNDI InitialContext usage detected"
fi

# === SA-JAVA-04: Reflection abuse ===
echo ""
echo "=== Checking for Reflection Abuse ==="
REFLECT=$(scan_java 'Class\.forName\s*\(' 10)
if [[ -n "$REFLECT" ]]; then
    echo "WARNING: Class.forName usage found (SA-JAVA-04):"
    echo "$REFLECT" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No Class.forName usage detected"
fi

# === SA-JAVA-05: SQL injection in JDBC ===
echo ""
echo "=== Checking for SQL Injection ==="
SQL_CONCAT=$(scan_java '(createStatement|executeQuery|executeUpdate)\s*\([^)]*\+' 10)
if [[ -n "$SQL_CONCAT" ]]; then
    echo "ERROR: JDBC string concatenation found (SA-JAVA-05):"
    echo "$SQL_CONCAT" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No JDBC string concatenation detected"
fi

# === SA-JAVA-06: XXE via DocumentBuilderFactory ===
echo ""
echo "=== Checking for XXE Vulnerabilities ==="
XXE=$(scan_java 'DocumentBuilderFactory\.newInstance\s*\(' 10)
if [[ -n "$XXE" ]]; then
    SECURED=$(scan_java_count 'disallow-doctype-decl|external-general-entities')
    if [[ "$SECURED" -eq 0 ]]; then
        echo "WARNING: XML parsing without XXE protection (SA-JAVA-06):"
        echo "$XXE" | head -5
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: XML parsing with security features detected"
    fi
else
    echo "OK: No DocumentBuilderFactory usage detected"
fi

# === SA-JAVA-07: Command injection via Runtime.exec ===
echo ""
echo "=== Checking for Command Injection ==="
CMD=$(scan_java 'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(' 10)
if [[ -n "$CMD" ]]; then
    echo "ERROR: Runtime.exec usage found (SA-JAVA-07):"
    echo "$CMD" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No Runtime.exec usage detected"
fi

# === SA-JAVA-08: Weak hash algorithms ===
echo ""
echo "=== Checking for Weak Cryptography ==="
WEAK_HASH=$(scan_java 'getInstance\s*\(\s*"(MD5|SHA-1)"\s*\)' 10)
if [[ -n "$WEAK_HASH" ]]; then
    echo "WARNING: Weak hash algorithm usage found (SA-JAVA-08):"
    echo "$WEAK_HASH" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash algorithm usage detected"
fi

# === SA-JAVA-09: Insecure random ===
INSECURE_RAND=$(scan_java 'new\s+Random\s*\(' 10)
if [[ -n "$INSECURE_RAND" ]]; then
    echo "WARNING: java.util.Random usage found (SA-JAVA-09):"
    echo "$INSECURE_RAND" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure Random usage detected"
fi

# === SA-JAVA-10: Weak cipher ===
WEAK_CIPHER=$(scan_java 'Cipher\.getInstance\s*\(\s*"(DES|.*ECB)' 10)
if [[ -n "$WEAK_CIPHER" ]]; then
    echo "ERROR: Weak cipher usage found (SA-JAVA-10):"
    echo "$WEAK_CIPHER" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No weak cipher usage detected"
fi

# === SA-JAVA-11: SSRF via openConnection ===
echo ""
echo "=== Checking for SSRF Patterns ==="
SSRF=$(scan_java '(openConnection|openStream)\s*\(\s*\)' 10)
if [[ -n "$SSRF" ]]; then
    echo "WARNING: URL.openConnection/openStream found (SA-JAVA-11):"
    echo "$SSRF" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No SSRF-prone URL patterns detected"
fi

# === SA-JAVA-12: Path traversal ===
echo ""
echo "=== Checking for Path Traversal ==="
PATH_TRAV=$(scan_java 'new\s+File\s*\(\s*[^)]*\+\s*(request|req|param|input|args)' 10)
if [[ -n "$PATH_TRAV" ]]; then
    echo "WARNING: File path from user input found (SA-JAVA-12):"
    echo "$PATH_TRAV" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No path traversal patterns detected"
fi

# === Summary ===
echo ""
echo "--- Java Security Scan Summary ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
exit 0
