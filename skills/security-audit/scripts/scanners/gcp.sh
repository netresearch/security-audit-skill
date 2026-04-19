#!/bin/bash
# GCP Security Scanner Module
# Scans GCP infrastructure files for common vulnerability patterns
# Part of security-audit-skill cloud security references

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Helper: grep across IaC files (*.tf, *.json, *.yaml, *.yml)
scan_iac() {
    local pattern="$1"
    local limit="${2:-5}"
    grep -rn -P "$pattern" "$PROJECT_DIR" \
        --include="*.tf" --include="*.json" --include="*.yaml" --include="*.yml" \
        2>/dev/null | head -"$limit" || true
}

# Helper: count matches
scan_iac_count() {
    local pattern="$1"
    grep -rc -E "$pattern" "$PROJECT_DIR" \
        --include="*.tf" --include="*.json" --include="*.yaml" --include="*.yml" \
        2>/dev/null | awk -F: '{s+=$2} END {print s+0}' || echo "0"
}

echo "=== GCP Security Scan ==="
echo "Scanning: $PROJECT_DIR"
echo ""

# SA-GCP-01: Primitive roles (Owner/Editor)
count=$(scan_iac_count 'role\s*=\s*"roles/(owner|editor)"|"roles/(owner|editor)"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-01: Found $count primitive role assignment(s) (Owner/Editor)"
    scan_iac 'role\s*=\s*"roles/(owner|editor)"|"roles/(owner|editor)"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-02: Service account key files
count=$(scan_iac_count 'resource\s+"google_service_account_key"|google_service_account_key\s*\{')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-02: Found $count service account key resource(s)"
    scan_iac 'resource\s+"google_service_account_key"|google_service_account_key\s*\{'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-03: allUsers / allAuthenticatedUsers
count=$(scan_iac_count '"allUsers"|"allAuthenticatedUsers"|member\s*=\s*"allUsers"|member\s*=\s*"allAuthenticatedUsers"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-03: Found $count allUsers/allAuthenticatedUsers binding(s)"
    scan_iac '"allUsers"|"allAuthenticatedUsers"|member\s*=\s*"allUsers"|member\s*=\s*"allAuthenticatedUsers"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-04: Public storage buckets
count=$(scan_iac_count 'google_storage_bucket_iam.*(allUsers|allAuthenticatedUsers)|predefinedAcl:\s*public')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-04: Found $count public Cloud Storage bucket(s)"
    scan_iac 'google_storage_bucket_iam.*(allUsers|allAuthenticatedUsers)|predefinedAcl:\s*public'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-05: Uniform bucket-level access disabled
count=$(scan_iac_count 'uniform_bucket_level_access\s*=\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[WARNING] SA-GCP-05: Found $count bucket(s) without uniform bucket-level access"
    scan_iac 'uniform_bucket_level_access\s*=\s*false'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-GCP-06: Secrets in Cloud Functions env vars
count=$(scan_iac_count 'environment_variables\s*=\s*\{[^}]*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*"[^"]+"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-06: Found $count Cloud Function(s) with hardcoded secrets in env vars"
    scan_iac 'environment_variables\s*=\s*\{[^}]*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*"[^"]+"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-07: allUsers Cloud Functions invoker
count=$(scan_iac_count 'cloudfunctions\.invoker.*allUsers|allUsers.*cloudfunctions\.invoker')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-07: Found $count Cloud Function(s) invocable by allUsers"
    scan_iac 'cloudfunctions\.invoker.*allUsers|allUsers.*cloudfunctions\.invoker'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-08: Open VPC firewall (0.0.0.0/0)
count=$(scan_iac_count 'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|sourceRanges:.*0\.0\.0\.0/0')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-08: Found $count VPC firewall rule(s) open to 0.0.0.0/0"
    scan_iac 'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|sourceRanges:.*0\.0\.0\.0/0'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-09: KMS key accessible by allUsers
count=$(scan_iac_count 'google_kms_crypto_key_iam.*(allUsers|allAuthenticatedUsers)')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-GCP-09: Found $count KMS key(s) accessible by allUsers"
    scan_iac 'google_kms_crypto_key_iam.*(allUsers|allAuthenticatedUsers)'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GCP-10: Audit log exemptions
count=$(scan_iac_count 'exempted_members\s*=\s*\[')
if [[ "$count" -gt 0 ]]; then
    echo "[WARNING] SA-GCP-10: Found $count audit log exemption(s)"
    scan_iac 'exempted_members\s*=\s*\['
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

echo "=== GCP Scan Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
