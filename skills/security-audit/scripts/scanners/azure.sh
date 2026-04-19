#!/bin/bash
# Azure Security Scanner Module
# Scans Azure infrastructure files for common vulnerability patterns
# Part of security-audit-skill cloud security references

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Helper: grep across IaC files (*.tf, *.json, *.yaml, *.yml, *.bicep)
scan_iac() {
    local pattern="$1"
    local limit="${2:-5}"
    grep -rn -P "$pattern" "$PROJECT_DIR" \
        --include="*.tf" --include="*.json" --include="*.yaml" --include="*.yml" --include="*.bicep" \
        2>/dev/null | head -"$limit" || true
}

# Helper: count matches
scan_iac_count() {
    local pattern="$1"
    grep -rc -E "$pattern" "$PROJECT_DIR" \
        --include="*.tf" --include="*.json" --include="*.yaml" --include="*.yml" --include="*.bicep" \
        2>/dev/null | awk -F: '{s+=$2} END {print s+0}' || echo "0"
}

echo "=== Azure Security Scan ==="
echo "Scanning: $PROJECT_DIR"
echo ""

# SA-AZURE-01: Owner/Contributor role assignments
count=$(scan_iac_count 'role_definition_name\s*=\s*"(Owner|Contributor)"|8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-01: Found $count Owner/Contributor role assignment(s)"
    scan_iac 'role_definition_name\s*=\s*"(Owner|Contributor)"|8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AZURE-03: Public blob access
count=$(scan_iac_count 'allow_nested_items_to_be_public\s*=\s*true|allow_blob_public_access\s*=\s*true|allowBlobPublicAccess.*true|container_access_type\s*=\s*"(blob|container)"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-03: Found $count storage resource(s) with public blob access"
    scan_iac 'allow_nested_items_to_be_public\s*=\s*true|allow_blob_public_access\s*=\s*true|allowBlobPublicAccess.*true|container_access_type\s*=\s*"(blob|container)"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AZURE-04: Anonymous function auth
count=$(scan_iac_count 'authLevel.*anonymous|"authLevel"\s*:\s*"anonymous"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-04: Found $count Azure Function(s) with anonymous auth level"
    scan_iac 'authLevel.*anonymous|"authLevel"\s*:\s*"anonymous"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AZURE-06: Open NSG inbound rules
count=$(scan_iac_count 'source_address_prefix\s*=\s*"\*"|sourceAddressPrefix.*"\*"|"sourceAddressPrefix"\s*:\s*"\*"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-06: Found $count NSG rule(s) open to * (all sources)"
    scan_iac 'source_address_prefix\s*=\s*"\*"|sourceAddressPrefix.*"\*"|"sourceAddressPrefix"\s*:\s*"\*"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AZURE-07: Missing purge protection
count=$(scan_iac_count 'purge_protection_enabled\s*=\s*false|enablePurgeProtection:\s*false|"enablePurgeProtection"\s*:\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-07: Found $count Key Vault(s) without purge protection"
    scan_iac 'purge_protection_enabled\s*=\s*false|enablePurgeProtection:\s*false|"enablePurgeProtection"\s*:\s*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AZURE-08: Access policies instead of RBAC
count=$(scan_iac_count 'enable_rbac_authorization\s*=\s*false|access_policy\s*\{')
if [[ "$count" -gt 0 ]]; then
    echo "[WARNING] SA-AZURE-08: Found $count Key Vault(s) using access policies instead of RBAC"
    scan_iac 'enable_rbac_authorization\s*=\s*false|access_policy\s*\{'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-AZURE-10: SQL public network access
count=$(scan_iac_count 'public_network_access_enabled\s*=\s*true|start_ip_address\s*=\s*"0\.0\.0\.0"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AZURE-10: Found $count Azure SQL resource(s) with public network access"
    scan_iac 'public_network_access_enabled\s*=\s*true|start_ip_address\s*=\s*"0\.0\.0\.0"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

echo "=== Azure Scan Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
