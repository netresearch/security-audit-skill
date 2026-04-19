#!/bin/bash
# AWS Security Scanner Module
# Scans AWS infrastructure files for common vulnerability patterns
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

echo "=== AWS Security Scan ==="
echo "Scanning: $PROJECT_DIR"
echo ""

# SA-AWS-01: IAM wildcard actions
count=$(scan_iac_count '"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"\s*\]')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-01: Found $count IAM policy(ies) with wildcard Action (*)"
    scan_iac '"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"\s*\]'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-03: Overly permissive trust policies
count=$(scan_iac_count '"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}|"Principal"\s*:\s*"\*"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-03: Found $count overly permissive trust policy(ies) (Principal: *)"
    scan_iac '"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}|"Principal"\s*:\s*"\*"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-05: Public S3 buckets
count=$(scan_iac_count 'acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-05: Found $count S3 bucket(s) with public ACL"
    scan_iac 'acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-06: S3 public access block disabled
count=$(scan_iac_count 'block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|restrict_public_buckets\s*=\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-06: Found $count S3 public access block(s) disabled"
    scan_iac 'block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|restrict_public_buckets\s*=\s*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-08: AdministratorAccess on roles
count=$(scan_iac_count 'policy_arn\s*=\s*"arn:aws:iam::aws:policy/AdministratorAccess"|policy_arn\s*=\s*"arn:aws:iam::aws:policy/PowerUserAccess"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-08: Found $count role(s) with AdministratorAccess/PowerUserAccess"
    scan_iac 'policy_arn\s*=\s*"arn:aws:iam::aws:policy/AdministratorAccess"|policy_arn\s*=\s*"arn:aws:iam::aws:policy/PowerUserAccess"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-09: Open security groups (0.0.0.0/0)
count=$(scan_iac_count 'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|CidrIp:\s*["\x27]?0\.0\.0\.0/0')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-09: Found $count security group rule(s) open to 0.0.0.0/0"
    scan_iac 'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|CidrIp:\s*["\x27]?0\.0\.0\.0/0'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-10: KMS key rotation disabled
count=$(scan_iac_count 'enable_key_rotation\s*=\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[WARNING] SA-AWS-10: Found $count KMS key(s) with rotation disabled"
    scan_iac 'enable_key_rotation\s*=\s*false'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-AWS-11: CloudTrail misconfiguration
count=$(scan_iac_count 'is_multi_region_trail\s*=\s*false|enable_log_file_validation\s*=\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-11: Found $count CloudTrail misconfiguration(s)"
    scan_iac 'is_multi_region_trail\s*=\s*false|enable_log_file_validation\s*=\s*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-12: Hardcoded passwords
count=$(scan_iac_count 'password\s*=\s*"[^"]+"|master_password\s*=\s*"[^"]+"')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-12: Found $count hardcoded password(s) in IaC files"
    scan_iac 'password\s*=\s*"[^"]+"|master_password\s*=\s*"[^"]+"'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-13: RDS publicly accessible
count=$(scan_iac_count 'publicly_accessible\s*=\s*true')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-13: Found $count RDS instance(s) publicly accessible"
    scan_iac 'publicly_accessible\s*=\s*true'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-AWS-14: RDS unencrypted storage
count=$(scan_iac_count 'storage_encrypted\s*=\s*false')
if [[ "$count" -gt 0 ]]; then
    echo "[ERROR] SA-AWS-14: Found $count RDS instance(s) with unencrypted storage"
    scan_iac 'storage_encrypted\s*=\s*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

echo "=== AWS Scan Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
