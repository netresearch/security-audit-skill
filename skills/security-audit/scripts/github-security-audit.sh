#!/bin/bash
# GitHub Repository Security Audit Script
# Audits GitHub repository security settings using the gh CLI
# Phase 4: GitHub and Project Settings

set -e

# Severity counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# Determine repository
if [[ -n "$1" ]]; then
    REPO="$1"
else
    REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null || true)
    if [[ -z "$REPO" ]]; then
        echo "ERROR: Could not determine repository. Pass owner/repo as argument or run from a git repo."
        exit 2
    fi
fi

echo "=== GitHub Security Audit ==="
echo "Repository: $REPO"
echo ""

# Helper: record a finding
finding() {
    local severity="$1"
    local message="$2"

    case "$severity" in
        CRITICAL)
            echo "[CRITICAL] $message"
            CRITICAL=$((CRITICAL + 1))
            ;;
        HIGH)
            echo "[HIGH] $message"
            HIGH=$((HIGH + 1))
            ;;
        MEDIUM)
            echo "[MEDIUM] $message"
            MEDIUM=$((MEDIUM + 1))
            ;;
        LOW)
            echo "[LOW] $message"
            LOW=$((LOW + 1))
            ;;
    esac
}

ok() {
    echo "[OK] $1"
}

# Helper: safely call gh api, return empty on error
gh_api() {
    gh api "$@" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# 1. Secret scanning enabled
# ---------------------------------------------------------------------------
echo "--- Secret Scanning ---"
SECRET_SCANNING=$(gh_api "repos/$REPO" --jq '.security_and_analysis.secret_scanning.status // empty')
if [[ "$SECRET_SCANNING" == "enabled" ]]; then
    ok "Secret scanning is enabled"
else
    finding CRITICAL "Secret scanning is DISABLED - enable it in Settings > Code security"
fi

# ---------------------------------------------------------------------------
# 2. Secret scanning push protection
# ---------------------------------------------------------------------------
PUSH_PROTECTION=$(gh_api "repos/$REPO" --jq '.security_and_analysis.secret_scanning_push_protection.status // empty')
if [[ "$PUSH_PROTECTION" == "enabled" ]]; then
    ok "Secret scanning push protection is enabled"
else
    finding CRITICAL "Push protection is DISABLED - secrets can be pushed without warning"
fi

# ---------------------------------------------------------------------------
# 3. Branch protection on default branch
# ---------------------------------------------------------------------------
echo ""
echo "--- Branch Protection ---"
DEFAULT_BRANCH=$(gh_api "repos/$REPO" --jq '.default_branch // "main"')
# gh api returns 404 if no branch protection; check if we got a valid response
PROTECTION_CHECK=$(gh api "repos/$REPO/branches/$DEFAULT_BRANCH/protection" 2>/dev/null && echo "exists" || echo "missing")
if [[ "$PROTECTION_CHECK" == "exists" ]]; then
    ok "Branch protection configured on $DEFAULT_BRANCH"
else
    finding CRITICAL "No branch protection on default branch ($DEFAULT_BRANCH)"
fi

# ---------------------------------------------------------------------------
# 4. Dependabot alerts enabled
# ---------------------------------------------------------------------------
echo ""
echo "--- Dependabot ---"
# Dependabot vulnerability alerts - check via the vulnerability-alerts API
VULN_ALERTS=$(gh api "repos/$REPO/vulnerability-alerts" 2>&1 || true)
if echo "$VULN_ALERTS" | grep -q "Dependabot alerts are disabled"; then
    finding HIGH "Dependabot alerts are DISABLED"
elif echo "$VULN_ALERTS" | grep -q "Not Found"; then
    finding HIGH "Dependabot alerts appear to be DISABLED (404 response)"
else
    ok "Dependabot alerts are enabled"
fi

# ---------------------------------------------------------------------------
# 5. Dependabot security updates enabled
# ---------------------------------------------------------------------------
DEPENDABOT_UPDATES=$(gh_api "repos/$REPO" --jq '.security_and_analysis.dependabot_security_updates.status // empty')
if [[ "$DEPENDABOT_UPDATES" == "enabled" ]]; then
    ok "Dependabot security updates are enabled"
else
    finding HIGH "Dependabot security updates are NOT enabled"
fi

# ---------------------------------------------------------------------------
# 6. Default workflow permissions
# ---------------------------------------------------------------------------
echo ""
echo "--- Actions & Workflows ---"
WORKFLOW_PERMS=$(gh_api "repos/$REPO/actions/permissions/workflow" --jq '.default_workflow_permissions // empty')
if [[ "$WORKFLOW_PERMS" == "read" ]]; then
    ok "Default workflow permissions are read-only"
elif [[ "$WORKFLOW_PERMS" == "write" ]]; then
    finding HIGH "Default workflow permissions are WRITE - should be read-only (least privilege)"
elif [[ -z "$WORKFLOW_PERMS" ]]; then
    # Could not determine; may be an org-level setting
    echo "[INFO] Could not determine default workflow permissions (may be set at org level)"
fi

# ---------------------------------------------------------------------------
# 7. CodeQL / code scanning configured
# ---------------------------------------------------------------------------
echo ""
echo "--- Code Scanning ---"
CODE_SCANNING=$(gh_api "repos/$REPO/code-scanning/analyses" --jq 'length // 0')
if [[ -n "$CODE_SCANNING" ]] && [[ "$CODE_SCANNING" -gt 0 ]]; then
    ok "Code scanning (CodeQL) has $CODE_SCANNING analysis results"
else
    # Check if there is a code scanning default setup
    CODE_SCANNING_SETUP=$(gh_api "repos/$REPO/code-scanning/default-setup" --jq '.state // empty')
    if [[ "$CODE_SCANNING_SETUP" == "configured" ]]; then
        ok "Code scanning default setup is configured"
    else
        finding MEDIUM "No code scanning (CodeQL) results found - consider enabling code scanning"
    fi
fi

# ---------------------------------------------------------------------------
# 8. Private vulnerability reporting enabled
# ---------------------------------------------------------------------------
echo ""
echo "--- Vulnerability Reporting ---"
# Private vulnerability reporting is a separate setting
PRIVATE_VULN_REPORTING=$(gh api "repos/$REPO/private-vulnerability-reporting" 2>&1 || true)
if echo "$PRIVATE_VULN_REPORTING" | grep -q '"enabled":true'; then
    ok "Private vulnerability reporting is enabled"
elif echo "$PRIVATE_VULN_REPORTING" | grep -q '"enabled":false'; then
    finding MEDIUM "Private vulnerability reporting is DISABLED - users cannot privately report security issues"
else
    # API may not be available for all repo types
    echo "[INFO] Could not determine private vulnerability reporting status"
fi

# ---------------------------------------------------------------------------
# 9. SECURITY.md exists
# ---------------------------------------------------------------------------
echo ""
echo "--- Security Documentation ---"
SECURITY_MD=$(gh_api "repos/$REPO/contents/SECURITY.md" --jq '.name // empty')
if [[ -n "$SECURITY_MD" ]]; then
    ok "SECURITY.md exists"
else
    # Also check .github/SECURITY.md
    SECURITY_MD_GH=$(gh_api "repos/$REPO/contents/.github/SECURITY.md" --jq '.name // empty')
    if [[ -n "$SECURITY_MD_GH" ]]; then
        ok "SECURITY.md exists (in .github/)"
    else
        finding MEDIUM "SECURITY.md is missing - add a security policy for vulnerability reporting"
    fi
fi

# ---------------------------------------------------------------------------
# 10. CODEOWNERS exists
# ---------------------------------------------------------------------------
CODEOWNERS=""
for path in CODEOWNERS .github/CODEOWNERS docs/CODEOWNERS; do
    CHECK=$(gh_api "repos/$REPO/contents/$path" --jq '.name // empty')
    if [[ -n "$CHECK" ]]; then
        CODEOWNERS="$path"
        break
    fi
done

if [[ -n "$CODEOWNERS" ]]; then
    ok "CODEOWNERS exists ($CODEOWNERS)"
else
    finding LOW "CODEOWNERS file is missing - consider adding for review assignment"
fi

# ---------------------------------------------------------------------------
# 11. Signed commits required
# ---------------------------------------------------------------------------
echo ""
echo "--- Commit Signing ---"
if [[ "$PROTECTION_CHECK" == "exists" ]]; then
    SIGNED_COMMITS=$(gh_api "repos/$REPO/branches/$DEFAULT_BRANCH/protection/required_signatures" --jq '.enabled // false')
    if [[ "$SIGNED_COMMITS" == "true" ]]; then
        ok "Signed commits are required on $DEFAULT_BRANCH"
    else
        finding LOW "Signed commits are NOT required on $DEFAULT_BRANCH"
    fi
else
    finding LOW "Cannot check signed commit requirement (no branch protection configured)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Summary ==="
echo "Critical: $CRITICAL"
echo "High:     $HIGH"
echo "Medium:   $MEDIUM"
echo "Low:      $LOW"
echo ""

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))
if [[ "$TOTAL" -eq 0 ]]; then
    echo "All checks passed - repository security settings look good."
elif [[ "$CRITICAL" -gt 0 ]]; then
    echo "CRITICAL issues found - immediate action required."
    exit 1
elif [[ "$HIGH" -gt 0 ]]; then
    echo "HIGH severity issues found - action recommended."
    exit 0
else
    echo "Only medium/low issues found - review at your convenience."
    exit 0
fi
