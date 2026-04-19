#!/bin/bash
# Secrets Scanner Module
# Scans projects for leaked secrets using TruffleHog and fallback regex patterns.
#
# Checks for: API keys, tokens, passwords, private keys, cloud credentials,
# database connection strings, and other sensitive values in source code and git history.
#
# Requires Bash 4+ (uses associative arrays via `declare -A`). macOS /bin/bash
# is 3.2 — install GNU bash via Homebrew and invoke via that newer binary.

# Fail fast with a clear message under Bash 3.x.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: scripts/scanners/secrets.sh requires Bash 4+ (current: $BASH_VERSION)" >&2
    echo "  macOS ships Bash 3.2 as /bin/bash; install GNU bash via Homebrew and" >&2
    echo "  re-run the dispatcher under that binary." >&2
    exit 1
fi

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

echo "--- Secrets Scanner ---"
echo "Scanning: $PROJECT_DIR"
echo ""

# === TruffleHog (if available) ===
if command -v trufflehog &>/dev/null; then
    echo "=== TruffleHog Filesystem Scan ==="
    TRUFFLEHOG_OUTPUT=$(trufflehog filesystem "$PROJECT_DIR" --no-update --json 2>/dev/null || true)
    TRUFFLEHOG_COUNT=$(echo "$TRUFFLEHOG_OUTPUT" | grep -c '"SourceMetadata"' 2>/dev/null || echo "0")

    if [[ "$TRUFFLEHOG_COUNT" -gt 0 ]]; then
        echo "ERROR: TruffleHog found $TRUFFLEHOG_COUNT secret(s):"
        echo "$TRUFFLEHOG_OUTPUT" | head -20
        ERRORS=$((ERRORS + TRUFFLEHOG_COUNT))
    else
        echo "OK: TruffleHog found no secrets"
    fi

    # Also scan git history if it's a git repo
    if [[ -d "$PROJECT_DIR/.git" ]]; then
        echo ""
        echo "=== TruffleHog Git History Scan ==="
        GIT_OUTPUT=$(trufflehog git "file://$PROJECT_DIR" --no-update --json 2>/dev/null || true)
        GIT_COUNT=$(echo "$GIT_OUTPUT" | grep -c '"SourceMetadata"' 2>/dev/null || echo "0")

        if [[ "$GIT_COUNT" -gt 0 ]]; then
            echo "ERROR: TruffleHog found $GIT_COUNT secret(s) in git history:"
            echo "$GIT_OUTPUT" | head -20
            ERRORS=$((ERRORS + GIT_COUNT))
        else
            echo "OK: No secrets in git history"
        fi
    fi
else
    echo "TruffleHog not installed — falling back to regex patterns"
    echo "  Install: https://github.com/trufflesecurity/trufflehog#installation"
    echo ""
fi

# === Fallback regex patterns (always run as defense-in-depth) ===
echo ""
echo "=== Regex-Based Secret Detection ==="

# Patterns to search for
declare -A SECRET_PATTERNS
SECRET_PATTERNS=(
    ["AWS Access Key"]='AKIA[0-9A-Z]{16}'
    ["AWS Secret Key"]='[0-9a-zA-Z/+=]{40}'
    ["GitHub Token"]='gh[ps]_[A-Za-z0-9_]{36,}'
    ["GitHub OAuth"]='gho_[A-Za-z0-9_]{36,}'
    ["GitLab Token"]='glpat-[A-Za-z0-9\-_]{20,}'
    ["Slack Token"]='xox[baprs]-[0-9a-zA-Z\-]{10,}'
    ["Slack Webhook"]='hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}'
    ["Private Key"]='-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    ["Generic API Key"]='[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'
    ["Generic Secret"]='[sS][eE][cC][rR][eE][tT]\s*[:=]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'
    ["Generic Password"]='[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['\''"][^'\''\"]{8,}['\''"]'
    ["JWT Token"]='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    ["Stripe Key"]='[sr]k_(live|test)_[0-9a-zA-Z]{24,}'
    ["SendGrid Key"]='SG\.[0-9a-zA-Z\-_]{22,}\.[0-9a-zA-Z\-_]{43,}'
    ["Twilio Key"]='SK[0-9a-fA-F]{32}'
    ["Database URL"]='(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+'
    ["Heroku API Key"]='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    ["Google API Key"]='AIza[0-9A-Za-z\-_]{35}'
    ["Firebase Key"]='AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
)

# Directories and files to skip
EXCLUDE_DIRS="node_modules|vendor|dist|build|\.git|target|\.next|coverage|__pycache__|\.cargo|\.nuget"
EXCLUDE_FILES="\.(lock|sum|min\.js|min\.css|map|woff|woff2|ttf|eot|png|jpg|jpeg|gif|ico|svg|pdf)$"

for name in "${!SECRET_PATTERNS[@]}"; do
    pattern="${SECRET_PATTERNS[$name]}"
    # GNU/BSD grep --include does NOT support brace expansion; pass each
    # extension as a separate --include flag.
    MATCHES=$(grep -rn -P "$pattern" "$PROJECT_DIR" \
        --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
        --include="*.py" --include="*.java" --include="*.cs" --include="*.go" \
        --include="*.rs" --include="*.rb" --include="*.php" \
        --include="*.yaml" --include="*.yml" --include="*.json" --include="*.xml" \
        --include="*.env" --include="*.cfg" --include="*.conf" --include="*.ini" \
        --include="*.toml" --include="*.properties" \
        --include="*.sh" --include="*.bash" --include="*.zsh" \
        2>/dev/null | grep -vE "$EXCLUDE_DIRS" | grep -vE "$EXCLUDE_FILES" | grep -vE "\.(example|sample|template)" | head -5 || true)

    if [[ -n "$MATCHES" ]]; then
        echo "WARNING: Potential $name found:"
        echo "$MATCHES" | head -3
        WARNINGS=$((WARNINGS + 1))
    fi
done

# === Check for .env files in repo ===
echo ""
echo "=== Environment Files ==="
# Parenthesise the -name alternations so -maxdepth 3 applies to all of them
# (without parens, -maxdepth binds only to the first -name and the others
# search the whole tree).
ENV_FILES=$(find "$PROJECT_DIR" -maxdepth 3 \( -name ".env" -o -name ".env.local" -o -name ".env.production" \) 2>/dev/null | grep -vE "$EXCLUDE_DIRS" || true)
if [[ -n "$ENV_FILES" ]]; then
    echo "WARNING: Environment files found (should not be in VCS):"
    echo "$ENV_FILES"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check .gitignore for env exclusion ===
if [[ -f "$PROJECT_DIR/.gitignore" ]]; then
    if ! grep -q "\.env" "$PROJECT_DIR/.gitignore" 2>/dev/null; then
        echo "WARNING: .gitignore does not exclude .env files"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

# === Summary ===
echo ""
echo "--- Secrets Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

exit "$ERRORS"
