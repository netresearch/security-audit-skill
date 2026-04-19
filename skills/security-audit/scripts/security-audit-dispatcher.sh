#!/bin/bash
# Security Audit Dispatcher
# Auto-detects languages/frameworks in a project and invokes relevant scanner modules.
#
# Usage: ./scripts/security-audit-dispatcher.sh /path/to/project
#
# The dispatcher checks for indicator files (package.json, requirements.txt, go.mod, etc.)
# and runs only the scanner modules relevant to the detected stack.

set -e

PROJECT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNERS_DIR="$SCRIPT_DIR/scanners"

TOTAL_ERRORS=0
TOTAL_WARNINGS=0
SCANNERS_RUN=0

echo "=== Security Audit Dispatcher ==="
echo "Project: $PROJECT_DIR"
echo ""

# Detect languages/frameworks and collect scanner list
DETECTED_SCANNERS=()

# PHP: composer.json or *.php files
if [[ -f "$PROJECT_DIR/composer.json" ]] || find "$PROJECT_DIR" -maxdepth 3 -name "*.php" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("php")
fi

# Python: requirements.txt, pyproject.toml, setup.py, Pipfile
if [[ -f "$PROJECT_DIR/requirements.txt" ]] || [[ -f "$PROJECT_DIR/pyproject.toml" ]] || [[ -f "$PROJECT_DIR/setup.py" ]] || [[ -f "$PROJECT_DIR/Pipfile" ]]; then
    DETECTED_SCANNERS+=("python")
fi

# JavaScript/TypeScript: package.json
if [[ -f "$PROJECT_DIR/package.json" ]]; then
    DETECTED_SCANNERS+=("javascript")
fi

# Node.js: package.json with server-side indicators
if [[ -f "$PROJECT_DIR/package.json" ]]; then
    if grep -q '"express"\|"fastify"\|"koa"\|"hapi"\|"nestjs"\|"node"\|"server"' "$PROJECT_DIR/package.json" 2>/dev/null; then
        DETECTED_SCANNERS+=("nodejs")
    fi
fi

# Java: pom.xml, build.gradle, *.java files
if [[ -f "$PROJECT_DIR/pom.xml" ]] || [[ -f "$PROJECT_DIR/build.gradle" ]] || [[ -f "$PROJECT_DIR/build.gradle.kts" ]]; then
    DETECTED_SCANNERS+=("java")
fi

# C#/.NET: *.csproj, *.sln
if find "$PROJECT_DIR" -maxdepth 2 -name "*.csproj" -print -quit 2>/dev/null | grep -q . || [[ -f "$PROJECT_DIR/*.sln" ]]; then
    DETECTED_SCANNERS+=("csharp")
fi

# Go: go.mod
if [[ -f "$PROJECT_DIR/go.mod" ]]; then
    DETECTED_SCANNERS+=("go")
fi

# Rust: Cargo.toml
if [[ -f "$PROJECT_DIR/Cargo.toml" ]]; then
    DETECTED_SCANNERS+=("rust")
fi

# Ruby: Gemfile
if [[ -f "$PROJECT_DIR/Gemfile" ]]; then
    DETECTED_SCANNERS+=("ruby")
fi

if [[ ${#DETECTED_SCANNERS[@]} -eq 0 ]]; then
    echo "No supported languages/frameworks detected."
    echo "Looked for: composer.json, package.json, requirements.txt, pyproject.toml,"
    echo "  go.mod, Cargo.toml, Gemfile, pom.xml, build.gradle, *.csproj"
    exit 0
fi

echo "Detected languages/frameworks: ${DETECTED_SCANNERS[*]}"
echo ""

# Run each detected scanner
for scanner in "${DETECTED_SCANNERS[@]}"; do
    SCANNER_SCRIPT="$SCANNERS_DIR/${scanner}.sh"
    if [[ -f "$SCANNER_SCRIPT" ]]; then
        echo "========================================"
        echo "Running $scanner scanner..."
        echo "========================================"
        set +e
        bash "$SCANNER_SCRIPT" "$PROJECT_DIR"
        SCANNER_EXIT=$?
        set -e
        TOTAL_ERRORS=$((TOTAL_ERRORS + SCANNER_EXIT))
        SCANNERS_RUN=$((SCANNERS_RUN + 1))
        echo ""
    else
        echo "Scanner module not yet available: $scanner (skipping)"
        echo "  To add: create $SCANNERS_DIR/${scanner}.sh"
        echo ""
    fi
done

# Always run secrets scanner regardless of detected languages
echo "========================================"
echo "Running secrets scanner..."
echo "========================================"
SECRETS_SCRIPT="$SCANNERS_DIR/secrets.sh"
if [[ -f "$SECRETS_SCRIPT" ]]; then
    set +e
    bash "$SECRETS_SCRIPT" "$PROJECT_DIR"
    SCANNER_EXIT=$?
    set -e
    TOTAL_ERRORS=$((TOTAL_ERRORS + SCANNER_EXIT))
    SCANNERS_RUN=$((SCANNERS_RUN + 1))
    echo ""
fi

# === Summary ===
echo "========================================"
echo "=== Dispatcher Summary ==="
echo "Scanners run: $SCANNERS_RUN"
echo "Total errors: $TOTAL_ERRORS"
echo "========================================"

if [[ $TOTAL_ERRORS -gt 0 ]]; then
    echo "Security audit FAILED with $TOTAL_ERRORS error(s)"
    exit 1
else
    echo "Security audit PASSED"
    exit 0
fi
