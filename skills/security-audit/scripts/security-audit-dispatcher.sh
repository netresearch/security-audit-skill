#!/bin/bash
# Security Audit Dispatcher
# Auto-detects languages/frameworks in a project and invokes relevant scanner modules.
#
# Usage: ./scripts/security-audit-dispatcher.sh /path/to/project
#
# The dispatcher checks for indicator files (package.json, requirements.txt, go.mod, etc.)
# and runs only the scanner modules relevant to the detected stack.
#
# Requires Bash 4+ for associative arrays in scripts/scanners/secrets.sh
# and scripts/scanners/common.sh.

set -e

PROJECT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNERS_DIR="$SCRIPT_DIR/scanners"

FAILED_SCANNERS=0
SCANNERS_RUN=0

echo "=== Security Audit Dispatcher ==="
echo "Project: $PROJECT_DIR"
echo ""

# Detect languages/frameworks and collect scanner list
DETECTED_SCANNERS=()

# PHP: composer.json or *.php files
if [[ -f "$PROJECT_DIR/composer.json" ]] \
  || find "$PROJECT_DIR" -maxdepth 3 -name "*.php" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("php")
fi

# Python: requirements.txt, pyproject.toml, setup.py, Pipfile
if [[ -f "$PROJECT_DIR/requirements.txt" ]] || [[ -f "$PROJECT_DIR/pyproject.toml" ]] \
  || [[ -f "$PROJECT_DIR/setup.py" ]] || [[ -f "$PROJECT_DIR/Pipfile" ]]; then
    DETECTED_SCANNERS+=("python")
fi

# JavaScript/TypeScript: package.json
if [[ -f "$PROJECT_DIR/package.json" ]]; then
    DETECTED_SCANNERS+=("javascript")
fi

# Node.js: package.json with server-side indicators
if [[ -f "$PROJECT_DIR/package.json" ]] \
  && grep -q '"express"\|"fastify"\|"koa"\|"hapi"\|"nestjs"\|"node"\|"server"' \
         "$PROJECT_DIR/package.json" 2>/dev/null; then
    DETECTED_SCANNERS+=("nodejs")
fi

# Java: pom.xml, build.gradle, *.java files
if [[ -f "$PROJECT_DIR/pom.xml" ]] || [[ -f "$PROJECT_DIR/build.gradle" ]] \
  || [[ -f "$PROJECT_DIR/build.gradle.kts" ]]; then
    DETECTED_SCANNERS+=("java")
fi

# C#/.NET: *.csproj, *.sln — use find so both unquoted-glob and literal-string
# variants are covered. Previous `[[ -f "$PROJECT_DIR/*.sln" ]]` tested for a
# literal file named "*.sln".
if find "$PROJECT_DIR" -maxdepth 2 \( -name "*.csproj" -o -name "*.sln" \) \
     -print -quit 2>/dev/null | grep -q .; then
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

# Android: AndroidManifest.xml or build.gradle with android plugin
if find "$PROJECT_DIR" -maxdepth 4 -name "AndroidManifest.xml" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("android")
fi

# iOS: *.xcodeproj or *.xcworkspace or Info.plist at a typical location
if find "$PROJECT_DIR" -maxdepth 3 \( -name "*.xcodeproj" -o -name "*.xcworkspace" \) \
     -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("ios")
fi

# Terraform / IaC: *.tf anywhere
if find "$PROJECT_DIR" -maxdepth 4 -name "*.tf" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("aws")     # aws.sh also scans Terraform for AWS resources
    DETECTED_SCANNERS+=("azure")   # same for Azure
    DETECTED_SCANNERS+=("gcp")     # same for GCP
fi

# WordPress: wp-config.php or wp-content/ (themes / plugins with WordPress stack)
if [[ -f "$PROJECT_DIR/wp-config.php" ]] \
  || [[ -d "$PROJECT_DIR/wp-content" ]] \
  || find "$PROJECT_DIR" -maxdepth 4 -name "wp-config.php" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("wordpress")
fi

# Drupal: composer.json with drupal/core OR sites/default/settings.php
if { [[ -f "$PROJECT_DIR/composer.json" ]] \
     && grep -q '"drupal/core"' "$PROJECT_DIR/composer.json" 2>/dev/null; } \
  || find "$PROJECT_DIR" -maxdepth 4 -name "settings.php" -path "*/sites/default/*" \
       -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("drupal")
fi

# Joomla: configuration.php at top level + administrator/ directory
if [[ -f "$PROJECT_DIR/configuration.php" ]] && [[ -d "$PROJECT_DIR/administrator" ]]; then
    DETECTED_SCANNERS+=("joomla")
fi

if [[ ${#DETECTED_SCANNERS[@]} -eq 0 ]]; then
    echo "No supported languages/frameworks detected."
    echo "Dispatcher recognises: composer.json, package.json, requirements.txt,"
    echo "  pyproject.toml, go.mod, Cargo.toml, Gemfile, pom.xml, build.gradle,"
    echo "  *.csproj / *.sln, AndroidManifest.xml, *.xcodeproj, *.tf, wp-config.php,"
    echo "  drupal/core in composer.json, Joomla configuration.php + administrator/."
    exit 0
fi

echo "Detected languages/frameworks: ${DETECTED_SCANNERS[*]}"
echo ""

# Run each detected scanner. Scanner modules may exit with a non-zero error
# count (their `ERRORS` counter), which is not a standard 0/1 exit contract.
# We therefore count FAILED scanners (any non-zero exit), not the raw exit
# code (which can overflow the 0-255 exit-code space if summed).
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
        if [[ $SCANNER_EXIT -ne 0 ]]; then
            FAILED_SCANNERS=$((FAILED_SCANNERS + 1))
        fi
        SCANNERS_RUN=$((SCANNERS_RUN + 1))
        echo ""
    else
        echo "Scanner module not yet available: $scanner (skipping)"
        echo "  To add: create $SCANNERS_DIR/${scanner}.sh"
        echo ""
    fi
done

# Always run secrets scanner regardless of detected languages.
echo "========================================"
echo "Running secrets scanner..."
echo "========================================"
SECRETS_SCRIPT="$SCANNERS_DIR/secrets.sh"
if [[ -f "$SECRETS_SCRIPT" ]]; then
    set +e
    bash "$SECRETS_SCRIPT" "$PROJECT_DIR"
    SCANNER_EXIT=$?
    set -e
    if [[ $SCANNER_EXIT -ne 0 ]]; then
        FAILED_SCANNERS=$((FAILED_SCANNERS + 1))
    fi
    SCANNERS_RUN=$((SCANNERS_RUN + 1))
    echo ""
fi

# === Summary ===
echo "========================================"
echo "=== Dispatcher Summary ==="
echo "Scanners run:    $SCANNERS_RUN"
echo "Scanners failed: $FAILED_SCANNERS"
echo "========================================"

if [[ $FAILED_SCANNERS -gt 0 ]]; then
    echo "Security audit FAILED ($FAILED_SCANNERS scanner(s) reported findings)"
    exit 1
else
    echo "Security audit PASSED"
    exit 0
fi
