#!/bin/bash
# Common utilities for scanner modules
# Sourced by individual scanner scripts
#
# Requires Bash 4+ (uses the `local -n` nameref below). On macOS /bin/bash
# is typically 3.2 — install GNU bash via Homebrew and invoke scanners with
# `/opt/homebrew/bin/bash` (or symlink into PATH).

# Fail fast with a clear message if sourced under Bash 3.x.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: scripts/scanners/common.sh requires Bash 4+ (current: $BASH_VERSION)" >&2
    echo "  macOS ships Bash 3.2 as /bin/bash; install GNU bash via Homebrew" >&2
    echo "  and run the dispatcher with 'bash scripts/security-audit-dispatcher.sh …'" >&2
    echo "  using that newer binary." >&2
    return 1 2>/dev/null || exit 1
fi

# scan_files: grep across directories for a pattern in files matching a glob
# Usage: scan_files DIRS_ARRAY PATTERN INCLUDE_GLOB [LIMIT]
scan_files() {
    local -n dirs=$1
    local pattern="$2"
    local include="$3"
    local limit="${4:-5}"
    local results=""
    for dir in "${dirs[@]}"; do
        local matches
        matches=$(grep -rn -P "$pattern" "$dir" --include="$include" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# scan_files_count: count matches across directories
# Usage: scan_files_count DIRS_ARRAY PATTERN INCLUDE_GLOB
scan_files_count() {
    local -n dirs=$1
    local pattern="$2"
    local include="$3"
    local total=0
    for dir in "${dirs[@]}"; do
        local count
        count=$(grep -rn -P "$pattern" "$dir" --include="$include" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}
