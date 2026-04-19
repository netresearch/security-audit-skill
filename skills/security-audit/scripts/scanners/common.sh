#!/bin/bash
# Common utilities for scanner modules
# Sourced by individual scanner scripts

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
        matches=$(grep -rn -E "$pattern" "$dir" --include="$include" 2>/dev/null || true)
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
        count=$(grep -rn -E "$pattern" "$dir" --include="$include" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}
