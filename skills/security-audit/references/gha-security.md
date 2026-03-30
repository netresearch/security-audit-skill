# GitHub Actions Security

## Code Injection Prevention

**NEVER** interpolate untrusted data directly in `run:` blocks — it allows shell injection via crafted PR titles, branch names, or inputs.

```yaml
# VULNERABLE — direct interpolation
- run: echo "${{ inputs.scripts-path }}"
- run: echo "${{ github.event.pull_request.title }}"

# SAFE — use env: block
- env:
    SCRIPTS_PATH: ${{ inputs.scripts-path }}
  run: echo "$SCRIPTS_PATH"
```

### Untrusted Data Sources

Always treat these as untrusted and route through `env:`:

- `github.event.*` — PR titles, branch names, commit messages, issue bodies
- `inputs.*` — reusable workflow inputs from callers (external repos can inject)
- `github.head_ref` — branch name from fork PRs (attacker-controlled)
- `github.event.pull_request.head.ref` — same as above
- `github.event.comment.body` — issue/PR comment content

### Safe Patterns

```yaml
# Pattern 1: env: block (preferred)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Title: $PR_TITLE"

# Pattern 2: fromJSON for structured data
- run: |
    title=$(echo '${{ toJSON(github.event.pull_request.title) }}' | jq -r '.')

# Pattern 3: Avoid entirely — use github.event in conditions, not run:
- if: github.event.pull_request.draft == false
  run: ./scripts/build.sh
```

## Dependency Vulnerability Triage

When Dependabot/Renovate flags vulnerabilities, follow this 4-step process:

### Step 1: Try Upgrade First

Direct upgrades resolve most transitive dependency vulnerabilities naturally:

```bash
# npm/pnpm
pnpm update --latest <package>
npm update <package>

# Go
go get package@latest
go mod tidy

# PHP/Composer
composer update vendor/package
```

Check if the vulnerability is in a transitive (indirect) dependency — often upgrading the direct parent resolves it.

### Step 2: Override as Last Resort

When upstream hasn't patched, use package manager overrides:

```json
// package.json — npm/pnpm
{
  "pnpm": {
    "overrides": {
      "vulnerable-pkg": ">=2.1.0"
    }
  },
  "overrides": {
    "vulnerable-pkg": ">=2.1.0"
  }
}
```

```yaml
# Go — replace directive in go.mod
replace (
  github.com/vulnerable/pkg v1.0.0 => github.com/vulnerable/pkg v1.0.1
)
```

### Step 3: Dismiss with Rationale

When no fix exists (e.g., Go module path issues like `docker/docker` v29.x naming), dismiss with a documented rationale:

- Link to the upstream issue/PR tracking the fix
- Explain why the vulnerability does not apply (e.g., code path not reachable)
- Set a review date for re-evaluation

### Step 4: Track for Upstream

Create an issue in your repo linking to the upstream fix timeline. Include:

- CVE identifier
- Affected package and version range
- Upstream issue/PR URL
- Expected fix timeline (if known)

**Never leave alerts unaddressed** — each must have a documented resolution strategy (upgrade, override, or dismiss with rationale).
