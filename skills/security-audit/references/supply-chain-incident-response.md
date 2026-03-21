# Supply Chain Incident Response

Operational playbook for responding to GitHub Actions supply chain compromises, based on the aquasecurity/trivy-action tag force-push incident (2026-03-19). Covers detection, triage, remediation, and post-incident hardening.

## Detection Patterns

Supply chain compromises in GitHub Actions typically surface through multiple signals. Monitor all of them.

### StepSecurity Harden-Runner Alerts

If `step-security/harden-runner` is deployed in audit or block mode, it will flag unexpected network activity from compromised actions:

- **Unexpected DNS lookups** to attacker-controlled domains
- **Outbound HTTPS connections** to endpoints not in the baseline
- **Process execution** anomalies (e.g., a scanning action spawning `curl` to unknown hosts)

Check the StepSecurity Insights dashboard at `https://app.stepsecurity.io` for anomalous runs.

### Failed SHA Verification

If actions are SHA-pinned, a force-pushed tag will cause the checkout to fail because the tag now points to a different commit than the pinned SHA. This is the clearest signal that a tag was compromised.

```
Error: Unable to resolve action `aquasecurity/trivy-action@0.2.1`.
The SHA for this ref changed. Expected: abc123..., Got: def456...
```

### Dependabot / Renovate Alerts

Dependency update tools may generate unexpected PRs when a tag is force-pushed. Watch for:

- PRs updating an action to the same version tag (tag was re-pointed)
- PRs with unusually large diffs for a patch version bump
- Multiple repos receiving the same suspicious update simultaneously

### Community and Advisory Channels

- GitHub Security Advisories (GHSA)
- StepSecurity blog and Twitter/X
- GitHub Actions changelog
- OSS security mailing lists (oss-security@lists.openwall.com)

## Triage Checklist

When a compromise is suspected, work through this checklist systematically.

### 1. Identify Affected Runs

```bash
# Find all workflow runs that used the compromised action in the time window
# Adjust the date range to the known compromise window
gh api "repos/OWNER/REPO/actions/runs?created=>2026-03-18&per_page=100" \
  --jq '.workflow_runs[] | {id: .id, name: .name, head_sha: .head_sha[:7], created_at: .created_at, status: .status}'
```

For org-wide assessment:

```bash
# List all repos in the org
gh repo list ORG --limit 500 --json nameWithOwner --jq '.[].nameWithOwner' | while read repo; do
  echo "=== $repo ==="
  gh api "repos/$repo/actions/runs?created=>2026-03-18&per_page=10" \
    --jq '.workflow_runs[] | select(.name | test("security|scan|trivy"; "i")) | {id, name, created_at}' 2>/dev/null
done
```

### 2. Assess Secret Exposure Scope

For each affected run, determine which secrets were accessible:

| Factor | Risk Level | Action |
|--------|-----------|--------|
| `GITHUB_TOKEN` with `contents: read` only | Low | No rotation needed; token expires after workflow |
| `GITHUB_TOKEN` with `contents: write` | Medium | Check for unauthorized commits/releases |
| Repository secrets in env | High | Rotate immediately |
| Organization secrets in env | Critical | Rotate immediately, notify all consuming repos |
| OIDC tokens (`id-token: write`) | High | Check for unauthorized artifact signatures |

**Job isolation matters:** Secrets are scoped to the job, not the workflow. If the compromised action ran in a job that did not reference any secrets beyond `GITHUB_TOKEN`, other jobs' secrets were not exposed.

```yaml
# This job's secrets are NOT exposed to the compromised action in the scan job
jobs:
  scan:  # <-- compromised action runs here
    permissions:
      contents: read  # Only GITHUB_TOKEN with read
  deploy:  # <-- secrets here are isolated
    needs: scan
    env:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

### 3. Check for Malicious Artifacts

Compromised actions may upload malicious SARIF results, tampered artifacts, or poisoned caches:

```bash
# List artifacts from suspicious runs
gh api "repos/OWNER/REPO/actions/runs/RUN_ID/artifacts" \
  --jq '.artifacts[] | {name, size_in_bytes, created_at, expires_at}'

# Check if SARIF was uploaded (could contain false negatives to hide real vulns)
gh api "repos/OWNER/REPO/code-scanning/analyses?ref=main" \
  --jq '.[] | {id, tool: .tool.name, created_at, results_count}'
```

## Secret Rotation Decision Tree

```
Was the compromised action in a job with custom secrets (not just GITHUB_TOKEN)?
├── YES → Rotate ALL secrets referenced in that job immediately
│         └── Were org-level secrets used?
│             ├── YES → Notify all repos consuming those secrets
│             └── NO  → Rotate only repo-level secrets
├── NO (only GITHUB_TOKEN) →
│   └── What permissions did GITHUB_TOKEN have?
│       ├── contents: read only → No rotation needed (token is ephemeral, read-only)
│       ├── contents: write → Check git log for unauthorized commits
│       ├── packages: write → Check package registry for unauthorized publishes
│       └── id-token: write → Audit OIDC token usage in Sigstore transparency log
└── UNKNOWN → Treat as HIGH risk, rotate all job secrets
```

**GITHUB_TOKEN lifetime:** Tokens expire when the workflow run completes. If the compromised run already finished, the token is no longer valid. However, during the run window, the token could have been exfiltrated for use before expiry.

## Org-Wide Remediation Playbook

### Step 1: Enable SHA Pinning Enforcement

```bash
# Enable org-level SHA pinning requirement
# (GitHub org settings > Actions > General > Fork pull request workflows)
# Or via API:
gh api orgs/ORG/actions/permissions -X PUT \
  -f allowed_actions=selected \
  --field sha_pinning_required=true
```

**Note:** Reusable workflows (e.g., `netresearch/.github/.github/workflows/reusable.yml@main`) are exempt from SHA pinning requirements. GitHub enforces pinning only on actions (`uses: owner/action@sha`), not on workflow calls (`uses: owner/repo/.github/workflows/file.yml@ref`).

### Step 2: Batch SHA-Pin All Actions

Use the `pin-github-action` npm tool for bulk pinning:

```bash
# Install
npm install -g pin-github-action

# Pin all actions in a repo, preserving internal workflow references
pin-github-action --allow "netresearch/*" .github/workflows/*.yml

# For org-wide pinning across all repos:
gh repo list ORG --limit 500 --json nameWithOwner --jq '.[].nameWithOwner' | while read repo; do
  echo "Processing $repo..."
  gh repo clone "$repo" "/tmp/pin-$repo" -- --depth 1
  cd "/tmp/pin-$repo"
  if ls .github/workflows/*.yml 1>/dev/null 2>&1; then
    pin-github-action --allow "ORG/*" .github/workflows/*.yml
    # Create PR with changes
    git checkout -b chore/pin-github-actions
    git add .github/workflows/
    git commit -S --signoff -m "chore: SHA-pin all GitHub Actions for supply chain security"
    git push -u origin chore/pin-github-actions
    gh pr create --title "chore: SHA-pin all GitHub Actions" \
      --body "Pins all third-party GitHub Actions to immutable commit SHAs to prevent tag hijacking attacks."
  fi
  cd -
done
```

### Step 3: Add Dependabot github-actions Ecosystem

Ensure all repos have Dependabot configured to monitor GitHub Actions versions:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "ci"
      - "dependencies"
```

This ensures that when SHA-pinned actions release new versions, Dependabot creates PRs to update both the SHA and the version comment.

### Step 4: Audit Workflow Runs in the Compromise Window

```bash
# Export all runs during compromise window for forensic review
START="2026-03-18T00:00:00Z"
END="2026-03-20T00:00:00Z"

gh repo list ORG --limit 500 --json nameWithOwner --jq '.[].nameWithOwner' | while read repo; do
  gh api "repos/$repo/actions/runs?created=$START..$END&per_page=100" \
    --jq ".workflow_runs[] | {repo: \"$repo\", id: .id, name: .name, conclusion: .conclusion, created_at: .created_at}" 2>/dev/null
done | jq -s '.' > compromise-window-runs.json

echo "Total runs in window: $(jq length compromise-window-runs.json)"
```

## Communication Template

Use this template for team notification via Matrix/Slack:

```
🚨 Supply Chain Security Incident — [ACTION_NAME]

**What happened:** The GitHub Action `[owner/action@tag]` was compromised via
tag force-push on [DATE]. The tag was re-pointed to a malicious commit that
[DESCRIBE PAYLOAD: exfiltrates secrets / injects code / uploads malicious artifacts].

**Impact to us:**
- [N] workflow runs used this action during the compromise window ([START] to [END])
- Affected repos: [LIST]
- Secret exposure: [NONE / LIST of secrets to rotate]

**Immediate actions taken:**
1. All affected workflows paused/disabled
2. [Secrets rotated / No rotation needed — only read-only GITHUB_TOKEN in scope]
3. SHA-pinning PRs created for all [N] repos

**Action required from team:**
- Review and merge SHA-pinning PRs in your repos
- Report any unexpected commits, releases, or package publishes since [DATE]

**Reference:** [LINK to GitHub Advisory / StepSecurity blog post]
```

## Post-Incident Hardening

### Migrate Harden-Runner from Audit to Block Mode

After baselining legitimate network activity in audit mode, switch to block mode with explicit domain allowlists:

```yaml
- name: Harden Runner
  uses: step-security/harden-runner@v2
  with:
    egress-policy: block
    allowed-endpoints: >
      api.github.com:443
      github.com:443
      packagist.org:443
      repo.packagist.org:443
      getcomposer.org:443
      objects.githubusercontent.com:443
      registry.npmjs.org:443
```

**Domain allowlist strategy:**
- Start with `egress-policy: audit` for 1-2 weeks to capture all legitimate endpoints
- Review the StepSecurity dashboard for each workflow
- Create per-job allowlists (different jobs need different endpoints)
- Switch to `egress-policy: block` once the allowlist is complete
- **Critical:** A blocked domain will cause the step to fail, so thorough baselining is essential

### Review and Restrict GITHUB_TOKEN Permissions

After an incident, audit all workflows for overly broad permissions:

```bash
# Find workflows with write-all or broad permissions
grep -rn 'permissions:' .github/workflows/*.yml
grep -rn 'write-all' .github/workflows/*.yml
grep -rn 'contents: write' .github/workflows/*.yml
```

Apply least-privilege at both workflow and job level. Set the org default to read-only:

```
Repository Settings > Actions > General > Workflow permissions
→ "Read repository contents and packages permissions"
```

### Implement Workflow Approval for Forks

Require approval for workflow runs from fork PRs to prevent malicious PRs from triggering compromised actions:

```
Repository Settings > Actions > General > Fork pull request workflows
→ "Require approval for all outside collaborators"
```

## Tools Reference

| Tool | Purpose | Install |
|------|---------|---------|
| `pin-github-action` | Batch SHA-pin actions in workflow files | `npm install -g pin-github-action` |
| `gh` CLI | Audit runs, manage repos, create PRs | `brew install gh` / `apt install gh` |
| `step-security/harden-runner` | Runtime network monitoring for Actions | Add to workflow YAML |
| StepSecurity Insights | Dashboard for harden-runner telemetry | https://app.stepsecurity.io |
| `cosign` | Verify artifact signatures | `brew install cosign` |
| `slsa-verifier` | Verify SLSA provenance | `go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest` |

## Real-World Incident: trivy-action (2026-03-19)

On March 19, 2026, `aquasecurity/trivy-action@v0.2.1` was compromised via a tag force-push attack. The attacker re-pointed the `v0.2.1` tag to a malicious commit.

**Timeline:**
- 2026-03-19: Compromised tag detected via StepSecurity Harden-Runner alerts showing unexpected outbound connections
- 2026-03-19: GitHub advisory published; community alerted via social media and security mailing lists
- 2026-03-20: Org-wide SHA pinning enforcement enabled (`sha_pinning_required=true`)
- 2026-03-20: 59 hardening PRs created across all netresearch repos using `pin-github-action --allow "netresearch/*"`

**Assessment:** Only one CI run was affected. The job used `GITHUB_TOKEN` with `contents: read` permissions only. No secret rotation was required. No malicious artifacts were uploaded.

**Key lessons:**
1. Tag-based action references are inherently mutable and vulnerable to force-push attacks
2. SHA pinning would have prevented exploitation entirely
3. Harden-Runner in audit mode detected the anomaly but did not block it — block mode with allowlists would have stopped the payload
4. Job-level permission isolation limited the blast radius to a read-only token
5. Dependabot `github-actions` ecosystem monitoring provides early warning of tag changes

## Related References

- `supply-chain-security.md` — SHA pinning, SLSA framework, dependency management
- `ci-security-pipeline.md` — CI/CD security patterns
- `automated-scanning.md` — Scanner configuration (semgrep, trivy, gitleaks)
