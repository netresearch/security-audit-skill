# Supply Chain Security

Supply chain attacks target the tools, dependencies, and processes used to build and deliver software. This reference covers frameworks, tools, and practices for securing the software supply chain in PHP projects.

## SLSA Framework (Supply-chain Levels for Software Artifacts)

SLSA (pronounced "salsa") is a security framework that defines increasing levels of supply chain integrity guarantees. It focuses on ensuring that software artifacts are produced by the expected source, through the expected process, and have not been tampered with.

### Level 1: Documentation of Build Process

Minimal requirements for supply chain transparency.

**Requirements:**
- Build process is scripted (not manual)
- Provenance metadata is generated (what was built, from what source)
- Provenance is available to consumers

```yaml
# Minimal SLSA Level 1: Documented build in GitHub Actions
name: Build

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install dependencies
        run: composer install --no-dev --optimize-autoloader

      - name: Create release archive
        run: |
          tar -czf myapp-${{ github.ref_name }}.tar.gz \
            --exclude='.git' \
            --exclude='tests' \
            --exclude='.github' \
            .

      - name: Generate build provenance
        run: |
          sha256sum myapp-${{ github.ref_name }}.tar.gz > checksums.txt
          echo "Build provenance:" >> provenance.txt
          echo "Source: ${{ github.repository }}@${{ github.sha }}" >> provenance.txt
          echo "Builder: GitHub Actions" >> provenance.txt
          echo "Build ID: ${{ github.run_id }}" >> provenance.txt
          echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> provenance.txt
```

### Level 2: Hosted Build Service, Generated Provenance

**Requirements:**
- All Level 1 requirements
- Build runs on a hosted service (not developer laptops)
- Provenance is generated automatically by the build service
- Provenance includes source reference and builder identity

```yaml
  # Level 2: Use GitHub's attestation feature
  build-with-attestation:
    runs-on: ubuntu-latest
    permissions:
      id-token: write      # For signing
      contents: read
      attestations: write   # For attestation
    steps:
      - uses: actions/checkout@v4

      - name: Build artifact
        run: |
          composer install --no-dev --optimize-autoloader
          tar -czf myapp-${{ github.ref_name }}.tar.gz .

      - name: Generate artifact attestation
        uses: actions/attest-build-provenance@v2
        with:
          subject-path: 'myapp-${{ github.ref_name }}.tar.gz'
```

### Level 3: Hardened Build Platform, Non-Forgeable Provenance

**Requirements:**
- All Level 2 requirements
- Build platform is hardened against tampering
- Provenance is signed and non-forgeable
- Provenance includes complete build instructions

```yaml
  # Level 3: Use slsa-github-generator for non-forgeable provenance
  # This runs in a separate, isolated workflow
  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      compile-generator: true  # Build from source to avoid binary fetch issues
```

**Important: base64-subjects format:**

```bash
# CORRECT: sha256sum raw output, base64-encoded
HASHES=$(sha256sum myapp-*.tar.gz | base64 -w0)
echo "hashes=$HASHES" >> "$GITHUB_OUTPUT"

# WRONG: JSON format will cause "unexpected sha256 hash format" error
# Do NOT use jq to create JSON arrays for this field
```

### Level 4: Two-Party Review

**Requirements:**
- All Level 3 requirements
- All changes require two-person review
- Build process is hermetic (no network access during build)

This level typically requires organizational policies:
- Branch protection rules requiring 2+ reviewers
- CODEOWNERS file for security-critical paths
- Hermetic build environments (no network access)

## Sigstore/Cosign for Artifact Signing

Sigstore provides keyless signing for software artifacts. Cosign is the primary tool for signing and verifying container images and blobs.

### Signing Container Images

```yaml
  sign-image:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # For OIDC token
      packages: write   # For pushing signatures
    steps:
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Sign image with Cosign (keyless)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

### Verifying Signed Artifacts

```bash
# Verify a signed container image
cosign verify \
  --certificate-identity-regexp="https://github.com/myorg/myrepo" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myrepo:latest

# Verify a signed blob (release artifact)
cosign verify-blob \
  --certificate artifact.pem \
  --signature artifact.sig \
  --certificate-identity-regexp="https://github.com/myorg/myrepo" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  myapp-v1.0.0.tar.gz
```

### Signing PHP Release Archives

```yaml
  sign-release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
    steps:
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Download release artifact
        run: gh release download ${{ github.ref_name }} --pattern "*.tar.gz"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Sign artifact
        run: |
          cosign sign-blob --yes \
            --output-signature myapp.tar.gz.sig \
            --output-certificate myapp.tar.gz.pem \
            myapp-${{ github.ref_name }}.tar.gz

      - name: Upload signatures to release
        run: |
          gh release upload ${{ github.ref_name }} \
            myapp.tar.gz.sig \
            myapp.tar.gz.pem
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## OpenSSF Scorecard

OpenSSF Scorecard assesses open-source project security practices. It checks automated tests, dependency management, code review, and more.

### What Scorecard Checks

| Check | What It Evaluates | Weight |
|-------|-------------------|--------|
| Binary-Artifacts | No binary files in repository | High |
| Branch-Protection | Branch protection rules configured | High |
| CI-Tests | Automated tests run on PRs | Medium |
| CII-Best-Practices | CII badge status | Low |
| Code-Review | All changes reviewed before merge | High |
| Contributors | Multiple active contributors | Low |
| Dangerous-Workflow | No dangerous patterns in workflows | Critical |
| Dependency-Update-Tool | Dependabot/Renovate configured | High |
| Fuzzing | Fuzz testing configured | Medium |
| License | License file present | Low |
| Maintained | Recent commits and issue responses | Medium |
| Packaging | Published via official package managers | Medium |
| Pinned-Dependencies | Dependencies pinned by hash | High |
| SAST | Static analysis tools configured | High |
| Security-Policy | SECURITY.md file present | Medium |
| Signed-Releases | Releases are cryptographically signed | High |
| Token-Permissions | Workflow permissions follow least privilege | High |
| Vulnerabilities | No unpatched vulnerabilities | High |

### Running Scorecard

```yaml
  scorecard:
    name: OpenSSF Scorecard
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Scorecard
        uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: scorecard-results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload Scorecard results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorecard-results.sarif
```

### How to Improve Scores

**Branch Protection (often the lowest score):**

```bash
# Via gh CLI
gh api repos/{owner}/{repo}/branches/main/protection -X PUT -f '{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "required_status_checks": {
    "strict": true,
    "contexts": ["tests", "security"]
  },
  "enforce_admins": true,
  "restrictions": null
}'
```

**Security Policy:**

Create a `SECURITY.md` in the repository root:

```markdown
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to security@example.com.
Do NOT create public GitHub issues for security vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | Security fixes only |
| < 1.0   | No        |
```

## GitHub Actions Security

### SHA-Pinned Actions

Never reference actions by mutable tag. Always pin to a specific commit SHA to prevent supply chain attacks via tag hijacking.

```yaml
# VULNERABLE: Tags can be moved to point to malicious commits
- uses: actions/checkout@v4
- uses: shivammathur/setup-php@v2

# SECURE: SHA-pinned to specific commit (immutable)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
- uses: shivammathur/setup-php@cf4cade2721270509d5b1c766ab3549210a39a2a  # v2.33.0
```

**How to find the SHA for a tag:**

```bash
# Use gh CLI to find the SHA for a specific tag
gh api repos/actions/checkout/tags --jq '.[] | select(.name == "v4.2.2") | "\(.name) \(.commit.sha)"'

# Or for the latest tag
gh api repos/actions/checkout/tags --jq '.[0] | "\(.name) \(.commit.sha)"'
```

**Why this matters:** In 2025, the `tj-actions/changed-files` action was compromised via a tag hijack. Pinned SHAs would have prevented exploitation.

### Least-Privilege Workflow Permissions

Set the minimum permissions needed at the workflow and job level.

```yaml
# VULNERABLE: Default permissions are too broad
permissions: write-all

# SECURE: Set minimal permissions at workflow level
permissions:
  contents: read  # Read repository contents

# Then expand only where needed at job level
jobs:
  build:
    permissions:
      contents: read

  deploy:
    permissions:
      contents: read
      packages: write      # Only this job needs package write
      id-token: write      # Only this job needs OIDC

  security-scan:
    permissions:
      contents: read
      security-events: write  # Only this job uploads SARIF
```

### GITHUB_TOKEN Minimal Permissions

The `GITHUB_TOKEN` automatically gets permissions based on the workflow-level `permissions` key. Restrict it.

```yaml
# Repository Settings > Actions > General > Workflow permissions
# Select: "Read repository contents and packages permissions"
# This sets the default for GITHUB_TOKEN across all workflows

# In workflow, only request what you need:
permissions:
  contents: read       # Clone/checkout
  pull-requests: write # Comment on PRs (if needed)
  # All other permissions: none
```

### harden-runner (Step Security)

`harden-runner` monitors and restricts network and process activity in workflow steps. It detects unexpected outbound connections that could indicate a compromised action.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@v2
        with:
          egress-policy: audit  # Start with audit to discover legitimate connections
          # egress-policy: block  # Switch to block after baselining

      - uses: actions/checkout@v4
      # ... remaining steps
```

**Modes:**
- `audit` - Log all outbound connections (start here)
- `block` - Block connections not in the allow list

**After running in audit mode, review the StepSecurity dashboard to create an allow list:**

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
```

## Dependency Management

### Lock Files

Lock files ensure reproducible builds by pinning exact dependency versions and their hashes.

**PHP (composer.lock):**
- Applications: Always commit `composer.lock`
- Libraries/Extensions: Do NOT commit `composer.lock` (let consumers resolve versions)
- Verify integrity: `composer install` verifies hashes from lock file

```bash
# Verify lock file is in sync with composer.json
composer validate --strict

# Install from lock file only (CI/production)
composer install --no-dev --optimize-autoloader
```

**JavaScript (package-lock.json):**

```bash
# Install from lock file only (CI)
npm ci

# Verify integrity
npm audit signatures
```

### Dependabot / Renovate for Automated Updates

**Dependabot configuration:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  # PHP dependencies
  - package-ecosystem: "composer"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
    open-pull-requests-limit: 10
    # Group minor/patch updates to reduce PR noise
    groups:
      minor-and-patch:
        update-types:
          - "minor"
          - "patch"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "ci"

  # npm (if applicable)
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"

  # Docker
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Renovate configuration (alternative to Dependabot):**

```json5
// renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    "security:openssf-scorecard",
    ":pinAllExceptPeerDependencies"
  ],
  "packageRules": [
    {
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true,
      "automergeType": "pr",
      "requiredStatusChecks": ["tests", "security"]
    },
    {
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "labels": ["breaking-change"]
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  }
}
```

### License Compliance

Ensure dependencies use compatible licenses. Some licenses have requirements that may conflict with your project's licensing.

```yaml
  license-check:
    name: License Compliance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check licenses with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scanners: 'license'
          severity: 'UNKNOWN,HIGH,CRITICAL'
```

**Composer license check:**

```bash
# List all dependency licenses
composer licenses

# Programmatic check
composer licenses --format=json | jq '.dependencies | to_entries[] | select(.value.license[0] | test("GPL|AGPL|SSPL"))'
```

## Reproducible Builds

Reproducible builds ensure that the same source code always produces the same binary output, allowing independent verification.

### PHP Application Reproducibility

```dockerfile
# Use fixed versions everywhere
FROM php:8.4.3-fpm-alpine3.21

# Pin OS package versions
RUN apk add --no-cache \
    libpng=1.6.44-r0 \
    icu-libs=74.2-r0

# Use lock file for exact dependency versions
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader --no-cache

# Set consistent metadata
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.revision=$VCS_REF
```

**Key practices:**
- Pin base image digests (not just tags)
- Pin OS package versions
- Use `composer.lock` for PHP dependencies
- Use `package-lock.json` for npm dependencies
- Set `SOURCE_DATE_EPOCH` for timestamp reproducibility
- Avoid build-time network access after dependency install

### Verification

```bash
# Build twice and compare
docker build -t myapp:build1 .
docker build -t myapp:build2 .

# Compare layer digests
docker inspect myapp:build1 --format='{{.RootFS.Layers}}' > layers1.txt
docker inspect myapp:build2 --format='{{.RootFS.Layers}}' > layers2.txt
diff layers1.txt layers2.txt
```

## Package Provenance Verification

### Verifying Composer Package Integrity

```bash
# Composer verifies package hashes from lock file automatically during install
composer install

# Check installed package sources
composer show --installed --format=json | jq '.installed[] | {name, version, source}'
```

### Verifying Container Image Provenance

```bash
# Check if an image was signed
cosign verify \
  --certificate-identity-regexp="https://github.com/myorg" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp:latest

# Verify SLSA provenance of an image
slsa-verifier verify-image \
  ghcr.io/myorg/myapp:latest \
  --source-uri github.com/myorg/myapp \
  --source-tag v1.0.0

# Verify GitHub artifact attestation
gh attestation verify myapp-v1.0.0.tar.gz \
  --owner myorg
```

## Detection Patterns for Supply Chain Audit

```
# Find unpinned GitHub Actions
uses:\s+[^@]+@v\d+
uses:\s+[^@]+@main
uses:\s+[^@]+@master

# Find overly permissive workflow permissions
permissions:\s*write-all
permissions:[\s\S]*?contents:\s+write(?!.*security-events)

# Find missing lock files
# composer.lock should exist for applications (not libraries)
# package-lock.json should exist if package.json exists

# Find workflows without harden-runner
# .github/workflows/*.yml should contain step-security/harden-runner

# Find unsigned releases
# Releases should have .sig or .pem files, or use GitHub attestation

# Find missing Dependabot/Renovate config
# .github/dependabot.yml or renovate.json should exist

# Find missing SECURITY.md
# Repository root should contain SECURITY.md
```

## Supply Chain Security Checklist

| Category | Check | Priority |
|----------|-------|----------|
| Dependencies | `composer audit` runs in CI | Critical |
| Dependencies | Lock files committed (for applications) | Critical |
| Dependencies | Dependabot or Renovate configured | High |
| Dependencies | License compliance checked | Medium |
| Actions | All actions SHA-pinned | Critical |
| Actions | Workflow permissions minimized | Critical |
| Actions | harden-runner configured | High |
| Actions | GITHUB_TOKEN has least privilege | High |
| Provenance | Build runs on hosted CI (not local) | High |
| Provenance | SLSA provenance generated | Medium |
| Provenance | Release artifacts signed (Cosign) | Medium |
| Provenance | SBOM generated for releases | Medium |
| Policy | SECURITY.md exists | High |
| Policy | Branch protection requires reviews | High |
| Policy | OpenSSF Scorecard score tracked | Medium |
| Builds | Reproducible build process documented | Low |
| Builds | Container images use pinned base digests | Medium |

## Remediation Priority

| Severity | Issue | Timeline |
|----------|-------|----------|
| Critical | Unpinned GitHub Actions (tag-based references) | Immediate |
| Critical | Overly permissive workflow permissions | Immediate |
| High | No dependency vulnerability scanning in CI | 24 hours |
| High | Missing SECURITY.md | 1 week |
| High | No automated dependency updates | 1 week |
| Medium | No artifact signing | 2 weeks |
| Medium | No SBOM generation | 2 weeks |
| Medium | No harden-runner in workflows | 2 weeks |
| Low | No SLSA Level 3 provenance | 1 month |
| Low | No reproducible build verification | 1 month |

## Related References

- `ci-security-pipeline.md` - CI tools that implement these practices
- `owasp-top10.md` - A06:2021 Vulnerable and Outdated Components, A08:2021 Software and Data Integrity
- `api-key-encryption.md` - Securing secrets that should never enter the supply chain
