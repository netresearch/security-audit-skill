# Pre-Publication Git-History Hygiene

Auditing a repository **before it goes public** — or before pushing a local/private repo to a new remote — is a distinct check from scanning the working tree. A clean `HEAD` does not mean a clean history: secrets and internal notes that were committed and later "deleted" remain in every clone of the history, and flipping a repo to public (or mirroring it) exposes all of it.

`scripts/scanners/secrets.sh` and the Gitleaks job in [`ci-security-pipeline.md`](ci-security-pipeline.md) already scan history for *secrets* (the script runs `trufflehog git` when a `.git` directory is present). This reference adds what they don't cover: **AI-context-file** leak detection in history, the **removal/scrub** recipe, and the pre-publication workflow that ties scanning and remediation together.

## 1. Scan the full history for secrets

A shallow clone or a `HEAD`-only scan misses secrets introduced and later removed. First make sure the clone has full history, then walk the entire commit graph:

```bash
# A shallow clone has no history to scan — deepen it first
[ "$(git rev-parse --is-shallow-repository)" = true ] && git fetch --unshallow

# TruffleHog — git mode walks every commit, not just the working tree
trufflehog git "file://$(pwd)" --only-verified --json

# Gitleaks — scans all history by default; --log-opts narrows the range
gitleaks detect --source . --redact
```

> **No native TruffleHog?** Run it via a container so a pre-publication audit isn't blocked on a local install. Mount the repo read-only:
> ```bash
> podman run --rm -v "$(pwd):$(pwd):ro" -w "$(pwd)" \
>   ghcr.io/trufflesecurity/trufflehog:latest git "file://$(pwd)" --only-verified
> # swap `podman` for `docker` if that's what's installed
> ```

**Removal is not rotation.** Any secret found in history must be **rotated at its source** (revoke the token, rebuild the key) *in addition to* being scrubbed — assume it was cloned the moment it was pushed.

## 2. Detect AI-context files in history

Agent-context files — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, `.cursor/` — routinely accumulate internal URLs, hostnames, credentials, project codenames, and business-logic notes. The current copy may be sanitized while an earlier revision still leaks (the same content class as [`llm-security.md`](llm-security.md) § LLM07 System Prompt Leakage, but in *history*).

Find any path that existed in *any* commit, even if it is gone from the working tree:

```bash
for p in CLAUDE.md AGENTS.md .cursorrules .github/copilot-instructions.md .cursor; do
  if git log --all --full-history --oneline -- "$p" | grep -q '.'; then
    echo "PRESENT IN HISTORY: $p"
  fi
done
```

Any output means the path was committed at some point — review those revisions before publishing:

```bash
git log --all --full-history -p -- CLAUDE.md   # inspect every historical version
```

## 3. Scrub a path from all history

Use [`git filter-repo`](https://github.com/newren/git-filter-repo) (the maintained, recommended tool):

```bash
git filter-repo --invert-paths \
  --path CLAUDE.md --path AGENTS.md --path .cursorrules \
  --path .github/copilot-instructions.md --path .cursor
```

If `filter-repo` cannot be installed, the git built-in `filter-branch` works for the same job (slower, fewer guardrails):

```bash
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch -r CLAUDE.md AGENTS.md .cursorrules .github/copilot-instructions.md .cursor' \
  --prune-empty --tag-name-filter cat -- --all
```

This **rewrites history**, so:

- Every commit SHA after the scrubbed point changes. Force-push (`git push --force --all && git push --force --tags`) and have collaborators re-clone — old clones still contain the secret.
- Open PRs built on the old history will need rebasing.
- Scrubbing removes the file from *your* history; it does **not** invalidate exposed credentials — rotate them (step 1).

## 4. Verify

Re-run the step-1 history scan and the step-2 path check after the rewrite. Both must come back clean before the repo is made public or mirrored.

```bash
trufflehog git "file://$(pwd)" --only-verified --json   # expect: no findings
git log --all --full-history --oneline -- CLAUDE.md      # expect: no output
```

## When to run this

- Before changing a repo's visibility from private → public.
- Before mirroring/pushing an existing local or private repo to a new public remote.
- During a security audit of any repo whose history predates secret-scanning push protection being enabled.
