# TYPO3 TypoScript and TSconfig Security

TypoScript is the configuration language that drives TYPO3's frontend rendering and most backend behaviour. It has its own injection surface — distinct from PHP or Fluid — because several constructs evaluate external input at runtime and at least one (`userFunc`) is a direct arbitrary-code-execution primitive. TSconfig is TypoScript used for backend configuration (page, user, site) with a smaller but similar surface.

For PHP-level TYPO3 patterns see `typo3-security.md`; for Fluid templating see `typo3-fluid-security.md`.

## The big three footguns

### 1. `userFunc` / `preUserFunc` — arbitrary PHP execution

`userFunc` is a TypoScript property that calls a PHP function or method. Any attacker who can write TypoScript (typically: a developer with low-priv code-review rights, or an integrator uploading a sitepackage, or a compromised Git pipeline that merges TypoScript files) can execute arbitrary PHP with the frontend's privileges.

```typoscript
# VULNERABLE: userFunc wired directly to a generic callable
lib.myOutput = USER
lib.myOutput {
    userFunc = TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance
    1 = {$somebody.untrusted.class}
}

# VULNERABLE: preUserFunc on stdWrap — runs before every use of the value
lib.greeting = TEXT
lib.greeting {
    value = Hello
    stdWrap.preUserFunc = VendorX\Ext\Utility\SuspiciousLoader->loadAndRun
    stdWrap.preUserFunc.payload = {getenv:API_KEY}
}

# SECURE: userFunc to a specific, allowlisted method that validates its input
lib.productPrice = USER
lib.productPrice {
    userFunc = MyVendor\MyExt\Service\PriceRenderer->render
    settings {
        # Only properties the PHP method explicitly consumes
        currency = EUR
    }
}
```

`userFunc` is a legitimate feature; it is not itself a vulnerability. The audit question is: **does the function name come from a trusted, versioned part of the TypoScript, or could it be influenced by sitepackage uploads, form data, or pipeline inputs?**

**Detection:**
```bash
# All userFunc / preUserFunc / postUserFunc usages — every one needs manual review.
# POSIX ERE (grep -E) does not portably support \s or \b; use character classes.
grep -rnE '(^|[^A-Za-z])(pre|post)?[Uu]serFunc[[:space:]]*=' \
  --include='*.typoscript' .
# Note: legacy pre-TYPO3-10 repos may still use the .ts extension for TypoScript.
# That extension collides with TypeScript source, so re-run the recipe scoped to
# Configuration/TypoScript/ or typo3conf/ rather than adding --include='*.ts' globally.
# Inside TCA / Services / YAML, the same concept reaches through 'userFunc' keys:
grep -rnE "'userFunc'[[:space:]]*=>|\"userFunc\"[[:space:]]*=>" \
  --include='*.php' Configuration/ 2>/dev/null
```

### 2. `stdWrap.insertData` — lazy marker evaluation

`insertData` re-parses the rendered string and expands `{…:…}` markers against runtime context. If the wrapped value came from GET/POST (`GP:field`) or from an untrusted database row, an attacker can inject a marker that then reads something else — a cross-reference XSS / information-disclosure primitive.

```typoscript
# VULNERABLE: insertData over an untrusted value
lib.bannerText = TEXT
lib.bannerText {
    value.data = GP:banner                  # attacker-controlled
    stdWrap.insertData = 1                   # now they can inject {TSFE:id}, {GP:debug}, etc.
}

# SECURE: Either drop insertData or apply it only to trusted config-time content
lib.bannerText = TEXT
lib.bannerText {
    value.data = GP:banner
    stdWrap.htmlSpecialChars = 1
    # insertData removed — not needed for plain text rendering
}
```

The allowed marker prefixes inside `insertData` (`GP:`, `TSFE:`, `page:`, `field:`, `register:`, `getIndpEnv:`, `LLL:`, `path:`) cover quite a bit of surface — enough to read environment context, session IDs, registered variables, and arbitrary file paths the frontend has access to.

**Detection:**
```bash
# insertData = 1 combined with GP: / cObj.data = *user* earlier in the same object
grep -rnE 'stdWrap\.insertData[[:space:]]*=[[:space:]]*1' --include='*.typoscript' .
```

### 3. `GP:`, `TSFE->fe_user`, and raw request data without `htmlSpecialChars`

```typoscript
# VULNERABLE: GP data rendered without escaping
lib.search = TEXT
lib.search.data = GP:q

# VULNERABLE: Override chain pulls attacker-controlled value into TypoScript
config.absRefPrefix = /
config.absRefPrefix.override.data = GP:base     # attacker sets /evil.com/

# SECURE: Always chain htmlSpecialChars, and cap the value domain
lib.search = TEXT
lib.search {
    data = GP:q
    htmlSpecialChars = 1
    ifEmpty = (no query)
    # Cap length so a 10kB blob can't blow up the page
    stdWrap.crop = 120 | ... | 1
}
```

`data = GP:…` (TYPO3's merged GET+POST accessor) and `data = TSFE:fe_user|…` bring raw request or session content directly into the output pipeline; `register:` and `field:` can carry tainted content that was written earlier in the pipeline. Any TEXT or COA_INT using these patterns without `htmlSpecialChars = 1` is an XSS sink.

**Detection:**
```bash
# Untrusted-input accessors feeding a cObject TEXT without a nearby
# htmlSpecialChars. This is a "relative order of instructions" check —
# line-oriented grep cannot decide it alone. A single awk pass per file
# reasons about the whole file and reports the hits that lack an
# htmlSpecialChars within 10 lines.
#
# GP is the documented merged GET+POST accessor; there is no bare POST: key.
# register:/field: can carry content that was written earlier in the pipeline
# and should be treated as tainted for this check.
find . -type f \( -name '*.typoscript' \) -print0 | xargs -0 awk '
  {
    if ($0 ~ /(^|[^A-Za-z_])data[[:space:]]*=[[:space:]]*(GP|TSFE|register|field):/) {
      hits[FNR] = $0
    }
    buf[NR % 21] = $0
  }
  FNR == 1 && NR > 1 { for (l in buf) delete buf[l]; for (l in hits) delete hits[l] }
  ENDFILE {
    # Re-scan: for each hit, look at ±10 lines for htmlSpecialChars = 1.
    n = NR
    for (l in hits) {
      ok = 0
      for (k = (l > 10 ? l - 10 : 1); k <= l + 10 && k <= n; k++) {
        if (lines[k] ~ /htmlSpecialChars[[:space:]]*=[[:space:]]*1/) { ok = 1; break }
      }
      if (!ok) print FILENAME ":" l ": " hits[l] "  # no htmlSpecialChars nearby"
    }
    delete hits; delete lines
  }
  { lines[FNR] = $0 }
'
```

## typolink / HMENU / redirect traps

### 4. `typolink.ATagParams` injection

```typoscript
# VULNERABLE: ATagParams concatenated from user data
lib.userLink = TEXT
lib.userLink {
    typolink {
        parameter = {$settings.url}
        ATagParams.data = GP:attrs        # attacker supplies: "onclick=alert(1)"
    }
}

# SECURE: Hardcode attributes; do not sink user data into the A-tag tag text
lib.userLink = TEXT
lib.userLink {
    typolink {
        parameter = {$settings.url}
        ATagParams = rel="noopener noreferrer" target="_blank"
    }
}
```

### 5. `typolink.additionalParams` open redirect / open-target

```typoscript
# VULNERABLE: Attacker-controlled target for server-side HTTP calls / redirects
lib.jump = TEXT
lib.jump {
    typolink {
        parameter.data = GP:to
        additionalParams.data = GP:params
        forceAbsoluteUrl = 1
    }
    stdWrap.typolink.returnLast = url
}
```

Any `parameter.data` that reads from `GP:` should be validated against an allowlist before it reaches `typolink`. Link-building is routed through `LinkService` and then through per-type handlers (`PageLinkHandler`, `ExternalLinkHandler`, `TelephoneLinkHandler`, etc.). `ExternalLinkHandler` handles external URLs and does not validate them against a host allowlist — validation must happen in the calling controller or a TypoScript `if.isTrue` check, before the value reaches `typolink.parameter`. TYPO3's HMAC / `cHash` machinery covers internal parameter integrity + caching, not external-URL trust.

### 6. `HMENU` with `if.isTrue.cObject` evaluation order

```typoscript
# VULNERABLE: The access check cObject itself uses user data before the check runs.
# Order of evaluation in HMENU is subtle; a cObject whose side-effect is "read GP"
# fires even when the outer branch is falsy.
lib.adminMenu = HMENU
lib.adminMenu {
    1 = TMENU
    1 {
        NO = 1
        NO.wrapItemAndSub = ...
        if.isTrue.cObject = USER
        if.isTrue.cObject.userFunc = MyExt\AccessCheck::currentUserIsAdmin
    }
}
```

`userFunc` inside `if.isTrue.cObject` is a common pattern for role-based menu gating. Two things to audit: (a) the `userFunc` itself must not have side effects (logging, session writes) that leak info; (b) the fallback when the check fails should not include the menu item's title or URL in a `wrap` that rendered earlier.

## `config.no_cache` and `config.debug`

```typoscript
# VULNERABLE: Entire site becomes uncached, easy DoS + information leaks
config.no_cache = 1
config.debug = 1
```

`config.no_cache = 1` and `config.debug = 1` at site-level turn off caching and enable debug output; both should never be committed. Check page-TSconfig and site-config overrides too — `no_cache` on specific page types (e.g., forms) is legitimate but should be narrow.

**Detection:**
```bash
# Site-wide no-cache or debug.
grep -rnE 'config\.(no_cache|debug)[[:space:]]*=[[:space:]]*1' \
  --include='*.typoscript' --include='*.yaml' .
```

## TSconfig (backend)

TSconfig is TypoScript used for backend UI configuration. It has a smaller surface but the same foot-guns apply.

### 7. Page TSconfig — `TCEMAIN.clearCacheCmd` abuse

```typoscript
# VULNERABLE: Untrusted page TSconfig can nuke caches on save, causing
# coordinated invalidation. Low-priv editors with Page TSconfig rights
# (via `options.pageTsConfig`) can chain this with other writes.
TCEMAIN.clearCacheCmd = all
```

### 8. RTE preset TSconfig — CKEditor 5 config path

Since TYPO3 12 the RTE is CKEditor 5 with YAML presets. Each preset can load an `editor.config.extraPlugins` list pointing at arbitrary JS modules in `Resources/Public/JavaScript/…`. An attacker who can commit a sitepackage can sneak in a plugin whose payload reaches every editor session.

```yaml
# VULNERABLE (YAML preset loaded via Page TSconfig)
editor:
  config:
    extraPlugins:
      - Vendor/UnknownPlugin/unpinned@latest   # any JS file; runs in editor context
```

For CKEditor 5 plugin authoring / preset best-practices, the sibling `netresearch/typo3-ckeditor5-skill` repo is the canonical reference; this section focuses on auditing unknown or `@latest`-pinned plugins that already landed in a site package.

### 9. `permissions.file` / `permissions.file.default`

```typoscript
# VULNERABLE: Page TSconfig relaxes file-mount permissions beyond the backend user group
permissions.file.default = show,read,write,delete,add,rename,replace,editMeta
```

Audit every site's Page TSconfig for `permissions.*` blocks that widen what the default backend group can do.

### 10. `mod.web_layout.disableAdvanced` and friends

```typoscript
# Cosmetic-looking but can mask security posture — editors see fewer warnings,
# fewer advanced fields, harder to spot "access hidden = 1" on a sensitive page.
mod.web_layout.disableAdvanced = 1
```

Not a direct vulnerability, but flag during audit: does disabling advanced UI hide security-relevant state from site editors?

## Prevention checklist

- [ ] All `userFunc` / `preUserFunc` / `postUserFunc` point at hardcoded, version-controlled callables — not at values influenced by sitepackage upload, forms, or pipeline inputs
- [ ] `stdWrap.insertData = 1` is never applied to values that came from `GP:` (the merged GET+POST accessor) or untrusted database rows
- [ ] Every `data = GP:…` (merged GET+POST) and `data = TSFE:fe_user|…` is followed by `htmlSpecialChars = 1` (or is wrapped in a cObject that escapes)
- [ ] `typolink.parameter.data = GP:…` is validated against an allowlist in a controller before reaching TypoScript
- [ ] `typolink.ATagParams.data` is not sourced from request data
- [ ] `config.no_cache = 1` and `config.debug = 1` do not appear in committed site configuration
- [ ] Page TSconfig overrides of `TCEMAIN`, `permissions.file`, and RTE presets are reviewed for privilege escalation
- [ ] RTE CKEditor 5 preset `extraPlugins` entries are pinned to a known version and sourced from a trusted path
- [ ] `HMENU` access checks via `if.isTrue.cObject.userFunc` are side-effect-free and the fallback rendering does not leak the hidden item's metadata

## Related references

- `typo3-security.md` — PHP-level TYPO3 patterns
- `typo3-fluid-security.md` — Fluid template escaping + ViewHelper pitfalls
- `framework-security.md` — cross-framework middleware / validation patterns
- External: `netresearch/typo3-ckeditor5-skill` — CKEditor 5 preset authoring (separate skill repo)
