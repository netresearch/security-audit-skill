# TYPO3 Fluid Template Security

Fluid is the templating engine used by TYPO3 (and Neos / other TYPO3-derived stacks). Its auto-escape pipeline is asymmetric — most variable output escapes by default, but a handful of ViewHelpers and syntax forms bypass that protection silently. This reference catalogues the XSS and template-injection surface specific to Fluid, plus the Fluid 4 breaking changes that shipped with TYPO3 13/14.

For PHP-level TYPO3 patterns see `typo3-security.md`; for TypoScript / TSconfig see `typo3-typoscript-security.md`.

## Escape pipeline

Fluid's default behaviour is context-sensitive auto-escaping: `{variable}` produces HTML-escaped output in HTML templates, and JSON-encoded output in JSON contexts. **This only holds for variables passed through the default output pipeline.** Several shapes opt out.

### 1. `f:format.raw` — explicit opt-out

```html
<!-- VULNERABLE: Raw output of user-controlled data -->
{article.body -> f:format.raw()}

<!-- VULNERABLE: Inline form, same effect -->
<f:format.raw>{article.body}</f:format.raw>

<!-- SECURE: Trust content from a sanitiser, not the raw field -->
<f:format.html parseFuncTSPath="lib.parseFunc_RTE">{article.body}</f:format.html>
```

`f:format.raw` should only be applied to content that has already been sanitised — typically RTE output processed by `lib.parseFunc_RTE` (which runs through `htmlSanitizer` since TYPO3 10.3). If you see `-> f:format.raw()` on a field that came directly from a `TextField`, a backend `input` / `text` TCA column, or from `request.arguments`, treat it as an XSS sink.

**Detection:**
```bash
grep -rnP '(->\s*f:format\.raw\s*\(\)|<f:format\.raw\b)' --include='*.html' .
# Then manually verify each hit is sanitiser output, not raw user data.
```

### 2. Attribute context is NOT auto-escaped against JavaScript

HTML-context auto-escape handles `<` `>` `&` `"` `'` — but not JavaScript-context escaping:

```html
<!-- VULNERABLE: Value reaches JS context without JS escaping -->
<a href="#" onclick="loadUser('{user.name}')">Load</a>

<!-- VULNERABLE: Inline event handler with backtick template literal -->
<button onclick="fetch(`/api/users/{user.id}`)">Load</button>

<!-- SECURE: Build the URL server-side, use data-* attributes, hydrate via JS -->
<a href="#" data-user-id="{user.id}" class="js-load-user">Load</a>
```

Fluid's default escape passes through `htmlspecialchars`. That is correct for element-text context but insufficient for JavaScript string context, where `</script>`, `\x00`, and Unicode line terminators (`\u2028` / `\u2029`) all terminate or break out of a string literal.

**Detection:**
```bash
# Fluid variables appearing inside JavaScript strings / event handlers.
grep -rnP '(on[a-z]+\s*=\s*"[^"]*\{[a-zA-Z_]|<script\b[^>]*>[\s\S]*?\{[a-zA-Z_])' \
  --include='*.html' .
```

### 3. `htmlentitiesDecode` double-decode

```html
<!-- VULNERABLE: Decodes HTML entities in content that may itself contain markup -->
{post.summary -> f:format.htmlentitiesDecode()}

<!-- VULNERABLE: Chained decode-then-raw is the classic XSS shape -->
{post.summary -> f:format.htmlentitiesDecode() -> f:format.raw()}
```

`htmlentitiesDecode` is not a sanitiser — it actively *removes* HTML escaping. Chaining it with `raw` (or just using it in a context Fluid would otherwise escape) unpicks the default protection. There is almost no legitimate use case; be skeptical when you find one.

**Detection:**
```bash
grep -rnP '->\s*f:format\.htmlentitiesDecode\b' --include='*.html' .
```

## Template / partial injection

### 4. Dynamic partial names

```html
<!-- VULNERABLE: Attacker controls which partial is rendered -->
<f:render partial="{settings.layout}" arguments="{_all}" />

<!-- VULNERABLE: Same via section -->
<f:render section="{request.arguments.section}" />

<!-- SECURE: Allowlist resolved server-side, with a safe default -->
<f:render partial="Layout/{layout}" arguments="{_all}" />
<!-- Controller: $this->view->assign('layout', in_array($req, ['Plain','Sidebar','Two-Col']) ? $req : 'Plain'); -->
```

Fluid resolves partials against `partialRootPaths`, which is controlled by TypoScript. If the attacker picks the name, they can select any partial the controller has access to — including admin-only partials, partials intended only for a different plugin, or traversal into neighbouring sitePackages.

**Detection:**
```bash
# Partial / section name interpolated from a variable.
grep -rnP '<f:render\b[^>]*\b(partial|section)\s*=\s*"\{' --include='*.html' .
```

### 5. `arguments="{_all}"` over-sharing

```html
<!-- VULNERABLE: Hands every variable in the current scope to the partial -->
<f:render partial="UserCard" arguments="{_all}" />

<!-- SECURE: Pass only the arguments the partial actually needs -->
<f:render partial="UserCard" arguments="{user: user, showEmail: currentUser.isEditor}" />
```

`{_all}` is a debugging convenience. In production it is a leakage surface — partials intended for admin rendering will still have `{currentUser}`, `{debug}`, `{apiToken}` in scope.

### 6. `f:cObject` invoking TypoScript from a variable

```html
<!-- VULNERABLE: Attacker controls which TypoScript object is rendered -->
<f:cObject typoscriptObjectPath="{path}" data="{data}" />

<!-- SECURE: Hardcode the path, pass only data -->
<f:cObject typoscriptObjectPath="lib.articleTeaser" data="{article}" />
```

`f:cObject` is a bridge into TypoScript — anything TypoScript can do (see `typo3-typoscript-security.md`, especially `userFunc`) becomes available if the path is attacker-controlled.

## ViewHelpers worth auditing

### 7. `f:uri.external` / `f:link.external` — open redirect

```html
<!-- VULNERABLE: Unchecked URL from query string -->
<f:link.external uri="{request.arguments.redirect}">continue</f:link.external>

<!-- SECURE: Validate host against an allowlist in the controller; fall back to safe default -->
<f:link.external uri="{redirectUri}">continue</f:link.external>
<!-- Controller resolves redirectUri to '/' if the host isn't in the allowlist. -->
```

### 8. `f:uri.image` / `f:image` — SSRF and local-file disclosure via `src`

User-controlled `src` attributes on `f:image` let Fluid load arbitrary files. In TYPO3 9+ this is restricted to files within `FAL`-known storages; earlier versions could be coerced into reading `/etc/passwd` style paths.

```html
<!-- VULNERABLE on TYPO3 < 9 and any unprotected legacy pipeline -->
<f:image src="{request.arguments.avatar}" />

<!-- SECURE: Resolve FileReference in the controller, pass the object -->
<f:image image="{user.avatar}" />
```

### 9. Custom ViewHelpers with `$escapeOutput` / `$escapeChildren` disabled

```php
// VULNERABLE: ViewHelper that opts its arguments out of auto-escaping
final class UnsafeViewHelper extends AbstractViewHelper
{
    protected $escapeChildren = false;   // children output raw
    protected $escapeOutput  = false;    // result output raw
    // ...
}

// SECURE: Opt back into escaping, or escape manually for the correct context
final class SafeViewHelper extends AbstractViewHelper
{
    protected $escapeOutput = true;
    public function render(): string
    {
        return htmlspecialchars(
            (string)$this->arguments['value'],
            ENT_QUOTES | ENT_HTML5,
            'UTF-8'
        );
    }
}
```

A custom ViewHelper is often where Fluid's auto-escape safety is silently defeated, because the author knows the ViewHelper needs to emit HTML and flips off escaping without thinking about the call sites.

**Detection:**
```bash
# ViewHelpers that disable escape. Every hit needs justification.
grep -rnP '\$escape(Output|Children)\s*=\s*false' \
  --include='*.php' --include='*ViewHelper.php' .
```

## Fluid 4 / TYPO3 13–14 changes to audit

Fluid 4 ships with TYPO3 13 and changes several escaping defaults. When upgrading, re-check every template.

| Area | Fluid 3 | Fluid 4 |
|---|---|---|
| Default escape behaviour of some numeric ViewHelpers | string-cast then escape | strict type check, may throw |
| `f:format.raw` on `NULL` / missing variable | empty string | unchanged |
| `f:security.ifAuthenticated` | requires explicit `frontendUser` / `backendUser` | unchanged |
| Deprecated: `v:` namespace `vhs` third-party pack | used for many custom escapes | removed; update templates |
| Namespaces declared via `{namespace vhs=...}` top-of-file | worked | removed; use inline `f:` core helpers |

A template-audit checklist for the 3 → 4 jump:

- [ ] Run `typo3 extensionscanner:scan` against every site package; inspect every `templates:/Fluid` hit
- [ ] `grep -rnP 'xmlns:[a-z]+' Resources/Private/Templates/` — any non-`f:` namespace likely comes from `vhs` or a removed third-party pack
- [ ] `grep -rn '{namespace ' Resources/Private/Templates/` — same
- [ ] Review every `->f:format.raw()` hit on dynamic content; Fluid 4 does not change its semantics but the upgrade is a reasonable time to tighten them
- [ ] Re-run an authenticated-crawler XSS scanner (e.g. nikto, zap) against key pages that use user-supplied content

## Prevention checklist

- [ ] `-> f:format.raw()` and `<f:format.raw>` are only applied to sanitiser output (`lib.parseFunc_RTE`, `htmlSanitizer`), never to raw user input
- [ ] `f:format.htmlentitiesDecode` is not used in user-content paths
- [ ] Fluid variables do not cross into JavaScript string context or inline event handlers without explicit JS-context escaping
- [ ] `f:render partial="{...}"` uses an allowlisted prefix, not a raw user value
- [ ] `arguments="{_all}"` is replaced with explicit argument lists on any partial rendered with user-visible output
- [ ] `f:cObject typoscriptObjectPath="{...}"` uses a hardcoded path
- [ ] `f:link.external` / `f:uri.external` URIs are host-allowlisted in the controller
- [ ] Custom ViewHelpers do not set `$escapeOutput = false` or `$escapeChildren = false` without explicit justification and manual context-appropriate escaping
- [ ] Fluid 4 migration: removed `vhs` / third-party namespace declarations are audited and replaced

## Related references

- `typo3-security.md` — PHP-level TYPO3 patterns (QueryBuilder, FAL, FormProtection)
- `typo3-typoscript-security.md` — TypoScript and TSconfig security
- `framework-security.md` — cross-framework middleware / validation patterns
- `owasp-top10.md` — XSS category (A03:2021)
