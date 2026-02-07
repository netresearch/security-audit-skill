# HTTP Security Headers Reference

## Overview

HTTP security headers instruct the browser to enable or disable security features
that protect against common web attacks. Missing or misconfigured headers are
covered by OWASP A05:2021 (Security Misconfiguration). This reference provides a
complete guide to every relevant security header, framework integration patterns,
and detection methods.

---

## Header Reference

### Strict-Transport-Security (HSTS)

Forces browsers to use HTTPS for all future requests to the domain, preventing
protocol downgrade attacks and cookie hijacking.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Directive | Purpose |
|-----------|---------|
| `max-age=31536000` | Browser remembers HTTPS-only for 1 year (in seconds) |
| `includeSubDomains` | Applies to all subdomains (required for preload) |
| `preload` | Eligible for browser preload list (hardcoded HTTPS in browsers) |

**Deployment notes:**
- Start with a short `max-age` (e.g., 300) during testing, then increase to 31536000.
- `includeSubDomains` requires ALL subdomains to support HTTPS. Audit before enabling.
- Preload submission: https://hstspreload.org -- once submitted, removal takes months.
- Only send HSTS over HTTPS responses. Sending it over HTTP is ignored by browsers.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// HSTS with short max-age provides minimal protection
header('Strict-Transport-Security: max-age=0');

// VULNERABLE - DO NOT USE
// Sending HSTS over HTTP is ignored and may indicate misconfiguration
// (This header must only be set on HTTPS responses)
```

```php
<?php

declare(strict_types=1);

// SECURE: Full HSTS with preload eligibility
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
```

---

### Content-Security-Policy (CSP)

Controls which resources the browser is allowed to load, providing strong mitigation
against XSS, data injection, and clickjacking attacks. CSP is the single most
effective header for preventing XSS.

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; report-uri /csp-report
```

**Key Directives:**

| Directive | Purpose | Example |
|-----------|---------|---------|
| `default-src` | Fallback for all resource types | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-abc123'` |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` |
| `connect-src` | AJAX, WebSocket, fetch targets | `'self' https://api.example.com` |
| `media-src` | Audio and video sources | `'self'` |
| `object-src` | Plugin content (Flash, Java) | `'none'` |
| `frame-src` | iframe sources | `'none'` |
| `frame-ancestors` | Who can embed this page (replaces X-Frame-Options) | `'none'` |
| `base-uri` | Allowed `<base>` element URLs | `'self'` |
| `form-action` | Allowed form submission targets | `'self'` |
| `report-uri` | (Deprecated) Endpoint for violation reports | `/csp-report` |
| `report-to` | Modern reporting endpoint | `csp-endpoint` |

**Nonce-Based CSP (Recommended):**

```php
<?php

declare(strict_types=1);

// SECURE: Nonce-based CSP for inline scripts
final class CspNonceGenerator
{
    private string $nonce;

    public function __construct()
    {
        // Generate a cryptographically random nonce per request
        $this->nonce = base64_encode(random_bytes(16));
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getHeader(): string
    {
        return sprintf(
            "default-src 'self'; "
            . "script-src 'self' 'nonce-%s'; "
            . "style-src 'self' 'nonce-%s'; "
            . "img-src 'self' data:; "
            . "font-src 'self'; "
            . "object-src 'none'; "
            . "frame-ancestors 'none'; "
            . "base-uri 'self'; "
            . "form-action 'self'",
            $this->nonce,
            $this->nonce,
        );
    }
}

// Usage in template:
// <script nonce="<?= htmlspecialchars($cspGenerator->getNonce(), ENT_QUOTES, 'UTF-8') ?>">
//     // Inline script allowed by nonce
// </script>
```

**Report-Only Mode (for testing):**

```php
<?php

declare(strict_types=1);

// SECURE: Deploy CSP in report-only mode first to identify violations without breaking the site
header("Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report");
```

**Reporting Endpoint Configuration (report-to):**

```php
<?php

declare(strict_types=1);

// SECURE: Modern reporting with report-to (replaces report-uri)
header('Report-To: {"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"https://example.com/csp-report"}]}');
header("Content-Security-Policy: default-src 'self'; report-to csp-endpoint");
```

---

### X-Content-Type-Options

Prevents the browser from MIME-sniffing a response away from the declared
`Content-Type`. Without this header, a browser may interpret a text file as
JavaScript if it contains script-like content.

```
X-Content-Type-Options: nosniff
```

This header has only one valid value: `nosniff`. Always set it.

```php
<?php

declare(strict_types=1);

// SECURE:
header('X-Content-Type-Options: nosniff');
```

---

### X-Frame-Options

Controls whether the page can be embedded in `<iframe>`, `<frame>`, `<embed>`, or
`<object>` elements. Prevents clickjacking attacks.

```
X-Frame-Options: DENY
```

| Value | Meaning |
|-------|---------|
| `DENY` | Page cannot be framed by any site |
| `SAMEORIGIN` | Page can only be framed by the same origin |

**Note:** `X-Frame-Options` is superseded by the CSP `frame-ancestors` directive,
which provides more granular control. However, `X-Frame-Options` should still be
set for browsers that do not fully support CSP Level 2.

```php
<?php

declare(strict_types=1);

// SECURE: Use both X-Frame-Options and CSP frame-ancestors for maximum compatibility
header('X-Frame-Options: DENY');
header("Content-Security-Policy: frame-ancestors 'none'");
```

---

### X-XSS-Protection -- DEPRECATED

```
X-XSS-Protection: 0
```

**This header is DEPRECATED and should be set to `0` (disabled).**

**Why it is dangerous to enable:**
- The `X-XSS-Protection: 1; mode=block` setting was removed from all modern
  browsers (Chrome 78+, Edge 78+, Firefox never supported it).
- In some edge cases, the XSS auditor itself could be exploited to *introduce*
  XSS vulnerabilities by selectively blocking parts of a page's legitimate scripts
  while leaving attacker-controlled content intact.
- Microsoft retired the XSS filter in Edge 17 after researchers demonstrated
  it could be weaponized.
- The correct mitigation for XSS is a strong Content-Security-Policy.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Enables the deprecated XSS auditor, which can itself introduce vulnerabilities
header('X-XSS-Protection: 1; mode=block');
```

```php
<?php

declare(strict_types=1);

// SECURE: Explicitly disable the deprecated XSS auditor
header('X-XSS-Protection: 0');
// Rely on Content-Security-Policy for XSS protection instead
```

---

### Referrer-Policy

Controls how much referrer information is included with requests. Prevents leaking
sensitive URL paths (session tokens, query parameters) to third-party sites.

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Value | Behavior |
|-------|----------|
| `no-referrer` | Never send referrer |
| `no-referrer-when-downgrade` | Drop referrer on HTTPS to HTTP (browser default) |
| `origin` | Send only the origin (no path) |
| `origin-when-cross-origin` | Full URL for same-origin, origin only for cross-origin |
| `same-origin` | Full URL for same-origin, nothing for cross-origin |
| `strict-origin` | Origin only, drop on downgrade |
| `strict-origin-when-cross-origin` | Full URL same-origin, origin cross-origin, nothing on downgrade |
| `unsafe-url` | Always send full URL (avoid) |

**Recommendation:** `strict-origin-when-cross-origin` balances functionality and privacy.
Use `no-referrer` for maximum privacy on sensitive pages.

```php
<?php

declare(strict_types=1);

// SECURE:
header('Referrer-Policy: strict-origin-when-cross-origin');
```

---

### Permissions-Policy (formerly Feature-Policy)

Controls which browser features and APIs the page can use. Restricts access to
sensitive device capabilities.

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
```

| Directive | Controls |
|-----------|----------|
| `camera=()` | Disables camera access |
| `microphone=()` | Disables microphone access |
| `geolocation=()` | Disables geolocation API |
| `payment=()` | Disables Payment Request API |
| `usb=()` | Disables WebUSB API |
| `interest-cohort=()` | Opts out of FLoC/Topics API (advertising) |
| `accelerometer=()` | Disables device motion sensors |
| `gyroscope=()` | Disables gyroscope |

The `()` (empty allowlist) means the feature is disabled entirely. Use `(self)` to
allow only the current origin.

```php
<?php

declare(strict_types=1);

// SECURE:
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
```

---

### Cross-Origin Headers (COOP, COEP, CORP)

These headers provide isolation between origins and are required for
`SharedArrayBuffer` and high-resolution timers (mitigating Spectre attacks).

**Cross-Origin-Opener-Policy (COOP):**

Controls the browsing context group. Isolates the window from cross-origin popups.

```
Cross-Origin-Opener-Policy: same-origin
```

| Value | Behavior |
|-------|----------|
| `unsafe-none` | Default, no isolation |
| `same-origin-allow-popups` | Isolate but allow popups to retain reference |
| `same-origin` | Full isolation from cross-origin windows |

**Cross-Origin-Embedder-Policy (COEP):**

Requires all cross-origin resources to explicitly grant permission via CORS or CORP.

```
Cross-Origin-Embedder-Policy: require-corp
```

| Value | Behavior |
|-------|----------|
| `unsafe-none` | Default, no restrictions |
| `require-corp` | All cross-origin resources must use CORS or CORP |
| `credentialless` | Cross-origin no-CORS requests are sent without credentials |

**Cross-Origin-Resource-Policy (CORP):**

Tells the browser who is allowed to load this resource (set on the resource response).

```
Cross-Origin-Resource-Policy: same-origin
```

| Value | Behavior |
|-------|----------|
| `same-site` | Only same-site origins can load this resource |
| `same-origin` | Only same-origin can load this resource |
| `cross-origin` | Any origin can load this resource |

```php
<?php

declare(strict_types=1);

// SECURE: Enable cross-origin isolation (required for SharedArrayBuffer)
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Embedder-Policy: require-corp');

// SECURE: Protect resources from cross-origin loading
header('Cross-Origin-Resource-Policy: same-origin');
```

**Note:** Enabling COOP + COEP together creates a cross-origin isolated context.
This can break third-party integrations (Google Maps, YouTube embeds, analytics)
that do not set CORP headers. Test thoroughly before deploying.

---

## Complete Middleware Implementation

```php
<?php

declare(strict_types=1);

// SECURE: Comprehensive security headers middleware
final class SecurityHeadersMiddleware
{
    public function __construct(
        private readonly CspNonceGenerator $cspNonce,
        private readonly bool $isProduction = true,
    ) {}

    public function __invoke(Request $request, callable $next): Response
    {
        $response = $next($request);

        // Transport security
        $response->headers->set(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains; preload',
        );

        // Content security
        $response->headers->set(
            'Content-Security-Policy',
            $this->cspNonce->getHeader(),
        );
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '0');

        // Privacy
        $response->headers->set(
            'Referrer-Policy',
            'strict-origin-when-cross-origin',
        );

        // Feature restrictions
        $response->headers->set(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
        );

        // Cross-origin isolation (enable only if needed and tested)
        // $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');
        // $response->headers->set('Cross-Origin-Embedder-Policy', 'require-corp');
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        return $response;
    }
}
```

---

## Framework-Specific Integration

### TYPO3

```typoscript
# TYPO3 TypoScript: Set security headers via config.additionalHeaders

config.additionalHeaders {
    10.header = Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    20.header = X-Content-Type-Options: nosniff
    30.header = X-Frame-Options: DENY
    40.header = X-XSS-Protection: 0
    50.header = Referrer-Policy: strict-origin-when-cross-origin
    60.header = Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
    70.header = Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
}
```

```php
<?php

declare(strict_types=1);

// TYPO3 PSR-15 Middleware for security headers (since TYPO3 v10)

namespace Vendor\MyExtension\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);

        return $response
            ->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('X-XSS-Protection', '0')
            ->withHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()')
            ->withHeader('Cross-Origin-Resource-Policy', 'same-origin');
    }
}

// Register in Configuration/RequestMiddlewares.php:
/*
return [
    'frontend' => [
        'vendor/my-extension/security-headers' => [
            'target' => \Vendor\MyExtension\Middleware\SecurityHeadersMiddleware::class,
            'before' => ['typo3/cms-frontend/output-compression'],
        ],
    ],
];
*/
```

### Symfony

```yaml
# config/packages/nelmio_security.yaml (NelmioSecurityBundle)
# https://github.com/nelmio/NelmioSecurityBundle

nelmio_security:
    content_type:
        nosniff: true

    clickjacking:
        paths:
            '^/.*': DENY

    csp:
        enabled: true
        hosts: []
        content_types: []
        enforce:
            default-src: ['self']
            script-src: ['self']
            style-src: ['self', 'unsafe-inline']
            img-src: ['self', 'data:']
            font-src: ['self']
            object-src: ['none']
            frame-ancestors: ['none']
            base-uri: ['self']
            form-action: ['self']

    referrer_policy:
        enabled: true
        policies:
            - strict-origin-when-cross-origin
```

```yaml
# Alternative: Symfony framework configuration (without NelmioSecurityBundle)
# config/packages/framework.yaml

framework:
    session:
        cookie_secure: true
        cookie_httponly: true
        cookie_samesite: lax
```

```php
<?php

declare(strict_types=1);

// Symfony EventSubscriber approach
namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();

        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '0');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
        );
    }
}
```

### Laravel

```php
<?php

declare(strict_types=1);

// Laravel Middleware

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '0');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
        );
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        return $response;
    }
}

// Register in bootstrap/app.php (Laravel 11+):
/*
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
})
*/

// Or in app/Http/Kernel.php (Laravel 10 and earlier):
/*
protected $middleware = [
    \App\Http\Middleware\SecurityHeaders::class,
];
*/
```

---

## Testing Security Headers

### Using curl

```bash
# Check all security headers on a URL
curl -s -D - https://example.com -o /dev/null | grep -iE \
  'strict-transport|content-security|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy|cross-origin'

# Check for missing headers (should produce no output if all are set)
for header in "strict-transport-security" "content-security-policy" "x-content-type-options" \
              "x-frame-options" "referrer-policy" "permissions-policy"; do
    if ! curl -s -D - https://example.com -o /dev/null 2>/dev/null | grep -qi "$header"; then
        echo "MISSING: $header"
    fi
done

# Verify X-XSS-Protection is set to 0 (not 1)
curl -s -D - https://example.com -o /dev/null | grep -i "x-xss-protection"
# Expected: X-XSS-Protection: 0
# BAD: X-XSS-Protection: 1; mode=block

# Check HSTS max-age is sufficiently long (at least 1 year = 31536000)
curl -s -D - https://example.com -o /dev/null | grep -i "strict-transport-security"
```

### PHPUnit Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class SecurityHeadersTest extends TestCase
{
    public function testAllSecurityHeadersPresent(): void
    {
        $response = $this->makeRequest('/');

        $requiredHeaders = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy',
            'Permissions-Policy',
        ];

        foreach ($requiredHeaders as $header) {
            self::assertTrue(
                $response->hasHeader($header),
                sprintf('Missing security header: %s', $header),
            );
        }
    }

    public function testHstsMaxAgeIsSufficient(): void
    {
        $response = $this->makeRequest('/');
        $hsts = $response->getHeader('Strict-Transport-Security');

        self::assertNotEmpty($hsts);
        self::assertMatchesRegularExpression('/max-age=\d{7,}/', $hsts[0]);
        self::assertStringContainsString('includeSubDomains', $hsts[0]);
    }

    public function testXssProtectionDisabled(): void
    {
        $response = $this->makeRequest('/');
        $xss = $response->getHeader('X-XSS-Protection');

        if (!empty($xss)) {
            self::assertSame('0', $xss[0], 'X-XSS-Protection must be 0 (disabled)');
        }
    }

    public function testFrameOptionsIsDeny(): void
    {
        $response = $this->makeRequest('/');
        $frameOptions = $response->getHeader('X-Frame-Options');

        self::assertNotEmpty($frameOptions);
        self::assertContains(
            strtoupper($frameOptions[0]),
            ['DENY', 'SAMEORIGIN'],
        );
    }

    public function testCspBlocksUnsafeInlineScripts(): void
    {
        $response = $this->makeRequest('/');
        $csp = $response->getHeader('Content-Security-Policy');

        self::assertNotEmpty($csp);
        // Verify script-src does not include 'unsafe-inline' (unless nonce-based)
        if (str_contains($csp[0], "'unsafe-inline'")) {
            self::assertStringContainsString(
                "'nonce-",
                $csp[0],
                "CSP allows 'unsafe-inline' without nonce fallback",
            );
        }
    }

    private function makeRequest(string $path): ResponseInterface
    {
        // Use your application's test client
        return $this->client->request('GET', $path);
    }
}
```

---

## Detection Patterns

### Static Analysis -- Finding Missing Headers

```bash
# Search for header() calls to verify correct values
grep -rn "header(" --include="*.php" src/ Classes/ | grep -iE "x-xss-protection|x-frame|strict-transport|content-security"

# Detect deprecated X-XSS-Protection: 1 (should be 0)
grep -rn "X-XSS-Protection.*1" --include="*.php" src/ Classes/
grep -rn "X-XSS-Protection.*mode=block" --include="*.php" src/ Classes/

# Detect overly permissive CSP
grep -rn "unsafe-inline" --include="*.php" src/ Classes/
grep -rn "unsafe-eval" --include="*.php" src/ Classes/
grep -rn "'\\*'" --include="*.php" src/ Classes/ | grep -i "content-security"

# Check for missing frame protection
grep -rn "X-Frame-Options" --include="*.php" src/ Classes/
grep -rn "frame-ancestors" --include="*.php" src/ Classes/

# TYPO3: Check TypoScript for headers
grep -rn "additionalHeaders" --include="*.typoscript" --include="*.ts" .
```

### Common Misconfigurations to Flag

```php
<?php

declare(strict_types=1);

// Patterns to detect during security audit

$misconfigurations = [
    // HSTS with max-age too low (less than 6 months)
    'hsts_weak' => '/max-age=\d{1,5}[^0-9]/',

    // CSP with wildcard or unsafe directives
    'csp_wildcard' => "/default-src\s+['\"]?\*/",
    'csp_unsafe_eval' => "/script-src[^;]*'unsafe-eval'/",
    'csp_unsafe_inline_without_nonce' => "/script-src[^;]*'unsafe-inline'(?!.*'nonce-)/",

    // Deprecated X-XSS-Protection enabled
    'xss_protection_enabled' => '/X-XSS-Protection:\s*1/',

    // ALLOW-FROM is not supported by modern browsers
    'frame_allow_from' => '/X-Frame-Options:\s*ALLOW-FROM/',

    // Referrer-Policy unsafe-url leaks full URLs
    'referrer_unsafe' => '/Referrer-Policy:\s*unsafe-url/',
];
```

---

## Header Checklist

| Header | Required Value | Severity if Missing |
|--------|---------------|---------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | High |
| `Content-Security-Policy` | Restrictive policy with no `unsafe-eval` | High |
| `X-Content-Type-Options` | `nosniff` | Medium |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Medium |
| `X-XSS-Protection` | `0` (disabled) | Low (info if set to 1) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Medium |
| `Permissions-Policy` | Deny unused features | Low |
| `Cross-Origin-Resource-Policy` | `same-origin` | Low |
| `Cross-Origin-Opener-Policy` | `same-origin` (if isolation needed) | Low |
| `Cross-Origin-Embedder-Policy` | `require-corp` (if isolation needed) | Low |

---

## Remediation Priority

| Severity | Finding | Timeline |
|----------|---------|----------|
| High | Missing HSTS header | Immediate |
| High | Missing or overly permissive CSP | 1 week |
| High | CSP allows `unsafe-eval` in script-src | 1 week |
| Medium | Missing X-Content-Type-Options | 48 hours |
| Medium | Missing X-Frame-Options and frame-ancestors | 48 hours |
| Medium | Referrer-Policy set to `unsafe-url` | 48 hours |
| Low | X-XSS-Protection set to `1; mode=block` instead of `0` | 1 week |
| Low | Missing Permissions-Policy | 2 weeks |
| Low | Missing cross-origin isolation headers | 2 weeks |

---

## Related References

- `owasp-top10.md` -- A05:2021 Security Misconfiguration
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Mozilla Observatory: https://observatory.mozilla.org
- SecurityHeaders.com: https://securityheaders.com
- MDN CSP Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- HSTS Preload List: https://hstspreload.org
