# Framework Security Patterns (Cross-framework)

Patterns that recur across web frameworks (backend + frontend) — middleware / pipeline architecture, input validation, output encoding, and a comparison matrix. For framework-specific detail see the dedicated references:

- **PHP**: `typo3-security.md`, `typo3-fluid-security.md`, `typo3-typoscript-security.md`, `symfony-security.md`, `laravel-security.md`
- **Python**: `django-security.md`, `flask-security.md`, `fastapi-security.md`
- **JVM**: `spring-security.md`
- **.NET**: `dotnet-security.md`, `blazor-security.md`
- **JavaScript/TypeScript**: `express-security.md`, `nestjs-security.md`, `react-security.md`, `vue-security.md`, `angular-security.md`, `nextjs-security.md`, `nuxt-security.md`
- **Go**: `gin-security.md`
- **Ruby**: `rails-security.md`

## Cross-Framework Patterns

### Middleware Security Pattern

All three frameworks support middleware for cross-cutting security concerns.

```php
<?php
declare(strict_types=1);

// Generic PSR-15 middleware (works with any PSR-15 compatible framework)
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
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            ->withHeader('X-XSS-Protection', '0');  // Disabled, use CSP instead
    }
}

final class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly RateLimiterInterface $limiter,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $clientIp = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        $key = 'rate_limit:' . $clientIp;

        if (!$this->limiter->allow($key)) {
            return new JsonResponse(
                ['error' => 'Rate limit exceeded'],
                429,
                ['Retry-After' => '60'],
            );
        }

        return $handler->handle($request);
    }
}
```

### Input Validation Pattern

```php
<?php
declare(strict_types=1);

/**
 * Framework-agnostic input validation.
 * Validate early, validate strictly, reject by default.
 */
final class InputValidator
{
    /**
     * Validate and sanitize an email address.
     */
    public static function email(string $input): string
    {
        $email = filter_var(trim($input), FILTER_VALIDATE_EMAIL);

        if ($email === false) {
            throw new ValidationException('Invalid email address');
        }

        return $email;
    }

    /**
     * Validate a positive integer.
     */
    public static function positiveInt(mixed $input): int
    {
        $value = filter_var($input, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1],
        ]);

        if ($value === false) {
            throw new ValidationException('Invalid positive integer');
        }

        return $value;
    }

    /**
     * Validate a string against an allowlist of values.
     *
     * @param list<string> $allowed
     */
    public static function oneOf(string $input, array $allowed): string
    {
        if (!in_array($input, $allowed, true)) {
            throw new ValidationException(
                'Value must be one of: ' . implode(', ', $allowed)
            );
        }

        return $input;
    }

    /**
     * Validate a URL (scheme allowlist + no internal IPs).
     */
    public static function safeUrl(string $input): string
    {
        $url = filter_var($input, FILTER_VALIDATE_URL);

        if ($url === false) {
            throw new ValidationException('Invalid URL');
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new ValidationException('Only HTTP(S) URLs allowed');
        }

        $host = parse_url($url, PHP_URL_HOST);
        $ip = gethostbyname($host);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            throw new ValidationException('URL resolves to internal IP');
        }

        return $url;
    }

    /**
     * Strip HTML tags and limit length.
     */
    public static function plainText(string $input, int $maxLength = 1000): string
    {
        $cleaned = strip_tags(trim($input));

        if (mb_strlen($cleaned) > $maxLength) {
            throw new ValidationException("Text exceeds maximum length of {$maxLength}");
        }

        return $cleaned;
    }
}
```

### Output Encoding Pattern

```php
<?php
declare(strict_types=1);

/**
 * Context-aware output encoding.
 * The encoding method MUST match the output context.
 */
final class OutputEncoder
{
    /**
     * HTML body context: encode for safe insertion into HTML elements.
     */
    public static function html(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * HTML attribute context: encode for safe use in HTML attributes.
     */
    public static function attribute(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * JavaScript context: encode for safe embedding in <script> blocks.
     * Prefer using json_encode with safe flags.
     */
    public static function javascript(mixed $input): string
    {
        return json_encode(
            $input,
            JSON_THROW_ON_ERROR
            | JSON_HEX_TAG      // Encode < and >
            | JSON_HEX_APOS     // Encode single quotes
            | JSON_HEX_QUOT     // Encode double quotes
            | JSON_HEX_AMP      // Encode ampersands
            | JSON_UNESCAPED_UNICODE,
        );
    }

    /**
     * URL parameter context: encode for safe use in URL query parameters.
     */
    public static function url(string $input): string
    {
        return rawurlencode($input);
    }

    /**
     * CSS context: encode for safe use in CSS values.
     */
    public static function css(string $input): string
    {
        // Remove anything that is not alphanumeric, space, or safe CSS characters
        return preg_replace('/[^a-zA-Z0-9\s\-_.]/', '', $input) ?? '';
    }
}

// Framework template engine auto-encoding:
//
// TYPO3 Fluid:
//   {variable} is NOT auto-escaped in all contexts
//   Use: {variable -> f:format.htmlspecialchars()}
//   Or: <f:format.htmlspecialchars>{variable}</f:format.htmlspecialchars>
//   Raw output: {variable -> f:format.raw()} -- use only for trusted HTML
//
// Symfony Twig:
//   {{ variable }} is auto-escaped by default
//   Raw output: {{ variable|raw }} -- use only for trusted HTML
//   Custom encoding: {{ variable|e('js') }} for JavaScript context
//
// Laravel Blade:
//   {{ $variable }} is auto-escaped (htmlspecialchars)
//   Raw output: {!! $variable !!} -- use only for trusted HTML
//   JSON in Blade: @json($data) or {{ Js::from($data) }}
```

### Framework Comparison Matrix

| Security Feature | TYPO3 | Symfony | Laravel |
|-----------------|-------|---------|---------|
| SQL injection prevention | `createNamedParameter()` | Doctrine DQL / DBAL | Eloquent / Query Builder |
| CSRF protection | `FormProtectionFactory` | `csrf_token()` / forms | `@csrf` / middleware |
| Mass assignment | Trusted properties (HMAC) | Form types (field list) | `$fillable` / `$guarded` |
| XSS prevention | Fluid ViewHelpers | Twig auto-escape | Blade `{{ }}` auto-escape |
| Authentication | `BackendUserAuthentication` | Security bundle | Auth scaffolding / Sanctum |
| Authorization | Backend module access / custom | Voters / `is_granted()` | Gates / Policies |
| File upload security | FAL + `FileNameValidator` | File constraints + validators | File validation rules |
| Rate limiting | Custom (or middleware) | RateLimiter component | `RateLimiter` facade |
| Encryption | Sodium (manual) | Sodium / OpenSSL | `Crypt` facade (AES-256-CBC) |
| Session security | `$TYPO3_CONF_VARS` settings | `framework.session` config | `config/session.php` |
| Security headers | TypoScript `additionalHeaders` | Middleware / `NelmioSecurityBundle` | Middleware |
| Content Security Policy | CSP API (v12+) | `NelmioSecurityBundle` | `spatie/laravel-csp` |

## Remediation Priority

| Issue | Severity | Action | Timeline |
|-------|----------|--------|----------|
| SQL injection (raw queries) | Critical | Use parameterized queries / ORM | Immediate |
| Missing CSRF protection | High | Enable framework CSRF tokens | Immediate |
| Disabled mass assignment protection | High | Configure fillable/trusted properties | 24 hours |
| Missing authorization checks | High | Implement voters/policies/gates | 24 hours |
| XSS via raw output | High | Use auto-escaping templates | 48 hours |
| Missing security headers | Medium | Add security headers middleware | 1 week |
| Missing rate limiting | Medium | Configure rate limiter | 1 week |
| Weak session configuration | Medium | Harden session settings | 1 week |
| Missing file upload validation | Medium | Use framework file validators | 1 week |
| No Content Security Policy | Low | Implement CSP headers | 2 weeks |
