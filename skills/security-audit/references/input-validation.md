# Input Validation and Output Encoding

## filter_var() Gotchas

PHP's `filter_var()` functions are useful but have surprising behaviors that create security gaps.

### FILTER_VALIDATE_URL Allows javascript: URLs

`FILTER_VALIDATE_URL` checks structural validity but does not restrict schemes. This means `javascript:` URLs pass validation, enabling XSS when the URL is rendered in HTML.

```php
// VULNERABLE: javascript: URLs pass validation
$url = 'javascript:alert(document.cookie)';
var_dump(filter_var($url, FILTER_VALIDATE_URL)); // string(38) "javascript:alert(document.cookie)"

// Also passes: data: URLs
$url = 'data:text/html,<script>alert(1)</script>';
var_dump(filter_var($url, FILTER_VALIDATE_URL)); // string(42) "data:text/html,..."

// SECURE: Validate URL AND enforce scheme whitelist
function validateUrl(string $url): ?string
{
    $filtered = filter_var($url, FILTER_VALIDATE_URL);
    if ($filtered === false) {
        return null;
    }

    $scheme = parse_url($filtered, PHP_URL_SCHEME);
    if (!in_array(strtolower($scheme), ['http', 'https'], true)) {
        return null;
    }

    return $filtered;
}
```

### FILTER_VALIDATE_EMAIL Accepts Unusual Addresses

The filter follows RFC 5321/5322, accepting technically valid but uncommon formats that may not be appropriate for user-facing applications.

```php
// These all pass FILTER_VALIDATE_EMAIL:
filter_var('"spaces allowed"@example.com', FILTER_VALIDATE_EMAIL); // valid
filter_var('user+tag@example.com', FILTER_VALIDATE_EMAIL);         // valid
filter_var('user@[192.168.1.1]', FILTER_VALIDATE_EMAIL);           // valid (IP literal)

// SECURE: Combine filter_var with additional restrictions
function validateUserEmail(string $email): ?string
{
    $filtered = filter_var($email, FILTER_VALIDATE_EMAIL);
    if ($filtered === false) {
        return null;
    }

    // Reject IP literals in domain part
    if (preg_match('/@\[/', $filtered)) {
        return null;
    }

    // Reject quoted local parts
    if (str_starts_with($filtered, '"')) {
        return null;
    }

    // Optionally check DNS MX record
    $domain = substr(strrchr($filtered, '@'), 1);
    if (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A')) {
        return null;
    }

    return $filtered;
}
```

### FILTER_SANITIZE_STRING Removed in PHP 8.1

`FILTER_SANITIZE_STRING` (and its alias `FILTER_SANITIZE_STRIPPED`) was removed in PHP 8.1 because its behavior was confusing and often misused. It stripped HTML tags and optionally encoded quotes, but developers frequently assumed it provided complete XSS protection.

```php
// REMOVED in PHP 8.1 - triggers deprecation in 8.0, error in 8.1+
$clean = filter_var($input, FILTER_SANITIZE_STRING);

// REPLACEMENT: Use context-appropriate encoding instead
// For HTML output:
$clean = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// For stripping tags (if that is genuinely what you need):
$clean = strip_tags($input);

// For rich text: use HTML Purifier (see HTML Sanitization section below)
```

### Detection Patterns

```
# Find vulnerable filter_var usage
filter_var\(.*FILTER_VALIDATE_URL\)
filter_var\(.*FILTER_SANITIZE_STRING\)
filter_var\(.*FILTER_SANITIZE_STRIPPED\)

# Missing scheme validation after URL filter
filter_var\(.*FILTER_VALIDATE_URL.*(?!parse_url|str_starts_with.*https?)
```

## Content Security Policy (CSP) Nonce Implementation

CSP nonces allow inline scripts and styles while blocking injected code. Each request must generate a unique nonce.

### Generate Nonce Per Request

```php
<?php

declare(strict_types=1);

final class CspNonceGenerator
{
    private ?string $nonce = null;

    /**
     * Generate or retrieve the nonce for the current request.
     * The same nonce must be used in both the header and all inline script/style tags.
     */
    public function getNonce(): string
    {
        if ($this->nonce === null) {
            // 16 bytes = 128 bits of entropy, base64-encoded
            $this->nonce = base64_encode(random_bytes(16));
        }

        return $this->nonce;
    }

    /**
     * Build the CSP header value.
     */
    public function getCspHeader(): string
    {
        $nonce = $this->getNonce();

        return implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}'",
            "style-src 'self' 'nonce-{$nonce}'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);
    }
}
```

### Pass Nonce to Templates and Set Header

```php
// Middleware or controller
final class CspMiddleware
{
    public function __construct(
        private readonly CspNonceGenerator $cspNonce,
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $response = $next($request);

        $response->headers->set(
            'Content-Security-Policy',
            $this->cspNonce->getCspHeader()
        );

        return $response;
    }
}

// In Twig template:
// <script nonce="{{ csp_nonce }}">
//     // inline script here
// </script>

// In PHP template:
// <script nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
//     // inline script here
// </script>
```

### Common CSP Mistakes

```php
// VULNERABLE: Using 'unsafe-inline' defeats the purpose of CSP entirely
// Header: Content-Security-Policy: script-src 'self' 'unsafe-inline'

// VULNERABLE: Allowing dynamic code execution via eval-like functions
// Header: Content-Security-Policy: script-src 'self' 'unsafe-eval'

// VULNERABLE: Reusing the same nonce across requests
// A static nonce provides zero protection

// VULNERABLE: Wildcard sources
// Header: Content-Security-Policy: script-src *

// CORRECT: Strict nonce-based policy
// Header: Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'
```

### Detection Patterns

```
# Find missing CSP headers
Content-Security-Policy  (should exist in response headers)

# Find unsafe CSP directives
unsafe-inline
unsafe-eval
script-src\s+\*
default-src\s+\*

# Find inline scripts without nonce attributes
<script(?![^>]*\bnonce=)
<style(?![^>]*\bnonce=)
```

## CORS Configuration

Cross-Origin Resource Sharing must be configured carefully to prevent unauthorized cross-origin access.

### Proper Access-Control-Allow-Origin

```php
<?php

declare(strict_types=1);

final class CorsMiddleware
{
    /** @var list<string> */
    private const array ALLOWED_ORIGINS = [
        'https://app.example.com',
        'https://admin.example.com',
    ];

    public function process(Request $request, callable $next): Response
    {
        $origin = $request->headers->get('Origin', '');

        // Handle preflight requests
        if ($request->getMethod() === 'OPTIONS') {
            return $this->handlePreflight($origin);
        }

        $response = $next($request);

        if ($this->isAllowedOrigin($origin)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
            // Only set if cookies/auth headers are needed
            // $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }

        return $response;
    }

    private function handlePreflight(string $origin): Response
    {
        $response = new Response('', 204);

        if ($this->isAllowedOrigin($origin)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            $response->headers->set('Access-Control-Max-Age', '86400');
            $response->headers->set('Vary', 'Origin');
        }

        return $response;
    }

    private function isAllowedOrigin(string $origin): bool
    {
        return in_array($origin, self::ALLOWED_ORIGINS, true);
    }
}
```

### CORS Security Mistakes

```php
// VULNERABLE: Wildcard origin allows ANY site to read responses
// Access-Control-Allow-Origin: *

// VULNERABLE: Reflecting the Origin header without validation
$response->headers->set('Access-Control-Allow-Origin', $request->headers->get('Origin'));

// VULNERABLE: Wildcard with credentials (browser blocks this, but indicates misconfiguration)
// Access-Control-Allow-Origin: *
// Access-Control-Allow-Credentials: true

// VULNERABLE: Regex-based origin check with insufficient anchoring
if (preg_match('/example\.com/', $origin)) {  // matches attacker-example.com
    $response->headers->set('Access-Control-Allow-Origin', $origin);
}

// SECURE: Exact match against whitelist (see CorsMiddleware above)
```

### Credentialed Requests

When `Access-Control-Allow-Credentials: true` is set, the browser sends cookies and HTTP auth headers. This requires:

1. `Access-Control-Allow-Origin` must be a specific origin (not `*`)
2. `Access-Control-Allow-Headers` must be a specific list (not `*`)
3. `Access-Control-Allow-Methods` must be a specific list (not `*`)

```php
// For APIs that require cookies or Authorization headers
if ($this->isAllowedOrigin($origin)) {
    $response->headers->set('Access-Control-Allow-Origin', $origin);
    $response->headers->set('Access-Control-Allow-Credentials', 'true');
    $response->headers->set('Vary', 'Origin');
}
```

### Detection Patterns

```
# Find wildcard CORS
Access-Control-Allow-Origin.*\*
header\(.*Access-Control-Allow-Origin.*\*

# Find reflected origin without validation
\$_SERVER\['HTTP_ORIGIN'\]
\$request->headers->get\('Origin'\).*Access-Control-Allow-Origin

# Find missing Vary: Origin header (caching issue)
Access-Control-Allow-Origin(?!.*Vary.*Origin)
```

## JSON Encoding Safety

When embedding JSON in HTML or serving it via API, improper encoding can lead to XSS.

### Safe JSON Encoding Flags

```php
<?php

declare(strict_types=1);

// VULNERABLE: Default json_encode can produce strings that break out of HTML contexts
$data = ['message' => '<script>alert(1)</script>'];
echo '<script>var config = ' . json_encode($data) . ';</script>';
// The </script> can close the script tag early depending on context

// SECURE: Use hex encoding flags when embedding JSON in HTML
$safeJson = json_encode(
    $data,
    JSON_HEX_TAG       // Encodes < and > as \u003C and \u003E
    | JSON_HEX_APOS    // Encodes ' as \u0027
    | JSON_HEX_QUOT    // Encodes " as \u0022
    | JSON_HEX_AMP     // Encodes & as \u0026
    | JSON_THROW_ON_ERROR  // Throw on encoding errors instead of returning false
);
```

### json_validate() for Pre-Decode Validation (PHP 8.3+)

```php
// PHP 8.3+: Validate JSON structure without decoding
// Useful to reject malformed input before expensive decode operations
$input = file_get_contents('php://input');

if (!json_validate($input)) {
    throw new BadRequestException('Invalid JSON payload');
}

// Now safe to decode
$data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
```

### Reusable Safe JSON Encoder

```php
final class SafeJsonEncoder
{
    private const int HTML_SAFE_FLAGS =
        JSON_HEX_TAG
        | JSON_HEX_APOS
        | JSON_HEX_QUOT
        | JSON_HEX_AMP
        | JSON_THROW_ON_ERROR;

    private const int API_FLAGS =
        JSON_THROW_ON_ERROR
        | JSON_UNESCAPED_UNICODE
        | JSON_UNESCAPED_SLASHES;

    /**
     * Encode for embedding in HTML (script tags, data attributes).
     */
    public static function forHtml(mixed $data): string
    {
        return json_encode($data, self::HTML_SAFE_FLAGS);
    }

    /**
     * Encode for JSON API responses (Content-Type: application/json).
     */
    public static function forApi(mixed $data): string
    {
        return json_encode($data, self::API_FLAGS);
    }
}
```

### Detection Patterns

```
# Find json_encode without safety flags in HTML context
echo.*json_encode\((?!.*JSON_HEX_TAG)
print.*json_encode\((?!.*JSON_HEX_TAG)

# Find json_decode without JSON_THROW_ON_ERROR
json_decode\((?!.*JSON_THROW_ON_ERROR)

# Find json_encode without JSON_THROW_ON_ERROR
json_encode\((?!.*JSON_THROW_ON_ERROR)
```

## HTML Sanitization

### htmlspecialchars() with Proper Flags

`htmlspecialchars()` is the primary defense against XSS for plain text output in HTML contexts.

```php
// VULNERABLE: Missing flags, missing charset
echo htmlspecialchars($input);                    // Default ENT_QUOTES is PHP 8.1+
echo htmlspecialchars($input, ENT_COMPAT);        // Does NOT encode single quotes

// SECURE: Always specify ENT_QUOTES | ENT_HTML5 and UTF-8
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Helper function for consistent usage
function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
```

**Important:** Starting in PHP 8.1, `ENT_QUOTES` is the default flag. However, explicitly specifying flags ensures consistent behavior across PHP versions and communicates intent clearly.

### HTML Purifier for Rich Text

When you must accept HTML input (WYSIWYG editors, markdown rendering), use HTML Purifier to strip dangerous elements while preserving safe formatting.

```php
use HTMLPurifier;
use HTMLPurifier_Config;

final class RichTextSanitizer
{
    private readonly HTMLPurifier $purifier;

    public function __construct()
    {
        $config = HTMLPurifier_Config::createDefault();

        // Only allow safe formatting elements
        $config->set('HTML.Allowed', 'p,br,strong,em,ul,ol,li,a[href],blockquote,code,pre');

        // Remove javascript: and data: URIs
        $config->set('URI.AllowedSchemes', ['http' => true, 'https' => true, 'mailto' => true]);

        // Disable CSS (prevents CSS injection)
        $config->set('CSS.AllowedProperties', []);

        // Set cache directory
        $config->set('Cache.SerializerPath', sys_get_temp_dir() . '/htmlpurifier');

        $this->purifier = new HTMLPurifier($config);
    }

    public function sanitize(string $dirtyHtml): string
    {
        return $this->purifier->purify($dirtyHtml);
    }
}

// Usage
$sanitizer = new RichTextSanitizer();
$cleanHtml = $sanitizer->sanitize('<p>Hello <script>alert(1)</script> world</p>');
// Result: <p>Hello  world</p>
```

### Context-Specific Encoding

Different output contexts require different encoding strategies. Using the wrong encoding for a context provides no protection.

```php
final class OutputEncoder
{
    /**
     * HTML body context: <p>{output}</p>
     */
    public static function html(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * HTML attribute context: <div data-value="{output}">
     * Same as HTML encoding but also handles unquoted attributes.
     */
    public static function htmlAttribute(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * JavaScript string context: var x = '{output}';
     * Encode for embedding in a JS string literal.
     */
    public static function jsString(string $value): string
    {
        return json_encode(
            $value,
            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_THROW_ON_ERROR
        );
    }

    /**
     * URL parameter context: <a href="/page?q={output}">
     */
    public static function urlParam(string $value): string
    {
        return rawurlencode($value);
    }

    /**
     * CSS value context: <div style="width: {output}">
     * Only allow known-safe values. CSS injection is difficult to prevent by encoding alone.
     */
    public static function cssValue(string $value): string
    {
        // Whitelist approach: only allow alphanumeric, #, and specific units
        if (!preg_match('/^[a-zA-Z0-9#%.\-_ ]+$/', $value)) {
            return '';  // Reject anything suspicious
        }

        return $value;
    }
}
```

### Detection Patterns

```
# Find missing output encoding
echo \$_GET\[
echo \$_POST\[
echo \$_REQUEST\[
echo \$[a-zA-Z]+;(?!.*htmlspecialchars)

# Find htmlspecialchars without proper flags
htmlspecialchars\([^)]*\)(?!.*ENT_QUOTES)
htmlspecialchars\([^,]+\)$  # Single argument, missing flags

# Find raw variable interpolation in HTML
"<[^>]*\$[a-zA-Z]
'<[^>]*\$[a-zA-Z]
```

## TYPO3 Input Handling

### ServerRequestInterface

TYPO3 follows PSR-7 for request handling. Controllers receive `ServerRequestInterface` objects rather than accessing superglobals directly.

```php
<?php

declare(strict_types=1);

namespace Vendor\Extension\Controller;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Http\ResponseFactory;

final class SecureController
{
    public function __construct(
        private readonly ResponseFactory $responseFactory,
    ) {}

    public function handleAction(ServerRequestInterface $request): ResponseInterface
    {
        // SECURE: Access query parameters via PSR-7 (never $_GET)
        $queryParams = $request->getQueryParams();
        $page = (int)($queryParams['page'] ?? 1);

        // SECURE: Access parsed body (never $_POST)
        $body = $request->getParsedBody();
        $title = is_array($body) ? trim((string)($body['title'] ?? '')) : '';

        // SECURE: Access uploaded files via PSR-7 (never $_FILES)
        $uploadedFiles = $request->getUploadedFiles();

        // SECURE: Access attributes set by middleware/routing
        $site = $request->getAttribute('site');
        $language = $request->getAttribute('language');

        // Validate before use
        if ($page < 1 || $page > 1000) {
            $page = 1;
        }

        if (mb_strlen($title) > 255) {
            $title = mb_substr($title, 0, 255);
        }

        // Build response via ResponseFactory
        $response = $this->responseFactory->createResponse();
        $response->getBody()->write('OK');

        return $response;
    }
}
```

### TYPO3 Validators (Extbase)

```php
<?php

declare(strict_types=1);

namespace Vendor\Extension\Domain\Model;

use TYPO3\CMS\Extbase\Annotation as Extbase;
use TYPO3\CMS\Extbase\DomainObject\AbstractEntity;

class Contact extends AbstractEntity
{
    #[Extbase\Validate(['validator' => 'NotEmpty'])]
    #[Extbase\Validate(['validator' => 'StringLength', 'options' => ['minimum' => 2, 'maximum' => 100]])]
    protected string $name = '';

    #[Extbase\Validate(['validator' => 'NotEmpty'])]
    #[Extbase\Validate(['validator' => 'EmailAddress'])]
    protected string $email = '';

    #[Extbase\Validate(['validator' => 'NumberRange', 'options' => ['minimum' => 0, 'maximum' => 150]])]
    protected int $age = 0;
}
```

### Custom TYPO3 Validator

```php
<?php

declare(strict_types=1);

namespace Vendor\Extension\Validation\Validator;

use TYPO3\CMS\Extbase\Validation\Validator\AbstractValidator;

final class SafeHtmlValidator extends AbstractValidator
{
    protected function isValid(mixed $value): void
    {
        if (!is_string($value)) {
            $this->addError('Value must be a string.', 1700000001);
            return;
        }

        // Reject script tags, event handlers, and javascript: URIs
        $dangerousPatterns = [
            '/<script\b/i',
            '/\bon\w+\s*=/i',             // onclick=, onerror=, etc.
            '/javascript\s*:/i',
            '/data\s*:[^,]*;base64/i',    // data: URIs with base64
            '/<iframe\b/i',
            '/<object\b/i',
            '/<embed\b/i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                $this->addError(
                    'Value contains potentially dangerous HTML content.',
                    1700000002
                );
                return;
            }
        }
    }
}
```

### TYPO3 Fluid Output Encoding

```html
<!-- SECURE: Fluid escapes output by default -->
<p>{contact.name}</p>
<!-- Rendered: <p>&lt;script&gt;...</p> -->

<!-- VULNERABLE: f:format.raw disables escaping - use only with trusted/sanitized content -->
<f:format.raw>{userContent}</f:format.raw>

<!-- SECURE: Explicit encoding in attributes -->
<a href="{f:uri.action(action: 'show', arguments: '{id: item.uid}')}">View</a>

<!-- SECURE: Use f:format.htmlspecialchars for explicit encoding -->
<f:format.htmlspecialchars>{someValue}</f:format.htmlspecialchars>
```

## Symfony Validation Component

### Attribute-Based Validation

```php
<?php

declare(strict_types=1);

namespace App\Dto;

use Symfony\Component\Validator\Constraints as Assert;

final class UserRegistrationRequest
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Length(min: 2, max: 50)]
        #[Assert\Regex(
            pattern: '/^[a-zA-Z0-9_.-]+$/',
            message: 'Username may only contain letters, numbers, dots, dashes, and underscores.'
        )]
        public readonly string $username,

        #[Assert\NotBlank]
        #[Assert\Email(mode: Assert\Email::VALIDATION_MODE_STRICT)]
        public readonly string $email,

        #[Assert\NotBlank]
        #[Assert\Length(min: 12, max: 128)]
        #[Assert\NotCompromisedPassword]  // Checks against Have I Been Pwned
        #[Assert\PasswordStrength(minScore: Assert\PasswordStrength::STRENGTH_MEDIUM)]
        public readonly string $password,

        #[Assert\NotBlank]
        #[Assert\Url(protocols: ['http', 'https'])]
        public readonly ?string $website = null,

        #[Assert\Range(min: 13, max: 150)]
        public readonly ?int $age = null,
    ) {}
}
```

### Validation in Controller

```php
use Symfony\Component\Validator\Validator\ValidatorInterface;

final class RegistrationController
{
    public function __construct(
        private readonly ValidatorInterface $validator,
    ) {}

    public function register(Request $request): Response
    {
        $data = json_decode(
            $request->getContent(),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        $dto = new UserRegistrationRequest(
            username: (string)($data['username'] ?? ''),
            email: (string)($data['email'] ?? ''),
            password: (string)($data['password'] ?? ''),
            website: isset($data['website']) ? (string)$data['website'] : null,
            age: isset($data['age']) ? (int)$data['age'] : null,
        );

        $violations = $this->validator->validate($dto);

        if (count($violations) > 0) {
            $errors = [];
            foreach ($violations as $violation) {
                $errors[$violation->getPropertyPath()][] = $violation->getMessage();
            }

            return new JsonResponse(['errors' => $errors], 422);
        }

        // Process valid input
        return new JsonResponse(['status' => 'created'], 201);
    }
}
```

### Custom Validator Constraint

```php
<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

#[\Attribute(\Attribute::TARGET_PROPERTY)]
final class NoHtmlTags extends Constraint
{
    public string $message = 'The value "{{ value }}" must not contain HTML tags.';
}
```

```php
<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

final class NoHtmlTagsValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof NoHtmlTags) {
            throw new UnexpectedTypeException($constraint, NoHtmlTags::class);
        }

        if ($value === null || $value === '') {
            return;
        }

        if (!is_string($value)) {
            throw new UnexpectedTypeException($value, 'string');
        }

        if ($value !== strip_tags($value)) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ value }}', $this->formatValue($value))
                ->addViolation();
        }
    }
}
```

## Best Practices Summary

| Area | Practice | Priority |
|------|----------|----------|
| URL validation | Always validate scheme after `filter_var()` | Critical |
| CSP | Generate unique nonce per request with `random_bytes()` | High |
| CORS | Whitelist origins, never use `*` with credentials | Critical |
| JSON in HTML | Always use `JSON_HEX_TAG \| JSON_HEX_APOS \| JSON_HEX_QUOT \| JSON_HEX_AMP` | High |
| HTML output | Always use `htmlspecialchars()` with `ENT_QUOTES \| ENT_HTML5` | Critical |
| Rich text | Use HTML Purifier, never regex-based sanitization | High |
| Context encoding | Match encoding to output context (HTML, JS, URL, CSS) | Critical |
| Input access | Use PSR-7 `ServerRequestInterface`, never superglobals | High |
| Validation | Validate server-side even if client-side validation exists | Critical |
| Type casting | Cast to expected types early: `(int)`, `(string)`, `(bool)` | Medium |

## Remediation Priority

| Severity | Issue | Timeline |
|----------|-------|----------|
| Critical | Raw user input in HTML output (XSS) | Immediate |
| Critical | Wildcard CORS with credentials | Immediate |
| High | Missing CSP headers | 24 hours |
| High | `json_encode()` in HTML without hex flags | 48 hours |
| Medium | `FILTER_SANITIZE_STRING` usage (PHP 8.1 breakage) | 1 week |
| Medium | Missing context-specific encoding | 1 week |
| Low | Email validation without DNS check | 1 month |

## Related References

- `owasp-top10.md` - A03:2021 Injection, A07:2021 XSS
- `xxe-prevention.md` - XML-specific input handling
- `php-security-features.md` - Language features that improve input safety
