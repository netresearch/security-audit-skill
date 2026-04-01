# Error Message Sanitization

## Overview

Exception messages and error responses can leak sensitive information such as API
keys, internal paths, database credentials, and infrastructure details. This
reference covers sanitizing exception messages before they propagate, enforcing
consistent exception hierarchies in provider abstractions, and preventing raw
error details from reaching frontend responses.

Related CWEs:
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-210: Self-generated Error Message Containing Sensitive Information
- CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere

---

## API Keys in Exception Messages

HTTP client exceptions frequently include the full request URL in their message.
When API keys are passed as query parameters (e.g., Gemini API uses `?key=...`),
the key leaks into logs, error tracking systems, and potentially frontend
responses.

### Vulnerable Pattern

```php
// VULNERABLE: raw URL with API key leaks into exception message
try {
    $response = $this->httpClient->request('POST', $url . '?key=' . $apiKey, [
        'json' => $payload,
    ]);
} catch (TransportExceptionInterface $e) {
    // $e->getMessage() contains: "HTTP 401 returned for https://api.example.com/v1/generate?key=AIzaSy..."
    throw new ProviderConnectionException(
        'Failed to connect: ' . $e->getMessage(),
    );
}
```

### Safe Pattern

```php
// SAFE: sanitize before including in exception
try {
    $response = $this->httpClient->request('POST', $url . '?key=' . $apiKey, [
        'json' => $payload,
    ]);
} catch (TransportExceptionInterface $e) {
    throw new ProviderConnectionException(
        'Failed to connect: ' . $this->sanitizeErrorMessage($e->getMessage()),
    );
}
```

### sanitizeErrorMessage Implementation

```php
private function sanitizeErrorMessage(string $message): string
{
    return preg_replace(
        '/([?&](key|api_key|apikey|token|secret|access_token|client_secret|password|bearer)=)[^&\s]*/i',
        '$1[REDACTED]',
        $message,
    ) ?? $message;
}
```

### Detection Patterns

```bash
# Find exception messages that include raw exception messages from HTTP clients
grep -rE 'throw[[:space:]]+new[[:space:]].*Exception\(.*getMessage' Classes/
grep -rE 'catch.*Exception.*getMessage' Classes/

# Find HTTP URLs constructed with API keys as query parameters
grep -rE '\?(key|api_key|apikey|token|secret|access_token)=.*\$' Classes/
```

---

## Exception Type Consistency

All providers in an abstraction layer must use the same exception hierarchy. When
provider A throws `ProviderConnectionException` for a 429 but provider B throws
`RuntimeException`, consumers cannot handle errors consistently. This also
prevents sensitive details from leaking through unexpected exception types that
bypass sanitization middleware.

### Exception Hierarchy Pattern

```php
// Base exception for the provider abstraction
abstract class ProviderException extends \RuntimeException {}

// Auth/config errors (401, 402, 403, invalid API key)
class ProviderConfigurationException extends ProviderException {}

// Network/availability errors (429 rate limit, 503 service unavailable, timeouts)
class ProviderConnectionException extends ProviderException {}

// API errors (400 bad request, 422 unprocessable, 500 server error)
class ProviderResponseException extends ProviderException {}

// Feature not available for this provider
class UnsupportedFeatureException extends ProviderException {}
```

### Vulnerable Pattern

```php
// VULNERABLE: inconsistent exception types across providers

// Provider A
if ($statusCode === 401) {
    throw new \RuntimeException('Auth failed');  // Generic exception
}

// Provider B
if ($statusCode === 401) {
    throw new BadMethodCallException('Invalid key');  // Wrong exception type
}
```

### Safe Pattern

```php
// SAFE: consistent exception types across all providers

// Provider A
if ($statusCode === 401) {
    throw new ProviderConfigurationException('Authentication failed for provider A');
}

// Provider B
if ($statusCode === 401) {
    throw new ProviderConfigurationException('Authentication failed for provider B');
}
```

### HTTP Status Code Mapping

| Status Code | Exception Type | Rationale |
|-------------|----------------|-----------|
| 401 Unauthorized | `ProviderConfigurationException` | Invalid or expired credentials |
| 402 Payment Required | `ProviderConfigurationException` | Account/billing issue |
| 403 Forbidden | `ProviderConfigurationException` | Insufficient permissions |
| 429 Too Many Requests | `ProviderConnectionException` | Rate limiting, retry later |
| 500 Internal Server Error | `ProviderResponseException` | Provider-side failure |
| 502 Bad Gateway | `ProviderConnectionException` | Network/infrastructure issue |
| 503 Service Unavailable | `ProviderConnectionException` | Provider temporarily down |
| Timeout / DNS failure | `ProviderConnectionException` | Network issue |

### Detection Patterns

```
# Find generic exceptions in provider implementations
throw\s+new\s+\\?(RuntimeException|BadMethodCallException|LogicException|InvalidArgumentException|\\Exception)\s*\(
# In files matching: *Provider*.php, *Client*.php, *Connector*.php, *Adapter*.php

# Find inconsistent catch blocks
catch\s*\(\s*\\?(RuntimeException|\\Exception)\s+\$
# In consumer/orchestrator code that should catch provider-specific exceptions
```

---

## Error Messages Exposed to Frontend

Controller catch blocks must not pass raw `$e->getMessage()` to HTTP responses.
Exception messages may contain SQL queries, file paths, stack traces, API keys,
or internal service names. Log the full exception server-side and return a generic
message to the client.

### Vulnerable Pattern

```php
// VULNERABLE: raw exception message in API response
class ApiController
{
    public function createAction(Request $request): JsonResponse
    {
        try {
            $result = $this->service->process($request->getPayload());
            return new JsonResponse($result);
        } catch (\Throwable $e) {
            // Leaks: "SQLSTATE[42S02]: Table 'mydb.users' doesn't exist"
            // Leaks: "file_get_contents(/etc/passwd): failed to open stream"
            // Leaks: "Connection refused to redis-internal.prod:6379"
            return new JsonResponse(
                ['error' => $e->getMessage()],
                500,
            );
        }
    }
}
```

### Safe Pattern

```php
// SAFE: log full exception, return generic message
class ApiController
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function createAction(Request $request): JsonResponse
    {
        try {
            $result = $this->service->process($request->getPayload());
            return new JsonResponse($result);
        } catch (ValidationException $e) {
            // Validation errors are safe to show (they contain field names, not internals)
            return new JsonResponse(
                ['error' => 'Validation failed', 'details' => $e->getErrors()],
                422,
            );
        } catch (ProviderConfigurationException $e) {
            $this->logger->error('Provider configuration error', [
                'exception' => $e,
            ]);
            return new JsonResponse(
                ['error' => 'Service configuration error. Please contact support.'],
                503,
            );
        } catch (\Throwable $e) {
            $this->logger->error('Unexpected error in createAction', [
                'exception' => $e,
            ]);
            return new JsonResponse(
                ['error' => 'An internal error occurred.'],
                500,
            );
        }
    }
}
```

### TYPO3-Specific Pattern

```php
// TYPO3 Extbase controller
final class ItemController extends ActionController
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function showAction(int $uid): ResponseInterface
    {
        try {
            $item = $this->itemRepository->findByUid($uid);
        } catch (\Throwable $e) {
            $this->logger->error('Failed to load item', [
                'uid' => $uid,
                'exception' => $e,
            ]);

            // Forward to error action with generic message
            return $this->htmlResponse('The requested item could not be loaded.');
        }

        $this->view->assign('item', $item);
        return $this->htmlResponse();
    }
}
```

### Detection Patterns

```bash
# Find catch blocks that pass exception message to responses
grep -rlE 'getMessage' Classes/ | xargs grep -lE 'JsonResponse|HtmlResponse|echo|return'
grep -rE 'JsonResponse.*getMessage|getMessage.*JsonResponse' Classes/
grep -rE 'HtmlResponse.*getMessage|getMessage.*HtmlResponse' Classes/
grep -rE 'echo.*getMessage' Classes/

# Find raw exception in Symfony/TYPO3 response patterns
grep -rE 'new[[:space:]]+(Json|Html)Response\(.*getMessage' Classes/
```

---

## Best Practices Summary

| Area | Practice | Priority |
|------|----------|----------|
| HTTP client exceptions | Sanitize URLs in messages to redact API keys | Critical |
| Exception hierarchy | Use domain-specific exceptions, never generic | High |
| Frontend responses | Never expose `$e->getMessage()` to clients | Critical |
| Logging | Log full exception server-side with context | High |
| Provider abstraction | Consistent exception types across all providers | High |
| Validation errors | Safe to return field-level validation details | Medium |

## Remediation Priority

| Severity | Issue | Timeline |
|----------|-------|----------|
| Critical | API keys leaked in exception messages | Immediate |
| Critical | Raw `$e->getMessage()` in HTTP responses | Immediate |
| High | Inconsistent exception types across providers | 1 week |
| High | Missing server-side logging of caught exceptions | 1 week |
| Medium | Generic catch blocks without specific exception types | 2 weeks |

## Related References

- `security-logging.md` - What to log and what not to log
- `api-key-encryption.md` - Encrypting API keys at rest
- `owasp-top10.md` - A09:2021 Security Logging and Monitoring Failures
- `cwe-top25.md` - CWE-209 Error Message Information Exposure
