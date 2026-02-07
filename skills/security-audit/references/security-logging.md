# Security Logging and Monitoring Patterns

## Overview

Security logging and monitoring failures are covered by OWASP A09:2021 (Security
Logging and Monitoring Failures). Insufficient logging enables attackers to operate
undetected, escalate privileges, tamper with data, and exfiltrate information
without triggering alerts. Conversely, logging sensitive data creates a secondary
attack surface. This reference covers what to log, what not to log, log injection
prevention, structured logging with PSR-3, audit trail requirements, and
framework-specific integration.

---

## What to Log

Every security-relevant event must be logged with enough context to reconstruct
what happened, who did it, and when.

### Authentication Events

```php
<?php

declare(strict_types=1);

// SECURE: Log all authentication lifecycle events
final class AuthenticationLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function logSuccess(string $username, string $ipAddress): void
    {
        $this->logger->info('Authentication successful', [
            'event' => 'auth.login.success',
            'username' => $username,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logFailure(string $username, string $ipAddress, string $reason): void
    {
        $this->logger->warning('Authentication failed', [
            'event' => 'auth.login.failure',
            'username' => $username,
            'ip' => $ipAddress,
            'reason' => $reason,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logLockout(string $username, string $ipAddress, int $attempts): void
    {
        $this->logger->warning('Account locked due to excessive failures', [
            'event' => 'auth.lockout',
            'username' => $username,
            'ip' => $ipAddress,
            'attempts' => $attempts,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logLogout(string $username, string $ipAddress): void
    {
        $this->logger->info('User logged out', [
            'event' => 'auth.logout',
            'username' => $username,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logPasswordChange(string $username, string $ipAddress): void
    {
        $this->logger->info('Password changed', [
            'event' => 'auth.password_change',
            'username' => $username,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logMfaEnrolled(string $username): void
    {
        $this->logger->info('MFA enrolled', [
            'event' => 'auth.mfa.enrolled',
            'username' => $username,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logMfaFailure(string $username, string $ipAddress): void
    {
        $this->logger->warning('MFA verification failed', [
            'event' => 'auth.mfa.failure',
            'username' => $username,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }
}
```

### Authorization Failures

```php
<?php

declare(strict_types=1);

// SECURE: Log access denied events -- these may indicate privilege escalation attempts
final class AuthorizationLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function logAccessDenied(
        string $userId,
        string $resource,
        string $action,
        string $ipAddress,
    ): void {
        $this->logger->warning('Authorization denied', [
            'event' => 'authz.denied',
            'user_id' => $userId,
            'resource' => $resource,
            'action' => $action,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logPrivilegeEscalationAttempt(
        string $userId,
        string $requestedRole,
        string $ipAddress,
    ): void {
        $this->logger->critical('Possible privilege escalation attempt', [
            'event' => 'authz.privilege_escalation',
            'user_id' => $userId,
            'requested_role' => $requestedRole,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }
}
```

### Input Validation Failures

```php
<?php

declare(strict_types=1);

// SECURE: Log input validation failures -- repeated failures from the same source
// may indicate probing or attack attempts
final class InputValidationLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function logValidationFailure(
        string $field,
        string $reason,
        string $ipAddress,
        ?string $userId = null,
    ): void {
        $this->logger->notice('Input validation failure', [
            'event' => 'input.validation_failure',
            'field' => $field,
            'reason' => $reason,
            'ip' => $ipAddress,
            'user_id' => $userId,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    /**
     * Log suspected injection attempts (SQL, XSS, command injection patterns detected).
     */
    public function logSuspectedInjection(
        string $field,
        string $pattern,
        string $ipAddress,
        ?string $userId = null,
    ): void {
        $this->logger->warning('Suspected injection attempt', [
            'event' => 'input.injection_attempt',
            'field' => $field,
            'pattern_matched' => $pattern,
            'ip' => $ipAddress,
            'user_id' => $userId,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
            // NEVER log the actual malicious input -- it could execute in log viewers
        ]);
    }
}
```

### Application Errors and Exceptions

```php
<?php

declare(strict_types=1);

// SECURE: Log unhandled exceptions with context but without sensitive data
final class SecurityExceptionHandler
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function handle(\Throwable $exception, ?ServerRequestInterface $request = null): void
    {
        $context = [
            'event' => 'app.exception',
            'exception_class' => $exception::class,
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ];

        if ($request !== null) {
            $context['method'] = $request->getMethod();
            $context['uri'] = $request->getUri()->getPath(); // Path only, no query params
            $context['ip'] = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        }

        // Classify by exception type
        if ($exception instanceof SecurityException) {
            $this->logger->critical('Security exception', $context);
        } elseif ($exception instanceof AuthenticationException) {
            $this->logger->warning('Authentication exception', $context);
        } else {
            $this->logger->error('Unhandled exception', $context);
        }
    }
}
```

### Administrative Actions

```php
<?php

declare(strict_types=1);

// SECURE: Log administrative and privileged operations
final class AdminActionLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function logAction(
        string $adminId,
        string $action,
        string $targetResource,
        array $details,
        string $ipAddress,
    ): void {
        $this->logger->info('Administrative action', [
            'event' => 'admin.action',
            'admin_id' => $adminId,
            'action' => $action,
            'target' => $targetResource,
            'details' => $details,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logConfigChange(
        string $adminId,
        string $setting,
        string $oldValue,
        string $newValue,
        string $ipAddress,
    ): void {
        $this->logger->warning('Configuration changed', [
            'event' => 'admin.config_change',
            'admin_id' => $adminId,
            'setting' => $setting,
            'old_value' => $this->redactIfSensitive($setting, $oldValue),
            'new_value' => $this->redactIfSensitive($setting, $newValue),
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    private function redactIfSensitive(string $setting, string $value): string
    {
        $sensitivePatterns = ['password', 'secret', 'key', 'token', 'credential'];
        foreach ($sensitivePatterns as $pattern) {
            if (stripos($setting, $pattern) !== false) {
                return '[REDACTED]';
            }
        }
        return $value;
    }
}
```

### Data Access to Sensitive Resources

```php
<?php

declare(strict_types=1);

// SECURE: Log access to sensitive data for audit trail compliance
final class DataAccessLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function logSensitiveDataAccess(
        string $userId,
        string $dataType,
        string $recordId,
        string $action,
        string $ipAddress,
    ): void {
        $this->logger->info('Sensitive data access', [
            'event' => 'data.access',
            'user_id' => $userId,
            'data_type' => $dataType,    // e.g., 'personal_data', 'financial', 'medical'
            'record_id' => $recordId,
            'action' => $action,          // e.g., 'read', 'export', 'modify', 'delete'
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }

    public function logBulkExport(
        string $userId,
        string $dataType,
        int $recordCount,
        string $ipAddress,
    ): void {
        $this->logger->warning('Bulk data export', [
            'event' => 'data.bulk_export',
            'user_id' => $userId,
            'data_type' => $dataType,
            'record_count' => $recordCount,
            'ip' => $ipAddress,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
        ]);
    }
}
```

---

## What NOT to Log

Logging sensitive data creates a secondary attack surface. If an attacker gains
access to log files, they should not find passwords, tokens, or personally
identifiable information.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Logging passwords or credentials
$this->logger->info('Login attempt', [
    'username' => $username,
    'password' => $password, // NEVER log passwords
]);

// VULNERABLE - DO NOT USE
// Logging session tokens or API keys
$this->logger->info('API request', [
    'api_key' => $apiKey,    // NEVER log API keys
    'session_id' => session_id(), // NEVER log full session IDs
]);

// VULNERABLE - DO NOT USE
// Logging credit card numbers or PII
$this->logger->info('Payment processed', [
    'card_number' => $cardNumber, // NEVER log card numbers
    'ssn' => $socialSecurityNumber, // NEVER log SSNs
]);

// VULNERABLE - DO NOT USE
// Logging full request bodies that may contain sensitive form data
$this->logger->info('Request received', [
    'body' => file_get_contents('php://input'), // May contain passwords
]);
```

```php
<?php

declare(strict_types=1);

// SECURE: Redact or omit sensitive data from logs
final class LogSanitizer
{
    private const array SENSITIVE_FIELDS = [
        'password',
        'passwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'authorization',
        'cookie',
        'session_id',
        'credit_card',
        'card_number',
        'cvv',
        'ssn',
        'social_security',
    ];

    /**
     * Sanitize a context array before logging.
     */
    public static function sanitize(array $context): array
    {
        $sanitized = [];

        foreach ($context as $key => $value) {
            if (self::isSensitiveKey($key)) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = self::sanitize($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Mask a value, showing only the last 4 characters.
     */
    public static function mask(string $value): string
    {
        if (strlen($value) <= 4) {
            return '****';
        }
        return str_repeat('*', strlen($value) - 4) . substr($value, -4);
    }

    private static function isSensitiveKey(string $key): bool
    {
        $normalizedKey = strtolower($key);
        foreach (self::SENSITIVE_FIELDS as $sensitiveField) {
            if (str_contains($normalizedKey, $sensitiveField)) {
                return true;
            }
        }
        return false;
    }
}

// Usage:
// $this->logger->info('User action', LogSanitizer::sanitize($context));
```

---

## Log Injection Prevention

Log injection occurs when an attacker inserts crafted input that corrupts log
entries, injects false entries, or exploits log viewer vulnerabilities.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Unsanitized user input in log messages allows log injection
$username = $_POST['username']; // Could contain: "admin\n[2026-02-07] INFO: User admin logged in successfully"
$this->logger->info("Login attempt for user: $username");
// This creates a fake log entry that looks legitimate
```

```php
<?php

declare(strict_types=1);

// SECURE: Sanitize log messages to prevent injection
final class SecureLogger
{
    public function __construct(
        private readonly LoggerInterface $innerLogger,
    ) {}

    public function info(string $message, array $context = []): void
    {
        $this->innerLogger->info(
            $this->sanitizeMessage($message),
            $this->sanitizeContext($context),
        );
    }

    public function warning(string $message, array $context = []): void
    {
        $this->innerLogger->warning(
            $this->sanitizeMessage($message),
            $this->sanitizeContext($context),
        );
    }

    /**
     * Remove newlines and control characters from log messages.
     * This prevents attackers from injecting fake log entries.
     */
    private function sanitizeMessage(string $message): string
    {
        // Replace newlines, carriage returns, and other control characters
        return preg_replace('/[\x00-\x1F\x7F]/', ' ', $message) ?? $message;
    }

    /**
     * Sanitize context values to prevent injection via structured fields.
     */
    private function sanitizeContext(array $context): array
    {
        $sanitized = [];

        foreach ($context as $key => $value) {
            if (is_string($value)) {
                // Remove control characters and limit length
                $sanitized[$key] = mb_substr(
                    preg_replace('/[\x00-\x1F\x7F]/', ' ', $value) ?? $value,
                    0,
                    1024,
                );
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeContext($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }
}
```

---

## Structured Logging with PSR-3

Use PSR-3 `LoggerInterface` for all security logging. Structured logging with
context arrays (not string interpolation) makes logs machine-parseable and
queryable by SIEM systems.

```php
<?php

declare(strict_types=1);

use Psr\Log\LoggerInterface;

// VULNERABLE - DO NOT USE
// String concatenation prevents structured querying
$logger->warning("Auth failure for $username from $ip");

// VULNERABLE - DO NOT USE
// sprintf also prevents structured querying
$logger->warning(sprintf('Auth failure for %s from %s', $username, $ip));
```

```php
<?php

declare(strict_types=1);

use Psr\Log\LoggerInterface;

// SECURE: Use message template with context array
// PSR-3 placeholders use {key} syntax; context provides the values
$logger->warning('Authentication failure for {username}', [
    'event' => 'auth.login.failure',
    'username' => $username,
    'ip' => $ipAddress,
    'reason' => 'invalid_password',
    'timestamp' => (new \DateTimeImmutable())->format('c'),
]);
```

### Audit Trail Requirements

Every security log entry should answer five questions:

| Question | Field | Example |
|----------|-------|---------|
| **Who?** | `user_id`, `username`, `ip` | `user_id: 42`, `ip: 203.0.113.1` |
| **What?** | `event`, `action` | `event: auth.login.failure` |
| **When?** | `timestamp` | `2026-02-07T14:30:00+00:00` |
| **Where?** | `resource`, `uri`, `method` | `resource: /api/users/42` |
| **Outcome?** | `result`, `reason` | `result: denied`, `reason: insufficient_permissions` |

```php
<?php

declare(strict_types=1);

// SECURE: Complete audit trail entry
final class AuditTrail
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function record(
        string $who,
        string $what,
        string $where,
        string $outcome,
        array $additionalContext = [],
    ): void {
        $entry = array_merge($additionalContext, [
            'actor' => $who,
            'action' => $what,
            'resource' => $where,
            'outcome' => $outcome,
            'timestamp' => (new \DateTimeImmutable())->format('c'),
            'correlation_id' => $this->getCorrelationId(),
        ]);

        $this->logger->info('Audit trail entry', $entry);
    }

    /**
     * Correlation ID ties related log entries across a single request.
     */
    private function getCorrelationId(): string
    {
        static $correlationId = null;
        if ($correlationId === null) {
            $correlationId = bin2hex(random_bytes(8));
        }
        return $correlationId;
    }
}
```

---

## Framework-Specific Solutions

### TYPO3

```php
<?php

declare(strict_types=1);

// TYPO3 Logging API (since TYPO3 v9)
// TYPO3 uses a PSR-3-compatible logging framework with configurable writers and processors.

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\GeneralUtility;

// Method 1: LoggerAwareInterface (preferred in services)
final class MySecurityService implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function performSecurityCheck(): void
    {
        $this->logger->warning('Security check failed', [
            'event' => 'security.check.failure',
            'component' => 'my_extension',
        ]);
    }
}

// Method 2: LogManager (when DI is not available)
$logger = GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);
$logger->warning('Authentication failure', [
    'username' => $username,
    'ip' => $ipAddress,
]);

// TYPO3 sys_log table
// TYPO3 automatically logs backend user actions to the sys_log table.
// This includes:
// - Login/logout events
// - Record modifications (create, update, delete)
// - File operations
// - Error events

// Query sys_log for security audit:
// SELECT * FROM sys_log WHERE type = 255 ORDER BY tstamp DESC;
// type 255 = login events
// type 1 = DB operations (insert/update/delete)
// type 2 = file operations
// type 5 = system errors

// TYPO3 Logging Configuration (ext_localconf.php or system/settings.php):
/*
$GLOBALS['TYPO3_CONF_VARS']['LOG']['Vendor']['MyExtension'] = [
    'writerConfiguration' => [
        \Psr\Log\LogLevel::WARNING => [
            \TYPO3\CMS\Core\Log\Writer\FileWriter::class => [
                'logFile' => \TYPO3\CMS\Core\Core\Environment::getVarPath() . '/log/security.log',
            ],
            // Optional: Write to syslog for SIEM integration
            \TYPO3\CMS\Core\Log\Writer\SyslogWriter::class => [
                'facility' => LOG_AUTH,
            ],
        ],
    ],
    'processorConfiguration' => [
        \Psr\Log\LogLevel::WARNING => [
            \TYPO3\CMS\Core\Log\Processor\WebProcessor::class => [],
        ],
    ],
];
*/

// BackendUtility for checking user context
use TYPO3\CMS\Backend\Utility\BackendUtility;

// Log admin actions with full context
if ($GLOBALS['BE_USER'] instanceof \TYPO3\CMS\Core\Authentication\BackendUserAuthentication) {
    $logger->info('Admin action performed', [
        'event' => 'admin.action',
        'admin_user' => $GLOBALS['BE_USER']->user['username'],
        'admin_uid' => $GLOBALS['BE_USER']->user['uid'],
        'action' => 'record_modified',
        'table' => $table,
        'uid' => $uid,
    ]);
}
```

### Symfony

```yaml
# config/packages/monolog.yaml
# Symfony uses Monolog with channel-based routing

monolog:
    channels:
        - security
        - audit

    handlers:
        # Security events to dedicated file
        security:
            type: stream
            path: '%kernel.logs_dir%/security.log'
            level: warning
            channels: ['security']
            formatter: monolog.formatter.json

        # Audit trail to separate file with all levels
        audit:
            type: stream
            path: '%kernel.logs_dir%/audit.log'
            level: info
            channels: ['audit']
            formatter: monolog.formatter.json

        # Critical security events to syslog (for SIEM)
        syslog_security:
            type: syslog
            level: critical
            ident: myapp
            facility: auth
            channels: ['security']

        # All other logs
        main:
            type: stream
            path: '%kernel.logs_dir%/%kernel.environment%.log'
            level: debug
            channels: ['!security', '!audit']
```

```php
<?php

declare(strict_types=1);

// Symfony Security Event Subscriber
namespace App\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final class SecurityEventSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly LoggerInterface $securityLogger, // Auto-wired to 'security' channel
    ) {}

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();

        $this->securityLogger->info('Login successful', [
            'event' => 'auth.login.success',
            'username' => $user->getUserIdentifier(),
            'ip' => $request->getClientIp(),
        ]);
    }

    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();

        $this->securityLogger->warning('Login failed', [
            'event' => 'auth.login.failure',
            'username' => $request->getPayload()->getString('_username'),
            'ip' => $request->getClientIp(),
            'reason' => $event->getException()->getMessage(),
        ]);
    }

    public function onLogout(LogoutEvent $event): void
    {
        $token = $event->getToken();
        $request = $event->getRequest();

        if ($token !== null) {
            $this->securityLogger->info('User logged out', [
                'event' => 'auth.logout',
                'username' => $token->getUserIdentifier(),
                'ip' => $request->getClientIp(),
            ]);
        }
    }
}
```

### Laravel

```php
<?php

declare(strict_types=1);

// Laravel Event Listener for authentication events
namespace App\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Log;

final class AuthenticationEventLogger
{
    public function handleLogin(Login $event): void
    {
        Log::channel('security')->info('Login successful', [
            'event' => 'auth.login.success',
            'user_id' => $event->user->id,
            'ip' => request()->ip(),
        ]);
    }

    public function handleFailed(Failed $event): void
    {
        Log::channel('security')->warning('Login failed', [
            'event' => 'auth.login.failure',
            'username' => $event->credentials['email'] ?? 'unknown',
            'ip' => request()->ip(),
        ]);
    }

    public function handleLockout(Lockout $event): void
    {
        Log::channel('security')->warning('Account locked', [
            'event' => 'auth.lockout',
            'ip' => $event->request->ip(),
        ]);
    }

    public function handleLogout(Logout $event): void
    {
        Log::channel('security')->info('Logout', [
            'event' => 'auth.logout',
            'user_id' => $event->user?->id,
            'ip' => request()->ip(),
        ]);
    }
}

// Register in EventServiceProvider:
/*
protected $listen = [
    Login::class => [AuthenticationEventLogger::class . '@handleLogin'],
    Failed::class => [AuthenticationEventLogger::class . '@handleFailed'],
    Lockout::class => [AuthenticationEventLogger::class . '@handleLockout'],
    Logout::class => [AuthenticationEventLogger::class . '@handleLogout'],
];
*/

// config/logging.php -- add security channel:
/*
'channels' => [
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'info',
        'days' => 90,
        'formatter' => \Monolog\Formatter\JsonFormatter::class,
    ],
],
*/
```

---

## SIEM Integration Patterns

Security Information and Event Management (SIEM) systems aggregate logs from
multiple sources for correlation, alerting, and forensic analysis.

### JSON Log Format for SIEM

```php
<?php

declare(strict_types=1);

// SECURE: Structured JSON logging for SIEM consumption
// Most SIEM systems (Splunk, ELK, Datadog, Graylog) prefer JSON-formatted logs.

final class JsonSecurityFormatter
{
    public function format(string $level, string $message, array $context): string
    {
        $entry = [
            '@timestamp' => (new \DateTimeImmutable())->format('c'), // ISO 8601
            'level' => $level,
            'message' => $message,
            'application' => 'my-app',
            'environment' => getenv('APP_ENV') ?: 'production',
            'hostname' => gethostname(),
        ];

        // Merge context, ensuring no sensitive fields leak
        $entry = array_merge($entry, LogSanitizer::sanitize($context));

        return json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }
}
```

### Syslog Integration

```php
<?php

declare(strict_types=1);

// SECURE: Forward security events to syslog for SIEM consumption
final class SyslogSecurityWriter
{
    public function __construct()
    {
        openlog('myapp-security', LOG_PID | LOG_NDELAY, LOG_AUTH);
    }

    public function writeSecurityEvent(string $level, string $message, array $context): void
    {
        $priority = match ($level) {
            'emergency' => LOG_EMERG,
            'alert' => LOG_ALERT,
            'critical' => LOG_CRIT,
            'error' => LOG_ERR,
            'warning' => LOG_WARNING,
            'notice' => LOG_NOTICE,
            'info' => LOG_INFO,
            'debug' => LOG_DEBUG,
            default => LOG_INFO,
        };

        $json = json_encode(
            array_merge(['message' => $message], LogSanitizer::sanitize($context)),
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );

        syslog($priority, $json);
    }

    public function __destruct()
    {
        closelog();
    }
}
```

### Log Retention

```
Security logs must be retained according to compliance requirements:

| Regulation | Minimum Retention |
|------------|-------------------|
| PCI DSS    | 1 year (3 months immediately accessible) |
| GDPR       | As long as necessary (minimize) |
| SOX        | 7 years |
| HIPAA      | 6 years |
| SOC 2      | 1 year |
| General    | 90 days minimum recommended |
```

---

## Detection Patterns

Use these patterns during security audits to identify logging deficiencies.

### Missing Logging in Authentication Flows

```bash
# Check if authentication code has logging
# Look for auth-related files and verify they use a logger

# Find authentication-related files
grep -rln "password_verify\|authenticate\|login\|signIn" --include="*.php" src/ Classes/

# Check if those files use a logger
for file in $(grep -rln "password_verify\|authenticate\|login\|signIn" --include="*.php" src/ Classes/ 2>/dev/null); do
    if ! grep -q "logger\|Logger\|LoggerInterface\|->log(" "$file"; then
        echo "MISSING LOGGING: $file"
    fi
done
```

### Sensitive Data in Logs

```bash
# Detect potential password logging
grep -rn "password.*=>" --include="*.php" src/ Classes/ | grep -i "log\|logger"

# Detect potential token/key logging
grep -rn "token.*=>\|api_key.*=>\|secret.*=>" --include="*.php" src/ Classes/ | grep -i "log\|logger"

# Detect logging of raw request body (may contain sensitive data)
grep -rn "php://input\|getContent()\|getRawBody()" --include="*.php" src/ Classes/ | grep -i "log\|logger"
```

### Log Injection Vulnerabilities

```bash
# Detect string interpolation in log messages (should use context array)
grep -rn '->warning(".*\$\|->error(".*\$\|->info(".*\$\|->critical(".*\$' --include="*.php" src/ Classes/
grep -rn "->warning('.*\.\s*\$\|->error('.*\.\s*\$\|->info('.*\.\s*\$" --include="*.php" src/ Classes/

# Detect sprintf in log messages
grep -rn "->warning(sprintf\|->error(sprintf\|->info(sprintf" --include="*.php" src/ Classes/
```

### Missing Structured Logging

```bash
# Check if PSR-3 LoggerInterface is used
grep -rn "LoggerInterface\|LoggerAwareInterface\|LoggerAwareTrait" --include="*.php" src/ Classes/

# Check for error_log() usage (should use PSR-3 instead)
grep -rn "error_log(" --include="*.php" src/ Classes/

# Check for var_dump/print_r in production code (debug artifacts)
grep -rn "var_dump\|print_r\|var_export" --include="*.php" src/ Classes/
```

---

## Testing Patterns

### Verifying Security Events Are Logged

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use Psr\Log\Test\TestLogger; // From psr/log

final class AuthenticationLoggingTest extends TestCase
{
    public function testSuccessfulLoginIsLogged(): void
    {
        $logger = new TestLogger();
        $authLogger = new AuthenticationLogger($logger);

        $authLogger->logSuccess('testuser', '192.168.1.1');

        self::assertTrue($logger->hasInfoThatContains('Authentication successful'));
        self::assertTrue($logger->hasInfoRecords());

        $record = $logger->records[0];
        self::assertSame('auth.login.success', $record['context']['event']);
        self::assertSame('testuser', $record['context']['username']);
        self::assertArrayHasKey('timestamp', $record['context']);
    }

    public function testFailedLoginIsLogged(): void
    {
        $logger = new TestLogger();
        $authLogger = new AuthenticationLogger($logger);

        $authLogger->logFailure('testuser', '192.168.1.1', 'invalid_password');

        self::assertTrue($logger->hasWarningRecords());

        $record = $logger->records[0];
        self::assertSame('auth.login.failure', $record['context']['event']);
        self::assertSame('invalid_password', $record['context']['reason']);
    }

    public function testLockoutIsLogged(): void
    {
        $logger = new TestLogger();
        $authLogger = new AuthenticationLogger($logger);

        $authLogger->logLockout('testuser', '192.168.1.1', 5);

        self::assertTrue($logger->hasWarningRecords());

        $record = $logger->records[0];
        self::assertSame('auth.lockout', $record['context']['event']);
        self::assertSame(5, $record['context']['attempts']);
    }
}
```

### Verifying Sensitive Data Is Not Logged

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class LogSanitizationTest extends TestCase
{
    public function testPasswordIsRedacted(): void
    {
        $context = [
            'username' => 'testuser',
            'password' => 'secret123',
            'ip' => '192.168.1.1',
        ];

        $sanitized = LogSanitizer::sanitize($context);

        self::assertSame('testuser', $sanitized['username']);
        self::assertSame('[REDACTED]', $sanitized['password']);
        self::assertSame('192.168.1.1', $sanitized['ip']);
    }

    public function testNestedSensitiveFieldsAreRedacted(): void
    {
        $context = [
            'request' => [
                'headers' => [
                    'authorization' => 'Bearer abc123',
                    'content-type' => 'application/json',
                ],
            ],
        ];

        $sanitized = LogSanitizer::sanitize($context);

        self::assertSame('[REDACTED]', $sanitized['request']['headers']['authorization']);
        self::assertSame('application/json', $sanitized['request']['headers']['content-type']);
    }

    public function testApiKeyVariantsAreRedacted(): void
    {
        $variants = ['api_key', 'apiKey', 'API_KEY', 'apikey'];

        foreach ($variants as $key) {
            $sanitized = LogSanitizer::sanitize([$key => 'sk-abc123']);
            self::assertSame(
                '[REDACTED]',
                $sanitized[$key],
                sprintf('Field "%s" was not redacted', $key),
            );
        }
    }
}
```

### Verifying Log Injection Prevention

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class LogInjectionPreventionTest extends TestCase
{
    public function testNewlinesAreStrippedFromMessages(): void
    {
        $logger = new TestLogger();
        $secureLogger = new SecureLogger($logger);

        $maliciousInput = "admin\n[2026-02-07] INFO: Fake log entry injected";
        $secureLogger->info('Login attempt for {username}', [
            'username' => $maliciousInput,
        ]);

        $record = $logger->records[0];
        self::assertStringNotContainsString("\n", $record['context']['username']);
    }

    public function testControlCharactersAreRemoved(): void
    {
        $logger = new TestLogger();
        $secureLogger = new SecureLogger($logger);

        $maliciousInput = "test\x00\x01\x02\x1F\x7F";
        $secureLogger->info('Input received', ['value' => $maliciousInput]);

        $record = $logger->records[0];
        self::assertDoesNotMatchRegularExpression('/[\x00-\x1F\x7F]/', $record['context']['value']);
    }
}
```

---

## Remediation Priority

| Severity | Finding | Timeline |
|----------|---------|----------|
| Critical | No logging on authentication failures | Immediate |
| Critical | Passwords or tokens logged in plaintext | Immediate |
| High | No logging on authorization failures | 24 hours |
| High | Log injection via unsanitized user input | 48 hours |
| Medium | Using error_log() instead of PSR-3 | 1 week |
| Medium | No structured logging (string concatenation in messages) | 1 week |
| Medium | Missing audit trail for administrative actions | 1 week |
| Low | No SIEM integration for security events | 2 weeks |
| Low | Debug logging (var_dump, print_r) in production code | 1 week |
| Low | Missing correlation IDs across log entries | 2 weeks |

---

## Related References

- `owasp-top10.md` -- A09:2021 Security Logging and Monitoring Failures
- `authentication-patterns.md` -- Authentication events to log
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- PSR-3 Logger Interface: https://www.php-fig.org/psr/psr-3/
- OWASP AppSensor (attack detection): https://owasp.org/www-project-appsensor/
