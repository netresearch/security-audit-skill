# Deserialization Prevention

## Understanding Deserialization Attacks

### Why `unserialize()` Is Dangerous

PHP's `unserialize()` instantiates objects from serialized data. An attacker who controls the serialized string can:

1. **Instantiate arbitrary classes** loaded in the application
2. **Trigger magic methods** (`__wakeup`, `__destruct`, `__toString`) on those objects
3. **Chain gadgets** across multiple classes to achieve remote code execution
4. **Read/write files**, execute commands, or exfiltrate data via destructor side effects

This is known as a **PHP Object Injection** vulnerability (CWE-502).

### Attack Vectors

```php
<?php
// Attacker-controlled serialized payload exploiting a gadget chain
// This creates an object whose __destruct() writes a PHP shell
$payload = 'O:14:"VulnerableClass":1:{s:4:"file";s:18:"/var/www/shell.php";}';

// If the application calls unserialize() on this, the attacker wins
$obj = unserialize($payload);  // __wakeup() fires immediately
// When $obj goes out of scope, __destruct() fires
```

### Gadget Chain Example

```php
<?php

declare(strict_types=1);

// A class that exists in the application (e.g., a logging utility)
class FileLogger
{
    public string $logFile = '/var/log/app.log';
    public string $buffer = '';

    public function __destruct()
    {
        // Writes buffered content to the log file on destruction
        if ($this->buffer !== '') {
            file_put_contents($this->logFile, $this->buffer, FILE_APPEND);
        }
    }
}

// Attacker crafts a serialized FileLogger with malicious properties:
// logFile = "/var/www/html/shell.php"
// buffer  = "<?php system($_GET['cmd']); ?>"
// When unserialize() creates this object and it goes out of scope,
// __destruct() writes a webshell to the document root.
```

### phar:// Deserialization Attacks

File operations on `phar://` URIs trigger deserialization of the phar's metadata without any call to `unserialize()`. This affects any function that accepts a file path:

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Any of these can trigger phar deserialization if $path is attacker-controlled:
file_exists($path);       // Triggers deserialization on phar://
file_get_contents($path); // Triggers deserialization on phar://
is_dir($path);            // Triggers deserialization on phar://
copy($path, $dest);       // Triggers deserialization on phar://
stat($path);              // Triggers deserialization on phar://
md5_file($path);          // Triggers deserialization on phar://
filemtime($path);         // Triggers deserialization on phar://

// The attacker uploads a valid phar archive with crafted metadata,
// then tricks the application into performing a file operation on:
// phar:///var/www/uploads/innocent.jpg
```

## Vulnerable Patterns

### Unserialize Without Allowed Classes

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// No restriction on which classes can be instantiated
$data = unserialize($_COOKIE['preferences']);

// VULNERABLE - DO NOT USE
// User-controlled data from database that was stored unsafely
$settings = unserialize($row['serialized_settings']);

// VULNERABLE - DO NOT USE
// Reading serialized data from cache without class restriction
$cached = unserialize(file_get_contents('/tmp/cache/session_data'));
```

### Unserialize in Session Handlers

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Custom session handler that uses unserialize without restrictions
final class CustomSessionHandler implements SessionHandlerInterface
{
    public function read(string $id): string|false
    {
        $data = file_get_contents("/tmp/sessions/$id");
        // Session data is deserialized by PHP's session mechanism
        // If session.serialize_handler is set to 'php_serialize',
        // an attacker who can inject into session files gets object injection
        return $data;
    }
}
```

## Secure Patterns

### Use `allowed_classes` Parameter (PHP 7.0+)

```php
<?php

declare(strict_types=1);

// SECURE: Deny all class instantiation - only scalar/array types allowed
$data = unserialize($serialized, ['allowed_classes' => false]);

// SECURE: Whitelist specific safe classes only
$data = unserialize($serialized, ['allowed_classes' => [
    \DateTimeImmutable::class,
    \stdClass::class,
]]);

// Any class not in the whitelist becomes __PHP_Incomplete_Class
// and cannot trigger magic methods
```

### Use JSON Instead (Preferred)

```php
<?php

declare(strict_types=1);

// SECURE: JSON cannot instantiate objects or trigger magic methods
final class SafeDataStorage
{
    /**
     * Store data safely as JSON
     */
    public function store(string $key, mixed $data): void
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        $this->cache->set($key, $json);
    }

    /**
     * Retrieve data safely from JSON
     */
    public function retrieve(string $key): mixed
    {
        $json = $this->cache->get($key);
        if ($json === null) {
            return null;
        }

        return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
}
```

### Secure Wrapper for Legacy Code

```php
<?php

declare(strict_types=1);

// SECURE: Wrapper that enforces allowed_classes restriction
final class SafeUnserializer
{
    /**
     * Unserialize data with no class instantiation allowed.
     * Only arrays, strings, integers, floats, booleans, and null are permitted.
     *
     * @throws \InvalidArgumentException if data cannot be unserialized
     */
    public static function unserialize(string $data): mixed
    {
        if ($data === '') {
            throw new \InvalidArgumentException('Empty serialized data');
        }

        // Reject any serialized data containing object markers
        // as an additional defense-in-depth measure
        if (preg_match('/(?:^|[;{])O:\d+:"/', $data)) {
            throw new \InvalidArgumentException('Serialized objects are not allowed');
        }

        $result = unserialize($data, ['allowed_classes' => false]);

        if ($result === false && $data !== 'b:0;') {
            throw new \InvalidArgumentException('Failed to unserialize data');
        }

        return $result;
    }

    /**
     * Unserialize with an explicit whitelist of permitted classes.
     *
     * @param list<class-string> $allowedClasses
     */
    public static function unserializeWithClasses(string $data, array $allowedClasses): mixed
    {
        if ($allowedClasses === []) {
            throw new \InvalidArgumentException(
                'Allowed classes list is empty; use unserialize() for scalar-only mode'
            );
        }

        $result = unserialize($data, ['allowed_classes' => $allowedClasses]);

        if ($result === false && $data !== 'b:0;') {
            throw new \InvalidArgumentException('Failed to unserialize data');
        }

        return $result;
    }
}
```

### Preventing phar:// Attacks

```php
<?php

declare(strict_types=1);

// SECURE: Validate and sanitize file paths to prevent phar:// deserialization
final class SafeFileAccess
{
    /**
     * Check if a path uses a dangerous stream wrapper
     */
    public static function isDangerousPath(string $path): bool
    {
        $dangerousWrappers = [
            'phar://',
            'compress.zlib://',
            'compress.bzip2://',
            'zip://',
            'rar://',
            'expect://',
            'data://',
            'php://input',
            'php://filter',
        ];

        $normalizedPath = strtolower(trim($path));

        foreach ($dangerousWrappers as $wrapper) {
            if (str_starts_with($normalizedPath, $wrapper)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Safely read a file, rejecting dangerous stream wrappers
     */
    public static function readFile(string $path): string
    {
        if (self::isDangerousPath($path)) {
            throw new \InvalidArgumentException('Dangerous stream wrapper detected');
        }

        $realPath = realpath($path);
        if ($realPath === false) {
            throw new \InvalidArgumentException('File does not exist: ' . $path);
        }

        $content = file_get_contents($realPath);
        if ($content === false) {
            throw new \RuntimeException('Could not read file: ' . $realPath);
        }

        return $content;
    }
}
```

## Framework-Specific Solutions

### TYPO3

```php
<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Utility\GeneralUtility;

// SECURE: GeneralUtility::makeInstance() is safe - it uses class name, not serialized data
$service = GeneralUtility::makeInstance(MyService::class);

// WARNING: Watch for serialized data in TYPO3 caching framework
// The database cache backend stores serialized data
// Always use the caching framework API, never raw unserialize on cache entries

// SECURE: Use TYPO3's caching framework (handles serialization internally)
use TYPO3\CMS\Core\Cache\CacheManager;

$cache = GeneralUtility::makeInstance(CacheManager::class)->getCache('my_cache');
$cache->set('key', $data);         // Framework handles serialization
$result = $cache->get('key');       // Framework handles deserialization safely

// VULNERABLE - DO NOT USE
// Never unserialize raw data from TYPO3 database tables
$row = $queryBuilder->select('serialized_config')
    ->from('tx_myext_config')
    ->executeQuery()
    ->fetchAssociative();
$config = unserialize($row['serialized_config']); // Dangerous!

// SECURE: Store configuration as JSON in TYPO3
$config = json_decode($row['json_config'], true, 512, JSON_THROW_ON_ERROR);

// SECURE: Use TYPO3's FlexForm XML for structured configuration
// FlexForms are parsed as XML, not unserialized
use TYPO3\CMS\Core\Service\FlexFormService;

$flexFormService = GeneralUtility::makeInstance(FlexFormService::class);
$settings = $flexFormService->convertFlexFormContentToArray($row['pi_flexform']);
```

### Symfony Serializer

```php
<?php

declare(strict_types=1);

use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\DateTimeNormalizer;

// SECURE: Symfony Serializer uses JSON by default and does not call unserialize()
$serializer = new Serializer(
    [new DateTimeNormalizer(), new ObjectNormalizer()],
    [new JsonEncoder()]
);

// Serialize to JSON (safe)
$json = $serializer->serialize($object, 'json');

// Deserialize from JSON into a specific class (safe - no arbitrary instantiation)
$object = $serializer->deserialize($json, UserDTO::class, 'json');

// The Serializer validates the target type, preventing arbitrary class instantiation
```

### Laravel

```php
<?php

declare(strict_types=1);

// SECURE: Laravel's Eloquent casts handle serialization safely
use Illuminate\Database\Eloquent\Model;

final class UserPreferences extends Model
{
    // Use 'array' or 'json' cast instead of serialized storage
    protected $casts = [
        'preferences' => 'array',    // Stored as JSON, decoded to array
        'settings' => 'json',        // Stored as JSON
        'metadata' => 'collection',  // Stored as JSON, cast to Collection
    ];

    // VULNERABLE - DO NOT USE
    // Never use 'object' cast with untrusted data as it uses unserialize()
    // protected $casts = ['data' => 'object'];  // Uses unserialize internally!
}

// SECURE: Use Laravel's encrypt/decrypt for sensitive serialized data
use Illuminate\Support\Facades\Crypt;

$encrypted = Crypt::encryptString(json_encode($sensitiveData));
$decrypted = json_decode(Crypt::decryptString($encrypted), true);
```

## Detection Patterns

### Static Analysis

```php
<?php

declare(strict_types=1);

// Grep patterns to detect vulnerable deserialization
$vulnerablePatterns = [
    // Direct unserialize without allowed_classes
    'unserialize(',

    // Functions vulnerable to phar:// deserialization
    'file_exists(',
    'file_get_contents(',
    'is_file(',
    'is_dir(',
    'is_link(',
    'copy(',
    'stat(',
    'fileatime(',
    'filectime(',
    'filemtime(',
    'filesize(',
    'md5_file(',
    'sha1_file(',
    'hash_file(',
];

// Search command: find unserialize calls without allowed_classes
// grep -rn "unserialize(" --include="*.php" | grep -v "allowed_classes"

// Search command: find unserialize with allowed_classes => true (insecure!)
// grep -rn "allowed_classes.*=>.*true" --include="*.php"
```

### PHPStan / Psalm Rules

```yaml
# phpstan.neon - custom rule to flag unserialize usage
rules:
    - SecurityAudit\Rules\DisallowUnserializeRule

# psalm.xml - taint analysis catches unserialize with tainted input
# Psalm's taint analysis will flag: unserialize($_GET['data'])
```

### Regex Detection Patterns

```php
<?php

declare(strict_types=1);

// Patterns for automated security scanning
$detectionPatterns = [
    // unserialize without second argument
    '/\bunserialize\s*\(\s*\$/' => 'CRITICAL: unserialize with variable input, check for allowed_classes',

    // unserialize with allowed_classes => true (same as no restriction)
    "/unserialize\s*\([^)]*['\"]allowed_classes['\"]\s*=>\s*true/" => 'CRITICAL: allowed_classes => true permits all classes',

    // phar:// in string literals or variables used with file functions
    '/phar:\/\//' => 'HIGH: phar:// wrapper usage detected, potential deserialization',

    // Serialized data in cookies or GET/POST
    '/unserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)/' => 'CRITICAL: unserialize on user input',

    // base64_decode -> unserialize chain
    '/unserialize\s*\(\s*base64_decode/' => 'HIGH: base64-encoded serialized data, likely untrusted input',
];
```

## Testing for Deserialization Vulnerabilities

### Unit Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class DeserializationPreventionTest extends TestCase
{
    public function testRejectsSerializedObjects(): void
    {
        $maliciousPayload = 'O:8:"stdClass":1:{s:4:"test";s:5:"value";}';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Serialized objects are not allowed');

        SafeUnserializer::unserialize($maliciousPayload);
    }

    public function testRejectsNestedSerializedObjects(): void
    {
        // Array containing a serialized object
        $payload = 'a:1:{s:3:"obj";O:8:"stdClass":0:{}}';

        // With allowed_classes => false, objects become __PHP_Incomplete_Class
        $result = unserialize($payload, ['allowed_classes' => false]);

        $this->assertIsArray($result);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result['obj']);
    }

    public function testAllowsScalarUnserialization(): void
    {
        $serializedArray = serialize(['key' => 'value', 'count' => 42]);

        $result = SafeUnserializer::unserialize($serializedArray);

        $this->assertSame(['key' => 'value', 'count' => 42], $result);
    }

    public function testAllowsWhitelistedClasses(): void
    {
        $serialized = serialize(new \DateTimeImmutable('2026-01-01'));

        $result = SafeUnserializer::unserializeWithClasses(
            $serialized,
            [\DateTimeImmutable::class]
        );

        $this->assertInstanceOf(\DateTimeImmutable::class, $result);
    }

    public function testRejectsNonWhitelistedClasses(): void
    {
        $serialized = serialize(new \SplStack());

        $result = SafeUnserializer::unserializeWithClasses(
            $serialized,
            [\DateTimeImmutable::class]
        );

        // Non-whitelisted class becomes __PHP_Incomplete_Class
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result);
    }

    public function testRejectsPharStreamWrapper(): void
    {
        $this->assertTrue(SafeFileAccess::isDangerousPath('phar:///tmp/evil.phar'));
        $this->assertTrue(SafeFileAccess::isDangerousPath('PHAR:///tmp/evil.phar'));
        $this->assertTrue(SafeFileAccess::isDangerousPath('phar:///var/www/uploads/image.jpg'));
        $this->assertFalse(SafeFileAccess::isDangerousPath('/var/www/uploads/image.jpg'));
        $this->assertFalse(SafeFileAccess::isDangerousPath('/tmp/data.json'));
    }

    public function testJsonAlternativeHandlesComplexData(): void
    {
        $data = [
            'users' => [
                ['name' => 'Alice', 'roles' => ['admin', 'editor']],
                ['name' => 'Bob', 'roles' => ['viewer']],
            ],
            'metadata' => ['version' => 2, 'created' => '2026-01-15'],
        ];

        $json = json_encode($data, JSON_THROW_ON_ERROR);
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame($data, $decoded);
    }

    public function testEmptyDataHandling(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SafeUnserializer::unserialize('');
    }

    public function testBooleanFalseSerialization(): void
    {
        // Edge case: serialize(false) === 'b:0;' and unserialize returns false
        $result = SafeUnserializer::unserialize('b:0;');
        $this->assertFalse($result);
    }
}
```

### Integration Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class DeserializationEndpointTest extends TestCase
{
    public function testApiRejectsSerializedPhpPayload(): void
    {
        $maliciousPayload = base64_encode('O:8:"stdClass":0:{}');

        $response = $this->client->request('POST', '/api/import', [
            'body' => json_encode(['data' => $maliciousPayload]),
            'headers' => ['Content-Type' => 'application/json'],
        ]);

        // API should accept JSON, never deserialize PHP serialized data
        $this->assertSame(200, $response->getStatusCode());

        // Verify the raw base64 string was stored, not unserialized
        $stored = $this->repository->findLatest();
        $this->assertIsString($stored->getData());
    }

    public function testSessionDataCannotContainObjects(): void
    {
        // Verify session handler does not instantiate objects from session data
        $session = $this->createSession();
        $session->set('preferences', ['theme' => 'dark']);
        $session->save();

        // Reload session
        $loaded = $this->loadSession($session->getId());
        $preferences = $loaded->get('preferences');

        $this->assertIsArray($preferences);
        $this->assertSame('dark', $preferences['theme']);
    }
}
```

## CVSS Scoring

```yaml
Vulnerability: PHP Object Injection via unserialize()
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Analysis:
  Attack Vector: Network (N)
    - Exploitable via HTTP request with crafted serialized payload
  Attack Complexity: Low (L)
    - Public gadget chains available for common frameworks
  Privileges Required: None (N)
    - Often exploitable without authentication (cookies, form data)
  User Interaction: None (N)
    - No user action needed
  Scope: Changed (C)
    - Can execute system commands, access other services
  Confidentiality: High (H)
    - Arbitrary file read, database access
  Integrity: High (H)
    - Arbitrary file write, code execution
  Availability: High (H)
    - Can delete files, crash application

Base Score: 10.0 (CRITICAL)
```

## Remediation Priority

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Replace all `unserialize()` on user-controlled input with `json_decode()` | Immediate |
| Critical | Add `allowed_classes => false` to any remaining `unserialize()` calls | Immediate |
| High | Validate and reject `phar://` stream wrappers on all file operations | 24 hours |
| High | Audit all classes with `__wakeup` / `__destruct` for gadget chain potential | 48 hours |
| Medium | Migrate serialized data storage to JSON format | 1 week |
| Medium | Add PHPStan / Psalm rules to flag unsafe deserialization | 1 week |
| Low | Add comprehensive test coverage for deserialization boundaries | 2 weeks |
