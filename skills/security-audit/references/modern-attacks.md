# Modern Attack Patterns

## SSRF (Server-Side Request Forgery) - Enhanced

### Overview

SSRF vulnerabilities allow attackers to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. In cloud environments, SSRF is particularly dangerous because it can access instance metadata services, internal APIs, and private network resources.

### Cloud Metadata Attacks

Cloud providers expose instance metadata at well-known IP addresses. An SSRF vulnerability can leak IAM credentials, API tokens, and configuration data.

```php
<?php
declare(strict_types=1);

// VULNERABLE: Fetches any URL the user provides
function fetchUrl(string $url): string
{
    return file_get_contents($url);
}

// Attacker payload examples:
// AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/
// AWS IMDSv2: requires token header but SSRF can chain requests
// GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
// Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
// Digital Ocean: http://169.254.169.254/metadata/v1/
```

**AWS IMDSv2 bypass**: IMDSv2 requires a PUT request to obtain a session token. If the SSRF allows control over HTTP method and headers, an attacker can still reach IMDSv2:

```php
<?php
declare(strict_types=1);

// VULNERABLE: Attacker can control method and headers via cURL options
function fetchWithOptions(string $url, string $method = 'GET', array $headers = []): string
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result ?: '';
}

// Attack chain for IMDSv2:
// Step 1: PUT http://169.254.169.254/latest/api/token with X-aws-ec2-metadata-token-ttl-seconds: 21600
// Step 2: GET http://169.254.169.254/latest/meta-data/ with X-aws-ec2-metadata-token: <token>
```

### DNS Rebinding Attacks

DNS rebinding bypasses IP-based SSRF protections by resolving a domain to a safe IP during validation, then to an internal IP during the actual request.

```php
<?php
declare(strict_types=1);

// VULNERABLE: DNS rebinding attack - TOCTOU between validation and request
function fetchUrlWithDnsCheck(string $url): string
{
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? '';

    // Check 1: Resolve DNS and validate IP (attacker's DNS returns public IP)
    $ip = gethostbyname($host);
    if (isInternalIp($ip)) {
        throw new \RuntimeException('Internal IP not allowed');
    }

    // Time passes... attacker's DNS TTL expires, now resolves to 169.254.169.254
    // Check 2: Actual request uses re-resolved DNS (now points to internal IP)
    return file_get_contents($url);  // Fetches internal resource
}

// SECURE: Pin the resolved IP and connect directly to it
function fetchUrlSafe(string $url): string
{
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? '';

    // Resolve DNS once
    $ip = gethostbyname($host);
    if (isInternalIp($ip)) {
        throw new \RuntimeException('Internal IP not allowed');
    }

    // Connect directly to the resolved IP, not the hostname
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);  // No redirects
    curl_setopt($ch, CURLOPT_RESOLVE, [$host . ':80:' . $ip, $host . ':443:' . $ip]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $result = curl_exec($ch);
    curl_close($ch);

    return $result ?: '';
}
```

### URL Validation Bypass Techniques

Attackers use various encoding techniques to bypass URL validation.

```php
<?php
declare(strict_types=1);

// Bypass techniques that a naive validator might miss:

// 1. Decimal IP encoding: http://2130706433 = http://127.0.0.1
// 2. Octal IP encoding: http://0177.0.0.1 = http://127.0.0.1
// 3. Hex IP encoding: http://0x7f000001 = http://127.0.0.1
// 4. IPv6 shorthand: http://[::1] = http://127.0.0.1
// 5. IPv6-mapped IPv4: http://[::ffff:127.0.0.1]
// 6. URL encoding: http://%31%32%37%2e%30%2e%30%2e%31
// 7. Redirects: http://attacker.com/redirect?to=http://169.254.169.254
// 8. DNS pointing to internal: attacker.com A record -> 127.0.0.1
// 9. URL fragment/auth: http://expected.com@attacker.com
// 10. Null bytes: http://expected.com%00.attacker.com

// VULNERABLE: Blocklist-based validation
function isAllowedUrlWeak(string $url): bool
{
    $host = parse_url($url, PHP_URL_HOST);
    $blocked = ['localhost', '127.0.0.1', '::1', '169.254.169.254'];
    return !in_array($host, $blocked, true);  // Bypassed by encoding tricks
}
```

### Safe URL Fetching with Allowlists

```php
<?php
declare(strict_types=1);

final class SafeUrlFetcher
{
    /** @var list<string> */
    private array $allowedHosts;

    /** @var list<string> */
    private array $allowedSchemes = ['https'];

    private int $maxRedirects = 0;

    private int $timeoutSeconds = 10;

    /**
     * @param list<string> $allowedHosts Explicitly allowed hostnames
     */
    public function __construct(array $allowedHosts)
    {
        $this->allowedHosts = $allowedHosts;
    }

    /**
     * Fetch a URL with strict validation.
     *
     * @throws \InvalidArgumentException If the URL fails validation
     * @throws \RuntimeException If the request fails
     */
    public function fetch(string $url): string
    {
        $this->validateUrl($url);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => $this->maxRedirects > 0,
            CURLOPT_MAXREDIRS => $this->maxRedirects,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,  // Only HTTPS
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($result === false) {
            throw new \RuntimeException('Request failed: ' . $error);
        }

        return $result;
    }

    private function validateUrl(string $url): void
    {
        $parsed = parse_url($url);

        if ($parsed === false || !isset($parsed['host'], $parsed['scheme'])) {
            throw new \InvalidArgumentException('Invalid URL');
        }

        // Allowlist scheme
        if (!in_array(strtolower($parsed['scheme']), $this->allowedSchemes, true)) {
            throw new \InvalidArgumentException('Scheme not allowed: ' . $parsed['scheme']);
        }

        // Allowlist host
        $host = strtolower($parsed['host']);
        if (!in_array($host, $this->allowedHosts, true)) {
            throw new \InvalidArgumentException('Host not allowed: ' . $host);
        }

        // Reject URL credentials (user:pass@host)
        if (isset($parsed['user']) || isset($parsed['pass'])) {
            throw new \InvalidArgumentException('URL credentials not allowed');
        }

        // Resolve DNS and verify not internal
        $ip = gethostbyname($host);
        if ($this->isInternalIp($ip)) {
            throw new \InvalidArgumentException('Resolved IP is internal');
        }
    }

    private function isInternalIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}
```

### Framework Patterns for SSRF Prevention

#### Symfony HttpClient

```php
<?php
declare(strict_types=1);

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;

// SECURE: Symfony's built-in protection against private network access
$client = HttpClient::create();
$safeClient = new NoPrivateNetworkHttpClient($client);

// This will throw TransportException if the resolved IP is private
$response = $safeClient->request('GET', $userProvidedUrl);
```

#### Laravel HTTP Client

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Http;

// SECURE: Validate before making request
final class WebhookService
{
    /** @var list<string> */
    private const array ALLOWED_HOSTS = ['api.example.com', 'hooks.slack.com'];

    public function sendWebhook(string $url, array $payload): void
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (!in_array($host, self::ALLOWED_HOSTS, true)) {
            throw new \InvalidArgumentException('Webhook host not allowed');
        }

        Http::timeout(10)
            ->withOptions(['allow_redirects' => false])
            ->post($url, $payload);
    }
}
```

#### TYPO3 Request Handling

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Http\RequestFactory;

// SECURE: Use TYPO3 RequestFactory with validated URLs
final class ExternalResourceFetcher
{
    public function __construct(
        private readonly RequestFactory $requestFactory,
    ) {}

    public function fetch(string $url): string
    {
        // Validate URL against allowlist before making request
        if (!$this->isAllowedUrl($url)) {
            throw new \InvalidArgumentException('URL not allowed');
        }

        $response = $this->requestFactory->request($url, 'GET', [
            'timeout' => 10,
            'allow_redirects' => false,
        ]);

        return $response->getBody()->getContents();
    }

    private function isAllowedUrl(string $url): bool
    {
        $parsed = parse_url($url);
        $host = strtolower($parsed['host'] ?? '');
        $scheme = strtolower($parsed['scheme'] ?? '');

        // Allowlist approach
        $allowedHosts = ['api.trusted-service.com'];
        return $scheme === 'https' && in_array($host, $allowedHosts, true);
    }
}
```

### Detection Patterns

```php
// Grep patterns for potential SSRF vulnerabilities:
$ssrfPatterns = [
    'file_get_contents(\$',        // Dynamic URL in file_get_contents
    'curl_setopt.*CURLOPT_URL',    // cURL with dynamic URL
    'fopen\(\$.*https?:',          // fopen with remote URL
    'new \SoapClient\(\$',         // SOAP with user-controlled WSDL
    'simplexml_load_file\(\$',     // XML loading from remote
    'readfile\(\$',                // readfile with dynamic path
    'copy\(\$.*,',                 // copy() with remote source
    'get_headers\(\$',             // get_headers with dynamic URL
    'gethostbyname\(\$',           // DNS resolution of user input
];
```

---

## Mass Assignment

### Overview

Mass assignment occurs when an application binds user-supplied input directly to object properties or database fields without filtering. An attacker can set fields they should not have access to, such as `is_admin`, `role`, or `price`.

### PHP Array Merge / Hydration Dangers

```php
<?php
declare(strict_types=1);

// VULNERABLE: Direct property assignment from request data
final class User
{
    public string $name = '';
    public string $email = '';
    public string $role = 'user';        // Should not be user-settable
    public bool $isAdmin = false;         // Should not be user-settable
    public float $accountBalance = 0.0;   // Should not be user-settable
}

// Attacker sends: {"name":"Evil","email":"x@x.com","isAdmin":true,"role":"admin"}
function createUser(array $data): User
{
    $user = new User();
    foreach ($data as $key => $value) {
        if (property_exists($user, $key)) {
            $user->$key = $value;  // Mass assignment vulnerability
        }
    }
    return $user;
}

// VULNERABLE: array_merge overwrites defaults with attacker-controlled values
$defaults = ['role' => 'user', 'isAdmin' => false];
$userData = array_merge($defaults, $_POST);  // POST data overrides role/isAdmin

// SECURE: Explicit field allowlist
function createUserSafe(array $data): User
{
    $user = new User();
    $allowed = ['name', 'email'];  // Only these fields from user input

    foreach ($allowed as $field) {
        if (isset($data[$field])) {
            $user->$field = $data[$field];
        }
    }

    return $user;
}
```

### Laravel: Fillable and Guarded

```php
<?php
declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;

// VULNERABLE: No mass assignment protection
class UserUnsafe extends Model
{
    protected $guarded = [];  // Everything is fillable - dangerous
}

// SECURE: Explicit fillable fields (allowlist approach, recommended)
class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
    // role, is_admin, etc. are NOT fillable and cannot be mass-assigned
}

// SECURE: Guarded fields (blocklist approach, less safe but valid)
class UserGuarded extends Model
{
    protected $guarded = ['id', 'is_admin', 'role'];
    // All other fields are fillable
}

// SECURE: Using validated data only
final class UserController
{
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:8',
        ]);

        // Only validated fields are passed - no mass assignment risk
        $user = User::create($validated);

        return response()->json($user, 201);
    }
}
```

### Symfony: Form Handling with Allowed Fields

```php
<?php
declare(strict_types=1);

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;

// SECURE: Symfony forms define exactly which fields are accepted
class UserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class)
            ->add('email', EmailType::class);
        // Fields not added here (role, isAdmin) cannot be submitted
    }
}

// SECURE: Handle form submission
final class UserController
{
    public function create(Request $request): Response
    {
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // Only name and email can be set via the form
            $this->entityManager->persist($user);
            $this->entityManager->flush();
        }

        return $this->render('user/create.html.twig', ['form' => $form]);
    }
}
```

### TYPO3: Trusted Properties

TYPO3 Extbase uses an HMAC-signed list of trusted properties to prevent mass assignment.

```php
<?php
declare(strict_types=1);

// TYPO3 Fluid template generates a hidden __trustedProperties field
// containing an HMAC-signed list of allowed form fields.
// The HMAC is verified server-side before property mapping.

// In Fluid template:
// <f:form action="create" object="{user}">
//   <f:form.textfield property="name" />
//   <f:form.textfield property="email" />
//   <!-- __trustedProperties hidden field is auto-generated with HMAC -->
// </f:form>

// VULNERABLE: Disabling trusted properties validation
// In controller, do NOT do this:
// $this->arguments['user']->getPropertyMappingConfiguration()
//     ->allowAllProperties()         // Disables protection
//     ->skipProperties()             // Skips validation
//     ->setTypeConverterOption(...)   // Can weaken type safety

// SECURE: Only allow specific properties when dynamic mapping is needed
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Property\TypeConverter\PersistentObjectConverter;

final class UserController extends ActionController
{
    public function initializeCreateAction(): void
    {
        $propertyMapping = $this->arguments['user']->getPropertyMappingConfiguration();

        // Only explicitly allow the fields you expect
        $propertyMapping->allowProperties('name', 'email');

        // Explicitly deny sensitive fields
        $propertyMapping->skipProperties('role', 'isAdmin', 'deleted');
    }

    public function createAction(User $user): void
    {
        // Only name and email can be set from form data
        $this->userRepository->add($user);
    }
}
```

### Detection Patterns

```php
// Grep patterns for potential mass assignment vulnerabilities:
$massAssignmentPatterns = [
    'protected \$guarded = \[\]',          // Laravel: empty guarded (everything fillable)
    '->allowAllProperties()',               // TYPO3: disabling trusted properties
    'array_merge.*\$_POST',                 // Direct merge with POST data
    'array_merge.*\$_REQUEST',              // Direct merge with REQUEST data
    'foreach.*\$_POST.*property_exists',    // Loop assignment from POST
    'extract\(\$',                          // extract() creates variables from array
    '->fill\(\$request->all\(\)\)',         // Laravel: filling with all request data
    'fromArray\(\$_',                       // Custom hydration from superglobals
];
```

---

## Race Conditions

### Overview

Race conditions occur when the behavior of a system depends on the sequence or timing of uncontrollable events. In web applications, race conditions can lead to duplicate transactions, inventory overselling, privilege escalation, and file system corruption.

### TOCTOU (Time of Check to Time of Use)

```php
<?php
declare(strict_types=1);

// VULNERABLE: Time gap between checking balance and deducting
final class WalletServiceUnsafe
{
    public function withdraw(int $userId, float $amount): void
    {
        $balance = $this->getBalance($userId);  // CHECK

        // Another request might withdraw between check and update
        if ($balance < $amount) {
            throw new InsufficientFundsException();
        }

        // TIME GAP: balance could have changed
        $this->updateBalance($userId, $balance - $amount);  // USE
    }
}

// SECURE: Atomic operation with database-level check
final class WalletServiceSafe
{
    public function withdraw(int $userId, float $amount, \PDO $pdo): void
    {
        $pdo->beginTransaction();

        try {
            // Atomic update with condition - single SQL statement
            $stmt = $pdo->prepare(
                'UPDATE wallets SET balance = balance - :amount
                 WHERE user_id = :userId AND balance >= :amount'
            );
            $stmt->execute(['amount' => $amount, 'userId' => $userId]);

            if ($stmt->rowCount() === 0) {
                throw new InsufficientFundsException();
            }

            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }
}
```

### Database Race Conditions with SELECT FOR UPDATE

```php
<?php
declare(strict_types=1);

// VULNERABLE: Read-then-write without locking
final class InventoryServiceUnsafe
{
    public function reserveItem(int $productId, int $quantity, \PDO $pdo): void
    {
        $stmt = $pdo->prepare('SELECT stock FROM products WHERE id = ?');
        $stmt->execute([$productId]);
        $stock = (int) $stmt->fetchColumn();

        // Concurrent request could read same stock value
        if ($stock < $quantity) {
            throw new OutOfStockException();
        }

        $pdo->prepare('UPDATE products SET stock = stock - ? WHERE id = ?')
            ->execute([$quantity, $productId]);
    }
}

// SECURE: Pessimistic locking with SELECT FOR UPDATE
final class InventoryServiceSafe
{
    public function reserveItem(int $productId, int $quantity, \PDO $pdo): void
    {
        $pdo->beginTransaction();

        try {
            // FOR UPDATE acquires a row-level exclusive lock
            $stmt = $pdo->prepare(
                'SELECT stock FROM products WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$productId]);
            $stock = (int) $stmt->fetchColumn();

            if ($stock < $quantity) {
                $pdo->rollBack();
                throw new OutOfStockException();
            }

            $pdo->prepare('UPDATE products SET stock = stock - ? WHERE id = ?')
                ->execute([$quantity, $productId]);

            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}

// SECURE: Optimistic locking with version column
final class InventoryServiceOptimistic
{
    public function reserveItem(int $productId, int $quantity, \PDO $pdo): void
    {
        $maxRetries = 3;

        for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
            $stmt = $pdo->prepare(
                'SELECT stock, version FROM products WHERE id = ?'
            );
            $stmt->execute([$productId]);
            $row = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ((int) $row['stock'] < $quantity) {
                throw new OutOfStockException();
            }

            // Update only if version has not changed (no concurrent modification)
            $update = $pdo->prepare(
                'UPDATE products SET stock = stock - ?, version = version + 1
                 WHERE id = ? AND version = ?'
            );
            $update->execute([$quantity, $productId, $row['version']]);

            if ($update->rowCount() > 0) {
                return;  // Success
            }

            // Version mismatch - retry with fresh data
            usleep(random_int(1000, 10000));
        }

        throw new ConcurrencyException('Too many concurrent modifications');
    }
}
```

### Doctrine ORM Locking

```php
<?php
declare(strict_types=1);

use Doctrine\DBAL\LockMode;
use Doctrine\ORM\Mapping as ORM;

// Pessimistic locking with Doctrine
#[ORM\Entity]
class Product
{
    #[ORM\Id, ORM\GeneratedValue, ORM\Column]
    private int $id;

    #[ORM\Column]
    private int $stock;

    #[ORM\Version, ORM\Column]
    private int $version;  // For optimistic locking
}

final class ProductService
{
    public function reserveStock(int $productId, int $quantity): void
    {
        $this->entityManager->beginTransaction();

        try {
            // PESSIMISTIC_WRITE = SELECT ... FOR UPDATE
            $product = $this->entityManager->find(
                Product::class,
                $productId,
                LockMode::PESSIMISTIC_WRITE
            );

            if ($product->getStock() < $quantity) {
                throw new OutOfStockException();
            }

            $product->decreaseStock($quantity);
            $this->entityManager->flush();
            $this->entityManager->commit();
        } catch (\Throwable $e) {
            $this->entityManager->rollBack();
            throw $e;
        }
    }
}
```

### File System Race Conditions

```php
<?php
declare(strict_types=1);

// VULNERABLE: TOCTOU in file operations
function writeIfNotExists(string $path, string $content): void
{
    if (!file_exists($path)) {   // CHECK
        // Another process could create the file here
        file_put_contents($path, $content);  // USE - may overwrite
    }
}

// SECURE: Atomic file creation with exclusive lock
function writeIfNotExistsSafe(string $path, string $content): bool
{
    // O_EXCL flag: fail if file already exists (atomic check-and-create)
    $fp = @fopen($path, 'x');
    if ($fp === false) {
        return false;  // File already exists
    }

    fwrite($fp, $content);
    fclose($fp);
    return true;
}

// SECURE: File locking for concurrent access
function updateFileWithLock(string $path, callable $transform): void
{
    $fp = fopen($path, 'c+');
    if ($fp === false) {
        throw new \RuntimeException('Cannot open file: ' . $path);
    }

    try {
        // LOCK_EX: Exclusive lock - blocks other writers and readers
        if (!flock($fp, LOCK_EX)) {
            throw new \RuntimeException('Cannot acquire lock');
        }

        $content = stream_get_contents($fp);
        $newContent = $transform($content);

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $newContent);
        fflush($fp);

        // Lock released on close, but explicit unlock is clearer
        flock($fp, LOCK_UN);
    } finally {
        fclose($fp);
    }
}
```

### PHP Mutex / Flock Patterns

```php
<?php
declare(strict_types=1);

/**
 * File-based mutex for PHP processes.
 * Suitable for single-server deployments.
 */
final class FileMutex
{
    /** @var resource|false */
    private $lockHandle = false;

    public function __construct(
        private readonly string $lockDir = '/tmp',
    ) {}

    /**
     * Acquire a named lock.
     *
     * @param string $name Lock identifier
     * @param int $timeoutSeconds Maximum time to wait for lock
     * @return bool True if lock was acquired
     */
    public function acquire(string $name, int $timeoutSeconds = 10): bool
    {
        $lockFile = $this->lockDir . '/mutex_' . md5($name) . '.lock';
        $this->lockHandle = fopen($lockFile, 'c');

        if ($this->lockHandle === false) {
            return false;
        }

        $deadline = time() + $timeoutSeconds;

        while (time() < $deadline) {
            if (flock($this->lockHandle, LOCK_EX | LOCK_NB)) {
                return true;
            }
            usleep(50000);  // 50ms between attempts
        }

        fclose($this->lockHandle);
        $this->lockHandle = false;
        return false;
    }

    public function release(): void
    {
        if ($this->lockHandle !== false) {
            flock($this->lockHandle, LOCK_UN);
            fclose($this->lockHandle);
            $this->lockHandle = false;
        }
    }
}

// Usage:
// $mutex = new FileMutex();
// if ($mutex->acquire('payment_' . $orderId)) {
//     try {
//         processPayment($orderId);
//     } finally {
//         $mutex->release();
//     }
// }
```

### Redis-Based Distributed Locking

```php
<?php
declare(strict_types=1);

/**
 * Redis-based distributed lock (Redlock simplified).
 * Suitable for multi-server deployments.
 */
final class RedisLock
{
    public function __construct(
        private readonly \Redis $redis,
    ) {}

    /**
     * Acquire a distributed lock.
     *
     * @param string $resource Lock key
     * @param int $ttlMs Lock time-to-live in milliseconds
     * @return string|null Lock token on success, null on failure
     */
    public function acquire(string $resource, int $ttlMs = 5000): ?string
    {
        $token = bin2hex(random_bytes(16));
        $key = 'lock:' . $resource;

        // SET NX (only if not exists) with TTL - atomic operation
        $acquired = $this->redis->set($key, $token, ['NX', 'PX' => $ttlMs]);

        return $acquired ? $token : null;
    }

    /**
     * Release a lock. Only the holder (matching token) can release it.
     * Uses Lua script for atomic compare-and-delete.
     */
    public function release(string $resource, string $token): bool
    {
        $key = 'lock:' . $resource;

        // Atomic: only delete if the value matches our token
        $script = <<<'LUA'
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
        LUA;

        return (bool) $this->redis->eval($script, [$key, $token], 1);
    }
}
```

### Detection Patterns

```php
// Grep patterns for potential race condition vulnerabilities:
$raceConditionPatterns = [
    'if.*file_exists.*file_put_contents',  // TOCTOU in file operations
    'SELECT.*FROM.*(?!FOR UPDATE)',         // SELECT without locking in write flow
    'getBalance.*updateBalance',            // Read-then-write pattern
    'findBy.*->set.*->flush',              // Doctrine read-modify-write
    'unlink\(\$.*\)',                       // File deletion race
    'rename\(\$.*,.*\$',                   // File rename race
    'mkdir\(\$.*\)',                        // Directory creation race
];
```

---

## Prototype Pollution via JSON

### Overview

While prototype pollution is primarily a JavaScript vulnerability, PHP APIs that accept JSON payloads can be vectors. If the PHP API passes JSON data to a JavaScript frontend or Node.js backend without sanitizing special keys like `__proto__`, `constructor`, or `prototype`, it enables prototype pollution in the downstream consumer.

### JSON Key Injection in API Payloads

```php
<?php
declare(strict_types=1);

// VULNERABLE: PHP API that stores and forwards JSON without sanitization
final class ApiControllerUnsafe
{
    public function updateSettings(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);

        // Attacker sends: {"__proto__": {"isAdmin": true}, "name": "Mallory"}
        // PHP itself is unaffected, but if this data is:
        // 1. Stored in DB and later consumed by JavaScript frontend
        // 2. Forwarded to a Node.js microservice
        // 3. Rendered as JSON in a <script> tag
        // ...the __proto__ key can pollute JavaScript Object.prototype

        $this->settingsRepository->save($data);  // Stored with __proto__ key

        return new JsonResponse(['status' => 'ok']);
    }
}

// SECURE: Sanitize dangerous keys from JSON input
final class JsonSanitizer
{
    /** @var list<string> */
    private const array DANGEROUS_KEYS = [
        '__proto__',
        'prototype',
        'constructor',
    ];

    /**
     * Recursively remove dangerous keys from parsed JSON data.
     */
    public static function sanitize(mixed $data): mixed
    {
        if (is_array($data)) {
            $cleaned = [];
            foreach ($data as $key => $value) {
                if (is_string($key) && in_array($key, self::DANGEROUS_KEYS, true)) {
                    continue;  // Skip dangerous keys
                }
                $cleaned[$key] = self::sanitize($value);
            }
            return $cleaned;
        }

        return $data;
    }
}

// SECURE: API controller with sanitization
final class ApiControllerSafe
{
    public function updateSettings(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);

        // Remove dangerous keys before processing
        $data = JsonSanitizer::sanitize($data);

        // Validate with explicit schema
        $validated = $this->validateSchema($data, [
            'name' => 'string',
            'theme' => 'string',
            'language' => 'string',
        ]);

        $this->settingsRepository->save($validated);

        return new JsonResponse(['status' => 'ok']);
    }

    /**
     * Schema-based validation: only allow expected keys and types.
     * This is the strongest defense against key injection.
     */
    private function validateSchema(array $data, array $schema): array
    {
        $result = [];
        foreach ($schema as $key => $type) {
            if (isset($data[$key]) && gettype($data[$key]) === $type) {
                $result[$key] = $data[$key];
            }
        }
        return $result;
    }
}
```

### Safe JSON Processing in PHP

```php
<?php
declare(strict_types=1);

/**
 * Secure JSON decoder that validates structure and prevents injection.
 */
final class SecureJsonDecoder
{
    /**
     * Decode JSON with strict validation.
     *
     * @param string $json Raw JSON string
     * @param int $maxDepth Maximum nesting depth (prevents DoS via deep nesting)
     * @param int $maxSize Maximum JSON string size in bytes
     * @return array<string, mixed> Decoded and validated data
     */
    public static function decode(
        string $json,
        int $maxDepth = 10,
        int $maxSize = 1_048_576  // 1 MB
    ): array {
        if (strlen($json) > $maxSize) {
            throw new \InvalidArgumentException('JSON payload exceeds maximum size');
        }

        $data = json_decode($json, true, $maxDepth, JSON_THROW_ON_ERROR);

        if (!is_array($data)) {
            throw new \InvalidArgumentException('JSON root must be an object or array');
        }

        return self::removePrototypePollutionKeys($data);
    }

    private static function removePrototypePollutionKeys(array $data): array
    {
        $cleaned = [];

        foreach ($data as $key => $value) {
            if (is_string($key) && in_array($key, ['__proto__', 'prototype', 'constructor'], true)) {
                continue;
            }

            $cleaned[$key] = is_array($value)
                ? self::removePrototypePollutionKeys($value)
                : $value;
        }

        return $cleaned;
    }
}
```

### Framework Patterns

#### Symfony JSON Validation

```php
<?php
declare(strict_types=1);

use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\SerializerInterface;

// SECURE: Use Symfony Serializer with strict DTO mapping
final class SettingsDto
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Length(max: 255)]
        public readonly string $name,

        #[Assert\Choice(choices: ['light', 'dark'])]
        public readonly string $theme = 'light',
    ) {}
    // Only declared properties are mapped - __proto__ is ignored
}

final class SettingsController
{
    public function update(
        Request $request,
        SerializerInterface $serializer,
    ): JsonResponse {
        $dto = $serializer->deserialize(
            $request->getContent(),
            SettingsDto::class,
            'json'
        );

        // Only name and theme are accessible - prototype pollution impossible
        return new JsonResponse(['status' => 'updated']);
    }
}
```

#### Laravel JSON Validation

```php
<?php
declare(strict_types=1);

use Illuminate\Http\Request;

// SECURE: Laravel validation acts as schema enforcement
final class SettingsController
{
    public function update(Request $request): JsonResponse
    {
        // Only validated keys are returned - __proto__ is excluded
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'theme' => 'in:light,dark',
            'language' => 'string|max:10',
        ]);

        // $validated only contains name, theme, language
        Settings::updateOrCreate(['user_id' => auth()->id()], $validated);

        return response()->json(['status' => 'updated']);
    }
}
```

### Detection Patterns

```php
// Grep patterns for potential prototype pollution vectors:
$prototypePollutionPatterns = [
    'json_decode.*true.*\$_',             // Decoding superglobals to arrays
    'json_decode.*getContent',             // Decoding request body without validation
    'echo.*json_encode\(\$',              // Echoing unsanitized JSON to frontend
    'JsonResponse\(\$data\)',              // Returning unvalidated data as JSON
    'response\(\)->json\(\$request',      // Forwarding raw request data
    '<script>.*var.*=.*json_encode',       // Embedding JSON in HTML script tags
];
```

## Remediation Priority

| Vulnerability | Severity | CVSS Range | Action | Timeline |
|--------------|----------|------------|--------|----------|
| SSRF to cloud metadata | Critical | 9.0-9.8 | Implement URL allowlist, block metadata IPs | Immediate |
| Mass assignment (admin fields) | High | 7.0-8.5 | Add fillable/allowlist, audit all form handlers | 24 hours |
| Race condition (financial) | High | 7.0-8.0 | Add database locking, atomic operations | 24 hours |
| SSRF to internal services | High | 7.0-8.5 | Block private IP ranges, use NoPrivateNetworkHttpClient | 48 hours |
| Race condition (non-financial) | Medium | 4.0-6.5 | Add file locking, optimistic concurrency | 1 week |
| JSON prototype pollution | Medium | 4.0-6.0 | Sanitize keys, use DTOs/validation | 1 week |
| Mass assignment (non-critical fields) | Low | 2.0-4.0 | Add explicit allowlists | 2 weeks |
