# PHP Security Features by Version

Modern PHP versions introduce language features that directly improve security when used correctly. This reference documents security-relevant features from PHP 8.0 through 8.4.

## PHP 8.0

### match Expression (Exhaustive Handling)

Unlike `switch`, `match` is an expression that throws `UnhandledMatchError` if no arm matches. This prevents logic bugs where unhandled cases silently fall through.

```php
// VULNERABLE: switch with missing break or missing case
// A forgotten 'break' causes fall-through, potentially granting elevated privileges
switch ($role) {
    case 'admin':
        $permissions = Permission::ALL;
        break;
    case 'editor':
        $permissions = Permission::EDIT;
        // Missing break! Falls through to viewer
    case 'viewer':
        $permissions = Permission::READ;
        break;
    // No default: unknown roles get no assignment, $permissions may be uninitialized
}

// SECURE: match is exhaustive and has no fall-through
$permissions = match ($role) {
    'admin' => Permission::ALL,
    'editor' => Permission::EDIT,
    'viewer' => Permission::READ,
    // If $role is anything else, UnhandledMatchError is thrown
};
```

**Security implication:** Prevents authorization bypass caused by unhandled roles or states. Forces developers to explicitly handle every case or provide a default.

### Named Arguments (Prevent Parameter Order Mistakes)

Named arguments prevent security-critical parameter mix-ups that can lead to misconfigured security functions.

```php
// VULNERABLE: Parameter order confusion
// Is the second argument the algorithm or the cost?
password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]); // cost=4 is too low

// SECURE: Named arguments make intent explicit
$hash = password_hash(
    password: $password,
    algo: PASSWORD_ARGON2ID,
    options: [
        'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
        'threads' => PASSWORD_ARGON2_DEFAULT_THREADS,
    ]
);

// SECURE: Named arguments for openssl functions prevent parameter confusion
$encrypted = openssl_encrypt(
    data: $plaintext,
    cipher_algo: 'aes-256-gcm',
    passphrase: $key,
    options: OPENSSL_RAW_DATA,
    iv: $iv,
    tag: $tag,
);
```

**Security implication:** Reduces risk of passing arguments in the wrong order for cryptographic and security functions.

### Nullsafe Operator (Prevent Null Reference Errors)

The `?->` operator short-circuits to `null` when the left side is null, preventing null reference errors that can expose error details or crash applications.

```php
// VULNERABLE: Null reference can expose stack traces in error pages
$user = $session->getUser();
$role = $user->getRole();        // Fatal error if $user is null
$name = $role->getName();        // Fatal error if $role is null

// SECURE: Nullsafe chain returns null without error
$roleName = $session->getUser()?->getRole()?->getName();

// Use in authorization checks
$isAdmin = $request->getAttribute('user')?->hasRole('admin') ?? false;
```

**Security implication:** Prevents information disclosure via error messages and stack traces. Ensures graceful handling of missing authentication/authorization objects.

### str_contains/str_starts_with/str_ends_with (Replace Error-Prone strpos)

The `strpos() !== false` pattern is a common source of bugs due to the `0 == false` loose comparison trap.

```php
// VULNERABLE: Classic strpos bug with loose comparison
if (strpos($token, 'admin') == false) {  // BUG: == instead of ===
    // 'admin_token' starts at position 0, which is falsy with ==
    // This incorrectly blocks admin tokens!
    deny();
}

// VULNERABLE: Inverted logic with strpos
if (!strpos($header, 'Bearer')) {  // BUG: position 0 is falsy
    throw new AuthenticationException('Missing Bearer token');
}

// SECURE: str_contains returns bool, no type confusion
if (!str_contains($header, 'Bearer')) {
    throw new AuthenticationException('Missing Bearer token');
}

// SECURE: str_starts_with for prefix checking
if (str_starts_with($apiKey, 'sk-')) {
    // This is an API key, handle securely
}

// SECURE: str_ends_with for suffix checking
if (!str_ends_with($redirectUrl, '.example.com')) {
    throw new SecurityException('Invalid redirect domain');
}
```

**Security implication:** Eliminates an entire class of boolean logic bugs in security-sensitive string comparisons.

## PHP 8.1

### Readonly Properties (Prevent Accidental Mutation)

Readonly properties can only be initialized once, preventing accidental or malicious mutation of security-sensitive data after construction.

```php
// VULNERABLE: Mutable security-sensitive properties
class Session
{
    public string $userId;
    public string $role;
    public int $expiresAt;
}

$session = new Session();
$session->userId = $authenticatedUser->id;
$session->role = 'viewer';

// Later in code, accidentally or maliciously:
$session->role = 'admin';  // Privilege escalation!

// SECURE: Readonly prevents mutation after initialization
class Session
{
    public function __construct(
        public readonly string $userId,
        public readonly string $role,
        public readonly int $expiresAt,
    ) {}
}

$session = new Session(
    userId: $authenticatedUser->id,
    role: 'viewer',
    expiresAt: time() + 3600,
);

$session->role = 'admin';  // Fatal error: Cannot modify readonly property
```

**Security implication:** Enforces immutability of authentication tokens, session data, and permission objects at the language level.

### Enums (Type-Safe Permissions, Roles, States)

Enums replace magic strings and integers for permissions and roles, making invalid values impossible at the type level.

```php
// VULNERABLE: String-based roles allow typos and injection
function hasAccess(string $role, string $resource): bool
{
    // Typo: 'admn' silently fails the check
    return $role === 'admin';
}

// SECURE: Enum-based roles are type-checked
enum Role: string
{
    case Admin = 'admin';
    case Editor = 'editor';
    case Viewer = 'viewer';

    public function canAccess(Permission $permission): bool
    {
        return match ($this) {
            self::Admin => true,
            self::Editor => in_array($permission, [Permission::Read, Permission::Write], true),
            self::Viewer => $permission === Permission::Read,
        };
    }
}

enum Permission
{
    case Read;
    case Write;
    case Delete;
    case ManageUsers;
}

// Usage: impossible to pass an invalid role
function authorize(Role $role, Permission $permission): void
{
    if (!$role->canAccess($permission)) {
        throw new AccessDeniedException();
    }
}

// Role::from('invalid') throws ValueError - no silent failures
$role = Role::from($request->getAttribute('role'));
```

**Security implication:** Eliminates entire classes of authorization bugs. Invalid roles/permissions are caught at compile-time (static analysis) or runtime (ValueError).

### Fibers (Secret Leakage via Shared State)

Fibers enable cooperative multitasking but share memory space. Security-sensitive data can leak between fibers if not isolated.

```php
// VULNERABLE: Shared state between fibers can leak secrets
class RequestContext
{
    public static ?string $currentApiKey = null;
}

$fiber1 = new Fiber(function () {
    RequestContext::$currentApiKey = 'secret-key-user-a';
    Fiber::suspend();
    // After resume, $currentApiKey may have been changed by fiber2
    $key = RequestContext::$currentApiKey; // Could be user-b's key!
});

$fiber2 = new Fiber(function () {
    RequestContext::$currentApiKey = 'secret-key-user-b';
    Fiber::suspend();
});

// SECURE: Use fiber-local storage or scoped context
final class FiberScopedContext
{
    /** @var \WeakMap<Fiber, array<string, mixed>> */
    private static WeakMap $storage;

    public static function init(): void
    {
        self::$storage ??= new WeakMap();
    }

    public static function set(string $key, mixed $value): void
    {
        $fiber = Fiber::getCurrent() ?? throw new LogicException('Not in a fiber');
        self::$storage[$fiber] ??= [];
        $data = self::$storage[$fiber];
        $data[$key] = $value;
        self::$storage[$fiber] = $data;
    }

    public static function get(string $key): mixed
    {
        $fiber = Fiber::getCurrent() ?? throw new LogicException('Not in a fiber');
        return self::$storage[$fiber][$key] ?? null;
    }
}
```

**Security implication:** Static/global state in fiber-based applications can cause cross-request data leakage. Always scope sensitive data to the execution context.

### Intersection Types (Strict Contracts)

Intersection types enforce that a value satisfies multiple type constraints simultaneously, enabling stricter security interfaces.

```php
// SECURE: Require both Authenticatable AND Authorizable
function processAdminAction(
    Authenticatable&Authorizable $user,
    string $action
): void {
    // Guaranteed to have both authentication and authorization methods
    if (!$user->isAuthenticated()) {
        throw new AuthenticationException();
    }

    if (!$user->isAuthorized($action)) {
        throw new AuthorizationException();
    }
}
```

**Security implication:** Prevents passing objects that only partially satisfy security requirements.

### never Return Type (Functions That Always Throw)

The `never` return type declares that a function never returns normally -- it always throws or exits. This provides static analysis guarantees that error paths terminate execution.

```php
// SECURE: Static analysis knows this never returns
function denyAccess(string $reason): never
{
    log_security_event('access_denied', $reason);
    throw new AccessDeniedException($reason);
}

// SECURE: Redirect and terminate
function forceHttps(ServerRequestInterface $request): never
{
    if ($request->getUri()->getScheme() !== 'https') {
        header('Location: https://' . $request->getUri()->getHost() . $request->getUri()->getPath());
        exit(0);
    }
    // Static analysis error: function declared never but may return
}
```

**Security implication:** Guarantees that security denial functions actually terminate execution. Static analyzers can verify no code runs after a `never` function call.

## PHP 8.2

### Readonly Classes

Readonly classes make all declared properties readonly, providing whole-object immutability with less boilerplate.

```php
// SECURE: Entire class is immutable
readonly class AuthToken
{
    public function __construct(
        public string $tokenId,
        public string $userId,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public array $scopes,
    ) {}

    public function isExpired(): bool
    {
        return new DateTimeImmutable() > $this->expiresAt;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}

// Cannot modify any property after construction
$token = new AuthToken(
    tokenId: bin2hex(random_bytes(32)),
    userId: $user->id,
    issuedAt: new DateTimeImmutable(),
    expiresAt: new DateTimeImmutable('+1 hour'),
    scopes: ['read', 'write'],
);

$token->scopes = ['admin'];  // Fatal error: Cannot modify readonly property
```

**Security implication:** Guarantees immutability of security objects (tokens, credentials, policy objects) at the class level.

### Disjunctive Normal Form (DNF) Types

DNF types combine union and intersection types for precise type constraints.

```php
// SECURE: Accept either an authenticated admin OR a service account
function performMaintenance(
    (Authenticatable&AdminRole)|ServiceAccount $actor
): void {
    // Type system guarantees the actor is authorized
}
```

### Deprecated Dynamic Properties (Prevents Mass Assignment)

PHP 8.2 deprecates setting undeclared properties on objects. In PHP 9.0 this will throw an error. This mitigates mass-assignment vulnerabilities.

```php
// VULNERABLE (PHP < 8.2): Mass assignment via dynamic properties
class UserProfile
{
    public string $name;
    public string $email;
}

$profile = new UserProfile();
foreach ($requestData as $key => $value) {
    $profile->$key = $value;  // Attacker sets $profile->isAdmin = true
}

// SECURE (PHP 8.2+): Dynamic properties trigger deprecation
// In PHP 9.0+, this will be a fatal error
$profile->isAdmin = true;  // Deprecated: Creation of dynamic property

// SECURE: Use explicit setter with validation
class UserProfile
{
    public string $name;
    public string $email;

    /** @var list<string> */
    private const array FILLABLE = ['name', 'email'];

    public function fill(array $data): void
    {
        foreach (self::FILLABLE as $field) {
            if (array_key_exists($field, $data)) {
                $this->$field = (string)$data[$field];
            }
        }
    }
}
```

**Security implication:** Prevents attackers from injecting unexpected properties (like `isAdmin`, `role`, `verified`) through mass assignment.

### Detection Patterns

```
# Find classes vulnerable to mass assignment (no AllowDynamicProperties and no readonly)
class\s+\w+(?!.*readonly)(?!.*#\[AllowDynamicProperties\])

# Find dynamic property assignment from user input
\$\w+->{\$
\$\w+->\$\w+\s*=
foreach.*\$\w+->\$\w+\s*=
```

## PHP 8.3

### json_validate() (Validate Before Decode)

`json_validate()` checks JSON validity without decoding, using less memory and preventing resource exhaustion from malicious payloads.

```php
// VULNERABLE: json_decode on untrusted input allocates memory for the decoded structure
// A deeply nested JSON payload can exhaust memory
$data = json_decode($untrustedInput, true);
if ($data === null) {
    // Could be valid null OR invalid JSON - ambiguous!
    throw new InvalidArgumentException('Invalid JSON');
}

// SECURE: Validate structure first, then decode
$rawBody = file_get_contents('php://input');

// Fast validation without memory allocation for decoded structure
if (!json_validate($rawBody)) {
    throw new BadRequestException('Invalid JSON payload');
}

// Limit depth to prevent deeply nested structures
if (!json_validate($rawBody, depth: 10)) {
    throw new BadRequestException('JSON nesting too deep');
}

// Now safe to decode with known-valid input
$data = json_decode($rawBody, true, 10, JSON_THROW_ON_ERROR);
```

**Security implication:** Prevents resource exhaustion from malformed JSON and eliminates the `null` ambiguity bug from `json_decode()`.

### Typed Class Constants

Typed constants prevent accidental type changes in security configuration values.

```php
// SECURE: Type-safe security configuration constants
final class SecurityConfig
{
    public const int MAX_LOGIN_ATTEMPTS = 5;
    public const int LOCKOUT_DURATION_SECONDS = 900;
    public const int SESSION_LIFETIME_SECONDS = 3600;
    public const int PASSWORD_MIN_LENGTH = 12;
    public const string HASH_ALGORITHM = 'sha256';
    public const int TOKEN_ENTROPY_BYTES = 32;

    // Child classes cannot change the type
}

// In interface: enforce type for implementors
interface RateLimiterInterface
{
    public const int DEFAULT_MAX_ATTEMPTS = 5;
    public const int DEFAULT_WINDOW_SECONDS = 60;
}
```

**Security implication:** Prevents accidental type coercion in security-critical constants (e.g., changing an int to a string that gets loosely compared).

### #[\Override] Attribute (Prevent Silent Method Signature Drift)

The `#[\Override]` attribute causes a compile-time error if the method does not actually override a parent method. This catches renamed or removed security methods.

```php
// VULNERABLE: Parent class renames isAuthorized() to checkAuthorization()
// Child class silently stops overriding it and the default (permissive) implementation runs
class AdminController extends BaseController
{
    public function isAuthorized(Request $request): bool  // No longer overrides anything!
    {
        return $this->user->hasRole('admin');
    }
}

// SECURE: #[Override] catches the mismatch
class AdminController extends BaseController
{
    #[\Override]
    public function isAuthorized(Request $request): bool
    {
        // Compile error: AdminController::isAuthorized() has #[\Override] attribute,
        // but no matching parent method exists
        return $this->user->hasRole('admin');
    }
}
```

**Security implication:** Prevents security bypass when parent class method signatures change. Without `#[\Override]`, a security check method could silently stop being called.

## PHP 8.4

### Property Hooks (Validation on Set)

Property hooks allow defining get/set logic directly on properties, enabling automatic input validation without separate setter methods.

```php
// SECURE: Validate on property assignment
class UserProfile
{
    public string $email {
        set(string $value) {
            $filtered = filter_var($value, FILTER_VALIDATE_EMAIL);
            if ($filtered === false) {
                throw new InvalidArgumentException('Invalid email address');
            }
            $this->email = $filtered;
        }
    }

    public string $username {
        set(string $value) {
            if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $value)) {
                throw new InvalidArgumentException(
                    'Username must be 3-30 alphanumeric characters or underscores'
                );
            }
            $this->username = $value;
        }
    }

    public string $password {
        set(string $value) {
            if (mb_strlen($value) < 12) {
                throw new InvalidArgumentException('Password must be at least 12 characters');
            }
            // Store hashed, never plain
            $this->password = password_hash($value, PASSWORD_ARGON2ID);
        }
    }
}

// Validation runs automatically on assignment
$profile = new UserProfile();
$profile->email = 'invalid';  // Throws InvalidArgumentException
$profile->username = '<script>alert(1)</script>';  // Throws InvalidArgumentException
```

**Security implication:** Ensures validation cannot be bypassed by direct property access. Every assignment path goes through the hook.

### Asymmetric Visibility (Public Read, Private Write)

Asymmetric visibility allows properties to be read publicly but only written privately, providing controlled immutability without readonly's all-or-nothing approach.

```php
// SECURE: Public read, private write for security-sensitive state
class AuthenticationResult
{
    public private(set) bool $isAuthenticated = false;
    public private(set) ?string $userId = null;
    public private(set) DateTimeImmutable $authenticatedAt;
    public private(set) string $method = 'none';

    public function authenticateWith(string $userId, string $method): void
    {
        // Only internal methods can modify these properties
        $this->isAuthenticated = true;
        $this->userId = $userId;
        $this->authenticatedAt = new DateTimeImmutable();
        $this->method = $method;
    }
}

$result = new AuthenticationResult();

// External code can read:
if ($result->isAuthenticated) { /* ... */ }
echo $result->userId;

// External code cannot write:
$result->isAuthenticated = true;  // Error: Cannot modify private(set) property
$result->userId = 'admin';       // Error: Cannot modify private(set) property
```

**Security implication:** Allows security state to be inspected by any code but modified only through controlled internal methods that enforce invariants.

### new Without Parentheses

A minor syntax change, but relevant for fluent security builder patterns.

```php
// PHP 8.4: new without parentheses in expressions
$policy = new SecurityPolicy
    ->allowOrigin('https://example.com')
    ->denyFrame()
    ->requireHttps();
```

## Detection Patterns for Auditing PHP Version Features

```
# Find code that would benefit from match (switch without default)
switch\s*\([^)]+\)\s*\{(?!.*default\s*:)

# Find strpos() that should be str_contains()
strpos\s*\([^)]+\)\s*(!==|===)\s*(false|0)
!strpos\(

# Find mutable properties that should be readonly
public\s+(string|int|float|bool|array)\s+\$(?!.*readonly)

# Find string-based role/permission checks that should use enums
===\s*'admin'|===\s*'editor'|===\s*'viewer'

# Find classes without #[Override] on overridden methods
# (requires static analysis tools like PHPStan)

# Find dynamic property usage (PHP 8.2 deprecation)
\$\w+->\$\w+\s*=

# Find json_decode without prior json_validate (PHP 8.3+)
json_decode\((?!.*json_validate)
```

## Version Adoption Security Checklist

| PHP Version | Feature | Security Benefit | Audit Action |
|------------|---------|------------------|--------------|
| 8.0 | match | Prevents unhandled case bypass | Replace security-sensitive switch statements |
| 8.0 | Named arguments | Prevents parameter confusion | Use for crypto/hash functions |
| 8.0 | str_contains | Eliminates strpos boolean bugs | Replace all strpos !== false patterns |
| 8.1 | readonly | Prevents mutation of security state | Apply to tokens, sessions, credentials |
| 8.1 | Enums | Type-safe roles/permissions | Replace string-based authorization |
| 8.1 | never | Guarantees termination | Use for deny/redirect functions |
| 8.2 | readonly classes | Whole-object immutability | Apply to DTOs and value objects |
| 8.2 | No dynamic props | Prevents mass assignment | Remove #[AllowDynamicProperties] |
| 8.3 | json_validate | Pre-decode validation | Validate untrusted JSON before decode |
| 8.3 | #[\Override] | Prevents silent override loss | Add to security method overrides |
| 8.4 | Property hooks | Automatic input validation | Replace manual setters |
| 8.4 | Asymmetric visibility | Controlled state mutation | Use for auth/session properties |

## Related References

- `owasp-top10.md` - Vulnerability patterns these features prevent
- `input-validation.md` - Input handling that leverages these features
- `ci-security-pipeline.md` - Static analysis tools that check for these patterns
