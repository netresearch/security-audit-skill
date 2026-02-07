# Authentication and Session Security Patterns

## Overview

Authentication is the process of verifying that a user is who they claim to be.
Weaknesses in authentication mechanisms are covered by OWASP A07:2021 (Identification
and Authentication Failures). This reference covers secure password hashing, session
management, JWT handling, multi-factor authentication, and framework-specific
implementations.

---

## Password Hashing

### Secure Algorithms

PHP provides `password_hash()` and `password_verify()` as the standard API for
password hashing. Always use these functions rather than raw hashing algorithms.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// MD5 is a fast hash, trivially crackable with rainbow tables and GPUs
$hash = md5($password);

// VULNERABLE - DO NOT USE
// SHA1 is a fast hash, not designed for password storage
$hash = sha1($password);

// VULNERABLE - DO NOT USE
// SHA-256 is still a fast hash, unsuitable for passwords even with salt
$hash = hash('sha256', $salt . $password);

// VULNERABLE - DO NOT USE
// crypt() with weak algorithm or misconfiguration
$hash = crypt($password, '$1$salt$'); // MD5-based crypt
```

```php
<?php

declare(strict_types=1);

// SECURE: PASSWORD_ARGON2ID (preferred, requires PHP 7.3+ with libargon2)
// Argon2id is resistant to both side-channel and GPU-based attacks
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST, // 65536 KiB (64 MiB)
    'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,     // 4 iterations
    'threads' => PASSWORD_ARGON2_DEFAULT_THREADS,          // 1 thread
]);

// SECURE: PASSWORD_BCRYPT (widely available fallback)
// bcrypt has a 72-byte input limit; longer passwords are silently truncated
$hash = password_hash($password, PASSWORD_BCRYPT, [
    'cost' => 12, // Adjust based on server performance (target ~250ms)
]);

// SECURE: PASSWORD_DEFAULT (currently bcrypt, may change in future PHP versions)
// Use this when you want PHP to select the best available algorithm
$hash = password_hash($password, PASSWORD_DEFAULT);
```

### Password Verification and Rehashing

```php
<?php

declare(strict_types=1);

final class PasswordService
{
    private const string PREFERRED_ALGORITHM = PASSWORD_ARGON2ID;
    private const array PREFERRED_OPTIONS = [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 1,
    ];

    /**
     * Verify a password and rehash if the stored hash uses an outdated algorithm.
     *
     * password_needs_rehash() returns true when the algorithm or cost parameters
     * differ from what is currently configured, enabling transparent upgrades.
     */
    public function verify(string $password, string $storedHash): bool
    {
        if (!password_verify($password, $storedHash)) {
            return false;
        }

        // Transparently upgrade hash if algorithm or parameters changed
        if (password_needs_rehash($storedHash, self::PREFERRED_ALGORITHM, self::PREFERRED_OPTIONS)) {
            $newHash = password_hash($password, self::PREFERRED_ALGORITHM, self::PREFERRED_OPTIONS);
            $this->updateStoredHash($newHash);
        }

        return true;
    }

    private function updateStoredHash(string $newHash): void
    {
        // Persist the upgraded hash to the database
    }
}
```

### Timing-Safe Comparison

Never compare hashes or tokens with `==` or `===`. These operators may leak
timing information that allows an attacker to determine the correct value
character by character.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Standard comparison leaks timing information
if ($submittedToken === $storedToken) {
    // Token valid
}

// VULNERABLE - DO NOT USE
// strcmp() also leaks timing information and has type juggling issues
if (strcmp($submittedToken, $storedToken) === 0) {
    // Token valid
}
```

```php
<?php

declare(strict_types=1);

// SECURE: hash_equals() performs constant-time string comparison
if (hash_equals($storedToken, $submittedToken)) {
    // Token valid -- comparison time does not depend on how many bytes match
}

// SECURE: For HMAC verification, use hash_equals with hash_hmac
$expectedSignature = hash_hmac('sha256', $payload, $secretKey);
if (hash_equals($expectedSignature, $submittedSignature)) {
    // Signature valid
}
```

---

## Session Security

### Session Regeneration

Session fixation attacks occur when an attacker sets a user's session ID before
authentication. After the user authenticates, the attacker uses the known session
ID to impersonate them. Always regenerate the session ID after any authentication
state change.

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// No session regeneration after login -- enables session fixation
function login(string $username, string $password): bool
{
    if ($this->authenticate($username, $password)) {
        $_SESSION['user'] = $username;
        $_SESSION['authenticated'] = true;
        return true;
    }
    return false;
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Regenerate session ID after authentication state changes
final class SessionAuthenticator
{
    public function login(string $username, string $password): bool
    {
        if (!$this->authenticate($username, $password)) {
            return false;
        }

        // Regenerate session ID and delete old session file
        // The `true` parameter is critical: it destroys the old session data
        session_regenerate_id(true);

        $_SESSION['user'] = $username;
        $_SESSION['authenticated'] = true;
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['last_activity'] = time();

        return true;
    }

    public function logout(): void
    {
        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires' => time() - 42000,
                    'path' => $params['path'],
                    'domain' => $params['domain'],
                    'secure' => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'],
                ],
            );
        }

        session_destroy();
    }

    public function validateSession(): bool
    {
        if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
            return false;
        }

        // Detect session hijacking via IP or user-agent change
        if ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
            $this->logout();
            return false;
        }

        // Enforce idle timeout (30 minutes)
        if (time() - $_SESSION['last_activity'] > 1800) {
            $this->logout();
            return false;
        }

        $_SESSION['last_activity'] = time();
        return true;
    }

    private function authenticate(string $username, string $password): bool
    {
        // Implementation depends on user storage backend
        return false;
    }
}
```

### Session Configuration

```ini
; php.ini -- secure session configuration

; Use cookies exclusively for session transport (no URL-based session IDs)
session.use_cookies = 1
session.use_only_cookies = 1
session.use_trans_sid = 0

; Cookie security attributes
session.cookie_httponly = 1    ; Prevent JavaScript access to session cookie
session.cookie_secure = 1      ; Only transmit cookie over HTTPS
session.cookie_samesite = Lax  ; Prevent CSRF via cross-site cookie sending
                                ; Use "Strict" for maximum protection (may break OAuth flows)

; Session ID entropy
session.sid_length = 48         ; Minimum 32 characters recommended
session.sid_bits_per_character = 6

; Session lifetime
session.gc_maxlifetime = 1800   ; 30 minutes server-side
session.cookie_lifetime = 0     ; Session cookie (deleted when browser closes)

; Strict mode prevents accepting uninitialized session IDs
session.use_strict_mode = 1
```

```php
<?php

declare(strict_types=1);

// SECURE: Set session configuration programmatically before session_start()
function configureSecureSession(): void
{
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');

    session_start();
}
```

---

## JWT Best Practices

JSON Web Tokens are commonly misused. The following patterns address the most
critical JWT vulnerabilities.

### Algorithm Validation

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Accepting "alg": "none" allows bypassing signature verification entirely
$payload = json_decode(base64_decode(explode('.', $token)[1]), true);

// VULNERABLE - DO NOT USE
// Not validating the algorithm allows algorithm confusion attacks
// An attacker can switch from RS256 to HS256, using the public key as HMAC secret
$decoded = JWT::decode($token, $key, ['HS256', 'RS256', 'none']);

// VULNERABLE - DO NOT USE
// Using the "alg" header from the token itself to determine verification method
$header = json_decode(base64_decode(explode('.', $token)[0]), true);
$algorithm = $header['alg']; // Attacker-controlled!
```

```php
<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// SECURE: Always specify the expected algorithm explicitly
// The Key object binds algorithm to key material, preventing confusion attacks
$decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

// SECURE: Validate all critical claims
final class JwtValidator
{
    public function __construct(
        private readonly string $publicKey,
        private readonly string $expectedIssuer,
        private readonly string $expectedAudience,
    ) {}

    public function validate(string $token): object
    {
        // Explicitly set the allowed algorithm -- never trust the token header
        $decoded = JWT::decode($token, new Key($this->publicKey, 'RS256'));

        // Validate issuer claim
        if (!isset($decoded->iss) || $decoded->iss !== $this->expectedIssuer) {
            throw new \UnexpectedValueException('Invalid issuer');
        }

        // Validate audience claim
        if (!isset($decoded->aud) || $decoded->aud !== $this->expectedAudience) {
            throw new \UnexpectedValueException('Invalid audience');
        }

        // Validate expiration (firebase/php-jwt checks exp automatically, but verify)
        if (!isset($decoded->exp) || $decoded->exp < time()) {
            throw new \UnexpectedValueException('Token expired');
        }

        // Validate not-before claim
        if (isset($decoded->nbf) && $decoded->nbf > time()) {
            throw new \UnexpectedValueException('Token not yet valid');
        }

        return $decoded;
    }
}
```

### JWT Token Creation

```php
<?php

declare(strict_types=1);

// SECURE: Creating a JWT with all recommended claims
final class JwtIssuer
{
    public function __construct(
        private readonly string $privateKey,
        private readonly string $issuer,
        private readonly int $ttlSeconds = 3600,
    ) {}

    public function issue(string $subject, string $audience, array $customClaims = []): string
    {
        $now = time();

        $payload = array_merge($customClaims, [
            'iss' => $this->issuer,           // Issuer
            'sub' => $subject,                 // Subject (user identifier)
            'aud' => $audience,                // Audience
            'iat' => $now,                     // Issued at
            'nbf' => $now,                     // Not before
            'exp' => $now + $this->ttlSeconds, // Expiration
            'jti' => bin2hex(random_bytes(16)), // Unique token ID (for revocation)
        ]);

        return JWT::encode($payload, $this->privateKey, 'RS256');
    }
}
```

---

## Multi-Factor Authentication (MFA/TOTP)

### TOTP Implementation

Time-based One-Time Passwords (TOTP, RFC 6238) are the most common second factor.

```php
<?php

declare(strict_types=1);

// SECURE: TOTP implementation using a well-vetted library
// Recommended: spomky-labs/otphp or robthree/twofactorauth

use OTPHP\TOTP;

final class TwoFactorService
{
    /**
     * Generate a new TOTP secret for a user during MFA enrollment.
     */
    public function generateSecret(string $userEmail): TOTP
    {
        $totp = TOTP::generate();
        $totp->setLabel($userEmail);
        $totp->setIssuer('MyApplication');

        // The provisioning URI is used to generate the QR code
        // Example: otpauth://totp/MyApplication:user@example.com?secret=...&issuer=MyApplication
        // Store $totp->getSecret() encrypted in the database -- do NOT log it
        return $totp;
    }

    /**
     * Verify a TOTP code submitted by the user.
     *
     * The window parameter allows a tolerance of +/- 1 time step (30 seconds)
     * to account for clock drift.
     */
    public function verify(string $secret, string $submittedCode): bool
    {
        $totp = TOTP::createFromSecret($secret);

        // Verify with a window of 1 (allows +/- 30 seconds drift)
        return $totp->verify($submittedCode, null, 1);
    }

    /**
     * Generate backup codes for account recovery.
     * Store hashed, never in plaintext.
     */
    public function generateBackupCodes(int $count = 10): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(4))); // 8-character hex codes
        }
        return $codes;
    }
}
```

### MFA Enrollment Flow Security

```php
<?php

declare(strict_types=1);

// SECURE: MFA enrollment with verification before activation
final class MfaEnrollmentController
{
    public function startEnrollment(Request $request): Response
    {
        $user = $this->getAuthenticatedUser($request);

        // Generate secret and store as PENDING (not yet active)
        $totp = $this->twoFactorService->generateSecret($user->getEmail());
        $this->userRepository->storePendingMfaSecret(
            $user->getId(),
            $totp->getSecret(),
        );

        return new Response([
            'qr_uri' => $totp->getProvisioningUri(),
            // Never expose the raw secret in the response if QR code is available
        ]);
    }

    public function confirmEnrollment(Request $request): Response
    {
        $user = $this->getAuthenticatedUser($request);
        $code = $request->get('code');

        $pendingSecret = $this->userRepository->getPendingMfaSecret($user->getId());

        // User must prove they can generate a valid code before MFA is activated
        if (!$this->twoFactorService->verify($pendingSecret, $code)) {
            return new Response(['error' => 'Invalid code'], 400);
        }

        // Activate MFA -- move secret from pending to active
        $this->userRepository->activateMfa($user->getId());

        // Generate and display backup codes (one-time display)
        $backupCodes = $this->twoFactorService->generateBackupCodes();
        $this->userRepository->storeHashedBackupCodes(
            $user->getId(),
            array_map(static fn(string $code): string => password_hash($code, PASSWORD_BCRYPT), $backupCodes),
        );

        return new Response([
            'backup_codes' => $backupCodes, // Display once, never again
        ]);
    }
}
```

---

## Rate Limiting on Authentication Endpoints

```php
<?php

declare(strict_types=1);

// SECURE: Rate limiting to prevent brute-force and credential stuffing attacks
final class AuthenticationRateLimiter
{
    private const int MAX_ATTEMPTS_PER_IP = 20;
    private const int MAX_ATTEMPTS_PER_USER = 5;
    private const int DECAY_MINUTES = 15;
    private const int LOCKOUT_MINUTES = 30;

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * Check rate limits BEFORE attempting authentication.
     * Rate limit by both IP address and username to prevent:
     * - Single IP brute-forcing multiple accounts (IP limit)
     * - Distributed brute-force against single account (username limit)
     */
    public function checkLimits(string $username, string $ipAddress): void
    {
        $ipKey = 'auth_rate_ip:' . $ipAddress;
        $userKey = 'auth_rate_user:' . strtolower($username);

        $ipAttempts = (int) $this->cache->get($ipKey, 0);
        $userAttempts = (int) $this->cache->get($userKey, 0);

        if ($ipAttempts >= self::MAX_ATTEMPTS_PER_IP) {
            $this->logger->warning('IP rate limit exceeded', [
                'ip' => $ipAddress,
                'attempts' => $ipAttempts,
            ]);
            throw new TooManyAttemptsException(
                'Too many login attempts. Please try again later.',
                self::DECAY_MINUTES * 60,
            );
        }

        if ($userAttempts >= self::MAX_ATTEMPTS_PER_USER) {
            $this->logger->warning('Account rate limit exceeded', [
                'username' => $username,
                'ip' => $ipAddress,
                'attempts' => $userAttempts,
            ]);
            throw new TooManyAttemptsException(
                'Account temporarily locked. Please try again later.',
                self::LOCKOUT_MINUTES * 60,
            );
        }
    }

    public function recordFailure(string $username, string $ipAddress): void
    {
        $ipKey = 'auth_rate_ip:' . $ipAddress;
        $userKey = 'auth_rate_user:' . strtolower($username);

        $this->incrementWithExpiry($ipKey, self::DECAY_MINUTES * 60);
        $this->incrementWithExpiry($userKey, self::LOCKOUT_MINUTES * 60);
    }

    public function clearOnSuccess(string $username, string $ipAddress): void
    {
        $userKey = 'auth_rate_user:' . strtolower($username);
        $this->cache->delete($userKey);
        // Note: Do NOT clear IP counter on success -- prevents IP-based brute force
    }

    private function incrementWithExpiry(string $key, int $ttlSeconds): void
    {
        $current = (int) $this->cache->get($key, 0);
        $this->cache->set($key, $current + 1, $ttlSeconds);
    }
}
```

### Account Lockout Patterns

```php
<?php

declare(strict_types=1);

// SECURE: Progressive lockout with exponential backoff
final class AccountLockoutService
{
    /**
     * Lockout durations in seconds, indexed by failure count threshold.
     * After 3 failures: 1 minute, after 5: 5 minutes, after 10: 30 minutes, after 20: 24 hours.
     */
    private const array LOCKOUT_SCHEDULE = [
        3 => 60,
        5 => 300,
        10 => 1800,
        20 => 86400,
    ];

    public function __construct(
        private readonly Connection $db,
        private readonly LoggerInterface $logger,
    ) {}

    public function recordFailedAttempt(string $userId): void
    {
        $this->db->executeStatement(
            'UPDATE users SET failed_login_attempts = failed_login_attempts + 1, '
            . 'last_failed_login = NOW() WHERE id = ?',
            [$userId],
        );

        $attempts = $this->getFailedAttempts($userId);
        $lockoutDuration = $this->calculateLockoutDuration($attempts);

        if ($lockoutDuration > 0) {
            $lockedUntil = new \DateTimeImmutable("+{$lockoutDuration} seconds");
            $this->db->executeStatement(
                'UPDATE users SET locked_until = ? WHERE id = ?',
                [$lockedUntil->format('Y-m-d H:i:s'), $userId],
            );

            $this->logger->warning('Account locked due to failed attempts', [
                'user_id' => $userId,
                'attempts' => $attempts,
                'locked_until' => $lockedUntil->format('c'),
            ]);
        }
    }

    public function isLocked(string $userId): bool
    {
        $lockedUntil = $this->db->fetchOne(
            'SELECT locked_until FROM users WHERE id = ?',
            [$userId],
        );

        if ($lockedUntil === null || $lockedUntil === false) {
            return false;
        }

        return new \DateTimeImmutable($lockedUntil) > new \DateTimeImmutable();
    }

    public function resetOnSuccess(string $userId): void
    {
        $this->db->executeStatement(
            'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
            [$userId],
        );
    }

    private function calculateLockoutDuration(int $attempts): int
    {
        $duration = 0;
        foreach (self::LOCKOUT_SCHEDULE as $threshold => $seconds) {
            if ($attempts >= $threshold) {
                $duration = $seconds;
            }
        }
        return $duration;
    }

    private function getFailedAttempts(string $userId): int
    {
        return (int) $this->db->fetchOne(
            'SELECT failed_login_attempts FROM users WHERE id = ?',
            [$userId],
        );
    }
}
```

---

## Framework-Specific Solutions

### TYPO3

```php
<?php

declare(strict_types=1);

// TYPO3 Authentication Service
// TYPO3 uses a chain of authentication services evaluated in order of priority.

use TYPO3\CMS\Core\Authentication\AuthenticationService;

final class CustomAuthenticationService extends AuthenticationService
{
    /**
     * Authenticate a frontend or backend user.
     *
     * Return values:
     *   >= 200: User authenticated (stop further services)
     *   >= 100: User not authenticated, try next service
     *     > 0:  User authenticated (continue checking other services)
     *    <= 0:  Authentication failed (stop)
     */
    public function authUser(array $user): int
    {
        // SECURE: Use TYPO3's built-in password hashing (Argon2id by default since v9)
        $passwordHashFactory = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(
            \TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory::class,
        );
        $hashInstance = $passwordHashFactory->getDefaultHashInstance('FE');

        if (!$hashInstance->checkPassword($this->login['uident_text'], $user['password'])) {
            return -1; // Authentication failed
        }

        // Check if password needs rehashing (algorithm upgrade)
        if (!$hashInstance->isValidSaltedPW($user['password'])) {
            $newHash = $hashInstance->getHashedPassword($this->login['uident_text']);
            // Update stored hash -- TYPO3 handles this automatically in core
        }

        return 200; // Authenticated
    }
}

// Accessing the current backend user
// $GLOBALS['BE_USER'] is the BackendUserAuthentication instance
// Always check authentication state before accessing protected resources
if ($GLOBALS['BE_USER']->isAdmin()) {
    // Admin-only operations
}

// Check specific permissions
if ($GLOBALS['BE_USER']->check('tables_modify', 'tx_myext_domain_model_record')) {
    // User has permission to modify this table
}

// TYPO3 session handling
// TYPO3 manages sessions internally. Use the session API:
$sessionManager = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(
    \TYPO3\CMS\Core\Session\SessionManager::class,
);

// Frontend user sessions
$frontendSession = $GLOBALS['TSFE']->fe_user;
$frontendSession->setAndSaveSessionData('mykey', 'myvalue');
$value = $frontendSession->getSessionData('mykey');

// TYPO3 rate limiting (since v11)
// Configure in $GLOBALS['TYPO3_CONF_VARS']['BE']['loginRateLimit'] and
// $GLOBALS['TYPO3_CONF_VARS']['FE']['loginRateLimit']
// Default: 5 attempts per 15 minutes
```

### Symfony

```php
<?php

declare(strict_types=1);

// Symfony Security Component

// security.yaml configuration
// The Symfony security component provides firewalls, authenticators, and voters.

/*
# config/packages/security.yaml
security:
    password_hashers:
        App\Entity\User:
            algorithm: auto  # Uses Argon2id if available, bcrypt as fallback

    firewalls:
        main:
            lazy: true
            provider: app_user_provider
            custom_authenticator: App\Security\LoginFormAuthenticator
            login_throttling:
                max_attempts: 5
                interval: '15 minutes'
            logout:
                path: app_logout
            remember_me:
                secret: '%kernel.secret%'
                secure: true
                httponly: true
                samesite: lax

    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/profile, roles: ROLE_USER }
*/

// Custom Authenticator (Symfony 6+)
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

final class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
{
    public function authenticate(Request $request): Passport
    {
        $email = $request->getPayload()->getString('email');
        $password = $request->getPayload()->getString('password');
        $csrfToken = $request->getPayload()->getString('_csrf_token');

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($password),
            [
                new CsrfTokenBadge('authenticate', $csrfToken),
                new RememberMeBadge(),
            ],
        );
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate('app_login');
    }
}

// Voter for fine-grained authorization
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class DocumentVoter extends Voter
{
    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, ['VIEW', 'EDIT', 'DELETE'], true)
            && $subject instanceof Document;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        /** @var Document $document */
        $document = $subject;

        return match ($attribute) {
            'VIEW' => $this->canView($document, $user),
            'EDIT' => $this->canEdit($document, $user),
            'DELETE' => $this->canDelete($document, $user),
            default => false,
        };
    }

    private function canView(Document $document, User $user): bool
    {
        return $document->isPublic() || $document->getOwner() === $user;
    }

    private function canEdit(Document $document, User $user): bool
    {
        return $document->getOwner() === $user;
    }

    private function canDelete(Document $document, User $user): bool
    {
        return $document->getOwner() === $user || in_array('ROLE_ADMIN', $user->getRoles(), true);
    }
}
```

### Laravel

```php
<?php

declare(strict_types=1);

// Laravel Authentication

// config/hashing.php
/*
return [
    'driver' => 'argon2id',  // Use Argon2id
    'argon' => [
        'memory' => 65536,
        'threads' => 1,
        'time' => 4,
    ],
];
*/

// Rate limiting in RouteServiceProvider or bootstrap/app.php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

// Define rate limiter
RateLimiter::for('login', function (Request $request) {
    return Limit::perMinute(5)->by($request->ip() . '|' . $request->input('email'));
});

// Apply to route
// Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:login');

// Gate and Policy authorization
use Illuminate\Support\Facades\Gate;

// Define gate
Gate::define('update-document', function (User $user, Document $document): bool {
    return $user->id === $document->user_id;
});

// Policy method
final class DocumentPolicy
{
    public function update(User $user, Document $document): bool
    {
        return $user->id === $document->user_id;
    }

    public function delete(User $user, Document $document): bool
    {
        return $user->id === $document->user_id || $user->isAdmin();
    }
}

// Usage in controller
// $this->authorize('update', $document);
```

---

## Detection Patterns

Use these patterns during security audits to identify authentication weaknesses.

### Insecure Password Hashing

```bash
# Detect md5/sha1 used for password hashing
grep -rn "md5(\$.*pass" --include="*.php" src/ Classes/
grep -rn "sha1(\$.*pass" --include="*.php" src/ Classes/
grep -rn "hash('md5'" --include="*.php" src/ Classes/
grep -rn "hash('sha1'" --include="*.php" src/ Classes/
grep -rn "hash('sha256'.*\$.*pass" --include="*.php" src/ Classes/
grep -rn 'crypt(\$' --include="*.php" src/ Classes/

# Detect missing password_needs_rehash (algorithm upgrade support)
# If password_verify is used but password_needs_rehash is never called, flag it
grep -rn "password_verify" --include="*.php" src/ Classes/
grep -rn "password_needs_rehash" --include="*.php" src/ Classes/
```

### Session Security Issues

```bash
# Detect missing session_regenerate_id after authentication
grep -rn "session_start" --include="*.php" src/ Classes/
grep -rn "session_regenerate_id" --include="*.php" src/ Classes/

# Detect insecure session configuration
grep -rn "session.cookie_httponly.*0\|session.cookie_httponly.*Off" --include="*.ini" .
grep -rn "session.cookie_secure.*0\|session.cookie_secure.*Off" --include="*.ini" .
grep -rn "session.use_only_cookies.*0" --include="*.ini" .
grep -rn "session.use_trans_sid.*1" --include="*.ini" .
```

### Timing-Unsafe Comparisons

```bash
# Detect direct comparison of tokens/hashes (should use hash_equals)
grep -rn "===.*\$.*token\|===.*\$.*hash\|===.*\$.*hmac" --include="*.php" src/ Classes/
grep -rn "strcmp.*token\|strcmp.*hash" --include="*.php" src/ Classes/

# Verify hash_equals is used for sensitive comparisons
grep -rn "hash_equals" --include="*.php" src/ Classes/
```

### JWT Vulnerabilities

```bash
# Detect JWT libraries and verify algorithm pinning
grep -rn "JWT::decode" --include="*.php" src/ Classes/
grep -rn "new Key(" --include="*.php" src/ Classes/
grep -rn "'none'" --include="*.php" src/ Classes/ | grep -i jwt
grep -rn "alg.*HS256.*RS256\|alg.*none" --include="*.php" src/ Classes/
```

### Missing MFA

```bash
# Check if MFA/2FA is implemented
grep -rn "totp\|two.factor\|2fa\|mfa\|otp" -i --include="*.php" src/ Classes/
grep -rn "OTPHP\|TwoFactor\|GoogleAuthenticator" --include="*.php" src/ Classes/
```

---

## Testing Patterns

### Password Hashing Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class PasswordHashingTest extends TestCase
{
    public function testPasswordUsesArgon2idOrBcrypt(): void
    {
        $password = 'test-password-123';
        $hash = password_hash($password, PASSWORD_ARGON2ID);

        // Verify hash uses Argon2id
        self::assertStringStartsWith('$argon2id$', $hash);
        self::assertTrue(password_verify($password, $hash));
    }

    public function testPasswordNeedsRehashDetectsOutdatedAlgorithm(): void
    {
        $password = 'test-password-123';

        // Simulate a hash created with bcrypt (old algorithm)
        $bcryptHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);

        // password_needs_rehash should return true when checking against Argon2id
        self::assertTrue(
            password_needs_rehash($bcryptHash, PASSWORD_ARGON2ID),
        );
    }

    public function testHashEqualsTimingSafe(): void
    {
        $expected = bin2hex(random_bytes(32));
        $correct = $expected;
        $incorrect = bin2hex(random_bytes(32));

        self::assertTrue(hash_equals($expected, $correct));
        self::assertFalse(hash_equals($expected, $incorrect));
    }
}
```

### Session Security Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class SessionSecurityTest extends TestCase
{
    public function testSessionRegeneratesIdAfterLogin(): void
    {
        // Simulate session
        $oldSessionId = session_create_id();

        // After login, session ID should change
        session_regenerate_id(true);
        $newSessionId = session_id();

        self::assertNotSame($oldSessionId, $newSessionId);
    }

    public function testSessionCookieConfiguration(): void
    {
        $params = session_get_cookie_params();

        self::assertTrue($params['httponly'], 'Session cookie must be httponly');
        self::assertTrue($params['secure'], 'Session cookie must be secure');
        self::assertContains(
            $params['samesite'],
            ['Lax', 'Strict'],
            'Session cookie must have SameSite attribute',
        );
    }
}
```

### Rate Limiting Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class RateLimitingTest extends TestCase
{
    public function testBlocksAfterMaxAttempts(): void
    {
        $cache = new ArrayCache();
        $logger = new NullLogger();
        $limiter = new AuthenticationRateLimiter($cache, $logger);

        $username = 'testuser';
        $ip = '192.168.1.1';

        // Record 5 failures (the per-user maximum)
        for ($i = 0; $i < 5; $i++) {
            $limiter->recordFailure($username, $ip);
        }

        // The next check should throw
        $this->expectException(TooManyAttemptsException::class);
        $limiter->checkLimits($username, $ip);
    }

    public function testClearsUserCounterOnSuccess(): void
    {
        $cache = new ArrayCache();
        $logger = new NullLogger();
        $limiter = new AuthenticationRateLimiter($cache, $logger);

        $username = 'testuser';
        $ip = '192.168.1.1';

        // Record 3 failures
        for ($i = 0; $i < 3; $i++) {
            $limiter->recordFailure($username, $ip);
        }

        // Successful login clears user counter
        $limiter->clearOnSuccess($username, $ip);

        // Should not throw -- user counter was reset
        $limiter->checkLimits($username, $ip);

        // This assertion passes if no exception was thrown
        self::assertTrue(true);
    }
}
```

---

## Remediation Priority

| Severity | Finding | Timeline |
|----------|---------|----------|
| Critical | MD5/SHA1 password hashing | Immediate |
| Critical | Missing session regeneration after login | Immediate |
| Critical | JWT algorithm confusion vulnerability | Immediate |
| High | No rate limiting on authentication endpoints | 24 hours |
| High | Missing account lockout | 24 hours |
| High | Timing-unsafe token comparison | 48 hours |
| Medium | No password rehashing on algorithm upgrade | 1 week |
| Medium | Missing MFA support | 2 weeks |
| Medium | Insecure session cookie configuration | 1 week |
| Low | No idle session timeout | 2 weeks |

---

## Related References

- `owasp-top10.md` -- A07:2021 Identification and Authentication Failures
- `api-key-encryption.md` -- Secure key storage patterns
- `security-logging.md` -- Logging authentication events
- PHP password hashing: https://www.php.net/manual/en/function.password-hash.php
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
