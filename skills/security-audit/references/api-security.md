# API Security Reference (OWASP API Top 10 - 2025)

## Overview

APIs are the backbone of modern web and mobile applications, exposing business logic
and sensitive data over HTTP. The OWASP API Security Top 10 (2025) identifies the most
critical API-specific risks. This reference covers detection patterns, vulnerable and
secure code examples (primarily PHP), and prevention strategies for each category, along
with GraphQL-specific and REST-specific security concerns.

---

## OWASP API Top 10 (2025)

### API1:2025 - Broken Object-Level Authorization (BOLA)

BOLA occurs when an API endpoint accepts an object identifier from the client and fails
to verify that the authenticated user has permission to access the referenced object.
This is the most prevalent and impactful API vulnerability.

#### Detection Patterns

- Endpoints that accept resource IDs (e.g., `/api/v1/orders/{id}`) without ownership checks
- Controllers that call `find($id)` or `findOneBy(['id' => $id])` without scoping to the current user
- Missing authorization middleware or voter/policy checks on resource retrieval
- Sequential/predictable resource IDs that invite enumeration

```php
<?php

declare(strict_types=1);

// VULNERABLE: Direct object reference without authorization
// Any authenticated user can access any order by changing the ID
class OrderController
{
    public function show(int $id): JsonResponse
    {
        $order = $this->orderRepository->find($id);

        if ($order === null) {
            return new JsonResponse(['error' => 'Not found'], 404);
        }

        return new JsonResponse($order->toArray());
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Scoped query - only retrieves orders belonging to the authenticated user
class OrderController
{
    public function show(int $id, Request $request): JsonResponse
    {
        $user = $request->getAttribute('authenticated_user');

        $order = $this->orderRepository->findOneBy([
            'id' => $id,
            'userId' => $user->getId(),
        ]);

        if ($order === null) {
            return new JsonResponse(['error' => 'Not found'], 404);
        }

        return new JsonResponse($order->toArray());
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Authorization voter pattern (Symfony)
class OrderController extends AbstractController
{
    #[Route('/api/orders/{id}', methods: ['GET'])]
    public function show(Order $order): JsonResponse
    {
        $this->denyAccessUnlessGranted('VIEW', $order);

        return $this->json($order, context: ['groups' => 'order:read']);
    }
}

// Corresponding voter
class OrderVoter extends Voter
{
    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof Order && in_array($attribute, ['VIEW', 'EDIT', 'DELETE'], true);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        return match ($attribute) {
            'VIEW', 'EDIT', 'DELETE' => $subject->getOwner() === $user,
            default => false,
        };
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Laravel policy pattern
class OrderPolicy
{
    public function view(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }

    public function update(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}

// Controller using the policy
class OrderController extends Controller
{
    public function show(Order $order): JsonResponse
    {
        $this->authorize('view', $order);

        return response()->json($order);
    }
}
```

#### Scoped Queries Pattern

A repository-level approach ensures every query is scoped automatically, removing the
risk of developers forgetting authorization checks on individual endpoints.

```php
<?php

declare(strict_types=1);

// SECURE: Repository that always scopes queries to the current user
final class ScopedOrderRepository
{
    public function __construct(
        private readonly EntityManagerInterface $em,
        private readonly Security $security,
    ) {}

    public function find(int $id): ?Order
    {
        $user = $this->security->getUser()
            ?? throw new AccessDeniedException('Authentication required');

        return $this->em->getRepository(Order::class)->findOneBy([
            'id' => $id,
            'owner' => $user,
        ]);
    }

    /**
     * @return Order[]
     */
    public function findAll(): array
    {
        $user = $this->security->getUser()
            ?? throw new AccessDeniedException('Authentication required');

        return $this->em->getRepository(Order::class)->findBy([
            'owner' => $user,
        ]);
    }
}
```

---

### API2:2025 - Broken Authentication

API authentication differs from traditional web authentication. APIs typically rely on
tokens (JWT, API keys, OAuth2 bearer tokens) rather than session cookies. Weaknesses
include missing token expiration, weak token generation, insecure token storage, and
lack of proper token validation.

#### Detection Patterns

- API keys transmitted in URL query parameters (logged in server/proxy logs)
- Missing or excessively long JWT `exp` claims
- JWTs signed with weak secrets or using the `none` algorithm
- API keys that never expire and cannot be rotated
- Missing brute-force protection on authentication endpoints
- Tokens not validated on every request

```php
<?php

declare(strict_types=1);

// VULNERABLE: API key in URL query parameter - appears in access logs, browser history, referer headers
// GET /api/data?api_key=sk_live_abc123
$apiKey = $_GET['api_key'] ?? '';
```

```php
<?php

declare(strict_types=1);

// SECURE: API key in Authorization header
// Authorization: Bearer sk_live_abc123
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$apiKey = '';
if (str_starts_with($authHeader, 'Bearer ')) {
    $apiKey = substr($authHeader, 7);
}
```

```php
<?php

declare(strict_types=1);

// VULNERABLE: JWT with no expiration, weak secret, and (on older firebase/php-jwt <6.0)
// no algorithm enforcement. On modern firebase/php-jwt (>=6.0) the Key object
// pins the algorithm, so the primary issues here are the missing `exp` claim
// and the guessable secret.
use Firebase\JWT\JWT;

$payload = [
    'sub' => $user->getId(),
    'name' => $user->getName(),
    // No 'exp' claim — token never expires.
];
$token = JWT::encode($payload, 'secret123', 'HS256'); // Short, guessable secret

// Decoding. On firebase/php-jwt >=6.0 the Key object pins the algorithm
// (so "alg:none" forgery is not possible). On older libraries or when the
// second argument is just a string, the algorithm is not enforced and an
// attacker can forge tokens by setting `"alg": "none"` in the header.
```

```php
<?php

declare(strict_types=1);

// SECURE: JWT with proper expiration, strong secret, algorithm enforcement
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

final class TokenService
{
    private const int ACCESS_TOKEN_TTL = 900;    // 15 minutes
    private const int REFRESH_TOKEN_TTL = 604800; // 7 days

    public function __construct(
        private readonly string $secretKey, // At least 256 bits from secure random source
    ) {}

    public function createAccessToken(User $user): string
    {
        $now = time();

        return JWT::encode([
            'iss' => 'https://api.example.com',
            'sub' => $user->getId(),
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + self::ACCESS_TOKEN_TTL,
            'jti' => bin2hex(random_bytes(16)), // Unique token ID for revocation
        ], $this->secretKey, 'HS256');
    }

    public function validateToken(string $token): object
    {
        // Explicitly specify allowed algorithms to prevent "none" algorithm attack
        return JWT::decode($token, new Key($this->secretKey, 'HS256'));
    }
}
```

```php
<?php

declare(strict_types=1);

// VULNERABLE: Weak API key generation
$apiKey = md5(uniqid()); // Predictable, only 128 bits of entropy from poor source
$apiKey = base64_encode($userId . ':' . time()); // Trivially guessable

// SECURE: Cryptographically strong API key generation
$apiKey = bin2hex(random_bytes(32)); // 256 bits of cryptographic randomness
$hashedKey = hash('sha256', $apiKey); // Store only the hash in the database
```

---

### API3:2025 - Broken Object Property Level Authorization

This category combines two former issues: mass assignment (accepting all fields from
the request body) and excessive data exposure (returning more data than the client
needs). APIs should only accept known, allowed fields on input and return only the
fields the client is authorized to see.

#### Mass Assignment

```php
<?php

declare(strict_types=1);

// VULNERABLE: Mass assignment - accepting all request fields directly
class UserController
{
    public function update(Request $request, int $id): JsonResponse
    {
        $user = $this->userRepository->find($id);

        // Attacker can send {"role": "admin", "is_verified": true} in the request body
        foreach ($request->toArray() as $key => $value) {
            $setter = 'set' . ucfirst($key);
            if (method_exists($user, $setter)) {
                $user->$setter($value);
            }
        }

        $this->em->flush();

        return new JsonResponse($user->toArray());
    }
}
```

```php
<?php

declare(strict_types=1);

// VULNERABLE: Laravel mass assignment without $fillable
class User extends Model
{
    // No $fillable or $guarded defined - all columns assignable
}

// Attacker sends POST with {"name": "Alice", "is_admin": true}
$user = User::create($request->all());
```

```php
<?php

declare(strict_types=1);

// SECURE: Explicit allowlist of updatable fields
class UserController
{
    private const array ALLOWED_UPDATE_FIELDS = ['name', 'email', 'bio'];

    public function update(Request $request, int $id): JsonResponse
    {
        $user = $this->userRepository->find($id);
        $data = $request->toArray();

        foreach (self::ALLOWED_UPDATE_FIELDS as $field) {
            if (array_key_exists($field, $data)) {
                $setter = 'set' . ucfirst($field);
                $user->$setter($data[$field]);
            }
        }

        $this->em->flush();

        return new JsonResponse($user->toArray());
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Laravel with explicit $fillable
class User extends Model
{
    protected $fillable = ['name', 'email', 'bio'];

    // 'role', 'is_admin', 'email_verified_at' are NOT fillable
}
```

#### Excessive Data Exposure

```php
<?php

declare(strict_types=1);

// VULNERABLE: Returning entire model including sensitive fields
class UserController
{
    public function show(int $id): JsonResponse
    {
        $user = $this->userRepository->find($id);

        // Exposes password_hash, internal_notes, ssn, etc.
        return new JsonResponse($user->toArray());
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: DTO pattern - only expose intended fields
final readonly class UserPublicDto
{
    public function __construct(
        public int $id,
        public string $name,
        public string $email,
        public string $createdAt,
    ) {}

    public static function fromEntity(User $user): self
    {
        return new self(
            id: $user->getId(),
            name: $user->getName(),
            email: $user->getEmail(),
            createdAt: $user->getCreatedAt()->format('c'),
        );
    }
}

class UserController
{
    public function show(int $id): JsonResponse
    {
        $user = $this->userRepository->find($id);

        return new JsonResponse(UserPublicDto::fromEntity($user));
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Symfony serialization groups
use Symfony\Component\Serializer\Annotation\Groups;

class User
{
    #[Groups(['user:read', 'user:admin'])]
    private int $id;

    #[Groups(['user:read', 'user:admin'])]
    private string $name;

    #[Groups(['user:admin'])]  // Only visible to admin API consumers
    private string $internalNotes;

    #[Groups([])]  // Never serialized
    private string $passwordHash;
}

// In controller: serialize with appropriate group
return $this->json($user, context: ['groups' => 'user:read']);
```

---

### API4:2025 - Unrestricted Resource Consumption

APIs that do not limit request rates, payload sizes, pagination, or query complexity
are vulnerable to denial-of-service attacks and resource exhaustion. Attackers can
send large payloads, request massive result sets, or flood endpoints with requests.

#### Detection Patterns

- No rate limiting middleware on any endpoint
- Pagination without maximum page size enforcement
- No request body size limits
- No query complexity or depth limits (especially GraphQL)
- Expensive operations (search, export, report generation) without throttling

```php
<?php

declare(strict_types=1);

// VULNERABLE: No rate limiting, no pagination limit
class ProductController
{
    public function list(Request $request): JsonResponse
    {
        $page = (int) ($request->query->get('page', 1));
        $limit = (int) ($request->query->get('limit', 10));

        // Attacker sends ?limit=1000000 to dump entire database
        $products = $this->repository->findBy([], null, $limit, ($page - 1) * $limit);

        return new JsonResponse($products);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Enforced pagination limits
class ProductController
{
    private const int MAX_PAGE_SIZE = 100;
    private const int DEFAULT_PAGE_SIZE = 20;

    public function list(Request $request): JsonResponse
    {
        $page = max(1, (int) ($request->query->get('page', 1)));
        $limit = min(
            self::MAX_PAGE_SIZE,
            max(1, (int) ($request->query->get('limit', self::DEFAULT_PAGE_SIZE)))
        );

        $products = $this->repository->findBy([], null, $limit, ($page - 1) * $limit);
        $total = $this->repository->count([]);

        return new JsonResponse([
            'data' => $products,
            'meta' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'pages' => (int) ceil($total / $limit),
            ],
        ]);
    }
}
```

#### Rate Limiting Middleware

```php
<?php

declare(strict_types=1);

// SECURE: Token bucket rate limiter middleware
final class RateLimitMiddleware
{
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int $maxRequests = 60,
        private readonly int $windowSeconds = 60,
    ) {}

    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        $identifier = $this->getClientIdentifier($request);
        $key = 'rate_limit:' . $identifier;

        $current = (int) $this->cache->get($key, fn () => 0);

        if ($current >= $this->maxRequests) {
            return new JsonResponse(
                ['error' => 'Rate limit exceeded', 'retry_after' => $this->windowSeconds],
                429,
                ['Retry-After' => (string) $this->windowSeconds]
            );
        }

        $this->cache->set($key, $current + 1, $this->windowSeconds);

        $response = $handler->handle($request);

        return $response->withHeader('X-RateLimit-Limit', (string) $this->maxRequests)
            ->withHeader('X-RateLimit-Remaining', (string) ($this->maxRequests - $current - 1));
    }

    private function getClientIdentifier(Request $request): string
    {
        // Prefer authenticated user ID; fall back to IP
        $user = $request->getAttribute('authenticated_user');
        if ($user !== null) {
            return 'user:' . $user->getId();
        }

        return 'ip:' . $request->getClientIp();
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Symfony rate limiter configuration
// config/packages/rate_limiter.yaml equivalent in PHP
use Symfony\Component\RateLimiter\RateLimiterFactory;

// Fixed window: 100 requests per minute
$apiLimiter = new RateLimiterFactory([
    'id' => 'api',
    'policy' => 'fixed_window',
    'limit' => 100,
    'interval' => '1 minute',
], $cacheStorage);

// Sliding window: 1000 requests per hour (smoother distribution)
$searchLimiter = new RateLimiterFactory([
    'id' => 'api_search',
    'policy' => 'sliding_window',
    'limit' => 1000,
    'interval' => '1 hour',
], $cacheStorage);
```

---

### API5:2025 - Broken Function-Level Authorization

This vulnerability occurs when administrative or privileged endpoints are accessible
to regular users. APIs often expose a larger attack surface than web UIs because they
may have admin-only routes that are not hidden behind a UI element.

#### Detection Patterns

- Admin endpoints (e.g., `/api/admin/users`) accessible without admin role check
- Different authorization requirements per HTTP method not enforced (GET allowed, but DELETE should be restricted)
- Endpoints relying on client-side role checks or UI hiding instead of server-side enforcement
- Missing role/permission middleware on route groups

```php
<?php

declare(strict_types=1);

// VULNERABLE: No role check on admin endpoint
#[Route('/api/admin/users', methods: ['GET'])]
public function listAllUsers(): JsonResponse
{
    // Any authenticated user can access the admin user list
    $users = $this->userRepository->findAll();

    return $this->json($users);
}

// VULNERABLE: HTTP method not restricted - GET is allowed but DELETE should require admin
#[Route('/api/users/{id}', methods: ['GET', 'PUT', 'DELETE'])]
public function handleUser(int $id, Request $request): JsonResponse
{
    $user = $this->userRepository->find($id);

    return match ($request->getMethod()) {
        'GET' => $this->json($user),
        'PUT' => $this->updateUser($user, $request),
        'DELETE' => $this->deleteUser($user), // No admin check!
        default => new JsonResponse(null, 405),
    };
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Role-based middleware on route groups (Symfony)
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/admin')]
#[IsGranted('ROLE_ADMIN')]
class AdminUserController extends AbstractController
{
    #[Route('/users', methods: ['GET'])]
    public function listAllUsers(): JsonResponse
    {
        return $this->json($this->userRepository->findAll(), context: ['groups' => 'admin:read']);
    }

    #[Route('/users/{id}', methods: ['DELETE'])]
    public function deleteUser(User $user): JsonResponse
    {
        $this->em->remove($user);
        $this->em->flush();

        return new JsonResponse(null, 204);
    }
}

// SECURE: Per-method authorization
#[Route('/api/users/{id}')]
class UserController extends AbstractController
{
    #[Route(methods: ['GET'])]
    public function show(User $user): JsonResponse
    {
        $this->denyAccessUnlessGranted('VIEW', $user);

        return $this->json($user, context: ['groups' => 'user:read']);
    }

    #[Route(methods: ['DELETE'])]
    #[IsGranted('ROLE_ADMIN')]
    public function delete(User $user): JsonResponse
    {
        $this->em->remove($user);
        $this->em->flush();

        return new JsonResponse(null, 204);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Laravel middleware on route groups
// routes/api.php
Route::middleware(['auth:sanctum', 'role:admin'])->prefix('admin')->group(function () {
    Route::get('/users', [AdminUserController::class, 'index']);
    Route::delete('/users/{user}', [AdminUserController::class, 'destroy']);
});

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/users/{user}', [UserController::class, 'show']);
    // DELETE is not available here for regular users
});
```

---

### API6:2025 - Unrestricted Access to Sensitive Business Flows

Some business flows (account registration, purchasing, coupon redemption, password
reset) are sensitive to automated abuse even when each individual request is
technically authorized. Protection requires understanding the business context and
implementing anti-automation measures.

#### Detection Patterns

- High-value endpoints without CAPTCHA or proof-of-work
- Coupon/discount endpoints without per-user limits
- Registration/signup without email verification throttling
- Checkout/purchase flows without device fingerprinting or velocity checks
- Ticket/reservation systems vulnerable to scalping bots

```php
<?php

declare(strict_types=1);

// VULNERABLE: Coupon redemption with no per-user or per-coupon limits
class CouponController
{
    public function redeem(Request $request): JsonResponse
    {
        $code = $request->toArray()['code'];
        $coupon = $this->couponRepository->findOneBy(['code' => $code, 'active' => true]);

        if ($coupon === null) {
            return new JsonResponse(['error' => 'Invalid coupon'], 400);
        }

        // No check if user already used this coupon
        // No check on total redemption count
        $this->applyDiscount($coupon, $request->getAttribute('authenticated_user'));

        return new JsonResponse(['message' => 'Coupon applied']);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Business logic protections against automation abuse
class CouponController
{
    public function __construct(
        private readonly CouponRepository $couponRepository,
        private readonly RedemptionRepository $redemptionRepository,
        private readonly CaptchaVerifier $captchaVerifier,
        private readonly RateLimiterFactory $rateLimiter,
    ) {}

    public function redeem(Request $request): JsonResponse
    {
        $user = $request->getAttribute('authenticated_user');
        $data = $request->toArray();

        // Anti-automation: verify CAPTCHA on sensitive operations
        if (!$this->captchaVerifier->verify($data['captcha_token'] ?? '')) {
            return new JsonResponse(['error' => 'CAPTCHA verification failed'], 400);
        }

        // Rate limit: max 5 coupon attempts per user per hour
        $limiter = $this->rateLimiter->create('coupon_redeem:' . $user->getId());
        if (!$limiter->consume()->isAccepted()) {
            return new JsonResponse(['error' => 'Too many attempts'], 429);
        }

        $coupon = $this->couponRepository->findOneBy([
            'code' => $data['code'],
            'active' => true,
        ]);

        if ($coupon === null) {
            return new JsonResponse(['error' => 'Invalid coupon'], 400);
        }

        // Per-user redemption check
        $existingRedemption = $this->redemptionRepository->findOneBy([
            'coupon' => $coupon,
            'user' => $user,
        ]);

        if ($existingRedemption !== null) {
            return new JsonResponse(['error' => 'Coupon already used'], 400);
        }

        // Global redemption limit check
        $totalRedemptions = $this->redemptionRepository->count(['coupon' => $coupon]);
        if ($totalRedemptions >= $coupon->getMaxRedemptions()) {
            return new JsonResponse(['error' => 'Coupon limit reached'], 400);
        }

        $this->applyDiscount($coupon, $user);

        return new JsonResponse(['message' => 'Coupon applied']);
    }
}
```

---

### API7:2025 - Server-Side Request Forgery (SSRF)

SSRF in APIs occurs when an endpoint accepts a URL or network address from the client
and makes a server-side request without proper validation. This is especially dangerous
in cloud environments where metadata endpoints can expose credentials.

For comprehensive SSRF coverage including cloud metadata attacks, DNS rebinding,
redirect-based bypasses, and secure URL validation patterns, see
**[modern-attacks.md](modern-attacks.md)**.

#### Key API-Specific SSRF Patterns

```php
<?php

declare(strict_types=1);

// VULNERABLE: Webhook registration with no URL validation
class WebhookController
{
    public function register(Request $request): JsonResponse
    {
        $url = $request->toArray()['callback_url'];

        // Attacker registers http://169.254.169.254/latest/meta-data/ as callback
        $webhook = new Webhook($url, $request->getAttribute('authenticated_user'));
        $this->em->persist($webhook);
        $this->em->flush();

        return new JsonResponse(['id' => $webhook->getId()], 201);
    }
}

// VULNERABLE: Image/avatar URL fetch
class AvatarController
{
    public function importFromUrl(Request $request): JsonResponse
    {
        $url = $request->toArray()['avatar_url'];
        $imageData = file_get_contents($url); // SSRF - fetches any URL

        return new JsonResponse(['avatar' => base64_encode($imageData)]);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Validate webhook URLs against allowlist and block internal networks
class WebhookController
{
    public function register(Request $request): JsonResponse
    {
        $url = $request->toArray()['callback_url'];

        if (!$this->urlValidator->isAllowedExternalUrl($url)) {
            return new JsonResponse(['error' => 'Invalid callback URL'], 400);
        }

        $webhook = new Webhook($url, $request->getAttribute('authenticated_user'));
        $this->em->persist($webhook);
        $this->em->flush();

        return new JsonResponse(['id' => $webhook->getId()], 201);
    }
}
```

---

### API8:2025 - Security Misconfiguration

Security misconfiguration in APIs encompasses CORS misconfigurations, verbose error
responses, unnecessary HTTP methods, missing security headers, and debug modes left
enabled in production.

#### CORS Misconfiguration

```php
<?php

declare(strict_types=1);

// VULNERABLE: Wildcard CORS with credentials - browsers block this, but misconfiguration
// often manifests as reflecting the Origin header without validation
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true'); // Browsers reject * with credentials

// VULNERABLE: Reflecting arbitrary Origin header
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
header('Access-Control-Allow-Origin: ' . $origin); // Reflects any origin
header('Access-Control-Allow-Credentials: true');
```

```php
<?php

declare(strict_types=1);

// SECURE: Explicit origin allowlist
final class CorsMiddleware
{
    private const array ALLOWED_ORIGINS = [
        'https://app.example.com',
        'https://admin.example.com',
    ];

    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        $origin = $request->getHeaderLine('Origin');

        if ($request->getMethod() === 'OPTIONS') {
            $response = new Response(204);
        } else {
            $response = $handler->handle($request);
        }

        if (in_array($origin, self::ALLOWED_ORIGINS, true)) {
            $response = $response
                ->withHeader('Access-Control-Allow-Origin', $origin)
                ->withHeader('Access-Control-Allow-Credentials', 'true')
                ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
                ->withHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
                ->withHeader('Access-Control-Max-Age', '86400');
        }

        return $response;
    }
}
```

#### Verbose Error Responses

```php
<?php

declare(strict_types=1);

// VULNERABLE: Leaking stack traces and internal details in production
class ErrorHandler
{
    public function handle(\Throwable $e): JsonResponse
    {
        return new JsonResponse([
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString(),     // Exposes internal file paths
            'file' => $e->getFile(),                 // Exposes server directory structure
            'query' => $this->lastQuery,             // Exposes SQL queries
        ], 500);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Environment-aware error handling
class ErrorHandler
{
    public function __construct(
        private readonly string $environment,
        private readonly LoggerInterface $logger,
    ) {}

    public function handle(\Throwable $e): JsonResponse
    {
        $errorId = bin2hex(random_bytes(8));
        $this->logger->error('API error', [
            'error_id' => $errorId,
            'exception' => $e,
        ]);

        if ($this->environment === 'dev') {
            return new JsonResponse([
                'error' => $e->getMessage(),
                'error_id' => $errorId,
                'trace' => $e->getTraceAsString(),
            ], 500);
        }

        // Production: generic message with correlation ID
        return new JsonResponse([
            'error' => 'An internal error occurred',
            'error_id' => $errorId,
        ], 500);
    }
}
```

#### Unnecessary HTTP Methods

```php
<?php

declare(strict_types=1);

// VULNERABLE: Catch-all route responds to any HTTP method
#[Route('/api/users/{id}')]
public function handleUser(Request $request, int $id): JsonResponse
{
    // TRACE and other methods are accepted
    // ...
}

// SECURE: Explicit method restrictions
#[Route('/api/users/{id}', methods: ['GET', 'PUT'])]
public function handleUser(Request $request, int $id): JsonResponse
{
    // Only GET and PUT accepted; all others return 405 Method Not Allowed
    // ...
}
```

#### Missing Security Headers

API responses should include security headers even for JSON responses. See
**[security-headers.md](security-headers.md)** for a comprehensive header reference.

Key headers for API responses:

```
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
Cache-Control: no-store
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
```

---

### API9:2025 - Improper Inventory Management

APIs evolve over time, and older versions may remain accessible with known
vulnerabilities. Undocumented or forgotten endpoints (shadow APIs), debug endpoints,
and deprecated versions create a hidden attack surface.

#### Detection Patterns

- Multiple API versions accessible simultaneously (e.g., `/api/v1/`, `/api/v2/`)
- Older versions lacking security fixes applied to newer versions
- Undocumented endpoints discoverable via brute-force or documentation leaks
- Debug/test endpoints left in production (`/api/debug`, `/api/test`, `/_profiler`)
- API documentation out of sync with actual endpoints
- Different host environments (staging, sandbox) sharing production data

```php
<?php

declare(strict_types=1);

// VULNERABLE: Old API version still active with known vulnerability
// /api/v1/users - no rate limiting, no auth, returns sensitive fields
// /api/v2/users - properly secured with auth, rate limiting, and field filtering
// v1 was never decommissioned

// VULNERABLE: Debug endpoint left in production
#[Route('/api/debug/phpinfo')]
public function debugInfo(): Response
{
    ob_start();
    phpinfo();
    $info = ob_get_clean();

    return new Response($info);
}

// VULNERABLE: Test endpoint with hardcoded credentials
#[Route('/api/test/login')]
public function testLogin(): JsonResponse
{
    $token = $this->auth->login('admin@example.com', 'test123');

    return new JsonResponse(['token' => $token]);
}
```

```php
<?php

declare(strict_types=1);

// SECURE: API version deprecation middleware
final class ApiVersionMiddleware
{
    private const array SUPPORTED_VERSIONS = ['v3', 'v2'];
    private const array DEPRECATED_VERSIONS = ['v2'];
    private const array REMOVED_VERSIONS = ['v1'];

    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        $version = $this->extractVersion($request->getUri()->getPath());

        if (in_array($version, self::REMOVED_VERSIONS, true)) {
            return new JsonResponse([
                'error' => 'This API version has been removed',
                'migration_guide' => 'https://docs.example.com/api/migration',
            ], 410); // 410 Gone
        }

        $response = $handler->handle($request);

        if (in_array($version, self::DEPRECATED_VERSIONS, true)) {
            $response = $response
                ->withHeader('Deprecation', 'true')
                ->withHeader('Sunset', 'Sat, 01 Jun 2025 00:00:00 GMT')
                ->withHeader('Link', '<https://api.example.com/v3>; rel="successor-version"');
        }

        return $response;
    }

    private function extractVersion(string $path): string
    {
        if (preg_match('#/api/(v\d+)/#', $path, $matches)) {
            return $matches[1];
        }

        return 'unknown';
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Ensure debug/test routes are environment-gated
if ($_ENV['APP_ENV'] === 'dev') {
    $router->addRoute('GET', '/api/debug/routes', [DebugController::class, 'routes']);
}

// In Symfony: use the when() condition
// config/routes/dev/debug.yaml (only loaded in dev environment)
```

---

### API10:2025 - Unsafe Consumption of APIs

When your API consumes data from third-party APIs, it must treat that data as
untrusted input. Third-party APIs can be compromised, return unexpected data, or
be subject to man-in-the-middle attacks if TLS is not enforced.

#### Detection Patterns

- Third-party API responses used directly without validation or sanitization
- Missing TLS certificate verification on outbound HTTP calls
- No timeout configuration on outbound requests
- Third-party responses rendered without escaping
- API responses deserialized into objects without schema validation

```php
<?php

declare(strict_types=1);

// VULNERABLE: Trusting third-party API response without validation
class PaymentService
{
    public function processPayment(Order $order): void
    {
        $response = $this->httpClient->request('POST', 'https://payment-provider.com/charge', [
            'json' => ['amount' => $order->getTotal(), 'currency' => 'USD'],
        ]);

        $data = json_decode($response->getBody()->getContents(), true);

        // Blindly trusting the response
        $order->setStatus($data['status']);           // Could be any string
        $order->setTransactionId($data['tx_id']);     // Could contain injection payload
        $order->setAmountCharged($data['charged']);   // Could differ from requested amount
        $this->em->flush();
    }
}

// VULNERABLE: Disabling SSL verification
$response = $this->httpClient->request('GET', $url, [
    'verify' => false, // Man-in-the-middle attack possible
]);
```

```php
<?php

declare(strict_types=1);

// SECURE: Validate and sanitize third-party API responses
class PaymentService
{
    public function processPayment(Order $order): void
    {
        $response = $this->httpClient->request('POST', 'https://payment-provider.com/charge', [
            'json' => ['amount' => $order->getTotal(), 'currency' => 'USD'],
            'verify' => true,          // Enforce TLS (default, but explicit is good)
            'timeout' => 10,           // Prevent hung connections
            'connect_timeout' => 5,
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new PaymentException('Payment API returned non-200 status');
        }

        $data = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);

        // Validate response schema
        $status = $data['status'] ?? null;
        if (!in_array($status, ['success', 'failed', 'pending'], true)) {
            throw new PaymentException('Unexpected payment status: ' . var_export($status, true));
        }

        $txId = $data['tx_id'] ?? null;
        if (!is_string($txId) || !preg_match('/^[a-zA-Z0-9_-]{10,64}$/', $txId)) {
            throw new PaymentException('Invalid transaction ID format');
        }

        $charged = $data['charged'] ?? null;
        if (!is_numeric($charged) || (float) $charged !== (float) $order->getTotal()) {
            throw new PaymentException('Charged amount does not match order total');
        }

        $order->setStatus($status);
        $order->setTransactionId($txId);
        $order->setAmountCharged((float) $charged);
        $this->em->flush();
    }
}
```

---

## GraphQL-Specific Security

GraphQL APIs introduce unique security concerns due to their flexible query language.
Unlike REST, a single GraphQL endpoint can serve arbitrary query shapes, which
amplifies several attack vectors.

### Introspection Enabled in Production

GraphQL introspection allows clients to query the schema itself, revealing all types,
fields, mutations, and their arguments. This is invaluable during development but
exposes the full API surface in production.

```php
<?php

declare(strict_types=1);

// VULNERABLE: Introspection enabled in production
// An attacker can send: { __schema { types { name fields { name type { name } } } } }
// This reveals every type, field, and relationship in the API

// SECURE: Disable introspection in production (webonyx/graphql-php)
use GraphQL\GraphQL;
use GraphQL\Validator\Rules\DisableIntrospection;
use GraphQL\Validator\DocumentValidator;

if ($_ENV['APP_ENV'] === 'prod') {
    DocumentValidator::addRule(new DisableIntrospection());
}
```

### Query Depth and Complexity Limits

Deeply nested or complex queries can cause exponential database load.

```graphql
# VULNERABLE: Deeply nested query causing N+1 and exponential load
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                # ...infinite nesting
              }
            }
          }
        }
      }
    }
  }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Enforce query depth and complexity limits (webonyx/graphql-php)
use GraphQL\GraphQL;
use GraphQL\Validator\DocumentValidator;
use GraphQL\Validator\Rules\QueryDepth;
use GraphQL\Validator\Rules\QueryComplexity;

$validationRules = array_merge(
    DocumentValidator::defaultRules(),
    [
        new QueryDepth(7),           // Maximum nesting depth of 7
        new QueryComplexity(200),    // Maximum query complexity score of 200
    ]
);

$result = GraphQL::executeQuery(
    schema: $schema,
    source: $query,
    variableValues: $variables,
    validationRules: $validationRules,
);
```

### Batching Attacks

GraphQL supports query batching (sending multiple queries in a single HTTP request),
which can be abused for brute-force attacks, such as testing thousands of passwords
in a single request that bypasses per-request rate limiting.

```json
// VULNERABLE: Batch of login attempts in a single request
[
  { "query": "mutation { login(email: \"admin@example.com\", password: \"password1\") { token } }" },
  { "query": "mutation { login(email: \"admin@example.com\", password: \"password2\") { token } }" },
  { "query": "mutation { login(email: \"admin@example.com\", password: \"password3\") { token } }" }
]
```

```php
<?php

declare(strict_types=1);

// SECURE: Limit batch size without consuming the downstream request body.
// Read the PSR-7 stream, but rewind before/after so later handlers still see it.
final class GraphQLBatchMiddleware
{
    private const int MAX_BATCH_SIZE = 5;

    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        $stream = $request->getBody();
        if ($stream->isSeekable()) {
            $stream->rewind();
        }
        $raw = $stream->getContents();
        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        try {
            $body = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return new JsonResponse(['error' => 'Invalid JSON payload'], 400);
        }

        if (is_array($body) && array_is_list($body) && count($body) > self::MAX_BATCH_SIZE) {
            return new JsonResponse([
                'error' => 'Batch size exceeds maximum of ' . self::MAX_BATCH_SIZE,
            ], 400);
        }

        return $handler->handle($request);
    }
}
```

### Field Suggestion Information Leakage

When a client queries a non-existent field, many GraphQL implementations suggest
similar field names in the error message, revealing the schema even with introspection
disabled.

```json
// Query: { users { pasword } }
// Response:
{
  "errors": [
    {
      "message": "Cannot query field 'pasword' on type 'User'. Did you mean 'password_hash' or 'password_reset_token'?"
    }
  ]
}
```

```php
<?php

declare(strict_types=1);

use GraphQL\Error\Error;
use GraphQL\Error\FormattedError;
use GraphQL\GraphQL;

// SECURE: Register a custom error formatter that strips the "Did you mean …?"
// suggestion tail from validation messages before returning errors to clients.
// Field suggestions leak the schema even when introspection is disabled.
$formatter = static function (Error $error): array {
    $formatted = FormattedError::createFromException($error);
    $formatted['message'] = preg_replace(
        '/\s*Did you mean[^?]*\?\s*$/u',
        '',
        (string) $formatted['message']
    );
    return $formatted;
};

$result  = GraphQL::executeQuery($schema, $query);
$output  = $result->setErrorFormatter($formatter)->toArray();
```

### N+1 Query DoS

GraphQL resolvers that load related entities individually per parent record create
N+1 query problems. While this is a performance issue in general, it becomes a
denial-of-service vector when an attacker crafts queries that maximize N+1 effects.

```php
<?php

declare(strict_types=1);

// VULNERABLE: Each user's posts resolved individually (N+1)
$resolvers = [
    'User' => [
        'posts' => function (User $user): array {
            // Called once per user in the result set - if 100 users, 100 queries
            return $this->postRepository->findBy(['author' => $user->getId()]);
        },
    ],
];

// SECURE: Use DataLoader pattern to batch resolve
use GraphQL\Deferred;

$postLoader = new DataLoader(function (array $userIds): array {
    // Single query: SELECT * FROM posts WHERE author_id IN (?, ?, ...)
    $posts = $this->postRepository->findBy(['author' => $userIds]);

    // Group posts by user ID
    $grouped = [];
    foreach ($posts as $post) {
        $grouped[$post->getAuthorId()][] = $post;
    }

    return array_map(fn (int $id) => $grouped[$id] ?? [], $userIds);
});

$resolvers = [
    'User' => [
        'posts' => function (User $user) use ($postLoader): Deferred {
            $postLoader->load($user->getId());

            return new Deferred(fn () => $postLoader->resolve($user->getId()));
        },
    ],
];
```

---

## REST API Security

### Versioning Security

Maintaining multiple API versions introduces risk when security patches are only
applied to the latest version. Older versions may remain accessible with known
vulnerabilities.

#### Detection Patterns

- `/api/v1/` endpoints still active after `/api/v2/` or `/api/v3/` are deployed
- Security middleware (rate limiting, auth) applied to new versions but not old ones
- RBAC rules differ between versions
- Patch for SQL injection in v2 not backported to v1

```php
<?php

declare(strict_types=1);

// SECURE: Apply security middleware to ALL active API versions
$app->group('/api', function (RouteCollectorProxy $group) {
    // Shared security middleware applied to entire /api group
    // This covers v1, v2, and all future versions
})->add(new AuthenticationMiddleware())
  ->add(new RateLimitMiddleware())
  ->add(new CorsMiddleware());
```

### Content-Type Validation

APIs should validate the `Content-Type` header to prevent content-type confusion
attacks and ensure the request body is parsed correctly.

```php
<?php

declare(strict_types=1);

// VULNERABLE: No content-type validation - accepts any format
class ApiController
{
    public function create(Request $request): JsonResponse
    {
        // PHP itself only parses application/x-www-form-urlencoded and
        // multipart/form-data into $_POST. JSON/XML must be handled manually
        // or by framework middleware. $request->toArray() here relies on
        // whatever framework decoder is wired up — if that silently accepts
        // text/xml, you may end up with XXE or unexpected parser behavior.
        $data = $request->toArray();

        return new JsonResponse($data);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Strict Content-Type enforcement middleware
final class ContentTypeMiddleware
{
    private const array ALLOWED_CONTENT_TYPES = [
        'application/json',
        'application/json; charset=utf-8',
    ];

    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH'], true)) {
            $contentType = strtolower(trim($request->getHeaderLine('Content-Type')));

            if (!in_array($contentType, self::ALLOWED_CONTENT_TYPES, true)) {
                return new JsonResponse(
                    ['error' => 'Unsupported Content-Type. Use application/json.'],
                    415 // 415 Unsupported Media Type
                );
            }
        }

        return $handler->handle($request);
    }
}
```

### HATEOAS Abuse

Hypermedia as the Engine of Application State (HATEOAS) includes links in API
responses to guide clients to related resources. Attackers can use these links to
discover endpoints and map the API surface, or inject malicious links if the
link-building process is not carefully controlled.

```php
<?php

declare(strict_types=1);

// VULNERABLE: Dynamic link generation using user-controlled input
class OrderController
{
    public function show(Order $order, Request $request): JsonResponse
    {
        return new JsonResponse([
            'id' => $order->getId(),
            'total' => $order->getTotal(),
            '_links' => [
                'self' => $request->getUri() . '/orders/' . $order->getId(),
                // If the Host header is spoofed, links point to attacker's domain
                'cancel' => $request->getSchemeAndHttpHost() . '/api/orders/' . $order->getId() . '/cancel',
            ],
        ]);
    }
}
```

```php
<?php

declare(strict_types=1);

// SECURE: Use a configured base URL, not request-derived values
class OrderController
{
    public function __construct(
        private readonly string $apiBaseUrl, // Injected from config: 'https://api.example.com'
    ) {}

    public function show(Order $order): JsonResponse
    {
        $orderId = $order->getId();

        return new JsonResponse([
            'id' => $orderId,
            'total' => $order->getTotal(),
            '_links' => [
                'self' => ['href' => $this->apiBaseUrl . '/orders/' . $orderId],
                'cancel' => $order->isCancellable()
                    ? ['href' => $this->apiBaseUrl . '/orders/' . $orderId . '/cancel']
                    : null,
            ],
        ]);
    }
}
```

---

## Prevention Checklist

### Authentication and Authorization

- [ ] Enforce authentication on every API endpoint (deny-by-default)
- [ ] Implement object-level authorization checks on every resource access (BOLA prevention)
- [ ] Use scoped queries to filter resources by the authenticated user at the repository level
- [ ] Enforce function-level authorization with role checks on admin and privileged endpoints
- [ ] Use short-lived access tokens (15 minutes or less) with refresh token rotation
- [ ] Generate API keys and tokens using cryptographically secure random sources
- [ ] Store API keys as hashed values, never in plaintext
- [ ] Transmit tokens via `Authorization` header, never in URL query parameters
- [ ] Enforce JWT algorithm verification; reject the `none` algorithm
- [ ] Implement token revocation (blacklisting or short expiry with refresh)

### Input and Output Control

- [ ] Define and enforce an allowlist of accepted request body fields (prevent mass assignment)
- [ ] Use DTOs or serialization groups to control which fields appear in API responses
- [ ] Validate `Content-Type` header; reject unexpected media types with 415 status
- [ ] Set maximum request body size limits at the web server and application level
- [ ] Validate and sanitize all data from third-party API responses before use
- [ ] Enforce TLS certificate verification on all outbound HTTP requests

### Rate Limiting and Resource Protection

- [ ] Implement per-user and per-IP rate limiting on all API endpoints
- [ ] Apply stricter rate limits on authentication, registration, and password reset endpoints
- [ ] Enforce maximum pagination size (e.g., max 100 items per page)
- [ ] Set timeouts on outbound HTTP requests to prevent resource exhaustion
- [ ] Implement query depth and complexity limits for GraphQL APIs
- [ ] Limit GraphQL batch query size

### Security Configuration

- [ ] Configure CORS with an explicit allowlist of origins; never reflect arbitrary `Origin` headers
- [ ] Return generic error messages in production; log detailed errors server-side with correlation IDs
- [ ] Restrict allowed HTTP methods per endpoint; return 405 for unsupported methods
- [ ] Set security headers on API responses (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, HSTS)
- [ ] Disable GraphQL introspection in production
- [ ] Suppress GraphQL field suggestion messages in production
- [ ] Remove or gate debug/test endpoints behind environment checks

### API Lifecycle Management

- [ ] Maintain an inventory of all API endpoints and their versions
- [ ] Deprecate old API versions with `Deprecation` and `Sunset` headers
- [ ] Remove deprecated API versions after the sunset date (return 410 Gone)
- [ ] Apply security patches to ALL active API versions, not just the latest
- [ ] Audit for undocumented/shadow API endpoints regularly
- [ ] Ensure staging/sandbox environments do not share production data

### Business Logic Protection

- [ ] Implement CAPTCHA or proof-of-work on sensitive business flow endpoints
- [ ] Enforce per-user limits on coupon redemption, account creation, and similar operations
- [ ] Apply velocity checks on financial transactions (unusual amounts, frequencies, or patterns)
- [ ] Use device fingerprinting and behavioral analysis for high-value operations
- [ ] Implement webhook URL validation to prevent SSRF via callback registration
