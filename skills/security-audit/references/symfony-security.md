# Symfony Security Patterns

Security patterns specific to Symfony — voters, firewalls, CSRF, Security Bundle, Rate Limiter. Cross-framework patterns (middleware, input validation, output encoding) live in `framework-security.md`.

## Security Voters for Authorization

Voters provide fine-grained, reusable authorization logic.

```php
<?php
declare(strict_types=1);

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Voter that determines if a user can perform actions on a Document.
 */
final class DocumentVoter extends Voter
{
    public const string VIEW = 'DOCUMENT_VIEW';
    public const string EDIT = 'DOCUMENT_EDIT';
    public const string DELETE = 'DOCUMENT_DELETE';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, [self::VIEW, self::EDIT, self::DELETE], true)
            && $subject instanceof Document;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;  // Not authenticated
        }

        /** @var Document $document */
        $document = $subject;

        return match ($attribute) {
            self::VIEW => $this->canView($document, $user),
            self::EDIT => $this->canEdit($document, $user),
            self::DELETE => $this->canDelete($document, $user),
            default => false,
        };
    }

    private function canView(Document $document, User $user): bool
    {
        // Public documents can be viewed by anyone
        if ($document->isPublic()) {
            return true;
        }

        // Owner can always view
        return $document->getOwner() === $user;
    }

    private function canEdit(Document $document, User $user): bool
    {
        return $document->getOwner() === $user;
    }

    private function canDelete(Document $document, User $user): bool
    {
        // Only owner with admin role can delete
        return $document->getOwner() === $user
            && in_array('ROLE_ADMIN', $user->getRoles(), true);
    }
}

// Usage in controller:
final class DocumentController extends AbstractController
{
    public function edit(Document $document): Response
    {
        // Throws AccessDeniedException if voter denies
        $this->denyAccessUnlessGranted(DocumentVoter::EDIT, $document);

        return $this->render('document/edit.html.twig', ['document' => $document]);
    }
}
```

## Firewall Configuration

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: auto  # Uses bcrypt or Argon2id based on PHP config

    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        api:
            pattern: ^/api
            stateless: true
            jwt: ~  # Or: custom_authenticators, api_key, etc.

        main:
            lazy: true
            provider: app_user_provider
            form_login:
                login_path: app_login
                check_path: app_login
                enable_csrf: true  # CSRF protection on login
            logout:
                path: app_logout
                invalidate_session: true
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800  # 1 week
                secure: true
                httponly: true
                samesite: strict

    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/profile, roles: ROLE_USER }
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: ROLE_API_USER }
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: PUBLIC_ACCESS }

    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER, ROLE_API_USER]
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH]
```

## CSRF Protection

```php
<?php
declare(strict_types=1);

use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;

final class FormController extends AbstractController
{
    public function __construct(
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
    ) {}

    public function delete(Request $request, int $id): Response
    {
        // Validate CSRF token from request
        $token = new CsrfToken(
            'delete_item_' . $id,                          // Token ID (unique per action)
            $request->request->get('_csrf_token', ''),     // Submitted token value
        );

        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }

        // Safe to proceed
        $this->itemRepository->delete($id);

        return $this->redirectToRoute('item_list');
    }
}
```

```twig
{# In Twig template: generate CSRF token #}
<form method="post" action="{{ path('item_delete', {id: item.id}) }}">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('delete_item_' ~ item.id) }}">
    <button type="submit">Delete</button>
</form>

{# For Symfony forms, CSRF is enabled by default: #}
{{ form_start(form) }}
    {# _token field is automatically included #}
    {{ form_widget(form) }}
{{ form_end(form) }}
```

## Security Bundle Configuration

```yaml
# config/packages/security.yaml - Additional security settings

security:
    # Hide whether a user exists during authentication
    hide_user_not_found: true

    # Session fixation protection
    session_fixation_strategy: migrate  # Regenerates session ID on login

framework:
    # Session security
    session:
        cookie_secure: auto       # HTTPS-only cookies in production
        cookie_httponly: true      # Prevent JavaScript access
        cookie_samesite: lax      # CSRF protection for cookies
        gc_maxlifetime: 1800      # 30-minute session lifetime
```

```php
<?php
declare(strict_types=1);

// Programmatic security checks
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class SecureService
{
    public function __construct(
        private readonly AuthorizationCheckerInterface $authChecker,
    ) {}

    public function performSensitiveAction(object $resource): void
    {
        // Check role
        if (!$this->authChecker->isGranted('ROLE_ADMIN')) {
            throw new AccessDeniedException('Admin access required');
        }

        // Check voter-based permission — $resource comes from the caller
        // (controller route argument, repository lookup, etc.). The attribute
        // string below matches the DocumentVoter::EDIT constant defined in
        // the earlier example; use the constant rather than the literal
        // string in real code so a voter rename refactors cleanly.
        if (!$this->authChecker->isGranted(DocumentVoter::EDIT, $resource)) {
            throw new AccessDeniedException('Cannot edit this resource');
        }
    }
}
```

## Rate Limiter Component

```php
<?php
declare(strict_types=1);

// config/packages/rate_limiter.yaml
// framework:
//     rate_limiter:
//         login_attempts:
//             policy: sliding_window
//             limit: 5
//             interval: '15 minutes'
//         api_requests:
//             policy: token_bucket
//             limit: 100
//             rate: { interval: '1 minute', amount: 10 }

use Symfony\Component\RateLimiter\RateLimiterFactory;

final class LoginController extends AbstractController
{
    public function __construct(
        private readonly RateLimiterFactory $loginLimiter,
    ) {}

    public function login(Request $request): Response
    {
        // Create limiter based on client IP. getClientIp() can return null
        // (reverse-proxy misconfig, CLI harness), so fall back to a fixed
        // bucket. Prefer a stable identifier (username + IP) when available.
        $limiterKey = $request->getClientIp() ?? 'unknown-client';
        $limiter = $this->loginLimiter->create($limiterKey);

        // Check if rate limit exceeded
        $limit = $limiter->consume();

        if (!$limit->isAccepted()) {
            $retryAfter = $limit->getRetryAfter();

            return new JsonResponse(
                ['error' => 'Too many login attempts. Try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => $retryAfter->getTimestamp() - time()],
            );
        }

        // Process login
        return $this->processLogin($request);
    }
}
```

## Detection Patterns for Symfony

```php
// Grep patterns for Symfony security issues:
$symfonyPatterns = [
    'security:\s*false',                     // Firewall disabled
    'enable_csrf:\s*false',                  // CSRF disabled on login
    'csrf_protection:\s*false',              // CSRF disabled on forms
    'PUBLIC_ACCESS.*admin',                  // Public access to admin routes
    'isGranted.*ROLE_.*false',               // Ignoring permission check results
    'hide_user_not_found:\s*false',          // User enumeration via login
    '#\[IsGranted\].*without.*attribute',    // Missing role specification
    'password_hashers.*plaintext',           // Plaintext password storage
    'cookie_secure:\s*false',               // Non-secure cookies
];
```

---

