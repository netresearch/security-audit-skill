# Framework Security Patterns

## TYPO3 Security

### QueryBuilder: createNamedParameter() for SQL Safety

TYPO3's QueryBuilder provides SQL injection protection through named parameters.

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

// VULNERABLE: String concatenation in QueryBuilder
final class UserRepositoryUnsafe
{
    public function findByUsername(string $username): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        // DO NOT concatenate user input into queries
        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where('username = ' . $queryBuilder->quote($username))  // quote() is NOT sufficient
            ->executeQuery()
            ->fetchAllAssociative();
    }
}

// SECURE: Use createNamedParameter()
final class UserRepositorySafe
{
    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    public function findByUsername(string $username): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->eq(
                    'username',
                    $queryBuilder->createNamedParameter($username)
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }

    public function findByIds(array $ids): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->in(
                    'uid',
                    $queryBuilder->createNamedParameter(
                        $ids,
                        Connection::PARAM_INT_ARRAY  // Type hint for integer arrays
                    )
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }

    /**
     * For LIKE queries, use createNamedParameter with explicit escaping.
     */
    public function searchByName(string $searchTerm): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->like(
                    'username',
                    $queryBuilder->createNamedParameter(
                        '%' . $queryBuilder->escapeLikeWildcards($searchTerm) . '%'
                    )
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }
}
```

### FormProtection (CSRF Prevention)

TYPO3 uses form protection tokens (CSRF tokens) for backend modules and install tool.

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\FormProtection\FormProtectionFactory;
use TYPO3\CMS\Core\FormProtection\BackendFormProtection;

// SECURE: Generate and validate CSRF tokens in backend modules
final class BackendModuleController
{
    public function __construct(
        private readonly FormProtectionFactory $formProtectionFactory,
    ) {}

    public function formAction(): ResponseInterface
    {
        $formProtection = $this->formProtectionFactory->createFromRequest($request);

        // Generate token for a specific form/action combination
        $token = $formProtection->generateToken(
            'myExtension',       // Form identifier
            'deleteRecord',      // Action
            (string) $recordUid  // Optional: specific record
        );

        // Pass token to Fluid template
        $this->view->assign('csrfToken', $token);

        return $this->htmlResponse();
    }

    public function deleteAction(ServerRequestInterface $request): ResponseInterface
    {
        $formProtection = $this->formProtectionFactory->createFromRequest($request);
        $token = $request->getParsedBody()['csrfToken'] ?? '';

        // Validate token before processing
        if (!$formProtection->validateToken(
            $token,
            'myExtension',
            'deleteRecord',
            (string) $recordUid
        )) {
            throw new \RuntimeException('CSRF token validation failed');
        }

        // Safe to proceed with deletion
        $this->repository->remove($recordUid);
        $formProtection->clean();

        return $this->redirect('list');
    }
}
```

### Trusted Properties (HMAC-Signed Form Field Lists)

```php
<?php
declare(strict_types=1);

// TYPO3 Extbase trusted properties protect against mass assignment.
// The form generates an HMAC-signed list of allowed properties as a hidden field.

// In Fluid template:
// <f:form action="update" object="{user}" name="user">
//   <f:form.textfield property="firstName" />
//   <f:form.textfield property="lastName" />
//   <f:form.textfield property="email" />
//   <!-- __trustedProperties auto-generated: HMAC(['firstName','lastName','email']) -->
// </f:form>

// The following patterns WEAKEN trusted properties protection:

// VULNERABLE: Allowing all properties bypasses HMAC protection
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

final class UserControllerUnsafe extends ActionController
{
    public function initializeUpdateAction(): void
    {
        // DO NOT allow all properties
        $this->arguments['user']
            ->getPropertyMappingConfiguration()
            ->allowAllProperties();  // Bypasses trusted properties entirely
    }
}

// VULNERABLE: Setting creation/modification allowed without restriction
// $this->arguments['user']
//     ->getPropertyMappingConfiguration()
//     ->setTypeConverterOption(
//         PersistentObjectConverter::class,
//         PersistentObjectConverter::CONFIGURATION_CREATION_ALLOWED,
//         true
//     );

// SECURE: Only allow explicitly needed properties
final class UserControllerSafe extends ActionController
{
    public function initializeUpdateAction(): void
    {
        $config = $this->arguments['user']->getPropertyMappingConfiguration();

        // Only allow the specific properties the form should set
        $config->allowProperties('firstName', 'lastName', 'email');

        // Explicitly skip sensitive properties
        $config->skipProperties('admin', 'usergroup', 'disable', 'deleted');
    }

    public function updateAction(\MyVendor\MyExt\Domain\Model\User $user): void
    {
        $this->userRepository->update($user);
        $this->redirect('list');
    }
}
```

### FAL (File Abstraction Layer) for Safe File Handling

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Resource\ResourceFactory;
use TYPO3\CMS\Core\Resource\Security\FileNameValidator;

// VULNERABLE: Direct file operations bypass FAL security
// move_uploaded_file($_FILES['file']['tmp_name'], 'fileadmin/' . $_FILES['file']['name']);

// SECURE: Use FAL for all file operations
final class FileUploadService
{
    public function __construct(
        private readonly ResourceFactory $resourceFactory,
        private readonly FileNameValidator $fileNameValidator,
    ) {}

    public function handleUpload(array $uploadedFile, string $targetFolder): void
    {
        $fileName = $uploadedFile['name'];

        // FAL validates file extensions against deny patterns
        if (!$this->fileNameValidator->isValid($fileName)) {
            throw new \RuntimeException('File type not allowed: ' . $fileName);
        }

        // Use FAL storage for upload (applies all configured security checks)
        $storage = $this->resourceFactory->getDefaultStorage();
        $folder = $storage->getFolder($targetFolder);

        $storage->addFile(
            $uploadedFile['tmp_name'],
            $folder,
            $fileName,
        );
    }
}

// FAL denies these file extensions by default (configurable in Install Tool):
// php, php3, php4, php5, php6, php7, php8, phpsh, phtml, pht, phar,
// shtml, cgi, pl, asp, aspx, js, htaccess, ...
//
// Configuration: $GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']
```

### IgnoreValidation Annotation Risks

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Extbase\Annotation\IgnoreValidation;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

// WARNING: @IgnoreValidation skips ALL validators on the argument.
// Use only for actions that display forms, never for actions that process data.

final class RegistrationController extends ActionController
{
    // SAFE: IgnoreValidation on "new" form display (no data persisted)
    #[IgnoreValidation(['value' => 'user'])]
    public function newAction(?\MyVendor\MyExt\Domain\Model\User $user = null): void
    {
        // Just display the empty form - no data processing
        $this->view->assign('user', $user ?? new User());
    }

    // VULNERABLE: IgnoreValidation on a create/update action
    // #[IgnoreValidation(['value' => 'user'])]
    // public function createAction(User $user): void
    // {
    //     // User input NOT validated - can contain invalid/malicious data
    //     $this->userRepository->add($user);
    // }

    // SECURE: Let validation run on data-processing actions
    public function createAction(\MyVendor\MyExt\Domain\Model\User $user): void
    {
        // Extbase validates $user against model validators before this runs
        $this->userRepository->add($user);
        $this->redirect('list');
    }
}
```

### Content Security in TypoScript

```typoscript
# Configure Content Security Policy headers via TypoScript
config {
    additionalHeaders {
        10 {
            header = Content-Security-Policy
            # Strict CSP: only allow same-origin resources
            header.value = default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'
        }
        20 {
            header = X-Content-Type-Options
            header.value = nosniff
        }
        30 {
            header = X-Frame-Options
            header.value = SAMEORIGIN
        }
        40 {
            header = Referrer-Policy
            header.value = strict-origin-when-cross-origin
        }
        50 {
            header = Permissions-Policy
            header.value = camera=(), microphone=(), geolocation=()
        }
    }
}

# TYPO3 v12+ CSP integration (backend and frontend)
# Configured in sites/<identifier>/csp.yaml or ext_localconf.php
```

```php
<?php
declare(strict_types=1);

// TYPO3 v12+ Content Security Policy API
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Directive;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Mutation;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\MutationCollection;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\MutationMode;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Scope;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\SourceKeyword;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\SourceScheme;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\UriValue;

// In ext_localconf.php or Configuration/ContentSecurityPolicies.php:
return \TYPO3\CMS\Core\Security\ContentSecurityPolicy\Map::fromArray([
    Scope::frontend() => new MutationCollection(
        new Mutation(
            MutationMode::Extend,
            Directive::DefaultSrc,
            SourceKeyword::Self,
        ),
        new Mutation(
            MutationMode::Extend,
            Directive::ScriptSrc,
            SourceKeyword::Self,
        ),
    ),
]);
```

### Backend Module Access Control

```php
<?php
declare(strict_types=1);

// Backend module registration with access control (TYPO3 v12+)
// In Configuration/Backend/Modules.php:
return [
    'my_module' => [
        'parent' => 'web',
        'position' => ['after' => 'web_info'],
        'access' => 'admin',  // Restrict to admin users
        // Or: 'access' => 'user,group'  // Authenticated backend users
        'labels' => 'LLL:EXT:my_ext/Resources/Private/Language/locallang_mod.xlf',
        'extensionName' => 'MyExt',
        'controllerActions' => [
            \MyVendor\MyExt\Controller\AdminController::class => [
                'list', 'show',
            ],
        ],
    ],
];

// Additional permission checks within controller
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

final class AdminController extends ActionController
{
    public function listAction(): ResponseInterface
    {
        $backendUser = $GLOBALS['BE_USER'];

        // Check specific table permissions
        if (!$backendUser->check('tables_select', 'tx_myext_domain_model_record')) {
            throw new \RuntimeException('Access denied: no permission to read records');
        }

        // Check custom permission
        if (!$backendUser->check('custom_options', 'tx_myext:manage_settings')) {
            throw new \RuntimeException('Access denied: insufficient permissions');
        }

        $records = $this->recordRepository->findAll();
        $this->view->assign('records', $records);

        return $this->htmlResponse();
    }
}
```

### Detection Patterns for TYPO3

```php
// Grep patterns for TYPO3 security issues:
$typo3Patterns = [
    '->quote\(',                        // Using quote() instead of createNamedParameter()
    'allowAllProperties',               // Disabling trusted properties
    'IgnoreValidation.*create',         // IgnoreValidation on write actions
    'IgnoreValidation.*update',         // IgnoreValidation on write actions
    'IgnoreValidation.*delete',         // IgnoreValidation on write actions
    '\$_FILES\[',                       // Direct file access bypassing FAL
    'move_uploaded_file',               // Direct upload bypassing FAL
    'GeneralUtility::_GP\(',            // Accessing GET/POST directly (deprecated)
    'GeneralUtility::_GET\(',           // Accessing GET directly (deprecated)
    'GeneralUtility::_POST\(',          // Accessing POST directly (deprecated)
    '\$GLOBALS\[.TSFE.\].*cObj->data',  // Direct TypoScript data access
];
```

---

## Symfony Security

### Security Voters for Authorization

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

### Firewall Configuration

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

### CSRF Protection

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

### Security Bundle Configuration

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

    public function performSensitiveAction(): void
    {
        // Check role
        if (!$this->authChecker->isGranted('ROLE_ADMIN')) {
            throw new AccessDeniedException('Admin access required');
        }

        // Check voter-based permission
        if (!$this->authChecker->isGranted('EDIT', $resource)) {
            throw new AccessDeniedException('Cannot edit this resource');
        }
    }
}
```

### Rate Limiter Component

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
        // Create limiter based on client IP
        $limiter = $this->loginLimiter->create($request->getClientIp());

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

### Detection Patterns for Symfony

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

## Laravel Security

### Gates and Policies

```php
<?php
declare(strict_types=1);

use Illuminate\Auth\Access\Gate;
use Illuminate\Support\Facades\Gate as GateFacade;

// Define gates in AuthServiceProvider
final class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Simple gate: closure-based
        GateFacade::define('manage-settings', function (User $user): bool {
            return $user->is_admin;
        });

        // Gate with resource: checks ownership
        GateFacade::define('update-post', function (User $user, Post $post): bool {
            return $user->id === $post->user_id;
        });
    }
}

// Policy class for fine-grained authorization
final class PostPolicy
{
    /**
     * Determine if the user can view the post.
     */
    public function view(User $user, Post $post): bool
    {
        return $post->published || $user->id === $post->user_id;
    }

    /**
     * Determine if the user can update the post.
     */
    public function update(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }

    /**
     * Determine if the user can delete the post.
     */
    public function delete(User $user, Post $post): bool
    {
        return $user->id === $post->user_id
            && $user->hasRole('editor');
    }
}

// Usage in controller:
final class PostController extends Controller
{
    public function update(Request $request, Post $post): JsonResponse
    {
        // Throws AuthorizationException if denied
        $this->authorize('update', $post);

        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
        ]);

        $post->update($validated);

        return response()->json($post);
    }
}

// Usage in Blade template:
// @can('update', $post)
//     <a href="{{ route('posts.edit', $post) }}">Edit</a>
// @endcan
```

### Mass Assignment Protection

```php
<?php
declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;

// VULNERABLE: No mass assignment protection
class PostUnsafe extends Model
{
    protected $guarded = [];  // NEVER do this in production
}

// VULNERABLE: Using $request->all() with guarded = []
// Post::create($request->all());  // All fields from request are saved

// SECURE: Explicit fillable (allowlist -- recommended)
class Post extends Model
{
    /**
     * Only these fields can be mass-assigned.
     * @var list<string>
     */
    protected $fillable = [
        'title',
        'body',
        'category_id',
    ];

    // These fields are automatically protected:
    // id, user_id, is_published, is_featured, created_at, updated_at
}

// SECURE: Using validated data only (defense in depth)
final class PostController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string|max:50000',
            'category_id' => 'required|exists:categories,id',
        ]);

        // Even with $fillable, always use validated data
        $post = $request->user()->posts()->create($validated);

        return response()->json($post, 201);
    }
}

// SECURE: Form Request for complex validation
final class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Post::class);
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'title' => ['required', 'string', 'max:255'],
            'body' => ['required', 'string'],
            'category_id' => ['required', 'integer', 'exists:categories,id'],
            // is_published, user_id, etc. are NOT in rules = cannot be submitted
        ];
    }
}
```

### CSRF Middleware

```php
<?php
declare(strict_types=1);

// Laravel includes CSRF middleware by default for web routes.
// The VerifyCsrfToken middleware checks _token on all POST/PUT/PATCH/DELETE requests.

// In Blade templates:
// <form method="POST" action="/posts">
//     @csrf                                    <!-- Adds hidden _token field -->
//     <input type="text" name="title">
//     <button type="submit">Create</button>
// </form>

// For AJAX requests:
// <meta name="csrf-token" content="{{ csrf_token() }}">
// <script>
//   fetch('/api/endpoint', {
//       method: 'POST',
//       headers: {
//           'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
//           'Content-Type': 'application/json',
//       },
//       body: JSON.stringify(data)
//   });
// </script>

// Exclude routes from CSRF (use sparingly, e.g., for webhooks):
// In app/Http/Middleware/VerifyCsrfToken.php:
final class VerifyCsrfToken extends Middleware
{
    /**
     * URIs that should be excluded from CSRF verification.
     * WARNING: Only exclude routes that have alternative authentication
     * (e.g., webhook signature verification, API tokens).
     *
     * @var list<string>
     */
    protected $except = [
        'webhooks/stripe',    // Uses Stripe signature verification
        'webhooks/github',    // Uses GitHub HMAC verification
    ];
}
```

### Encryption (Crypt Facade)

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Contracts\Encryption\DecryptException;

// Laravel's Crypt facade uses AES-256-CBC with HMAC (encrypt-then-MAC)
// Key is derived from APP_KEY in .env

final class SecureStorageService
{
    /**
     * Encrypt sensitive data for storage.
     */
    public function store(string $sensitiveData): string
    {
        // Crypt::encrypt serializes and encrypts (handles objects/arrays too)
        return Crypt::encryptString($sensitiveData);

        // For arrays/objects:
        // return Crypt::encrypt(['key' => 'value']);
    }

    /**
     * Decrypt stored data.
     */
    public function retrieve(string $encryptedData): string
    {
        try {
            return Crypt::decryptString($encryptedData);
        } catch (DecryptException $e) {
            // Tampered data, wrong key, or corrupted ciphertext
            throw new \RuntimeException('Data integrity check failed', 0, $e);
        }
    }
}

// IMPORTANT: Protect APP_KEY
// - Never commit APP_KEY to version control
// - Rotate with: php artisan key:generate
// - After rotation, re-encrypt all data encrypted with old key
// - Store in environment variable, never in config files
```

### Query Builder Parameterization

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\DB;

// VULNERABLE: Raw string concatenation
$users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'");

// VULNERABLE: Raw expression without binding
$users = DB::table('users')
    ->whereRaw("name = '$name'")  // SQL injection
    ->get();

// SECURE: Query builder with automatic parameterization
$users = DB::table('users')
    ->where('name', '=', $name)     // Parameterized automatically
    ->where('active', true)
    ->get();

// SECURE: Raw queries with parameter binding
$users = DB::select(
    'SELECT * FROM users WHERE name = ? AND role = ?',
    [$name, $role]
);

// SECURE: Named bindings
$users = DB::select(
    'SELECT * FROM users WHERE name = :name',
    ['name' => $name]
);

// SECURE: whereRaw with bindings (when raw SQL is needed)
$users = DB::table('users')
    ->whereRaw('LOWER(email) = ?', [strtolower($email)])
    ->get();

// SECURE: Eloquent ORM (always parameterized)
$users = User::where('name', $name)
    ->where('active', true)
    ->get();

// SECURE: Subqueries
$latestPosts = DB::table('posts')
    ->select('user_id', DB::raw('MAX(created_at) as last_post'))
    ->groupBy('user_id');

$users = DB::table('users')
    ->joinSub($latestPosts, 'latest_posts', function ($join) {
        $join->on('users.id', '=', 'latest_posts.user_id');
    })
    ->get();
```

### Detection Patterns for Laravel

```php
// Grep patterns for Laravel security issues:
$laravelPatterns = [
    'protected \$guarded = \[\]',           // Empty guarded array
    '->fill\(\$request->all\(\)\)',         // Mass assignment with all()
    '::create\(\$request->all\(\)\)',       // Create with all request data
    'DB::raw\(\$',                          // Raw SQL with variable
    'whereRaw\(.*\$',                       // whereRaw with variable interpolation
    'DB::select\(.*\.\s*\$',               // Concatenated SQL
    'Crypt::decrypt.*catch.*\{\}',         // Swallowed decryption errors
    'except.*=.*\[.*\*',                   // Wildcard CSRF exclusion
    'auth\(\)->user\(\).*without.*check',  // Missing null check on user
    'APP_KEY.*base64:.*config',            // Hardcoded APP_KEY
];
```

---

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
