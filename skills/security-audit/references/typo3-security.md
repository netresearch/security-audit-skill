# TYPO3 Security Patterns (PHP-level)

Security patterns specific to TYPO3 CMS — PHP-level patterns only. For Fluid template auto-escape / ViewHelper pitfalls see `typo3-fluid-security.md`; for TypoScript / TSconfig see `typo3-typoscript-security.md`.

## QueryBuilder: createNamedParameter() for SQL Safety

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
    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

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

## FormProtection (CSRF Prevention)

TYPO3 uses form protection tokens (CSRF tokens) for backend modules and install tool.

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\FormProtection\FormProtectionFactory;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

// SECURE: Generate and validate CSRF tokens in a backend Extbase module
final class BackendModuleController extends ActionController
{
    public function __construct(
        private readonly FormProtectionFactory $formProtectionFactory,
    ) {}

    public function formAction(int $recordUid): ResponseInterface
    {
        // TYPO3 v13: ExtbaseRequestInterface implements ServerRequestInterface,
        // so $this->request can be passed straight to createFromRequest().
        //
        // TYPO3 v12 (LTS): ExtbaseRequestInterface does NOT implement
        // ServerRequestInterface directly — unwrap the underlying request
        // explicitly. The helper below works on both and is safe to copy
        // verbatim when your extension supports the v12/v13 overlap window.
        $psrRequest = method_exists($this->request, 'getRequest')
            ? $this->request->getRequest()   // v12 Extbase\Request wraps the PSR-7
            : $this->request;                // v13+ already-is PSR-7
        $formProtection = $this->formProtectionFactory->createFromRequest($psrRequest);

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

    public function deleteAction(int $recordUid): ResponseInterface
    {
        $psrRequest = method_exists($this->request, 'getRequest')
            ? $this->request->getRequest()
            : $this->request;
        $formProtection = $this->formProtectionFactory->createFromRequest($psrRequest);
        $token = (string)($psrRequest->getParsedBody()['csrfToken'] ?? '');

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

## Trusted Properties (HMAC-Signed Form Field Lists)

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

## FAL (File Abstraction Layer) for Safe File Handling

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

// FAL's default deny pattern (FILE_DENY_PATTERN_DEFAULT):
//   \.(php[3-8]?|phpsh|phtml|pht|phar|shtml|cgi)(\..*)?$|^\.htaccess$
// Blocks: php, php3-php8, phpsh, phtml, pht, phar, shtml, cgi, .htaccess
// NOT blocked by default: pl, asp, aspx, js, jsp, py, rb, sh, exe, ...
// Tighten $GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern'] if the host
// stack serves any of these via an interpreter (IIS .asp/.aspx, Perl .pl,
// or a misconfigured web server handling .js as a script).
```

## IgnoreValidation Annotation Risks

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

## Content Security in TypoScript

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

## Backend Module Access Control

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

## Detection Patterns for TYPO3

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

