# Path Traversal Prevention

## Understanding Path Traversal (CWE-22)

### What Is Path Traversal?

Path traversal (also called directory traversal) allows an attacker to access files and directories outside the intended directory by manipulating file path inputs. By injecting sequences like `../` into file parameters, attackers can read sensitive files (`/etc/passwd`, application configuration, source code) or write to arbitrary locations.

### Attack Vectors

```
# Basic directory traversal
../../../etc/passwd

# Double-encoded traversal (bypasses naive URL decoding filters)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd

# Null byte injection (PHP < 5.3.4)
../../../etc/passwd%00.jpg
../../../etc/passwd\0.png

# Backslash traversal (Windows servers)
..\..\..\windows\system32\config\sam

# Mixed separators
..\/..\/..\/etc/passwd

# Overlong UTF-8 encoding
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af

# Absolute path injection (when prepend is weak)
/etc/passwd
C:\Windows\system32\config\sam

# Using wrapper schemes
file:///etc/passwd
php://filter/read=convert.base64-encode/resource=/etc/passwd
```

## Vulnerable Patterns

### File Read with User Input

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Direct concatenation of user input into file path
$filename = $_GET['file'];
$content = file_get_contents('/var/www/uploads/' . $filename);
echo $content;
// Attacker: ?file=../../../etc/passwd

// VULNERABLE - DO NOT USE
// Include with user-controlled path
$page = $_GET['page'];
include '/var/www/templates/' . $page . '.php';
// Attacker: ?page=../../../etc/passwd%00  (null byte, old PHP)
// Attacker: ?page=../../../var/log/apache2/access.log  (log poisoning)

// VULNERABLE - DO NOT USE
// Download handler with unsanitized filename
$file = $_GET['download'];
$path = '/var/www/storage/' . $file;
header('Content-Disposition: attachment; filename="' . basename($file) . '"');
readfile($path);
// Attacker: ?download=../../config/database.yml
```

### File Write with User Input

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Writing uploaded files to user-controlled path
$destination = '/var/www/uploads/' . $_POST['filename'];
move_uploaded_file($_FILES['file']['tmp_name'], $destination);
// Attacker: filename=../../public/shell.php

// VULNERABLE - DO NOT USE
// Log file path from user input
$logFile = '/var/log/app/' . $_GET['module'] . '.log';
file_put_contents($logFile, $logEntry, FILE_APPEND);
// Attacker: ?module=../../var/www/html/backdoor.php%00
```

### Insufficient Validation

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// str_replace can be bypassed with nested sequences
$filename = str_replace('../', '', $_GET['file']);
// Attacker: ....// becomes ../ after replacement
// Attacker: ..././ also becomes ../

// VULNERABLE - DO NOT USE
// Only checking for leading ../
$filename = $_GET['file'];
if (!str_starts_with($filename, '../')) {
    readfile('/var/www/uploads/' . $filename);
}
// Attacker: ?file=subdir/../../etc/passwd

// VULNERABLE - DO NOT USE
// Extension check but no path check
$filename = $_GET['file'];
if (str_ends_with($filename, '.pdf')) {
    readfile('/var/www/docs/' . $filename);
}
// Attacker: ?file=../../../etc/passwd%00.pdf  (old PHP)
// Attacker: ?file=../../config/secrets.pdf     (if file exists)
```

## Secure Patterns

### realpath() Validation

```php
<?php

declare(strict_types=1);

// SECURE: Resolve the real path and verify it is within the allowed directory
final class SecureFileAccess
{
    public function __construct(
        private readonly string $baseDirectory,
    ) {}

    /**
     * Safely read a file, ensuring it is within the allowed base directory.
     *
     * @throws \InvalidArgumentException if the path escapes the base directory
     * @throws \RuntimeException if the file cannot be read
     */
    public function readFile(string $userInput): string
    {
        $requestedPath = $this->baseDirectory . '/' . $userInput;

        // realpath() resolves symlinks and ../ sequences, returns false if file does not exist
        $realPath = realpath($requestedPath);

        if ($realPath === false) {
            throw new \InvalidArgumentException('File not found');
        }

        // Verify the resolved path is still within the base directory
        $realBase = realpath($this->baseDirectory);
        if ($realBase === false) {
            throw new \RuntimeException('Base directory does not exist');
        }

        if (!str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)) {
            throw new \InvalidArgumentException('Access denied: path traversal detected');
        }

        $content = file_get_contents($realPath);
        if ($content === false) {
            throw new \RuntimeException('Could not read file');
        }

        return $content;
    }
}
```

### basename() for Filename Extraction

```php
<?php

declare(strict_types=1);

// SECURE: Use basename() to strip all directory components
final class SafeDownloadHandler
{
    private const ALLOWED_EXTENSIONS = ['pdf', 'csv', 'txt', 'xlsx'];

    public function __construct(
        private readonly string $uploadDirectory,
    ) {}

    /**
     * Serve a file download safely.
     *
     * @throws \InvalidArgumentException if the file is not allowed
     */
    public function download(string $requestedFile): void
    {
        // basename() strips all directory components, preventing traversal
        $filename = basename($requestedFile);

        // Validate extension against whitelist
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            throw new \InvalidArgumentException('File type not allowed');
        }

        $fullPath = $this->uploadDirectory . '/' . $filename;

        // Additional realpath check for symlink protection
        $realPath = realpath($fullPath);
        if ($realPath === false || !is_file($realPath)) {
            throw new \InvalidArgumentException('File not found');
        }

        $realBase = realpath($this->uploadDirectory);
        if ($realBase === false || !str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)) {
            throw new \InvalidArgumentException('Access denied');
        }

        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($realPath));
        header('X-Content-Type-Options: nosniff');
        readfile($realPath);
    }
}
```

### Whitelist Approach

```php
<?php

declare(strict_types=1);

// SECURE: Only allow access to predefined files via a mapping
final class TemplateLoader
{
    /** @var array<string, string> Map of template IDs to file paths */
    private const TEMPLATES = [
        'invoice' => '/var/www/templates/invoice.html',
        'receipt' => '/var/www/templates/receipt.html',
        'report'  => '/var/www/templates/report.html',
    ];

    /**
     * Load a template by its identifier, not by a user-supplied file path.
     *
     * @throws \InvalidArgumentException if the template ID is not recognized
     */
    public function load(string $templateId): string
    {
        if (!isset(self::TEMPLATES[$templateId])) {
            throw new \InvalidArgumentException(
                'Unknown template: ' . $templateId
            );
        }

        $content = file_get_contents(self::TEMPLATES[$templateId]);
        if ($content === false) {
            throw new \RuntimeException('Could not load template: ' . $templateId);
        }

        return $content;
    }
}

// Usage:
// $loader->load($_GET['template']);
// Attacker can only pass 'invoice', 'receipt', or 'report' - no path manipulation possible
```

### Comprehensive Path Sanitization

```php
<?php

declare(strict_types=1);

// SECURE: Multi-layered path validation utility
final class PathValidator
{
    /**
     * Validate that a user-supplied path component is safe.
     *
     * @param string $input    The user-supplied filename or relative path
     * @param string $baseDir  The allowed base directory (absolute path)
     * @return string The validated absolute path
     *
     * @throws \InvalidArgumentException if the path is unsafe
     */
    public static function validate(string $input, string $baseDir): string
    {
        // 1. Reject empty input
        if ($input === '' || $input === '.' || $input === '..') {
            throw new \InvalidArgumentException('Invalid file path');
        }

        // 2. Reject null bytes (defense-in-depth, fixed in PHP 5.3.4+)
        if (str_contains($input, "\0")) {
            throw new \InvalidArgumentException('Null byte in file path');
        }

        // 3. Reject stream wrappers
        if (preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//', $input)) {
            throw new \InvalidArgumentException('Stream wrappers are not allowed');
        }

        // 4. Reject absolute paths
        if ($input[0] === '/' || $input[0] === '\\') {
            throw new \InvalidArgumentException('Absolute paths are not allowed');
        }

        // 5. Reject directory traversal sequences (before realpath as defense-in-depth)
        if (preg_match('/(?:^|[\\/])\.\.(?:[\\/]|$)/', $input)) {
            throw new \InvalidArgumentException('Directory traversal detected');
        }

        // 6. Build and resolve the full path
        $fullPath = $baseDir . DIRECTORY_SEPARATOR . $input;
        $realPath = realpath($fullPath);

        if ($realPath === false) {
            throw new \InvalidArgumentException('File not found');
        }

        // 7. Final containment check with resolved paths
        $realBase = realpath($baseDir);
        if ($realBase === false) {
            throw new \RuntimeException('Base directory does not exist');
        }

        if (!str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)) {
            throw new \InvalidArgumentException('Path traversal detected');
        }

        return $realPath;
    }
}
```

## Framework-Specific Solutions

### TYPO3 FAL (File Abstraction Layer)

```php
<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Resource\ResourceFactory;
use TYPO3\CMS\Core\Resource\StorageRepository;
use TYPO3\CMS\Core\Utility\GeneralUtility;

// SECURE: TYPO3's FAL handles path traversal prevention internally
// Files are accessed via storage + identifier, not raw file paths

$resourceFactory = GeneralUtility::makeInstance(ResourceFactory::class);

// Access files through FAL - storage boundaries are enforced
$file = $resourceFactory->getFileObjectFromCombinedIdentifier('1:/user_upload/report.pdf');

// Read file content safely through FAL
$content = $file->getContents();

// FAL prevents access outside the configured storage root
// Attempting traversal via the identifier will throw an exception:
// $file = $resourceFactory->getFileObjectFromCombinedIdentifier('1:/../../../etc/passwd');
// ^ Throws InvalidPathException

// SECURE: Use storage repository for file operations
$storageRepository = GeneralUtility::makeInstance(StorageRepository::class);
$storage = $storageRepository->findByUid(1);

// getFile() validates the path is within the storage
$file = $storage->getFile('user_upload/document.pdf');

// SECURE: For extension file access, use Environment API
use TYPO3\CMS\Core\Core\Environment;

$publicPath = Environment::getPublicPath();
$varPath = Environment::getVarPath();

// Validate against known safe directories
$safePath = realpath($varPath . '/log/' . basename($logFileName));
```

### Symfony File Handling

```php
<?php

declare(strict_types=1);

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

// SECURE: Use Symfony's Filesystem component for path operations
final class SecureFileController
{
    public function __construct(
        private readonly string $uploadDir,
        private readonly Filesystem $filesystem,
    ) {}

    public function download(string $filename): BinaryFileResponse
    {
        // Symfony's Path::canonicalize resolves ../ sequences
        $canonicalPath = Path::canonicalize($this->uploadDir . '/' . $filename);

        // Verify the canonical path is within the upload directory
        if (!Path::isBasePath($this->uploadDir, $canonicalPath)) {
            throw new NotFoundHttpException('File not found');
        }

        if (!$this->filesystem->exists($canonicalPath)) {
            throw new NotFoundHttpException('File not found');
        }

        $response = new BinaryFileResponse($canonicalPath);
        $response->setContentDisposition(
            ResponseHeaderBag::DISPOSITION_ATTACHMENT,
            basename($canonicalPath)
        );

        return $response;
    }
}

// SECURE: Symfony's Finder component for safe file listing
use Symfony\Component\Finder\Finder;

$finder = new Finder();
$finder->files()
    ->in($uploadDirectory)      // Constrains to this directory
    ->depth('< 2')              // Limit directory depth
    ->name('*.pdf')             // Only PDF files
    ->sortByName();

foreach ($finder as $file) {
    // $file->getRealPath() is guaranteed within the $uploadDirectory
    echo $file->getFilename();
}
```

### Laravel File Handling

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\StreamedResponse;

// SECURE: Laravel's Storage facade abstracts file paths
// The configured disk root prevents traversal automatically

// Read a file safely
$content = Storage::disk('uploads')->get('reports/monthly.pdf');

// Download a file safely
$response = Storage::disk('uploads')->download('reports/monthly.pdf');

// Check existence (constrained to disk root)
if (Storage::disk('uploads')->exists($userInput)) {
    // File is guaranteed to be within the disk root
}

// SECURE: Additional validation for user-supplied paths
final class FileAccessService
{
    public function getFile(string $userPath): string
    {
        // Normalize and reject traversal
        $normalized = str_replace('\\', '/', $userPath);
        if (str_contains($normalized, '..')) {
            throw new \InvalidArgumentException('Invalid file path');
        }

        $content = Storage::disk('uploads')->get($normalized);
        if ($content === null) {
            throw new \InvalidArgumentException('File not found');
        }

        return $content;
    }
}
```

## Detection Patterns

### Static Analysis

```php
<?php

declare(strict_types=1);

// File functions that are dangerous with user-controlled paths
$dangerousFunctions = [
    // Read operations
    'file_get_contents',
    'fopen',
    'readfile',
    'file',
    'fread',
    'fgets',
    'SplFileObject',
    'SplFileInfo',

    // Write operations
    'file_put_contents',
    'fwrite',
    'fputs',
    'move_uploaded_file',
    'copy',
    'rename',

    // Include/require (also code execution!)
    'include',
    'include_once',
    'require',
    'require_once',

    // Directory operations
    'opendir',
    'scandir',
    'glob',
    'mkdir',
    'rmdir',

    // File info operations
    'file_exists',
    'is_file',
    'is_dir',
    'is_readable',
    'is_writable',
    'filesize',
    'filemtime',
    'stat',

    // Image operations
    'imagecreatefromjpeg',
    'imagecreatefrompng',
    'imagecreatefromgif',
    'getimagesize',
    'exif_read_data',
];

// Search commands:
// Find file operations with user input ($_GET, $_POST, $_REQUEST, $_COOKIE)
// grep -rn 'file_get_contents.*\$_\(GET\|POST\|REQUEST\|COOKIE\)' --include="*.php"
// grep -rn 'include.*\$' --include="*.php"
// grep -rn 'readfile.*\$' --include="*.php"

// Find missing realpath validation
// grep -rn 'file_get_contents.*\$' --include="*.php" | grep -v 'realpath'
```

### Regex Detection Patterns

```php
<?php

declare(strict_types=1);

$detectionPatterns = [
    // File read with direct variable concatenation
    '/(?:file_get_contents|readfile|fopen|file)\s*\(\s*[\'"][^"\']*[\'"]\s*\.\s*\$/'
        => 'HIGH: File operation with concatenated variable input',

    // Include/require with variable
    '/(?:include|require)(?:_once)?\s*\(\s*.*\$/'
        => 'CRITICAL: Dynamic include/require with variable path',

    // Missing realpath check near file operations
    '/file_get_contents\s*\(\s*\$(?!.*realpath)/'
        => 'MEDIUM: File read without realpath validation',

    // User input directly in file path
    '/(?:file_get_contents|readfile|fopen)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)/'
        => 'CRITICAL: Direct user input in file operation',

    // Insufficient traversal filtering
    '/str_replace\s*\(\s*[\'"]\.\.\/[\'"]\s*,\s*[\'"]{2}/'
        => 'HIGH: Bypassable path traversal filter (str_replace)',
];
```

## Testing for Path Traversal

### Unit Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class PathTraversalPreventionTest extends TestCase
{
    private SecureFileAccess $fileAccess;
    private string $testBaseDir;

    protected function setUp(): void
    {
        $this->testBaseDir = sys_get_temp_dir() . '/path_traversal_test_' . bin2hex(random_bytes(8));
        mkdir($this->testBaseDir, 0755, true);
        mkdir($this->testBaseDir . '/subdir', 0755, true);
        file_put_contents($this->testBaseDir . '/allowed.txt', 'safe content');
        file_put_contents($this->testBaseDir . '/subdir/nested.txt', 'nested content');

        $this->fileAccess = new SecureFileAccess($this->testBaseDir);
    }

    protected function tearDown(): void
    {
        // Clean up test files
        @unlink($this->testBaseDir . '/allowed.txt');
        @unlink($this->testBaseDir . '/subdir/nested.txt');
        @rmdir($this->testBaseDir . '/subdir');
        @rmdir($this->testBaseDir);
    }

    public function testAllowsAccessToFileInBaseDirectory(): void
    {
        $content = $this->fileAccess->readFile('allowed.txt');
        $this->assertSame('safe content', $content);
    }

    public function testAllowsAccessToNestedFile(): void
    {
        $content = $this->fileAccess->readFile('subdir/nested.txt');
        $this->assertSame('nested content', $content);
    }

    public function testRejectsBasicDirectoryTraversal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->fileAccess->readFile('../../../etc/passwd');
    }

    public function testRejectsTraversalInMiddleOfPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->fileAccess->readFile('subdir/../../etc/passwd');
    }

    public function testRejectsAbsolutePath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('/etc/passwd', $this->testBaseDir);
    }

    public function testRejectsNullBytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate("allowed.txt\0.jpg", $this->testBaseDir);
    }

    public function testRejectsStreamWrappers(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('php://filter/read=convert.base64-encode/resource=/etc/passwd', $this->testBaseDir);
    }

    public function testRejectsPharWrapper(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('phar:///tmp/evil.phar/file.txt', $this->testBaseDir);
    }

    public function testRejectsDotDotInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('..', $this->testBaseDir);
    }

    public function testRejectsDotInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('.', $this->testBaseDir);
    }

    public function testRejectsEmptyInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate('', $this->testBaseDir);
    }

    /**
     * @dataProvider bypassAttemptProvider
     */
    public function testRejectsTraversalBypassAttempts(string $maliciousInput): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PathValidator::validate($maliciousInput, $this->testBaseDir);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function bypassAttemptProvider(): array
    {
        return [
            'basic traversal' => ['../../../etc/passwd'],
            'backslash traversal' => ['..\\..\\..\\etc\\passwd'],
            'mixed separators' => ['..\/..\/etc/passwd'],
            'double dot at end' => ['subdir/..'],
            'current dir traversal' => ['./../../etc/passwd'],
            'embedded null byte' => ["test\0/../../../etc/passwd"],
            'url encoded traversal' => ['%2e%2e%2fetc/passwd'],
            'file wrapper' => ['file:///etc/passwd'],
            'php wrapper' => ['php://input'],
            'data wrapper' => ['data://text/plain;base64,SSBsb3ZlIFBIUAo='],
        ];
    }

    public function testBasenameStripsDirectoryComponents(): void
    {
        $this->assertSame('passwd', basename('../../../etc/passwd'));
        $this->assertSame('passwd', basename('/etc/passwd'));
        $this->assertSame('file.txt', basename('subdir/../file.txt'));
    }
}
```

### Integration Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class PathTraversalEndpointTest extends TestCase
{
    public function testDownloadEndpointRejectsTraversal(): void
    {
        $response = $this->client->request('GET', '/api/files/download', [
            'query' => ['file' => '../../../etc/passwd'],
        ]);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringNotContainsString('root:', $response->getContent());
    }

    public function testDownloadEndpointRejectsWrappers(): void
    {
        $response = $this->client->request('GET', '/api/files/download', [
            'query' => ['file' => 'php://filter/read=convert.base64-encode/resource=/etc/passwd'],
        ]);

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testDownloadEndpointServesAllowedFiles(): void
    {
        $response = $this->client->request('GET', '/api/files/download', [
            'query' => ['file' => 'report.pdf'],
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/octet-stream', $response->getHeaders()['content-type'][0]);
    }
}
```

## CVSS Scoring

```yaml
Vulnerability: Path Traversal - Arbitrary File Read
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Analysis:
  Attack Vector: Network (N)
    - Exploitable via HTTP request with crafted file parameter
  Attack Complexity: Low (L)
    - Simple ../ sequences, no special conditions
  Privileges Required: None (N)
    - Often exploitable without authentication
  User Interaction: None (N)
    - No user action needed
  Scope: Unchanged (U)
    - Limited to file system access
  Confidentiality: High (H)
    - Can read /etc/passwd, config files, source code, secrets
  Integrity: None (N)
    - Read-only access (for file read variant)
  Availability: None (N)
    - No service disruption

Base Score: 7.5 (HIGH)
```

```yaml
Vulnerability: Path Traversal - Arbitrary File Write
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Analysis:
  Attack Vector: Network (N)
  Attack Complexity: Low (L)
  Privileges Required: None (N)
  User Interaction: None (N)
  Scope: Changed (C)
    - Can write webshells, modify system files
  Confidentiality: High (H)
    - Code execution leads to full data access
  Integrity: High (H)
    - Can overwrite application files
  Availability: High (H)
    - Can delete or corrupt critical files

Base Score: 10.0 (CRITICAL)
```

## Remediation Priority

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Add `realpath()` + base directory validation to all file operations with user input | Immediate |
| Critical | Replace dynamic `include`/`require` with class autoloading or whitelists | Immediate |
| High | Use `basename()` for all user-supplied filenames in download handlers | 24 hours |
| High | Reject stream wrappers (`phar://`, `php://`, `file://`, `data://`) on file inputs | 24 hours |
| Medium | Migrate to framework file abstraction (TYPO3 FAL, Symfony Filesystem, Laravel Storage) | 1 week |
| Medium | Add static analysis rules to detect file operations with unsanitized paths | 1 week |
| Low | Implement file access audit logging for forensic analysis | 2 weeks |
| Low | Add comprehensive path traversal test coverage with bypass attempt data providers | 2 weeks |
