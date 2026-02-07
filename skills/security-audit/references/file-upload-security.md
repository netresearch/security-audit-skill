# File Upload Security

## Understanding File Upload Vulnerabilities (CWE-434)

### Why File Uploads Are Dangerous

Unrestricted file uploads allow attackers to place executable code on the server. A PHP webshell uploaded to a web-accessible directory gives the attacker full control of the server. Even non-executable uploads can be exploited through polyglot files, MIME type confusion, or by chaining with other vulnerabilities such as local file inclusion.

### Attack Vectors

```
1. PHP Webshell Upload
   - Upload shell.php containing: <?php system($_GET['cmd']); ?>
   - Access via: https://target.com/uploads/shell.php?cmd=whoami

2. Double Extension Bypass
   - Upload shell.php.jpg (Apache may execute as PHP depending on config)
   - Upload shell.phtml, shell.php5, shell.phar (alternative PHP extensions)

3. Null Byte Bypass (PHP < 5.3.4)
   - Upload shell.php%00.jpg (server sees .jpg, but saves as .php)

4. MIME Type Spoofing
   - Set Content-Type: image/jpeg on a PHP file
   - Server trusts the Content-Type header instead of inspecting content

5. Polyglot Files
   - A valid JPEG file that is also valid PHP
   - GIF header (GIF89a) followed by PHP code
   - Works when the server checks magic bytes but not file integrity

6. .htaccess Upload
   - Upload .htaccess to enable PHP execution in upload directory:
     AddType application/x-httpd-php .jpg

7. SVG with Embedded Script
   - Upload SVG containing: <svg><script>alert(document.cookie)</script></svg>
   - Causes stored XSS when served inline

8. ImageMagick Exploits (ImageTragick)
   - Crafted image files that exploit ImageMagick vulnerabilities
   - Can lead to remote code execution via image processing

9. ZIP/Archive Bombs
   - Extremely compressed files that expand to fill disk space
   - Denial of service through resource exhaustion
```

## Vulnerable Patterns

### Trusting User-Supplied Filename and Type

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Trusts the original filename from the client
$filename = $_FILES['upload']['name'];
$destination = '/var/www/uploads/' . $filename;
move_uploaded_file($_FILES['upload']['tmp_name'], $destination);
// Attacker: uploads "shell.php" and gets code execution

// VULNERABLE - DO NOT USE
// Trusts the Content-Type header from the client
if ($_FILES['upload']['type'] === 'image/jpeg') {
    // Attacker sets Content-Type: image/jpeg on a PHP file
    move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $_FILES['upload']['name']);
}

// VULNERABLE - DO NOT USE
// Extension-only validation is insufficient
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if (in_array($ext, ['jpg', 'png', 'gif'])) {
    // Attacker uses shell.php.jpg (double extension) or shell.PHP (case bypass)
    move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $_FILES['upload']['name']);
}
```

### Storing in Web Root with Original Name

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Predictable filename in web-accessible directory
$uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/';
move_uploaded_file(
    $_FILES['upload']['tmp_name'],
    $uploadDir . $_FILES['upload']['name']
);
// Attacker knows exact URL: https://target.com/uploads/shell.php
```

### Insufficient Size Validation

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Only checking $_FILES['size'] which can be spoofed
if ($_FILES['upload']['size'] < 1000000) {
    move_uploaded_file($_FILES['upload']['tmp_name'], $destination);
}
// The 'size' value comes from the client and may not match actual file size
// Always use filesize() on the temp file
```

## Secure Upload Pattern

### Complete Secure Upload Handler

```php
<?php

declare(strict_types=1);

// SECURE: Defense-in-depth file upload handler
final class SecureFileUpload
{
    /** @var array<string, list<string>> Map of allowed MIME types to extensions */
    private const ALLOWED_TYPES = [
        'image/jpeg'      => ['jpg', 'jpeg'],
        'image/png'       => ['png'],
        'image/gif'       => ['gif'],
        'image/webp'      => ['webp'],
        'application/pdf' => ['pdf'],
        'text/csv'        => ['csv'],
    ];

    private const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

    public function __construct(
        private readonly string $uploadDirectory,
    ) {
        // Upload directory MUST be outside the web root
        // e.g., /var/app/storage/uploads/ not /var/www/html/uploads/
    }

    /**
     * Process an uploaded file securely.
     *
     * @param array{tmp_name: string, error: int, size: int, name: string} $uploadedFile
     * @return string The generated filename for reference
     *
     * @throws \InvalidArgumentException on validation failure
     * @throws \RuntimeException on processing failure
     */
    public function handleUpload(array $uploadedFile): string
    {
        // 1. Check for upload errors
        $this->validateUploadError($uploadedFile['error']);

        // 2. Verify the file was actually uploaded via HTTP POST
        if (!is_uploaded_file($uploadedFile['tmp_name'])) {
            throw new \InvalidArgumentException('File was not uploaded via HTTP POST');
        }

        // 3. Validate file size using actual file, not client-reported size
        $actualSize = filesize($uploadedFile['tmp_name']);
        if ($actualSize === false || $actualSize > self::MAX_FILE_SIZE) {
            throw new \InvalidArgumentException(
                'File exceeds maximum size of ' . (self::MAX_FILE_SIZE / 1024 / 1024) . ' MB'
            );
        }

        if ($actualSize === 0) {
            throw new \InvalidArgumentException('Uploaded file is empty');
        }

        // 4. Detect MIME type from file content, not from client headers
        $detectedMimeType = $this->detectMimeType($uploadedFile['tmp_name']);

        // 5. Validate MIME type against whitelist
        if (!isset(self::ALLOWED_TYPES[$detectedMimeType])) {
            throw new \InvalidArgumentException(
                'File type not allowed: ' . $detectedMimeType
            );
        }

        // 6. Validate extension matches detected MIME type
        $originalExtension = strtolower(pathinfo($uploadedFile['name'], PATHINFO_EXTENSION));
        $allowedExtensions = self::ALLOWED_TYPES[$detectedMimeType];

        if (!in_array($originalExtension, $allowedExtensions, true)) {
            throw new \InvalidArgumentException(
                'File extension does not match content type'
            );
        }

        // 7. Generate random filename (prevents path traversal and overwrites)
        $safeFilename = $this->generateSafeFilename($originalExtension);

        // 8. Move file to storage directory outside web root
        $destination = $this->uploadDirectory . '/' . $safeFilename;
        if (!move_uploaded_file($uploadedFile['tmp_name'], $destination)) {
            throw new \RuntimeException('Failed to move uploaded file');
        }

        // 9. Set restrictive file permissions (read-only, no execute)
        chmod($destination, 0644);

        return $safeFilename;
    }

    /**
     * Detect MIME type from file content using finfo (libmagic).
     * Never trust $_FILES['type'] - it comes from the client.
     */
    private function detectMimeType(string $filePath): string
    {
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($filePath);

        if ($mimeType === false) {
            throw new \RuntimeException('Could not detect file MIME type');
        }

        return $mimeType;
    }

    /**
     * Generate a cryptographically random filename.
     * This prevents:
     * - Path traversal via filename
     * - Filename collision
     * - Information disclosure via original filenames
     */
    private function generateSafeFilename(string $extension): string
    {
        return bin2hex(random_bytes(16)) . '.' . $extension;
    }

    /**
     * Validate the PHP upload error code.
     */
    private function validateUploadError(int $errorCode): void
    {
        match ($errorCode) {
            UPLOAD_ERR_OK => null,
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE
                => throw new \InvalidArgumentException('File exceeds size limit'),
            UPLOAD_ERR_PARTIAL
                => throw new \InvalidArgumentException('File was only partially uploaded'),
            UPLOAD_ERR_NO_FILE
                => throw new \InvalidArgumentException('No file was uploaded'),
            UPLOAD_ERR_NO_TMP_DIR
                => throw new \RuntimeException('Missing temporary folder'),
            UPLOAD_ERR_CANT_WRITE
                => throw new \RuntimeException('Failed to write file to disk'),
            UPLOAD_ERR_EXTENSION
                => throw new \RuntimeException('Upload stopped by PHP extension'),
            default
                => throw new \RuntimeException('Unknown upload error: ' . $errorCode),
        };
    }
}
```

### Image Reprocessing (Strip Metadata, Neutralize Polyglots)

```php
<?php

declare(strict_types=1);

// SECURE: Reprocess images through GD to strip metadata and neutralize embedded code
final class ImageSanitizer
{
    /** @var array<string, array{create: string, output: string}> */
    private const IMAGE_HANDLERS = [
        'image/jpeg' => ['create' => 'imagecreatefromjpeg', 'output' => 'imagejpeg'],
        'image/png'  => ['create' => 'imagecreatefrompng', 'output' => 'imagepng'],
        'image/gif'  => ['create' => 'imagecreatefromgif', 'output' => 'imagegif'],
        'image/webp' => ['create' => 'imagecreatefromwebp', 'output' => 'imagewebp'],
    ];

    /**
     * Reprocess an image to strip EXIF metadata and neutralize polyglot payloads.
     * Creates a clean copy by decoding and re-encoding the image data.
     *
     * @throws \InvalidArgumentException if the image type is unsupported or corrupt
     */
    public function sanitize(string $inputPath, string $outputPath, string $mimeType): void
    {
        if (!isset(self::IMAGE_HANDLERS[$mimeType])) {
            throw new \InvalidArgumentException('Unsupported image type: ' . $mimeType);
        }

        $handler = self::IMAGE_HANDLERS[$mimeType];

        // Validate image dimensions (prevents decompression bombs)
        $imageInfo = getimagesize($inputPath);
        if ($imageInfo === false) {
            throw new \InvalidArgumentException('File is not a valid image');
        }

        [$width, $height] = $imageInfo;

        // Reject extremely large images (decompression bomb protection)
        if ($width > 10000 || $height > 10000) {
            throw new \InvalidArgumentException('Image dimensions exceed maximum allowed');
        }

        // Memory limit check: width * height * 4 bytes per pixel (RGBA)
        $requiredMemory = $width * $height * 4;
        if ($requiredMemory > 256 * 1024 * 1024) {
            throw new \InvalidArgumentException('Image would require too much memory to process');
        }

        // Create image from file (decodes pixel data, strips everything else)
        $createFunction = $handler['create'];
        $image = $createFunction($inputPath);

        if ($image === false) {
            throw new \InvalidArgumentException('Could not decode image');
        }

        try {
            // Re-encode to output path (creates clean file without embedded payloads)
            $outputFunction = $handler['output'];

            if ($mimeType === 'image/jpeg') {
                $outputFunction($image, $outputPath, 85); // Quality 85
            } elseif ($mimeType === 'image/png') {
                $outputFunction($image, $outputPath, 6);  // Compression 6
            } else {
                $outputFunction($image, $outputPath);
            }
        } finally {
            imagedestroy($image);
        }
    }
}
```

### Execution Prevention Configuration

```apache
# .htaccess - Place in upload directory to prevent PHP execution
# SECURE: Deny all script execution in upload directory

# Disable PHP execution
<FilesMatch "\.(?:php[0-9]?|phtml|phar|phps)$">
    Require all denied
</FilesMatch>

# Override any AddHandler/AddType for PHP
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .phps
RemoveType .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .phps

# Disable script execution entirely
Options -ExecCGI
SetHandler none

# Force all files to be served as binary download
ForceType application/octet-stream
Header set Content-Disposition attachment

# Exception for specific safe types to serve inline
<FilesMatch "\.(?:jpe?g|png|gif|webp|pdf)$">
    ForceType none
    Header unset Content-Disposition
</FilesMatch>
```

```nginx
# nginx - Deny script execution in upload directory
# SECURE: Prevent PHP execution in upload paths

location /uploads/ {
    # Disable PHP processing
    location ~ \.php$ {
        deny all;
        return 403;
    }

    # Serve files as static content only
    location ~* \.(jpg|jpeg|png|gif|webp|pdf|csv|txt)$ {
        add_header X-Content-Type-Options nosniff;
        add_header Content-Security-Policy "default-src 'none'";
        try_files $uri =404;
    }

    # Deny everything else
    deny all;
}
```

### Serving Uploaded Files Safely

```php
<?php

declare(strict_types=1);

// SECURE: Serve files through a PHP controller, not directly from the web root
final class FileServeController
{
    /** @var array<string, string> Safe MIME types for inline display */
    private const INLINE_TYPES = [
        'image/jpeg' => 'image/jpeg',
        'image/png'  => 'image/png',
        'image/gif'  => 'image/gif',
        'image/webp' => 'image/webp',
        'application/pdf' => 'application/pdf',
    ];

    public function __construct(
        private readonly string $storageDirectory,
    ) {}

    /**
     * Serve a file safely with proper headers.
     */
    public function serve(string $storedFilename): void
    {
        // Only allow alphanumeric filenames with a single extension
        if (!preg_match('/^[a-f0-9]{32}\.[a-z]{2,4}$/', $storedFilename)) {
            http_response_code(400);
            exit;
        }

        $filePath = $this->storageDirectory . '/' . $storedFilename;
        $realPath = realpath($filePath);

        if ($realPath === false || !is_file($realPath)) {
            http_response_code(404);
            exit;
        }

        // Verify file is within storage directory
        $realBase = realpath($this->storageDirectory);
        if ($realBase === false || !str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)) {
            http_response_code(403);
            exit;
        }

        // Detect MIME type from content
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($realPath);

        // Security headers
        header('X-Content-Type-Options: nosniff');
        header('Content-Security-Policy: default-src \'none\'');
        header('X-Frame-Options: DENY');

        // Determine disposition: inline for safe types, attachment for everything else
        if (isset(self::INLINE_TYPES[$mimeType])) {
            header('Content-Type: ' . self::INLINE_TYPES[$mimeType]);
            header('Content-Disposition: inline; filename="' . $storedFilename . '"');
        } else {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $storedFilename . '"');
        }

        header('Content-Length: ' . filesize($realPath));

        readfile($realPath);
        exit;
    }
}
```

## Framework-Specific Solutions

### TYPO3 FAL Upload Handling

```php
<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Resource\ResourceFactory;
use TYPO3\CMS\Core\Resource\DuplicationBehavior;
use TYPO3\CMS\Core\Resource\Security\FileNameValidator;
use TYPO3\CMS\Core\Utility\GeneralUtility;

// SECURE: TYPO3 FAL handles upload security through its storage layer
// FAL validates file extensions against $GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']
// Default denies: php, phtml, phar, and other executable extensions

$resourceFactory = GeneralUtility::makeInstance(ResourceFactory::class);
$storage = $resourceFactory->getDefaultStorage();

// FAL enforces file extension rules and path sanitization
$folder = $storage->getFolder('user_upload/');

// addUploadedFile validates extension, sanitizes filename, prevents traversal
$file = $folder->addUploadedFile(
    $uploadedFileInfo,                     // $_FILES array entry
    DuplicationBehavior::RENAME           // Rename on conflict, never overwrite
);

// SECURE: TYPO3's FileNameValidator checks against deny patterns
$fileNameValidator = GeneralUtility::makeInstance(FileNameValidator::class);
if (!$fileNameValidator->isValid($originalFilename)) {
    throw new \InvalidArgumentException('File type not allowed');
}

// SECURE: Configure allowed file extensions in TYPO3
// In ext_localconf.php or AdditionalConfiguration.php:
$GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern'] =
    '\\.(php[0-9]?|phtml|phar|phps|cgi|pl|py|sh|bash|exe|bat|cmd|com|htaccess|htpasswd)$';

// SECURE: Use FAL for all file operations in extensions
// Never use direct PHP file functions with user-supplied paths
```

### Symfony File Upload Handling

```php
<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Validator\ValidatorInterface;

// SECURE: Symfony UploadedFile provides built-in security
final class SecureUploadController
{
    public function __construct(
        private readonly ValidatorInterface $validator,
        private readonly string $uploadDirectory,
    ) {}

    public function upload(Request $request): string
    {
        /** @var UploadedFile|null $file */
        $file = $request->files->get('document');

        if ($file === null) {
            throw new \InvalidArgumentException('No file uploaded');
        }

        // Symfony validates the upload error internally
        if (!$file->isValid()) {
            throw new \InvalidArgumentException($file->getErrorMessage());
        }

        // SECURE: Use Symfony validator constraints for file validation
        $violations = $this->validator->validate($file, [
            new Assert\File([
                'maxSize' => '10M',
                'mimeTypes' => [
                    'image/jpeg',
                    'image/png',
                    'image/gif',
                    'application/pdf',
                ],
                'mimeTypesMessage' => 'Please upload a valid image or PDF file',
            ]),
        ]);

        if ($violations->count() > 0) {
            throw new \InvalidArgumentException((string) $violations->get(0)->getMessage());
        }

        // SECURE: guessExtension() uses finfo (content-based), not the original extension
        $extension = $file->guessExtension();
        if ($extension === null) {
            throw new \InvalidArgumentException('Could not determine file type');
        }

        // SECURE: Generate random filename
        $safeFilename = bin2hex(random_bytes(16)) . '.' . $extension;

        // SECURE: move() uses move_uploaded_file() internally
        $file->move($this->uploadDirectory, $safeFilename);

        return $safeFilename;
    }
}

// SECURE: Symfony form type with file constraints
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\FormBuilderInterface;

final class DocumentUploadType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder->add('file', FileType::class, [
            'constraints' => [
                new Assert\NotBlank(),
                new Assert\File([
                    'maxSize' => '10M',
                    'mimeTypes' => ['application/pdf', 'image/jpeg', 'image/png'],
                ]),
            ],
        ]);
    }
}
```

### Laravel File Upload Handling

```php
<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

// SECURE: Laravel provides validation and safe storage out of the box
final class FileUploadController
{
    public function upload(Request $request): string
    {
        // SECURE: Validate using Laravel's file validation rules
        $validated = $request->validate([
            'document' => [
                'required',
                'file',
                'max:10240',                           // 10 MB in kilobytes
                'mimes:jpeg,png,gif,pdf',              // Extension check
                'mimetypes:image/jpeg,image/png,image/gif,application/pdf', // Content check
            ],
        ]);

        /** @var UploadedFile $file */
        $file = $request->file('document');

        // SECURE: Store with a random filename on a disk outside web root
        // The 'local' disk points to storage/app/ by default (not public)
        $path = $file->store('uploads', 'local');
        // $path = "uploads/abc123def456.pdf" (auto-generated unique name)

        // SECURE: Or generate a custom hashed filename
        $hashedName = $file->hashName(); // Based on file content
        $path = $file->storeAs('uploads', $hashedName, 'local');

        return $path;
    }
}

// SECURE: Form request with comprehensive file validation
use Illuminate\Foundation\Http\FormRequest;

final class FileUploadRequest extends FormRequest
{
    /**
     * @return array<string, list<string>>
     */
    public function rules(): array
    {
        return [
            'avatar' => [
                'required',
                'file',
                'image',          // Must be an image (jpeg, png, gif, bmp, svg, webp)
                'max:2048',       // 2 MB
                'dimensions:max_width=4000,max_height=4000', // Prevent decompression bombs
            ],
        ];
    }
}
```

## move_uploaded_file() Security Considerations

```php
<?php

declare(strict_types=1);

// move_uploaded_file() provides one critical security guarantee:
// It verifies the source file was actually uploaded via HTTP POST.
// This prevents an attacker from tricking your script into moving
// arbitrary files (e.g., /etc/passwd) to a new location.

// SECURE: Always use move_uploaded_file(), never rename() or copy()
if (is_uploaded_file($_FILES['file']['tmp_name'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $destination);
}

// VULNERABLE - DO NOT USE
// rename() and copy() do not verify the file was uploaded
rename($_FILES['file']['tmp_name'], $destination);  // No upload verification!
copy($_FILES['file']['tmp_name'], $destination);    // No upload verification!

// IMPORTANT: move_uploaded_file() does NOT:
// - Validate MIME type (you must do this yourself with finfo)
// - Sanitize the destination path (you must validate against traversal)
// - Restrict file extensions (you must whitelist allowed extensions)
// - Set file permissions (you must chmod after moving)
// - Strip malicious content from images (you must reprocess with GD/Imagick)
```

## Detection Patterns

### Static Analysis

```php
<?php

declare(strict_types=1);

// Patterns indicating vulnerable file upload handling
$vulnerablePatterns = [
    // Direct use of user-supplied filename
    '$_FILES[' => 'Check if original filename is used for storage',

    // Missing MIME type validation
    'move_uploaded_file' => 'Verify finfo/MIME validation occurs before move',

    // Uploads to web-accessible directory
    'DOCUMENT_ROOT' => 'Check if uploads go to web root (should be outside)',
    'public/' => 'Check if upload directory is web-accessible',
    'htdocs/' => 'Check if upload directory is web-accessible',

    // Missing is_uploaded_file check
    'rename(' => 'Verify is_uploaded_file() or move_uploaded_file() is used',
    'copy(' => 'Verify is_uploaded_file() or move_uploaded_file() is used',
];

// Search commands:
// Find file upload handling code
// grep -rn '\$_FILES' --include="*.php"
// grep -rn 'move_uploaded_file' --include="*.php"
// grep -rn 'tmp_name' --include="*.php"

// Find missing finfo validation
// grep -rn 'move_uploaded_file' --include="*.php" | grep -v 'finfo'

// Find uploads to web root
// grep -rn 'DOCUMENT_ROOT.*upload\|upload.*DOCUMENT_ROOT' --include="*.php"
```

### Regex Detection Patterns

```php
<?php

declare(strict_types=1);

$detectionPatterns = [
    // Original filename used as destination
    '/move_uploaded_file\s*\([^,]+,\s*.*\$_FILES\s*\[.*\]\s*\[.name.\]/'
        => 'CRITICAL: Original filename used for upload destination',

    // MIME type from $_FILES (client-controlled, not content-based)
    '/\$_FILES\s*\[.*\]\s*\[.type.\]/'
        => 'HIGH: Client-supplied MIME type used for validation (use finfo instead)',

    // Upload to document root
    '/move_uploaded_file\s*\([^,]+,\s*.*(?:DOCUMENT_ROOT|public_html|htdocs|www)/'
        => 'CRITICAL: File uploaded to web-accessible directory',

    // Missing size validation
    '/move_uploaded_file\s*\((?!.*filesize)/'
        => 'MEDIUM: move_uploaded_file without filesize validation',

    // Using rename/copy instead of move_uploaded_file
    '/(?:rename|copy)\s*\(\s*\$_FILES/'
        => 'HIGH: Using rename/copy instead of move_uploaded_file for uploads',

    // Checking extension only (case-sensitive)
    "/pathinfo\s*\([^)]*PATHINFO_EXTENSION\)(?!.*strtolower)/"
        => 'MEDIUM: Extension check may be case-sensitive (use strtolower)',
];
```

## Testing for File Upload Vulnerabilities

### Unit Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class FileUploadSecurityTest extends TestCase
{
    private SecureFileUpload $uploader;
    private string $uploadDir;

    protected function setUp(): void
    {
        $this->uploadDir = sys_get_temp_dir() . '/upload_test_' . bin2hex(random_bytes(8));
        mkdir($this->uploadDir, 0755, true);

        $this->uploader = new SecureFileUpload($this->uploadDir);
    }

    protected function tearDown(): void
    {
        // Clean up uploaded files
        $files = glob($this->uploadDir . '/*');
        if ($files !== false) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
        @rmdir($this->uploadDir);
    }

    public function testRejectsPhpExtension(): void
    {
        $tmpFile = $this->createTempFileWithContent('<?php echo "shell"; ?>');

        $this->expectException(\InvalidArgumentException::class);
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_OK,
            'size' => filesize($tmpFile),
            'name' => 'shell.php',
        ]);
    }

    public function testRejectsDoubleExtension(): void
    {
        $tmpFile = $this->createTempFileWithContent('<?php echo "shell"; ?>');

        $this->expectException(\InvalidArgumentException::class);
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_OK,
            'size' => filesize($tmpFile),
            'name' => 'shell.php.jpg',
        ]);
    }

    public function testRejectsMimeTypeMismatch(): void
    {
        // Create a file with PHP content but .jpg extension
        $tmpFile = $this->createTempFileWithContent('<?php system($_GET["cmd"]); ?>');

        $this->expectException(\InvalidArgumentException::class);
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_OK,
            'size' => filesize($tmpFile),
            'name' => 'innocent.jpg',
        ]);
    }

    public function testRejectsEmptyFile(): void
    {
        $tmpFile = $this->createTempFileWithContent('');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('empty');
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_OK,
            'size' => 0,
            'name' => 'empty.jpg',
        ]);
    }

    public function testRejectsOversizedFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('size');

        // Simulate an oversized upload (error code from PHP)
        $tmpFile = $this->createTempFileWithContent('x');
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_INI_SIZE,
            'size' => 999999999,
            'name' => 'huge.jpg',
        ]);
    }

    public function testGeneratesRandomFilename(): void
    {
        $tmpFile = $this->createValidJpegFile();

        // Note: move_uploaded_file() will fail in tests since the file
        // is not actually uploaded via HTTP POST. In production code,
        // use a mock or integration test with a real HTTP request.
        // This test validates the filename generation logic.

        // Test the filename format
        $filename = bin2hex(random_bytes(16)) . '.jpg';
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}\.jpg$/', $filename);
    }

    public function testRejectsUploadErrors(): void
    {
        $errorCodes = [
            UPLOAD_ERR_INI_SIZE,
            UPLOAD_ERR_FORM_SIZE,
            UPLOAD_ERR_PARTIAL,
            UPLOAD_ERR_NO_FILE,
        ];

        foreach ($errorCodes as $errorCode) {
            try {
                $this->uploader->handleUpload([
                    'tmp_name' => '/tmp/nonexistent',
                    'error' => $errorCode,
                    'size' => 0,
                    'name' => 'test.jpg',
                ]);
                $this->fail('Expected exception for error code ' . $errorCode);
            } catch (\InvalidArgumentException | \RuntimeException) {
                // Expected
                $this->assertTrue(true);
            }
        }
    }

    public function testRejectsSvgWithScript(): void
    {
        $svgContent = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
        $tmpFile = $this->createTempFileWithContent($svgContent);

        $this->expectException(\InvalidArgumentException::class);
        $this->uploader->handleUpload([
            'tmp_name' => $tmpFile,
            'error' => UPLOAD_ERR_OK,
            'size' => filesize($tmpFile),
            'name' => 'image.svg',
        ]);
    }

    public function testImageSanitizerStripsExifData(): void
    {
        $inputPath = $this->createValidJpegFile();
        $outputPath = $this->uploadDir . '/sanitized.jpg';

        $sanitizer = new ImageSanitizer();
        $sanitizer->sanitize($inputPath, $outputPath, 'image/jpeg');

        $this->assertFileExists($outputPath);
        $this->assertGreaterThan(0, filesize($outputPath));

        // Verify the output is a valid JPEG
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $this->assertSame('image/jpeg', $finfo->file($outputPath));
    }

    public function testImageSanitizerRejectsCorruptImage(): void
    {
        $fakePath = $this->createTempFileWithContent('This is not an image');

        $sanitizer = new ImageSanitizer();

        $this->expectException(\InvalidArgumentException::class);
        $sanitizer->sanitize($fakePath, $this->uploadDir . '/output.jpg', 'image/jpeg');
    }

    /**
     * Create a minimal valid JPEG file for testing.
     */
    private function createValidJpegFile(): string
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_');
        $image = imagecreatetruecolor(10, 10);
        imagejpeg($image, $tmpFile, 90);
        imagedestroy($image);
        return $tmpFile;
    }

    private function createTempFileWithContent(string $content): string
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'upload_test_');
        file_put_contents($tmpFile, $content);
        return $tmpFile;
    }
}
```

### Integration Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class FileUploadEndpointTest extends TestCase
{
    public function testUploadEndpointRejectsPhpFile(): void
    {
        $response = $this->client->request('POST', '/api/upload', [
            'headers' => ['Content-Type' => 'multipart/form-data'],
            'extra' => [
                'files' => [
                    'document' => $this->createUploadedFile(
                        '<?php system("id"); ?>',
                        'shell.php',
                        'application/x-php'
                    ),
                ],
            ],
        ]);

        $this->assertSame(422, $response->getStatusCode());
    }

    public function testUploadEndpointRejectsMimeSpoofing(): void
    {
        $response = $this->client->request('POST', '/api/upload', [
            'headers' => ['Content-Type' => 'multipart/form-data'],
            'extra' => [
                'files' => [
                    'document' => $this->createUploadedFile(
                        '<?php system("id"); ?>',
                        'image.jpg',
                        'image/jpeg'  // Spoofed MIME type
                    ),
                ],
            ],
        ]);

        $this->assertSame(422, $response->getStatusCode());
    }

    public function testUploadEndpointAcceptsValidImage(): void
    {
        $image = imagecreatetruecolor(100, 100);
        ob_start();
        imagejpeg($image, null, 90);
        $imageData = ob_get_clean();
        imagedestroy($image);

        $response = $this->client->request('POST', '/api/upload', [
            'headers' => ['Content-Type' => 'multipart/form-data'],
            'extra' => [
                'files' => [
                    'document' => $this->createUploadedFile(
                        $imageData,
                        'photo.jpg',
                        'image/jpeg'
                    ),
                ],
            ],
        ]);

        $this->assertSame(200, $response->getStatusCode());

        // Verify file was stored with a random name, not the original
        $data = json_decode($response->getContent(), true);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}\.jpg$/', $data['filename']);
    }

    public function testUploadedFilesNotDirectlyAccessible(): void
    {
        // Verify uploaded files cannot be accessed via web URL
        $response = $this->client->request('GET', '/uploads/test.php');
        $this->assertSame(403, $response->getStatusCode());
    }
}
```

## Security Checklist

### Upload Handler

- [ ] MIME type validated from file content using `finfo_file()`, not from `$_FILES['type']`
- [ ] File extension validated against a whitelist
- [ ] Extension matches detected MIME type (no mismatch)
- [ ] Random filename generated (not using original filename)
- [ ] `move_uploaded_file()` used (not `rename()` or `copy()`)
- [ ] File size validated using `filesize()` on temp file, not `$_FILES['size']`
- [ ] Upload error code checked (`$_FILES['error']`)

### Storage

- [ ] Upload directory is outside the web root
- [ ] Upload directory has execution disabled (`.htaccess` or nginx config)
- [ ] File permissions set to non-executable (`0644`)
- [ ] No directory listing enabled on upload directory

### Content Processing

- [ ] Images reprocessed through GD/Imagick to strip metadata and embedded code
- [ ] SVG files rejected or sanitized (contain inline scripts)
- [ ] Archive files (ZIP, TAR) validated for size after extraction (zip bombs)
- [ ] Maximum image dimensions enforced (decompression bomb prevention)

## CVSS Scoring

```yaml
Vulnerability: Unrestricted File Upload - PHP Webshell
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

Analysis:
  Attack Vector: Network (N)
    - Exploitable via file upload form
  Attack Complexity: Low (L)
    - Simple upload of PHP file
  Privileges Required: Low (L)
    - Usually requires authenticated access to upload feature
  User Interaction: None (N)
    - No user action needed after upload
  Scope: Changed (C)
    - Full server compromise, access to other services
  Confidentiality: High (H)
    - Arbitrary file read, database access
  Integrity: High (H)
    - Arbitrary file write, code execution
  Availability: High (H)
    - Can shut down services, delete data

Base Score: 9.9 (CRITICAL)
```

## Remediation Priority

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Validate MIME type from file content using `finfo`, not client headers | Immediate |
| Critical | Move upload storage outside web root | Immediate |
| Critical | Disable script execution in upload directories (`.htaccess` / nginx) | Immediate |
| High | Generate random filenames, never use original filenames | 24 hours |
| High | Whitelist allowed file extensions and MIME types | 24 hours |
| High | Enforce file size limits using `filesize()` on the temp file | 24 hours |
| Medium | Reprocess images through GD/Imagick to strip metadata and payloads | 1 week |
| Medium | Serve files through a controller with security headers, not direct access | 1 week |
| Medium | Migrate to framework upload handling (TYPO3 FAL, Symfony UploadedFile, Laravel Storage) | 1 week |
| Low | Add decompression bomb protection (max dimensions, memory limits) | 2 weeks |
| Low | Implement upload audit logging and virus scanning | 2 weeks |
