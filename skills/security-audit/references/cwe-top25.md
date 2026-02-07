# CWE Top 25 Most Dangerous Software Weaknesses (2025)

Navigation document mapping all 25 CWEs from the [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) to skill coverage.

**PHP-relevant: 18 of 25.** Memory-safety CWEs (5, 7, 8, 11, 13, 14, 16) are not applicable to PHP.

---

## Rank 1 — CWE-79: Cross-Site Scripting (XSS)

**MITRE Score:** 56.94 | **PHP:** Yes

Improper neutralization of input during web page generation.

**Vulnerable:**
```php
echo $_GET['name']; // Reflected XSS
echo $userInput;    // Stored XSS if from database
```

**Secure:**
```php
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
// Fluid templates escape by default; avoid f:format.raw with user data
```

**Coverage:**
- Reference: `owasp-top10.md`
- Checkpoints: SA-13 (echo $), SA-19 (LLM XSS review)
- Script: XSS pattern check in `security-audit.sh`

---

## Rank 2 — CWE-89: SQL Injection

**MITRE Score:** 41.61 | **PHP:** Yes

Improper neutralization of special elements used in an SQL command.

**Vulnerable:**
```php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$db->query($query);
```

**Secure:**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
// TYPO3: $queryBuilder->createNamedParameter($id)
```

**Coverage:**
- Reference: `owasp-top10.md`
- Checkpoints: SA-10 ($_GET), SA-11 ($_POST), SA-12 ($_REQUEST), SA-17 (LLM SQL review)
- Script: SQL injection pattern check in `security-audit.sh`

---

## Rank 3 — CWE-352: Cross-Site Request Forgery (CSRF)

**MITRE Score:** 34.39 | **PHP:** Yes

Missing or improper validation of CSRF tokens on state-changing requests.

**Vulnerable:**
```php
// POST handler without CSRF token validation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db->delete('users', ['id' => $_POST['id']]);
}
```

**Secure:**
```php
// Verify CSRF token on every state-changing endpoint
if (!hash_equals($_SESSION['csrf_token'], $_POST['_token'])) {
    throw new SecurityException('CSRF token mismatch');
}
// TYPO3: Use FormProtectionFactory
```

**Coverage:**
- Checkpoints: SA-LLM-25 (LLM CSRF review)
- Script: CSRF reference count in `security-audit.sh`

---

## Rank 4 — CWE-862: Missing Authorization

**MITRE Score:** 31.33 | **PHP:** Yes

Software does not perform an authorization check when accessing a resource or performing an action.

**Vulnerable:**
```php
// Admin endpoint with no authorization check
public function deleteUser(int $userId): void {
    $this->userRepository->delete($userId);
}
```

**Secure:**
```php
public function deleteUser(int $userId): void {
    if (!$this->authService->isAdmin($this->currentUser)) {
        throw new AccessDeniedException();
    }
    $this->userRepository->delete($userId);
}
```

**Coverage:**
- Reference: `authentication-patterns.md`
- Checkpoints: SA-20 (LLM auth/authz review)

---

## Rank 5 — CWE-787: Out-of-bounds Write

**MITRE Score:** 27.40 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (managed memory).

---

## Rank 6 — CWE-22: Path Traversal

**MITRE Score:** 23.41 | **PHP:** Yes

Improper limitation of a pathname to a restricted directory.

**Vulnerable:**
```php
$file = $_GET['file'];
readfile('/uploads/' . $file); // ../../../etc/passwd
```

**Secure:**
```php
$filename = basename($_GET['file']); // Strip path components
$path = realpath('/uploads/' . $filename);
$baseDir = realpath('/uploads');
if ($path === false || $baseDir === false || !str_starts_with($path, $baseDir . DIRECTORY_SEPARATOR)) {
    throw new SecurityException('Invalid path');
}
readfile($path);
```

**Coverage:**
- Reference: `path-traversal-prevention.md`
- Checkpoints: SA-34 (open redirect), SA-35 (open redirect)
- Script: Path traversal check in `security-audit.sh`

---

## Rank 7 — CWE-416: Use After Free

**MITRE Score:** 22.40 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (garbage collected).

---

## Rank 8 — CWE-125: Out-of-bounds Read

**MITRE Score:** 21.73 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (managed memory).

---

## Rank 9 — CWE-78: OS Command Injection

**MITRE Score:** 20.03 | **PHP:** Yes

Improper neutralization of special elements used in an OS command.

**Vulnerable:**
```php
$host = $_GET['host'];
system("ping -c 4 " . $host); // ; rm -rf / injection
```

**Secure:**
```php
$host = escapeshellarg($_GET['host']);
system("ping -c 4 " . $host);
// Better: use Symfony Process component
$process = new Process(['ping', '-c', '4', $host]);
```

**Coverage:**
- Reference: `owasp-top10.md`
- Checkpoints: SA-25 (exec), SA-26 (system), SA-27 (shell_exec), SA-28 (passthru)
- Script: Command injection check in `security-audit.sh`

---

## Rank 10 — CWE-94: Code Injection

**MITRE Score:** 19.42 | **PHP:** Yes

Improper control of generation of code.

**Vulnerable:**
```php
// DANGEROUS: Dynamic code execution with variable input
$result = call_user_func($_GET['callback'], $data);
preg_replace('/' . $pattern . '/e', $replacement, $subject); // Deprecated /e modifier
```

**Secure:**
```php
// Use allowlists for callable references
$allowed = ['strtoupper', 'strtolower', 'trim'];
if (!in_array($callback, $allowed, true)) {
    throw new SecurityException('Invalid callback');
}
// Use preg_replace_callback() instead of /e modifier
preg_replace_callback('/pattern/', function ($m) {
    return strtoupper($m[0]);
}, $subject);
```

**Coverage:**
- Checkpoints: SA-37 (dynamic execution), SA-38 (assert), SA-39 (preg_replace /e), SA-LLM-27 (LLM code injection review)
- Script: Dangerous functions check in `security-audit.sh`

---

## Rank 11 — CWE-120: Buffer Overflow (Classic)

**MITRE Score:** 17.70 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (managed memory).

---

## Rank 12 — CWE-434: Unrestricted File Upload

**MITRE Score:** 17.25 | **PHP:** Yes

Unrestricted upload of file with dangerous type.

**Vulnerable:**
```php
move_uploaded_file(
    $_FILES['file']['tmp_name'],
    '/uploads/' . $_FILES['file']['name']
);
```

**Secure:**
```php
$allowed = ['image/jpeg', 'image/png', 'image/gif'];
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['file']['tmp_name']);
if (!in_array($mime, $allowed, true)) {
    throw new SecurityException('Invalid file type');
}
$safeName = bin2hex(random_bytes(16)) . '.jpg';
move_uploaded_file(
    $_FILES['file']['tmp_name'],
    '/uploads/' . $safeName
);
```

**Coverage:**
- Reference: `file-upload-security.md`
- Checkpoints: SA-32 (move_uploaded_file), SA-LLM-22 (LLM file upload review)

---

## Rank 13 — CWE-476: NULL Pointer Dereference

**MITRE Score:** 16.72 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (null is a value type).

---

## Rank 14 — CWE-121: Stack-based Buffer Overflow

**MITRE Score:** 14.20 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (managed memory).

---

## Rank 15 — CWE-502: Deserialization of Untrusted Data

**MITRE Score:** 14.12 | **PHP:** Yes

Deserialization of untrusted data can lead to remote code execution.

**Vulnerable:**
```php
$data = unserialize($_POST['data']); // RCE via __wakeup()/__destruct() gadget chains
```

**Secure:**
```php
// Best: use JSON
$data = json_decode($_POST['data'], true, 512, JSON_THROW_ON_ERROR);
// If unserialize is required:
$data = unserialize($trustedData, ['allowed_classes' => false]);
```

**Coverage:**
- Reference: `deserialization-prevention.md`
- Checkpoints: SA-21 (unserialize $_), SA-22 (unserialize $), SA-LLM-21 (LLM deserialization review)

---

## Rank 16 — CWE-122: Heap-based Buffer Overflow

**MITRE Score:** 13.06 | **PHP:** N/A

Memory-safety vulnerability. Not applicable to PHP (managed memory).

---

## Rank 17 — CWE-863: Incorrect Authorization

**MITRE Score:** 12.94 | **PHP:** Yes

Software performs an authorization check but does it incorrectly.

**Vulnerable:**
```php
// Checking role name with loose comparison or wrong logic
if ($user->role == 'admin' || $user->role == 'editor') {
    // Missing: check if editor is allowed THIS specific action
    $this->deleteAllPosts();
}
```

**Secure:**
```php
// Use permission-based checks, not just role checks
if (!$this->accessControl->isAllowed($user, 'posts.delete_all')) {
    throw new AccessDeniedException();
}
```

**Coverage:**
- Reference: `authentication-patterns.md`
- Checkpoints: SA-20 (LLM auth/authz review)

---

## Rank 18 — CWE-20: Improper Input Validation

**MITRE Score:** 12.70 | **PHP:** Yes

Software does not validate or incorrectly validates input.

**Vulnerable:**
```php
$age = $_POST['age'];
$query = "UPDATE users SET age = $age"; // No validation at all
```

**Secure:**
```php
$age = filter_input(INPUT_POST, 'age', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 0, 'max_range' => 150]
]);
if ($age === false || $age === null) {
    throw new ValidationException('Invalid age');
}
```

**Coverage:**
- Reference: `input-validation.md`

---

## Rank 19 — CWE-284: Improper Access Control *(NEW in 2025)*

**MITRE Score:** 12.20 | **PHP:** Yes

Software does not restrict or incorrectly restricts access to a resource.

**Vulnerable:**
```php
// Route accessible without authentication middleware
$app->get('/admin/users', [AdminController::class, 'listUsers']);
```

**Secure:**
```php
// Apply authentication + authorization middleware at route level
$app->get('/admin/users', [AdminController::class, 'listUsers'])
    ->middleware(['auth', 'role:admin']);
// TYPO3: Use access configuration in ext_tables.php / module registration
```

**Coverage:**
- Reference: `authentication-patterns.md`
- Checkpoints: SA-LLM-31 (LLM access control review)

---

## Rank 20 — CWE-200: Exposure of Sensitive Information *(NEW in 2025)*

**MITRE Score:** 12.12 | **PHP:** Yes

Software exposes sensitive information to unauthorized actors.

**Vulnerable:**
```php
try {
    $db->query($sql);
} catch (\Exception $e) {
    echo $e->getMessage(); // Exposes DB schema, query, credentials
    echo $e->getTraceAsString(); // Exposes file paths, internal structure
}
```

**Secure:**
```php
try {
    $db->query($sql);
} catch (\Exception $e) {
    $this->logger->error('Database error', ['exception' => $e]);
    throw new PublicException('An internal error occurred.'); // Generic user message
}
// Ensure display_errors=Off, error_reporting in production
```

**Coverage:**
- Checkpoints: SA-31 (phpinfo), SA-SEC-01 through SA-SEC-04 (secret scanning), SA-LLM-30 (LLM info exposure review)

---

## Rank 21 — CWE-306: Missing Authentication for Critical Function

**MITRE Score:** 12.02 | **PHP:** Yes

Software does not require authentication for critical functionality.

**Vulnerable:**
```php
// API endpoint with no authentication
public function resetPassword(Request $request): Response {
    $user = $this->userRepo->findByEmail($request->get('email'));
    $user->setPassword('newpassword');
}
```

**Secure:**
```php
// Require authentication + re-verification for critical actions
public function resetPassword(Request $request): Response {
    $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');
    $this->verifyRecentAuth($request); // Re-verify within last 5 minutes
    // ... proceed with password reset
}
```

**Coverage:**
- Reference: `authentication-patterns.md`
- Checkpoints: SA-20 (LLM auth/authz review)

---

## Rank 22 — CWE-918: Server-Side Request Forgery (SSRF)

**MITRE Score:** 11.69 | **PHP:** Yes

Software fetches a remote resource using user-supplied URL without proper validation.

**Vulnerable:**
```php
$url = $_GET['url'];
$content = file_get_contents($url);    // SSRF: internal network access
$ch = curl_init($_POST['webhook_url']); // SSRF: attacker-controlled URL
```

**Secure:**
```php
// Allowlist-based URL validation
$parsed = parse_url($url);
$allowedHosts = ['api.example.com', 'cdn.example.com'];
if (!in_array($parsed['host'], $allowedHosts, true)) {
    throw new SecurityException('URL not allowed');
}
// Block internal IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
$ip = gethostbyname($parsed['host']);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    throw new SecurityException('Internal addresses not allowed');
}
```

**Coverage:**
- Reference: `modern-attacks.md`
- Checkpoints: SA-LLM-26 (LLM SSRF review)
- Script: SSRF pattern check in `security-audit.sh`

---

## Rank 23 — CWE-77: Command Injection

**MITRE Score:** 11.64 | **PHP:** Yes

Improper neutralization of special elements used in a command (broader than CWE-78).

**Coverage:**
- Same as CWE-78 (Rank 9). See Rank 9 for details.
- Checkpoints: SA-25 through SA-28

---

## Rank 24 — CWE-639: Authorization Bypass Through User-Controlled Key (IDOR) *(NEW in 2025)*

**MITRE Score:** 11.13 | **PHP:** Yes

System uses a user-controlled key to access resources without verifying the user's authorization.

**Vulnerable:**
```php
// Direct object reference without ownership check
$invoice = $invoiceRepo->find($_GET['invoice_id']);
return new Response($invoice->toPdf()); // Any user can access any invoice
```

**Secure:**
```php
$invoice = $invoiceRepo->find($_GET['invoice_id']);
if ($invoice->getUserId() !== $currentUser->getId()) {
    throw new AccessDeniedException('Not your invoice');
}
return new Response($invoice->toPdf());
// Or use scoped queries: $invoiceRepo->findByUserAndId($currentUser, $id)
```

**Coverage:**
- Checkpoints: SA-40 (direct $_GET/$_POST ID in query), SA-LLM-28 (LLM IDOR review)
- Script: IDOR pattern check in `security-audit.sh`

---

## Rank 25 — CWE-770: Allocation of Resources Without Limits or Throttling *(NEW in 2025)*

**MITRE Score:** 11.08 | **PHP:** Yes

Software allocates resources (memory, files, connections) without limits, enabling denial of service.

**Vulnerable:**
```php
// No limit on uploaded file size
$data = file_get_contents('php://input'); // Unlimited POST body
// No pagination on query results
$allUsers = $userRepo->findAll(); // Could be millions of rows
// No rate limiting on API endpoint
```

**Secure:**
```php
// Enforce upload size limits
ini_set('upload_max_filesize', '10M');
ini_set('post_max_size', '10M');
// Paginate queries
$users = $userRepo->findBy([], null, $limit, $offset);
// Rate limit endpoints
if (!$this->rateLimiter->consume($clientIp)->isAccepted()) {
    throw new TooManyRequestsException();
}
```

**Coverage:**
- Checkpoints: SA-LLM-29 (LLM resource exhaustion review)

---

## Coverage Summary

| Rank | CWE | Name | Mechanical | LLM Review | Script | Reference |
|------|-----|------|-----------|------------|--------|-----------|
| 1 | 79 | XSS | SA-13 | SA-19 | Yes | owasp-top10 |
| 2 | 89 | SQL Injection | SA-10,11,12 | SA-17 | Yes | owasp-top10 |
| 3 | 352 | CSRF | — | SA-LLM-25 | Yes | — |
| 4 | 862 | Missing Authz | — | SA-20 | — | authentication-patterns |
| 5 | 787 | OOB Write | N/A | N/A | N/A | N/A |
| 6 | 22 | Path Traversal | SA-34,35 | — | Yes | path-traversal-prevention |
| 7 | 416 | Use After Free | N/A | N/A | N/A | N/A |
| 8 | 125 | OOB Read | N/A | N/A | N/A | N/A |
| 9 | 78 | OS Cmd Injection | SA-25..28 | — | Yes | owasp-top10 |
| 10 | 94 | Code Injection | SA-37,38,39 | SA-LLM-27 | Yes | — |
| 11 | 120 | Buffer Overflow | N/A | N/A | N/A | N/A |
| 12 | 434 | File Upload | SA-32 | SA-LLM-22 | — | file-upload-security |
| 13 | 476 | NULL Deref | N/A | N/A | N/A | N/A |
| 14 | 121 | Stack Overflow | N/A | N/A | N/A | N/A |
| 15 | 502 | Deserialization | SA-21,22 | SA-LLM-21 | — | deserialization-prevention |
| 16 | 122 | Heap Overflow | N/A | N/A | N/A | N/A |
| 17 | 863 | Incorrect Authz | — | SA-20 | — | authentication-patterns |
| 18 | 20 | Input Validation | — | — | — | input-validation |
| 19 | 284 | Access Control | — | SA-LLM-31 | — | authentication-patterns |
| 20 | 200 | Info Exposure | SA-31, SA-SEC-01..04 | SA-LLM-30 | Yes | — |
| 21 | 306 | Missing Auth | — | SA-20 | — | authentication-patterns |
| 22 | 918 | SSRF | — | SA-LLM-26 | Yes | modern-attacks |
| 23 | 77 | Cmd Injection | SA-25..28 | — | Yes | owasp-top10 |
| 24 | 639 | IDOR | SA-40 | SA-LLM-28 | Yes | — |
| 25 | 770 | Resource Exhaust | — | SA-LLM-29 | — | — |
