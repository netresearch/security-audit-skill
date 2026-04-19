# Go Security Features by Version

Modern Go versions introduce language features that directly improve security when used correctly. This reference documents security-relevant features and vulnerability patterns from Go 1.18 through Go 1.22.

## Core Go Security Patterns

### 1. Goroutine Race Conditions (CWE-362)

Shared mutable state accessed by multiple goroutines without synchronization leads to data races that can corrupt security-critical data such as authentication state, permission checks, or financial calculations.

```go
// VULNERABLE: Shared state without synchronization
var isAuthenticated bool

func handleLogin(w http.ResponseWriter, r *http.Request) {
    go func() {
        // Race condition: multiple goroutines read/write isAuthenticated
        if validateCredentials(r) {
            isAuthenticated = true // DATA RACE
        }
    }()
    if isAuthenticated {
        grantAccess(w) // May grant access based on stale/corrupt value
    }
}

// SECURE: Use sync primitives for shared state
var (
    mu              sync.RWMutex
    sessionStore    = make(map[string]bool)
)

func handleLoginSafe(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("X-Session-Token")
    mu.RLock()
    authenticated := sessionStore[token]
    mu.RUnlock()

    if !authenticated {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    grantAccess(w)
}
```

**Security implication:** Data races on security-critical variables can cause authentication bypass, privilege escalation, or inconsistent authorization decisions. Always run tests with `-race` flag: `go test -race ./...`

**Detection:** static regexes catch obvious `go func(){ ... }()` sites but can't reason about shared state. The Go toolchain's built-in data-race detector is the right answer — it instruments the binary and reports races at runtime:

```bash
go test -race ./...            # run tests with the race detector
go run -race ./cmd/server      # instrument a running binary
go build -race -o ./bin/server ./cmd/server   # produce an instrumented build
```

`go vet` does not have a `-race` mode; the `-race` flag belongs to `go test` / `go run` / `go build` (it instruments the binary — you still have to exercise it).

### 2. Unsafe Pointer Usage (CWE-119, CWE-787)

The `unsafe` package bypasses Go's type safety and memory safety guarantees. It enables arbitrary memory access, buffer overflows, and use-after-free vulnerabilities.

```go
// VULNERABLE: unsafe pointer arithmetic
import "unsafe"

func readBeyondBuffer(data []byte) byte {
    ptr := unsafe.Pointer(&data[0])
    // Read beyond slice bounds — buffer over-read
    farPtr := unsafe.Pointer(uintptr(ptr) + uintptr(len(data)+100))
    return *(*byte)(farPtr) // Undefined behavior, potential info leak
}

// VULNERABLE: unsafe type casting bypasses type safety
func unsafeCast(i int64) *http.Request {
    return (*http.Request)(unsafe.Pointer(&i)) // Nonsensical cast, memory corruption
}

// SECURE: Use encoding/binary for type conversions
import "encoding/binary"

func safeConvert(data []byte) (uint32, error) {
    if len(data) < 4 {
        return 0, fmt.Errorf("insufficient data: need 4 bytes, got %d", len(data))
    }
    return binary.BigEndian.Uint32(data[:4]), nil
}
```

**Security implication:** `unsafe` operations can cause buffer overflows, information disclosure, and arbitrary code execution. Any use of `unsafe` in security-critical code requires manual audit.

**Detection regex:** `unsafe\.Pointer|unsafe\.Sizeof|unsafe\.Offsetof|unsafe\.Alignof|unsafe\.Slice|unsafe\.String`

### 3. Template Injection: text/template vs html/template (CWE-79)

Go's `text/template` package performs no output escaping. Using it for HTML output enables XSS attacks. The `html/template` package automatically escapes output for the HTML context.

```go
// VULNERABLE: text/template does NOT escape HTML
import "text/template"

func renderPage(w http.ResponseWriter, username string) {
    tmpl := template.Must(template.New("page").Parse(
        `<h1>Hello, {{.Username}}</h1>`,
    ))
    tmpl.Execute(w, map[string]string{
        "Username": username, // If username is "<script>alert(1)</script>", XSS occurs
    })
}

// SECURE: html/template auto-escapes for HTML context
import "html/template"

func renderPageSafe(w http.ResponseWriter, username string) {
    tmpl := template.Must(template.New("page").Parse(
        `<h1>Hello, {{.Username}}</h1>`,
    ))
    // html/template escapes: <script> becomes &lt;script&gt;
    tmpl.Execute(w, map[string]string{
        "Username": username,
    })
}
```

**Security implication:** Using `text/template` for HTML output allows stored/reflected XSS. Always use `html/template` for web responses. Note: `html/template` only escapes for HTML — for JavaScript or URL contexts, additional care is needed.

**Detection regex:** `"text/template"`

### 4. SQL Injection in database/sql (CWE-89)

String concatenation in SQL queries creates injection vulnerabilities. Go's `database/sql` package supports parameterized queries that prevent injection.

```go
// VULNERABLE: String concatenation in SQL query
func getUser(db *sql.DB, username string) (*User, error) {
    query := "SELECT id, name, email FROM users WHERE name = '" + username + "'"
    row := db.QueryRow(query) // SQL injection if username contains ' OR 1=1 --
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}

// VULNERABLE: fmt.Sprintf for SQL queries
func getUserFmt(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT id, name FROM users WHERE name = '%s'", username)
    row := db.QueryRow(query) // SQL injection
    var u User
    err := row.Scan(&u.ID, &u.Name)
    return &u, err
}

// SECURE: Parameterized query with placeholder
func getUserSafe(db *sql.DB, username string) (*User, error) {
    row := db.QueryRow("SELECT id, name, email FROM users WHERE name = $1", username)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}

// SECURE: Using prepared statements
func getUserPrepared(db *sql.DB, username string) (*User, error) {
    stmt, err := db.Prepare("SELECT id, name, email FROM users WHERE name = $1")
    if err != nil {
        return nil, err
    }
    defer stmt.Close()
    row := stmt.QueryRow(username)
    var u User
    err = row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}
```

**Security implication:** SQL injection can lead to full database compromise. Always use parameterized queries. Be cautious with ORMs — raw query methods (e.g., `gorm.Raw()`) can still be vulnerable.

**Detection regex:** `(Sprintf|"|')\s*\+.*SELECT|Sprintf.*SELECT|Sprintf.*INSERT|Sprintf.*UPDATE|Sprintf.*DELETE|\.Query\(.*\+|\.Exec\(.*\+`

### 5. Command Injection via os/exec (CWE-78)

Using `exec.Command` with shell invocation (`sh -c`) combined with user input enables command injection. Direct execution without a shell is safer.

```go
// VULNERABLE: Shell invocation with user input
import "os/exec"

func processFile(filename string) ([]byte, error) {
    // sh -c allows shell metacharacters: filename = "; rm -rf /"
    cmd := exec.Command("sh", "-c", "cat "+filename)
    return cmd.Output()
}

// VULNERABLE: bash -c with string concatenation
func convert(input string) error {
    cmd := exec.Command("bash", "-c", "convert "+input+" output.png")
    return cmd.Run()
}

// SECURE: Direct execution without shell — no metacharacter interpretation
func processFileSafe(filename string) ([]byte, error) {
    // Arguments passed directly to the binary, not interpreted by shell
    cmd := exec.Command("cat", filename)
    return cmd.Output()
}

// SECURE: Validate input before execution
func processFileValidated(filename string) ([]byte, error) {
    // Allowlist: only alphanumeric, dots, hyphens, underscores
    if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(filename) {
        return nil, fmt.Errorf("invalid filename")
    }
    cmd := exec.Command("cat", filepath.Join("/safe/dir", filename))
    return cmd.Output()
}
```

**Security implication:** Shell injection via `sh -c` or `bash -c` allows arbitrary command execution. Pass arguments directly to `exec.Command` and validate inputs.

**Detection regex:** `exec\.Command\s*\(\s*"(sh|bash|cmd|powershell)"`

### 6. Path Traversal (CWE-22)

`filepath.Join` does not prevent path traversal — joining with `..` segments can escape the intended directory.

```go
// VULNERABLE: filepath.Join does not sanitize ".."
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    // filepath.Join("/data", "../../etc/passwd") => "/etc/passwd"
    path := filepath.Join("/data", filename)
    http.ServeFile(w, r, path)
}

// SECURE: Validate resolved path is within base directory
func serveFileSafe(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    basePath := "/data"
    // Clean and resolve the path
    resolved := filepath.Clean(filepath.Join(basePath, filename))
    // Verify the resolved path starts with the base directory
    if !strings.HasPrefix(resolved, basePath+string(filepath.Separator)) &&
        resolved != basePath {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, resolved)
}
```

**Security implication:** Path traversal can expose sensitive files (`/etc/passwd`, application configuration, secrets). Always validate that resolved paths remain within the intended directory.

**Detection regex:** `filepath\.Join\s*\(.*\b(r\.|req\.|request\.|params|query|URL)`

### 7. HTTP Header Injection (CWE-113)

Setting HTTP headers with unsanitized user input can inject additional headers or split responses.

```go
// VULNERABLE: User input directly in response header
func redirect(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    // If target contains \r\n, attacker can inject headers
    w.Header().Set("Location", target)
    w.WriteHeader(http.StatusFound)
}

// SECURE: Validate and sanitize redirect URLs
func redirectSafe(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    // Parse and validate the URL
    parsed, err := url.Parse(target)
    if err != nil || parsed.Host != "" {
        http.Error(w, "Invalid redirect", http.StatusBadRequest)
        return
    }
    // Only allow relative redirects
    http.Redirect(w, r, parsed.Path, http.StatusFound)
}
```

**Security implication:** HTTP header injection can enable response splitting, cache poisoning, and session fixation. Validate all user input before placing in headers.

**Detection regex:** `Header\(\)\.Set\s*\(.*\b(r\.|req\.|request\.|params|query)`

### 8. SSRF via http.Get with User Input (CWE-918)

Passing user-controlled URLs to `http.Get` or `http.Client.Do` without validation allows Server-Side Request Forgery.

```go
// VULNERABLE: User-controlled URL in HTTP request
func fetchProxy(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, err := http.Get(target) // SSRF: attacker can reach internal services
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

// SECURE: Validate URL against allowlist and block internal networks
func fetchProxySafe(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    parsed, err := url.Parse(target)
    if err != nil {
        http.Error(w, "Invalid URL", http.StatusBadRequest)
        return
    }
    // Only allow HTTPS to specific domains
    allowed := map[string]bool{"api.example.com": true, "cdn.example.com": true}
    if parsed.Scheme != "https" || !allowed[parsed.Host] {
        http.Error(w, "URL not allowed", http.StatusForbidden)
        return
    }
    // Use a client with timeouts and no redirect following
    client := &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    resp, err := client.Get(parsed.String())
    if err != nil {
        http.Error(w, "Fetch failed", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

**Security implication:** SSRF can expose internal services, cloud metadata endpoints (169.254.169.254), and enable network scanning from the server.

**Detection regex:** `http\.(Get|Post|Head)\s*\(.*\b(r\.|req\.|request\.|params|query|URL)`

### 9. Insecure TLS Configuration (CWE-295)

Setting `InsecureSkipVerify: true` disables TLS certificate validation, enabling man-in-the-middle attacks.

```go
// VULNERABLE: Skip TLS certificate verification
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // Accepts ANY certificate, including forged ones
        },
    },
}
resp, err := client.Get("https://api.example.com/secrets")

// VULNERABLE: Minimum TLS version too low
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS10, // TLS 1.0 has known vulnerabilities
}

// SECURE: Proper TLS configuration
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
            // Default InsecureSkipVerify is false — certificates are validated
        },
    },
}
resp, err := client.Get("https://api.example.com/secrets")

// SECURE: Pin specific CA certificates
certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(caCert)
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:    certPool,
            MinVersion: tls.VersionTLS12,
        },
    },
}
```

**Security implication:** Disabling certificate verification allows attackers to intercept encrypted traffic. This is commonly left in code after debugging.

**Detection regex:** `InsecureSkipVerify\s*:\s*true`

### 10. Insecure Randomness: crypto/rand vs math/rand (CWE-330)

`math/rand` uses a deterministic PRNG unsuitable for security-sensitive operations. Use `crypto/rand` for tokens, keys, and nonces.

```go
// VULNERABLE: math/rand for security-sensitive values
import "math/rand"

func generateToken() string {
    // math/rand is deterministic — tokens are predictable
    token := make([]byte, 32)
    for i := range token {
        token[i] = byte(rand.Intn(256))
    }
    return hex.EncodeToString(token)
}

// VULNERABLE: math/rand seeded with time (still predictable)
func generateTokenSeeded() string {
    rand.Seed(time.Now().UnixNano()) // Seed is guessable
    return fmt.Sprintf("%d", rand.Int63())
}

// SECURE: crypto/rand for cryptographically secure random values
import "crypto/rand"

func generateTokenSecure() (string, error) {
    token := make([]byte, 32)
    if _, err := rand.Read(token); err != nil {
        return "", fmt.Errorf("failed to generate token: %w", err)
    }
    return hex.EncodeToString(token), nil
}
```

**Security implication:** Predictable tokens allow session hijacking, CSRF bypass, and password reset token forgery. Always use `crypto/rand` for security-critical randomness.

**Detection regex:** `"math/rand"`

### 11. Integer Overflow in Calculations (CWE-190)

Go does not panic on integer overflow — values silently wrap around. This can cause incorrect security decisions, buffer size miscalculations, or financial errors.

```go
// VULNERABLE: Integer overflow in allocation size
func allocateBuffer(count int, size int) []byte {
    total := count * size // Silent overflow: 1<<31 * 2 wraps to 0
    buf := make([]byte, total)
    return buf
}

// VULNERABLE: Overflow in bounds check
func isValidIndex(index int32, length int32) bool {
    return index+1 <= length // If index == math.MaxInt32, index+1 wraps to -2147483648
}

// SECURE: Check for overflow before arithmetic
func allocateBufferSafe(count, size int) ([]byte, error) {
    if count < 0 || size < 0 {
        return nil, fmt.Errorf("negative size")
    }
    if count > 0 && size > math.MaxInt/count {
        return nil, fmt.Errorf("allocation size overflow")
    }
    return make([]byte, count*size), nil
}
```

**Security implication:** Integer overflows can bypass bounds checks, cause undersized allocations leading to buffer overflows, or produce incorrect financial calculations.

**Detection regex:** Best detected via static analysis (`go vet`, `staticcheck`). Regex detection is unreliable for this pattern.

## Go 1.18+ Security Features

### Generics for Type-Safe Validation

Go 1.18 introduced generics, enabling reusable, type-safe validation functions that reduce copy-paste errors in security-critical code.

```go
// BEFORE Go 1.18: Repeated validation logic prone to copy-paste errors
func validateStringLength(s string, max int) error {
    if len(s) > max {
        return fmt.Errorf("string too long: %d > %d", len(s), max)
    }
    return nil
}

// AFTER Go 1.18: Generic bounded validator
type Bounded interface {
    ~int | ~int32 | ~int64 | ~float64 | ~string
}

func ValidateRange[T constraints.Ordered](value T, min, max T) error {
    if value < min || value > max {
        return fmt.Errorf("value %v out of range [%v, %v]", value, min, max)
    }
    return nil
}

// Type-safe allowlist check
func InAllowlist[T comparable](value T, allowed []T) bool {
    for _, a := range allowed {
        if value == a {
            return true
        }
    }
    return false
}

// Usage: compile-time type safety prevents mixing types
err := ValidateRange(userAge, 0, 150)
ok := InAllowlist(role, []string{"admin", "editor", "viewer"})
```

**Security implication:** Generic validators reduce the risk of bugs in repeated validation logic across types.

### Fuzzing Support (go test -fuzz)

Go 1.18 added native fuzzing to the testing framework, enabling automated discovery of edge cases and vulnerabilities.

```go
// Fuzz test for input validation
func FuzzValidateInput(f *testing.F) {
    f.Add("normal-input")
    f.Add("<script>alert(1)</script>")
    f.Add("'; DROP TABLE users; --")
    f.Add(strings.Repeat("A", 10000))

    f.Fuzz(func(t *testing.T, input string) {
        result, err := ValidateInput(input)
        if err == nil {
            // If validation passes, result must be safe
            if strings.Contains(result, "<script>") {
                t.Error("XSS payload passed validation")
            }
        }
    })
}
```

**Security implication:** Fuzzing discovers crashes, panics, and logic bugs in parsers and validators that manual testing misses.

## Go 1.21+ Security Features

### log/slog for Structured Security Logging

Go 1.21 introduced `log/slog`, the standard library structured logger. Structured logging prevents log injection and enables security event correlation.

```go
// VULNERABLE: Unstructured logging with user input (log injection)
import "log"

func handleRequest(r *http.Request) {
    user := r.URL.Query().Get("user")
    // Attacker can inject: user=admin\n[INFO] Access granted to admin
    log.Printf("[INFO] Login attempt for user: %s", user)
}

// SECURE: Structured logging with slog
import "log/slog"

func handleRequestSafe(r *http.Request) {
    user := r.URL.Query().Get("user")
    slog.Info("login_attempt",
        slog.String("user", user),           // Properly escaped as structured field
        slog.String("ip", r.RemoteAddr),
        slog.String("method", r.Method),
    )
}

// SECURE: Security event logger with required fields
var securityLogger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

func logSecurityEvent(event string, attrs ...slog.Attr) {
    securityLogger.LogAttrs(context.Background(), slog.LevelWarn, event, attrs...)
}
```

**Security implication:** Structured logging prevents log injection attacks and produces machine-parseable security audit trails.

**Detection regex:** `log\.(Print|Fatal|Panic)(f|ln)?\s*\(` (warning: suggests migration to `slog`)

### maps and slices Packages

Go 1.21 added `maps` and `slices` packages with safe operations that reduce off-by-one errors and race conditions.

```go
// SECURE: slices.Contains for safe allowlist check (replaces manual loops)
import "slices"

func isAllowedRole(role string) bool {
    allowed := []string{"admin", "editor", "viewer"}
    return slices.Contains(allowed, role)
}

// SECURE: maps.Clone produces a SHALLOW copy — the returned map has
// its own backing store, so the caller can add or remove keys without
// touching `original`. But reference-typed values (slices, maps,
// pointers, structs containing them) are still shared. For `map[string]bool`
// this is safe because bool is a value type; for a map of slices or
// structs-with-slices you must deep-copy the values yourself.
import "maps"

func clonePermissions(original map[string]bool) map[string]bool {
    return maps.Clone(original) // OK: bool values are not references.
}

// Example: when values are slices, maps.Clone is NOT enough.
func cloneRoleAssignments(original map[string][]string) map[string][]string {
    out := make(map[string][]string, len(original))
    for k, v := range original {
        out[k] = append([]string(nil), v...)   // copy each slice
    }
    return out
}
```

**Security implication:** Standard library functions for common operations reduce the chance of logic errors in security-critical code paths.

## Go 1.22+ Security Features

### Loop Variable Semantics Fix

Go 1.22 changed loop variable semantics so that each iteration creates a new variable, fixing a longstanding class of bugs where closures captured the loop variable by reference.

```go
// BEFORE Go 1.22: Loop variable captured by reference (bug)
func startHandlers(ports []int) {
    for _, port := range ports {
        go func() {
            // BUG: all goroutines use the same 'port' variable
            // They all bind to the LAST port in the slice
            http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
        }()
    }
}

// Go 1.22+: Each iteration gets its own variable (fixed)
func startHandlers(ports []int) {
    for _, port := range ports {
        go func() {
            // CORRECT in Go 1.22+: each goroutine has its own 'port'
            http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
        }()
    }
}
```

**Security implication:** The old behavior could cause services to bind to wrong ports, security checks to use wrong values, and goroutines to process wrong data. Go 1.22 eliminates this class of bugs.

### Enhanced Routing Patterns in net/http

Go 1.22 added method-based routing and path parameters to the standard `net/http` mux, reducing reliance on third-party routers.

```go
// Go 1.22+: Method-specific routes prevent method confusion
mux := http.NewServeMux()
mux.HandleFunc("GET /api/users/{id}", getUser)    // Only matches GET
mux.HandleFunc("DELETE /api/users/{id}", deleteUser) // Only matches DELETE

func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id") // Safe path parameter extraction
    // Validate id before use
    if !isValidID(id) {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }
    // ...
}
```

**Security implication:** Method-specific routing prevents unauthorized operations via HTTP method confusion (e.g., GET reaching a DELETE handler).

## Detection Patterns for Auditing Go Security Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| `unsafe` package usage | `unsafe\.Pointer\|unsafe\.Sizeof\|unsafe\.Slice` | error | SA-GO-01 |
| `text/template` for HTML | `"text/template"` | error | SA-GO-02 |
| SQL string concatenation | `(Sprintf\|"\s*\+).*(?i)(SELECT\|INSERT\|UPDATE\|DELETE)` | error | SA-GO-03 |
| Shell command injection | `exec\.Command\s*\(\s*"(sh\|bash\|cmd)"` | error | SA-GO-04 |
| Path traversal via Join | `filepath\.Join\s*\(.*req\.\|r\.URL` | warning | SA-GO-05 |
| `InsecureSkipVerify: true` | `InsecureSkipVerify\s*:\s*true` | error | SA-GO-06 |
| `math/rand` for security | `"math/rand"` | warning | SA-GO-07 |
| SSRF via user-supplied URL | `http\.(Get\|Post)\s*\(.*req\.\|r\.URL` | error | SA-GO-08 |
| Unstructured log with user input | `log\.(Print\|Fatal)(f\|ln)?\s*\(` | warning | SA-GO-09 |
| HTTP header injection | `Header\(\)\.Set\s*\(.*r\.\|req\.` | warning | SA-GO-10 |
| `VersionTLS10` or `VersionTLS11` | `VersionTLS1[01]\b` | error | SA-GO-11 |
| Hardcoded credentials | `(password\|secret\|apiKey\|token)\s*[:=]\s*"[^"]{8,}"` | error | SA-GO-12 |
| Missing error check on crypto | `rand\.Read\(.*\)\s*$` without error check | warning | SA-GO-13 |
| `net.Listen` on 0.0.0.0 | `net\.Listen\s*\(\s*"tcp"\s*,\s*":` | warning | SA-GO-14 |
| Goroutine leak (unbounded) | `go\s+func\s*\(` without context/cancel pattern | warning | SA-GO-15 |

## Version Adoption Security Checklist

- [ ] Enable `-race` flag in CI test pipeline
- [ ] Run `go vet ./...` and `staticcheck ./...` in CI
- [ ] Audit all uses of `unsafe` package
- [ ] Replace `text/template` with `html/template` for HTML output
- [ ] Replace all SQL string concatenation with parameterized queries
- [ ] Verify no `InsecureSkipVerify: true` in production code
- [ ] Replace `math/rand` with `crypto/rand` for tokens, keys, nonces
- [ ] Validate all user-supplied URLs before HTTP requests
- [ ] Migrate from `log.Printf` to `log/slog` for security events (Go 1.21+)
- [ ] Run `go test -fuzz` on parsers and validators (Go 1.18+)
- [ ] Update to Go 1.22+ to get loop variable fix
- [ ] Run `govulncheck ./...` to detect known vulnerabilities in dependencies

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `path-traversal-prevention.md` — Path traversal prevention
- `cryptography-guide.md` — Cryptographic best practices
- `security-logging.md` — Security logging patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Multi-language security references expansion |
