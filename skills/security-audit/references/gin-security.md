# Gin Security Patterns

Security patterns, common misconfigurations, and detection regexes for Gin (Go) web applications. Gin's middleware-based architecture introduces unique security considerations around middleware ordering, input binding, template rendering, file serving, and proxy trust. Many vulnerabilities arise from implicit trust in user input and misconfigured middleware chains.

---

## Middleware Ordering

### SA-GIN-01: Middleware Ordering Vulnerabilities

Gin executes middleware in registration order. If authentication or authorization middleware is registered after route handlers, or if security middleware (CORS, rate limiting, logging) is placed incorrectly, routes may be exposed without protection.

```go
// VULNERABLE: Auth middleware registered after routes
func main() {
    r := gin.Default()

    // These routes have NO authentication!
    api := r.Group("/api")
    api.GET("/users", listUsers)
    api.DELETE("/users/:id", deleteUser)

    // Auth middleware registered too late — does not protect routes above
    r.Use(authMiddleware())

    r.Run(":8080")
}

// VULNERABLE: Recovery middleware missing — panics crash the server
func main() {
    r := gin.New() // No default middleware
    r.Use(authMiddleware())
    // Missing gin.Recovery() — a panic in any handler kills the process
    r.GET("/api/data", dataHandler)
    r.Run(":8080")
}
```

```go
// SECURE: Middleware registered before routes, correct ordering
func main() {
    r := gin.New()

    // 1. Recovery first — catches panics from all subsequent middleware/handlers
    r.Use(gin.Recovery())
    // 2. Logging
    r.Use(gin.Logger())
    // 3. Security headers / CORS
    r.Use(corsMiddleware())
    // 4. Rate limiting
    r.Use(rateLimitMiddleware())

    // 5. Auth on protected groups
    api := r.Group("/api")
    api.Use(authMiddleware())
    api.GET("/users", listUsers)
    api.DELETE("/users/:id", deleteUser)

    // Public routes defined separately
    r.GET("/health", healthCheck)

    r.Run(":8080")
}
```

**Detection regex:** `\.Use\(auth[A-Za-z]*\(`
**Severity:** error

---

## Mass Assignment

### SA-GIN-02: c.Bind / ShouldBind Mass Assignment

Gin's binding functions (`c.Bind`, `c.ShouldBindJSON`, `c.BindJSON`, etc.) map request data directly to Go structs. If the struct contains sensitive fields (e.g., `IsAdmin`, `Role`, `ID`), attackers can set these by including them in the request body.

```go
// VULNERABLE: Binding directly to a model with sensitive fields
type User struct {
    ID        uint   `json:"id" gorm:"primaryKey"`
    Name      string `json:"name"`
    Email     string `json:"email"`
    IsAdmin   bool   `json:"is_admin"`
    Role      string `json:"role"`
    CreatedAt time.Time
}

func createUser(c *gin.Context) {
    var user User
    // Attacker sends: {"name":"evil","email":"a@b.c","is_admin":true,"role":"superadmin"}
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    db.Create(&user) // is_admin=true, role=superadmin persisted!
    c.JSON(201, user)
}
```

```go
// SECURE: Use a dedicated input DTO that excludes sensitive fields
type CreateUserInput struct {
    Name  string `json:"name" binding:"required,min=1,max=100"`
    Email string `json:"email" binding:"required,email"`
}

func createUser(c *gin.Context) {
    var input CreateUserInput
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    user := User{
        Name:    input.Name,
        Email:   input.Email,
        IsAdmin: false,          // Explicitly set server-side
        Role:    "user",         // Explicitly set server-side
    }
    db.Create(&user)
    c.JSON(201, user)
}
```

**Detection regex:** `c\.(Bind|ShouldBind|ShouldBindJSON|BindJSON|ShouldBindQuery)\s*\(`
**Severity:** warning

---

## Cross-Site Scripting (XSS)

### SA-GIN-03: c.HTML Template Injection

Gin uses Go's `html/template` package which auto-escapes by default. However, using `template.HTML()` to cast user input bypasses escaping entirely, creating XSS vulnerabilities. Similarly, rendering user-controlled strings via `c.Data` or `c.Writer.WriteString` with `text/html` content type bypasses template escaping.

```go
// VULNERABLE: Casting user input to template.HTML bypasses auto-escaping
func profileHandler(c *gin.Context) {
    username := c.Query("name")
    // template.HTML tells Go "this is already safe" — it is NOT
    c.HTML(200, "profile.html", gin.H{
        "username": template.HTML(username),
    })
}

// VULNERABLE: Writing raw HTML from user input
func searchHandler(c *gin.Context) {
    query := c.Query("q")
    c.Data(200, "text/html; charset=utf-8",
        []byte("<h1>Results for: "+query+"</h1>"))
}

// VULNERABLE: Using fmt.Sprintf to build HTML
func renderPage(c *gin.Context) {
    title := c.Param("title")
    html := fmt.Sprintf("<html><head><title>%s</title></head></html>", title)
    c.Writer.WriteString(html)
}
```

```go
// SECURE: Let html/template handle escaping automatically
func profileHandler(c *gin.Context) {
    username := c.Query("name")
    // Pass as plain string — html/template auto-escapes
    c.HTML(200, "profile.html", gin.H{
        "username": username,
    })
}

// SECURE: Use templates for all HTML output
func searchHandler(c *gin.Context) {
    query := c.Query("q")
    c.HTML(200, "search.html", gin.H{
        "query": query, // Auto-escaped by template engine
    })
}
```

**Detection regex:** `template\.HTML\s*\(|c\.Data\s*\([^)]*"text/html|c\.Writer\.WriteString\s*\(`
**Severity:** error

---

## CORS Misconfiguration

### SA-GIN-04: CORS Middleware Misconfiguration

The popular `gin-contrib/cors` middleware can be misconfigured to allow all origins, expose credentials, or use wildcard origins with credentials — all of which weaken the same-origin policy.

```go
// VULNERABLE: Allow all origins with credentials
import "github.com/gin-contrib/cors"

func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"*"},       // Any origin
        AllowCredentials: true,                // With cookies!
        AllowHeaders:     []string{"*"},
        AllowMethods:     []string{"*"},
    }))
    r.Run(":8080")
}

// VULNERABLE: AllowAllOrigins with credentials
func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowAllOrigins:  true,
        AllowCredentials: true,
    }))
    r.Run(":8080")
}

// VULNERABLE: Dynamic origin reflection without validation
func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowOriginFunc: func(origin string) bool {
            return true // Reflects any origin — same as wildcard
        },
        AllowCredentials: true,
    }))
    r.Run(":8080")
}
```

```go
// SECURE: Explicit allowlist of trusted origins
func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowOrigins: []string{
            "https://app.example.com",
            "https://admin.example.com",
        },
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
        AllowHeaders:     []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }))
    r.Run(":8080")
}

// SECURE: Dynamic origin with strict validation
func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowOriginFunc: func(origin string) bool {
            u, err := url.Parse(origin)
            if err != nil {
                return false
            }
            return u.Hostname() == "example.com" ||
                strings.HasSuffix(u.Hostname(), ".example.com")
        },
        AllowCredentials: true,
    }))
    r.Run(":8080")
}
```

**Detection regex:** `AllowAllOrigins\s*:\s*true|AllowOrigins\s*:\s*\[\s*"\*"\s*\]|AllowOriginFunc\s*:.*return\s+true`
**Severity:** error

---

## Path Traversal

### SA-GIN-05: c.File / c.FileAttachment Path Traversal

`c.File()` and `c.FileAttachment()` serve files from the server filesystem. If the filename or path includes user input without sanitization, attackers can traverse directories to access arbitrary files.

```go
// VULNERABLE: User-controlled path passed directly to c.File
func downloadHandler(c *gin.Context) {
    filename := c.Param("filename")
    // Attacker sends: /download/../../../etc/passwd
    c.File("/uploads/" + filename)
}

// VULNERABLE: Query parameter used in file path
func serveFile(c *gin.Context) {
    path := c.Query("path")
    c.FileAttachment(path, "download.pdf")
}

// VULNERABLE: Insufficient sanitization
func downloadHandler(c *gin.Context) {
    filename := c.Param("filename")
    // strings.Replace only handles "../" but not "..\" or encoded variants
    safe := strings.Replace(filename, "../", "", -1)
    c.File("/uploads/" + safe)
}
```

```go
// SECURE: Validate filename, use filepath.Base, and verify resolved path
func downloadHandler(c *gin.Context) {
    filename := c.Param("filename")

    // Strip to base filename — removes all directory components
    base := filepath.Base(filename)

    // Reject hidden files and empty base
    if base == "." || base == ".." || strings.HasPrefix(base, ".") {
        c.JSON(400, gin.H{"error": "invalid filename"})
        return
    }

    // Resolve full path and verify it's within the uploads directory.
    // HasPrefix alone is not enough: "/var/app/uploads" is a prefix of
    // "/var/app/uploads_secret/…", so a sibling directory with a matching
    // prefix would pass the check. Enforce a directory boundary either by
    // appending the OS separator before the compare, or (preferred) by
    // using filepath.Rel and rejecting results that start with "..".
    uploadsDir := "/var/app/uploads"
    fullPath := filepath.Join(uploadsDir, base)
    resolved, err := filepath.EvalSymlinks(fullPath)
    if err != nil {
        c.JSON(404, gin.H{"error": "file not found"})
        return
    }
    rel, err := filepath.Rel(uploadsDir, resolved)
    if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
        c.JSON(404, gin.H{"error": "file not found"})
        return
    }

    c.File(resolved)
}
```

**Detection regex:** `c\.(File|FileAttachment)\s*\([^)]*c\.(Param|Query|PostForm)\s*\(`
**Severity:** error

---

## Panic Recovery

### SA-GIN-06: Panic Recovery Middleware

Without `gin.Recovery()` middleware, an unhandled panic in any handler or middleware will crash the entire server process. In production, this creates a denial-of-service vector. Additionally, the default recovery middleware may leak stack traces to clients.

```go
// VULNERABLE: No recovery middleware — panic crashes server
func main() {
    r := gin.New()
    r.GET("/api/data", func(c *gin.Context) {
        // Any nil pointer dereference, index out of range, etc.
        // will kill the process
        var data *MyStruct
        c.JSON(200, data.Field) // panic: nil pointer dereference
    })
    r.Run(":8080")
}

// VULNERABLE: Recovery middleware in wrong position
func main() {
    r := gin.New()
    r.Use(authMiddleware()) // Panic here is NOT caught
    r.Use(gin.Recovery())   // Too late for panics in auth
    r.Run(":8080")
}
```

```go
// SECURE: Recovery as first middleware with custom handler
func main() {
    r := gin.New()

    // Recovery FIRST — catches panics from all middleware and handlers
    r.Use(gin.CustomRecovery(func(c *gin.Context, err interface{}) {
        // Log the full error internally
        log.Printf("panic recovered: %v\n%s", err, debug.Stack())
        // Return generic error to client — no stack trace leak
        c.AbortWithStatusJSON(500, gin.H{
            "error": "internal server error",
        })
    }))

    r.Use(gin.Logger())
    r.Use(authMiddleware())

    r.GET("/api/data", dataHandler)
    r.Run(":8080")
}
```

**Detection regex:** `gin\.New\s*\(\s*\)(?![\s\S]*?\.Use\s*\(\s*gin\.(Recovery|CustomRecovery))`
**Severity:** error

---

## Trusted Proxy Configuration

### SA-GIN-07: Trusted Proxy Configuration

Gin trusts all proxies by default, meaning `c.ClientIP()` can be spoofed via `X-Forwarded-For` or `X-Real-IP` headers. This undermines rate limiting, IP-based access control, and audit logging.

```go
// VULNERABLE: Default configuration trusts all proxies
func main() {
    r := gin.Default()
    // gin trusts all proxies by default
    // c.ClientIP() can be spoofed by any client via X-Forwarded-For header

    r.GET("/api/data", func(c *gin.Context) {
        ip := c.ClientIP() // Can be spoofed!
        log.Printf("Request from: %s", ip)
        c.JSON(200, gin.H{"data": "sensitive"})
    })
    r.Run(":8080")
}
```

```go
// SECURE: Explicitly configure trusted proxies
func main() {
    r := gin.Default()

    // Only trust your known reverse proxy/load balancer IPs
    r.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})

    // Or trust no proxies at all (direct client connections)
    // r.SetTrustedProxies(nil)

    r.GET("/api/data", func(c *gin.Context) {
        ip := c.ClientIP() // Now reliable
        log.Printf("Request from: %s", ip)
        c.JSON(200, gin.H{"data": "sensitive"})
    })
    r.Run(":8080")
}
```

**Detection regex:** `gin\.(Default|New)\s*\(\s*\)(?![\s\S]*?SetTrustedProxies)`
**Severity:** warning

---

## Rate Limiting

### SA-GIN-08: Rate Limiting

Without rate limiting, Gin applications are vulnerable to brute-force attacks, credential stuffing, and denial-of-service. Rate limiting should be applied as middleware, ideally per-IP or per-user, and configured before authentication to protect login endpoints.

```go
// VULNERABLE: No rate limiting on sensitive endpoints
func main() {
    r := gin.Default()

    r.POST("/api/login", loginHandler)        // No rate limit — brute force
    r.POST("/api/reset-password", resetHandler) // No rate limit — account enumeration
    r.GET("/api/search", searchHandler)         // No rate limit — DoS

    r.Run(":8080")
}
```

```go
// SECURE: Rate limiting with a middleware library
import "github.com/ulule/limiter/v3"
import mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
import "github.com/ulule/limiter/v3/drivers/store/memory"

func main() {
    r := gin.Default()

    // Global rate limit: 100 requests per minute per IP
    rate, _ := limiter.NewRateFromFormatted("100-M")
    store := memory.NewStore()
    globalLimiter := mgin.NewMiddleware(limiter.New(store, rate))
    r.Use(globalLimiter)

    // Stricter limit on auth endpoints: 5 per minute
    authRate, _ := limiter.NewRateFromFormatted("5-M")
    authLimiter := mgin.NewMiddleware(limiter.New(store, authRate))

    auth := r.Group("/api/auth")
    auth.Use(authLimiter)
    auth.POST("/login", loginHandler)
    auth.POST("/reset-password", resetHandler)

    r.Run(":8080")
}
```

**Detection regex:** `\.(POST|PUT)\s*\(\s*"[^"]*(?:login|auth|token|password|reset)[^"]*"\s*,\s*\w+\s*\)`
**Severity:** warning

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-GIN-01 Middleware ordering | Critical | Immediate | Low |
| SA-GIN-02 Mass assignment via Bind | High | 1 week | Medium |
| SA-GIN-03 Template injection | Critical | Immediate | Low |
| SA-GIN-04 CORS misconfiguration | High | 1 week | Low |
| SA-GIN-05 Path traversal via c.File | Critical | Immediate | Medium |
| SA-GIN-06 Missing panic recovery | High | Immediate | Low |
| SA-GIN-07 Trusted proxy config | Medium | 1 week | Low |
| SA-GIN-08 Missing rate limiting | Medium | 1 month | Medium |

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `api-security.md` -- API-level security patterns
- Go standard library `html/template` auto-escaping documentation

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 framework expansion |
