# Rust Security Features by Version

Modern Rust editions introduce language features that directly improve security when used correctly. While Rust's ownership system prevents many memory safety issues at compile time, `unsafe` blocks, logic bugs, and ecosystem pitfalls still create real vulnerabilities. This reference documents security-relevant patterns from Rust Edition 2021 through Edition 2024.

## Core Rust Security Patterns

### 1. Unsafe Block Audit Patterns (CWE-119, CWE-787)

`unsafe` blocks opt out of Rust's safety guarantees. Every `unsafe` block is a potential source of memory corruption, undefined behavior, and security vulnerabilities.

```rust
// VULNERABLE: Unnecessary unsafe for performance shortcut
unsafe fn get_unchecked_item(data: &[u8], index: usize) -> u8 {
    *data.get_unchecked(index) // No bounds check — buffer over-read
}

// VULNERABLE: Unsafe transmute between incompatible types
unsafe fn force_cast(input: u64) -> &'static str {
    std::mem::transmute(input) // Undefined behavior — invalid pointer
}

// VULNERABLE: Dereferencing raw pointer without validation
unsafe fn read_raw(ptr: *const u8) -> u8 {
    *ptr // May be null, dangling, or misaligned
}

// SECURE: Use safe alternatives
fn get_item(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied() // Returns None if out of bounds
}

// SECURE: When unsafe is truly needed, document invariants
/// # Safety
/// `ptr` must be non-null, properly aligned, and point to an initialized `u8`.
/// The caller must ensure the pointer is valid for the lifetime of this call.
unsafe fn read_raw_documented(ptr: *const u8) -> u8 {
    debug_assert!(!ptr.is_null());
    *ptr
}
```

**Security implication:** Every `unsafe` block is a potential vulnerability. Audit for: null pointer derefs, buffer overflows, data races, invalid type transmutes, and violation of aliasing rules. Minimize `unsafe` surface area.

**Detection regex:** `unsafe\s*\{|unsafe\s+fn\s|unsafe\s+impl\s`

### 2. FFI Boundary Issues (CWE-119, CWE-476)

Foreign Function Interface (FFI) calls cross the safety boundary. Null pointers, lifetime mismanagement, and missing error handling at FFI boundaries cause vulnerabilities.

```rust
// VULNERABLE: No null check on FFI pointer
extern "C" {
    fn get_data() -> *const c_char;
}

fn read_external_data() -> String {
    unsafe {
        let ptr = get_data();
        // ptr may be null — undefined behavior
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// VULNERABLE: Exposing Rust-owned memory to C without lifetime management
#[no_mangle]
pub extern "C" fn get_string() -> *const c_char {
    let s = CString::new("hello").unwrap();
    s.as_ptr() // s is dropped here — dangling pointer returned to C!
}

// SECURE: Null check and proper error handling
fn read_external_data_safe() -> Result<String, Box<dyn std::error::Error>> {
    unsafe {
        let ptr = get_data();
        if ptr.is_null() {
            return Err("null pointer from FFI".into());
        }
        Ok(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

// SECURE: Use into_raw to transfer ownership to C
#[no_mangle]
pub extern "C" fn get_string_safe() -> *mut c_char {
    let s = CString::new("hello").unwrap();
    s.into_raw() // Ownership transferred — caller must free with free_string()
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)); }
    }
}
```

**Security implication:** FFI boundaries are the primary source of memory safety bugs in Rust. All C/FFI pointers must be validated for null, alignment, and lifetime correctness.

**Detection regex:** `extern\s+"C"\s*\{|#\[no_mangle\]`

### 3. panic! in Library Code — Denial of Service (CWE-248)

`panic!` in library code causes unwinding that can crash the entire application. In servers, a panic in a handler can take down the process.

```rust
// VULNERABLE: panic! in library code
pub fn parse_config(input: &str) -> Config {
    let parts: Vec<&str> = input.split(':').collect();
    Config {
        host: parts[0].to_string(), // Panics if input is empty
        port: parts[1].parse().unwrap(), // Panics if not a number
    }
}

// SECURE: Return Result instead of panicking
pub fn parse_config_safe(input: &str) -> Result<Config, ConfigError> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() < 2 {
        return Err(ConfigError::InvalidFormat);
    }
    let port = parts[1].parse::<u16>()
        .map_err(|_| ConfigError::InvalidPort)?;
    Ok(Config {
        host: parts[0].to_string(),
        port,
    })
}
```

**Security implication:** Panics in libraries or request handlers enable denial-of-service. Library code should return `Result` or `Option`, never `panic!`. Use `catch_unwind` at service boundaries as a safety net.

**Detection regex:** `panic!\s*\(|todo!\s*\(|unimplemented!\s*\(`

### 4. .unwrap() / .expect() in Production Paths (CWE-248)

`.unwrap()` and `.expect()` panic on `None`/`Err`, crashing the application. In production code paths, they create denial-of-service vectors.

```rust
// VULNERABLE: unwrap in request handler
async fn handle_request(req: Request) -> Response {
    let body: serde_json::Value = serde_json::from_str(&req.body()).unwrap(); // Panics on invalid JSON
    let user_id = body["user_id"].as_str().unwrap(); // Panics if missing or not string
    let user = db.get_user(user_id).await.unwrap(); // Panics on DB error
    Response::ok(user)
}

// SECURE: Proper error handling with ? operator
async fn handle_request_safe(req: Request) -> Result<Response, AppError> {
    let body: serde_json::Value = serde_json::from_str(&req.body())
        .map_err(|_| AppError::BadRequest("invalid JSON"))?;
    let user_id = body["user_id"].as_str()
        .ok_or(AppError::BadRequest("missing user_id"))?;
    let user = db.get_user(user_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Response::ok(user))
}
```

**Security implication:** Every `.unwrap()` in a production code path is a potential DoS vector. Use `?`, `unwrap_or`, `unwrap_or_default`, or `match` instead.

**Detection regex:** `\.unwrap\(\)|\.expect\(\s*"`

### 5. Integer Overflow: Debug vs Release Behavior (CWE-190)

Rust panics on integer overflow in debug mode but **silently wraps** in release mode. This behavioral difference can hide bugs during development that become exploitable in production.

```rust
// VULNERABLE: Overflow behavior differs between debug and release
fn calculate_allocation_size(count: u32, size: u32) -> u32 {
    count * size // Panics in debug, wraps in release!
    // If count=65536 and size=65536, release result is 0 (wraps)
}

// VULNERABLE: Overflow in security-relevant bounds check
fn is_within_bounds(offset: u32, length: u32) -> bool {
    offset + length <= MAX_SIZE // In release: wraps to small value, check passes
}

// SECURE: Use checked arithmetic
fn calculate_allocation_size_safe(count: u32, size: u32) -> Option<u32> {
    count.checked_mul(size) // Returns None on overflow
}

// SECURE: Use saturating arithmetic where appropriate
fn add_with_limit(a: u32, b: u32) -> u32 {
    a.saturating_add(b) // Returns u32::MAX on overflow instead of wrapping
}
```

**Security implication:** Silent overflow in release builds can bypass bounds checks, cause undersized allocations, or corrupt financial calculations. Use `checked_*`, `saturating_*`, or `overflowing_*` methods.

**Detection regex:** Best detected via `clippy::arithmetic_side_effects` lint. No reliable simple regex.

### 6. Use-After-Free via Raw Pointers in Unsafe (CWE-416)

Raw pointers in `unsafe` blocks bypass the borrow checker, allowing use-after-free vulnerabilities.

```rust
// VULNERABLE: Use-after-free with raw pointers
fn use_after_free() {
    let ptr: *const String;
    {
        let s = String::from("secret data");
        ptr = &s as *const String;
    } // s is dropped here
    unsafe {
        println!("{}", *ptr); // Use-after-free: reading freed memory
    }
}

// VULNERABLE: Raw pointer from vector that may reallocate
fn dangling_from_vec() {
    let mut v = vec![1, 2, 3];
    let ptr = v.as_ptr();
    v.push(4); // May reallocate, invalidating ptr
    unsafe {
        println!("{}", *ptr); // Potential use-after-free
    }
}

// SECURE: Use references with proper lifetimes
fn safe_access(data: &[i32]) -> Option<&i32> {
    data.first() // Borrow checker ensures data outlives the reference
}

// SECURE: Pin for self-referential structures
use std::pin::Pin;
fn pinned_data(data: Pin<&String>) -> &str {
    data.as_str() // Data cannot be moved while pinned
}
```

**Security implication:** Use-after-free can lead to information disclosure, code execution, or crashes. Avoid raw pointers when safe alternatives exist.

**Detection regex:** `as\s+\*const\s|as\s+\*mut\s|\*const\s+\w+\s*;|\*mut\s+\w+\s*;`

### 7. SQL Injection in Diesel/sqlx (CWE-89)

While Diesel's query builder is injection-safe, raw SQL methods (`sql_query`, `query_as` with string interpolation) bypass this protection.

```rust
// VULNERABLE: Raw SQL with string formatting in Diesel
use diesel::sql_query;

fn get_user(conn: &mut PgConnection, username: &str) -> QueryResult<Vec<User>> {
    sql_query(format!("SELECT * FROM users WHERE name = '{}'", username))
        .load(conn) // SQL injection!
}

// VULNERABLE: sqlx raw query with format!
async fn get_user_sqlx(pool: &PgPool, username: &str) -> Result<Vec<User>, sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{}'", username);
    sqlx::query_as::<_, User>(&query)
        .fetch_all(pool)
        .await
}

// SECURE: Diesel query builder (injection-safe by design)
fn get_user_safe(conn: &mut PgConnection, name: &str) -> QueryResult<User> {
    users::table
        .filter(users::name.eq(name)) // Parameterized automatically
        .first(conn)
}

// SECURE: sqlx with bind parameters
async fn get_user_sqlx_safe(pool: &PgPool, username: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE name = $1")
        .bind(username) // Parameterized
        .fetch_one(pool)
        .await
}
```

**Security implication:** ORM raw query methods bypass injection protection. Always use query builders or explicit bind parameters.

**Detection:** the inline forms (`sql_query(format!(...))`, `query_as(&format!(...))`) are caught by the regex below. The more common shape — a `let` binding that builds the query string, then gets passed into `query_as(&query)` — needs a two-pass check: first list files that use `format!(...)` against a `SELECT/INSERT/UPDATE/DELETE` literal, then verify those same files pass the resulting variable into a raw-SQL method.

```bash
# Pass 1: find format! calls that look like SQL.
grep -rnP 'format!\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b' --include='*.rs' .
# Pass 2: for each hit, check whether the variable reaches a raw-SQL entry point.
grep -rnP '\b(sql_query|query|query_as|query_scalar|execute)\s*\(\s*&[A-Za-z_]' --include='*.rs' .
```

### 8. Command Injection via std::process::Command (CWE-78)

Using shell invocation with user input enables command injection, similar to Go's `exec.Command("sh", "-c", ...)`.

```rust
// VULNERABLE: Shell invocation with user input
use std::process::Command;

fn process_file(filename: &str) -> std::io::Result<Vec<u8>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", filename)) // Shell injection: filename = "; rm -rf /"
        .output()?;
    Ok(output.stdout)
}

// SECURE: Direct execution without shell
fn process_file_safe(filename: &str) -> std::io::Result<Vec<u8>> {
    let output = Command::new("cat")
        .arg(filename) // Passed as single argument, no shell interpretation
        .output()?;
    Ok(output.stdout)
}

// SECURE: Validate input before execution
fn process_file_validated(filename: &str) -> Result<Vec<u8>, AppError> {
    let re = regex::Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    if !re.is_match(filename) {
        return Err(AppError::InvalidInput("invalid filename"));
    }
    let path = Path::new("/safe/dir").join(filename);
    let output = Command::new("cat")
        .arg(&path)
        .output()?;
    Ok(output.stdout)
}
```

**Security implication:** Shell invocation via `sh -c` or `bash -c` interprets metacharacters. Pass arguments directly to `Command::new` and avoid shell wrappers.

**Detection regex:** `Command::new\s*\(\s*"(sh|bash|cmd|powershell)"`

### 9. Path Traversal (CWE-22)

Path joining in Rust does not sanitize `..` components. An absolute path argument to `.join()` replaces the base entirely.

```rust
// VULNERABLE: Path::join with user input
fn serve_file(base: &Path, user_input: &str) -> std::io::Result<Vec<u8>> {
    let path = base.join(user_input);
    // If user_input is "../../etc/passwd", path escapes base
    // If user_input is "/etc/passwd" (absolute), base is REPLACED entirely
    std::fs::read(path)
}

// SECURE: Canonicalize and validate
fn serve_file_safe(base: &Path, user_input: &str) -> Result<Vec<u8>, AppError> {
    let base = base.canonicalize()?;
    let requested = base.join(user_input).canonicalize()?;
    if !requested.starts_with(&base) {
        return Err(AppError::Forbidden);
    }
    Ok(std::fs::read(requested)?)
}
```

**Security implication:** Path traversal exposes sensitive files. Always canonicalize and verify the resolved path stays within the base directory.

**Detection regex:** `Path::new\s*\(.*\)\.join\s*\(|\.join\s*\(\s*&?(req|input|param|query|user)`

### 10. Serde Deserialization Pitfalls (CWE-502)

Deserializing untrusted data with `serde` can cause denial of service (deeply nested structures, huge allocations) or logic bugs (missing fields silently defaulted).

```rust
// VULNERABLE: Deserialize untrusted input without limits
#[derive(Deserialize)]
struct UserRequest {
    name: String,         // Unbounded string — attacker sends 1GB name
    tags: Vec<String>,    // Unbounded vector — millions of elements
    metadata: HashMap<String, Value>, // Unbounded map — memory exhaustion
}

fn handle(body: &[u8]) -> Result<UserRequest, serde_json::Error> {
    serde_json::from_slice(body) // No size limits
}

// VULNERABLE: Default values hide missing security-critical fields
#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    #[serde(default)]
    require_mfa: bool, // Defaults to false if omitted — MFA bypass!
}

// SECURE: Bounded deserialization with validation
use validator::Validate;

#[derive(Deserialize, Validate)]
struct UserRequestSafe {
    #[validate(length(min = 1, max = 255))]
    name: String,
    #[validate(length(max = 50))]
    #[serde(default)]
    tags: Vec<String>,
}

fn handle_safe(body: &[u8]) -> Result<UserRequestSafe, AppError> {
    if body.len() > 1_048_576 { // 1MB limit
        return Err(AppError::PayloadTooLarge);
    }
    let req: UserRequestSafe = serde_json::from_slice(body)?;
    req.validate()?;
    Ok(req)
}
```

**Security implication:** Unbounded deserialization enables memory exhaustion DoS. Default values on security-critical fields can bypass authentication or authorization. Always validate after deserialization and set size limits.

**Detection regex:** `serde_json::from_str\s*\(|serde_json::from_slice\s*\(|serde_json::from_reader\s*\(`

### 11. Timing Side-Channel in Comparisons (CWE-208)

Standard equality comparison (`==`) for secrets (tokens, MACs, hashes) leaks timing information that allows attackers to guess values byte-by-byte.

```rust
// VULNERABLE: Standard comparison leaks timing information
fn verify_token(provided: &str, expected: &str) -> bool {
    provided == expected // Short-circuits on first different byte
}

fn verify_hmac(provided: &[u8], expected: &[u8]) -> bool {
    provided == expected // Timing leak reveals which bytes match
}

// SECURE: Constant-time comparison
use constant_time_eq::constant_time_eq;

fn verify_token_safe(provided: &[u8], expected: &[u8]) -> bool {
    constant_time_eq(provided, expected) // Same time regardless of which bytes differ
}

// SECURE: Using ring or subtle crate
use subtle::ConstantTimeEq;

fn verify_hmac_safe(provided: &[u8], expected: &[u8]) -> bool {
    provided.ct_eq(expected).into()
}
```

**Security implication:** Timing attacks against token/HMAC comparison can recover secrets with repeated network requests. Always use constant-time comparison for security-sensitive values.

**Detection regex:** `==\s*(token|secret|hmac|hash|key|password|mac|signature|api_key|auth)`

### 12. Memory Leaks via mem::forget or Rc Cycles (CWE-401)

`mem::forget` prevents destructors from running, leaking resources. `Rc`/`Arc` reference cycles cause unbounded memory growth.

```rust
// VULNERABLE: mem::forget leaks sensitive data
use std::mem;

fn process_secret(secret: String) {
    // ... use secret ...
    mem::forget(secret); // Destructor never runs — secret stays in memory
    // Sensitive data persists in memory indefinitely
}

// VULNERABLE: Rc cycle causes memory leak
use std::rc::Rc;
use std::cell::RefCell;

struct Node {
    next: Option<Rc<RefCell<Node>>>,
}

fn create_cycle() {
    let a = Rc::new(RefCell::new(Node { next: None }));
    let b = Rc::new(RefCell::new(Node { next: Some(a.clone()) }));
    a.borrow_mut().next = Some(b.clone()); // Cycle: a -> b -> a
    // Neither a nor b will ever be freed — memory leak
}

// SECURE: Use Weak references to break cycles
use std::rc::Weak;

struct SafeNode {
    next: Option<Rc<RefCell<SafeNode>>>,
    parent: Option<Weak<RefCell<SafeNode>>>, // Weak breaks the cycle
}

// SECURE: Zeroize sensitive data before drop
use zeroize::Zeroize;

fn process_secret_safe(mut secret: String) {
    // ... use secret ...
    secret.zeroize(); // Overwrites memory with zeros before drop
}
```

**Security implication:** `mem::forget` prevents cleanup of sensitive data and resources. Reference cycles cause unbounded memory growth (DoS). Use `Weak` for back-references and `zeroize` for sensitive data.

**Detection regex:** `mem::forget\s*\(|ManuallyDrop::new\s*\(`

## Rust Edition 2021+ Security Features

### Disjoint Capture in Closures

Edition 2021 changed closures to capture only the fields they use, not the entire struct. This reduces unintended data exposure in closures.

```rust
// Before Edition 2021: entire struct captured
struct Session {
    token: String,
    debug_info: String,
}

fn log_debug(session: &Session) {
    let logger = || {
        // Before 2021: captures all of `session`, including `token`
        // After 2021: captures only `session.debug_info`
        println!("{}", session.debug_info);
    };
    logger();
}
```

**Security implication:** Disjoint capture reduces accidental exposure of sensitive fields when closures are passed to logging, serialization, or error handling functions.

### Default Cargo Features and Dependency Auditing

```toml
# SECURE: Audit dependencies and minimize features
[dependencies]
reqwest = { version = "0.11", default-features = false, features = ["json", "rustls-tls"] }
# Use rustls instead of openssl to reduce native dependency surface

# Run: cargo audit
# Run: cargo deny check
```

**Security implication:** Default features can pull in unnecessary native dependencies that increase attack surface. Use `default-features = false` and explicitly list needed features.

## Rust Edition 2024+ Security Features

### Unsafe Extern Blocks

Edition 2024 requires `unsafe` on `extern` blocks, making FFI boundaries more visible in code review.

```rust
// Edition 2024: extern blocks require unsafe keyword
unsafe extern "C" {
    fn external_function(ptr: *const u8) -> i32;
}
```

**Security implication:** Explicit `unsafe` on extern blocks ensures FFI calls are not overlooked during security audits.

### Lifetime Elision Improvements

Edition 2024 refines lifetime elision rules, reducing the need for explicit lifetimes while maintaining safety guarantees.

**Security implication:** Fewer explicit lifetimes means fewer opportunities for lifetime annotation errors that could lead to dangling references.

## Detection Patterns for Auditing Rust Security Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| `unsafe` block/fn/impl | `unsafe\s*\{\|unsafe\s+fn\s\|unsafe\s+impl\s` | warning | SA-RS-01 |
| FFI boundary | `extern\s+"C"\s*\{\|#\[no_mangle\]` | warning | SA-RS-02 |
| `panic!` in library code | `panic!\s*\(\|todo!\s*\(\|unimplemented!\s*\(` | warning | SA-RS-03 |
| `.unwrap()` / `.expect()` | `\.unwrap\(\)\|\.expect\(\s*"` | warning | SA-RS-04 |
| Raw pointer cast | `as\s+\*const\s\|as\s+\*mut\s` | warning | SA-RS-05 |
| SQL with format! | `sql_query\s*\(\s*format!\|query.*&format!` | error | SA-RS-06 |
| Shell command injection | `Command::new\s*\(\s*"(sh\|bash\|cmd)"` | error | SA-RS-07 |
| Path traversal via join | `\.join\s*\(.*req\|input\|param\|query\|user` | warning | SA-RS-08 |
| Unbounded deserialization | `serde_json::from_(str\|slice\|reader)\s*\(` | warning | SA-RS-09 |
| Timing-unsafe comparison | `==\s*(token\|secret\|hmac\|hash\|key\|password)` | error | SA-RS-10 |
| `mem::forget` usage | `mem::forget\s*\(\|ManuallyDrop::new\s*\(` | warning | SA-RS-11 |
| Hardcoded credentials | `(password\|secret\|api_key\|token)\s*[:=]\s*"[^"]{8,}"` | error | SA-RS-12 |
| `transmute` usage | `std::mem::transmute\|mem::transmute` | error | SA-RS-13 |
| Missing `#[must_use]` on Result | Custom lint — use `clippy::must_use_candidate` | warning | SA-RS-14 |
| Unbounded allocation | `Vec::with_capacity\s*\(\s*(req\|input\|user)` | warning | SA-RS-15 |

## Version Adoption Security Checklist

- [ ] Run `cargo clippy -- -W clippy::all -W clippy::pedantic` in CI
- [ ] Run `cargo audit` to check dependencies for known vulnerabilities
- [ ] Run `cargo deny check` for license and vulnerability compliance
- [ ] Audit all `unsafe` blocks — document safety invariants with `// Safety:` comments
- [ ] Audit all FFI boundaries for null checks and lifetime correctness
- [ ] Replace `.unwrap()` / `.expect()` in production code paths with proper error handling
- [ ] Verify no `panic!` / `todo!` / `unimplemented!` in library code
- [ ] Use `checked_*` arithmetic for security-relevant calculations
- [ ] Use constant-time comparison for tokens, MACs, and hashes
- [ ] Set payload size limits before `serde` deserialization
- [ ] Use `zeroize` crate for sensitive data cleanup
- [ ] Minimize dependency features with `default-features = false`
- [ ] Use `rustls` instead of `openssl` bindings where possible

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `path-traversal-prevention.md` — Path traversal prevention
- `cryptography-guide.md` — Cryptographic best practices
- `supply-chain-security.md` — Dependency auditing

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Multi-language security references expansion |
