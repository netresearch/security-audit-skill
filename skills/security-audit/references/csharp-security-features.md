# C# Security Features by Version

Modern C# versions introduce language features and API improvements that directly improve security when used correctly. This reference documents security-relevant features and common vulnerability patterns from C# 9 through C# 12, targeting .NET 5 through .NET 8.

## Core C# Security Patterns

### BinaryFormatter Insecure Deserialization

`BinaryFormatter` is the most dangerous serialization mechanism in .NET. It deserializes arbitrary types and can lead to remote code execution through gadget chains.

```csharp
// VULNERABLE: BinaryFormatter on untrusted input
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(request.Body); // RCE via gadget chains
```

```csharp
// SECURE: Use System.Text.Json with explicit types
var options = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
};
UserDto user = JsonSerializer.Deserialize<UserDto>(request.Body, options);

// SECURE: Use MessagePack with strict mode for binary serialization
var options = MessagePackSerializerOptions.Standard
    .WithSecurity(MessagePackSecurity.UntrustedData);
UserDto user = MessagePackSerializer.Deserialize<UserDto>(data, options);
```

**Security implication:** `BinaryFormatter` (CWE-502) enables remote code execution through .NET gadget chains (ysoserial.net). Microsoft has marked it as obsolete in .NET 5+ and removed it from .NET 9. Never use `BinaryFormatter` on untrusted data. Migrate to `System.Text.Json` or `MessagePack`.

**Detection regex:** `new\s+BinaryFormatter\s*\(`

---

### NetDataContractSerializer Deserialization

`NetDataContractSerializer` embeds full .NET type information in the serialized data, enabling type confusion and code execution attacks.

```csharp
// VULNERABLE: NetDataContractSerializer on untrusted input
var serializer = new NetDataContractSerializer();
object obj = serializer.Deserialize(xmlReader); // Type info from attacker

// VULNERABLE: DataContractSerializer with untrusted known types
var knownTypes = GetTypesFromConfig(); // Attacker controls the type list
var serializer = new DataContractSerializer(typeof(object), knownTypes);
```

```csharp
// SECURE: DataContractSerializer with explicit, fixed known types
var knownTypes = new[] { typeof(UserDto), typeof(OrderDto) };
var serializer = new DataContractSerializer(typeof(UserDto), knownTypes);
UserDto user = (UserDto)serializer.ReadObject(xmlReader);

// SECURE: Use System.Text.Json
UserDto user = JsonSerializer.Deserialize<UserDto>(json);
```

**Security implication:** `NetDataContractSerializer` (CWE-502) includes .NET type information in serialized data, allowing attackers to specify arbitrary types. This enables the same gadget chain attacks as `BinaryFormatter`. Always use serializers with explicit type binding.

**Detection regex:** `new\s+NetDataContractSerializer\s*\(`

---

### SQL Injection in Entity Framework

Entity Framework Core's `FromSqlRaw` and `FromSqlInterpolated` have different safety characteristics. String interpolation in `FromSqlRaw` is dangerous.

```csharp
// VULNERABLE: String concatenation in FromSqlRaw
string username = request.Query["username"];
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Username = '" + username + "'")
    .ToList();

// VULNERABLE: String interpolation in FromSqlRaw (NOT parameterized)
var users = context.Users
    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'")
    .ToList();
```

```csharp
// SECURE: Use FromSqlInterpolated (auto-parameterizes)
string username = request.Query["username"];
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
    .ToList();

// SECURE: Use FromSqlRaw with explicit parameters
var users = context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username)
    .ToList();

// SECURE: Use LINQ queries (always parameterized)
var users = context.Users
    .Where(u => u.Username == username)
    .ToList();
```

**Security implication:** `FromSqlRaw` with string interpolation or concatenation (CWE-89) creates SQL injection vulnerabilities. The critical distinction is that `FromSqlInterpolated` converts `FormattableString` interpolation into parameterized queries, while `FromSqlRaw` with `$""` passes a plain string. Always prefer LINQ queries or `FromSqlInterpolated`.

**Detection regex:** `FromSqlRaw\s*\(\s*\$`

---

### LDAP Injection

Constructing LDAP queries from user input without sanitization enables LDAP injection attacks.

```csharp
// VULNERABLE: String concatenation in LDAP filter
string username = request.Query["user"];
string filter = $"(&(objectClass=user)(sAMAccountName={username}))";
DirectorySearcher searcher = new DirectorySearcher(filter);
SearchResultCollection results = searcher.FindAll();
// Attacker sends: *)(objectClass=*) to dump all entries
```

```csharp
// SECURE: Escape LDAP special characters
string username = request.Query["user"];
string safeUsername = LdapEscape(username);
string filter = $"(&(objectClass=user)(sAMAccountName={safeUsername}))";

static string LdapEscape(string input)
{
    return input
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}

// SECURE: Use Novell.Directory.Ldap with parameterized searches
var filter = LdapFilter.Create("(&(objectClass=user)(sAMAccountName=?))", username);
```

**Security implication:** LDAP injection (CWE-90) allows attackers to modify LDAP queries to bypass authentication, enumerate users, or extract directory data. Always escape LDAP special characters (`*`, `(`, `)`, `\`, NUL) or use parameterized query libraries.

**Detection regex:** `DirectorySearcher\s*\(\s*\$`

---

### XML External Entities (XXE)

`XmlDocument` with default settings in older .NET versions is vulnerable to XXE. `XmlReader` with secure defaults is the recommended approach.

```csharp
// VULNERABLE: XmlDocument with ProhibitDtd=false or .NET < 4.5.2
XmlDocument doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver(); // Enables external entity resolution
doc.LoadXml(userInput);

// VULNERABLE: XmlTextReader without DtdProcessing disabled
XmlTextReader reader = new XmlTextReader(stream);
// DtdProcessing defaults to Parse in older .NET
```

```csharp
// SECURE: XmlDocument with null resolver (.NET 4.5.2+, default is secure)
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null; // Explicitly disable external entity resolution
doc.LoadXml(userInput);

// SECURE: XmlReader with secure settings
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 1024
};
using XmlReader reader = XmlReader.Create(stream, settings);

// SECURE: Use LINQ to XML (secure by default in .NET Core)
XDocument doc = XDocument.Parse(userInput);
```

**Security implication:** XXE (CWE-611) in .NET occurs when XML parsers resolve external entities. While .NET Core / .NET 5+ defaults are generally secure, explicitly setting `XmlResolver = null` and `DtdProcessing = DtdProcessing.Prohibit` provides defense in depth. Always prefer `XmlReader` with explicit secure settings.

**Detection regex:** `new\s+XmlDocument\s*\(`

---

### Command Injection via Process.Start

Using `Process.Start` with user-controlled arguments and `UseShellExecute = true` enables command injection.

```csharp
// VULNERABLE: User input in process arguments with shell execution
string filename = request.Query["file"];
Process.Start("cmd.exe", $"/c type {filename}");

// VULNERABLE: UseShellExecute with user input
var psi = new ProcessStartInfo
{
    FileName = userInput,
    UseShellExecute = true // Interprets shell metacharacters
};
Process.Start(psi);
```

```csharp
// SECURE: Validate input and avoid shell execution
string filename = request.Query["file"];
if (!Regex.IsMatch(filename, @"^[a-zA-Z0-9_\-]+\.(txt|csv|pdf)$"))
{
    throw new ArgumentException("Invalid filename");
}

var psi = new ProcessStartInfo
{
    FileName = "/usr/bin/cat",
    Arguments = filename,
    UseShellExecute = false, // Do not pass through shell
    RedirectStandardOutput = true,
    CreateNoWindow = true
};
using var process = Process.Start(psi);

// SECURE: Use .NET APIs instead of shell commands
string content = await File.ReadAllTextAsync(validatedPath);
```

**Security implication:** Command injection (CWE-78) via `Process.Start` with `UseShellExecute = true` passes arguments through the OS shell, enabling metacharacter injection. Always set `UseShellExecute = false`, validate arguments against strict patterns, and prefer .NET library APIs over shell commands.

**Detection regex:** `Process\.Start\s*\(`

---

### Path Traversal

Constructing file paths from user input without validation allows directory traversal.

```csharp
// VULNERABLE: Direct use of user input in file paths
string filename = request.Query["file"];
string path = Path.Combine("/uploads", filename);
byte[] content = File.ReadAllBytes(path);
// Two distinct path-traversal failure modes to know about:
//  (1) Relative traversal:  "../etc/passwd"  → Combine returns
//      "/uploads/../etc/passwd", which File.ReadAllBytes happily
//      resolves outside /uploads unless the caller re-anchors it.
//  (2) Rooted-override:     "/etc/passwd"    → Path.Combine drops
//      the first argument when the second is absolute, so the result
//      is literally "/etc/passwd". This is documented behaviour.
```

```csharp
// SECURE: Validate resolved path stays within allowed directory
string filename = request.Query["file"];
string baseDir = Path.GetFullPath("/uploads");
string fullPath = Path.GetFullPath(Path.Combine(baseDir, filename));

if (!fullPath.StartsWith(baseDir + Path.DirectorySeparatorChar))
{
    throw new SecurityException("Path traversal detected");
}
byte[] content = File.ReadAllBytes(fullPath);

// SECURE: Use Path.GetFileName to strip directory components
string safeFilename = Path.GetFileName(filename); // strips all path components
string fullPath = Path.Combine(baseDir, safeFilename);
```

**Security implication:** Path traversal (CWE-22) in .NET is particularly dangerous because `Path.Combine` has a surprising behavior: if the second argument is an absolute path, it ignores the first argument entirely. Always use `Path.GetFullPath` and verify the result starts with the expected base directory.

**Detection regex:** `Path\.Combine\s*\([^)]*request\.|Path\.Combine\s*\([^)]*Request\.`

---

### CORS Misconfiguration in ASP.NET Core

Overly permissive CORS policies allow cross-origin attacks against authenticated endpoints.

```csharp
// VULNERABLE: Allow any origin
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// VULNERABLE: Reflecting Origin header as allowed origin
app.Use(async (context, next) =>
{
    var origin = context.Request.Headers["Origin"].ToString();
    context.Response.Headers.Add("Access-Control-Allow-Origin", origin);
    context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
    await next();
});
```

```csharp
// SECURE: Explicitly allowlist trusted origins
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                "https://app.example.com",
                "https://admin.example.com")
              .WithMethods("GET", "POST")
              .WithHeaders("Content-Type", "Authorization")
              .AllowCredentials();
    });
});
```

**Security implication:** CORS misconfiguration (CWE-346) with `AllowAnyOrigin` combined with `AllowCredentials` allows any website to make authenticated requests on behalf of users. Always specify explicit origins, methods, and headers. Never reflect the `Origin` header as the allowed origin.

**Detection regex:** `AllowAnyOrigin\s*\(`

---

### Weak Cryptography

Use of broken or deprecated cryptographic algorithms.

```csharp
// VULNERABLE: MD5 is broken
using var md5 = MD5.Create();
byte[] hash = md5.ComputeHash(data);

// VULNERABLE: SHA-1 is deprecated for security use
using var sha1 = SHA1.Create();
byte[] hash = sha1.ComputeHash(data);

// VULNERABLE: DES is broken (56-bit key)
using var des = DESCryptoServiceProvider.Create();

// VULNERABLE: TripleDES is deprecated
using var tdes = TripleDESCryptoServiceProvider.Create();
```

```csharp
// SECURE: SHA-256 or stronger
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(data);

// SECURE: AES-GCM for authenticated encryption (.NET Core 3.0+)
using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

// SECURE: Use BCrypt/Argon2 for passwords (via library)
string hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
```

**Security implication:** MD5 (CWE-328) and SHA-1 are vulnerable to collision attacks. DES (CWE-327) has insufficient key length. Always use SHA-256+ for hashing and AES-GCM for encryption. Use BCrypt or Argon2 for password hashing.

**Detection regex (MD5):** `MD5\.Create\s*\(`
**Detection regex (SHA-1):** `SHA1\.Create\s*\(`
**Detection regex (DES):** `DESCryptoServiceProvider`

---

### Insecure Random Number Generation

`System.Random` is not cryptographically secure and must not be used for security-sensitive operations.

```csharp
// VULNERABLE: System.Random is predictable
var random = new Random();
string token = Convert.ToBase64String(
    BitConverter.GetBytes(random.Next()));

// VULNERABLE: System.Random seeded with time
var random = new Random(DateTime.Now.Millisecond);
int otp = random.Next(100000, 999999);
```

```csharp
// SECURE: RandomNumberGenerator for security-sensitive operations
byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
string token = Convert.ToBase64String(tokenBytes);

// SECURE: Cryptographic random integer
int otp = RandomNumberGenerator.GetInt32(100000, 999999);

// SECURE: .NET 6+ simplified API
string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
```

**Security implication:** `System.Random` (CWE-338) uses a predictable PRNG algorithm. If an attacker can observe outputs or guess the seed, they can predict future values, compromising tokens, OTPs, CSRF tokens, and other security-critical random values. Always use `RandomNumberGenerator` for security purposes.

**Detection regex:** `new\s+Random\s*\(`

---

## C# 9+

### Records for Immutable DTOs

Records provide value-based equality and immutability, making them ideal for data transfer objects that should not be modified after validation.

```csharp
// VULNERABLE: Mutable DTO allows post-validation tampering
public class LoginRequest
{
    public string Username { get; set; }
    public string Role { get; set; }
}

var request = Deserialize<LoginRequest>(input);
Validate(request);
request.Role = "admin"; // Modified after validation (TOCTOU)
```

```csharp
// SECURE: Record is immutable after construction
public record LoginRequest(string Username, string Role)
{
    // Validation in constructor
    public LoginRequest
    {
        ArgumentNullException.ThrowIfNull(Username);
        ArgumentNullException.ThrowIfNull(Role);
        if (!new[] { "user", "editor", "viewer" }.Contains(Role))
            throw new ArgumentException($"Invalid role: {Role}");
    }
}

var request = Deserialize<LoginRequest>(input);
// request.Role = "admin"; // Compilation error — init-only
```

**Security implication:** Records enforce immutability through init-only properties, preventing TOCTOU (CWE-367) attacks where data is modified between validation and use. The positional syntax ensures all required fields are set at construction time.

---

### Init-Only Properties

`init` accessors prevent modification after object initialization.

```csharp
// VULNERABLE: Regular setter allows mutation after creation
public class SecurityConfig
{
    public string EncryptionKey { get; set; }
    public bool RequireSsl { get; set; }
}

// Someone accidentally resets in middleware
config.RequireSsl = false;
```

```csharp
// SECURE: Init-only setters prevent post-initialization changes
public class SecurityConfig
{
    public required string EncryptionKey { get; init; }
    public required bool RequireSsl { get; init; }
}

var config = new SecurityConfig
{
    EncryptionKey = Environment.GetEnvironmentVariable("ENC_KEY")!,
    RequireSsl = true
};
// config.RequireSsl = false; // Compilation error
```

**Security implication:** Init-only properties prevent accidental or malicious modification of security configuration after initialization, reducing the attack surface for configuration tampering.

---

## C# 10+

### File-Scoped Namespaces and Global Usings Security

Global usings can inadvertently expose dangerous APIs across the entire project.

```csharp
// VULNERABLE: Global using exposes dangerous APIs everywhere
// GlobalUsings.cs
global using System.Diagnostics; // Process.Start available everywhere
global using System.Runtime.Serialization.Formatters.Binary; // BinaryFormatter everywhere
global using System.Reflection; // Reflection APIs everywhere
```

```csharp
// SECURE: Only globalize safe, commonly needed namespaces
// GlobalUsings.cs
global using System;
global using System.Collections.Generic;
global using System.Linq;
global using System.Threading.Tasks;
global using Microsoft.Extensions.Logging;

// Import dangerous namespaces only where needed, per file
// In ProcessService.cs only:
using System.Diagnostics;
```

**Security implication:** Global usings reduce the friction of using dangerous APIs. If `System.Diagnostics` is a global using, any file can call `Process.Start` without an explicit import — making it harder to audit for command injection during code review. Restrict global usings to safe, utility namespaces.

---

### Constant Interpolated Strings

C# 10 allows `const` interpolated strings, which improves security by ensuring string values are compile-time constants.

```csharp
// SECURE: Const interpolated strings for configuration keys
const string AppName = "MyApp";
const string ConfigPrefix = $"{AppName}:Security";
const string EncryptionKeyPath = $"{ConfigPrefix}:EncryptionKey";
// These cannot be modified at runtime
```

**Security implication:** Constant strings prevent runtime tampering with configuration paths and keys, providing compile-time guarantees about their values.

---

## C# 11+

### Required Members for Initialization Safety

The `required` modifier ensures that properties are set during initialization, preventing null-reference security issues.

```csharp
// VULNERABLE: Optional properties may be unset
public class AuthToken
{
    public string UserId { get; set; }
    public string Token { get; set; }
    public DateTime Expiry { get; set; }
}

var token = new AuthToken { UserId = "admin" };
// Token and Expiry are default — null and DateTime.MinValue
// Checks against Expiry may pass (MinValue < now is true, but wrong semantics)
```

```csharp
// SECURE: Required members force complete initialization
public class AuthToken
{
    public required string UserId { get; init; }
    public required string Token { get; init; }
    public required DateTime Expiry { get; init; }
}

var token = new AuthToken
{
    UserId = "admin",
    Token = GenerateToken(),
    Expiry = DateTime.UtcNow.AddHours(1)
};
// Omitting any required property is a compile-time error
```

**Security implication:** The `required` modifier (CWE-665 prevention) ensures all security-critical fields are initialized. Without it, uninitialized DateTime fields default to `DateTime.MinValue`, which can cause unexpected behavior in expiry checks.

---

### Raw String Literals for Safe Query Templates

Raw string literals eliminate escaping issues in SQL, regex, and configuration strings.

```csharp
// VULNERABLE: Escaping errors in complex queries
string query = "SELECT * FROM Users WHERE Name = @name AND Role = 'admin\'s role'";
// Easy to get escaping wrong, leading to SQL syntax errors or injection

// VULNERABLE: Regex escaping mistakes
string pattern = "password\\s*=\\s*['\"][^'\"]+['\"]";
// Hard to verify correctness with all the backslashes
```

```csharp
// SECURE: Raw string literals — no escaping needed
string query = """
    SELECT * FROM Users
    WHERE Name = @name
    AND Role = 'admin''s role'
    """;

// SECURE: Regex is readable and verifiable
string pattern = """password\s*=\s*['"][^'"]+['"]""";
```

**Security implication:** Raw string literals reduce the risk of escaping errors in SQL queries, regular expressions, and configuration strings. When escape sequences are wrong, they can lead to SQL injection, regex denial of service, or configuration bypass.

---

## C# 12+

### Primary Constructors for Concise Validation

Primary constructors reduce boilerplate while still enabling constructor validation.

```csharp
// C# 12: Primary constructor with validation
public class SecureService(ILogger<SecureService> logger, IEncryptionService encryption)
{
    private readonly ILogger<SecureService> _logger = logger
        ?? throw new ArgumentNullException(nameof(logger));
    private readonly IEncryptionService _encryption = encryption
        ?? throw new ArgumentNullException(nameof(encryption));

    public string Encrypt(string data)
    {
        _logger.LogInformation("Encrypting data");
        return _encryption.Encrypt(data);
    }
}
```

**Security implication:** Primary constructors reduce boilerplate code where security-critical null checks might be omitted. Combined with `required` members, they ensure complete initialization of service dependencies.

---

### Collection Expressions for Allowlists

Collection expressions provide concise syntax for defining security allowlists.

```csharp
// C# 12: Collection expressions for security configuration
public static class SecurityPolicy
{
    public static readonly IReadOnlyList<string> AllowedOrigins =
        ["https://app.example.com", "https://admin.example.com"];

    public static readonly IReadOnlySet<string> AllowedMethods =
        (IReadOnlySet<string>)new HashSet<string>(["GET", "POST", "PUT"]);

    public static readonly IReadOnlyList<string> BlockedExtensions =
        [".exe", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js"];
}
```

**Security implication:** Collection expressions make security allowlists and blocklists more readable and maintainable. Clearer definitions reduce the chance of misconfiguration.

---

## Detection Patterns for Auditing C# Security Features

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| BinaryFormatter deserialization | `new\s+BinaryFormatter\s*\(` | error | SA-CS-01 |
| NetDataContractSerializer | `new\s+NetDataContractSerializer\s*\(` | error | SA-CS-02 |
| SQL injection via FromSqlRaw | `FromSqlRaw\s*\(\s*\$` | error | SA-CS-03 |
| LDAP injection via DirectorySearcher | `DirectorySearcher\s*\(\s*\$` | error | SA-CS-04 |
| XXE via XmlDocument | `new\s+XmlDocument\s*\(` | warning | SA-CS-05 |
| Command injection via Process.Start | `Process\.Start\s*\(` | warning | SA-CS-06 |
| Path traversal via Path.Combine with request | `Path\.Combine\s*\([^)]*request\.` | warning | SA-CS-07 |
| CORS AllowAnyOrigin | `AllowAnyOrigin\s*\(` | error | SA-CS-08 |
| Weak hash MD5 | `MD5\.Create\s*\(` | warning | SA-CS-09 |
| Insecure random System.Random | `new\s+Random\s*\(` | warning | SA-CS-10 |
| Weak hash SHA-1 | `SHA1\.Create\s*\(` | warning | SA-CS-11 |
| DES cryptography | `DESCryptoServiceProvider` | error | SA-CS-12 |
| XmlTextReader without DtdProcessing | `new\s+XmlTextReader\s*\(` | warning | SA-CS-13 |
| Origin header reflection | `Headers\[.Origin.\]` | warning | SA-CS-14 |
| Unsafe ProcessStartInfo with ShellExecute | `UseShellExecute\s*=\s*true` | warning | SA-CS-15 |

## Version Adoption Security Checklist

- [ ] Upgrade to .NET 8+ for latest security defaults and API improvements
- [ ] Replace all `BinaryFormatter` usage with `System.Text.Json` or `MessagePack`
- [ ] Remove all `NetDataContractSerializer` usage
- [ ] Audit all `FromSqlRaw` calls; migrate to `FromSqlInterpolated` or LINQ
- [ ] Replace mutable DTOs with records for validated, immutable data transfer
- [ ] Verify all XML parsers set `XmlResolver = null` and `DtdProcessing = Prohibit`
- [ ] Replace `System.Random` with `RandomNumberGenerator` for security-sensitive uses
- [ ] Migrate from DES/3DES to AES-GCM; from MD5/SHA-1 to SHA-256+
- [ ] Audit all `Process.Start` calls; set `UseShellExecute = false`
- [ ] Verify CORS policies use explicit origin allowlists
- [ ] Use `Path.GetFullPath` and boundary checks for all file access with user input
- [ ] Add `required` modifier to all security-critical initialization properties
- [ ] Restrict global usings to safe namespaces only
- [ ] Enable dependency vulnerability scanning (dotnet audit, Snyk)

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `java-security-features.md` — Java security features
- `php-security-features.md` — PHP security features

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 2 — Multi-language security references |
