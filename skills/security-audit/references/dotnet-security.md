# .NET Security Patterns

Security patterns, common misconfigurations, and detection regexes for ASP.NET Core applications.

## Security Misconfiguration

### Middleware Ordering - Auth Before Routing

`MapControllers()` only registers endpoints — it does not execute per-request. The order that actually matters is of the **middleware** calls: `UseRouting` → `UseAuthentication` → `UseAuthorization` → endpoint execution. Getting that sequence wrong (e.g., authorization before authentication) is what causes auth to be skipped.

```csharp
// VULNERABLE: Authorization registered before authentication —
// requests reach UseAuthorization with no identity established, so
// [Authorize] attributes evaluate against an anonymous principal.
var app = builder.Build();

app.UseRouting();
app.UseAuthorization();       // Runs before identity is set
app.UseAuthentication();
app.MapControllers();

// SECURE: Correct middleware ordering
var app = builder.Build();

app.UseRouting();
app.UseAuthentication();      // 1. Establish identity
app.UseAuthorization();       // 2. Check permissions
app.MapControllers();         // 3. Register endpoints (order of the
                              //    call relative to the auth middleware
                              //    does not matter — MapControllers()
                              //    only registers routes).
```

**Detection guidance:** flag files where `UseAuthorization()` appears before `UseAuthentication()` on the middleware pipeline, or where `UseAuthentication()` is missing entirely from a pipeline that calls `UseAuthorization()`. A line-oriented regex like `UseAuthorization\s*\([\s\S]{0,200}UseAuthentication\s*\(` catches the first case; the second needs a per-file check. Do not match on `MapControllers()`-vs-`UseAuthentication()` ordering — that is not the bug.
**Severity:** error

### CORS Policy Misconfiguration

```csharp
// VULNERABLE: Allowing any origin with credentials
builder.Services.AddCors(options =>
{
    options.AddPolicy("Open", policy =>
    {
        policy.AllowAnyOrigin()     // Any origin
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();   // With credentials — browser will block,
                                     // but indicates intent to be wide open
    });
});

// VULNERABLE: Wildcard origin pattern
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.SetIsOriginAllowed(_ => true)  // Accepts ANY origin
              .AllowCredentials();
    });
});

// SECURE: Explicit origin allowlist
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                "https://app.example.com",
                "https://admin.example.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Content-Type", "Authorization")
              .AllowCredentials();
    });
});
```

**Detection regex:** `AllowAnyOrigin\s*\(\s*\)|SetIsOriginAllowed\s*\(\s*_?\s*=>\s*true\s*\)`
**Severity:** error

## Injection

### Entity Framework Raw SQL Injection

```csharp
// VULNERABLE: String concatenation in raw SQL
public class ProductRepository
{
    private readonly AppDbContext _context;

    public async Task<List<Product>> Search(string name)
    {
        // SQL injection via string concatenation
        return await _context.Products
            .FromSqlRaw("SELECT * FROM Products WHERE Name LIKE '%" + name + "%'")
            .ToListAsync();
    }
}

// VULNERABLE: String interpolation with FromSqlRaw (NOT parameterized)
public async Task<List<Product>> SearchUnsafe(string name)
{
    var query = $"SELECT * FROM Products WHERE Name LIKE '%{name}%'";
    return await _context.Products.FromSqlRaw(query).ToListAsync();
}

// SECURE: Use FromSqlInterpolated (auto-parameterizes)
public async Task<List<Product>> SearchSafe(string name)
{
    return await _context.Products
        .FromSqlInterpolated($"SELECT * FROM Products WHERE Name LIKE {"%" + name + "%"}")
        .ToListAsync();
}

// SECURE: Use FromSqlRaw with explicit parameters
public async Task<List<Product>> SearchSafeParams(string name)
{
    return await _context.Products
        .FromSqlRaw("SELECT * FROM Products WHERE Name LIKE {0}", "%" + name + "%")
        .ToListAsync();
}

// BEST: Use LINQ instead of raw SQL
public async Task<List<Product>> SearchBest(string name)
{
    return await _context.Products
        .Where(p => p.Name.Contains(name))
        .ToListAsync();
}
```

**Detection regex:** `FromSqlRaw\s*\(\s*\$"|FromSqlRaw\s*\(\s*"[^"]*"\s*\+|ExecuteSqlRaw\s*\(\s*\$"|ExecuteSqlRaw\s*\(\s*"[^"]*"\s*\+`
**Severity:** error

### Razor View XSS

```csharp
// VULNERABLE: Unencoded output in Razor view
@{
    var userComment = ViewBag.Comment;  // "<script>alert('xss')</script>"
}

<!-- This renders raw HTML — XSS -->
@Html.Raw(userComment)

<!-- Also vulnerable: writing to JavaScript context -->
<script>
    var data = '@Html.Raw(ViewBag.UserInput)';  // XSS in JS context
</script>

<!-- Also vulnerable: using MarkupString in Blazor/Razor components -->
@((MarkupString)userInput)

// SECURE: Use default Razor encoding (automatic)
<p>@Model.Comment</p>  <!-- Auto-encoded by Razor -->

// SECURE: Use explicit encoding for JavaScript context
<script>
    var data = '@Json.Serialize(Model.UserInput)';  // Properly encoded for JS
</script>

// SECURE: Sanitize if raw HTML is truly needed
@using Ganss.Xss;
@{
    var sanitizer = new HtmlSanitizer();
    var safeHtml = sanitizer.Sanitize(Model.Comment);
}
@Html.Raw(safeHtml)
```

**Detection regex:** `Html\.Raw\s*\((?!.*Sanitiz)|@\(\s*\(MarkupString\)\s*\w+|MarkupString\)\s*(?:userInput|input|request|query|param|data|content|comment|message|text|body|html|value)`
**Severity:** error

## Authentication & Authorization

### [AllowAnonymous] Overreach

```csharp
// VULNERABLE: [AllowAnonymous] on controller exposes all actions
[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]                 // ALL endpoints in this controller are public
public class UsersController : ControllerBase
{
    [HttpGet]
    public IActionResult GetAll() => Ok(_users);

    [HttpDelete("{id}")]         // DELETE is also anonymous!
    public IActionResult Delete(int id)
    {
        _userService.Delete(id);
        return NoContent();
    }

    [HttpPut("{id}/role")]       // Role change is also anonymous!
    public IActionResult ChangeRole(int id, [FromBody] RoleDto dto)
    {
        _userService.UpdateRole(id, dto.Role);
        return NoContent();
    }
}

// SECURE: Apply [AllowAnonymous] only to specific actions
[ApiController]
[Route("api/[controller]")]
[Authorize]                       // Controller-level auth by default
public class UsersController : ControllerBase
{
    [HttpGet]
    [AllowAnonymous]              // Only GET is public
    public IActionResult GetAll() => Ok(_users);

    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]  // Explicit admin role required
    public IActionResult Delete(int id)
    {
        _userService.Delete(id);
        return NoContent();
    }

    [HttpPut("{id}/role")]
    [Authorize(Policy = "SuperAdmin")]
    public IActionResult ChangeRole(int id, [FromBody] RoleDto dto)
    {
        _userService.UpdateRole(id, dto.Role);
        return NoContent();
    }
}
```

**Detection regex:** `\[AllowAnonymous\]\s*(?:\r?\n\s*)*(?:public\s+class|\[(?:ApiController|Route)\])`
**Severity:** error

### Anti-Forgery Token Misuse

```csharp
// VULNERABLE: POST action without anti-forgery validation
[HttpPost]
public IActionResult Transfer([FromForm] TransferModel model)
{
    // No [ValidateAntiForgeryToken] — CSRF vulnerable
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Success");
}

// VULNERABLE: Anti-forgery disabled globally
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new IgnoreAntiforgeryTokenAttribute());  // Disables for ALL actions
});

// SECURE: Add anti-forgery validation
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult Transfer([FromForm] TransferModel model)
{
    _bankService.Transfer(model.FromAccount, model.ToAccount, model.Amount);
    return RedirectToAction("Success");
}

// SECURE: Add anti-forgery globally via AutoValidateAntiforgeryToken
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// In Razor views, include the token:
// <form method="post">
//     @Html.AntiForgeryToken()
//     ...
// </form>
// Or use Tag Helpers (automatically included with <form> tag helper)
```

**Detection regex:** `IgnoreAntiforgeryTokenAttribute\s*\(\s*\)|IgnoreAntiforgeryToken\]`
**Severity:** warning

## Data Protection

### IDataProtector Key Rotation

```csharp
// VULNERABLE: Static key material or missing key rotation config
builder.Services.AddDataProtection()
    .SetApplicationName("my-app");
    // No key storage configured — keys stored in memory, lost on restart
    // No key lifetime configured — keys never rotate

// VULNERABLE: Disabling automatic key generation
builder.Services.AddDataProtection()
    .DisableAutomaticKeyGeneration();  // Keys will expire and never rotate

// SECURE: Configure persistent storage and key rotation
builder.Services.AddDataProtection()
    .SetApplicationName("my-app")
    .PersistKeysToAzureBlobStorage(blobClient)
    .ProtectKeysWithAzureKeyVault(keyUri, credential)
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));  // Rotate every 90 days

// SECURE: For multi-server deployments, share key ring
builder.Services.AddDataProtection()
    .SetApplicationName("my-app")
    .PersistKeysToDbContext<DataProtectionKeyContext>()
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
```

**Detection regex:** `DisableAutomaticKeyGeneration\s*\(\s*\)`
**Severity:** warning

### SignalR Authentication

```csharp
// VULNERABLE: SignalR hub without authentication
[AllowAnonymous]  // or simply missing [Authorize]
public class ChatHub : Hub
{
    public async Task SendMessage(string user, string message)
    {
        // Any anonymous client can broadcast messages
        await Clients.All.SendAsync("ReceiveMessage", user, message);
    }

    public async Task JoinAdminChannel()
    {
        // No auth check — anyone can join admin channel
        await Groups.AddToGroupAsync(Context.ConnectionId, "admins");
    }
}

// SECURE: Require authentication on hub
[Authorize]
public class ChatHub : Hub
{
    public async Task SendMessage(string message)
    {
        var user = Context.User?.Identity?.Name
            ?? throw new HubException("Not authenticated");

        await Clients.All.SendAsync("ReceiveMessage", user, message);
    }

    [Authorize(Roles = "Admin")]
    public async Task JoinAdminChannel()
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, "admins");
    }
}

// SECURE: Configure SignalR auth with JWT for WebSocket transport
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Read token from query string for WebSocket connections
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) &&
                    path.StartsWithSegments("/hubs"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });
```

**Detection regex:** `class\s+\w+Hub\s*:\s*Hub\b(?![\s\S]{0,50}\[Authorize\])|(?<!\[Authorize[^\]]*\]\s*(?:\r?\n\s*)*)public\s+class\s+\w+Hub\s*:\s*Hub\b`
**Severity:** warning

## Cross-Site Scripting (XSS)

### Tag Helper / HTML Helper Misuse

```csharp
// VULNERABLE: Rendering user HTML in tag helper
<div id="comments">
    @foreach (var comment in Model.Comments)
    {
        @Html.Raw(comment.Body)  // XSS — user content rendered as raw HTML
    }
</div>

// SECURE: Let Razor auto-encode
<div id="comments">
    @foreach (var comment in Model.Comments)
    {
        <p>@comment.Body</p>  <!-- Auto-encoded -->
    }
</div>
```

See SA-DOTNET-04 above for the primary Razor XSS detection pattern.

## Detection Patterns for .NET

```csharp
// Grep patterns for ASP.NET Core security issues:
string[] dotnetPatterns = {
    @"FromSqlRaw\(\$""",                   // SQL injection
    @"Html\.Raw\(",                         // XSS via raw HTML
    @"\[AllowAnonymous\].*class",          // Controller-wide anonymous access
    @"AllowAnyOrigin\(\)",                 // Open CORS
    @"IgnoreAntiforgeryToken",             // Anti-forgery disabled
    @"DisableAutomaticKeyGeneration",      // Key rotation disabled
    @"MapControllers.*UseAuthentication",  // Wrong middleware order
    @"SetIsOriginAllowed.*true",           // CORS wildcard
    @"class\s+\w+Hub\s*:\s*Hub",          // SignalR hub — verify auth
    @"BinaryFormatter",                    // Insecure deserialization
};
```

---

## CSRF Protection

### Form-Based CSRF in ASP.NET Core

ASP.NET Core provides automatic anti-forgery token generation via Tag Helpers. See SA-DOTNET-06 above for configuration patterns and detection.

Key points:
- MVC: Use `[AutoValidateAntiforgeryToken]` globally or `[ValidateAntiForgeryToken]` per action
- Razor Pages: Anti-forgery is enabled by default for `POST` handlers
- API controllers: CSRF is generally not needed for stateless JWT/Bearer token APIs
- SignalR: Uses its own anti-forgery mechanism via connection tokens

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| Middleware ordering (SA-DOTNET-01) | Critical | Immediate | Low |
| Raw SQL injection (SA-DOTNET-02) | Critical | Immediate | Medium |
| [AllowAnonymous] on controller (SA-DOTNET-03) | Critical | Immediate | Low |
| Razor XSS via Html.Raw (SA-DOTNET-04) | Critical | Immediate | Medium |
| CORS wildcard (SA-DOTNET-05) | High | 1 week | Low |
| Anti-forgery disabled (SA-DOTNET-06) | High | 1 week | Low |
| Key rotation disabled (SA-DOTNET-07) | Medium | 1 month | Medium |
| SignalR unauthenticated (SA-DOTNET-08) | Medium | 1 month | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `blazor-security.md` — Blazor-specific patterns (WebAssembly, server-side)
- `spring-security.md` — Comparison with Spring Security patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 — framework security references |
