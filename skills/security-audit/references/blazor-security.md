# Blazor Security Patterns

Security patterns, common misconfigurations, and detection regexes for Blazor applications (WebAssembly and Server).

## Authentication & Authorization

### WebAssembly Client-Side Auth Bypass

```csharp
// VULNERABLE: Authorization logic implemented only on the client (Blazor WASM)
// The client-side [Authorize] attribute can be bypassed by modifying WASM or
// calling APIs directly — it is a UX convenience, not a security boundary.

// Pages/Admin/Dashboard.razor
@page "/admin/dashboard"
@attribute [Authorize(Roles = "Admin")]

<h1>Admin Dashboard</h1>
<p>Sensitive admin data: @adminData</p>

@code {
    private string adminData;

    protected override async Task OnInitializedAsync()
    {
        // VULNERABLE: Fetching from unprotected API endpoint
        adminData = await Http.GetStringAsync("/api/admin/data");
    }
}

// On the server, the API has no authorization:
[ApiController]
[Route("api/admin")]
public class AdminApiController : ControllerBase
{
    [HttpGet("data")]
    // Missing [Authorize] — anyone can call this directly
    public IActionResult GetData() => Ok(new { secret = "sensitive" });
}

// SECURE: Always enforce authorization on the server API
[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]   // Server-side enforcement
public class AdminApiController : ControllerBase
{
    [HttpGet("data")]
    public IActionResult GetData() => Ok(new { secret = "sensitive" });
}

// SECURE: Blazor WASM component with proper error handling for unauthorized
@page "/admin/dashboard"
@attribute [Authorize(Roles = "Admin")]
@inject AuthenticationStateProvider AuthProvider

<AuthorizeView Roles="Admin">
    <Authorized>
        <h1>Admin Dashboard</h1>
        <p>@adminData</p>
    </Authorized>
    <NotAuthorized>
        <p>Access denied. Administrators only.</p>
    </NotAuthorized>
</AuthorizeView>

@code {
    private string adminData;

    protected override async Task OnInitializedAsync()
    {
        try
        {
            adminData = await Http.GetStringAsync("/api/admin/data");
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            adminData = "Access denied";
        }
    }
}
```

**Detection regex:** `Http\.\w+Async\s*\(\s*"[^"]*(?:admin|secret|internal|private|manage)[^"]*"\s*\)[\s\S]{0,500}(?<!\[Authorize)`
**Severity:** error

The `[Authorize]` attribute in Blazor WASM only controls UI rendering. An attacker can bypass it by calling the API endpoint directly with any HTTP client. All security-sensitive operations must be authorized on the server.

### [Authorize] Attribute Bypass via Render Mode

```csharp
// VULNERABLE: Component with [Authorize] rendered in static SSR mode
// In .NET 8+ with per-component render modes, static SSR components
// do NOT have access to authentication state by default.

// Pages/Secure.razor
@page "/secure"
@attribute [Authorize]
@rendermode InteractiveServer   // OK — has circuit for auth state

// But if accidentally set to static:
@page "/secure"
@attribute [Authorize]
// No @rendermode — defaults to static SSR, auth attribute may not enforce

// VULNERABLE: Mixing render modes causes auth gaps
// App.razor
<Routes @rendermode="InteractiveServer" />
// But individual pages override:
@page "/admin"
@attribute [Authorize]
@rendermode @(new InteractiveWebAssemblyRenderMode(prerender: true))
// During prerender, auth state may not be available

// SECURE: Ensure authentication middleware covers all render modes
// Program.cs
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode()
   .AddInteractiveWebAssemblyRenderMode();

// SECURE: Use cascading authentication state
// App.razor
<CascadingAuthenticationState>
    <Router AppAssembly="typeof(App).Assembly">
        <Found Context="routeData">
            <AuthorizeRouteView RouteData="routeData"
                                DefaultLayout="typeof(MainLayout)">
                <NotAuthorized>
                    <RedirectToLogin />
                </NotAuthorized>
            </AuthorizeRouteView>
        </Found>
    </Router>
</CascadingAuthenticationState>
```

**Detection regex:** `\[Authorize\][\s\S]{0,200}@rendermode\s+@?\(?new\s+Interactive\w*RenderMode\s*\(\s*prerender\s*:\s*true\s*\)`
**Severity:** warning

## Injection

### JavaScript Interop Injection

```csharp
// VULNERABLE: Passing unsanitized user input to JS interop
@inject IJSRuntime JS

<input @bind="userInput" />
<button @onclick="Execute">Run</button>

@code {
    private string userInput = "";

    private async Task Execute()
    {
        // Attacker enters: "); alert(document.cookie); //
        await JS.InvokeVoidAsync("eval", userInput);
    }
}

// VULNERABLE: Building JS dynamically with user input
@code {
    private async Task ShowMessage(string message)
    {
        // XSS if message contains: </script><script>alert(1)</script>
        await JS.InvokeVoidAsync("eval", $"alert('{message}')");
    }
}

// VULNERABLE: Invoking a JS function that uses innerHTML
// wwwroot/js/app.js:
// window.renderHtml = (elementId, html) => {
//     document.getElementById(elementId).innerHTML = html;  // XSS sink
// };

@code {
    private async Task RenderComment(string commentHtml)
    {
        await JS.InvokeVoidAsync("renderHtml", "comment-box", commentHtml);
    }
}

// SECURE: Use parameterized JS calls with safe functions
@code {
    private async Task ShowMessage(string message)
    {
        // Pass data as parameter, use safe JS function
        await JS.InvokeVoidAsync("showNotification", message);
    }
}

// wwwroot/js/app.js:
// window.showNotification = (message) => {
//     const el = document.getElementById("notification");
//     el.textContent = message;  // textContent is safe — no HTML parsing
// };

// SECURE: Validate and sanitize before interop
@code {
    private static readonly Regex SafePattern = new(@"^[\w\s.,!?-]+$");

    private async Task ShowMessage(string message)
    {
        if (!SafePattern.IsMatch(message))
        {
            return;  // Reject suspicious input
        }
        await JS.InvokeVoidAsync("showNotification", message);
    }
}
```

**Detection regex:** `InvokeVoidAsync\s*\(\s*"eval"|InvokeAsync\s*\(\s*"eval"|InvokeVoidAsync\s*\(\s*"[^"]*"\s*,\s*\$"|InvokeVoidAsync\s*\([^)]*innerHTML`
**Severity:** error

## Data Exposure

### Server-Side Blazor State Management

```csharp
// VULNERABLE: Storing sensitive data in component state (Blazor Server)
// In Blazor Server, component state lives on the server in a circuit.
// However, state can leak through prerendering, error messages, or
// reconnection scenarios.

@page "/account"
@attribute [Authorize]

@code {
    // VULNERABLE: Full credit card stored in component state
    private string creditCardNumber = "";
    private string cvv = "";

    // State persisted across reconnections — if circuit is hijacked,
    // attacker gets access to all component state
    protected override async Task OnInitializedAsync()
    {
        var user = await UserService.GetCurrentUser();
        creditCardNumber = user.CreditCard;  // Full CC in memory
        cvv = user.Cvv;                      // CVV in memory
    }
}

// VULNERABLE: Storing long-lived or high-value secrets in browser-side
// Protected*Storage. ProtectedSessionStorage / ProtectedLocalStorage DO
// encrypt the stored ciphertext using the server-side Data Protection
// API (keys live on the server, not in the page), so the stored value
// is opaque to the user and to browser extensions.
// BUT: the ciphertext is still round-tripped through the browser, so
// persistence lifetime, cross-tab visibility, and the user's ability
// to capture the encrypted blob all become part of the threat model.
// Treat it like a signed cookie — fine for short-lived UI state, not
// a substitute for a server-side session store for API tokens.
@inject ProtectedSessionStorage SessionStorage

@code {
    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            await SessionStorage.SetAsync("apiToken", apiToken);
        }
    }
}

// SECURE: Minimize sensitive data in component state
@page "/account"
@attribute [Authorize]

@code {
    private string maskedCardNumber = "";
    // Only store masked version
    protected override async Task OnInitializedAsync()
    {
        var user = await UserService.GetCurrentUser();
        maskedCardNumber = "****-****-****-" + user.CreditCard[^4..];
        // Never store CVV in component state
    }
}

// SECURE: Use server-side session for sensitive operations
@code {
    private async Task ProcessPayment()
    {
        // Sensitive data stays on server, never in component state
        var result = await PaymentService.ChargeCurrentUser(amount);
    }
}
```

**Detection regex:** `(?:private|protected|public)\s+string\s+(?:creditCard|cvv|ssn|password|secret|token|apiKey)\s*=|SessionStorage\.SetAsync\s*\(\s*"(?:token|secret|password|apiKey|creditCard)`
**Severity:** warning

### Component Lifecycle Data Exposure

```csharp
// VULNERABLE: OnInitializedAsync fetches data that leaks via prerendering
@page "/dashboard"
@attribute [Authorize]

@code {
    private List<SensitiveRecord> records;

    // During prerendering, this runs on the server and embeds data
    // into the initial HTML response — visible in page source
    protected override async Task OnInitializedAsync()
    {
        records = await SensitiveDataService.GetRecords();
        // If prerendering is enabled, this data is serialized into
        // the __blazor-ssr state and visible to anyone viewing source
    }
}

// SECURE: Defer sensitive data loading to OnAfterRenderAsync
@page "/dashboard"
@attribute [Authorize]

@code {
    private List<SensitiveRecord>? records;
    private bool isLoading = true;

    // OnAfterRenderAsync does NOT run during prerendering
    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            records = await SensitiveDataService.GetRecords();
            isLoading = false;
            StateHasChanged();
        }
    }
}

// ALTERNATIVE: Disable prerendering for sensitive pages
@page "/dashboard"
@attribute [Authorize]
@rendermode @(new InteractiveServerRenderMode(prerender: false))

@code {
    private List<SensitiveRecord> records;

    protected override async Task OnInitializedAsync()
    {
        records = await SensitiveDataService.GetRecords();
    }
}
```

**Detection regex:** `OnInitializedAsync[\s\S]{0,300}(?:Sensitive|Secret|Private|Confidential|GetRecords|GetCredentials|GetTokens)`
**Severity:** warning

### Render Mode Security Implications

```csharp
// UNDERSTANDING RENDER MODES AND SECURITY:
//
// Static SSR: Server renders HTML, sends to client. No interactivity.
//   Security: Auth state may not be enforced without middleware.
//
// Interactive Server (Blazor Server): UI updates via SignalR circuit.
//   Security: State lives on server. Circuit can be hijacked if SignalR
//   connection is compromised. DoS via many open circuits.
//
// Interactive WebAssembly (Blazor WASM): Runs in browser.
//   Security: ALL client code is visible. Auth is UX only.
//   API must enforce all security. Assembly can be decompiled.
//
// Interactive Auto: Server first, then WASM after download.
//   Security: Combines both threat models. Must protect against both.

// VULNERABLE: Security-critical logic in a WASM component
// Shared/AdminPanel.razor
@rendermode InteractiveWebAssembly

@code {
    // This code runs in the browser — attacker can modify it
    private bool IsAuthorized()
    {
        // Client-side only check — trivially bypassed
        return currentUser.Role == "Admin";
    }

    private async Task DeleteAllUsers()
    {
        if (IsAuthorized())
        {
            await Http.DeleteAsync("/api/users/all");
        }
    }
}

// SECURE: Server-enforced authorization with appropriate render mode
@rendermode InteractiveServer  // Runs on server — code not exposed

@code {
    [Inject] private AuthenticationStateProvider AuthProvider { get; set; }

    private async Task DeleteAllUsers()
    {
        var authState = await AuthProvider.GetAuthenticationStateAsync();
        if (!authState.User.IsInRole("Admin"))
        {
            throw new UnauthorizedAccessException();
        }
        await UserService.DeleteAllUsers();  // Server-side service call
    }
}
```

**Detection regex:** `@rendermode\s+Interactive(?:WebAssembly|Auto)[\s\S]{0,500}(?:Delete|Remove|Admin|Manage|Transfer|Approve)`
**Severity:** warning

## Detection Patterns for Blazor

```csharp
// Grep patterns for Blazor security issues:
string[] blazorPatterns = {
    @"InvokeVoidAsync\s*\(\s*""eval""",            // JS interop eval
    @"Http\.\w+Async.*admin.*(?<!\[Authorize)",     // Unprotected API call
    @"@rendermode\s+InteractiveWebAssembly",        // WASM — verify server auth
    @"(MarkupString)\s*\w+",                        // Raw HTML rendering
    @"ProtectedSessionStorage.*token|secret",       // Sensitive data in storage
    @"creditCard|cvv|ssn.*=\s*""",                  // Sensitive data in state
    @"OnInitializedAsync.*Sensitive",               // Data leak via prerender
    @"\[Authorize\].*prerender:\s*true",            // Auth with prerender
    @"innerHTML",                                    // DOM XSS via interop
};
```

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| Client-side auth bypass (SA-BLAZOR-01) | Critical | Immediate | Medium |
| JS interop injection (SA-BLAZOR-03) | Critical | Immediate | Medium |
| Sensitive state exposure (SA-BLAZOR-02) | High | 1 week | Medium |
| [Authorize] with prerender (SA-BLAZOR-04) | High | 1 week | Low |
| Lifecycle data exposure (SA-BLAZOR-05) | Medium | 1 month | Low |
| Render mode implications (SA-BLAZOR-06) | Medium | 1 month | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `dotnet-security.md` — ASP.NET Core patterns (middleware, EF, Razor)
- `spring-security.md` — Comparison with Spring Security patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 — framework security references |
