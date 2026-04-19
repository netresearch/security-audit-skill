# Angular Security Patterns

Security patterns, common misconfigurations, and detection regexes for Angular applications (Angular 2+). This reference covers XSS through sanitization bypasses, injection risks, authentication/authorization pitfalls, and framework-specific misconfigurations in the Angular ecosystem.

---

## Cross-Site Scripting (XSS)

### SA-ANG-01 — `bypassSecurityTrust*` Misuse

Angular's `DomSanitizer` provides `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustUrl`, and `bypassSecurityTrustResourceUrl` methods. These explicitly disable Angular's built-in sanitization. When used with user-controlled input, they create direct XSS vulnerabilities.

```typescript
// VULNERABLE: Bypassing sanitizer with user input
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="trustedComment"></div>`
})
export class CommentComponent {
  trustedComment: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {}

  displayComment(userInput: string) {
    // DANGEROUS: user input bypasses all sanitization
    this.trustedComment = this.sanitizer.bypassSecurityTrustHtml(userInput);
  }
}
```

```typescript
// SECURE: Use Angular's built-in sanitization or a sanitize library
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import DOMPurify from 'dompurify';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="sanitizedComment"></div>`
})
export class CommentComponent {
  sanitizedComment: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {}

  displayComment(userInput: string) {
    // Option 1: Let Angular's built-in sanitizer handle it
    this.sanitizedComment = userInput; // Angular sanitizes by default

    // Option 2: Pre-sanitize with DOMPurify for stricter control
    const clean = DOMPurify.sanitize(userInput);
    this.sanitizedComment = this.sanitizer.bypassSecurityTrustHtml(clean);
  }
}
```

**Detection regex:** `bypassSecurityTrust(Html|Script|Url|ResourceUrl)\s*\(`
**Severity:** error

**Why it matters:** Angular automatically sanitizes values bound to properties like `innerHTML`, `href`, and `src`. The `bypassSecurityTrust*` methods explicitly opt out of this protection. Every usage must be audited to ensure only server-controlled or pre-sanitized content is passed through.

---

### SA-ANG-02 — Dynamic Template Compilation / Template Injection

Dynamically compiling Angular templates at runtime with user-controlled content allows template injection. Angular's template syntax includes powerful expressions that can access component properties and methods.

```typescript
// VULNERABLE: Dynamic template compilation with user input
import { Compiler, Component, NgModule, ViewContainerRef } from '@angular/core';

@Component({
  selector: 'app-dynamic',
  template: `<ng-container #container></ng-container>`
})
export class DynamicComponent {
  constructor(
    private compiler: Compiler,
    private vcr: ViewContainerRef
  ) {}

  renderUserTemplate(userTemplate: string) {
    // Attacker injects: {{constructor.constructor('alert(1)')()}}
    const tmpComponent = Component({ template: userTemplate })(class {});
    const tmpModule = NgModule({ declarations: [tmpComponent] })(class {});
    this.compiler.compileModuleAndAllComponentsAsync(tmpModule)
      .then(factories => {
        const factory = factories.componentFactories[0];
        this.vcr.createComponent(factory);
      });
  }
}
```

```typescript
// SECURE: Use predefined templates with data binding, not dynamic compilation
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-safe-render',
  template: `
    <div class="user-content">
      <h3>{{ title }}</h3>
      <p>{{ content }}</p>
    </div>
  `
})
export class SafeRenderComponent {
  @Input() title: string = '';
  @Input() content: string = '';
}
```

**Detection regex:** `compiler\.compileModuleAndAllComponentsAsync|Component\(\s*\{\s*template\s*:`
**Severity:** error

**Why it matters:** Angular's Ahead-of-Time (AOT) compilation is a security feature — it pre-compiles templates at build time, preventing runtime template injection. JIT compilation with user-controlled templates bypasses this protection entirely, granting attackers full access to the component context.

---

### SA-ANG-03 — `DomSanitizer` Bypass Patterns

Developers sometimes create custom pipes or utility functions that systematically bypass Angular's sanitizer, effectively disabling security for entire categories of bindings across the application.

```typescript
// VULNERABLE: Pipe that globally bypasses sanitization
import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({ name: 'safeHtml' })
export class SafeHtmlPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(value: string): SafeHtml {
    // Every usage of this pipe bypasses sanitization
    return this.sanitizer.bypassSecurityTrustHtml(value);
  }
}

// Usage in template — looks innocuous but is dangerous
// <div [innerHTML]="userComment | safeHtml"></div>
```

```typescript
// SECURE: Pipe that sanitizes using DOMPurify instead of bypassing
import { Pipe, PipeTransform } from '@angular/core';
import DOMPurify from 'dompurify';

@Pipe({ name: 'sanitizeHtml' })
export class SanitizeHtmlPipe implements PipeTransform {
  transform(value: string): string {
    // Sanitize the content — Angular will also apply its own sanitization
    return DOMPurify.sanitize(value, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href', 'title']
    });
  }
}
```

**Detection regex:** `@Pipe[\s\S]*?bypassSecurityTrust`
**Severity:** error

**Why it matters:** A bypass pipe is a force multiplier for XSS — a single pipe definition creates a reusable sanitization bypass used across many templates. Developers treat pipes as safe transformations, so the danger is hidden behind a clean API. Auditing `bypassSecurityTrust` calls in pipes is critical.

---

### SA-ANG-04 — `innerHTML` Binding with User Input

While Angular sanitizes `[innerHTML]` bindings by default, relying on this alone is insufficient for complex HTML content. Additionally, when combined with `bypassSecurityTrust*`, the sanitization is removed.

```typescript
// VULNERABLE: innerHTML binding with data from untrusted source
@Component({
  selector: 'app-post',
  template: `
    <article>
      <h2>{{ post.title }}</h2>
      <div [innerHTML]="post.htmlContent"></div>
    </article>
  `
})
export class PostComponent {
  post = {
    title: '',
    // HTML content from external CMS or user input
    // Angular sanitizes this, but complex payloads may slip through
    htmlContent: ''
  };

  loadPost(data: any) {
    // Directly assigning unsanitized external HTML
    this.post.htmlContent = data.body;
  }
}
```

```typescript
// SECURE: Pre-sanitize HTML content before binding
import DOMPurify from 'dompurify';

@Component({
  selector: 'app-post',
  template: `
    <article>
      <h2>{{ post.title }}</h2>
      <div [innerHTML]="post.htmlContent"></div>
    </article>
  `
})
export class PostComponent {
  post = { title: '', htmlContent: '' };

  loadPost(data: any) {
    this.post.title = data.title;
    // Pre-sanitize with strict allowlist
    this.post.htmlContent = DOMPurify.sanitize(data.body, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a'],
      ALLOWED_ATTR: ['href']
    });
  }
}
```

**Detection regex:** `\[innerHTML\]\s*=`
**Severity:** warning

**Why it matters:** Angular's built-in sanitizer handles many XSS vectors, but it is not a complete defense. Complex or novel payloads, sanitizer bugs, or the use of `bypassSecurityTrust*` in the data pipeline can bypass it. Defense-in-depth requires pre-sanitizing HTML content before it reaches the template.

---

## Injection

### SA-ANG-05 — Route Guard Bypass (Client-Side Only Authorization)

Angular route guards (`CanActivate`, `CanLoad`, `CanActivateChild`) execute entirely in the browser. They are a UX mechanism, not a security boundary. Any authorization enforced only via route guards can be bypassed.

```typescript
// VULNERABLE: Authorization enforced only client-side
import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  constructor(private router: Router) {}

  canActivate(): boolean {
    // This runs in the browser — trivially bypassed
    const role = localStorage.getItem('userRole');
    if (role === 'admin') {
      return true;
    }
    this.router.navigate(['/unauthorized']);
    return false;
  }
}

// Route config
const routes = [
  { path: 'admin', component: AdminComponent, canActivate: [AdminGuard] }
];
```

```typescript
// SECURE: Server-side authorization + client guard as UX convenience
@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  async canActivate(): Promise<boolean> {
    try {
      // Verify with the server — but this is still just UX
      await this.authService.verifyAdminAccess();
      return true;
    } catch {
      this.router.navigate(['/unauthorized']);
      return false;
    }
  }
}

// SERVER-SIDE: The real security boundary
// Express middleware example
app.use('/api/admin/*', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Insufficient privileges' });
  }
  next();
});
```

**Detection regex:** `canActivate|CanActivate|canLoad|CanLoad`
**Severity:** warning

**Why it matters:** Client-side route guards protect the UI, not the data. An attacker can modify `localStorage`, use browser devtools to override the guard return value, or call backend APIs directly. Every route guard must have a corresponding server-side authorization check.

---

### SA-ANG-06 — HTTP Interceptor Misconfiguration

Angular HTTP interceptors are the standard mechanism for attaching auth tokens, CSRF tokens, and security headers to outgoing requests. Misconfigured interceptors can leak credentials to third-party domains or fail to attach tokens at all.

```typescript
// VULNERABLE: Interceptor sends auth token to ALL domains
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler } from '@angular/common/http';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler) {
    const token = localStorage.getItem('auth_token');
    // Sends token to every HTTP request, including third-party APIs
    const authReq = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` }
    });
    return next.handle(authReq);
  }
}
```

```typescript
// SECURE: Only attach tokens to same-origin or allowlisted API domains
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler } from '@angular/common/http';
import { environment } from '../environments/environment';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private allowedOrigins = [
    environment.apiUrl,
    'https://api.trusted-service.com'
  ];

  intercept(req: HttpRequest<any>, next: HttpHandler) {
    const isAllowed = this.allowedOrigins.some(origin =>
      req.url.startsWith(origin)
    );

    if (isAllowed) {
      const token = localStorage.getItem('auth_token');
      if (token) {
        const authReq = req.clone({
          setHeaders: { Authorization: `Bearer ${token}` }
        });
        return next.handle(authReq);
      }
    }

    return next.handle(req);
  }
}
```

**Detection regex:** `HttpInterceptor[\s\S]*?intercept\s*\(`
**Severity:** warning

**Why it matters:** HTTP interceptors operate globally on all `HttpClient` requests. A misconfigured interceptor that does not check the request URL before attaching credentials will leak tokens to third-party analytics, CDNs, and other external services. This is a common SSRF and credential leak vector.

---

### SA-ANG-07 — `eval` in Expressions and Services

Using `eval()`, `new Function()`, or `setTimeout`/`setInterval` with string arguments in Angular services or components allows arbitrary code execution if user input reaches these functions.

```typescript
// VULNERABLE: eval in an Angular service
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class FormulaService {
  calculate(userFormula: string): number {
    // Direct code injection via eval
    return eval(userFormula);
  }
}

@Component({
  selector: 'app-calculator',
  template: `<input [(ngModel)]="formula" (change)="compute()">`
})
export class CalculatorComponent {
  formula = '';
  result = 0;

  constructor(private formulaService: FormulaService) {}

  compute() {
    // User input flows directly to eval
    this.result = this.formulaService.calculate(this.formula);
  }
}
```

```typescript
// SECURE: Use a safe expression evaluator
import { Injectable } from '@angular/core';
import { evaluate } from 'mathjs';

@Injectable({ providedIn: 'root' })
export class FormulaService {
  calculate(userFormula: string): number {
    try {
      return evaluate(userFormula);
    } catch {
      return NaN;
    }
  }
}
```

**Detection regex:** `eval\s*\([^)]*\)|new\s+Function\s*\(`
**Severity:** error

**Why it matters:** Angular's template expressions are sandboxed and do not allow arbitrary JS. However, `eval()` in TypeScript services and components bypasses this sandbox entirely. Dependency injection makes it easy for user input to flow through services to `eval()` calls.

---

## Data Exposure & Misconfiguration

### SA-ANG-08 — Zone.js Context Leaks

Zone.js patches all async operations in Angular. Long-running or improperly scoped zones can retain references to sensitive data, preventing garbage collection and creating memory-resident secrets.

```typescript
// VULNERABLE: Sensitive data persisting in Zone context
import { Component, NgZone } from '@angular/core';

@Component({
  selector: 'app-payment',
  template: `<button (click)="processPayment()">Pay</button>`
})
export class PaymentComponent {
  constructor(private ngZone: NgZone) {}

  processPayment() {
    const creditCard = this.getCreditCardInput();
    // Zone.js wraps this — creditCard stays in zone context
    this.ngZone.run(() => {
      this.apiService.charge(creditCard).subscribe(result => {
        // creditCard still referenced in zone's task data
        this.showReceipt(result);
      });
    });
  }
}
```

```typescript
// SECURE: Run sensitive operations outside Angular zone, clear references
import { Component, NgZone } from '@angular/core';

@Component({
  selector: 'app-payment',
  template: `<button (click)="processPayment()">Pay</button>`
})
export class PaymentComponent {
  constructor(private ngZone: NgZone) {}

  processPayment() {
    let creditCard = this.getCreditCardInput();

    // Run outside zone to minimize context retention
    this.ngZone.runOutsideAngular(() => {
      this.apiService.charge(creditCard).subscribe(result => {
        // Explicitly clear the sensitive reference
        creditCard = null;

        // Re-enter zone only for UI update
        this.ngZone.run(() => {
          this.showReceipt(result);
        });
      });
    });
  }
}
```

**Detection regex:** `ngZone\.run\s*\([\s\S]*?(password|token|secret|creditCard|ssn|apiKey)`
**Severity:** warning

**Why it matters:** Zone.js maintains a task queue that retains references to closures and their captured variables. Sensitive data captured in these closures persists longer than expected, surviving in memory where it can be extracted via heap dumps or memory inspection tools.

---

### SA-ANG-09 — Missing CSRF Token in HttpClient

Angular's `HttpClient` does not automatically include CSRF tokens. If the backend expects a CSRF token (common with cookie-based auth), failing to configure the `HttpClientXsrfModule` leaves the application vulnerable to cross-site request forgery.

```typescript
// VULNERABLE: HttpClient without CSRF token configuration
import { NgModule } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';

@NgModule({
  imports: [
    HttpClientModule  // No XSRF configuration
  ]
})
export class AppModule {}
```

```typescript
// SECURE: Configure XSRF token handling
import { NgModule } from '@angular/core';
import { HttpClientModule, HttpClientXsrfModule } from '@angular/common/http';

@NgModule({
  imports: [
    HttpClientModule,
    HttpClientXsrfModule.withOptions({
      cookieName: 'XSRF-TOKEN',   // Cookie name set by backend
      headerName: 'X-XSRF-TOKEN'  // Header name expected by backend
    })
  ]
})
export class AppModule {}

// For standalone components (Angular 16+):
import { provideHttpClient, withXsrfConfiguration } from '@angular/common/http';

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    )
  ]
});
```

**Detection regex:** `HttpClientModule[^]*?(?!HttpClientXsrfModule)|provideHttpClient\s*\([^)]*(?!withXsrfConfiguration)`
**Severity:** warning

**Why it matters:** Cookie-based authentication is inherently vulnerable to CSRF. Angular provides `HttpClientXsrfModule` to read CSRF tokens from cookies and attach them as headers, but it must be explicitly configured. Without it, state-changing requests can be forged from attacker-controlled pages.

---

### SA-ANG-10 — Insecure Direct Object Reference in Angular Services

Angular services that construct API URLs using user-supplied IDs without server-side authorization checks enable IDOR vulnerabilities.

```typescript
// VULNERABLE: Direct object reference without server-side authorization
@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getUserProfile(userId: string) {
    // Any user can fetch any profile by changing the ID
    return this.http.get(`/api/users/${userId}/profile`);
  }

  deleteUser(userId: string) {
    // No authorization check — relies on client-side role
    return this.http.delete(`/api/users/${userId}`);
  }
}
```

```typescript
// SECURE: Server-side authorization; use session-based identity for sensitive ops
@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getMyProfile() {
    // Server derives user ID from authenticated session
    return this.http.get('/api/users/me/profile');
  }

  getUserProfile(userId: string) {
    // Server must verify caller has permission to view this profile
    return this.http.get(`/api/users/${userId}/profile`);
    // Backend enforces: only self, admin, or explicit share
  }
}
```

**Detection regex:** `this\.http\.(get|post|put|delete|patch)\s*\(\s*[\`'"].*\$\{`
**Severity:** warning

**Why it matters:** Angular services make it easy to parameterize API calls, but the security boundary must be on the server. Client-side Angular code cannot enforce object-level authorization. Every endpoint that takes a user-supplied ID must validate that the authenticated user is authorized to access that resource.

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-ANG-01 — `bypassSecurityTrust*` misuse | Critical | Immediate | Medium |
| SA-ANG-02 — Dynamic template compilation | Critical | Immediate | High |
| SA-ANG-03 — `DomSanitizer` bypass pipe | Critical | Immediate | Low |
| SA-ANG-04 — `innerHTML` binding | High | 1 week | Low |
| SA-ANG-05 — Route guard bypass | High | 1 week | Medium |
| SA-ANG-06 — Interceptor misconfiguration | High | 1 week | Low |
| SA-ANG-07 — `eval` in services | Critical | Immediate | Medium |
| SA-ANG-08 — Zone.js context leaks | Medium | 1 month | Medium |
| SA-ANG-09 — Missing CSRF token | High | 1 week | Low |
| SA-ANG-10 — IDOR in Angular services | High | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `javascript-typescript-security-features.md` — Language-level JS/TS patterns
- `frontend-security.md` — General frontend security patterns
- `security-headers.md` — CSP and security header configuration

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 8 |
