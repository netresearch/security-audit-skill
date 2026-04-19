# JavaScript/TypeScript Security Features and Vulnerability Patterns

Modern JavaScript (ES5 through ES2024) and TypeScript introduce features that directly improve security when used correctly, but also present unique attack surfaces. This reference documents security-relevant patterns, organized by ES version where applicable, covering prototype pollution, injection vectors, type-safety pitfalls, and more.

## Core JavaScript Security (ES5-ES2020+)

### 1. Prototype Pollution (`__proto__`, `Object.assign` deep merge)

Prototype pollution occurs when an attacker injects properties into `Object.prototype`, affecting all objects in the application. This is especially dangerous in deep-merge utilities and query-string parsers.

```javascript
// VULNERABLE: Recursive merge without prototype check
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker-controlled input:
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
deepMerge({}, malicious);

// Now every object inherits isAdmin:
const user = {};
console.log(user.isAdmin); // true — privilege escalation!

// SECURE: Guard against prototype keys
function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Skip dangerous keys
    }
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = Object.create(null);
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Alternative: Use Object.create(null) for lookup objects
const safeMap = Object.create(null);
// safeMap has no prototype chain, immune to pollution
```

**Security implication:** Prototype pollution can lead to privilege escalation, authentication bypass, and remote code execution (CWE-1321). Any code path that merges user-controlled objects into application state is at risk. Libraries like `lodash.merge` (pre-4.17.12) and `qs` were historically vulnerable.

### 2. Unsafe `eval()` / `Function()` Constructor / `setTimeout(string)`

These APIs compile and execute arbitrary strings as code. If user input reaches them, it is equivalent to remote code execution.

```javascript
// VULNERABLE: eval with user-controlled input
const userExpr = getQueryParam('expr');
const result = eval(userExpr); // RCE if userExpr = "process.exit(1)"

// VULNERABLE: Function constructor (equivalent to eval)
const fn = new Function('x', userInput);
fn(42);

// VULNERABLE: setTimeout/setInterval with string argument
const callback = getUserPreference('action');
setTimeout(callback, 1000); // Executes string as code

// SECURE: Use safe parsing for expressions
const data = JSON.parse(userInput); // Only parses JSON, no code execution

// SECURE: Use function references instead of strings
const actions = {
  greet: () => console.log('Hello'),
  farewell: () => console.log('Goodbye'),
};
const actionName = getUserPreference('action');
if (actions[actionName]) {
  setTimeout(actions[actionName], 1000);
}

// SECURE: Use a sandboxed expression evaluator for math
import { evaluate } from 'mathjs';
const result = evaluate(userExpr); // Only evaluates math, not arbitrary code
```

**Security implication:** `eval()` and equivalents enable arbitrary code execution (CWE-94, CWE-95). In server-side JavaScript (Node.js), this leads to full system compromise. In the browser, it enables XSS. The `Function` constructor and string-form `setTimeout`/`setInterval` are often overlooked eval equivalents.

### 3. DOM XSS Sources/Sinks (`innerHTML`, `outerHTML`, `document.write`, `location.href`)

DOM-based XSS occurs when user-controlled data flows from a source (URL, `postMessage`, storage) to a sink that interprets HTML or JavaScript.

```javascript
// VULNERABLE: innerHTML with user input
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;
// If name = "<img src=x onerror=alert(1)>", XSS is triggered

// VULNERABLE: document.write with user data
document.write('<div>' + location.hash.slice(1) + '</div>');

// VULNERABLE: outerHTML with user input
element.outerHTML = '<span>' + userInput + '</span>';

// VULNERABLE: location.href as JavaScript URI sink
window.location.href = userInput;
// If userInput = "javascript:alert(1)", code executes

// SECURE: Use textContent for text-only output
document.getElementById('greeting').textContent = 'Hello, ' + name;

// SECURE: Use DOM APIs to create elements
const div = document.createElement('div');
div.textContent = userInput;
document.body.appendChild(div);

// SECURE: Validate URL schemes before navigation
function safeNavigate(url) {
  const parsed = new URL(url, window.location.origin);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Invalid URL scheme');
  }
  window.location.href = parsed.href;
}

// SECURE: Use DOMPurify for cases where HTML rendering is required
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userHtml);
```

**Security implication:** DOM XSS (CWE-79) bypasses server-side sanitization because the payload never reaches the server. The `innerHTML`, `outerHTML`, and `document.write` sinks interpret HTML markup, while `location.href` can execute `javascript:` URIs. Always use `textContent` for text output.

### 4. `postMessage` Origin Validation

The `postMessage` API enables cross-origin communication. Without origin validation, any page can send messages to your application.

```javascript
// VULNERABLE: No origin check on message handler
window.addEventListener('message', (event) => {
  // Any origin can send this message!
  const config = JSON.parse(event.data);
  updateAppConfig(config); // Attacker-controlled configuration
});

// VULNERABLE: Wildcard target origin
parentWindow.postMessage(sensitiveData, '*');
// Any page that embeds this iframe receives the data

// SECURE: Validate origin strictly
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted-app.example.com') {
    return; // Reject messages from untrusted origins
  }
  const config = JSON.parse(event.data);
  updateAppConfig(config);
});

// SECURE: Specify exact target origin
parentWindow.postMessage(sensitiveData, 'https://parent-app.example.com');
```

**Security implication:** Missing `postMessage` origin validation (CWE-346) allows attackers to inject data or exfiltrate information via cross-origin frames. Always validate `event.origin` on the receiver and specify a target origin on the sender.

### 5. Regular Expression Denial of Service (ReDoS)

Certain regex patterns exhibit catastrophic backtracking when matched against crafted input, causing the JavaScript event loop to freeze.

```javascript
// VULNERABLE: Catastrophic backtracking pattern
const emailRegex = /^([a-zA-Z0-9]+)+@example\.com$/;
// Input "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential backtracking

// VULNERABLE: Nested quantifiers
const pathRegex = /^(\/[a-z]+)*$/;
// Input "/a/a/a/a/a/a/a/a/a/a/a/a!" triggers ReDoS

// SECURE: Use atomic-style patterns (no nested quantifiers)
const safeEmailRegex = /^[a-zA-Z0-9]+@example\.com$/;

// SECURE: Use the 're2' library for guaranteed linear-time matching
import RE2 from 're2';
const safeRegex = new RE2('^([a-zA-Z0-9]+)+@example\\.com$');

// SECURE: Enforce input length limits before regex matching
function validateEmail(input) {
  if (input.length > 254) {
    return false; // RFC 5321 maximum email length
  }
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(input);
}
```

**Security implication:** ReDoS (CWE-1333) can cause complete denial of service in single-threaded Node.js applications. Nested quantifiers like `(a+)+`, `(a|a)*`, and `(a+)*` are the primary culprits. Limit input length and avoid nested repetition.

### 6. Insecure Deserialization (`JSON.parse` with Reviver Pitfalls, `serialize-javascript`)

While `JSON.parse` is generally safe, certain patterns around deserialization introduce vulnerabilities.

```javascript
// VULNERABLE: serialize-javascript with user input can execute code
const serialize = require('serialize-javascript');
// serialize-javascript outputs executable JS, not JSON
const serialized = serialize({ fn: function() { return 1; } });
// Output: {"fn":function() { return 1; }}
// If this string is eval'd on the client, arbitrary code runs

// VULNERABLE: JSON.parse reviver that constructs objects unsafely
const data = JSON.parse(untrustedInput, (key, value) => {
  if (value && value.__type === 'Date') {
    return new Date(value.timestamp); // Controlled object construction
  }
  if (value && value.__type === 'RegExp') {
    return new RegExp(value.source, value.flags); // ReDoS via deserialization!
  }
  return value;
});

// SECURE: Use JSON.parse without reviver for untrusted input
const safeData = JSON.parse(untrustedInput);
// JSON.parse alone cannot execute code

// SECURE: Validate reviver output strictly
const safeData2 = JSON.parse(untrustedInput, (key, value) => {
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    const date = new Date(value);
    if (isNaN(date.getTime())) return value; // Invalid date, keep as string
    return date;
  }
  return value;
});

// SECURE: Use superjson or devalue for structured serialization
import superjson from 'superjson';
const parsed = superjson.parse(trustedData); // Type-safe deserialization
```

**Security implication:** The `serialize-javascript` library outputs executable JavaScript, not JSON (CWE-502). If its output is ever evaluated, it enables code injection. Reviver functions in `JSON.parse` can be exploited if they reconstruct executable objects like `RegExp` or call constructors with attacker-controlled arguments.

### 7. Dynamic `import()` and Module Injection

Dynamic `import()` loads modules at runtime. If the module specifier comes from user input, attackers can load arbitrary code.

```javascript
// VULNERABLE: Dynamic import with user-controlled path
const moduleName = req.query.plugin;
const plugin = await import(moduleName);
// Attacker sets moduleName to a malicious npm package or file path

// VULNERABLE: Template literal with user input in import
const component = await import(`./components/${userInput}`);
// Path traversal: userInput = "../../etc/passwd" or "../secrets/keys"

// SECURE: Allowlist of permitted modules
const ALLOWED_PLUGINS = new Set(['markdown', 'csv', 'json']);
const moduleName = req.query.plugin;
if (!ALLOWED_PLUGINS.has(moduleName)) {
  throw new Error('Invalid plugin');
}
const plugin = await import(`./plugins/${moduleName}.js`);

// SECURE: Use a Map for static resolution
const pluginMap = {
  markdown: () => import('./plugins/markdown.js'),
  csv: () => import('./plugins/csv.js'),
};
const loader = pluginMap[req.query.plugin];
if (!loader) throw new Error('Unknown plugin');
const plugin = await loader();
```

**Security implication:** Uncontrolled dynamic `import()` (CWE-94) enables loading attacker-specified modules, potentially executing arbitrary code. In Node.js, this can load any file on the filesystem. Always use an allowlist for dynamic module resolution.

### 8. Template Literal Injection in Tagged Templates

Tagged template functions receive raw string parts and interpolated values. If the tag function processes strings unsafely, injection is possible.

```javascript
// VULNERABLE: Tagged template that builds HTML
function html(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return result + str + (values[i] || '');
  }, '');
}
const userInput = '<img src=x onerror=alert(1)>';
const output = html`<div>${userInput}</div>`;
// output contains unescaped HTML: XSS!

// VULNERABLE: Tagged template for SQL
function sql(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return result + str + (values[i] != null ? values[i] : '');
  }, '');
}
const query = sql`SELECT * FROM users WHERE name = '${userName}'`;
// SQL injection if userName contains quotes

// SECURE: Escape interpolated values in tagged templates
function safeHtml(strings, ...values) {
  return strings.reduce((result, str, i) => {
    const escaped = String(values[i] || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    return result + str + escaped;
  }, '');
}

// SECURE: Use parameterized queries
const result = await db.query('SELECT * FROM users WHERE name = $1', [userName]);
```

**Security implication:** Tagged templates that concatenate interpolated values without escaping are injection vectors (CWE-79, CWE-89). The tag function must sanitize all interpolated values appropriate to the output context (HTML, SQL, shell, etc.).

### 9. Weak Randomness (`Math.random()` for Security)

`Math.random()` uses a PRNG that is not cryptographically secure. Its output is predictable and must never be used for tokens, keys, or security-sensitive identifiers.

```javascript
// VULNERABLE: Math.random for session tokens
function generateToken() {
  return Math.random().toString(36).substring(2);
}
// Output is predictable; attacker can reproduce the sequence

// VULNERABLE: Math.random for CSRF tokens
const csrfToken = Math.random().toString(16).slice(2);

// SECURE: Use crypto.randomUUID() (Node.js 14.17+ / 16+ / modern browsers)
const token = crypto.randomUUID();

// SECURE: Use crypto.getRandomValues for byte arrays
const buffer = new Uint8Array(32);
crypto.getRandomValues(buffer);
const token2 = Array.from(buffer, b => b.toString(16).padStart(2, '0')).join('');

// SECURE: Use crypto.randomBytes in Node.js
import { randomBytes } from 'node:crypto';
const token3 = randomBytes(32).toString('hex');
```

**Security implication:** `Math.random()` (CWE-338) produces predictable values. Attackers can recover the internal state and predict future outputs. Use `crypto.getRandomValues()` (browser), `crypto.randomUUID()`, or `crypto.randomBytes()` (Node.js) for all security-sensitive random values.

### 10. `debugger` Statements in Production

The `debugger` statement halts execution when developer tools are open. In production, it can be used to analyze application logic and bypass client-side security controls.

```javascript
// VULNERABLE: debugger left in production code
function processPayment(card) {
  debugger; // Pauses execution, exposes variables in dev tools
  return chargeCard(card);
}

// VULNERABLE: Conditional debugger that reveals logic
function checkLicense(key) {
  if (key === 'master-key-2024') {
    debugger; // Reveals the hardcoded master key
    return true;
  }
  return validateKey(key);
}

// SECURE: Remove debugger statements before production
// Use ESLint rule: no-debugger
// .eslintrc.json: { "rules": { "no-debugger": "error" } }

// SECURE: Use conditional logging instead
function processPayment(card) {
  if (process.env.NODE_ENV === 'development') {
    console.log('Processing payment:', card.lastFour);
  }
  return chargeCard(card);
}
```

**Security implication:** `debugger` statements in production code (CWE-489) enable attackers to inspect runtime state, including sensitive variables, authentication tokens, and business logic. They should be removed by linting rules and build processes.

## ES2020+ Security Features

### 11. Optional Chaining (`?.`) Preventing Null-Dereference Crashes

Optional chaining short-circuits to `undefined` when a property access encounters `null` or `undefined`, preventing crashes that could expose error details.

```javascript
// VULNERABLE: Unguarded property access crashes the application
function getUserRole(session) {
  const role = session.user.profile.role;
  // TypeError if session.user is null — may expose stack trace
  return role;
}

// VULNERABLE: Manual null checks are error-prone and verbose
function getUserRole(session) {
  if (session && session.user && session.user.profile) {
    return session.user.profile.role;
  }
  return null;
  // Easy to miss a level, especially with refactoring
}

// SECURE: Optional chaining (ES2020)
function getUserRole(session) {
  return session?.user?.profile?.role ?? 'anonymous';
}

// SECURE: Optional chaining with method calls
const isAdmin = request.auth?.user?.hasRole?.('admin') ?? false;

// SECURE: Optional chaining with computed properties
const setting = config?.features?.[featureName]?.enabled ?? false;
```

**Security implication:** Unguarded property access causes `TypeError` exceptions that may expose stack traces, internal paths, and variable names in error responses (CWE-209). Optional chaining eliminates null-dereference crashes and simplifies defensive coding.

### 12. Nullish Coalescing (`??`) Preventing Falsy-Value Logic Bugs

The `??` operator returns the right operand only when the left is `null` or `undefined`, unlike `||` which triggers on any falsy value (0, '', false).

```javascript
// VULNERABLE: || treats 0, '', and false as "missing"
function getPort(config) {
  return config.port || 3000;
  // If config.port = 0 (a valid port), this incorrectly returns 3000
}

function getTimeout(options) {
  return options.timeout || 5000;
  // If options.timeout = 0 (no timeout), this returns 5000
}

function isFeatureEnabled(flags) {
  return flags.darkMode || true;
  // Always returns true, even if flags.darkMode = false
}

// SECURE: ?? only triggers on null/undefined (ES2020)
function getPort(config) {
  return config.port ?? 3000;
  // config.port = 0 correctly returns 0
}

function getTimeout(options) {
  return options.timeout ?? 5000;
  // options.timeout = 0 correctly returns 0
}

function isFeatureEnabled(flags) {
  return flags.darkMode ?? true;
  // flags.darkMode = false correctly returns false
}
```

**Security implication:** Using `||` for defaults creates logic bugs when legitimate falsy values (0, '', false) are valid inputs (CWE-480). In security contexts, this can disable timeouts (`timeout = 0` treated as missing), misconfigure ports, or bypass feature flags. Use `??` for null-checking defaults.

### 13. `globalThis` vs `window`/`global` Misuse

`globalThis` (ES2020) provides a universal reference to the global object across environments. Misuse of environment-specific globals leads to security-relevant bugs.

```javascript
// VULNERABLE: Assuming window exists (fails in Node.js/Workers)
if (window.isSecureContext) {
  enableSecureFeatures();
}
// In Node.js: ReferenceError, may skip security setup

// VULNERABLE: Polluting the global scope
window.authToken = getToken();
// Accessible to any script on the page, including injected scripts

// SECURE: Use globalThis for cross-environment code
if (globalThis.isSecureContext) {
  enableSecureFeatures();
}

// SECURE: Avoid storing secrets on global objects
// Use closures or module-scoped variables instead
const authModule = (() => {
  let token = null;
  return {
    setToken: (t) => { token = t; },
    getToken: () => token,
  };
})();
```

**Security implication:** Environment detection failures can cause security features to silently not activate (CWE-684). Storing sensitive data on global objects exposes it to cross-site scripting attacks. Use module-scoped variables and `globalThis` for environment-agnostic code.

## TypeScript-Specific Security

### 14. `any` vs `unknown` -- Type Safety for Untrusted Input

The `any` type disables all type checking, while `unknown` requires explicit narrowing before use. For untrusted input, `unknown` enforces validation at the type level.

```typescript
// VULNERABLE: 'any' silently bypasses all type checks
function processInput(data: any) {
  // No type errors, but data could be anything
  return data.user.name.toUpperCase();
  // Runtime TypeError if data is not the expected shape
}

// VULNERABLE: API response typed as 'any'
const response: any = await fetch('/api/user').then(r => r.json());
document.getElementById('name')!.innerHTML = response.name;
// XSS if response.name contains HTML (no type forces you to sanitize)

// SECURE: 'unknown' forces validation before use
function processInput(data: unknown) {
  if (
    typeof data === 'object' && data !== null &&
    'user' in data && typeof (data as Record<string, unknown>).user === 'object'
  ) {
    const user = (data as Record<string, unknown>).user as Record<string, unknown>;
    if (typeof user.name === 'string') {
      return user.name.toUpperCase();
    }
  }
  throw new Error('Invalid input shape');
}

// SECURE: Use Zod or similar for runtime validation
import { z } from 'zod';
const UserSchema = z.object({
  name: z.string().max(100),
  email: z.string().email(),
});
function processUser(data: unknown) {
  const user = UserSchema.parse(data); // Throws on invalid input
  return user.name.toUpperCase(); // Type-safe after validation
}
```

**Security implication:** The `any` type (CWE-20) effectively removes TypeScript's safety net. Untrusted data typed as `any` flows through the application without validation, enabling injection attacks and runtime crashes. Always type external input as `unknown` and validate with runtime checks or schema libraries.

### 15. Type Assertion Abuse (`as` Casting Bypassing Checks)

Type assertions (`as`) tell the compiler to trust the developer. They do not perform runtime checks and can mask type errors that lead to vulnerabilities.

```typescript
// VULNERABLE: Type assertion bypasses validation
interface AdminUser {
  role: 'admin';
  permissions: string[];
}
const userData = JSON.parse(requestBody) as AdminUser;
// No runtime check! userData.role might not be 'admin'
if (userData.role === 'admin') {
  grantFullAccess(userData); // Always true if attacker sends { role: 'admin' }
  // But this is a tautology — the assertion already told TS it's AdminUser
}

// VULNERABLE: Double assertion to bypass type system
const input = userString as unknown as SecureConfig;
// Completely bypasses type checking

// SECURE: Use type guards for runtime validation
function isAdminUser(data: unknown): data is AdminUser {
  return (
    typeof data === 'object' && data !== null &&
    'role' in data && (data as any).role === 'admin' &&
    'permissions' in data && Array.isArray((data as any).permissions)
  );
}

const userData: unknown = JSON.parse(requestBody);
if (isAdminUser(userData)) {
  grantFullAccess(userData); // Runtime-validated
} else {
  denyAccess();
}

// SECURE: Use schema validation (Zod, io-ts, etc.)
const AdminUserSchema = z.object({
  role: z.literal('admin'),
  permissions: z.array(z.string()),
});
const validated = AdminUserSchema.parse(JSON.parse(requestBody));
```

**Security implication:** Type assertions are compile-time only and perform zero runtime validation (CWE-704). Using `as` on untrusted data creates a false sense of security. Attackers can craft payloads that satisfy the asserted type shape while carrying malicious content. Always pair assertions with runtime validation.

### 16. Branded/Nominal Types for Input Validation

TypeScript's structural type system allows any object with matching properties to be used interchangeably. Branded types create nominal distinctions that enforce validation boundaries.

```typescript
// VULNERABLE: Structural typing allows unvalidated strings
function queryDatabase(sql: string) {
  return db.execute(sql); // Any string accepted, including injections
}
queryDatabase(`SELECT * FROM users WHERE id = '${userInput}'`); // SQL injection

// VULNERABLE: Email and UserId are both just strings
function sendEmail(email: string) { /* ... */ }
sendEmail(userId); // Type system doesn't catch the mistake

// SECURE: Branded types enforce validation
type SanitizedSQL = string & { readonly __brand: unique symbol };
type ValidatedEmail = string & { readonly __brand: unique symbol };

function sanitizeSQL(input: string): SanitizedSQL {
  // Actual sanitization logic here
  const escaped = input.replace(/'/g, "''");
  return escaped as SanitizedSQL;
}

function validateEmail(input: string): ValidatedEmail {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input) || input.length > 254) {
    throw new Error('Invalid email');
  }
  return input as ValidatedEmail;
}

function queryDatabase(sql: SanitizedSQL) {
  return db.execute(sql);
}
function sendEmail(email: ValidatedEmail) { /* ... */ }

// queryDatabase("raw string") // Compile error!
queryDatabase(sanitizeSQL(userInput)); // Must go through sanitizer
```

**Security implication:** Branded types create compile-time barriers that force all data to pass through validation functions before entering sensitive operations (CWE-20). This moves input validation from a convention to a compiler-enforced requirement.

### 17. `satisfies` Operator for Configuration Validation (TypeScript 4.9+)

The `satisfies` operator validates that a value conforms to a type while preserving its literal type. This catches configuration mistakes at compile time.

```typescript
// VULNERABLE: Type annotation widens literal types
const config: Record<string, string> = {
  apiUrl: 'https://api.example.com',
  authMode: 'outh2', // Typo! But no error — it's just a string
};

// VULNERABLE: No type checking on configuration objects
const corsConfig = {
  origin: '*',            // Overly permissive, but no type to flag it
  credentials: true,
  methods: ['GET', 'PSOT'], // Typo in POST
};

// SECURE: satisfies preserves literals while checking structure
interface SecurityConfig {
  apiUrl: string;
  authMode: 'oauth2' | 'apikey' | 'jwt';
}

const config = {
  apiUrl: 'https://api.example.com',
  authMode: 'oauth2',
} satisfies SecurityConfig;
// 'outh2' would cause a compile error!

// SECURE: satisfies for CORS configuration
interface CorsConfig {
  origin: string | string[];
  credentials: boolean;
  methods: Array<'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'>;
}

const corsConfig = {
  origin: 'https://app.example.com',
  credentials: true,
  methods: ['GET', 'POST'],
} satisfies CorsConfig;
// Typos in HTTP methods are caught at compile time
```

**Security implication:** The `satisfies` operator catches security misconfigurations (CWE-16) at compile time, including typos in auth modes, overly permissive CORS settings, and invalid HTTP methods, while preserving the exact literal types for downstream inference.

### 18. `NoInfer` Utility Type (TypeScript 5.4+)

`NoInfer` prevents TypeScript from inferring a type parameter from a specific argument, forcing the developer to be explicit. This prevents type-widening bugs in security-critical APIs.

```typescript
// VULNERABLE: Type inference widens 'allowed' to include attacker values
function grantPermission<T extends string>(role: T, allowed: T[]) {
  // T inferred from both 'role' and 'allowed'
}
grantPermission('admin', ['admin', 'superadmin', 'anything']);
// 'anything' is accepted because T widens to include it

// SECURE: NoInfer blocks inference from 'allowed'
function grantPermission<T extends string>(role: T, allowed: NoInfer<T>[]) {
  // T is only inferred from 'role'
}
grantPermission('admin', ['admin']); // OK
// grantPermission('admin', ['admin', 'anything']); // Error: 'anything' not in 'admin'
```

**Security implication:** Without `NoInfer`, TypeScript may widen type parameters to accommodate all arguments, silently accepting values that should be rejected. In authorization and permission systems, this can lead to privilege escalation through type-level bypass.

### 19. Strict Mode (`strict: true`) Security Implications

TypeScript's `strict` flag enables a suite of checks that catch entire categories of security-relevant bugs at compile time.

```typescript
// WITHOUT strict: true — these dangerous patterns compile silently

// strictNullChecks: off — null dereference
function getUser(): User | null { return null; }
const user = getUser();
console.log(user.name); // Runtime crash, no compile error

// noImplicitAny: off — untyped parameters bypass all checks
function processRequest(req, res) {
  res.send(req.body.data); // No type checking at all
}

// strictPropertyInitialization: off — uninitialized security fields
class AuthService {
  private secretKey: string; // Never initialized!
  verify(token: string) {
    return jwt.verify(token, this.secretKey); // undefined key!
  }
}

// WITH strict: true — all of the above are compile errors

// tsconfig.json
// {
//   "compilerOptions": {
//     "strict": true
//     // Equivalent to enabling ALL of:
//     // strictNullChecks, noImplicitAny, strictPropertyInitialization,
//     // strictBindCallApply, strictFunctionTypes, noImplicitThis,
//     // useUnknownInCatchVariables, alwaysStrict
//   }
// }
```

**Security implication:** Running without `strict: true` disables critical safety checks including null safety, implicit any detection, and property initialization checks (CWE-476, CWE-908). Production TypeScript projects should always enable `strict: true` in `tsconfig.json`.

## Detection Patterns for Auditing JavaScript/TypeScript

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| eval() usage | `eval\(` | error | SA-JS-01 |
| innerHTML assignment | `\.innerHTML\s*=` | error | SA-JS-02 |
| document.write usage | `document\.write\(` | error | SA-JS-03 |
| postMessage without origin check | `addEventListener\(.message` | warning | SA-JS-04 |
| Math.random for security | `Math\.random\(\)` | warning | SA-JS-05 |
| Prototype pollution vector | `__proto__` | error | SA-JS-06 |
| Function constructor | `new\s+Function\(` | error | SA-JS-07 |
| setTimeout with string | `setTimeout\(\s*['"\`]` | error | SA-JS-08 |
| outerHTML assignment | `\.outerHTML\s*=` | error | SA-JS-09 |
| debugger statement | `\bdebugger\b` | warning | SA-JS-10 |
| serialize-javascript usage | `require\(.serialize-javascript` | warning | SA-JS-11 |
| TypeScript any type | `:\s*any\b` | warning | SA-JS-12 |
| Double type assertion | `as\s+unknown\s+as` | error | SA-JS-13 |
| Dynamic import with variable | `import\([^)]*\$\{` | error | SA-JS-14 |
| setInterval with string | `setInterval\(\s*['"\`]` | error | SA-JS-15 |
| location.href assignment | `location\.href\s*=` | warning | SA-JS-16 |
| Wildcard postMessage target | `postMessage\([^,]+,\s*['"]\*['"]` | error | SA-JS-17 |
| Nested regex quantifiers | `(\+\)\+|\*\)\*|\+\)\*)` | warning | SA-JS-18 |
| strict mode disabled | `"strict"\s*:\s*false` | warning | SA-JS-19 |
| Unvalidated JSON.parse reviver | `JSON\.parse\([^)]+,\s*\(` | warning | SA-JS-20 |

## Version Adoption Security Checklist

- [ ] Enable `strict: true` in `tsconfig.json` for all TypeScript projects
- [ ] Replace all `eval()`, `Function()`, and string-form `setTimeout`/`setInterval` with safe alternatives
- [ ] Audit all `innerHTML`, `outerHTML`, and `document.write` usage for XSS
- [ ] Validate `event.origin` in all `postMessage` handlers
- [ ] Replace `Math.random()` with `crypto.getRandomValues()` or `crypto.randomUUID()` for security-sensitive values
- [ ] Audit all deep-merge utilities and query-string parsers for prototype pollution
- [ ] Replace `any` types on external input boundaries with `unknown` and runtime validation
- [ ] Remove all `debugger` statements from production code
- [ ] Validate dynamic `import()` specifiers against an allowlist
- [ ] Use branded types for security-critical string values (SQL, HTML, URLs)
- [ ] Configure ESLint with `no-eval`, `no-implied-eval`, `no-debugger`, and `@typescript-eslint/no-explicit-any`
- [ ] Audit regex patterns for catastrophic backtracking (nested quantifiers)
- [ ] Use `satisfies` for configuration objects to catch typos at compile time

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `cwe-top25.md` -- CWE Top 25 mapping
- `input-validation.md` -- Input validation patterns
- `php-security-features.md` -- PHP security features (for comparison)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 |
