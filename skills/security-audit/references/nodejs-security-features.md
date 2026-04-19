# Node.js Security Features by Version

Modern Node.js versions introduce runtime features, APIs, and permission controls that directly improve security when used correctly. This reference documents security-relevant patterns and features from Node.js 16 through 22+, focusing on server-side vulnerability classes unique to the Node.js execution model.

## Core Node.js Security Patterns

These patterns apply across all supported Node.js versions and represent the most common vulnerability classes in server-side JavaScript.

### 1. Command Injection via `child_process.exec`

`child_process.exec` spawns a shell and passes the command string to it, making it vulnerable to shell metacharacter injection when user input is interpolated into the command string.

```javascript
// VULNERABLE: String concatenation passes user input through a shell
const { exec } = require('child_process');

app.get('/lookup', (req, res) => {
  const host = req.query.host;
  exec('nslookup ' + host, (err, stdout) => {
    res.send(stdout);
  });
});
// Attacker sends: host=example.com;cat /etc/passwd

// VULNERABLE: Template literals are equally dangerous
exec(`convert ${req.body.filename} output.png`);

// SECURE: execFile does not spawn a shell — arguments are passed as an array
const { execFile } = require('child_process');

app.get('/lookup', (req, res) => {
  const host = req.query.host;
  execFile('nslookup', [host], (err, stdout) => {
    res.send(stdout);
  });
});

// SECURE: spawn with explicit argument array
const { spawn } = require('child_process');
const proc = spawn('convert', [req.body.filename, 'output.png']);
```

**Security implication:** Shell injection (CWE-78) allows arbitrary command execution on the server. `exec` and `execSync` invoke `/bin/sh -c`, so semicolons, pipes, backticks, and `$()` are all interpreted. Always use `execFile`, `execFileSync`, or `spawn` with argument arrays, which bypass the shell entirely.

**Detection regex:** `child_process.*exec\(`

---

### 2. Path Traversal via `fs` Operations

When user-supplied input is passed to `fs` methods without validation, attackers can read or write files outside the intended directory using `../` sequences. `path.join` does not prevent traversal — it resolves `..` segments normally.

```javascript
// VULNERABLE: path.join resolves .. segments — does NOT prevent traversal
const path = require('path');
const fs = require('fs');

app.get('/file', (req, res) => {
  const filePath = path.join('/app/uploads', req.query.name);
  // req.query.name = "../../etc/passwd" → filePath = "/etc/passwd"
  fs.readFile(filePath, (err, data) => {
    res.send(data);
  });
});

// VULNERABLE: fs.readFile with direct user input
fs.readFile(req.params.path, 'utf8', callback);

// SECURE: Resolve and verify the path stays within the allowed directory
const UPLOAD_DIR = path.resolve('/app/uploads');

app.get('/file', (req, res) => {
  const requested = path.resolve(UPLOAD_DIR, req.query.name);
  if (!requested.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  fs.readFile(requested, (err, data) => {
    res.send(data);
  });
});

// SECURE (Node.js 20+): Use the Permission Model to restrict fs access
// Start with: node --experimental-permission --allow-fs-read=/app/uploads
```

**Security implication:** Path traversal (CWE-22) allows reading sensitive files like `/etc/passwd`, `.env`, or application source code. Always resolve the full path with `path.resolve` and verify it starts with the intended base directory using `startsWith`.

**Detection regex:** `fs\.(readFile|writeFile|readdir|unlink|access|stat|createReadStream|createWriteStream)\s*\(`

---

### 3. `vm` / `vm2` Sandbox Escape

The Node.js `vm` module is explicitly documented as **not a security mechanism**. Code running in a `vm.Script` or `vm.createContext` can escape the sandbox and access the host process. The third-party `vm2` library was deprecated after multiple CVEs demonstrating sandbox escapes.

```javascript
// VULNERABLE: vm module is NOT a security boundary
const vm = require('vm');

app.post('/eval', (req, res) => {
  const sandbox = { result: null };
  vm.createContext(sandbox);
  vm.runInContext(req.body.code, sandbox);
  res.json({ result: sandbox.result });
});
// Attacker escapes with:
// this.constructor.constructor('return process')().exit()

// VULNERABLE: vm2 has known sandbox escapes (CVE-2023-37466, CVE-2023-32314)
const { VM } = require('vm2');
const vm2 = new VM();
vm2.run(userCode); // Still escapable

// SECURE: Use a separate process with limited permissions
const { execFile } = require('child_process');

app.post('/eval', (req, res) => {
  // Run in isolated process with timeout and resource limits
  execFile('node', ['--max-old-space-size=64', 'sandbox-worker.js'],
    { timeout: 5000, cwd: '/app/sandbox', uid: 65534 },
    (err, stdout) => {
      res.json({ result: stdout });
    }
  );
});

// SECURE: Use worker_threads with transferable-only communication
const { Worker } = require('worker_threads');
const worker = new Worker('./sandbox-worker.js', {
  workerData: { code: userCode },
  resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16 }
});
```

**Security implication:** Sandbox escape (CWE-265) leads to full remote code execution. The `vm` module provides execution context isolation but not security isolation. For untrusted code, use OS-level isolation (containers, separate processes with `uid`/`chroot`, or dedicated sandboxing services).

**Detection regex:** `require\s*\(\s*['"]vm2?['"]\s*\)`

---

### 4. `Buffer` Misuse

`Buffer.allocUnsafe` returns uninitialized memory that may contain sensitive data from previous allocations. `Buffer(number)` (deprecated constructor) also returns uninitialized memory in older Node.js versions.

```javascript
// VULNERABLE: allocUnsafe exposes uninitialized heap memory
const buf = Buffer.allocUnsafe(1024);
// buf may contain fragments of previous strings, keys, passwords
res.send(buf); // Leaks memory contents to client

// VULNERABLE: Deprecated Buffer constructor with number argument
const buf = new Buffer(userSize); // Uninitialized in Node < 10
res.send(buf);

// VULNERABLE: Buffer.from without encoding can misinterpret input
const decoded = Buffer.from(userInput); // Assumes UTF-8; no validation

// SECURE: Use Buffer.alloc which zero-fills memory
const buf = Buffer.alloc(1024);

// SECURE: Explicit encoding for Buffer.from
const decoded = Buffer.from(userInput, 'base64');

// SECURE: Validate buffer sizes to prevent DoS
const MAX_SIZE = 1024 * 1024; // 1MB
const size = parseInt(req.query.size, 10);
if (isNaN(size) || size < 0 || size > MAX_SIZE) {
  return res.status(400).send('Invalid size');
}
const buf = Buffer.alloc(size);
```

**Security implication:** Information disclosure (CWE-200) through uninitialized memory. `Buffer.allocUnsafe` is a performance optimization that should only be used when the buffer will be completely overwritten before being read. Never send an `allocUnsafe` buffer directly to a client.

**Detection regex:** `Buffer\.(allocUnsafe|allocUnsafeSlow)\s*\(`

---

### 5. Dynamic `require()` with User Input

When `require()` receives a path derived from user input, attackers can load arbitrary modules from the filesystem, potentially including files they have uploaded or symlinked.

```javascript
// VULNERABLE: Dynamic require with user-controlled path
app.get('/plugin/:name', (req, res) => {
  const plugin = require('./plugins/' + req.params.name);
  plugin.run(res);
});
// Attacker sends: name=../../../etc/passwd (error leaks path info)
// Or: name=../node_modules/child_process (loads built-in)

// VULNERABLE: require with template literal
const mod = require(`./handlers/${req.query.handler}`);

// SECURE: Allowlist of permitted modules
const ALLOWED_PLUGINS = {
  'markdown': './plugins/markdown',
  'csv': './plugins/csv',
  'json': './plugins/json',
};

app.get('/plugin/:name', (req, res) => {
  const pluginPath = ALLOWED_PLUGINS[req.params.name];
  if (!pluginPath) {
    return res.status(404).send('Plugin not found');
  }
  const plugin = require(pluginPath);
  plugin.run(res);
});
```

**Security implication:** Arbitrary code execution (CWE-94) through module loading. Dynamic `require` can load any `.js`, `.json`, or `.node` file on the filesystem. Always use an allowlist mapping from user input to safe module paths.

**Detection regex:** `require\s*\(\s*[^'"]\s*[+\`]`

---

### 6. Event Loop Blocking

CPU-bound synchronous operations in request handlers block the entire event loop, creating denial-of-service vulnerabilities. This includes synchronous crypto, large JSON parsing, and regular expression backtracking (ReDoS).

```javascript
// VULNERABLE: Synchronous bcrypt blocks event loop for ALL requests
const bcrypt = require('bcryptjs');
app.post('/login', (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 12); // Blocks ~300ms
  // All other requests are blocked during hashing
});

// VULNERABLE: ReDoS via evil regex with user input
const userRegex = new RegExp(req.query.pattern);
userRegex.test(someString); // Can hang for minutes with crafted input

// VULNERABLE: JSON.parse on unbounded user input
const data = JSON.parse(req.body); // 100MB JSON = frozen server

// SECURE: Use async operations
app.post('/login', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 12);
  // Event loop stays responsive
});

// SECURE: Limit input size and use streaming JSON parsers
app.use(express.json({ limit: '1mb' }));

// SECURE: Prefer a linear-time engine (google/re2 via the `re2` npm package)
// over feeding user input to the V8 backtracking RegExp engine. safe-regex
// is a useful smell-test but known to be bypassable with crafted inputs —
// it stops the obvious cases, not a determined attacker.
const RE2 = require('re2');
try {
  const compiled = new RE2(req.query.pattern);      // throws if input uses
  const matches = compiled.match(req.query.subject); // unsupported features
  res.json({ matches });
} catch {
  return res.status(400).send('Invalid or unsupported pattern');
}
// Also always enforce a maximum input length before any regex work:
if (req.query.subject && req.query.subject.length > 10_000) {
  return res.status(413).send('Input too large');
}
```

**Security implication:** Denial of service (CWE-400) via event loop blocking. A single slow synchronous operation prevents the server from handling any other requests. Use async APIs, limit input sizes, and never construct regular expressions from untrusted input.

**Detection regex:** `(hashSync|compareSync|pbkdf2Sync|scryptSync|randomFillSync)\s*\(`

---

### 7. HTTP Header Injection (CRLF Injection)

If user input is passed to `res.setHeader` or `res.writeHead` without sanitization, attackers can inject CRLF characters (`\r\n`) to add arbitrary headers or split the HTTP response.

```javascript
// VULNERABLE: User input directly in response header
app.get('/redirect', (req, res) => {
  res.setHeader('Location', req.query.url);
  // Attacker: url=http://evil.com%0d%0aSet-Cookie:%20admin=true
  res.status(302).end();
});

// VULNERABLE: User input in custom header
res.setHeader('X-User-Name', req.query.name);

// SECURE: Validate and sanitize header values
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // Strip CR and LF characters
  if (/[\r\n]/.test(url)) {
    return res.status(400).send('Invalid URL');
  }
  // Validate it's a relative URL or from allowed origins
  const parsed = new URL(url, 'https://myapp.com');
  if (parsed.origin !== 'https://myapp.com') {
    return res.status(400).send('Invalid redirect');
  }
  res.redirect(302, parsed.href);
});

// SECURE: Use a library that sanitizes headers automatically
// Note: Node.js 18+ rejects headers containing \r or \n by default
```

**Security implication:** HTTP response splitting (CWE-113) allows attackers to inject headers, set cookies, or split responses to perform cache poisoning and XSS. Node.js 18+ includes built-in protection, but explicit validation is required for older versions and for defense in depth.

**Detection regex:** `res\.(setHeader|writeHead)\s*\([^)]*req\.(query|params|body|headers)`

---

### 8. Stream Backpressure (Memory Exhaustion)

When piping data from a fast source to a slow destination without respecting backpressure, the internal buffer grows unbounded, eventually exhausting server memory.

```javascript
// VULNERABLE: No backpressure handling — memory grows unbounded
const http = require('http');
const fs = require('fs');

http.createServer((req, res) => {
  if (req.method === 'POST') {
    const writeStream = fs.createWriteStream('/tmp/upload.dat');
    req.on('data', (chunk) => {
      writeStream.write(chunk); // Ignoring return value!
      // If disk is slow, chunks accumulate in memory
    });
  }
});

// SECURE: Use pipe() which handles backpressure automatically
http.createServer((req, res) => {
  if (req.method === 'POST') {
    const writeStream = fs.createWriteStream('/tmp/upload.dat');
    req.pipe(writeStream);
    writeStream.on('finish', () => res.end('OK'));
    writeStream.on('error', (err) => {
      res.statusCode = 500;
      res.end('Upload failed');
    });
  }
});

// SECURE: Use pipeline() from stream/promises for proper error handling
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');

app.post('/upload', async (req, res) => {
  try {
    await pipeline(req, createWriteStream('/tmp/upload.dat'));
    res.end('OK');
  } catch (err) {
    res.status(500).end('Upload failed');
  }
});
```

**Security implication:** Memory exhaustion denial of service (CWE-400). An attacker sending data faster than the server can write it to disk can crash the process. Always use `pipe()` or `pipeline()` which automatically pause the readable stream when the writable stream's buffer is full.

**Detection regex:** `\.on\s*\(\s*['"]data['"]\s*,.*\.write\s*\(`

---

### 9. Insecure `http.createServer` Configuration

Bare `http.createServer` without timeouts, size limits, or security headers leaves the server vulnerable to slowloris attacks, large payload DoS, and various HTTP-level exploits.

```javascript
// VULNERABLE: No timeouts, no size limits, no security headers
const http = require('http');
const server = http.createServer((req, res) => {
  // Slowloris attack: client sends headers very slowly, holds connection
  // Large body attack: client sends huge POST body, fills memory
  let body = '';
  req.on('data', chunk => { body += chunk; }); // Unbounded!
  req.on('end', () => {
    res.end('OK');
  });
});
server.listen(3000);

// SECURE: Configure timeouts and limits
const server = http.createServer((req, res) => {
  // Limit body size
  let body = '';
  let size = 0;
  const MAX_BODY = 1024 * 1024; // 1MB

  req.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_BODY) {
      res.writeHead(413);
      res.end('Payload Too Large');
      req.destroy();
      return;
    }
    body += chunk;
  });

  // Set security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  req.on('end', () => {
    res.end('OK');
  });
});

// Configure timeouts
server.headersTimeout = 20000;    // 20s to receive headers
server.requestTimeout = 30000;    // 30s total for request
server.keepAliveTimeout = 5000;   // 5s keep-alive
server.timeout = 60000;           // 60s total connection timeout
server.maxHeadersCount = 50;      // Limit header count

server.listen(3000);
```

**Security implication:** Denial of service (CWE-400) through resource exhaustion. Without timeouts, a slowloris attack can exhaust connection slots. Without body size limits, a single request can consume all available memory. Production servers should always set `headersTimeout`, `requestTimeout`, and body size limits.

**Detection regex:** `http\.createServer\s*\(`

---

### 10. Prototype Pollution via `Object.assign` / Spread

Prototype pollution occurs when an attacker can inject properties into `Object.prototype` through unvalidated object merging, affecting all objects in the application.

```javascript
// VULNERABLE: Deep merge of user-controlled objects
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
deepMerge({}, JSON.parse(req.body));
// Now: ({}).isAdmin === true — all objects are "admin"

// VULNERABLE: Object.assign with user input into shared config
Object.assign(config, req.body);

// SECURE: Block prototype-polluting keys
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Skip dangerous keys
    }
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// SECURE: Use Object.create(null) for dictionary objects
const config = Object.create(null); // No prototype chain

// SECURE: Use Map instead of plain objects for user data
const userSettings = new Map();
userSettings.set(key, value);

// SECURE: Freeze the prototype (defense in depth)
Object.freeze(Object.prototype);
```

**Security implication:** Prototype pollution (CWE-1321) can lead to authorization bypass, denial of service, or remote code execution depending on how the polluted properties are used. Validate all keys before merging user-controlled objects, use `Object.create(null)` for dictionaries, and consider `Object.freeze(Object.prototype)` as defense in depth.

**Detection regex:** `__proto__|Object\.assign\s*\([^,]+,\s*req\.(body|query|params)`

---

## Node.js 16+ Features

### 11. `crypto.randomUUID()` for Secure Identifiers

Node.js 16 introduced `crypto.randomUUID()` as a built-in way to generate cryptographically secure UUIDs without external dependencies.

```javascript
// VULNERABLE: Math.random is not cryptographically secure
function generateToken() {
  return Math.random().toString(36).substring(2);
  // Predictable! Math.random uses xorshift128+ — output is recoverable
}

// VULNERABLE: Timestamp-based identifiers are guessable
const sessionId = Date.now().toString(36);

// VULNERABLE: uuid v1 is timestamp-based, not random
const { v1: uuidv1 } = require('uuid');
const token = uuidv1(); // Based on timestamp + MAC address

// SECURE: crypto.randomUUID (Node.js 16+)
const crypto = require('crypto');
const sessionId = crypto.randomUUID();
// Returns: "36b8f84d-df4e-4d49-b662-bcde71a8764f"

// SECURE: crypto.randomBytes for arbitrary-length tokens
const token = crypto.randomBytes(32).toString('hex');

// SECURE: crypto.randomInt for bounded random integers (Node.js 14.10+)
const otp = crypto.randomInt(100000, 999999); // 6-digit OTP
```

**Security implication:** Insecure randomness (CWE-330) in session tokens, CSRF tokens, or API keys allows attackers to predict and forge values. `Math.random()` is not cryptographically secure and its output can be reverse-engineered from a few observed values. Always use `crypto.randomUUID()`, `crypto.randomBytes()`, or `crypto.randomInt()` for security-sensitive values.

**Detection regex:** `Math\.random\s*\(`

---

### 12. AbortController for Request Cancellation

Node.js 16 stabilized `AbortController`, enabling safe request cancellation with proper resource cleanup. This prevents resource leaks from abandoned or timed-out operations.

```javascript
// VULNERABLE: No timeout on outgoing HTTP requests
const https = require('https');
app.get('/proxy', (req, res) => {
  https.get(req.query.url, (proxyRes) => {
    proxyRes.pipe(res);
  });
  // If upstream never responds, this connection hangs forever
});

// VULNERABLE: fetch without timeout (Node.js 18+)
const data = await fetch(url); // Hangs indefinitely on slow servers

// SECURE: AbortController with timeout (Node.js 16+)
app.get('/proxy', async (req, res) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(req.query.url, {
      signal: controller.signal,
    });
    const data = await response.text();
    res.send(data);
  } catch (err) {
    if (err.name === 'AbortError') {
      res.status(504).send('Upstream timeout');
    } else {
      res.status(502).send('Upstream error');
    }
  } finally {
    clearTimeout(timeout);
  }
});

// SECURE: AbortSignal.timeout() shorthand (Node.js 18+)
const response = await fetch(url, {
  signal: AbortSignal.timeout(5000),
});
```

**Security implication:** Resource exhaustion (CWE-400) from connections that never close. Without timeouts and cancellation, a slow or malicious upstream can hold server resources indefinitely, eventually exhausting connection pools and memory. Always use `AbortController` or `AbortSignal.timeout()` for outgoing requests.

**Detection regex:** `https?\.(get|request)\s*\([^)]*\)\s*(?!.*abort|.*timeout)`

---

## Node.js 18+ Features

### 13. Built-in Test Runner Security

Node.js 18 introduced a built-in test runner (`node:test`) that eliminates the dependency on external test frameworks for security-sensitive testing.

```javascript
// SECURE: Built-in test runner for security tests (no third-party deps)
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeInput, validatePath } = require('../src/security');

describe('Input Sanitization', () => {
  it('rejects path traversal attempts', () => {
    assert.throws(() => validatePath('../../../etc/passwd'), {
      message: /path traversal/i
    });
  });

  it('strips null bytes from input', () => {
    assert.strictEqual(
      sanitizeInput('file.txt\x00.jpg'),
      'file.txt.jpg'
    );
  });

  it('rejects prototype pollution keys', () => {
    const result = sanitizeInput('{"__proto__": {"admin": true}}');
    assert.strictEqual(({}).admin, undefined);
  });
});
```

**Security implication:** Reducing test framework dependencies shrinks the supply chain attack surface. The built-in `node:test` module requires no `npm install`, avoiding potential dependency confusion or malicious package injection through test tooling.

---

### 14. Built-in `fetch` API (SSRF Considerations)

Node.js 18 includes a built-in `fetch` implementation (based on `undici`). While this reduces the dependency on `node-fetch`, it introduces server-side request forgery (SSRF) risks if URLs come from user input.

```javascript
// VULNERABLE: Fetching user-supplied URLs without validation (SSRF)
app.get('/preview', async (req, res) => {
  const response = await fetch(req.query.url);
  const html = await response.text();
  res.send(html);
});
// Attacker sends: url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
// Attacker sends: url=http://localhost:6379/CONFIG%20SET%20dir%20/tmp (Redis)

// VULNERABLE: DNS rebinding bypass — URL looks external but resolves to internal
// First resolution: 1.2.3.4 (external), second resolution: 127.0.0.1 (internal)

// SECURE: Validate and restrict URLs
const { URL } = require('url');

const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
const BLOCKED_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'];

async function safeFetch(urlString) {
  const url = new URL(urlString);

  // Block internal hostnames
  if (BLOCKED_HOSTS.has(url.hostname)) {
    throw new Error('Internal hosts not allowed');
  }

  // Block non-HTTP(S) schemes
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP(S) allowed');
  }

  // Resolve DNS and check for internal IPs before fetching
  const { resolve4 } = require('dns/promises');
  const addresses = await resolve4(url.hostname);
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error('Internal IP not allowed');
    }
  }

  return fetch(urlString, {
    signal: AbortSignal.timeout(5000),
    redirect: 'manual', // Don't follow redirects to internal URLs
  });
}
```

**Security implication:** Server-side request forgery (CWE-918) allows attackers to use the server as a proxy to access internal services, cloud metadata endpoints, and other resources not directly reachable from the internet. Always validate and restrict outgoing URLs, resolve DNS before fetching, block private IP ranges, and do not follow redirects automatically.

**Detection regex:** `fetch\s*\(\s*req\.(query|params|body)`

---

## Node.js 20+ Features

### 15. Permission Model

Node.js 20 introduced an experimental Permission Model that restricts access to the filesystem, child processes, and worker threads at the runtime level.

```bash
# SECURE: Restrict filesystem access to only the app directory
node --experimental-permission --allow-fs-read=/app --allow-fs-write=/app/data server.js

# SECURE: Allow only specific command execution
node --experimental-permission --allow-child-process server.js

# SECURE: Read-only mode — no filesystem writes at all
node --experimental-permission --allow-fs-read=* server.js

# SECURE: Deny all — no fs, no child_process, no worker_threads
node --experimental-permission server.js
# Any fs.readFile, child_process.exec, or new Worker() will throw ERR_ACCESS_DENIED
```

```javascript
// Runtime permission check (Node.js 20+)
const { permission } = require('node:process');

// Check if a specific permission is granted
if (process.permission.has('fs.read', '/etc/passwd')) {
  console.log('WARNING: Process can read /etc/passwd');
}

if (process.permission.has('child.process')) {
  console.log('WARNING: Process can spawn child processes');
}

// SECURE: Use permission model to enforce least privilege
// Start server with only the permissions it needs:
// node --experimental-permission \
//   --allow-fs-read=/app \
//   --allow-fs-write=/app/uploads \
//   --allow-fs-write=/tmp \
//   server.js
```

**Security implication:** The Permission Model provides defense in depth (CWE-250, principle of least privilege). Even if an attacker achieves code execution through an injection vulnerability, the Permission Model limits what operations they can perform. This significantly reduces the blast radius of vulnerabilities.

**Detection regex:** `--experimental-permission|--allow-fs-(read|write)|--allow-child-process`

---

## Node.js 22+ Features

### 16. `require(esm)` and Dynamic Import Security

`require()` of ES modules is an experimental / flagged feature in Node.js 22 (`--experimental-require-module`), not a stable default — treat it as unreleased for security-critical code. Dynamic `import()` expressions, on the other hand, have been stable since Node.js 13.2. Both can be vectors for loading untrusted code when the specifier comes from user input.

```javascript
// VULNERABLE: Dynamic import with user-controlled specifier
app.get('/widget/:name', async (req, res) => {
  const widget = await import(`./widgets/${req.params.name}.js`);
  // Attacker: name=../../../etc/passwd — import error leaks path info
  // Attacker: name=../node_modules/malicious-pkg/index — loads arbitrary package
  res.json(widget.default());
});

// VULNERABLE: require(esm) with user input (Node.js 22+)
const mod = require(`./plugins/${req.query.plugin}.mjs`);

// SECURE: Allowlist with static imports
const WIDGETS = {
  chart: () => import('./widgets/chart.js'),
  table: () => import('./widgets/table.js'),
  map: () => import('./widgets/map.js'),
};

app.get('/widget/:name', async (req, res) => {
  const loader = WIDGETS[req.params.name];
  if (!loader) {
    return res.status(404).send('Widget not found');
  }
  const widget = await loader();
  res.json(widget.default());
});

// SECURE: Import assertions for JSON modules (prevents code execution)
const config = await import('./config.json', { with: { type: 'json' } });
```

**Security implication:** Arbitrary code execution (CWE-94) through dynamic module loading. Both `require()` and `import()` execute code at load time. Dynamic specifiers from user input allow loading arbitrary files. Use allowlists mapping user input to static import paths. Import assertions (`with: { type: 'json' }`) ensure JSON files are not executed as code.

**Detection regex:** `import\s*\(\s*[^'"]\s*[+\`]`

---

## Detection Patterns for Auditing Node.js Security

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| Command injection via exec | `child_process.*exec\(` | error | SA-NODE-01 |
| fs operations with user input | `fs\.(readFile\|writeFile\|readdir\|unlink).*req\.(query\|params\|body)` | error | SA-NODE-02 |
| vm/vm2 sandbox usage | `require\s*\(\s*['"]vm2?['"]\s*\)` | error | SA-NODE-03 |
| Buffer.allocUnsafe usage | `Buffer\.(allocUnsafe\|allocUnsafeSlow)\s*\(` | warning | SA-NODE-04 |
| Dynamic require with user input | `require\s*\(\s*[^'"]\s*[+\x60]` | error | SA-NODE-05 |
| Sync crypto in request handler | `(hashSync\|compareSync\|pbkdf2Sync\|scryptSync)\s*\(` | warning | SA-NODE-06 |
| HTTP header injection | `res\.(setHeader\|writeHead)\s*\([^)]*req\.(query\|params\|body)` | error | SA-NODE-07 |
| Math.random for security | `Math\.random\s*\(` | warning | SA-NODE-08 |
| http.createServer without timeouts | `http\.createServer\s*\(` | warning | SA-NODE-09 |
| Prototype pollution via merge | `__proto__\|Object\.assign\s*\([^,]+,\s*req\.(body\|query)` | error | SA-NODE-10 |
| SSRF via fetch with user URL | `fetch\s*\(\s*req\.(query\|params\|body)` | error | SA-NODE-11 |
| Weak crypto hash algorithms | `createHash\s*\(\s*['"]md5['"]` | warning | SA-NODE-12 |
| eval() usage | `\beval\s*\(` | error | SA-NODE-13 |
| Dynamic import with user input | `import\s*\(\s*[^'"]\s*[+\x60]` | error | SA-NODE-14 |
| new Function() constructor | `new\s+Function\s*\(` | error | SA-NODE-15 |

## Version Adoption Security Checklist

- [ ] Upgrade to Node.js 18+ for built-in header injection protection
- [ ] Replace `node-fetch` with built-in `fetch` and add SSRF validation
- [ ] Add `--experimental-permission` flags in production (Node.js 20+)
- [ ] Replace `Math.random()` with `crypto.randomUUID()` or `crypto.randomBytes()`
- [ ] Replace `Buffer.allocUnsafe` with `Buffer.alloc` unless performance-critical and fully overwritten
- [ ] Replace `exec`/`execSync` with `execFile`/`spawn` + argument arrays
- [ ] Remove `vm2` dependency (deprecated, multiple CVEs)
- [ ] Add `AbortController` timeouts to all outgoing HTTP requests
- [ ] Set `server.headersTimeout`, `server.requestTimeout`, and body size limits
- [ ] Use `node:test` for security tests to reduce test dependency surface

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `javascript-typescript-security-features.md` — Browser/client-side JavaScript/TypeScript patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 |
