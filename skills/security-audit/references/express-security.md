# Express Security Patterns

Security patterns, common misconfigurations, and detection regexes for Express.js applications. Express is intentionally minimal and unopinionated, meaning security features like header hardening, CSRF protection, input validation, and rate limiting must be explicitly added via middleware. The ordering and configuration of this middleware is critical -- misplacement or misconfiguration is the most common source of vulnerabilities.

---

## Middleware Ordering

### SA-EXPRESS-01: Middleware Ordering (Helmet, CORS, Auth)

Express executes middleware in registration order. Security middleware (Helmet for headers, CORS, rate limiting) must be registered before route handlers. Auth middleware registered after routes leaves those routes unprotected.

```javascript
// VULNERABLE: Routes defined before security middleware
const app = express();

app.get('/api/users', listUsers);          // No helmet, no CORS, no auth
app.delete('/api/users/:id', deleteUser);  // Completely unprotected

// Security middleware added too late
app.use(helmet());
app.use(cors({ origin: 'https://app.example.com' }));
app.use(authMiddleware);

app.listen(3000);

// VULNERABLE: No helmet at all — missing security headers
const app = express();
app.use(express.json());
app.use('/api', apiRouter);
// No helmet() — no X-Content-Type-Options, no CSP, no HSTS, etc.
app.listen(3000);
```

```javascript
// SECURE: Correct middleware ordering
const app = express();

// 1. Security headers (first — applies to all responses)
app.use(helmet());

// 2. CORS (before routes, after helmet)
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true,
}));

// 3. Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

// 4. Rate limiting (before auth to protect login endpoints)
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// 5. Auth middleware on protected routes
app.use('/api', authMiddleware, apiRouter);

// 6. Public routes
app.use('/health', healthRouter);

// 7. Error handler LAST
app.use(errorHandler);

app.listen(3000);
```

**Detection regex:** `app\.(get|post|put|delete|use)\s*\([^)]*\)[\s\S]*?app\.use\s*\(\s*helmet\s*\(`
**Severity:** error

---

## Injection via Request Parameters

### SA-EXPRESS-02: req.params / req.query Injection

Express passes user input through `req.params`, `req.query`, and `req.body`. Using these values directly in database queries, shell commands, or template rendering without validation enables injection attacks. Note that `req.query` values can be strings OR arrays, which can bypass type-checking logic.

```javascript
// VULNERABLE: req.query directly in MongoDB query (NoSQL injection)
app.get('/api/users', async (req, res) => {
  const users = await User.find({ role: req.query.role });
  // Attacker sends: ?role[$ne]=null  →  returns ALL users
  res.json(users);
});

// VULNERABLE: req.params in shell command
app.get('/api/logs/:filename', (req, res) => {
  const output = execSync(`cat logs/${req.params.filename}`);
  // Attacker sends: /api/logs/access.log;cat /etc/passwd
  res.send(output);
});

// VULNERABLE: req.query type confusion
app.get('/api/search', (req, res) => {
  if (req.query.admin === 'true') {
    // Attacker sends: ?admin=true  →  type is string, passes check
    // OR: ?admin[]=true  →  type is array, may bypass other checks
  }
});
```

```javascript
// SECURE: Validate and sanitize all inputs
const { query, validationResult } = require('express-validator');

app.get('/api/users',
  query('role').isIn(['user', 'editor', 'admin']).optional(),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const users = await User.find({ role: req.query.role });
      res.json(users);
    } catch (err) {
      next(err);
    }
  }
);

// SECURE: Never use user input in shell commands
app.get('/api/logs/:filename', (req, res) => {
  const basename = path.basename(req.params.filename);
  const allowed = /^[a-zA-Z0-9_-]+\.log$/.test(basename);
  if (!allowed) return res.status(400).json({ error: 'Invalid filename' });

  const logPath = path.join(__dirname, 'logs', basename);
  const resolved = fs.realpathSync(logPath);
  if (!resolved.startsWith(path.join(__dirname, 'logs'))) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(resolved);
});
```

**Detection regex:** `execSync\s*\(.*req\.(params|query|body)|exec\s*\(.*req\.(params|query|body)`
**Severity:** error

---

## Path Traversal

### SA-EXPRESS-03: res.sendFile Path Traversal

`res.sendFile()` serves files from the filesystem. Without the `root` option or path validation, user-controlled input can traverse directories.

```javascript
// VULNERABLE: User input directly in sendFile without root option
app.get('/files/:name', (req, res) => {
  res.sendFile(req.params.name);
  // Attacker sends: /files/../../../etc/passwd
});

// VULNERABLE: Path concatenation
app.get('/download', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.query.file);
  // path.join does NOT prevent traversal: path.join('/uploads', '../../../etc/passwd')
  //   → '/etc/passwd'
  res.sendFile(filePath);
});

// VULNERABLE: Insufficient sanitization
app.get('/files/:name', (req, res) => {
  const safe = req.params.name.replace(/\.\./g, '');
  // Can be bypassed: '....//....//etc/passwd' → '../../etc/passwd'
  res.sendFile(path.join(__dirname, 'uploads', safe));
});
```

```javascript
// SECURE: Use root option to restrict to a directory
app.get('/files/:name', (req, res) => {
  const options = {
    root: path.join(__dirname, 'uploads'),
    dotfiles: 'deny',
  };
  // sendFile with root option rejects paths containing ..
  res.sendFile(req.params.name, options, (err) => {
    if (err) res.status(404).json({ error: 'Not found' });
  });
});

// SECURE: Validate basename and verify resolved path
app.get('/download', (req, res) => {
  const basename = path.basename(req.query.file);
  const uploadsDir = path.resolve(__dirname, 'uploads');
  const fullPath = path.resolve(uploadsDir, basename);

  if (!fullPath.startsWith(uploadsDir + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }

  res.sendFile(fullPath);
});
```

**Detection regex:** `res\.sendFile\s*\(\s*(?:req\.(params|query|body)|path\.join\s*\([^)]*req\.(params|query|body))`
**Severity:** error

---

## Session Configuration

### SA-EXPRESS-04: Session Configuration (Secure Cookies, Session Store)

Express sessions via `express-session` must be configured with secure cookie flags, a production-grade session store, and a strong secret. The default in-memory store leaks memory and does not scale.

```javascript
// VULNERABLE: Insecure session configuration
const session = require('express-session');

app.use(session({
  secret: 'keyboard cat',           // Weak, hardcoded secret
  resave: true,                      // Unnecessary writes
  saveUninitialized: true,           // Creates sessions for unauthenticated users
  // Missing cookie security flags
  // Using default MemoryStore — memory leak in production
}));

// VULNERABLE: Cookie without secure flag
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: false,   // Accessible to JavaScript — XSS can steal session
    secure: false,     // Sent over HTTP — MITM can steal session
    sameSite: 'none',  // Cross-site requests allowed
  },
}));
```

```javascript
// SECURE: Production session configuration
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect();

app.set('trust proxy', 1); // Required for secure cookies behind a reverse proxy

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,   // Strong, from environment
  resave: false,
  saveUninitialized: false,
  name: '__session',                    // Custom name (not 'connect.sid')
  cookie: {
    httpOnly: true,      // Not accessible to JavaScript
    secure: true,        // HTTPS only
    sameSite: 'strict',  // No cross-site sending
    maxAge: 1800000,     // 30 minutes
  },
}));
```

**Detection regex:** `session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]{0,20}['"]|cookie\s*:\s*\{[^}]*httpOnly\s*:\s*false|cookie\s*:\s*\{[^}]*secure\s*:\s*false`
**Severity:** error

---

## Rate Limiting

### SA-EXPRESS-05: Rate Limiting

Without rate limiting, Express applications are vulnerable to brute-force attacks, credential stuffing, and API abuse. The `express-rate-limit` middleware should be applied globally with stricter limits on authentication endpoints.

```javascript
// VULNERABLE: No rate limiting
const app = express();

app.post('/api/login', loginHandler);           // Brute force
app.post('/api/register', registerHandler);     // Account spam
app.post('/api/forgot-password', forgotHandler); // Enumeration
app.get('/api/search', searchHandler);          // DoS

app.listen(3000);
```

```javascript
// SECURE: Global and per-route rate limiting
const rateLimit = require('express-rate-limit');

// Global: 100 requests per 15 minutes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Strict: 5 attempts per 15 minutes for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts, try again later' },
});
app.use('/api/login', authLimiter);
app.use('/api/forgot-password', authLimiter);
```

**Detection regex:** `app\.(post|put)\s*\(\s*['"]\/[^'"]*(?:login|auth|token|password|register)[^'"]*['"]`
**Severity:** warning

---

## Input Validation

### SA-EXPRESS-06: Input Validation (express-validator Patterns)

Express does not validate input by default. All request data (`req.body`, `req.query`, `req.params`) must be explicitly validated. Using `express-validator` or `joi` is recommended over manual checks.

```javascript
// VULNERABLE: No input validation
app.post('/api/users', async (req, res) => {
  const { name, email, age } = req.body;
  // No type checking, no length limits, no format validation
  const user = await User.create({ name, email, age });
  res.json(user);
});

// VULNERABLE: Trusting req.body shape for database operations
app.put('/api/users/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);
  // Attacker can set any field: { isAdmin: true, role: 'superadmin' }
  res.json({ success: true });
});
```

```javascript
// SECURE: express-validator with explicit rules
const { body, param, validationResult } = require('express-validator');

app.post('/api/users',
  body('name').isString().trim().isLength({ min: 1, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('age').isInt({ min: 0, max: 150 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, age } = req.body;
    const user = await User.create({ name, email, age });
    res.json(user);
  }
);

// SECURE: Allowlist fields for update
app.put('/api/users/:id',
  param('id').isMongoId(),
  body('name').isString().trim().isLength({ min: 1, max: 100 }).optional(),
  body('email').isEmail().normalizeEmail().optional(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Inline allowlist — keeps the example dependency-free.
    // Equivalent to lodash/Ramda `pick`.
    const allowed = { name: req.body.name, email: req.body.email };
    await User.findByIdAndUpdate(req.params.id, allowed);
    res.json({ success: true });
  }
);
```

**Detection regex:** `findByIdAndUpdate\s*\([^,]+,\s*req\.body\s*\)|\.create\s*\(\s*req\.body\s*\)`
**Severity:** warning

---

## Code Injection

### SA-EXPRESS-07: eval() in Route Handlers

Using `eval()`, `new Function()`, `vm.runInNewContext()`, or `child_process.exec()` with user input enables arbitrary code execution.

```javascript
// VULNERABLE: eval with user input
app.get('/api/calculate', (req, res) => {
  const expression = req.query.expr;
  const result = eval(expression);
  // Attacker sends: ?expr=process.exit(1)
  // Or: ?expr=require('child_process').execSync('cat /etc/passwd').toString()
  res.json({ result });
});

// VULNERABLE: new Function with user input
app.post('/api/transform', (req, res) => {
  const fn = new Function('data', req.body.transform);
  const result = fn(req.body.data);
  res.json({ result });
});

// VULNERABLE: vm module with user code
const vm = require('vm');
app.post('/api/sandbox', (req, res) => {
  const result = vm.runInNewContext(req.body.code, {});
  // vm is NOT a security sandbox — it can be escaped
  res.json({ result });
});
```

```javascript
// SECURE: Use a safe expression evaluator
const { Parser } = require('expr-eval');
const parser = new Parser();

app.get('/api/calculate', (req, res) => {
  try {
    const expr = parser.parse(req.query.expr);
    const result = expr.evaluate();
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// SECURE: Predefined transformations instead of dynamic code
const TRANSFORMS = {
  uppercase: (data) => String(data).toUpperCase(),
  lowercase: (data) => String(data).toLowerCase(),
  reverse: (data) => String(data).split('').reverse().join(''),
};

app.post('/api/transform', (req, res) => {
  const fn = TRANSFORMS[req.body.transform];
  if (!fn) return res.status(400).json({ error: 'Unknown transform' });
  res.json({ result: fn(req.body.data) });
});
```

**Detection regex:** `eval\s*\(\s*req\.(query|body|params)|new\s+Function\s*\([^)]*req\.(query|body|params)|vm\.run`
**Severity:** error

---

## Error Handling

### SA-EXPRESS-08: Error Handler Information Disclosure

Express's default error handler sends full stack traces in development mode. If `NODE_ENV` is not set to `production`, or if custom error handlers leak internal details, attackers gain information about the application structure, file paths, and dependencies.

```javascript
// VULNERABLE: Stack traces exposed to clients
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,         // Full stack trace with file paths
    details: err.details,     // Internal error details
  });
});

// VULNERABLE: NODE_ENV not set — Express defaults to development
// $ node server.js  (without NODE_ENV=production)
// Express sends: "Error: Cannot find module './config'\n at Module._resolveFilename..."

// VULNERABLE: Database error details exposed
app.use((err, req, res, next) => {
  if (err.name === 'MongoError') {
    res.status(500).json({ error: err.message });
    // Leaks: "E11000 duplicate key error collection: mydb.users index: email_1"
  }
});
```

```javascript
// SECURE: Generic error response with internal logging
app.use((err, req, res, next) => {
  // Log full error internally
  console.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
  });

  // Generic response to client
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal server error' : err.message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// SECURE: Ensure NODE_ENV is set in production
// Dockerfile: ENV NODE_ENV=production
// Or: package.json scripts: "start": "NODE_ENV=production node server.js"
```

**Detection regex:** `res\.(status|json)\s*\([^)]*err\.(stack|message)|\.json\s*\(\s*\{[^}]*stack\s*:\s*err`
**Severity:** warning

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-EXPRESS-01 Middleware ordering | Critical | Immediate | Low |
| SA-EXPRESS-02 Request parameter injection | Critical | Immediate | Medium |
| SA-EXPRESS-03 res.sendFile path traversal | Critical | Immediate | Medium |
| SA-EXPRESS-04 Session misconfiguration | High | 1 week | Low |
| SA-EXPRESS-05 Missing rate limiting | Medium | 1 week | Low |
| SA-EXPRESS-06 Missing input validation | High | 1 week | Medium |
| SA-EXPRESS-07 eval in route handlers | Critical | Immediate | Low |
| SA-EXPRESS-08 Error handler info disclosure | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `api-security.md` -- API-level security patterns
- Express.js Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 framework expansion |
