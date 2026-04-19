# Ruby Security Features by Version

Modern Ruby versions introduce language features that directly improve security when used correctly. This reference documents security-relevant patterns and version-specific features from Ruby 3.0 through 3.3, covering the most critical vulnerability classes in Ruby and Ruby on Rails applications.

## Core Ruby Security Patterns

### SA-RB-01: eval / instance_eval / class_eval Code Injection

Ruby's `eval` family executes arbitrary strings as code. When user input reaches these methods, attackers gain full code execution on the server.

```ruby
# VULNERABLE: eval with user-controlled input (CWE-94)
# An attacker sending "system('rm -rf /')" as input gets shell access
def calculate(user_expression)
  eval(user_expression)
end

# SECURE: Use a predefined method dispatch instead of eval
ALLOWED_FILTERS = {
  'uppercase' => ->(obj) { obj.to_s.upcase },
  'lowercase' => ->(obj) { obj.to_s.downcase },
  'strip'     => ->(obj) { obj.to_s.strip }
}.freeze

def apply_filter(obj, filter_name)
  handler = ALLOWED_FILTERS[filter_name]
  raise ArgumentError, "Unknown filter: #{filter_name}" unless handler
  handler.call(obj)
end
```

**Security implication:** `eval` is the most dangerous method in Ruby. Any path from user input to `eval`, `instance_eval`, or `class_eval` with a string argument constitutes a Remote Code Execution (RCE) vulnerability. Even indirect paths through template engines or configuration parsers must be audited. CWE-94: Improper Control of Generation of Code.

**Detection regex:** `\beval\s*\(` , `\binstance_eval\s*[\(\s]` , `\bclass_eval\s*[\(\s]`

---

### SA-RB-02: send / public_send Method Injection

Ruby's `send` method invokes any method by name, including private ones. When the method name comes from user input, attackers can call arbitrary methods on any object.

```ruby
# VULNERABLE: send with user-controlled method name (CWE-470)
# Attacker sends method_name="system" with args=["cat /etc/passwd"]
def perform_action(obj, method_name, *args)
  obj.send(method_name, *args)
end

# SECURE: Allowlist of permitted methods
ALLOWED_METHODS = %w[name email created_at updated_at].freeze

def perform_action(obj, method_name)
  unless ALLOWED_METHODS.include?(method_name)
    raise ArgumentError, "Method not allowed: #{method_name}"
  end
  obj.public_send(method_name)
end

# SECURE: Use a case/when dispatch
def perform_action(obj, action)
  case action
  when 'activate'   then obj.activate
  when 'deactivate' then obj.deactivate
  else raise ArgumentError, "Unknown action: #{action}"
  end
end
```

**Security implication:** `send` bypasses method visibility (private/protected). Even `public_send` is dangerous when the method name is attacker-controlled, as it can invoke destructive public methods like `delete`, `destroy`, or `system`. CWE-470: Use of Externally-Controlled Input to Select Classes or Code.

**Detection regex:** `\.send\s*\(` , `\.public_send\s*\(`

---

### SA-RB-03: system / exec / backtick Command Injection

Ruby provides multiple ways to execute shell commands. String interpolation or concatenation with user input enables OS command injection.

```ruby
# VULNERABLE: system() with string interpolation (CWE-78)
# Attacker sends filename="; rm -rf /"
def convert_file(filename)
  system("convert #{filename} output.png")
end

# VULNERABLE: backticks with user input
def get_file_info(path)
  `file #{path}`
end

# SECURE: Use array form to avoid shell interpretation
def convert_file(filename)
  system('convert', filename, 'output.png')
end

# SECURE: Use Open3 for capturing output safely
require 'open3'

def get_file_info(path)
  stdout, stderr, status = Open3.capture3('file', path)
  raise "Command failed: #{stderr}" unless status.success?
  stdout
end

# SECURE: Shellwords.shellescape if shell form is unavoidable
require 'shellwords'

def convert_file(filename)
  system("convert #{Shellwords.shellescape(filename)} output.png")
end
```

**Security implication:** Ruby's `system`, `exec`, `%x{}`, and backticks all invoke a shell when given a single string argument. The array form of `system` and `exec` bypasses the shell entirely, making it immune to injection. Always prefer the array form. CWE-78: Improper Neutralization of Special Elements used in an OS Command.

**Detection regex (run each separately):**

```bash
# System / exec calls that take a single string (shell invocation) — check the array-vs-string form manually.
grep -rnE '\b(system|exec)\s*\(' --include='*.rb' .
# Backtick invocations containing #{...} interpolation — the backtick
# here is escaped with a backslash to keep the inline code span intact.
grep -rnP '\x60[^\x60]*#\{' --include='*.rb' .
```

---

### SA-RB-04: Marshal.load Insecure Deserialization

`Marshal.load` deserializes arbitrary Ruby objects. A crafted payload can instantiate any class and trigger code execution through methods like `initialize`, method_missing, or finalizers.

```ruby
# VULNERABLE: Marshal.load on untrusted data (CWE-502)
# Attacker can craft a payload that executes arbitrary code on deserialization
def restore_session(cookie_data)
  session = Marshal.load(Base64.decode64(cookie_data))
  session
end

# SECURE: Use JSON for untrusted data
require 'json'

def restore_session(cookie_data)
  session = JSON.parse(Base64.decode64(cookie_data))
  session
end

# SECURE: If Marshal is absolutely needed, use a class filter
def restore_session(cookie_data)
  raw = Base64.decode64(cookie_data)
  allowed = [String, Integer, Float, Symbol, TrueClass, FalseClass, NilClass, Array, Hash]
  Marshal.load(raw, ->(obj) {
    raise TypeError, "Disallowed: #{obj.class}" unless allowed.include?(obj.class)
    obj
  })
end
```

**Security implication:** `Marshal.load` is functionally equivalent to `eval` for attacker-controlled data. There are well-known gadget chains in Ruby and Rails that achieve RCE through crafted Marshal payloads. Never use Marshal for data from untrusted sources. CWE-502: Deserialization of Untrusted Data.

**Detection regex:** `Marshal\.load\s*\(`

---

### SA-RB-05: YAML Deserialization (YAML.load vs YAML.safe_load)

`YAML.load` can instantiate arbitrary Ruby objects via YAML tags like `!ruby/object:`. This enables RCE when parsing untrusted YAML input.

```ruby
# VULNERABLE: YAML.load on untrusted input (CWE-502)
# Payload: "--- !ruby/object:Gem::Installer\ni: x\n" triggers code execution
def parse_config(user_yaml)
  config = YAML.load(user_yaml)
  config
end

# SECURE: Use YAML.safe_load (restricts to basic types)
def parse_config(user_yaml)
  config = YAML.safe_load(user_yaml, permitted_classes: [Date, Time])
  config
end

# SECURE: In Ruby 3.1+, YAML.load requires permitted_classes by default
# But explicit safe_load is still clearer and safer
def parse_config(user_yaml)
  YAML.safe_load(user_yaml)
end
```

**Security implication:** `YAML.load` was the source of multiple critical Rails CVEs (CVE-2013-0156). Since Psych 4.0 (Ruby 3.1+), `YAML.load` raises on unknown tags by default, but `YAML.safe_load` remains the explicit safe choice. Always use `safe_load` for untrusted data. CWE-502: Deserialization of Untrusted Data.

**Detection regex:** `YAML\.load\s*\(` (not preceded by `safe_`)

---

### SA-RB-06: ERB Template Injection

ERB templates execute arbitrary Ruby code within `<%= %>` tags. When user input is embedded into ERB template strings before rendering, server-side template injection (SSTI) occurs.

```ruby
# VULNERABLE: ERB template injection (CWE-94)
# Attacker sends name="<%= system('id') %>"
def render_greeting(name)
  template = ERB.new("Hello, #{name}!")
  template.result(binding)
end

# SECURE: Pass user input as data, not template content
def render_greeting(name)
  # Match the template variable to the hash key. `result_with_hash`
  # binds locals, so the template must reference `<%= name %>`, not
  # `@name` (which is an instance variable and wouldn't be set).
  template = ERB.new("Hello, <%= name %>!")
  template.result_with_hash(name: ERB::Util.html_escape(name))
end

# SECURE: Use a safe templating engine like Liquid for user templates
require 'liquid'

def render_page(user_template, data)
  template = Liquid::Template.parse(user_template)
  template.render(data)
end
```

**Security implication:** ERB has full access to the Ruby runtime. If user input becomes part of an ERB template string before compilation, the attacker controls what Ruby code runs on the server. Use sandboxed template engines (Liquid, Mustache) for user-facing templates. CWE-94: Improper Control of Generation of Code.

**Detection regex:** `ERB\.new\s*\(` (audit when argument contains interpolation or variables)

---

### SA-RB-07: SQL Injection in ActiveRecord

While ActiveRecord parameterizes queries by default, several methods accept raw SQL strings. String interpolation in these contexts creates SQL injection vulnerabilities.

```ruby
# VULNERABLE: String interpolation in where clause (CWE-89)
def search_users(query)
  User.where("name LIKE '%#{query}%'")
end

# VULNERABLE: find_by_sql with interpolation
def find_user(id)
  User.find_by_sql("SELECT * FROM users WHERE id = #{id}")
end

# SECURE: Use parameterized queries
def search_users(query)
  User.where('name LIKE ?', "%#{query}%")
end

# SECURE: Use hash conditions
def find_active_users(status)
  User.where(status: status)
end

```

**Security implication:** ActiveRecord's `where` with a string, `find_by_sql`, `order`, `group`, `having`, `pluck`, `select`, and `from` all accept raw SQL. String interpolation in any of these is a SQL injection vector. Always use parameterized queries (`?` placeholders) or hash conditions. CWE-89: SQL Injection.

**Detection regex:** `find_by_sql\s*\(` , `\.where\s*\(\s*"[^"]*#\{`

---

### SA-RB-08: html_safe / raw XSS Bypass in Rails Views

Rails auto-escapes output in ERB views by default. However, `html_safe`, `raw()`, and `<%== %>` bypass this protection, creating XSS vulnerabilities when used with user-controlled data.

```ruby
# VULNERABLE: html_safe on user input (CWE-79)
# In a Rails view:
# <%= user.bio.html_safe %>

# VULNERABLE: raw() helper with user data
# <%= raw(params[:message]) %>

# VULNERABLE: <%== %> shorthand (equivalent to raw)
# <%== comment.body %>

# SECURE: Let Rails auto-escape (default behavior)
# <%= user.bio %>

# SECURE: Use sanitize helper for partial HTML
# <%= sanitize(user.bio, tags: %w[b i em strong], attributes: %w[]) %>

```

**Security implication:** Rails' automatic output escaping is the primary XSS defense. Every use of `html_safe`, `raw()`, or `<%== %>` is a deliberate bypass that must be audited. The content must either be fully trusted (generated server-side with no user input) or sanitized before marking as safe. CWE-79: Cross-site Scripting.

**Detection regex:** `\.html_safe\b` , `\braw\s*\(`

---

### SA-RB-09: Mass Assignment Without Strong Parameters

Rails strong parameters protect against mass assignment attacks. Without them, attackers can set any model attribute, including admin flags and foreign keys.

```ruby
# VULNERABLE: Mass assignment without strong parameters (CWE-915)
def create
  @user = User.new(params[:user])
  @user.save
end

# VULNERABLE: permit! allows all parameters
def update
  @user.update(params[:user].permit!)
  redirect_to @user
end

# SECURE: Use strong parameters to allowlist attributes
def user_params
  params.require(:user).permit(:name, :email, :password, :password_confirmation)
end

def create
  @user = User.new(user_params)
  @user.save
end

```

**Security implication:** Without strong parameters, an attacker can add `admin=true` or `role=superadmin` to form submissions. Always use `permit` with an explicit list of allowed attributes. Never use `permit!` in production code. CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes.

**Detection regex:** `\.permit!\b`

---

### SA-RB-10: Kernel.open / open-uri SSRF and Pipe Injection

Ruby's `Kernel.open` (and the `open-uri` library) can open URLs, files, and even execute commands via the pipe (`|`) prefix. User input in `open()` calls can lead to SSRF or RCE.

```ruby
# VULNERABLE: Kernel.open with user input (CWE-918, CWE-78)
# Attacker sends url="|cat /etc/passwd"
def fetch_content(url)
  content = open(url).read
  content
end

# SECURE: Use Net::HTTP with URL validation
require 'net/http'
require 'uri'

ALLOWED_HOSTS = %w[api.example.com cdn.example.com].freeze

def fetch_content(url)
  uri = URI.parse(url)
  raise "Invalid scheme" unless %w[http https].include?(uri.scheme)
  raise "Host not allowed" unless ALLOWED_HOSTS.include?(uri.host)
  raise "Private IP" if private_ip?(uri.host)

  Net::HTTP.get(uri)
end

# SECURE: Use specific file operations instead of open()
def read_file(path)
  File.read(path)  # Does not interpret pipe prefix
end
```

**Security implication:** `Kernel.open` with a string starting with `|` executes the rest as a shell command. Even without the pipe prefix, user-controlled URLs enable SSRF attacks against internal services. Always use `Net::HTTP`, `URI.open` with strict validation, or `File.read` for files. CWE-918: Server-Side Request Forgery, CWE-78: OS Command Injection.

**Detection regex:** `\bKernel\.open\s*\(` , `\bopen\s*\(\s*[^)]*(?:params|request|user|input|url|uri)`

---

### SA-RB-11: Path Traversal

`File.join`, `send_file`, and path concatenation with user input can allow directory traversal to access files outside the intended directory.

```ruby
# VULNERABLE: Path traversal via File.join (CWE-22)
# Attacker sends filename="../../etc/passwd"
def serve_file(filename)
  path = File.join(Rails.root, 'public', 'uploads', filename)
  send_file(path)
end

# SECURE: Validate the resolved path stays within the base directory
def serve_file(filename)
  base_dir = File.realpath(File.join(Rails.root, 'public', 'uploads'))
  full_path = File.realpath(File.join(base_dir, filename))

  unless full_path.start_with?(base_dir + '/')
    raise SecurityError, "Path traversal detected"
  end

  send_file(full_path)
end

```

**Security implication:** `File.join` does not sanitize `..` sequences. An attacker can traverse to any file readable by the application process. Always resolve the full path with `File.realpath` and verify it stays within the expected base directory. CWE-22: Improper Limitation of a Pathname to a Restricted Directory.

**Detection regex:** `send_file\s*\(` , `File\.join\s*\([^)]*params`

---

### SA-RB-12: Weak Cryptography (MD5, SHA1 for Security Tokens)

Using MD5 or SHA1 for password hashing, token generation, or integrity verification provides inadequate security against modern attacks.

```ruby
# VULNERABLE: MD5 for password hashing (CWE-327)
require 'digest'

def hash_password(password)
  Digest::MD5.hexdigest(password)
end

# VULNERABLE: SHA1 for API tokens
def generate_token(user_id)
  Digest::SHA1.hexdigest("#{user_id}-#{Time.now}")
end

# SECURE: Use bcrypt for password hashing
require 'bcrypt'

def hash_password(password)
  BCrypt::Password.create(password, cost: 12)
end

def verify_password(password, hash)
  BCrypt::Password.new(hash) == password
end

# SECURE: Use SecureRandom for token generation
require 'securerandom'

def generate_token
  SecureRandom.urlsafe_base64(32)
end

# SECURE: Use SHA-256 or stronger for integrity checks
def compute_checksum(data)
  Digest::SHA256.hexdigest(data)
end
```

**Security implication:** MD5 has known collision attacks and is broken for any security use. SHA1 is deprecated for security purposes (SHAttered attack). Use bcrypt/scrypt/argon2 for passwords and SecureRandom for tokens. CWE-327: Use of a Broken or Risky Cryptographic Algorithm.

**Detection regex:** `Digest::MD5` , `Digest::SHA1`

---

## Ruby 3.0

### Ractor for Thread-Safe Concurrency

Ractors provide actor-based concurrency with strict object isolation. Objects shared between Ractors must be immutable (frozen), preventing race conditions on shared mutable state.

```ruby
# VULNERABLE: Thread with shared mutable state (CWE-362)
session_store = {}
threads = 10.times.map do |i|
  Thread.new { session_store["user_#{i}"] = { role: 'admin' } }
end
threads.each(&:join)

# SECURE: Ractor enforces isolation — no shared mutable state
results = 10.times.map do |i|
  Ractor.new(i) do |idx|
    { "user_#{idx}" => { role: 'viewer' } }
  end
end
session_store = results.map(&:take).reduce({}, :merge)
```

**Security implication:** Ractors make data races impossible by enforcing that only frozen (immutable) or copied objects cross Ractor boundaries. This eliminates a class of concurrency bugs that can lead to privilege escalation or state corruption. CWE-362: Race Condition.

### Pattern Matching for Structured Input Validation

Ruby 3.0 introduced `case/in` pattern matching, enabling expressive validation of complex data structures.

```ruby
# VULNERABLE: Manual hash access without validation
def process_webhook(payload)
  event = payload['event']
  user_id = payload['data']['user_id']
  # NoMethodError if structure is unexpected, potential crash
  handle_event(event, user_id)
end

# SECURE: Pattern matching validates structure and extracts values
def process_webhook(payload)
  case payload
  in { 'event' => String => event, 'data' => { 'user_id' => Integer => user_id } }
    handle_event(event, user_id)
  in { 'event' => String => event }
    handle_event_without_user(event)
  else
    raise ArgumentError, "Invalid webhook payload structure"
  end
end
```

**Security implication:** Pattern matching validates both structure and types in a single expression, reducing the chance of processing malformed input that could lead to unexpected behavior or crashes. It makes data validation explicit and exhaustive.

---

## Ruby 3.1

### Data Class for Immutable Value Objects

The `Data` class (Ruby 3.1.1+) creates simple immutable value objects, ideal for security-sensitive data that should not be modified after creation.

```ruby
# VULNERABLE: Struct is mutable by default
Token = Struct.new(:value, :expires_at, :scope)
token = Token.new('abc123', Time.now + 3600, 'read')
token.scope = 'admin'  # Attacker modifies scope after creation!

# SECURE: Data class creates immutable value objects
Token = Data.define(:value, :expires_at, :scope)
token = Token.new(value: 'abc123', expires_at: Time.now + 3600, scope: 'read')
token.scope = 'admin'  # => NoMethodError: undefined method 'scope=' — immutable!

# SECURE: Use Data for security configuration
SecurityConfig = Data.define(:algorithm, :key_size, :iterations)
config = SecurityConfig.new(algorithm: 'argon2id', key_size: 256, iterations: 3)
# config is frozen and cannot be tampered with
```

**Security implication:** Immutable value objects prevent tampering with security-critical data after initialization. Unlike Struct (which has setters) or OpenStruct (which allows arbitrary attributes), Data objects cannot be modified. Use Data for tokens, credentials, security configs, and audit records.

### YAML.load Restricted by Default (Psych 4.0)

Starting with Ruby 3.1 (Psych 4.0), `YAML.load` restricts which classes can be instantiated by default. However, `YAML.safe_load` remains the recommended approach as it communicates intent clearly and provides defense in depth.

```ruby
# Always use safe_load for untrusted input, even on Ruby 3.1+
config = YAML.safe_load(untrusted_yaml, permitted_classes: [Date, Time])
```

---

## Ruby 3.2

### Regexp.timeout for ReDoS Protection

Ruby 3.2 introduced `Regexp.timeout` to prevent Regular Expression Denial of Service (ReDoS) attacks where crafted input causes catastrophic backtracking.

```ruby
# VULNERABLE: Regex without timeout (CWE-1333)
# Input like "aaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential backtracking
def validate_email(input)
  input.match?(/^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@[a-zA-Z0-9]+(\.[a-zA-Z]+)+$/)
end

# SECURE: Set a global regex timeout (Ruby 3.2+)
Regexp.timeout = 1.0  # 1 second timeout for all regexps

# SECURE: Set per-regex timeout
pattern = Regexp.new(
  '^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@[a-zA-Z0-9]+(\.[a-zA-Z]+)+$',
  timeout: 0.5
)

begin
  input.match?(pattern)
rescue Regexp::TimeoutError
  false  # Treat timeout as validation failure
end

# SECURE: Use atomic groups or possessive quantifiers to prevent backtracking
def validate_email(input)
  # Simplified non-backtracking pattern
  input.match?(/\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/)
end
```

**Security implication:** ReDoS is a denial-of-service attack that exploits vulnerable regex patterns. `Regexp.timeout` provides a safety net, but the best defense is writing non-backtracking patterns. Set a global timeout as defense in depth. CWE-1333: Inefficient Regular Expression Complexity.

### Anonymous Method Forwarding

Anonymous `*` and `**` forwarding reduces the risk of accidentally exposing or logging sensitive parameters.

```ruby
# VULNERABLE: Named splat can leak sensitive params in logs/errors
def authenticate(username, password, **options)
  log("Auth attempt: #{options.inspect}")  # Might leak sensitive data
  do_auth(username, password, **options)
end

# SECURE: Anonymous forwarding — no local variable to leak
def authenticate(username, password, **)
  do_auth(username, password, **)
end
```

**Security implication:** Anonymous forwarding prevents accidental exposure of forwarded arguments in logs, error messages, or debugging output. This is a minor but useful defense against information leakage.

---

## Ruby 3.3

### YJIT Performance and Security Implications

Ruby 3.3 made YJIT (Yet Another JIT compiler) production-ready with significant performance improvements. JIT compilation has security implications that must be considered.

```ruby
# Enable YJIT: RUBY_YJIT_ENABLE=1 ruby app.rb
# Or: ruby --yjit app.rb
# YJIT is safe for production — respects W^X memory protection
```

**Security implication:** YJIT follows W^X (Write XOR Execute) memory protection, mitigating JIT spraying attacks. Performance gains also reduce the impact of algorithmic complexity DoS attacks.

### Range#overlap? for Secure Range Validation

Ruby 3.3 added `Range#overlap?` for checking if two ranges intersect, useful for time-based access control and resource scheduling.

```ruby
# VULNERABLE: Manual range overlap check is error-prone
def time_slot_available?(requested_start, requested_end, bookings)
  bookings.none? do |booking|
    # Easy to get boundary conditions wrong
    requested_start < booking.end_time && requested_end > booking.start_time
  end
end

# SECURE: Use Range#overlap? for correct boundary handling (Ruby 3.3+)
def time_slot_available?(requested_range, bookings)
  bookings.none? do |booking|
    requested_range.overlap?(booking.start_time..booking.end_time)
  end
end
```

**Security implication:** Incorrect range comparisons in access control (time-based permissions, IP ranges, date validity) can create authorization bypasses. `Range#overlap?` provides a well-tested, correct implementation that handles edge cases.

---

## Detection Patterns for Auditing Ruby Security

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| eval() code injection | `\beval\s*\(` | error | SA-RB-01 |
| instance_eval code injection | `\binstance_eval\s*[\(\s]` | error | SA-RB-01b |
| send() method injection | `\.send\s*\(` | warning | SA-RB-02 |
| system() command injection | `\bsystem\s*\(` | warning | SA-RB-03 |
| exec() command injection | `\bexec\s*\(` | warning | SA-RB-03b |
| Marshal.load deserialization | `Marshal\.load\s*\(` | error | SA-RB-04 |
| YAML.load (unsafe) | `YAML\.load\b(?!_file)` | error | SA-RB-05 |
| ERB.new with variable | `ERB\.new\s*\(` | warning | SA-RB-06 |
| find_by_sql injection | `find_by_sql\s*\(` | error | SA-RB-07 |
| html_safe XSS bypass | `\.html_safe\b` | warning | SA-RB-08 |
| raw() XSS bypass | `\braw\s*\(` | warning | SA-RB-08b |
| permit! mass assignment | `\.permit!\b` | error | SA-RB-09 |
| Kernel.open pipe injection | `\bKernel\.open\s*\(` | error | SA-RB-10 |
| Digest::MD5 weak crypto | `Digest::MD5` | warning | SA-RB-12 |
| Digest::SHA1 weak crypto | `Digest::SHA1` | warning | SA-RB-13 |
| send_file path traversal | `send_file\s*\(` | warning | SA-RB-14 |

## Version Adoption Security Checklist

| Ruby Version | Feature | Security Benefit | Audit Action |
|-------------|---------|------------------|--------------|
| 3.0 | Ractor | Eliminates shared mutable state | Use for concurrent security-critical operations |
| 3.0 | Pattern matching | Structured input validation | Replace manual hash traversal for webhook/API payloads |
| 3.1 | Data class | Immutable value objects | Use for tokens, credentials, security configs |
| 3.1 | Psych 4.0 | YAML.load restricted by default | Still use safe_load explicitly for clarity |
| 3.2 | Regexp.timeout | ReDoS protection | Set global timeout, audit regex patterns |
| 3.2 | Anonymous forwarding | Prevents parameter leakage | Use for auth/security method wrappers |
| 3.3 | YJIT (production) | DoS resilience via performance | Enable in production for compute-heavy apps |
| 3.3 | Range#overlap? | Correct range comparisons | Use for time-based access control |

- [ ] Upgrade to Ruby 3.2+ and set `Regexp.timeout` globally
- [ ] Replace all `YAML.load` with `YAML.safe_load`
- [ ] Audit all `eval`, `instance_eval`, `class_eval`, `send` calls
- [ ] Replace `Marshal.load` on untrusted data with JSON
- [ ] Ensure shell commands use array form of `system`/`exec`
- [ ] Audit all `html_safe` and `raw()` in views
- [ ] Verify strong parameters in all controllers (no `permit!`)
- [ ] Replace `Kernel.open` with `File.read` or `Net::HTTP`
- [ ] Replace MD5/SHA1 with SHA-256+ or bcrypt

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `cwe-top25.md` -- CWE Top 25 mapping
- `input-validation.md` -- Input validation patterns
- `php-security-features.md` -- PHP security reference (similar structure)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Ruby language security reference for security-audit skill |
