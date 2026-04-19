# Python Security Features by Version

Modern Python versions introduce language features and standard library changes that directly improve security when used correctly. This reference documents security-relevant patterns and features from Python 3.9 through 3.13, with detection regexes for automated auditing.

## Core Python Security Patterns

These patterns apply across all supported Python versions (3.9+) and represent the most common vulnerability classes found in Python codebases.

### 1. Insecure Deserialization via pickle / shelve / marshal

The `pickle` module can execute arbitrary code during deserialization. Any data from an untrusted source that is unpickled can lead to remote code execution. The `shelve` module uses `pickle` internally and inherits the same risk. `marshal` is similarly unsafe.

```python
# VULNERABLE: Deserializing untrusted data with pickle
import pickle

def load_user_session(session_data: bytes):
    # An attacker can craft a pickle payload that executes os.system("rm -rf /")
    return pickle.loads(session_data)

# VULNERABLE: shelve uses pickle internally
import shelve

def load_cache(cache_path: str):
    db = shelve.open(cache_path)  # If cache_path is user-controlled, RCE is possible
    return db["settings"]

# VULNERABLE: marshal is not safe for untrusted data
import marshal

def load_bytecode(data: bytes):
    return marshal.loads(data)
```

```python
# SECURE: Use JSON or other safe serialization formats
import json
from typing import Any

def load_user_session(session_data: str) -> dict[str, Any]:
    return json.loads(session_data)

# SECURE: Sign a JSON payload if you must round-trip server-to-server data.
# Signing a pickle does NOT make it safe — the signature only stops third-
# party tampering; the server still deserializes attacker-crafted data the
# moment its own signature verifies. Use JSON and read the HMAC key from the
# environment (not from source).
import hmac
import hashlib
import os

SIGNING_KEY = os.environb[b"APP_SIGNING_KEY"]  # fail hard if unset

def load_verified_json(signed_data: bytes, signature: bytes) -> Any:
    expected = hmac.new(SIGNING_KEY, signed_data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Data integrity check failed")
    return json.loads(signed_data)

# SECURE: Use RestrictedUnpickler to whitelist allowed classes
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {("builtins", "dict"), ("builtins", "list")}

    def find_class(self, module: str, name: str) -> type:
        if (module, name) not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return super().find_class(module, name)

def safe_unpickle(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

**Security implication:** Insecure deserialization (CWE-502) is consistently ranked in the OWASP Top 10. Pickle payloads can execute arbitrary system commands, exfiltrate data, or establish reverse shells. Never unpickle data from untrusted sources.

### 2. Code Injection via eval() / exec() / compile()

The `eval()` and `exec()` builtins execute arbitrary Python code. When user input reaches these functions, attackers gain full code execution.

```python
# VULNERABLE: eval with user input
def calculate(expression: str) -> float:
    return eval(expression)  # User sends: __import__('os').system('id')

# VULNERABLE: exec with user input
def run_user_script(code: str):
    exec(code)  # Full arbitrary code execution

# VULNERABLE: compile + exec
def execute_template(template_code: str):
    compiled = compile(template_code, "<string>", "exec")
    exec(compiled)
```

```python
# SECURE: Use ast.literal_eval for safe evaluation of literals
import ast

def parse_value(user_input: str):
    return ast.literal_eval(user_input)  # Only allows literals: strings, numbers, tuples, lists, dicts, bools, None

# SECURE: Use a math expression parser for calculations
from decimal import Decimal
import operator

SAFE_OPS = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "/": operator.truediv,
}

def safe_calculate(left: str, op: str, right: str) -> Decimal:
    if op not in SAFE_OPS:
        raise ValueError(f"Unsupported operator: {op}")
    return SAFE_OPS[op](Decimal(left), Decimal(right))
```

**Security implication:** Code injection (CWE-94, CWE-95) allows full system compromise. Even `eval()` with restricted globals can be bypassed. There is no safe way to sandbox `eval()` or `exec()` in CPython.

### 3. Server-Side Template Injection (SSTI) in Jinja2 and Mako

When user input is passed directly as a template string rather than as a template variable, attackers can execute arbitrary code through the template engine.

```python
# VULNERABLE: User input used as Jinja2 template source
from jinja2 import Template

def render_greeting(user_input: str) -> str:
    template = Template(user_input)  # SSTI! User sends: {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
    return template.render()

# VULNERABLE: Jinja2 Environment without sandboxing
from jinja2 import Environment

env = Environment()
template = env.from_string(user_input)  # Same SSTI risk

# VULNERABLE: Mako template injection
from mako.template import Template as MakoTemplate

def render_mako(user_input: str) -> str:
    return MakoTemplate(user_input).render()  # RCE via ${__import__('os').system('id')}
```

```python
# SECURE: Pass user input as a variable, not as the template itself
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

def render_greeting(username: str) -> str:
    template = env.get_template("greeting.html")
    return template.render(username=username)

# SECURE: Use Jinja2 SandboxedEnvironment if dynamic templates are required
from jinja2.sandbox import SandboxedEnvironment

sandbox_env = SandboxedEnvironment()

def render_sandboxed(template_str: str, variables: dict) -> str:
    # SandboxedEnvironment restricts attribute access and method calls
    template = sandbox_env.from_string(template_str)
    return template.render(**variables)
```

**Security implication:** SSTI (CWE-1336) in Python template engines typically leads to Remote Code Execution. Jinja2's default `Environment` does not sandbox templates. Always load templates from files and pass user data as variables.

### 4. Command Injection via subprocess / os.system / os.popen

Passing user input to shell commands without proper sanitization leads to command injection.

```python
# VULNERABLE: subprocess with shell=True
import subprocess

def ping_host(hostname: str):
    subprocess.call(f"ping -c 1 {hostname}", shell=True)
    # User sends: "127.0.0.1; cat /etc/passwd"

# VULNERABLE: os.system always uses the shell
import os

def list_directory(path: str):
    os.system(f"ls -la {path}")  # User sends: "/tmp; rm -rf /"

# VULNERABLE: os.popen uses the shell
def get_disk_usage(path: str) -> str:
    return os.popen(f"du -sh {path}").read()
```

```python
# SECURE: Use subprocess with shell=False (the default) and argument list
import subprocess
import shlex

def ping_host(hostname: str):
    # Validate hostname format first
    if not hostname.replace(".", "").replace("-", "").isalnum():
        raise ValueError("Invalid hostname")
    result = subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout

# SECURE: Use pathlib for filesystem operations instead of shell commands
from pathlib import Path

def list_directory(path: str) -> list[str]:
    target = Path(path).resolve()
    allowed_root = Path("/var/data").resolve()
    if not str(target).startswith(str(allowed_root)):
        raise ValueError("Path outside allowed directory")
    return [str(p) for p in target.iterdir()]
```

**Security implication:** OS command injection (CWE-78) is a critical vulnerability. Using `shell=True` with `subprocess` or any function in the `os.system` / `os.popen` family exposes the application to shell metacharacter injection.

### 5. Unsafe YAML Loading

`yaml.load()` without a safe Loader can execute arbitrary Python objects, leading to code execution.

```python
# VULNERABLE: yaml.load without Loader argument
import yaml

def parse_config(config_str: str) -> dict:
    return yaml.load(config_str)  # Default Loader can instantiate arbitrary Python objects

# VULNERABLE: yaml.load with FullLoader (still allows some dangerous tags)
def parse_data(data: str) -> dict:
    return yaml.load(data, Loader=yaml.FullLoader)
```

```python
# SECURE: Use yaml.safe_load (or SafeLoader)
import yaml

def parse_config(config_str: str) -> dict:
    return yaml.safe_load(config_str)  # Only allows basic Python types

# SECURE: Use yaml.safe_load_all for multi-document YAML
def parse_multi_doc(data: str) -> list:
    return list(yaml.safe_load_all(data))
```

**Security implication:** Unsafe YAML deserialization (CWE-502) allows instantiation of arbitrary Python objects. The `!!python/object` tag in YAML can trigger code execution. Always use `yaml.safe_load()`.

### 6. SQL Injection via String Formatting

Building SQL queries with f-strings, `.format()`, or `%` string formatting with user input causes SQL injection.

```python
# VULNERABLE: f-string in SQL query
import sqlite3

def get_user(db: sqlite3.Connection, username: str):
    cursor = db.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()

# VULNERABLE: .format() in SQL query
def search_users(db, query: str):
    sql = "SELECT * FROM users WHERE name LIKE '%{}%'".format(query)
    return db.execute(sql).fetchall()

# VULNERABLE: % formatting in SQL query
def get_order(db, order_id: str):
    return db.execute("SELECT * FROM orders WHERE id = %s" % order_id).fetchone()

# VULNERABLE: String concatenation in Django raw query
from django.db import connection

def get_user_django(name: str):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
        return cursor.fetchone()
```

```python
# SECURE: Parameterized queries
import sqlite3

def get_user(db: sqlite3.Connection, username: str):
    cursor = db.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()

# SECURE: Django ORM (parameterized by default)
from myapp.models import User

def get_user_django(name: str):
    return User.objects.filter(name=name).first()

# SECURE: SQLAlchemy parameterized query
from sqlalchemy import text

def get_user_alchemy(session, username: str):
    result = session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": username})
    return result.fetchone()

# SECURE: psycopg2 parameterized query
def get_user_pg(conn, username: str):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE name = %s", (username,))
        return cur.fetchone()
```

**Security implication:** SQL injection (CWE-89) remains one of the most exploited vulnerability classes. Python's DB-API 2.0 (PEP 249) supports parameterized queries across all database adapters. Never use string formatting to build SQL.

### 7. XML External Entity (XXE) and Billion Laughs

Python's `xml.etree.ElementTree` and other XML parsers are vulnerable to XXE and entity expansion attacks.

```python
# VULNERABLE: ElementTree with untrusted XML
import xml.etree.ElementTree as ET

def parse_xml(xml_string: str):
    return ET.fromstring(xml_string)
    # Vulnerable to billion laughs (exponential entity expansion)
    # Limited XXE in ElementTree but still risky with other parsers

# VULNERABLE: xml.dom.minidom
from xml.dom.minidom import parseString

def parse_dom(xml_data: str):
    return parseString(xml_data)

# VULNERABLE: lxml without disabling entities
from lxml import etree

def parse_lxml(xml_data: bytes):
    return etree.fromstring(xml_data)  # XXE enabled by default in older lxml
```

```python
# SECURE: Use defusedxml which blocks all XML attacks
import defusedxml.ElementTree as ET

def parse_xml(xml_string: str):
    return ET.fromstring(xml_string)  # XXE and entity expansion blocked

# SECURE: lxml with safe parser settings
from lxml import etree

def parse_lxml(xml_data: bytes):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )
    return etree.fromstring(xml_data, parser=parser)
```

**Security implication:** XXE (CWE-611) can lead to file disclosure, SSRF, and denial of service. The billion laughs attack (CWE-776) causes exponential memory consumption. Use `defusedxml` as a drop-in replacement for all standard library XML parsers.

### 8. Path Traversal via os.path.join

`os.path.join()` silently discards previous path components when a segment is an absolute path, enabling path traversal.

```python
# VULNERABLE: os.path.join with user-supplied filename
import os

UPLOAD_DIR = "/var/uploads"

def get_upload(filename: str) -> str:
    # If filename is "/etc/passwd", os.path.join returns "/etc/passwd"
    return os.path.join(UPLOAD_DIR, filename)

# VULNERABLE: Relative path traversal
def read_document(doc_name: str) -> bytes:
    path = os.path.join(UPLOAD_DIR, doc_name)
    # doc_name = "../../etc/passwd" traverses out of UPLOAD_DIR
    with open(path, "rb") as f:
        return f.read()
```

```python
# SECURE: Use pathlib with resolve() and prefix check
from pathlib import Path

UPLOAD_DIR = Path("/var/uploads").resolve()

def get_upload(filename: str) -> Path:
    # Strip leading slashes and resolve to prevent traversal
    safe_name = Path(filename).name  # Takes only the filename component
    resolved = (UPLOAD_DIR / safe_name).resolve()
    if not str(resolved).startswith(str(UPLOAD_DIR)):
        raise ValueError("Path traversal detected")
    return resolved

# SECURE: os.path.realpath with validation
import os

def read_document(doc_name: str) -> bytes:
    base = os.path.realpath(UPLOAD_DIR)
    full_path = os.path.realpath(os.path.join(base, doc_name))
    if not full_path.startswith(base + os.sep):
        raise ValueError("Path traversal detected")
    with open(full_path, "rb") as f:
        return f.read()
```

**Security implication:** Path traversal (CWE-22) allows attackers to read or write arbitrary files. `os.path.join` is deceptive because it silently handles absolute paths and `..` segments. Always resolve paths and verify they remain within the intended directory.

### 9. JWT Handling Pitfalls

Common JWT library misconfigurations allow token forgery and algorithm confusion attacks.

```python
# VULNERABLE: Not specifying algorithms parameter
import jwt

def verify_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret)
    # Attacker can set alg: "none" in header to bypass verification

# VULNERABLE: Accepting "none" algorithm
def verify_token_weak(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256", "none"])

# VULNERABLE: Using symmetric secret to verify RS256 token
# If the server expects RS256 but accepts HS256, an attacker can sign
# with the public key (which is often public) using HS256
PUBLIC_KEY = open("public.pem").read()

def verify_token_confused(token: str) -> dict:
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
```

```python
# SECURE: Explicit algorithm list, no "none"
import jwt

def verify_token(token: str, secret: str) -> dict:
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],  # Explicit, single algorithm
        options={"require": ["exp", "iat", "sub"]},
    )

# SECURE: Asymmetric verification with strict algorithm
def verify_token_rsa(token: str, public_key: str) -> dict:
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],  # Only RS256, never HS256
        options={"require": ["exp", "iat", "sub"]},
    )
```

**Security implication:** JWT algorithm confusion (CWE-327) and the "none" algorithm bypass allow token forgery. Always specify an explicit `algorithms` list with a single expected algorithm. Never mix symmetric and asymmetric algorithms.

### 10. Weak Hashing Algorithms

Using MD5 or SHA1 for security-sensitive operations (password hashing, integrity verification) is unsafe due to collision attacks.

```python
# VULNERABLE: MD5 for password hashing
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA1 for integrity checking
def verify_integrity(data: bytes, expected_hash: str) -> bool:
    return hashlib.sha1(data).hexdigest() == expected_hash
```

```python
# SECURE: Use bcrypt or argon2 for passwords
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except Exception:
        return False

# SECURE: Use SHA-256 or SHA-3 for integrity, with HMAC for authentication
import hashlib
import hmac

def compute_integrity(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_integrity(data: bytes, key: bytes, expected: str) -> bool:
    computed = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected)
```

**Security implication:** MD5 (CWE-328) and SHA1 are cryptographically broken for collision resistance. MD5 collisions can be computed in seconds. Use bcrypt, scrypt, or argon2 for passwords. Use SHA-256+ or SHA-3 for integrity verification.

### 11. Dynamic Import Abuse via __import__ / importlib

Dynamic imports with user-controlled module names allow loading arbitrary modules.

```python
# VULNERABLE: __import__ with user input
def load_plugin(plugin_name: str):
    module = __import__(plugin_name)  # User sends: "os" -> access to os.system
    return module

# VULNERABLE: importlib with user input
import importlib

def load_handler(handler_name: str):
    module = importlib.import_module(handler_name)
    return module.handle
```

```python
# SECURE: Whitelist allowed modules
ALLOWED_PLUGINS = {"analytics", "reporting", "notifications"}

def load_plugin(plugin_name: str):
    if plugin_name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {plugin_name}")
    module = importlib.import_module(f"app.plugins.{plugin_name}")
    return module

# SECURE: Use entry_points for plugin discovery
from importlib.metadata import entry_points

def load_plugins():
    discovered = entry_points(group="myapp.plugins")
    return {ep.name: ep.load() for ep in discovered}
```

**Security implication:** Unrestricted dynamic imports (CWE-94) allow loading arbitrary standard library modules (e.g., `os`, `subprocess`, `socket`), enabling code execution, file access, and network connections. Always validate module names against a whitelist.

### 12. tempfile Race Conditions

`tempfile.mktemp()` creates a filename but not the file, introducing a TOCTOU (time-of-check to time-of-use) race condition.

```python
# VULNERABLE: mktemp has a race condition
import tempfile
import os

def write_temp_data(data: bytes):
    path = tempfile.mktemp()  # Returns a name, but file doesn't exist yet
    # Another process could create a symlink at this path before we write
    with open(path, "wb") as f:
        f.write(data)
```

```python
# SECURE: Use mkstemp which atomically creates the file
import tempfile
import os

def write_temp_data(data: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix="app_", suffix=".tmp")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path

# SECURE: Use NamedTemporaryFile or TemporaryDirectory
def write_temp_managed(data: bytes) -> str:
    with tempfile.NamedTemporaryFile(delete=False, prefix="app_") as f:
        f.write(data)
        return f.name
```

**Security implication:** TOCTOU race conditions (CWE-367) in temporary file creation can be exploited via symlink attacks to overwrite arbitrary files. `tempfile.mktemp()` is deprecated precisely for this reason. Use `mkstemp()` or `NamedTemporaryFile`.

### 13. Regular Expression Denial of Service (ReDoS)

Poorly constructed regular expressions with nested quantifiers can cause catastrophic backtracking, freezing the application.

```python
# VULNERABLE: Catastrophic backtracking
import re

# This regex takes exponential time on inputs like "aaaaaaaaaaaaaaaaaaaaa!"
EMAIL_REGEX = re.compile(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$")

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

# VULNERABLE: Nested quantifiers
URL_REGEX = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/.*)*$")
```

```python
# SECURE: Avoid nested quantifiers, use possessive-style patterns
import re

# Flattened regex without nested quantifiers
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

def validate_email(email: str) -> bool:
    if len(email) > 254:  # RFC 5321 maximum
        return False
    return bool(EMAIL_REGEX.match(email))

# SECURE: Use a dedicated validation library
from email_validator import validate_email as ev_validate

def validate_email_safe(email: str) -> bool:
    try:
        ev_validate(email, check_deliverability=False)
        return True
    except Exception:
        return False

# SECURE: Set a timeout with re2 (Google's linear-time regex engine)
# pip install google-re2
# import re2
# re2.compile(pattern)  # Guaranteed O(n) matching time
```

**Security implication:** ReDoS (CWE-1333) can cause application-level denial of service. A single malicious input to a vulnerable regex can freeze a web server thread for minutes or hours. Audit all regex patterns that process user input for nested quantifiers.

## Python 3.9

### Dictionary Union Operators for Safe Config Merging

Python 3.9 introduced `|` and `|=` operators for dictionaries, providing a cleaner way to merge configuration defaults with overrides.

```python
# VULNERABLE: Using **kwargs merging allows override of security defaults
def get_config(user_prefs: dict) -> dict:
    defaults = {"debug": False, "allow_admin": False, "max_retries": 3}
    return {**defaults, **user_prefs}  # user_prefs can override "allow_admin"!

# SECURE: Whitelist allowed overrides with 3.9 union operator
ALLOWED_USER_KEYS = {"theme", "language", "max_retries"}

def get_config(user_prefs: dict) -> dict:
    defaults = {"debug": False, "allow_admin": False, "max_retries": 3}
    safe_prefs = {k: v for k, v in user_prefs.items() if k in ALLOWED_USER_KEYS}
    return defaults | safe_prefs  # Clean merge with whitelisted keys only
```

**Security implication:** Uncontrolled dictionary merging can override security-critical configuration keys. The `|` operator itself does not add security, but its readability encourages explicit merge patterns where input filtering is visible.

### Type Hinting Generics in Built-in Collections

Python 3.9 allows `list[int]`, `dict[str, Any]` in annotations without importing from `typing`, making type hints easier and encouraging their use in security-critical code.

```python
# Python 3.9+: Built-in generics for clearer security-related type hints
def validate_allowed_ips(ip_list: list[str]) -> list[str]:
    """Type hints make it clear this expects a list of strings, not raw bytes."""
    import ipaddress
    validated = []
    for ip in ip_list:
        addr = ipaddress.ip_address(ip)  # Raises ValueError on invalid IP
        validated.append(str(addr))
    return validated
```

**Security implication:** Easier type annotations encourage static type checking which catches type confusion bugs at development time rather than runtime.

## Python 3.10

### Structural Pattern Matching for Input Validation

The `match`/`case` statement provides exhaustive pattern matching, ideal for validating and dispatching on structured input.

```python
# VULNERABLE: Complex if/elif chains miss edge cases
def handle_request(action: str, payload: dict):
    if action == "read":
        return read_file(payload["path"])
    elif action == "write":
        write_file(payload["path"], payload["data"])
    # Forgot to handle "delete" -> silently does nothing
    # Forgot to validate payload structure

# SECURE: Structural pattern matching with exhaustive handling
def handle_request(request: dict):
    match request:
        case {"action": "read", "path": str(path)} if path.startswith("/allowed/"):
            return read_file(path)
        case {"action": "write", "path": str(path), "data": str(data)} if path.startswith("/allowed/"):
            return write_file(path, data)
        case {"action": action}:
            raise ValueError(f"Unknown or unauthorized action: {action}")
        case _:
            raise ValueError("Malformed request: missing 'action' field")
```

**Security implication:** Structural pattern matching (PEP 634) enforces structure validation at the language level. The mandatory `case _` wildcard catch-all prevents silent pass-through of malformed or unauthorized requests. Guards (`if` clauses) enable inline authorization checks.

### Parenthesized Context Managers

Python 3.10 allows parenthesized context managers, improving readability for multi-resource security operations.

```python
# SECURE: Multiple security-critical resources managed together
from pathlib import Path
import tempfile

def secure_file_copy(src: Path, dst: Path):
    with (
        open(src, "rb") as source,
        tempfile.NamedTemporaryFile(dir=dst.parent, delete=False) as tmp,
    ):
        tmp.write(source.read())
        # Atomic rename after successful write
        Path(tmp.name).rename(dst)
```

**Security implication:** Grouping multiple context managers ensures all resources are properly cleaned up even when errors occur. This prevents file descriptor leaks and partial writes that could leave systems in insecure states.

## Python 3.11

### tomllib for Safe TOML Parsing

Python 3.11 added `tomllib` to the standard library, providing a safe TOML parser that replaces third-party libraries which may have had code execution vulnerabilities.

```python
# VULNERABLE: Some third-party TOML parsers had code execution issues
# (e.g., toml library with custom decoders)
import toml

config = toml.load("config.toml")  # Depends on third-party library security

# SECURE: Use stdlib tomllib (Python 3.11+)
import tomllib

def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)

# tomllib only parses — no code execution possible
# It reads bytes, preventing encoding-related attacks
```

**Security implication:** Standard library inclusion means fewer third-party dependencies in the trust chain. `tomllib` is read-only and cannot execute code, making it safe for parsing untrusted TOML configuration files.

### Exception Groups and except*

Exception groups allow handling multiple exceptions simultaneously, which is valuable for reporting multiple security validation failures.

```python
# SECURE: Report all validation errors at once using ExceptionGroup
class ValidationError(Exception):
    pass

def validate_input(data: dict) -> dict:
    errors = []
    if not isinstance(data.get("email"), str):
        errors.append(ValidationError("email must be a string"))
    if not isinstance(data.get("age"), int) or data["age"] < 0:
        errors.append(ValidationError("age must be a non-negative integer"))
    if len(data.get("password", "")) < 12:
        errors.append(ValidationError("password must be at least 12 characters"))
    if errors:
        raise ExceptionGroup("Validation failed", errors)
    return data

# Caller handles with except*
try:
    validate_input(user_data)
except* ValidationError as eg:
    for err in eg.exceptions:
        log_validation_failure(str(err))
```

**Security implication:** Exception groups prevent early-exit validation where only the first error is reported, allowing comprehensive input validation in a single pass.

### Fine-grained Error Locations

Python 3.11 provides precise error locations pointing to the exact expression that caused an error, not just the line. This aids security debugging.

**Security implication:** More precise tracebacks reduce debugging time for security issues and make it easier to identify the exact sub-expression involved in a vulnerability.

## Python 3.12

### Type Parameter Syntax (PEP 695)

Python 3.12 introduces cleaner generic type syntax, making security-critical generic code more readable.

```python
# Python 3.12+: New type parameter syntax
type UserId = int
type SessionToken = str

# Clear type aliases for security boundaries
type SanitizedHTML = str
type RawUserInput = str

def sanitize(raw: RawUserInput) -> SanitizedHTML:
    import html
    return html.escape(raw)

# Generic validator with new syntax
def validate_bounded[T: (int, float)](value: T, min_val: T, max_val: T) -> T:
    if not (min_val <= value <= max_val):
        raise ValueError(f"Value {value} out of bounds [{min_val}, {max_val}]")
    return value
```

**Security implication:** Type aliases like `SanitizedHTML` vs `RawUserInput` create semantic boundaries that make it obvious when unsanitized data is being used where sanitized data is expected. Static type checkers can then catch these mismatches.

### Per-Interpreter GIL (PEP 684)

Python 3.12 introduces per-interpreter GIL, enabling true parallel execution with separate interpreters that have isolated state.

```python
# SECURE: Separate interpreters have isolated state
# This prevents cross-contamination between security contexts
# Each interpreter has its own modules, globals, and builtins
# Useful for multi-tenant applications where isolation is critical
```

**Security implication:** Per-interpreter GIL provides stronger isolation than threading for multi-tenant Python applications, as each interpreter has completely separate state, reducing the risk of data leakage between tenants.

## Python 3.13

### warnings.deprecated (PEP 702)

Python 3.13 introduces a `@warnings.deprecated` decorator that can mark security-deprecated functions with clear messages.

```python
# SECURE: Mark insecure functions as deprecated
import warnings

@warnings.deprecated("Use hash_password_argon2() instead — MD5 is cryptographically broken")
def hash_password_md5(password: str) -> str:
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_argon2(password: str) -> str:
    from argon2 import PasswordHasher
    return PasswordHasher().hash(password)

# Type checkers and linters will flag calls to hash_password_md5()
```

**Security implication:** `warnings.deprecated` enables gradual migration away from insecure functions. Unlike comments, the decorator is machine-readable and can be enforced by type checkers and CI tools.

### Improved Error Messages

Python 3.13 continues to improve error messages with better suggestions and more context.

**Security implication:** Clearer error messages help developers identify and fix security misconfigurations faster during development, reducing the risk of deploying vulnerable code.

### Free-Threaded CPython (Experimental)

Python 3.13 introduces an experimental build without the GIL. Multi-threaded code requires more careful attention to thread safety.

```python
# CAUTION: With free-threaded Python, shared mutable state needs explicit synchronization
import threading

# VULNERABLE in free-threaded mode: unsynchronized shared state
rate_limit_counts: dict[str, int] = {}

def check_rate_limit(ip: str) -> bool:
    count = rate_limit_counts.get(ip, 0)  # TOCTOU race
    rate_limit_counts[ip] = count + 1
    return count < 100

# SECURE: Use threading.Lock for shared security state
rate_lock = threading.Lock()

def check_rate_limit_safe(ip: str) -> bool:
    with rate_lock:
        count = rate_limit_counts.get(ip, 0)
        rate_limit_counts[ip] = count + 1
        return count < 100
```

**Security implication:** Free-threaded Python removes the GIL safety net. Race conditions in security-critical code (rate limiting, authentication checks, session management) that were previously masked by the GIL will now manifest as real bugs.

## Detection Patterns for Auditing Python Security Features

| Pattern | Regex | Severity |
|---------|-------|----------|
| Insecure deserialization via pickle | `pickle\.(loads\|load)\(` | error |
| Code injection via eval() | `eval\(` | error |
| Code injection via exec() | `exec\(` | error |
| Command injection via subprocess shell=True | `subprocess\.\w+\(.*shell\s*=\s*True` | error |
| Command injection via os.system | `os\.system\(` | error |
| Unsafe YAML loading | `yaml\.load\(` | error |
| SQL injection via f-string in query | `execute\(f"` | error |
| SQL injection via .format() in query | `execute\(.*\.format\(` | error |
| Weak hash: MD5 for security | `hashlib\.md5\(` | warning |
| Weak hash: SHA1 for security | `hashlib\.sha1\(` | warning |
| Deprecated tempfile.mktemp | `tempfile\.mktemp\(` | error |
| Dynamic import with __import__ | `__import__\(` | warning |
| XML parsing without defusedxml | `xml\.etree\.ElementTree` | warning |
| Jinja2 Template with variable | `Template\s*\(.*\w+.*\)` | warning |
| Command injection via os.popen | `os\.popen\(` | error |
| Code injection via compile() | `compile\(.*,.*,` | warning |
| Insecure deserialization via shelve | `shelve\.open\(` | warning |
| Insecure deserialization via marshal | `marshal\.loads\(` | warning |

## Version Adoption Security Checklist

- [ ] Audit all `pickle.loads()` / `shelve.open()` / `marshal.loads()` calls for untrusted data
- [ ] Replace all `eval()` / `exec()` with safe alternatives (`ast.literal_eval`, parser libraries)
- [ ] Ensure Jinja2 templates load from files, not from user-supplied strings
- [ ] Verify all `subprocess` calls use `shell=False` (the default) with argument lists
- [ ] Replace `yaml.load()` with `yaml.safe_load()` everywhere
- [ ] Audit all SQL queries for string formatting; use parameterized queries
- [ ] Replace `xml.etree.ElementTree` with `defusedxml.ElementTree`
- [ ] Validate all file paths with `resolve()` and prefix checks
- [ ] Verify JWT `algorithms` parameter is explicit and does not include `"none"`
- [ ] Replace `hashlib.md5` / `hashlib.sha1` with SHA-256+ for integrity, argon2/bcrypt for passwords
- [ ] Replace `tempfile.mktemp()` with `tempfile.mkstemp()` or `NamedTemporaryFile`
- [ ] Audit regex patterns processing user input for catastrophic backtracking
- [ ] (3.11+) Migrate TOML parsing to `tomllib`
- [ ] (3.12+) Adopt type aliases for security boundaries (`SanitizedHTML` vs `RawUserInput`)
- [ ] (3.13+) Mark deprecated insecure functions with `@warnings.deprecated`
- [ ] (3.13+) Audit thread safety for free-threaded CPython builds

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `php-security-features.md` — PHP security features reference
- `nodejs-security-features.md` — Node.js security features reference

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 4 |