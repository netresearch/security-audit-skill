# Flask Security Patterns

Security patterns, common misconfigurations, and detection regexes for Flask applications. Covers Jinja2 SSTI, request parameter injection, path traversal, client-side session tampering, debug mode, CORS misconfiguration, session fixation, and SQLAlchemy raw query injection.

## Injection

### SA-FLASK-01: Jinja2 Server-Side Template Injection (SSTI)

When user input is passed directly into Jinja2 template strings (not template files), attackers can execute arbitrary Python code on the server. This occurs when `render_template_string()` is used with unsanitized input or when templates are constructed from user data.

```python
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)

# VULNERABLE: User input in render_template_string
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
    # Attacker: ?name={{config.items()}}
    # Attacker: ?name={{''.__class__.__mro__[1].__subclasses__()}}

# VULNERABLE: Template constructed from user input
@app.route("/page")
def dynamic_page():
    header = request.args.get("header", "Welcome")
    body = request.args.get("body", "")
    template = "<h1>" + header + "</h1><p>" + body + "</p>"
    return render_template_string(template)

# VULNERABLE: User input as format string then rendered
@app.route("/email-preview")
def email_preview():
    template_str = request.form.get("template")
    return render_template_string(template_str)  # Full SSTI

# SECURE: Pass user input as template variable
@app.route("/greet")
def greet_safe():
    name = request.args.get("name", "World")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)

# SECURE: Use render_template with .html files
@app.route("/greet")
def greet_safest():
    name = request.args.get("name", "World")
    return render_template("greet.html", name=name)

# SECURE: Use Jinja2 sandbox for user-provided templates
from jinja2.sandbox import SandboxedEnvironment

sandbox = SandboxedEnvironment()

@app.route("/custom-template")
def custom_template():
    template_str = request.form.get("template")
    template = sandbox.from_string(template_str)
    return template.render(data=get_safe_data())
```

**Detection regex:** `render_template_string\s*\(`
**Severity:** error

### SA-FLASK-02: Request Parameter Injection

Flask's `request.args`, `request.form`, and `request.values` return user-controlled data. Using this data without validation in database queries, shell commands, file operations, or URL construction leads to injection vulnerabilities.

```python
from flask import Flask, request, redirect
import subprocess
import os

app = Flask(__name__)

# VULNERABLE: request.args in shell command
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()
    # Attacker: ?host=localhost;cat /etc/passwd

# VULNERABLE: request.args in file path
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    path = os.path.join("/app/data/", filename)
    return open(path).read()
    # Attacker: ?file=../../etc/passwd

# VULNERABLE: request.args in redirect
@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
    # Attacker: ?next=https://evil.com

# SECURE: Validate and sanitize input
import re
from urllib.parse import urlparse

@app.route("/ping")
def ping_safe():
    host = request.args.get("host", "localhost")
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return "Invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],  # list form, no shell=True
        capture_output=True
    )
    return result.stdout.decode()

@app.route("/login")
def login_safe():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    if parsed.netloc and parsed.netloc != request.host:
        next_url = "/"
    return redirect(next_url)
```

**Detection regex:** `request\.args\s*\[|request\.args\.get\s*\(|request\.form\s*\[|request\.form\.get\s*\(|request\.values`
**Severity:** warning

### SA-FLASK-06: SQLAlchemy Raw Query Injection

SQLAlchemy provides an ORM that generates parameterized queries by default. However, using `text()`, `execute()`, or string concatenation to build queries introduces SQL injection vulnerabilities.

```python
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
db = SQLAlchemy(app)

# VULNERABLE: String formatting in execute()
@app.route("/users")
def search_users():
    name = request.args.get("name")
    result = db.session.execute(
        f"SELECT * FROM users WHERE name = '{name}'"
    )
    return jsonify([dict(r) for r in result])

# VULNERABLE: String concatenation with text()
@app.route("/products")
def search_products():
    category = request.args.get("cat")
    query = text("SELECT * FROM products WHERE category = '" + category + "'")
    result = db.session.execute(query)
    return jsonify([dict(r) for r in result])

# VULNERABLE: %-formatting in raw SQL
@app.route("/orders")
def get_orders():
    user_id = request.args.get("user_id")
    sql = "SELECT * FROM orders WHERE user_id = %s" % user_id
    result = db.engine.execute(sql)
    return jsonify([dict(r) for r in result])

# SECURE: Use parameterized text() queries
@app.route("/users")
def search_users_safe():
    name = request.args.get("name")
    result = db.session.execute(
        text("SELECT * FROM users WHERE name = :name"),
        {"name": name}
    )
    return jsonify([dict(r) for r in result])

# SECURE: Use ORM query methods
@app.route("/users")
def search_users_orm():
    name = request.args.get("name")
    users = User.query.filter_by(name=name).all()
    return jsonify([u.to_dict() for u in users])

# SECURE: Use parameterized execute with bound parameters
@app.route("/products")
def search_products_safe():
    category = request.args.get("cat")
    stmt = text("SELECT * FROM products WHERE category = :cat")
    result = db.session.execute(stmt.bindparams(cat=category))
    return jsonify([dict(r) for r in result])
```

**Detection regex:** `db\.session\.execute\s*\(\s*f["\']|db\.session\.execute\s*\(\s*["\'].*%s.*["\']\s*%|db\.engine\.execute\s*\(\s*f["\']|\.execute\s*\(\s*f["\']SELECT|\.execute\s*\(\s*f["\']INSERT|\.execute\s*\(\s*f["\']UPDATE|\.execute\s*\(\s*f["\']DELETE`
**Severity:** error

## Security Misconfiguration

### SA-FLASK-03: Path Traversal via send_file / send_from_directory

Flask's `send_file()` and `send_from_directory()` serve files from the filesystem. If user input is used to construct file paths without proper sanitization, attackers can read arbitrary files.

```python
from flask import Flask, request, send_file, send_from_directory
import os

app = Flask(__name__)

# VULNERABLE: send_file with user-controlled path
@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(f"/app/uploads/{filename}")
    # Attacker: ?file=../../etc/passwd

# VULNERABLE: os.path.join does not prevent traversal
@app.route("/static/<path:filename>")
def serve_static(filename):
    filepath = os.path.join("/app/static/", filename)
    return send_file(filepath)
    # Attacker: /static/../../etc/passwd

# SECURE: Use send_from_directory (validates path stays within directory)
@app.route("/download")
def download_safe():
    filename = request.args.get("file")
    return send_from_directory("/app/uploads", filename)

# SECURE: Validate filename against allowlist
@app.route("/download")
def download_allowlist():
    filename = request.args.get("file")
    allowed = {"report.pdf", "data.csv", "readme.txt"}
    if filename not in allowed:
        return "File not found", 404
    return send_from_directory("/app/uploads", filename)

# SECURE: Use secure_filename and validate extension
from werkzeug.utils import secure_filename

@app.route("/download/<filename>")
def download_secure(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        return "Invalid filename", 400
    allowed_ext = {".pdf", ".csv", ".txt"}
    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in allowed_ext:
        return "Invalid file type", 400
    return send_from_directory("/app/uploads", safe_name)
```

**Detection regex:** `send_file\s*\(\s*f["\']|send_file\s*\(\s*.*request\.|send_file\s*\(\s*os\.path\.join`
**Severity:** error

### SA-FLASK-04: debug=True in Production

Flask's debug mode enables the Werkzeug interactive debugger, which allows arbitrary code execution in the browser. It also exposes detailed tracebacks, environment variables, and source code.

```python
from flask import Flask

app = Flask(__name__)

# VULNERABLE: debug=True in app.run()
if __name__ == "__main__":
    app.run(debug=True)

# VULNERABLE: Debug mode via config
app.config["DEBUG"] = True

# VULNERABLE: ENV set to development (enables debug features)
app.config["ENV"] = "development"

# VULNERABLE: FLASK_DEBUG=1 in .env or .flaskenv
# .flaskenv:
# FLASK_DEBUG=1

# SECURE: debug=False (default)
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8000)

# SECURE: Use environment variable with safe default
import os
debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
if __name__ == "__main__":
    app.run(debug=debug_mode)

# SECURE: Use a WSGI server in production
# gunicorn -w 4 -b 0.0.0.0:8000 myapp:app
# uwsgi --http 0.0.0.0:8000 --module myapp:app
```

**Detection regex:** `app\.run\s*\(.*debug\s*=\s*True|\.config\s*\[\s*["\']DEBUG["\']\s*\]\s*=\s*True|FLASK_DEBUG\s*=\s*1`
**Severity:** error

### SA-FLASK-05: Client-Side Session Tampering

Flask's default session implementation uses signed cookies. The session data is encoded (not encrypted) and visible to clients. If the `SECRET_KEY` is weak or leaked, attackers can forge session cookies.

```python
from flask import Flask, request, session

app = Flask(__name__)

def authenticate(username: str, password: str):
    ...  # look up + verify user; return user object or None

# VULNERABLE: Weak SECRET_KEY
app.secret_key = "dev"
app.secret_key = "changeme"
app.secret_key = "super-secret"

# VULNERABLE: Storing sensitive data in client-side session
@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        session["user_id"] = user.id
        session["is_admin"] = user.is_admin  # Visible to client!
        session["permissions"] = user.permissions  # Visible to client!

# VULNERABLE: SECRET_KEY in source code
app.config["SECRET_KEY"] = "my-production-secret-key-2024"

# SECURE: Strong, random SECRET_KEY from environment
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# SECURE: Use server-side session storage
# pip install flask-session
from flask_session import Session

app.config["SESSION_TYPE"] = "redis"  # or "filesystem", "sqlalchemy"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
Session(app)

# SECURE: Minimal data in session, verify server-side
@app.route("/login", methods=["POST"])
def login_safe():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        session["user_id"] = user.id
        # Check is_admin from database on each request, not from session
```

**Detection regex:** `secret_key\s*=\s*["\'][^"\']{1,30}["\']|app\.config\s*\[\s*["\']SECRET_KEY["\']\s*\]\s*=\s*["\']`
**Severity:** error

### SA-FLASK-07: Session Fixation with Flask-Login

Session fixation occurs when an application does not regenerate the session ID after authentication. If Flask-Login or custom session handling does not rotate sessions on login, attackers can pre-set a session cookie for the victim.

```python
from flask import Flask, session, request
from flask_login import LoginManager, login_user

app = Flask(__name__)
login_manager = LoginManager(app)

# VULNERABLE: No session regeneration on login
@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(
        username=request.form["username"]
    ).first()
    if user and user.check_password(request.form["password"]):
        login_user(user)  # Session ID not regenerated
        return redirect("/dashboard")

# SECURE: Rotate the session on login. Flask's built-in session has no
# first-class "regenerate ID" API (it's a signed-cookie implementation, so
# every session payload is already bound to the current signing key).
# Portable approach: clear() the old session before populating it with the
# authenticated identity, which invalidates the previous cookie value.
# If you use server-side sessions (Flask-Session, Flask-Login), rotate the
# backend session ID with the backend's documented call — the exact name
# varies (flask_session.SessionInterface backends expose their own rotate
# hook; consult your backend's docs).
@app.route("/login", methods=["POST"])
def login_safe():
    user = User.query.filter_by(
        username=request.form["username"]
    ).first()
    if user and user.check_password(request.form["password"]):
        session.clear()            # drop any pre-login session state
        login_user(user)           # Flask-Login writes a fresh session
        return redirect("/dashboard")

# SECURE: Configure session cookie security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # HTTPS only
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)
```

**Detection regex:** `login_user\s*\(|flask_login\s+import.*login_user`
**Severity:** warning

### SA-FLASK-08: CORS Misconfiguration

Flask-CORS or manual CORS header configuration can expose APIs to cross-origin requests from any domain if configured with wildcards or overly permissive origins.

```python
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# VULNERABLE: Allow all origins
CORS(app)  # Defaults to allow all origins (*)

# VULNERABLE: Wildcard with credentials
CORS(app, origins="*", supports_credentials=True)

# VULNERABLE: Reflecting Origin header
@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = origin  # reflects any origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# SECURE: Specific origins only
CORS(app, origins=["https://app.example.com", "https://admin.example.com"])

# SECURE: Per-route CORS with specific origins
from flask_cors import cross_origin

@app.route("/api/public")
@cross_origin(origins=["https://app.example.com"])
def public_api():
    return jsonify({"data": "public"})

# SECURE: Validate origin against allowlist
ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

@app.after_request
def add_cors_safe(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

**Detection regex:** `CORS\s*\(\s*app\s*\)|origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin.*\*`
**Severity:** error

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-FLASK-01: Jinja2 SSTI | Critical | Immediate | Medium |
| SA-FLASK-02: Request parameter injection | High | 1 week | Medium |
| SA-FLASK-03: Path traversal (send_file) | High | Immediate | Low |
| SA-FLASK-04: debug=True in production | Critical | Immediate | Low |
| SA-FLASK-05: Client-side session tampering | High | 1 week | Medium |
| SA-FLASK-06: SQLAlchemy raw query injection | Critical | Immediate | Medium |
| SA-FLASK-07: Session fixation | Medium | 1 week | Medium |
| SA-FLASK-08: CORS misconfiguration | High | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `python-security-features.md` — Language-level Python patterns
- `django-security.md` — Django-specific patterns
- `fastapi-security.md` — FastAPI-specific patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 2: Python framework coverage |
