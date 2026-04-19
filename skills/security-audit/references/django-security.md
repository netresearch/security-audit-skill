# Django Security Patterns

Security patterns, common misconfigurations, and detection regexes for Django applications. Covers ORM injection, CSRF misconfiguration, XSS via mark_safe, session backend risks, debug settings, secret key exposure, file uploads, admin exposure, and QuerySet injection.

## Injection

### SA-DJANGO-01: ORM Injection via raw() and extra()

Django's ORM is safe by default when using QuerySet methods with parameterized values. However, `raw()`, `extra()`, and `RawSQL()` bypass these protections when user input is interpolated directly into query strings.

```python
from django.db import connection
from myapp.models import User

# VULNERABLE: String interpolation in raw()
def search_users(request):
    query = request.GET.get("q")
    users = User.objects.raw(f"SELECT * FROM myapp_user WHERE name = '{query}'")
    return render(request, "users.html", {"users": users})

# VULNERABLE: f-string in extra()
def filter_users(request):
    order = request.GET.get("order", "id")
    users = User.objects.extra(order_by=[order])  # attacker controls ORDER BY
    return render(request, "users.html", {"users": users})

# VULNERABLE: Direct cursor execution with string formatting
def raw_query(request):
    user_id = request.GET.get("id")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM myapp_user WHERE id = %s" % user_id)
        rows = cursor.fetchall()
    return render(request, "users.html", {"rows": rows})

# SECURE: Parameterized raw()
def search_users_safe(request):
    query = request.GET.get("q")
    users = User.objects.raw(
        "SELECT * FROM myapp_user WHERE name = %s", [query]
    )
    return render(request, "users.html", {"users": users})

# SECURE: Use ORM filtering instead of extra()
def filter_users_safe(request):
    allowed_orders = {"id", "name", "date_joined"}
    order = request.GET.get("order", "id")
    if order not in allowed_orders:
        order = "id"
    users = User.objects.order_by(order)
    return render(request, "users.html", {"users": users})

# SECURE: Parameterized cursor execution
def raw_query_safe(request):
    user_id = request.GET.get("id")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM myapp_user WHERE id = %s", [user_id])
        rows = cursor.fetchall()
    return render(request, "users.html", {"rows": rows})
```

**Detection regex:** `\.raw\s*\(\s*f["\']|\.raw\s*\(\s*["\'].*%s.*["\']\s*%|\.extra\s*\(|cursor\.execute\s*\(\s*f["\']|cursor\.execute\s*\(\s*["\'].*%s.*["\']\s*%`
**Severity:** error

### SA-DJANGO-09: QuerySet Injection via Untrusted Field Names

When user-supplied input is used as field names in `filter()`, `exclude()`, `values()`, `order_by()`, or `annotate()`, attackers can traverse relationships or extract data from related models.

```python
from django.http import HttpResponseBadRequest, JsonResponse
from myapp.models import User

# VULNERABLE: User-controlled field in filter()
def search(request):
    field = request.GET.get("field", "username")
    value = request.GET.get("value")
    results = User.objects.filter(**{field: value})
    # Attacker can use: ?field=password&value=admin123
    # Or traverse: ?field=profile__ssn&value=123-45-6789
    return render(request, "results.html", {"results": results})

# VULNERABLE: User-controlled field in values()
def export(request):
    fields = request.GET.getlist("fields")
    data = User.objects.values(*fields)
    # Attacker: ?fields=password&fields=email
    return JsonResponse(list(data), safe=False)

# VULNERABLE: User-controlled ordering
def list_users(request):
    sort = request.GET.get("sort", "id")
    users = User.objects.order_by(sort)
    return render(request, "users.html", {"users": users})

# SECURE: Allowlist field names
ALLOWED_SEARCH_FIELDS = {"username", "email", "first_name", "last_name"}
ALLOWED_SORT_FIELDS = {"id", "username", "date_joined", "-id", "-username", "-date_joined"}

def search_safe(request):
    field = request.GET.get("field", "username")
    value = request.GET.get("value")
    if field not in ALLOWED_SEARCH_FIELDS:
        return HttpResponseBadRequest("Invalid field")
    results = User.objects.filter(**{field: value})
    return render(request, "results.html", {"results": results})

def list_users_safe(request):
    sort = request.GET.get("sort", "id")
    if sort not in ALLOWED_SORT_FIELDS:
        sort = "id"
    users = User.objects.order_by(sort)
    return render(request, "users.html", {"users": users})
```

**Detection regex:** `\.filter\s*\(\s*\*\*\s*\{.*request\.|\.values\s*\(\s*\*.*request\.|\.order_by\s*\(.*request\.`
**Severity:** warning

## Cross-Site Scripting (XSS)

### SA-DJANGO-04: XSS via mark_safe() and |safe Filter

Django auto-escapes template variables by default. The `mark_safe()` function and `|safe` template filter bypass this protection. When combined with user input, they create XSS vulnerabilities.

```python
from django.utils.safestring import mark_safe
from django.utils.html import format_html

# VULNERABLE: mark_safe with user input
def user_profile(request, user_id):
    user = User.objects.get(id=user_id)
    bio_html = mark_safe(user.bio)  # user.bio could contain <script>
    return render(request, "profile.html", {"bio": bio_html})

# VULNERABLE: mark_safe with string formatting
def greeting(request):
    name = request.GET.get("name", "World")
    message = mark_safe(f"<h1>Hello, {name}!</h1>")
    return render(request, "greeting.html", {"message": message})

# VULNERABLE: |safe filter in template
# In template: {{ user.bio|safe }}
# This bypasses Django's auto-escaping

# SECURE: Use format_html() for safe HTML construction
def greeting_safe(request):
    name = request.GET.get("name", "World")
    message = format_html("<h1>Hello, {}!</h1>", name)
    return render(request, "greeting.html", {"message": message})

# SECURE: Use bleach or similar library for user HTML
import bleach

ALLOWED_TAGS = ["b", "i", "u", "a", "p", "br", "ul", "ol", "li"]
ALLOWED_ATTRS = {"a": ["href", "title"]}

def user_profile_safe(request, user_id):
    user = User.objects.get(id=user_id)
    bio_html = bleach.clean(user.bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    return render(request, "profile.html", {"bio": mark_safe(bio_html)})
```

**Detection regex:** `mark_safe\s*\(|\.safestring\s+import|safestring\.mark_safe`
**Severity:** error

### SA-DJANGO-10: Template |safe Filter Usage

The `|safe` filter in Django templates is equivalent to `mark_safe()` in Python code. It disables auto-escaping for a variable and should only be used with trusted, pre-sanitized content.

```html
<!-- VULNERABLE: |safe on user-controlled data -->
<div class="bio">{{ user.bio|safe }}</div>
<div class="comment">{{ comment.body|safe }}</div>

<!-- VULNERABLE: |safe on data from external API -->
<div>{{ api_response.html|safe }}</div>

<!-- SECURE: Let Django auto-escape (default behavior) -->
<div class="bio">{{ user.bio }}</div>

<!-- SECURE: Use |escape explicitly for clarity -->
<div class="comment">{{ comment.body|escape }}</div>

<!-- SECURE: Use |safe only on pre-sanitized content -->
<!-- In view: sanitized = bleach.clean(user.bio, ...) -->
<div class="bio">{{ sanitized_bio|safe }}</div>
```

**Detection regex:** `\|\s*safe\b`
**Severity:** warning

## CSRF Protection

### SA-DJANGO-02: CSRF Misconfiguration via @csrf_exempt

Django provides automatic CSRF protection via middleware. The `@csrf_exempt` decorator disables this for individual views. State-changing endpoints without CSRF protection are vulnerable to cross-site request forgery.

```python
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

# VULNERABLE: csrf_exempt on state-changing endpoint
@csrf_exempt
def transfer_funds(request):
    if request.method == "POST":
        amount = request.POST.get("amount")
        recipient = request.POST.get("recipient")
        # Process transfer without CSRF protection
        return JsonResponse({"status": "ok"})

# VULNERABLE: csrf_exempt on class-based view
from django.utils.decorators import method_decorator
from django.views import View

@method_decorator(csrf_exempt, name="dispatch")
class UpdateProfileView(View):
    def post(self, request):
        # State-changing operation without CSRF
        request.user.profile.update(name=request.POST.get("name"))
        return JsonResponse({"status": "updated"})

# SECURE: Use CSRF protection (default)
def transfer_funds_safe(request):
    if request.method == "POST":
        amount = request.POST.get("amount")
        recipient = request.POST.get("recipient")
        return JsonResponse({"status": "ok"})

# SECURE: For APIs, use token authentication instead
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response

@api_view(["POST"])
@authentication_classes([TokenAuthentication])
def api_transfer(request):
    amount = request.data.get("amount")
    recipient = request.data.get("recipient")
    return Response({"status": "ok"})
```

**Detection regex:** `@csrf_exempt|csrf_exempt\s*\(|decorators\.csrf\s+import\s+csrf_exempt`
**Severity:** error

## Authentication & Authorization

### SA-DJANGO-07: Admin Site Exposure

Django's admin site (`/admin/`) is a powerful interface that should be protected beyond default authentication. Exposing it on public URLs without additional protections creates an attack surface.

```python
# VULNERABLE: Default admin URL with no extra protection
# urls.py
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),  # predictable URL
]

# VULNERABLE: Admin with DEBUG=True exposes detailed errors
# settings.py
DEBUG = True
ALLOWED_HOSTS = ["*"]

# SECURE: Change admin URL to non-predictable path
urlpatterns = [
    path("manage-8f3k2j/", admin.site.urls),  # obscure URL
]

# SECURE: Add IP restriction middleware or decorator
from django.http import HttpResponseForbidden

class AdminIPRestrictionMiddleware:
    ALLOWED_IPS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/admin/"):
            ip = request.META.get("REMOTE_ADDR")
            if not self._is_allowed(ip):
                return HttpResponseForbidden("Forbidden")
        return self.get_response(request)

    def _is_allowed(self, ip):
        import ipaddress
        client = ipaddress.ip_address(ip)
        return any(
            client in ipaddress.ip_network(net) for net in self.ALLOWED_IPS
        )

# SECURE: Enforce 2FA for admin (django-otp or django-two-factor-auth)
# SECURE: Rate-limit admin login (django-axes)
```

**Detection regex:** `path\s*\(\s*["\']admin/["\']|url\s*\(\s*r?\s*["\'].*admin/`
**Severity:** warning

## Security Misconfiguration

### SA-DJANGO-03: DEBUG=True in Production

Django's `DEBUG = True` setting exposes detailed error pages, SQL queries, installed apps, settings, and full tracebacks. This information is invaluable to attackers.

```python
# VULNERABLE: DEBUG=True in settings.py
# settings.py
DEBUG = True
ALLOWED_HOSTS = ["*"]  # Often accompanies DEBUG=True

# VULNERABLE: Conditional debug that defaults to True
import os
DEBUG = os.environ.get("DEBUG", True)  # Default is True if env var missing

# SECURE: DEBUG=False with explicit ALLOWED_HOSTS
DEBUG = False
ALLOWED_HOSTS = ["example.com", "www.example.com"]

# SECURE: Use environment variable with safe default
import os
DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"

# SECURE: Split settings files
# settings/base.py — shared settings
# settings/development.py — DEBUG = True (never deployed)
# settings/production.py — DEBUG = False, strict ALLOWED_HOSTS
```

**Detection regex:** `DEBUG\s*=\s*True`
**Severity:** error

### SA-DJANGO-05: SECRET_KEY Exposure

Django's `SECRET_KEY` is used for cryptographic signing (sessions, CSRF tokens, password reset tokens). Hardcoding it in source code or committing it to version control allows attackers to forge sessions and tokens.

```python
# VULNERABLE: Hardcoded SECRET_KEY in settings.py
SECRET_KEY = "django-insecure-abc123def456ghi789jkl012mno345"

# VULNERABLE: SECRET_KEY in committed file
SECRET_KEY = "my-super-secret-key-that-should-not-be-here"

# VULNERABLE: Weak or default SECRET_KEY
SECRET_KEY = "change-me"
SECRET_KEY = "django-insecure-"

# SECURE: Load from environment variable
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]  # Fails loudly if missing

# SECURE: Load from a secrets file not in VCS
from pathlib import Path
SECRET_KEY = Path("/run/secrets/django_secret_key").read_text().strip()

# SECURE: Use django-environ
import environ
env = environ.Env()
SECRET_KEY = env("DJANGO_SECRET_KEY")
```

**Detection regex:** `SECRET_KEY\s*=\s*["\'][^"\']{8,}["\']`
**Severity:** error

### SA-DJANGO-06: Insecure Session Backend (Pickle)

Django supports multiple session serializers. The `PickleSerializer` deserializes session data using Python's `pickle` module, which can execute arbitrary code if an attacker can tamper with session data (e.g., via a leaked SECRET_KEY).

```python
# VULNERABLE: Pickle session serializer
# settings.py
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"

# VULNERABLE: Custom pickle-based serializer
SESSION_SERIALIZER = "myapp.serializers.CustomPickleSerializer"

# VULNERABLE: Pickle combined with cookie session backend
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
# Worst combination: cookie-based + pickle = RCE if SECRET_KEY leaks

# SECURE: Use JSON serializer (Django default since 1.6)
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"

# SECURE: Use database-backed sessions (default engine)
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"

# SECURE: Use cache-backed sessions with JSON
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"
SESSION_CACHE_ALIAS = "sessions"
```

**Detection regex:** `PickleSerializer|SESSION_SERIALIZER.*[Pp]ickle`
**Severity:** error

### SA-DJANGO-08: File Upload Validation

Django handles file uploads via `request.FILES`. Without proper validation, attackers can upload executable files, oversized files, or files with misleading extensions.

```python
from django.core.validators import FileExtensionValidator
from django.db import models

# VULNERABLE: No file type or size validation
class Document(models.Model):
    file = models.FileField(upload_to="documents/")

# VULNERABLE: Trusting Content-Type header
def upload_file(request):
    uploaded = request.FILES["file"]
    if uploaded.content_type == "image/png":  # easily spoofed
        handle_upload(uploaded)

# VULNERABLE: Saving to predictable location without sanitization
import os
def upload_avatar(request):
    f = request.FILES["avatar"]
    path = os.path.join("/media/avatars/", f.name)  # path traversal risk
    with open(path, "wb+") as dest:
        for chunk in f.chunks():
            dest.write(chunk)

# SECURE: Validate extension, size, and content type
class Document(models.Model):
    file = models.FileField(
        upload_to="documents/%Y/%m/",
        validators=[
            FileExtensionValidator(allowed_extensions=["pdf", "docx", "txt"]),
        ],
    )

    def clean(self):
        super().clean()
        if self.file.size > 10 * 1024 * 1024:  # 10 MB limit
            raise ValidationError("File too large (max 10 MB)")

# SECURE: Use python-magic to verify actual file type
import magic

def validate_file_type(uploaded_file):
    mime = magic.from_buffer(uploaded_file.read(2048), mime=True)
    uploaded_file.seek(0)
    allowed = {"application/pdf", "image/png", "image/jpeg"}
    if mime not in allowed:
        raise ValidationError(f"Unsupported file type: {mime}")

# SECURE: Django's default_storage with sanitized filename
from django.core.files.storage import default_storage
from django.utils.text import get_valid_filename
import uuid

def upload_avatar_safe(request):
    f = request.FILES["avatar"]
    ext = os.path.splitext(f.name)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".gif"}:
        return HttpResponseBadRequest("Invalid file type")
    filename = f"{uuid.uuid4()}{ext}"
    path = default_storage.save(f"avatars/{filename}", f)
    return JsonResponse({"path": path})
```

**Detection regex:** `FileField\s*\(\s*upload_to\s*=\s*["\'][^"\']*["\'](?:\s*\)|\s*,\s*\))|request\.FILES\[`
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-DJANGO-01: ORM injection (raw/extra) | Critical | Immediate | Medium |
| SA-DJANGO-02: CSRF disabled (@csrf_exempt) | High | Immediate | Low |
| SA-DJANGO-03: DEBUG=True in production | Critical | Immediate | Low |
| SA-DJANGO-04: mark_safe XSS | High | 1 week | Medium |
| SA-DJANGO-05: SECRET_KEY exposure | Critical | Immediate | Low |
| SA-DJANGO-06: Pickle session backend | High | 1 week | Low |
| SA-DJANGO-07: Admin site exposure | Medium | 1 month | Medium |
| SA-DJANGO-08: File upload validation | Medium | 1 week | Medium |
| SA-DJANGO-09: QuerySet field injection | Medium | 1 week | Medium |
| SA-DJANGO-10: Template |safe filter | Medium | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `python-security-features.md` — Language-level Python patterns
- `flask-security.md` — Flask-specific patterns
- `fastapi-security.md` — FastAPI-specific patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 2: Python framework coverage |
