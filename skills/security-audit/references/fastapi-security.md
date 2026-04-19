# FastAPI Security Patterns

Security patterns, common misconfigurations, and detection regexes for FastAPI applications. Covers Pydantic validation bypass, dependency injection auth patterns, CORS middleware misconfiguration, response header injection, file upload handling, OAuth2 implementation pitfalls, background task data exposure, and WebSocket authentication.

## Authentication & Authorization

### SA-FASTAPI-01: Missing Dependency Injection for Auth

FastAPI uses dependency injection for authentication and authorization via `Depends()`. Endpoints that lack auth dependencies are publicly accessible. Unlike Django, FastAPI has no global auth middleware by default -- each endpoint must explicitly declare its dependencies.

```python
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError  # python-jose
from myapp.models import User   # your ORM / data access layer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.environ["APP_JWT_KEY"]  # fail fast if unset; never hardcode

# VULNERABLE: No auth dependency -- endpoint is public
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = await User.get(user_id)
    return user

# VULNERABLE: Auth check in function body (easy to forget, not enforced)
@app.post("/admin/settings")
async def update_settings(settings: dict):
    # Developer might forget this check in some endpoints
    # No compile-time or startup-time guarantee
    return {"status": "updated"}

# VULNERABLE: Optional auth that doesn't enforce
@app.get("/data")
async def get_data(token: str = None):
    if token:
        user = verify_token(token)
    # Continues even without valid token

# SECURE: Auth via Depends()
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await User.get(user_id)
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/{user_id}")
async def get_user_safe(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    user = await User.get(user_id)
    return user

# SECURE: Role-based access via dependency chain
async def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user

@app.post("/admin/settings")
async def update_settings_safe(
    settings: dict,
    admin: User = Depends(require_admin),
):
    return {"status": "updated"}

# SECURE: Global auth via router-level dependency
from fastapi import APIRouter

admin_router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_admin)],
)

@admin_router.post("/settings")
async def update_settings_router(settings: dict):
    return {"status": "updated"}
```

**Detection (two-pass, since line-oriented grep can't match across `\n`):**
First flag all route decorators, then separately check that the function signature on the next line mentions `Depends(`.
```bash
# Pass 1: list files with route decorators (PCRE, supports \s):
files=$(grep -rlP '@app\.(get|post|put|patch|delete)\s*\(' --include='*.py' .)
# Pass 2: for each file, find decorators whose next signature lacks Depends(:
for f in $files; do
  awk '/^@app\.(get|post|put|patch|delete)\s*\(/ { deco=NR; next }
       /^(async[[:space:]]+)?def[[:space:]]/ && deco {
         if ($0 !~ /Depends/) print FILENAME":"deco": route without Depends(...) auth"
         deco=0
       }' "$f"
done
```
**Severity:** warning

### SA-FASTAPI-02: Pydantic Validation Bypass

FastAPI relies on Pydantic for request validation. However, bypasses occur when using `dict` or `Any` types, when Pydantic models have overly permissive fields, or when `model_config` disables validation features.

```python
from fastapi import FastAPI, Body
from pydantic import BaseModel, Field, field_validator
from typing import Any

app = FastAPI()

# VULNERABLE: Accepting raw dict bypasses all validation
@app.post("/users")
async def create_user(data: dict):
    # No type checking, no field validation
    # Attacker can send any fields including internal ones
    return await User.create(**data)

# VULNERABLE: Using Any type
class UserUpdate(BaseModel):
    role: Any  # Accepts anything -- string, list, dict, None
    metadata: Any

# VULNERABLE: Extra fields allowed (mass assignment)
class UserCreate(BaseModel):
    model_config = {"extra": "allow"}
    username: str
    email: str
    # Attacker can add: {"username": "x", "email": "x", "is_admin": true}

# VULNERABLE: No string length limits
class Comment(BaseModel):
    body: str  # Could be 100MB string
    title: str

# SECURE: Strict Pydantic model with validation
class UserCreate(BaseModel):
    model_config = {"extra": "forbid"}  # Reject unknown fields

    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    email: str = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[1]:
            raise ValueError("Invalid email format")
        return v.lower()

class Comment(BaseModel):
    model_config = {"extra": "forbid"}
    body: str = Field(max_length=10000)
    title: str = Field(max_length=200)

# SECURE: Use specific types, not Any. Pydantic's `max_length` constraint
# only applies to string/bytes/sequence types — not to `dict`. To cap the
# number of entries in a metadata dict, add a validator.
from pydantic import field_validator

class UserUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    role: str = Field(pattern=r"^(user|editor|admin)$")
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _cap_metadata_size(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 20:
            raise ValueError("metadata may contain at most 20 keys")
        return v
```

**Detection regex:** `def\s+\w+\s*\([^)]*:\s*dict\s*[,\)]|:\s*Any\s*[,\)=]|extra\s*=\s*["\']allow["\']`
**Severity:** warning

### SA-FASTAPI-06: OAuth2 Implementation Pitfalls

FastAPI provides OAuth2 utilities, but common implementation mistakes include not verifying token expiration, using weak signing algorithms, not validating token audience/issuer, and storing tokens insecurely.

```python
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# VULNERABLE: No expiration check
async def get_current_user_bad(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    # No check for expired tokens!
    user_id = payload.get("sub")
    return await User.get(user_id)

# VULNERABLE: Algorithm confusion (accepts "none" algorithm)
async def verify_token_bad(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
    return payload

# VULNERABLE: Weak secret for JWT signing
SECRET_KEY = "secret"
ACCESS_TOKEN_EXPIRE_MINUTES = 525600  # 1 year -- too long

# VULNERABLE: No audience/issuer validation
def create_token(user_id: str):
    payload = {"sub": user_id}  # No exp, aud, iss claims
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# SECURE: Complete token creation and verification
import os
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ISSUER = "myapp.example.com"
AUDIENCE = "myapp-api"

def create_access_token(user_id: str, scopes: list[str] = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "scopes": scopes or [],
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user_safe(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],  # Single, specific algorithm
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "sub", "iss", "aud"]},
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await User.get(user_id)
    if user is None:
        raise credentials_exception
    return user
```

**Detection regex:** `algorithms\s*=\s*\[.*none.*\]|jwt\.decode\s*\(\s*token\s*,\s*[^,]+\s*\)\s*$|ACCESS_TOKEN_EXPIRE.*(?:525600|86400|43200)`
**Severity:** error

## Security Misconfiguration

### SA-FASTAPI-03: CORS Middleware Misconfiguration

FastAPI uses Starlette's `CORSMiddleware`. Misconfiguration with wildcard origins, especially combined with `allow_credentials=True`, exposes the API to cross-origin attacks.

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# VULNERABLE: Allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# VULNERABLE: Wildcard with credentials (browsers block this, but shows intent)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # Dangerous with wildcard
    allow_methods=["*"],
    allow_headers=["*"],
)

# VULNERABLE: allow_origin_regex too broad
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.example\.com",
    # Matches https://evil.example.com too
)

# SECURE: Specific origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.example.com",
        "https://admin.example.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# SECURE: Environment-based CORS configuration
import os

ALLOWED_ORIGINS = os.environ.get(
    "CORS_ORIGINS", "https://app.example.com"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)
```

**Detection regex:** `allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]|CORSMiddleware.*allow_origins.*\*`
**Severity:** error

### SA-FASTAPI-04: Response Header Injection

When user input is used in response headers without sanitization, attackers can inject additional headers or modify existing ones, potentially enabling cache poisoning, session fixation, or XSS via headers.

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

app = FastAPI()

# VULNERABLE: User input in response header
@app.get("/download")
async def download(request: Request):
    filename = request.query_params.get("name", "file.txt")
    response = JSONResponse(content={"status": "ok"})
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    # Attacker: ?name=file.txt\r\nX-Injected: header
    return response

# VULNERABLE: User input in redirect Location header
@app.get("/redirect")
async def redirect_endpoint(request: Request):
    url = request.query_params.get("url", "/")
    return RedirectResponse(url=url)
    # Attacker: ?url=https://evil.com or ?url=javascript:alert(1)

# VULNERABLE: User input in Set-Cookie via header
@app.get("/set-lang")
async def set_language(request: Request):
    lang = request.query_params.get("lang", "en")
    response = JSONResponse(content={"lang": lang})
    response.headers["Set-Cookie"] = f"lang={lang}; Path=/"
    return response

# SECURE: Sanitize header values
import re

def sanitize_header_value(value: str) -> str:
    """Remove newlines and control characters from header values."""
    return re.sub(r"[\r\n\x00-\x1f]", "", value)

@app.get("/download")
async def download_safe(request: Request):
    filename = request.query_params.get("name", "file.txt")
    safe_filename = sanitize_header_value(filename)
    safe_filename = safe_filename.replace('"', '\\"')
    response = JSONResponse(content={"status": "ok"})
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
    return response

# SECURE: Validate redirect URLs
from urllib.parse import urlparse

ALLOWED_REDIRECT_HOSTS = {"example.com", "app.example.com"}

@app.get("/redirect")
async def redirect_safe(request: Request):
    url = request.query_params.get("url", "/")
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        url = "/"
    return RedirectResponse(url=url)

# SECURE: Use response.set_cookie() instead of raw headers
@app.get("/set-lang")
async def set_language_safe(request: Request):
    lang = request.query_params.get("lang", "en")
    allowed_langs = {"en", "de", "fr", "es"}
    if lang not in allowed_langs:
        lang = "en"
    response = JSONResponse(content={"lang": lang})
    response.set_cookie(key="lang", value=lang, httponly=True, samesite="lax")
    return response
```

**Detection regex:** `response\.headers\s*\[.*\]\s*=\s*f["\']|response\.headers\s*\[.*\]\s*=.*request\.|\.headers\s*\[\s*["\']Set-Cookie["\']\s*\]\s*=`
**Severity:** warning

### SA-FASTAPI-05: File Upload Handling

FastAPI handles file uploads via `UploadFile`. Without proper validation of file size, type, and content, attackers can upload malicious files, cause denial of service with large files, or exploit path traversal via filenames.

```python
from fastapi import FastAPI, UploadFile, File, HTTPException
import shutil
import os

app = FastAPI()

# VULNERABLE: No file size or type validation
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    with open(f"/app/uploads/{file.filename}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"filename": file.filename}

# VULNERABLE: Trusting content_type header
@app.post("/upload-image")
async def upload_image(file: UploadFile = File(...)):
    if file.content_type.startswith("image/"):  # easily spoofed
        contents = await file.read()
        # Process as image...

# VULNERABLE: Path traversal via filename
@app.post("/upload")
async def upload_bad(file: UploadFile = File(...)):
    path = os.path.join("/app/uploads", file.filename)
    # file.filename = "../../etc/cron.d/backdoor"

# SECURE: Validate file size, type, and sanitize filename
import uuid
import magic

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf"}
ALLOWED_MIMES = {"image/jpeg", "image/png", "image/gif", "application/pdf"}

@app.post("/upload")
async def upload_safe(file: UploadFile = File(...)):
    # Check extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type {ext} not allowed")

    # Read with size limit
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(400, "File too large (max 10 MB)")

    # Verify actual content type with python-magic
    mime = magic.from_buffer(contents[:2048], mime=True)
    if mime not in ALLOWED_MIMES:
        raise HTTPException(400, f"Invalid file content type: {mime}")

    # Generate safe filename
    safe_filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join("/app/uploads", safe_filename)

    with open(filepath, "wb") as f:
        f.write(contents)

    return {"filename": safe_filename}
```

**Detection regex:** `UploadFile.*filename|file\.filename|shutil\.copyfileobj\s*\(\s*file`
**Severity:** warning

## Data Exposure

### SA-FASTAPI-07: Background Task Data Exposure

FastAPI's `BackgroundTasks` run after the response is sent. If background tasks reference mutable request data, session objects, or database connections from the request scope, they may access stale or recycled data.

```python
from fastapi import FastAPI, BackgroundTasks, Depends, Request

app = FastAPI()

# VULNERABLE: Background task captures request object
@app.post("/process")
async def process_data(request: Request, background_tasks: BackgroundTasks):
    background_tasks.add_task(log_request, request)
    # request object may be recycled by the time the task runs
    return {"status": "accepted"}

async def log_request(request: Request):
    # Request body may already be consumed or connection closed
    body = await request.body()  # May fail or return wrong data
    print(f"Logged: {body}")

# VULNERABLE: Background task with db session from request scope
@app.post("/orders")
async def create_order(
    order: OrderCreate,
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks,
):
    new_order = Order(**order.dict())
    db.add(new_order)
    db.commit()
    # db session will be closed after response -- task may fail
    background_tasks.add_task(send_confirmation, db, new_order.id)

# VULNERABLE: Logging sensitive data in background task
@app.post("/login")
async def login(creds: LoginRequest, background_tasks: BackgroundTasks):
    user = authenticate(creds.username, creds.password)
    background_tasks.add_task(log_login_attempt, creds.username, creds.password)
    # Password logged in background -- visible in logs
    return {"token": create_token(user)}

# SECURE: Extract needed data before passing to background task
@app.post("/process")
async def process_data_safe(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    headers = dict(request.headers)
    background_tasks.add_task(log_request_safe, body, headers)
    return {"status": "accepted"}

async def log_request_safe(body: bytes, headers: dict):
    print(f"Logged: {len(body)} bytes")

# SECURE: Create new db session in background task
@app.post("/orders")
async def create_order_safe(
    order: OrderCreate,
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks,
):
    new_order = Order(**order.dict())
    db.add(new_order)
    db.commit()
    order_id = new_order.id  # Extract the ID
    background_tasks.add_task(send_confirmation_safe, order_id)

async def send_confirmation_safe(order_id: int):
    async with get_async_session() as db:
        order = await db.get(Order, order_id)
        await send_email(order.user.email, "Order confirmed", str(order))
```

**Detection regex:** `background_tasks\.add_task\s*\(.*request\b|background_tasks\.add_task\s*\(.*\bdb\b|BackgroundTasks.*password|BackgroundTasks.*secret`
**Severity:** warning

### SA-FASTAPI-08: WebSocket Authentication

FastAPI WebSocket endpoints do not automatically inherit HTTP authentication. Without explicit auth checks, WebSocket connections can be established by unauthenticated users. Browsers do not send custom headers with WebSocket upgrade requests, so token-based auth must use query parameters or the first message.

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()

# VULNERABLE: No authentication on WebSocket
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Echo: {data}")

# VULNERABLE: Auth check after accept (connection already established)
@app.websocket("/ws/chat")
async def chat(websocket: WebSocket):
    await websocket.accept()
    token = await websocket.receive_text()  # First message is token
    # Connection is already open -- attacker can send/receive before auth
    user = verify_token(token)
    if not user:
        await websocket.close(code=1008)
        return

# SECURE: Auth via query parameter, verified before accept
@app.websocket("/ws")
async def websocket_safe(websocket: WebSocket, token: str = Query(...)):
    user = verify_token(token)
    if not user:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Echo: {data}")

# SECURE: Auth via dependency injection
async def get_ws_user(websocket: WebSocket) -> User:
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        raise WebSocketDisconnect(code=1008)
    user = verify_token(token)
    if not user:
        await websocket.close(code=1008)
        raise WebSocketDisconnect(code=1008)
    return user

@app.websocket("/ws")
async def websocket_with_dep(
    websocket: WebSocket,
    user: User = Depends(get_ws_user),
):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Hello {user.name}: {data}")

# SECURE: Cookie-based auth for WebSockets
@app.websocket("/ws")
async def websocket_cookie_auth(websocket: WebSocket):
    session_id = websocket.cookies.get("session_id")
    if not session_id:
        await websocket.close(code=1008)
        return
    user = await get_user_from_session(session_id)
    if not user:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    # ... handle messages
```

**Detection regex:** `@app\.websocket\s*\(\s*["\'][^"\']*["\']\s*\)` — flag every WebSocket route, then manually verify each `async def` accepts an auth token / Depends parameter. A single-line regex cannot span the decorator and the signature; use the two-pass approach shown earlier for Depends() verification.
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-FASTAPI-01: Missing auth dependency | High | Immediate | Low |
| SA-FASTAPI-02: Pydantic validation bypass | Medium | 1 week | Medium |
| SA-FASTAPI-03: CORS wildcard origins | High | Immediate | Low |
| SA-FASTAPI-04: Response header injection | Medium | 1 week | Low |
| SA-FASTAPI-05: File upload handling | Medium | 1 week | Medium |
| SA-FASTAPI-06: OAuth2 pitfalls | High | Immediate | Medium |
| SA-FASTAPI-07: Background task data exposure | Medium | 1 week | Medium |
| SA-FASTAPI-08: WebSocket auth | High | 1 week | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `python-security-features.md` — Language-level Python patterns
- `django-security.md` — Django-specific patterns
- `flask-security.md` — Flask-specific patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 2: Python framework coverage |
