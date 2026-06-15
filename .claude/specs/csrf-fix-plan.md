# Implementation Plan — CSRF Fix (Synchronizer-Token Pattern, Session-Bound)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Spec:** [csrf-fix.md](./csrf-fix.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [CSRF — state-changing POSTs accept any cross-origin submission](https://github.com/arifpucit/vuln-web-app/issues)

---

## 0. Plan Overview

This plan implements the fix specified in [csrf-fix.md](./csrf-fix.md). It closes the **CSRF** vulnerability and **only** that vulnerability, by installing a session-bound synchronizer-token mechanism: a **pure ASGI** middleware (`CSRFMiddleware`, implementing `__call__(scope, receive, send)` directly — *not* `BaseHTTPMiddleware`) that validates `csrf_token` on every POST against `scope["session"]["csrf_token"]` and re-streams the request body to the downstream handler, plus a helper that lazily issues the token on the GET handlers that render the login and signup forms, plus one hidden `<input>` per form template. The mechanism is implemented with Python standard library only (`secrets.token_urlsafe`, `secrets.compare_digest`, `json`, `urllib.parse.parse_qs`, `html.escape`) — no new dependency. The work is split into **six phases** so the change is small, individually verifiable, and easy to revert.

**Two implementation realities surfaced during code generation and are baked into this plan:**

1. **Pure ASGI, not `BaseHTTPMiddleware`.** `BaseHTTPMiddleware` wraps the request and caches `request.form()` on its own `Request` wrapper. FastAPI's `Form(...)` dependency builds a *new* `Request` from the same scope/receive for the route handler — the cache does not carry over, the body stream is already consumed, and the handler reports "all fields are required" (400). The pure-ASGI pattern reads the body once, validates the token, and replays the buffered body to the downstream app via a wrapped `receive` callable. This is the standard primitive for body-touching middleware.
2. **Middleware ordering is registration-order-prepended.** Starlette's `add_middleware` **prepends** to its internal `user_middleware` list, so the **last** `add_middleware` call ends up as the **outermost** layer on the request path. To get `RateLimit (outer) → Session → CSRF (inner) → handler`, the registration order is `CSRFMiddleware` first, then `SessionMiddleware`, then `RateLimitMiddleware`. Registering CSRF after Session would put CSRF outside Session, and CSRF would see `scope["session"]` unset on every request and reject everything — verified failure mode during implementation.

The seven already-closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db`, env-sourced session secret, escaped dashboard `{{username}}`, escaped `/search` reflection sinks, per-IP POST rate-limit middleware) MUST remain closed after every phase. Each phase ends with an explicit "MUST NOT" callout listing things that would silently alter another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Author `CSRFMiddleware` + `get_or_create_csrf_token` in a new `core/csrf.py` | `backend/app/core/csrf.py` | Stdlib pure-ASGI middleware: per-session token, method/scope-first short-circuit, body-replay, 403 on mismatch |
| 2 | Wire the middleware into `main.py` (CSRF first, Session second, RateLimit last) | `backend/app/main.py` | Import the class; `add_middleware(CSRFMiddleware)` *before* `SessionMiddleware`, with `RateLimitMiddleware` last so request flow is `RateLimit → Session → CSRF → handler` |
| 3 | Add token splice to `GET /login` and `GET /signup` handlers | `backend/app/api/routes/auth.py` | Two GET handlers gain `request: Request` param, call the helper, splice `{{csrf_token}}` |
| 4 | Add hidden `<input>` to `login.html` and `signup.html` | `frontend/templates/login.html`, `frontend/templates/signup.html` | One hidden field inside each form, no JS change |
| 5 | Update `CLAUDE.md` (map, rules, post-fix subsection, spec hierarchy) | `CLAUDE.md` | Reflect VULN-8's closed status; all 8 vulns now closed |
| 6 | End-to-end verification + vulnerability preservation audit | None (read-only) | Walk every Verification Step in spec §10 |

### Files Modified / Created (Authored)

Exactly the six files declared in spec §3:

- **New** — `backend/app/core/csrf.py`
- **Modified** — `backend/app/main.py`
- **Modified** — `backend/app/api/routes/auth.py`
- **Modified** — `frontend/templates/login.html`
- **Modified** — `frontend/templates/signup.html`
- **Modified** — `CLAUDE.md`

No dependency change (`secrets`, `html` are stdlib; `starlette` is already transitive via FastAPI), so no `pyproject.toml` or `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/services/auth_service.py` — preserves parameterized queries (VULN-1) and the bcrypt verify call (VULN-5). The service layer knows nothing about CSRF.
- `backend/app/core/security.py` — bcrypt stays (VULN-5).
- `backend/app/core/rate_limit.py` — per-IP rate-limit middleware stays (VULN-7).
- `backend/app/db/session.py` — schema and connection layer; untouched. **No schema change** — the token lives in the session cookie, not the database.
- `frontend/templates/dashboard.html` — no form on the dashboard. The only POST origins are `/login` and `/signup`; `/logout` is a GET link.
- Any CSS under `frontend/static/`.
- `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — the middleware is stdlib-only).

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After every phase, re-confirm:

1. **SQL Injection.** Already CLOSED — `auth_service.py` uses parameterized queries (`WHERE username = ?`, `VALUES (?, ?, ?)`) and `/search` uses `LIKE ?`. Not touched by this plan; stays closed.
2. **Stored XSS.** Already CLOSED — `welcome_page` escapes `username` via `html.escape(..., quote=True)`. Not touched; stays closed.
3. **Reflected XSS.** Already CLOSED — `/search` escapes `q`, both row columns, and the exception text. Not touched; stays closed.
4. **Session Hijacking.** Already CLOSED — `main.py` sources `SECRET_KEY` from the environment with a `secrets.token_hex(32)` fallback. Phase 2 adds one more `add_middleware` call below this region but does NOT alter the secret-key line.
5. **Weak Password (bcrypt).** Already CLOSED — `security.py` uses bcrypt at rounds ≥ 12 with the defensive `try/except` in `verify_password`. Not touched; stays closed.
6. **Exposed Database endpoint.** Already CLOSED — `/download/db` route removed. Not touched; stays closed.
7. **No Rate Limiting.** Already CLOSED — `RateLimitMiddleware` registered. Phase 2 adds `CSRFMiddleware` as the *first* `add_middleware` call (innermost) and moves `SessionMiddleware` to second; `RateLimitMiddleware` remains the last call and therefore the outermost layer. Verified in Phase 6.16 by a 6th-POST-returns-429 check.
8. **CSRF.** **This is the only vulnerability being closed.** After Phase 2 + Phase 3 + Phase 4, every POST `/signup` and POST `/login` without a matching session-bound token returns HTTP 403.

---

## Phase 1 — Author `CSRFMiddleware` in `backend/app/core/csrf.py`

### 1.1 Goal

Create a new file `backend/app/core/csrf.py` containing:

- A top-level helper `get_or_create_csrf_token(request)` that reads `request.session["csrf_token"]` and writes a freshly generated `secrets.token_urlsafe(32)` if the value is missing or empty.
- A `CSRFMiddleware` class implementing the **pure ASGI interface** (`__init__(self, app)` plus `async def __call__(self, scope, receive, send)`) — **not** `BaseHTTPMiddleware` (see plan §0 for rationale). The class reads `scope["session"]["csrf_token"]` for the expected value, drains the ASGI `receive` callable to buffer the request body, parses the urlencoded body with `urllib.parse.parse_qs` to extract the submitted token, compares them with `secrets.compare_digest`, and on success re-streams the buffered body to the downstream app via a wrapped `receive` callable. On mismatch, missing token, or any internal error, it sends an HTTP 403 response directly via `send` and returns without forwarding.

### 1.2 File to Create

- `backend/app/core/csrf.py`

### 1.3 File Contents

Write the file with exactly this content:

```python
import json
import secrets
from urllib.parse import parse_qs

from starlette.requests import Request


_SESSION_KEY = "csrf_token"
_FORM_FIELD = "csrf_token"


def get_or_create_csrf_token(request: Request) -> str:
    """Return the per-session CSRF token, lazily generating one on first read.

    The token is a 43-character URL-safe Base64 string carrying 256 bits of
    entropy from secrets.token_urlsafe(32). It is generated once per session
    (NFR-10) and lives only inside the signed session cookie -- no database
    column, no in-process map.
    """
    existing = request.session.get(_SESSION_KEY)
    if not isinstance(existing, str) or not existing:
        existing = secrets.token_urlsafe(32)
        request.session[_SESSION_KEY] = existing
    return existing


def _reject_response_bytes() -> tuple[bytes, list[tuple[bytes, bytes]]]:
    # FR-05 + NFR-06: generic body, no IP/path/UA leakage.
    body = json.dumps({"error": "CSRF token missing or invalid"}).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    return body, headers


async def _send_reject(send) -> None:
    body, headers = _reject_response_bytes()
    await send({"type": "http.response.start", "status": 403, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class CSRFMiddleware:
    """Synchronizer-token CSRF validator for every POST request.

    Pure ASGI middleware (not BaseHTTPMiddleware) so the request body can be
    read for token validation and then re-streamed to the downstream handler
    without consumption. Token lives in the session
    (request.session["csrf_token"]) -- see get_or_create_csrf_token for the
    issuance contract. Fail-closed on any validation failure (NFR-07).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # FR-01 / FR-07: method check is the first statement. Every non-POST
        # request and every non-HTTP scope bypasses the validator with zero
        # session/form access.
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        try:
            session = scope.get("session")
            if not isinstance(session, dict):
                # EC-01: SessionMiddleware did not populate scope["session"].
                await _send_reject(send)
                return

            expected = session.get(_SESSION_KEY)
            if not isinstance(expected, str) or not expected:
                # EC-02: no session token issued yet -- reject.
                await _send_reject(send)
                return

            body = await _read_body(receive)
            submitted = _extract_csrf_token(scope, body)
            if not isinstance(submitted, str) or not submitted:
                # EC-03 / EC-04: missing or empty form field -- reject.
                await _send_reject(send)
                return

            # FR-06: constant-time comparison, coerce to str defensively.
            if not secrets.compare_digest(str(expected), str(submitted)):
                # EC-05: wrong value -- reject.
                await _send_reject(send)
                return
        except Exception:
            # NFR-07: fail-CLOSED on any internal bookkeeping error. The
            # original vulnerability was an unguarded state-changing POST;
            # failing open here would re-open it.
            await _send_reject(send)
            return

        # Re-stream the buffered body so the downstream handler can re-read it.
        await self.app(scope, _replay_receive(body), send)


async def _read_body(receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            # Disconnect or unexpected message -- stop reading.
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _extract_csrf_token(scope, body: bytes) -> str | None:
    content_type = b""
    for name, value in scope.get("headers", []):
        if name == b"content-type":
            content_type = value
            break

    # Only urlencoded form bodies carry the CSRF token in this lab. JSON or
    # multipart bodies would need a different path; spec §EC-09 / §EC-10
    # explicitly scopes CSRF to form-urlencoded POSTs.
    if not content_type.startswith(b"application/x-www-form-urlencoded"):
        return None

    try:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        return None
    values = parsed.get(_FORM_FIELD)
    if not values:
        return None
    return values[0]


def _replay_receive(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive
```

### 1.4 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| Imports limited to `json`, `secrets`, `urllib.parse.parse_qs`, and `starlette.requests` (typing only for the helper) | Stdlib-only — no new third-party dependency; pure ASGI middleware avoids `BaseHTTPMiddleware`'s body-consumption pitfall | FR-11, NFR-09, AC-02 |
| `_SESSION_KEY = "csrf_token"`, `_FORM_FIELD = "csrf_token"` module constants | Avoid magic strings; the form field and session key are intentionally the same string for clarity | (cleanliness) |
| `get_or_create_csrf_token(request)` reads `request.session.get(...)` before generating | Idempotent within a session — visiting `/login` then `/signup` does NOT rotate the token | FR-02, NFR-10, AC-12 |
| `isinstance(existing, str)` and `not existing` checks | Defensive: a session value that was overwritten by another middleware (or unset) is treated as absent | FR-02 |
| `secrets.token_urlsafe(32)` | 32 bytes = 256 bits of entropy → unguessable; URL-safe Base64 so no HTML-significant characters | FR-02, EC-08, NFR-01 |
| `_send_reject(send)` emits an `http.response.start` (status 403, content-type + content-length headers) followed by `http.response.body` | Single source of truth for the reject response shape; emitted directly via ASGI `send`, no `Set-Cookie` change | FR-05, NFR-06, AC-04, AC-05 |
| **Pure ASGI** class (no `BaseHTTPMiddleware`) with `__init__(self, app)` and `async def __call__(self, scope, receive, send)` | `BaseHTTPMiddleware`'s `await request.form()` consumes the body on its own `Request` wrapper; FastAPI builds a fresh `Request` for the handler and finds the stream empty (verified failure mode during implementation). Pure ASGI lets us read the body once and replay it to the downstream app explicitly. | FR-04, EC-12, AC-01 |
| `if scope["type"] != "http" or scope.get("method") != "POST"` as the very first statement of `__call__` | Method/scope-first short-circuit — non-POST and non-HTTP overhead is two dict lookups + two equality compares | FR-01, FR-07, AC-03 |
| `session = scope.get("session")` and `if not isinstance(session, dict): _send_reject(send)` | Defensive: if `SessionMiddleware` did not populate the scope (e.g., misconfigured ordering), fail-closed rather than crash | EC-01, NFR-07 |
| `expected = session.get(_SESSION_KEY)` | Reads from the Starlette-decoded session dict — registration order puts `SessionMiddleware` *outside* `CSRFMiddleware` on the request path, so the session is already populated when we read | FR-04, FR-09 |
| `if not isinstance(expected, str) or not expected: _send_reject(send)` | Fail-closed when no token has been issued yet — students cannot brute-force `POST /signup` via raw `curl` without first fetching `GET /signup`/`GET /login` | EC-02, NFR-07 |
| `body = await _read_body(receive)` — drain `http.request` messages until `more_body=False` | Buffers the full request body for parsing; the original `receive` is now exhausted, so a wrapped replay is mandatory | FR-04, EC-12 |
| `_extract_csrf_token(scope, body)` — checks `content-type == application/x-www-form-urlencoded`, then `parse_qs(body.decode("utf-8"), keep_blank_values=True)` | The lab's POSTs are urlencoded (login JS `FormData` and native signup form both default to urlencoded); JSON / multipart explicitly out of scope per spec §EC-09 / §EC-10 | FR-04, EC-09, EC-10 |
| `if not isinstance(submitted, str) or not submitted: _send_reject(send)` | Treats missing-key, empty-string, and non-string the same — fail-closed | EC-03, EC-04, NFR-07 |
| `secrets.compare_digest(str(expected), str(submitted))` | Constant-time comparison; spec mandates `compare_digest`, never `==` | FR-06, AC-11, TC-05 |
| `str(...)` coercion on both operands | Defensive against an attacker-controllable session value that was overwritten by some future middleware to a bytes/int | FR-06 |
| `try ... except Exception: await _send_reject(send); return` around the whole validation | Fail-**closed** on any internal error (contrast with the rate-limit middleware's fail-open) — re-opening the original vulnerability via liveness errors would be self-defeating | NFR-07 |
| `_replay_receive(body)` returns a closure that emits one `http.request` message with the buffered body on the first call and `http.disconnect` thereafter | The standard ASGI body-replay pattern: the downstream `app(scope, wrapped_receive, send)` reads exactly the same bytes as the original client sent, and FastAPI's `Form(...)` dependency parses them normally | FR-04, EC-12 |
| Pass the original `send` through to `self.app` unchanged | Response messages flow straight from the handler to the client — no buffering, no header rewrites, `Set-Cookie` survives intact | FR-08 |
| No log emission | The lab application does not configure structured logging; emitting logs would add noise and risk leaking session tokens to log sinks | NFR-06 |

### 1.5 What NOT to Change in Phase 1

- **DO NOT** use `BaseHTTPMiddleware`. `await request.form()` inside its `dispatch` consumes the body on a wrapper Request that FastAPI's handler never sees, leaving the downstream `Form(...)` dependency with an empty body and producing handler-level 400s on legitimate requests. The pure-ASGI pattern with explicit body replay is the only correct choice for body-touching middleware in this stack.
- **DO NOT** add an `Origin` or `Referer` header check. The synchronizer token is self-contained (spec §2.4). Layering header checks adds complexity without a matching threat-model gain.
- **DO NOT** validate via `==` between `expected` and `submitted`. The spec mandates `secrets.compare_digest` (constant-time) (spec §FR-06, §AC-11).
- **DO NOT** rotate the token on every request, on login, or on session writes. The spec mandates one token per session (spec §2.4, §NFR-10). Rotating per-request would break the login JS's submit-and-show-error flow.
- **DO NOT** store the token in a separate cookie ("double-submit cookie" pattern). The spec mandates session-only storage (spec §2.4).
- **DO NOT** read `csrf_token` from query string, JSON body, or custom headers. The spec mandates form-body submission only (spec §EC-11).
- **DO NOT** clear `scope["session"]` (or otherwise mutate the session dict) on a CSRF failure. Doing so would let an attacker who can issue forged POSTs (without succeeding) repeatedly log the victim out — a self-inflicted DoS (spec §FR-05).
- **DO NOT** forward `(scope, receive, send)` to `self.app` after a rejection. The reject path MUST emit the 403 directly via `send` and `return` — the downstream handler must never run.
- **DO NOT** forget to replay the body. The non-rejection path MUST forward to `self.app(scope, _replay_receive(body), send)`, NOT `self.app(scope, receive, send)`. Forwarding the original (now-exhausted) `receive` will produce a 400 in the handler.
- **DO NOT** add a third-party dependency (`fastapi-csrf-protect`, `starlette-csrf`, etc.). The spec mandates stdlib-only (spec §FR-11, §NFR-09).
- **DO NOT** emit a log line on rejection. The 403 response is the only signal (spec §NFR-06).
- **DO NOT** fail-OPEN on internal exceptions. The CSRF middleware fails CLOSED (spec §NFR-07) — opposite of the rate-limit middleware's fail-open posture. Liveness errors must not re-open the vulnerability.

### 1.6 Phase 1 Verification (Pre-Server)

```bash
# File exists and contains the right class + helper
grep -n 'class CSRFMiddleware' backend/app/core/csrf.py
grep -n 'def get_or_create_csrf_token' backend/app/core/csrf.py

# Stdlib-only imports
grep -nE '^(import|from)' backend/app/core/csrf.py
# Expected: only json, secrets, urllib.parse, and starlette.requests
# (the last used only for typing the helper's Request parameter)

# Pure ASGI -- no BaseHTTPMiddleware inheritance
grep -n 'BaseHTTPMiddleware' backend/app/core/csrf.py \
  || echo '(no BaseHTTPMiddleware — pure ASGI, preserved)'

# Method/scope check is the very first statement of __call__
grep -n 'scope\["type"\] != "http"' backend/app/core/csrf.py
grep -n 'scope.get("method") != "POST"' backend/app/core/csrf.py

# Constant-time comparison used
grep -n 'secrets.compare_digest' backend/app/core/csrf.py

# Body-replay pattern present
grep -n '_replay_receive\|async def __call__' backend/app/core/csrf.py

# No `==` between expected and submitted
grep -n 'expected == submitted\|submitted == expected' backend/app/core/csrf.py \
  || echo '(no naive == comparison — preserved)'

# No double-submit cookie / no proxy-header trust
grep -niE 'set_cookie|x-csrf-token|referer|^.*\borigin\b' backend/app/core/csrf.py \
  || echo '(no header check, no double-submit cookie — preserved)'

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.core.csrf import CSRFMiddleware, get_or_create_csrf_token; print('import ok')" && cd ..
```

Expected: the class/helper greps each match; the `BaseHTTPMiddleware` grep prints its fallback (confirming pure ASGI); the scope-type and method greps match; the `compare_digest` and `__call__` greps match; the naive-`==` grep prints its fallback; the proxy-header grep prints its fallback (the word "original" appears in a comment and is fine — the regex anchors on a real `origin` token); the import smoke test prints `import ok`.

---

## Phase 2 — Wire the Middleware Into `backend/app/main.py`

### 2.1 Goal

Add an import for `CSRFMiddleware` and register it via `app.add_middleware(CSRFMiddleware)` **first**, then the existing `SessionMiddleware` second, then the existing `RateLimitMiddleware` last. Starlette's `add_middleware` prepends to `app.user_middleware`, so the *last* `add_middleware` call ends up *outermost* on the request path. The resulting layering is `RateLimit (outer) → Session → CSRF (inner) → handler` — per spec §FR-09. The pre-fix code registered `SessionMiddleware` first; Phase 2 moves the CSRF registration **before** it so `SessionMiddleware` wraps `CSRFMiddleware` on the request path and the latter can read `scope["session"]`.

### 2.2 File to Modify

- `backend/app/main.py`

### 2.3 Edit A — Add the Middleware Import

**Before** (L13–L15 region):

```python
from app.api.routes.auth import router
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db
```

**After**:

```python
from app.api.routes.auth import router
from app.core.csrf import CSRFMiddleware
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db
```

The new import is placed alongside the other local-app imports, alphabetically between `auth` and `rate_limit`.

### 2.4 Edit B — Reorder Registrations: CSRF First, Then Session, Then RateLimit

**Before** (L19–L32 region):

```python
# FIXED: Session Hijacking closed -- secret loaded from the environment,
# with a strong random fallback so a fresh checkout never ships a known key.
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# FIXED: No Rate Limiting closed -- per-IP sliding-window throttle on every POST.
# Defaults: 5 POSTs per 60 s per IP. Tune via RATE_LIMIT_MAX / RATE_LIMIT_WINDOW_SECONDS.
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

**After**:

```python
# NOTE on Starlette middleware ordering: add_middleware() prepends, so the
# LAST add_middleware call is the OUTERMOST layer on the request path.
# Desired layering: RateLimit (outer) -> Session -> CSRF (inner) -> handler,
# so CSRF can read request.session and rate-limit still gates floods first.
# Therefore registrations go inner-to-outer: CSRF, Session, RateLimit.

# FIXED: CSRF closed -- synchronizer-token middleware rejects every POST whose
# csrf_token form field does not match request.session["csrf_token"].
app.add_middleware(CSRFMiddleware)

# FIXED: Session Hijacking closed -- secret loaded from the environment,
# with a strong random fallback so a fresh checkout never ships a known key.
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# FIXED: No Rate Limiting closed -- per-IP sliding-window throttle on every POST.
# Defaults: 5 POSTs per 60 s per IP. Tune via RATE_LIMIT_MAX / RATE_LIMIT_WINDOW_SECONDS.
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

Four concrete changes:

1. A new `NOTE on Starlette middleware ordering` comment block at the top of the middleware region, explaining the prepend semantics for future maintainers.
2. A new `# FIXED: CSRF closed -- ...` two-line comment block followed by `app.add_middleware(CSRFMiddleware)` placed **above** the existing `SessionMiddleware` registration. Starlette's prepend semantics ("last `add_middleware` call = outermost") then yields the layering `RateLimit (outer) → Session → CSRF (inner)` — `SessionMiddleware` wraps `CSRFMiddleware` on the request path, so CSRF can read `scope["session"]`.
3. The `SessionMiddleware` registration moves down by 4 lines. The `SECRET_KEY = os.environ.get(...)` line and the `add_middleware(SessionMiddleware, secret_key=SECRET_KEY)` call are byte-for-byte unchanged — VULN-4's closure is the env-sourced secret, not the line number, so this relocation does not regress VULN-4.
4. Nothing else changes. `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_SECONDS`, the static mounts, the `init_db()` call, and the `__main__` uvicorn block are byte-for-byte unchanged.

### 2.5 Edit Summary

Edits inside `main.py`:

1. **Local-imports block** — add `from app.core.csrf import CSRFMiddleware`.
2. **Middleware-registration region** — add the `NOTE` comment block and the `# FIXED: CSRF closed -- ...` comment + `app.add_middleware(CSRFMiddleware)` call directly above the existing `SessionMiddleware` registration. The `SessionMiddleware` block (its `# FIXED: Session Hijacking ...` comment, the `SECRET_KEY = ...` line, and the `add_middleware(SessionMiddleware, ...)` call) shifts down 4 lines but is otherwise unchanged. The `RateLimitMiddleware` block is unchanged.

No other line in the file changes.

### 2.6 Line-by-Line Justification

| Line / Block | Decision | Spec ref |
|---|---|---|
| `from app.core.csrf import CSRFMiddleware` | Local-app import for the new middleware | AC-01, AC-08 |
| `NOTE on Starlette middleware ordering` comment | Documents the prepend semantics inline so a future maintainer who adds another middleware does not unintentionally invert the layering | FR-09 |
| `# FIXED: CSRF closed -- ...` comment block | Mirrors the existing `# FIXED: Session Hijacking closed -- ...` and `# FIXED: No Rate Limiting closed -- ...` blocks below it | (style consistency) |
| `app.add_middleware(CSRFMiddleware)` placed BEFORE `SessionMiddleware` and `RateLimitMiddleware` | Starlette's `add_middleware` prepends to `user_middleware`, so the *first* call is the *innermost* layer. With this order, CSRF is innermost (sees the session populated by the outer Session layer), Session is middle, and RateLimit is outermost (gates floods first). | FR-09 |
| `SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))` unchanged | VULN-4 closure stays exactly as it is; only the surrounding 4-line block moves down | AC-14 |
| `add_middleware(SessionMiddleware, secret_key=SECRET_KEY)` call body unchanged | VULN-4 closure preserved — the `secret_key=SECRET_KEY` argument is the closure, not the source line number | AC-14 |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` reads unchanged | VULN-7 closure stays exactly as it is | AC-14 |
| Static mounts and `init_db()` unchanged | No other behavior changes | NFR-02, NFR-03 |

### 2.7 What NOT to Change in Phase 2

- **DO NOT** put the `CSRFMiddleware` registration **after** `SessionMiddleware`. Because `add_middleware` prepends, "after" in source order means "outside" on the request path — CSRF would then run *before* `SessionMiddleware` populates `scope["session"]`, and every POST would be rejected with 403 (verified failure mode during implementation).
- **DO NOT** put `CSRFMiddleware` **after** `RateLimitMiddleware`. CSRF would become the outermost layer and would parse every request body before rate-limit could short-circuit floods — defeating the "fail before bcrypt" guarantee of VULN-7.
- **DO NOT** change the `SECRET_KEY = os.environ.get(...)` line or the `secret_key=SECRET_KEY` argument. VULN-4 stays closed (spec §AC-14). Don't replace the `secrets.token_hex(32)` fallback with anything else. The line is allowed to move down 4 lines as part of the registration-order edit, but its body is byte-for-byte unchanged.
- **DO NOT** touch the `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` env reads or the `RateLimitMiddleware` registration. VULN-7 stays closed (spec §AC-14).
- **DO NOT** pass any constructor arguments to `CSRFMiddleware`. The middleware is configuration-free by design (spec §2.4 — no env var).
- **DO NOT** parse `.env` files. No new dependency.
- **DO NOT** add a third-party dependency or modify `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (spec §NFR-09, §AC-16).
- **DO NOT** change the static-file mounts, the FastAPI title, the uvicorn host/port logic, or the `init_db()` call.
- **DO NOT** re-introduce a closed vulnerability:
  - No re-adding `/download/db` (VULN-6 stays closed).
  - No reverting `main.py` to the hardcoded `"super-secret-key-12345"` (VULN-4 stays closed).
  - No reverting `security.py` to MD5 (VULN-5 stays closed).
  - No reverting `auth_service.py` / `auth.py` to string-concatenated SQL (VULN-1 stays closed).
  - No removing the `html.escape` calls in `auth.py` (VULN-2 + VULN-3 stay closed).
  - No removing the `RateLimitMiddleware` registration (VULN-7 stays closed).

### 2.8 Phase 2 Verification (Pre-Server)

```bash
# Import added
grep -n 'from app.core.csrf import CSRFMiddleware' backend/app/main.py

# Source-order: CSRFMiddleware < SessionMiddleware < RateLimitMiddleware
awk '
  /add_middleware\(CSRFMiddleware/        { c=NR }
  /add_middleware\(SessionMiddleware/     { s=NR }
  /add_middleware\(RateLimitMiddleware|add_middleware\(\s*$/ { r=NR }
  END {
    if (c && s && r && c < s && s < r) print "source order ok: CSRF@"c" < Session@"s" < RateLimit@"r;
    else print "ORDER WRONG: CSRF="c" Session="s" RateLimit="r;
  }' backend/app/main.py

# Runtime middleware order: outer to inner = RateLimit, Session, CSRF
cd backend && uv run python -c "
from app.main import app
order = [m.cls.__name__ for m in app.user_middleware]
print('runtime order (outer->inner):', order)
assert order == ['RateLimitMiddleware', 'SessionMiddleware', 'CSRFMiddleware'], 'WRONG'
print('runtime order ok')
" && cd ..

# VULN-4 closure untouched
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-7 closure untouched
grep -n 'RATE_LIMIT_MAX' backend/app/main.py
grep -n 'RateLimitMiddleware' backend/app/main.py

# No dependency-file edits
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.main import app; print('boot ok')" && cd ..
```

Expected: the import grep matches; the awk line prints `source order ok: ...`; the runtime-order Python check prints `runtime order ok`; the VULN-4 grep matches and the hardcoded-secret grep prints its fallback; the VULN-7 greps match; the dependency-files grep prints its fallback; the boot smoke test prints `boot ok`.

---

## Phase 3 — Add Token Splice to GET Handlers in `backend/app/api/routes/auth.py`

### 3.1 Goal

Modify `GET /login` and `GET /signup` to:

1. Take a `request: Request` parameter (currently they take none).
2. Call `get_or_create_csrf_token(request)` to read or issue the per-session token.
3. Splice the token into the rendered HTML via `str.replace("{{csrf_token}}", html.escape(token, quote=True))`, in the same pattern as the existing `{{username}}` substitution in `welcome_page`.

All POST handlers, `index`, `search_user`, `welcome_page`, and `logout` MUST remain byte-for-byte unchanged.

### 3.2 File to Modify

- `backend/app/api/routes/auth.py`

### 3.3 Edit A — Add the Helper Import

**Before** (top of file):

```python
import os
import html

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.services import auth_service
from app.db.session import get_db
```

**After**:

```python
import os
import html

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.csrf import get_or_create_csrf_token
from app.services import auth_service
from app.db.session import get_db
```

The new import is placed alongside other local-app imports, alphabetically before `app.services` and `app.db.session`.

### 3.4 Edit B — Modify `GET /signup`

**Before**:

```python
@router.get("/signup")
async def signup_page():
    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        html = f.read()
    return HTMLResponse(content=html)
```

**After**:

```python
@router.get("/signup")
async def signup_page(request: Request):
    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", __import__("html").escape(token, quote=True))
    return HTMLResponse(content=page)
```

Wait — the local `html` variable in the original shadows the imported `html` module. The cleanest fix is to rename the local to `page` (which we want anyway for consistency with `welcome_page`). That removes the shadowing entirely, so the splice can use the imported `html` module directly:

**Corrected After**:

```python
@router.get("/signup")
async def signup_page(request: Request):
    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)
```

Three concrete changes:

1. `signup_page()` becomes `signup_page(request: Request)`.
2. The local variable `html` (which shadowed the imported `html` module) becomes `page`, matching the existing `welcome_page` style.
3. Two new lines add the token splice via the existing `html.escape(..., quote=True)` pattern.

### 3.5 Edit C — Modify `GET /login`

**Before**:

```python
@router.get("/login")
async def login_page():
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "r") as f:
        html = f.read()
    return HTMLResponse(content=html)
```

**After**:

```python
@router.get("/login")
async def login_page(request: Request):
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)
```

Same three changes as Edit B, applied to the login handler.

### 3.6 Files NOT to Modify in This Phase

- The POST handlers `signup_post`, `login_post` — byte-for-byte unchanged. They consume `username`, `email`, `password` via FastAPI's `Form(...)` dependency. The middleware has already validated the `csrf_token` field, and FastAPI's `Form(...)` ignores unknown extra fields by default — so the POST handler signatures do NOT change.
- `search_user`, `welcome_page`, `logout`, `index` — byte-for-byte unchanged. `/search` is a GET and is outside the CSRF scope (spec §2.4). `/welcome` and `/logout` are GETs. `/` is a redirect to `/signup`.
- `backend/app/services/auth_service.py` — byte-for-byte unchanged.

### 3.7 Line-by-Line Justification

| Line / Block | Decision | Spec ref |
|---|---|---|
| `from app.core.csrf import get_or_create_csrf_token` | Local-app import for the new helper | AC-01, AC-09 |
| `signup_page(request: Request)` | Signature gains `request` so the helper can read `request.session` | FR-03 |
| `with open(...) as f: page = f.read()` (rename `html` → `page`) | Removes the existing variable-shadow of the imported `html` module, matching the pattern in `welcome_page` | (cleanliness — required for the splice to use `html.escape`) |
| `token = get_or_create_csrf_token(request)` | Lazy issuance: returns the existing session token, or generates one if missing | FR-03, NFR-10 |
| `page = page.replace("{{csrf_token}}", html.escape(token, quote=True))` | Same splice pattern as `{{username}}` in `welcome_page`; `html.escape` is defensive (the token alphabet contains no HTML-significant chars) | FR-03, EC-08 |
| `login_page` mirrors `signup_page` | Same shape for both form-rendering GETs | FR-03 |
| All other handlers unchanged | Surgical scope | FR-10, NFR-02, AC-13 |

### 3.8 What NOT to Change in Phase 3

- **DO NOT** touch `signup_post` or `login_post`. The POST handlers do not need to read `csrf_token` themselves — the middleware has validated it (spec §EC-13). FastAPI's `Form(...)` dependency ignores the extra `csrf_token` field by default.
- **DO NOT** touch `search_user`. It is GET-only and outside CSRF scope (spec §2.4).
- **DO NOT** touch `welcome_page`. It is GET-only. The `{{username}}` splice + `html.escape` (VULN-2 closure) MUST stay byte-for-byte.
- **DO NOT** touch `logout`. It is GET-only. `request.session.clear()` MUST stay — clearing the session is correct on logout (and it also invalidates the CSRF token, see spec §EC-07).
- **DO NOT** modify `auth_service.py`. The service layer knows nothing about CSRF (spec §3 file list).
- **DO NOT** change the `from fastapi import APIRouter, Form, Request` import. `Request` was already imported in the existing file (used by `login_post` and `welcome_page`).
- **DO NOT** introduce any new template-engine dependency (Jinja2 etc.). The `str.replace` pattern is the established style.
- **DO NOT** introduce a "render template" helper or move the `replace` calls into a separate file. The two splices are five-line additions and the spec mandates a surgical edit (spec §FR-10).

### 3.9 Phase 3 Verification (Pre-Server)

```bash
# Helper imported
grep -n 'from app.core.csrf import get_or_create_csrf_token' backend/app/api/routes/auth.py

# Both GET handlers updated
grep -n 'async def signup_page(request: Request)' backend/app/api/routes/auth.py
grep -n 'async def login_page(request: Request)' backend/app/api/routes/auth.py

# Token splice present in both handlers
grep -c '{{csrf_token}}' backend/app/api/routes/auth.py
# Expected: 2

# html.escape calls — original 5 + 2 new = 7
test "$(grep -c 'html.escape(' backend/app/api/routes/auth.py)" -ge 7 \
  && echo '(>=7 html.escape calls — VULN-2/3 closures intact + 2 new CSRF splices)'

# POST handlers untouched
grep -n 'async def signup_post' backend/app/api/routes/auth.py
grep -n 'async def login_post' backend/app/api/routes/auth.py

# Variable-shadow fixed in both GET handlers (no `html = f.read()` line)
grep -n 'html = f.read()' backend/app/api/routes/auth.py \
  || echo '(no html-module shadow — preserved)'

# Service layer untouched
git diff --stat backend/app/services/auth_service.py | grep -E '^\s*$|0 (files? changed|insertions?|deletions?)' \
  || git diff --stat backend/app/services/auth_service.py
```

Expected: each grep matches as described; the `html = f.read()` grep prints its fallback (because we renamed both local variables to `page`); the service-layer diff shows no changes.

---

## Phase 4 — Add Hidden `<input>` to Both Templates

### 4.1 Goal

Add a single hidden field `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` inside the `<form>` element in both `login.html` and `signup.html`. No JS, CSS, layout, or other structural change.

### 4.2 Files to Modify

- `frontend/templates/login.html`
- `frontend/templates/signup.html`

### 4.3 Edit A — `frontend/templates/login.html`

Inside the existing `<form id="login-form">` (currently at L70), add the hidden field as the very first child of the form. The diff for that region:

**Before** (L70):

```html
                <form id="login-form">
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
```

**After**:

```html
                <form id="login-form">
                    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
```

Placing it as the first child of the form ensures:

- The hidden input is included in `new FormData(form)` (which iterates all named form controls in document order).
- It is visually offscreen (it has no rendered representation — `type="hidden"` per HTML spec).
- It is grouped with the form, not the surrounding markup, so a future template refactor that moves the form will move the hidden field with it.

### 4.4 Edit B — `frontend/templates/signup.html`

Inside the existing `<form id="signup-form" action="/signup" method="POST">` (currently at L68), add the hidden field as the very first child. The diff for that region:

**Before** (L68):

```html
                <form id="signup-form" action="/signup" method="POST">
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
```

**After**:

```html
                <form id="signup-form" action="/signup" method="POST">
                    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
```

The behavior is identical to Edit A: the native form-POST submission includes the hidden input in the urlencoded body.

### 4.5 Files NOT to Modify in This Phase

- `frontend/templates/dashboard.html` — there is no `<form>` on the dashboard. The only state-changing endpoints are `/login` and `/signup`; `/logout` is a GET `<a>` link.
- `frontend/static/css/styles.css` — no styling change. `type="hidden"` inputs are unrendered by the browser; no CSS rule is needed.
- Any image under `frontend/static/images/`.

### 4.6 Line-by-Line Justification

| Edit | Decision | Spec ref |
|---|---|---|
| Hidden input is the **first** child of the form | Document-order inclusion in `new FormData(form)`; survives future form-restructuring; visually offscreen | FR-03, AC-09 |
| `name="csrf_token"` matches `_FORM_FIELD = "csrf_token"` in `core/csrf.py` | Same string everywhere to avoid magic-string drift | FR-04 |
| `value="{{csrf_token}}"` matches the splice placeholder in `signup_page` / `login_page` | The handler does `page.replace("{{csrf_token}}", html.escape(token, quote=True))` | FR-03 |
| `type="hidden"` (not `type="text"` with CSS) | Native HTML hidden-input behavior; no CSS, no a11y concern | AC-18 |
| No JS wiring added to either template | The login form already uses `new FormData(form)` which includes hidden inputs; the signup form is a native form POST | NFR-03 |

### 4.7 What NOT to Change in Phase 4

- **DO NOT** touch the theme-toggle script, the theme-toggle button, the auth-container layout, the form-group structure, the password-confirm validation script in signup, or the login fetch handler.
- **DO NOT** add JavaScript that reads `document.cookie` to find the token. The token is NOT in a cookie that JS can read; it lives in the signed session cookie (server-side only). Add the token only via the server-rendered hidden field (spec §FR-03).
- **DO NOT** touch `dashboard.html`. It has no form.
- **DO NOT** add a separate `<input type="hidden" name="csrf_token">` outside the `<form>` tag. The browser only includes form controls that are descendants of the submitting form.
- **DO NOT** change `action="/signup"` or `method="POST"` on the signup form.
- **DO NOT** add a `csrf_token` URL query string anywhere. The middleware reads only from the parsed urlencoded request body, not from `scope["query_string"]` (spec §EC-11).

### 4.8 Phase 4 Verification (Pre-Server)

```bash
# Both templates carry exactly one hidden csrf_token input
grep -c 'name="csrf_token"' frontend/templates/login.html
# Expected: 1
grep -c 'name="csrf_token"' frontend/templates/signup.html
# Expected: 1

# The hidden input is inside the form, on the line immediately after the <form> open tag
awk '/<form id="login-form"/{flag=1; next} flag && /csrf_token/{print "login: csrf_token on line "NR" — ok"; flag=0}' frontend/templates/login.html
awk '/<form id="signup-form"/{flag=1; next} flag && /csrf_token/{print "signup: csrf_token on line "NR" — ok"; flag=0}' frontend/templates/signup.html

# Dashboard untouched
grep -n 'csrf_token' frontend/templates/dashboard.html \
  || echo '(no csrf_token in dashboard — preserved, no form there)'

# No JS read of cookie for csrf
grep -ni 'document\.cookie' frontend/templates/login.html frontend/templates/signup.html \
  || echo '(no document.cookie access — preserved)'

# No change to existing form action/method
grep -n 'action="/signup" method="POST"' frontend/templates/signup.html
```

Expected: both `grep -c` lines print `1`; both `awk` lines print their respective `ok` message; the dashboard and document.cookie greps each print their fallback; the signup action/method grep matches.

---

## Phase 5 — Update `CLAUDE.md`

### 5.1 Goal

Reflect VULN-8's closed status across the four `CLAUDE.md` sections that mention CSRF or vulnerability counts: the opening paragraph, the Vulnerability Map row, the "Important Rules" section, and the Specification Hierarchy list. Also add a new "CSRF Protection After the Fix" subsection mirroring the existing "Rate Limiting After the Fix" subsection.

### 5.2 File to Modify

- `CLAUDE.md`

### 5.3 Edit A — Opening Paragraph (Count Update)

**Before** (L5):

> This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. Seven of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), VULN-3 (Reflected XSS), and VULN-7 (No Rate Limiting) — have since been closed. The other 1 remains intentionally exploitable for students to attack, understand, and remediate.

**After**:

> This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. All 8 of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), VULN-3 (Reflected XSS), VULN-7 (No Rate Limiting), and VULN-8 (CSRF) — have since been closed. No vulnerabilities remain intentionally exploitable; the project is now a complete "before / after" reference, with v0.1.0 as the fully vulnerable baseline.

**Before** (L7 — the WARNING paragraph):

> **WARNING:** The remaining 1 vulnerability is intentional. Do not "fix" it unless explicitly asked. The closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, the escaped search output, and the per-IP POST rate-limit middleware) are permanent — do not revert them.

**After**:

> **WARNING:** All eight closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, the escaped search output, the per-IP POST rate-limit middleware, and the synchronizer-token CSRF middleware) are permanent — do not revert them. To study the original vulnerabilities, students should check out the `v0.1.0` tag rather than weakening the current codebase.

### 5.4 Edit B — Vulnerability Map Row

**Before** (the VULN-8 row in the Vulnerability Map table):

```
| 8 | CSRF | Global | No CSRF tokens | Open |
```

**After**:

```
| 8 | CSRF | `backend/app/core/csrf.py` + `backend/app/main.py` + form templates | Synchronizer-token `CSRFMiddleware` rejects every POST whose `csrf_token` form field does not match `request.session["csrf_token"]`; token issued by `get_or_create_csrf_token` on `GET /login` / `GET /signup` and spliced into the rendered HTML | **Closed** |
```

### 5.5 Edit C — "Important Rules" Section

**Before**:

> - Never add CSRF tokens to forms (preserves VULN-8)

**After**:

> - Never remove the CSRF middleware in `backend/app/main.py` / `backend/app/core/csrf.py`, the hidden `csrf_token` field in the login/signup templates, or the `get_or_create_csrf_token` calls in the two GET handlers. VULN-8 is closed by a session-bound synchronizer-token pattern: a 256-bit token (`secrets.token_urlsafe(32)`) is stored in `request.session["csrf_token"]`, spliced into every form, and validated on every POST with `secrets.compare_digest`. The middleware, the hidden field, and the splice are permanent and must stay (stdlib-only, no third-party CSRF dependency).

### 5.6 Edit D — Add "CSRF Protection After the Fix" Subsection

Insert this subsection between the existing "Rate Limiting After the Fix" subsection and the "Frontend-Backend Integration" subsection:

````markdown
### CSRF Protection After the Fix

`main.py` registers a stdlib-only `CSRFMiddleware` (defined in `backend/app/core/csrf.py`) as the first `add_middleware` call, with `SessionMiddleware` second and `RateLimitMiddleware` last:

```python
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

Starlette wraps middleware in reverse-registration order, so the request path becomes `RateLimit (outer) → CSRF → Session (inner) → handler`. Rate-limit still gates floods first; CSRF reads the already-decoded session.

- **Token:** `secrets.token_urlsafe(32)` — 256 bits of entropy, URL-safe Base64 (43 characters, `[A-Za-z0-9_-]`).
- **Storage:** `request.session["csrf_token"]` — lives only inside the signed session cookie (VULN-4's `SECRET_KEY` signs the whole session dict). No database column, no in-process map.
- **Issuance:** `GET /login` and `GET /signup` call `get_or_create_csrf_token(request)`, which lazily writes a token on first read and returns the existing value on subsequent reads (one token per session, not per request).
- **Splice:** the handlers do `page.replace("{{csrf_token}}", html.escape(token, quote=True))` — same pattern as the `{{username}}` splice in `welcome_page`. The hidden input `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` is the first child of each form.
- **Validation:** on every POST, `CSRFMiddleware` drains the ASGI `receive` to buffer the body, runs `urllib.parse.parse_qs` over the urlencoded bytes, extracts the `csrf_token` value, and compares it against `scope["session"]["csrf_token"]` with `secrets.compare_digest` (constant-time). Mismatch, missing field, empty field, wrong content-type, or any internal exception → HTTP `403` with body `{"error": "CSRF token missing or invalid"}` (fail-CLOSED). On success the same body bytes are replayed to the downstream handler via a wrapped `receive`.
- **Scope:** every `POST` request. GET / HEAD / OPTIONS / static-file requests bypass with a single method-check.
- **What it does not do:** no `Origin` / `Referer` header check, no double-submit cookie, no per-request rotation, no `SameSite` cookie-attribute change. The synchronizer token alone is sufficient on this single-origin lab.
- **Local lab use:** no configuration needed. Visit `/login` or `/signup` and the token is issued automatically; subsequent forms in the same session reuse it.
````

### 5.7 Edit E — Append to Specification Hierarchy

**Before** (the last item in the Specification Hierarchy list):

```
10. `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md` — VULN-7 fix
```

**After** — append item 11:

```
10. `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md` — VULN-7 fix
11. `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md` — VULN-8 fix
```

### 5.8 What NOT to Change in Phase 5

- **DO NOT** touch the count or status of VULN-1, VULN-2, VULN-3, VULN-4, VULN-5, VULN-6, or VULN-7 in the Vulnerability Map. Only the VULN-8 row changes.
- **DO NOT** delete the "Login Flow After the Bcrypt Fix", "Session Secret After the Fix", or "Rate Limiting After the Fix" subsections. They remain valid and are part of the project's permanent documentation.
- **DO NOT** edit the "Development Commands", "Architecture", or "Frontend-Backend Integration" subsections — except for inserting the new "CSRF Protection After the Fix" subsection (Phase 5.6) between two of them.
- **DO NOT** rename existing rule bullets. Only the CSRF rule changes; the other rules stay byte-for-byte.

### 5.9 Phase 5 Verification

```bash
# VULN-8 row now reads Closed
grep -n '| 8 | CSRF' CLAUDE.md

# New "CSRF Protection After the Fix" subsection added
grep -n '^### CSRF Protection After the Fix' CLAUDE.md

# Important Rules section's old "Never add CSRF tokens" line is gone
grep -n 'Never add CSRF tokens to forms' CLAUDE.md \
  || echo '(old rule retired — preserved)'

# New "Never remove the CSRF middleware" rule present
grep -n 'Never remove the CSRF middleware' CLAUDE.md

# Spec hierarchy includes item 11
grep -n 'csrf-fix.md' CLAUDE.md

# Opening paragraph reflects "All 8" closed
grep -n 'All 8 of them' CLAUDE.md

# Existing closure docs untouched
grep -n '^### Rate Limiting After the Fix' CLAUDE.md
grep -n '^### Session Secret After the Fix' CLAUDE.md
grep -n '^### Login Flow After the Bcrypt Fix' CLAUDE.md
```

Expected: each grep matches (and the "old rule retired" line prints its fallback).

---

## Phase 6 — End-to-End Verification + Vulnerability Preservation Audit

This phase walks every Verification Step in spec §10 in order. **No edits** are made; if any step fails, return to the relevant earlier phase to repair.

### 6.1 Start the Application (spec §10.5 — AC-17, TC-26)

```bash
rm -f vulnerable_app.db jar.txt jarA.txt jarB.txt
uv run backend/app/main.py
```

The DB reset is recommended so the test users registered below have predictable bcrypt hashes and a clean `users` table. The server listens on `http://localhost:3001` with no import/boot error.

### 6.2 Middleware File + Helper (spec §10.1 — AC-01, TC-01)

```bash
grep -n 'class CSRFMiddleware' backend/app/core/csrf.py
grep -n 'def get_or_create_csrf_token' backend/app/core/csrf.py
```

Expected: each command returns one matching line.

### 6.3 Stdlib-Only Imports (spec §10.2 — AC-02, TC-02)

```bash
grep -nE '^(import|from)' backend/app/core/csrf.py
```

Expected: only `json`, `secrets`, `urllib.parse`, and `starlette.requests` (the last used only for typing the helper). No `BaseHTTPMiddleware` import.

### 6.4 Middleware Registered in `main.py` (spec §10.3 — AC-08, TC-03)

```bash
grep -n 'CSRFMiddleware\|SessionMiddleware\|RateLimitMiddleware' backend/app/main.py
cd backend && uv run python -c "from app.main import app; print([m.cls.__name__ for m in app.user_middleware])" && cd ..
```

Expected: the source-order grep shows the import line plus three `add_middleware(...)` lines in the order CSRFMiddleware → SessionMiddleware → RateLimitMiddleware. The runtime print shows `['RateLimitMiddleware', 'SessionMiddleware', 'CSRFMiddleware']` (outer → inner on the request path).

### 6.5 Constant-Time Comparison (spec §10.4 — AC-11, TC-05)

```bash
grep -n 'secrets.compare_digest' backend/app/core/csrf.py
```

Expected: a single matching line.

### 6.6 Hidden Field Present in Both Forms (spec §10.6 — AC-09, TC-06, TC-07)

```bash
curl -s -c jar.txt http://localhost:3001/login  | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"'
curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"'
```

Expected: each command prints one matching line.

### 6.7 Token Persists Across Same-Session GETs (spec §10.7 — AC-10, AC-12, TC-08)

```bash
T1=$(curl -s -c jar.txt -b jar.txt http://localhost:3001/login  | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | head -1)
T2=$(curl -s -c jar.txt -b jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | head -1)
test "$T1" = "$T2" && echo 'tokens match (NFR-10 satisfied)' || echo 'TOKENS DIFFER — REGRESSION'
```

Expected: prints `tokens match (NFR-10 satisfied)`.

### 6.8 Forged POST Without Token Rejected (spec §10.8 — AC-04, AC-05, TC-09)

```bash
curl -s -o body -w 'HTTP=%{http_code}\n' -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost' \
     --data-urlencode 'email=ghost@x' \
     --data-urlencode 'password=p'
cat body
sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username='ghost';"
```

Expected: `HTTP=403`; `body` contains `{"error":"CSRF token missing or invalid"}`; the sqlite query is empty (no row created).

### 6.9 Forged POST With Wrong Token Rejected (spec §10.9 — TC-10)

```bash
rm -f jar.txt
curl -s -c jar.txt http://localhost:3001/signup > /dev/null
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost' \
     --data-urlencode 'email=ghost@x' \
     --data-urlencode 'password=p' \
     --data-urlencode 'csrf_token=wrong-value-here'
```

Expected: `HTTP=403`.

### 6.10 Legitimate Signup With Matching Token (spec §10.10 — AC-06, TC-11)

```bash
rm -f jar.txt
TOKEN=$(curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' \
     --data-urlencode 'email=alice@test.com' \
     --data-urlencode 'password=pass123' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=302`.

### 6.11 Legitimate Login With Matching Token (spec §10.11 — AC-06, TC-12)

```bash
TOKEN=$(curl -s -b jar.txt -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -i -b jar.txt -c jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=pass123' \
     --data-urlencode "csrf_token=$TOKEN" | head -20
```

Expected: HTTP `200`, JSON body `{"success":true,"redirect":"/welcome"}`, `Set-Cookie: session=...`.

### 6.12 Login With Matching Token but Wrong Password Returns 401 (spec §10.12 — TC-13)

```bash
TOKEN=$(curl -s -b jar.txt -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=wrong' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=401`.

### 6.13 GET Routes Unaffected (spec §10.13 — AC-07, TC-14)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/login
done | sort -u
```

Expected: only `200`.

### 6.14 Logout Invalidates Token (spec §10.14 — TC-15)

```bash
curl -s -b jar.txt http://localhost:3001/logout > /dev/null
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost2' \
     --data-urlencode 'email=g2@x' \
     --data-urlencode 'password=p' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=403`.

### 6.15 Cross-Session Replay Rejected (spec §10.15 — TC-16)

```bash
TOKEN_A=$(curl -s -c jarA.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -c jarB.txt http://localhost:3001/login > /dev/null
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jarB.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost3' \
     --data-urlencode 'email=g3@x' \
     --data-urlencode 'password=p' \
     --data-urlencode "csrf_token=$TOKEN_A"
```

Expected: `HTTP=403`.

### 6.16 Rate Limit Still Gates First (spec §10.16 — TC-24)

```bash
rm -f jar.txt
TOKEN=$(curl -s -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
for i in {1..6}; do
  curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt -X POST http://localhost:3001/login \
       --data-urlencode 'username=alice' \
       --data-urlencode 'password=wrong' \
       --data-urlencode "csrf_token=$TOKEN"
done
```

Expected: five `401` lines and a final `429` (not `403`).

### 6.17 Vulnerability Preservation Walkthrough (spec §10.17 — AC-14, TC-18–TC-24)

```bash
# VULN-1 SQL injection stays closed (TC-18)
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py

# VULN-2 Stored XSS stays closed (TC-19)
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py

# VULN-3 Reflected XSS stays closed + new CSRF splices = >=7 html.escape calls (TC-20)
test "$(grep -c 'html.escape(' backend/app/api/routes/auth.py)" -ge 7 \
  && echo '(>=7 html.escape calls present — VULN-2 + VULN-3 closures intact + 2 new CSRF splices)'

# VULN-4 Session secret env-sourced (TC-21)
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-5 Bcrypt stays in use (TC-22)
grep -n 'bcrypt' backend/app/core/security.py

# VULN-6 /download/db stays removed (TC-23)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
# Expected: 404
```

Every grep / curl matches its spec-expected output.

### 6.18 No New Dependency (spec §10.18 — AC-16, TC-25)

```bash
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'
```

Expected: prints the fallback.

### 6.19 Affected-Files Audit (spec §10.19 — AC-13, AC-15, TC-17, TC-27)

```bash
git status --porcelain
```

Expected output — exactly the six declared files plus the two new spec docs:

```
?? backend/app/core/csrf.py
 M backend/app/main.py
 M backend/app/api/routes/auth.py
 M frontend/templates/login.html
 M frontend/templates/signup.html
 M CLAUDE.md
?? .claude/specs/csrf-fix.md
?? .claude/specs/csrf-fix-plan.md
```

No other path. In particular, no entry for `auth_service.py`, `security.py`, `rate_limit.py`, `db/session.py`, `dashboard.html`, any CSS file, `README.md`, or any pyproject/lock file.

### 6.20 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 New Middleware File Exists (Phase 1.3, Phase 6.2)
- [ ] AC-02 Middleware Stdlib-Only (Phase 1.3, Phase 6.3)
- [ ] AC-03 Method Check Comes First (Phase 1.3, Phase 1.6)
- [ ] AC-04 Forged POST Returns 403 (Phase 6.8, 6.9)
- [ ] AC-05 403 Response Body Shape (Phase 6.8)
- [ ] AC-06 Legitimate POST Untouched (Phase 6.10, 6.11)
- [ ] AC-07 GET Routes Unaffected (Phase 6.13)
- [ ] AC-08 Middleware Registered in `main.py` (Phase 2.4, Phase 6.4)
- [ ] AC-09 Token Field Present in Rendered Forms (Phase 6.6)
- [ ] AC-10 Token Persists Across Same-Session GETs (Phase 6.7)
- [ ] AC-11 Constant-Time Comparison (Phase 1.3, Phase 6.5)
- [ ] AC-12 Token Issuance Idempotent (Phase 6.7)
- [ ] AC-13 Handler Code Untouched Beyond Two GET Routes (Phase 6.19)
- [ ] AC-14 Other Vulnerabilities Preserved (Phase 6.17)
- [ ] AC-15 CLAUDE.md Updated (Phase 5.3–5.7)
- [ ] AC-16 No New Dependency (Phase 6.18)
- [ ] AC-17 Application Boots (Phase 6.1)
- [ ] AC-18 Hidden Field Not Visible (Phase 4.3, 4.4 — `type="hidden"`)

### 6.21 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Middleware ordering wrong (`CSRFMiddleware` registered AFTER `SessionMiddleware`) → because `add_middleware` prepends, CSRF ends up outside Session on the request path, `scope["session"]` is unset when CSRF runs, and every POST is rejected with 403 (verified failure mode during implementation) | High | High | Spec §FR-09 + Phase 2.4 explicitly show source order CSRF → Session → RateLimit; Phase 2.8 awk check asserts source order; the Python `[m.cls.__name__ for m in app.user_middleware]` check asserts the runtime order is `[RateLimit, Session, CSRF]`; Phase 6.4 re-confirms both |
| Middleware ordering wrong the other way (`CSRFMiddleware` registered AFTER `RateLimitMiddleware`) → CSRF becomes outermost and parses every request body before rate-limit can short-circuit floods, defeating rate-limit's "fail before bcrypt" guarantee | Medium | Medium | Same Phase 2.8 source-order check covers this case; Phase 6.16 explicitly asserts a 6-POST flood produces 429 (not 403), proving rate-limit is still outermost |
| Using `BaseHTTPMiddleware` instead of pure ASGI → `await request.form()` consumes the body on the middleware's `Request` wrapper; FastAPI builds a fresh `Request` for the handler and finds an exhausted receive stream, causing the handler to return 400 ("All fields are required") on legitimate POSTs (verified failure mode during implementation) | High | High | Phase 1.3 file contents implement pure ASGI (`__init__(self, app)` + `async def __call__(self, scope, receive, send)`); Phase 1.5 MUST-NOT forbids `BaseHTTPMiddleware`; Phase 1.6 grep asserts `BaseHTTPMiddleware` is absent from the file; Phase 6.10 / 6.11 end-to-end test exercises the legitimate path and would catch a regression |
| Forgetting to replay the body after consuming it → forwarding the original (now-exhausted) `receive` to `self.app` produces a 400 in the handler on legitimate POSTs | Medium | High | Phase 1.3 forwards `self.app(scope, _replay_receive(body), send)`, not `self.app(scope, receive, send)`; Phase 1.5 MUST-NOT calls this out explicitly; Phase 6.10 / 6.11 catches a regression end-to-end |
| Naive `==` comparison instead of `secrets.compare_digest` → timing-channel anti-pattern in security code | Low | Low | Phase 1.6 grep asserts `secrets.compare_digest` present and `==` between expected/submitted absent |
| Body-double-read concern is structural, not just a caching question — see the `BaseHTTPMiddleware` risk row above, which captures the actual failure mode and mitigation | High | High | Pure ASGI + explicit body replay is the canonical fix (Phase 1.3) |
| Variable shadow in `signup_page` / `login_page` (local `html = f.read()` shadows the imported `html` module) → `html.escape(...)` raises `AttributeError` at request time | Medium | High | Phase 3.4 / 3.5 rename the local to `page`; Phase 3.9 grep asserts no `html = f.read()` line remains in `auth.py` |
| Token rotated on every request → legitimate flows break (page renders one token, JS submits stale one) | Low | High | Spec §FR-02 + Phase 1.3 helper reads existing token before generating; Phase 6.7 explicitly verifies idempotency |
| Token rotated on login (a "secure best practice" some sources cite) → first-attempt login fails because the freshly issued token does not match the one in the rendered form | Low | Medium | Spec §2.4 + Phase 1.5 MUST-NOT explicitly forbid rotation in this fix; the login JS submit-and-show-error flow assumes the token stays stable |
| Fail-open on internal exception in CSRF middleware (e.g., a malformed multipart body) → re-opens the vulnerability we are fixing | Medium | High | Spec §NFR-07 explicitly mandates fail-CLOSED; Phase 1.3 code uses `_reject()` in the bare `except`; Phase 1.5 MUST-NOT contrasts this with the rate-limit middleware's fail-open posture |
| Adding a third-party dependency (`fastapi-csrf-protect`, `starlette-csrf`) "for production-readiness" | Low | Medium | Spec §FR-11, §NFR-09 + Phase 1.5 MUST-NOT forbid new deps; Phase 6.18 grep asserts no pyproject/lock edits |
| Hidden field placed outside the `<form>` element → browser does not include it in the submission | Low | High | Phase 4.3 / 4.4 explicitly show the input as the first child of the form; Phase 4.8 awk check confirms it lives inside the form |
| Hidden field added to `dashboard.html` (which has no form) → wasted change + diff-surface noise | Very Low | Low | Phase 4.5 + Phase 4.7 MUST-NOT call out that dashboard has no form; Phase 6.19 file audit catches the stray edit |
| Touching the POST handlers ("symmetry", "while in here") → scope creep, possible regression in the bcrypt-verify or 401 path | Medium | Medium | Spec §FR-10 + Phase 3.6, 3.8 MUST-NOT call out leaving POST handlers byte-for-byte unchanged; Phase 6.19 file audit catches it |
| Accidentally re-opening a previously closed vulnerability while editing `main.py` (e.g. reverting the `SECRET_KEY` line) | Very Low | High | Phase 2.7 MUST-NOT enumerates all closed vulns; Phase 2.8 grep + Phase 6.17 walkthrough catch any regression |
| Reading the token from a query string in addition to the form body → introduces a token-leak vector (Referer headers, server logs, browser history) | Low | Medium | Spec §EC-11 + Phase 1.5 MUST-NOT forbid query-string reads; Phase 1.3 code reads only from the buffered request body via `parse_qs` |
| Clearing `request.session` on a CSRF failure → self-inflicted DoS (attacker repeatedly forces victim to lose session) | Low | Medium | Spec §FR-05 + Phase 1.5 MUST-NOT explicitly forbid session-clear-on-reject; Phase 1.3 `_reject()` only returns a JSONResponse |
| Token read from a header `X-CSRF-Token` instead of the form body → JS would need rewiring to set the header; a future header-based approach should be a separate spec | Low | Low | Spec §EC-11 + Phase 1.5 MUST-NOT forbid header reads; the spec mandates form-body submission only |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/main.py backend/app/api/routes/auth.py frontend/templates/login.html frontend/templates/signup.html CLAUDE.md
rm -f backend/app/core/csrf.py
```

The five modified files snap back to their pre-fix state and the new middleware file is removed. No dependency, schema, or data migration is involved — the `vulnerable_app.db` file, the `users` table, and the session cookie format are all untouched by the fix in the first place.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No `Origin` / `Referer` header check.** The synchronizer token is self-contained.
- **No double-submit cookie.** Token storage is server-side only (inside the signed session).
- **No per-request token rotation.** One token per session. Per-request rotation would break the login JS's submit-and-show-error flow without adding meaningful defense once XSS (VULN-2 / VULN-3) is closed.
- **No `SameSite` cookie attribute change.** Starlette's `SessionMiddleware` already defaults to `SameSite=Lax`. Touching the session middleware risks re-opening VULN-4.
- **No JSON-body POST support.** The middleware only parses bodies whose `content-type` starts with `application/x-www-form-urlencoded`. JSON or multipart bodies are rejected. The lab has no JSON-bodied POST endpoints today.
- **No header-based token submission (e.g., `X-CSRF-Token`).** Form-body only.
- **No CSRF protection on `/search`.** It is GET-only and outside synchronizer-token scope.
- **No new dependency.** No `fastapi-csrf-protect`, no `starlette-csrf`. The middleware is stdlib + Starlette (already transitive via FastAPI).
- **No database column for CSRF state.** The token lives in the signed session cookie only. `vulnerable_app.db` schema is unchanged.
- **No JavaScript change in either template.** The login form's `new FormData(form)` naturally includes hidden inputs; the signup form is a native form POST. The hidden `<input type="hidden">` is the *only* template-side change.
- **No CSS change.** `type="hidden"` is unrendered by HTML spec.
- **No template-engine adoption (Jinja2 etc.).** The existing `str.replace` pattern is reused.
- **No change to `auth_service.py`.** The service layer does not know the CSRF mechanism exists.
- **No change to `dashboard.html`.** No form there.
- **No change to bcrypt cost factor, the rate-limit defaults, the session-cookie attributes, the `SECRET_KEY` source, the `/search` escape, the `/welcome` escape, the `/download/db` removal, the parameterized SQL, or any other already-closed fix.**
- **No reversal of prior fixes.** VULN-1 through VULN-7 stay closed.
- **No log line on rejection.** The 403 response itself is the only signal.
- **No file** created or modified beyond `backend/app/core/csrf.py` (new), `backend/app/main.py` (modified), `backend/app/api/routes/auth.py` (modified), `frontend/templates/login.html` (modified), `frontend/templates/signup.html` (modified), `CLAUDE.md` (modified), and this spec/plan pair.
