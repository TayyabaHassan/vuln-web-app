# Software Specification Document — CSRF Fix (Synchronizer-Token Pattern, Session-Bound)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [CSRF — state-changing POSTs accept any cross-origin submission](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the remediation of the **Cross-Site Request Forgery (CSRF)** vulnerability (OWASP **A01:2021 — Broken Access Control**, sub-control "request forgery / unsafe state-changing methods"). The application currently accepts every `POST /signup` and `POST /login` from any origin, with no proof that the request was actually initiated by the user viewing one of the legitimate forms. The most dangerous consequence is on the two state-changing routes:

- **Forged signup:** an attacker hosts `evil.com` with a hidden `<form action="http://localhost:3001/signup" method="POST">` that auto-submits when the victim visits the page. The victim's browser issues the cross-origin POST with whatever form fields the attacker chose. The application happily creates an account the attacker can later use (a "session-fixation-by-account-takeover" or "ghost-account" pattern).
- **Forged login:** the same trick with `/login` lets the attacker log the victim into the *attacker's* account. Anything the victim then types into the dashboard (notes, search history, future profile data) is captured under credentials the attacker controls. This is the classic "login-CSRF" attack chain.
- **General:** because no form carries any unguessable, per-session value, *any* cross-origin POST that knows the field names succeeds. The session cookie is sent automatically by the browser (it is the *user's* cookie); the attacker only needs to ship the HTML.

The `CLAUDE.md` vulnerability map calls this VULN-8 ("CSRF") and notes it is enforced **globally** — there is no CSRF token field, no middleware, no `Origin` / `Referer` check, and no SameSite cookie attribute set anywhere in the codebase.

This fix installs a **synchronizer-token pattern**, session-bound, stdlib-only:

1. A small ASGI middleware (`CSRFMiddleware`) runs on every POST and rejects requests whose form field `csrf_token` does not match the per-session token stored in `request.session["csrf_token"]`. Comparison uses `secrets.compare_digest` (constant-time).
2. The GET handlers that render `/login` and `/signup` lazily generate a per-session token via `secrets.token_urlsafe(32)` (stored in `request.session["csrf_token"]` on first read), splice it into the rendered HTML via the same `str.replace("{{csrf_token}}", …)` mechanism the dashboard already uses for `{{username}}`, and the templates carry one new `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` per form.
3. The login page's JS already submits the form with `new FormData(form)`, so the hidden field rides along automatically. The signup page is a native form POST, so the field is included by the browser. **No client-side wiring** is added beyond the hidden input.

The token is implemented with **Python standard library only** (`secrets.token_urlsafe`, `secrets.compare_digest`, `html.escape`) — no new third-party dependency, in line with the project's stdlib-only pattern (`secrets` for the session key, `html.escape` for VULN-2 / VULN-3, `collections` + `asyncio` for VULN-7). When a POST arrives without a matching token, the middleware returns **HTTP 403 Forbidden** with a JSON body, **before** the handler runs (so neither the bcrypt verify nor the SQLite write are invoked on a forged call).

The fix is **surgical** and closes the **CSRF** vulnerability **only**. Every previously-closed fix (bcrypt password hashing, parameterized SQL, removed `/download/db` route, env-sourced session secret, escaped dashboard `{{username}}`, escaped `/search` reflection sinks, per-IP POST rate-limit middleware) remains permanently in place. After this fix, **all eight** intentional vulnerabilities are closed; the application becomes a "before/after" educational artifact that students compare against the v0.1.0 baseline.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Create one new file, `backend/app/core/csrf.py`, containing a small, standard-library-only **pure ASGI** middleware class (`CSRFMiddleware`, implementing `__call__(scope, receive, send)` directly — *not* `BaseHTTPMiddleware`; see §FR-04 / §EC-12 for the rationale) and one helper function (`get_or_create_csrf_token(request)`) that lazily generates and stores the per-session token.
- Wire that middleware into the app via `app.add_middleware(CSRFMiddleware)` inside `backend/app/main.py`. Starlette's `add_middleware` **prepends** to its internal middleware list, so the **last** `add_middleware` call becomes the **outermost** layer on the request path. To get the desired layering `RateLimit (outer) → Session → CSRF (inner) → handler`, the registration order MUST be `CSRFMiddleware` first, then `SessionMiddleware`, then `RateLimitMiddleware` last. Rate limiting still gates floods first (so a flood is denied before CSRF reads any body); `SessionMiddleware` runs *before* `CSRFMiddleware` on the request path so the per-session token is readable from `request.session`.
- Modify `backend/app/api/routes/auth.py` so that `GET /login` and `GET /signup` call the helper to issue (or read back) the session-bound token and splice it into the rendered HTML via the existing `str.replace("{{csrf_token}}", …)` pattern. The splice MUST be done with the token already URL-safe (token_urlsafe produces only `[A-Za-z0-9_-]`, no HTML-significant characters, so no additional escape is strictly required — but the splice MUST use `html.escape(token, quote=True)` defensively in case the algorithm changes later).
- Modify `frontend/templates/login.html` and `frontend/templates/signup.html` to add a single hidden field `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` inside each form. **No JavaScript change is required:** the login form already submits via `new FormData(form)`, which includes hidden inputs; the signup form is a native form POST.
- The middleware MUST validate ONLY requests whose HTTP method is `POST` and whose ASGI scope type is `"http"`. Every non-POST (and every non-HTTP) request MUST pass through with zero overhead beyond a single method/scope-type check branch.
- The middleware MUST identify the expected token from `scope["session"].get("csrf_token")` (the `session` key in the ASGI scope, populated by `SessionMiddleware`) and the submitted token from the buffered request body, parsed via `urllib.parse.parse_qs` on the urlencoded body.
- The middleware MUST compare the two values with `secrets.compare_digest` (constant-time) and reject if either value is `None`, empty, or mismatched.
- After reading the body for validation, the middleware MUST re-stream the same bytes to the downstream handler via a wrapped `receive` callable that emits a single `http.request` message with the buffered body. This is required because `BaseHTTPMiddleware` does NOT correctly propagate `request.form()` results to FastAPI's `Form(...)` dependency — the cached form lives on the middleware's `Request` wrapper, not on the new `Request` FastAPI constructs from the same scope. Using pure ASGI with explicit body replay is the standard primitive for body-touching middleware.
- The middleware MUST emit responses with status `403`, a JSON body of the shape `{"error": "CSRF token missing or invalid"}`, and no `Set-Cookie` header changes.
- Update `CLAUDE.md` to:
  - Move VULN-8 from "Open" to "Closed" in the Vulnerability Map, with a short mechanism description.
  - Update the opening paragraph's count ("All 8 of them … closed. No vulnerabilities remain intentionally exploitable.") and remove the "remaining 1 vulnerability is intentional" WARNING paragraph (or rewrite it to note that the lab is now fully patched; see §AC-14 for exact text).
  - Replace the "Never add CSRF tokens to forms (preserves VULN-8)" rule with a new "Never remove the CSRF middleware / token field" rule.
  - Add a "CSRF Protection After the Fix" subsection mirroring the existing "Rate Limiting After the Fix" subsection.
  - Append the new spec/plan pair to the Specification Hierarchy list.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix addresses the **last** remaining intentional vulnerability. After this change, no OWASP-Top-10 vulnerability from the original v0.1.0 baseline remains open. The table below records the closure status for completeness:

| Vulnerability | OWASP | Status under this fix |
|---------------|-------|-----------------------|
| SQL Injection (`auth_service.py` queries) | A03:2021 | Already CLOSED (parameterized) — stays closed |
| Stored XSS (`{{username}}` substitution in dashboard) | A03:2021 | Already CLOSED (`html.escape`) — stays closed |
| Reflected XSS (`/search?q=` reflection) | A03:2021 | Already CLOSED (`html.escape`) — stays closed |
| Session Hijacking (hardcoded session secret) | A07:2021 | Already CLOSED (env-sourced secret) — stays closed |
| Weak Password Storage | A02:2021 | Already CLOSED (bcrypt) — stays closed |
| Exposed Database endpoint (`/download/db`) | A01:2021 | Already CLOSED (route removed) — stays closed |
| No Rate Limiting (unbounded POST per IP) | A07:2021 | Already CLOSED (per-IP sliding-window middleware) — stays closed |
| **CSRF (no tokens)** | **A01:2021** | **CLOSED by this spec** |

### 2.3 Explicit Preservation Note

Every already-closed fix MUST remain closed:

- **VULN-1 (SQL Injection):** `auth_service.py` and `/search` MUST keep their parameterized `?` queries.
- **VULN-2 (Stored XSS):** `welcome_page` MUST keep escaping the `{{username}}` substitution with `html.escape(..., quote=True)`.
- **VULN-3 (Reflected XSS):** `/search` MUST keep escaping `q`, both row columns, and the exception text.
- **VULN-4 (Session Hijacking):** `main.py` MUST keep sourcing `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback.
- **VULN-5 (Weak Password Storage):** `core/security.py` MUST keep its bcrypt implementation (rounds ≥ 12) and the defensive `try/except` in `verify_password`.
- **VULN-6 (Exposed Database):** the `/download/db` route MUST NOT be re-introduced.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` MUST stay registered. The CSRF middleware is added *under* (inside) it — Rate-limit still runs first on the request path, so a forged-token flood from one IP still triggers 429 before any CSRF parsing happens.

### 2.4 Explicit Non-Goals

- This fix does **not** introduce a "double-submit cookie" pattern. The token is stored only in the server-side session, not duplicated in a separate cookie. Rationale: the session is already signed (VULN-4 closure), so server-side storage is the simplest correct primitive; a double-submit cookie adds complexity without a matching threat-model gain on a single-origin lab.
- This fix does **not** validate `Origin` or `Referer` headers. The synchronizer token is sufficient and self-contained; layering header checks adds branching without adding meaningful defense (the token itself is the unforgeable secret).
- This fix does **not** rotate the CSRF token on every request, on login, or on session writes. The token's lifetime equals the session's lifetime. Rotation is a defense-in-depth measure used against token-theft-via-XSS — and XSS in this lab is already closed (VULN-2 / VULN-3). Per-request rotation would also break the login JS flow (the JS would have to fetch a fresh token between submit and re-submit on error), which is out of scope.
- This fix does **not** set `SameSite=Lax` or `SameSite=Strict` on the session cookie. Starlette's `SessionMiddleware` defaults to `lax` since 0.20; this is independent of the synchronizer-token mechanism and the fix MUST NOT touch the existing session middleware configuration (it MUST stay byte-for-byte to preserve VULN-4 closure).
- This fix does **not** add a CSRF field to the search endpoint (`GET /search?q=`). `GET` is, by HTTP-method contract, non-state-changing; the existing `/search` is read-only and outside the synchronizer-token scope.
- This fix does **not** introduce a new dependency. `secrets`, `html`, `starlette.middleware.base`, `starlette.requests`, `starlette.responses` are already in use.
- This fix does **not** change the response shape of `POST /login` or `POST /signup` for *legitimate* requests (those carrying the matching token). A successful login still returns the existing JSON `{"success": True, "redirect": "/welcome"}`; a failed login still returns JSON 401; a successful signup still returns a 302; a duplicate-username signup still returns the existing HTML 400.
- This fix does **not** persist the CSRF token across server restarts beyond what the session itself does. The session cookie is signed with `SECRET_KEY`; if `SECRET_KEY` is unset and a restart picks a new random key, all sessions (and therefore all CSRF tokens) become invalid — the user re-logs in, gets a fresh session and a fresh token. This is the existing VULN-4 behavior and is unchanged.
- This fix does **not** add per-form, per-endpoint, or rotating-on-action tokens. One token per session, the same value for every form rendered in that session. Minimum complexity, maximum educational clarity.

---

## 3. Affected Files

The fix MUST touch only the following files. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/csrf.py` | **New** | `CSRFMiddleware` class + `get_or_create_csrf_token(request)` helper (stdlib only) |
| `backend/app/main.py` | Modified | Import the middleware and register it via `app.add_middleware(CSRFMiddleware)` as the **first** `add_middleware` call (innermost), with `SessionMiddleware` second and `RateLimitMiddleware` last |
| `backend/app/api/routes/auth.py` | Modified | `GET /login` and `GET /signup` call the helper and splice the token into the rendered HTML via `str.replace("{{csrf_token}}", ...)` |
| `frontend/templates/login.html` | Modified | Add `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` inside `<form id="login-form">` |
| `frontend/templates/signup.html` | Modified | Add `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` inside `<form id="signup-form">` |
| `CLAUDE.md` | Modified | Update vulnerability map, count, rules, add post-fix subsection, append to spec hierarchy |

Files that MUST NOT be modified by this change:

- `backend/app/services/auth_service.py` (parameterized queries + bcrypt verify — VULN-1 / VULN-5 stay closed).
- `backend/app/core/security.py` (bcrypt — VULN-5 stays closed).
- `backend/app/core/rate_limit.py` (per-IP rate-limit middleware — VULN-7 stays closed).
- `backend/app/db/session.py` (schema and connection layer — untouched; **no schema column for CSRF state** — the token lives in the session, not the database).
- `frontend/templates/dashboard.html` (no form on the dashboard — the only POST origins are `/login` and `/signup`; `/logout` is a GET link, not a POST).
- Any CSS under `frontend/static/`.
- `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md` and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — the middleware is stdlib-only).

---

## 4. Functional Requirements

### FR-01: Middleware Validates Only POST Requests

- The middleware MUST check `scope["type"] != "http"` and `scope.get("method") != "POST"` at the top of its `__call__` method.
- If the scope is not HTTP or the method is **not** `POST`, the middleware MUST forward to `await self.app(scope, receive, send)` immediately, with no session access, no body read, and no token comparison. GET, OPTIONS, HEAD, PUT, DELETE, PATCH, lifespan, and websocket scopes all bypass the validator.

### FR-02: Per-Session Token Storage

- The token MUST be stored at `request.session["csrf_token"]` — a single string per session, written once when the user's first form-rendering GET handler is invoked.
- The token MUST be generated with `secrets.token_urlsafe(32)`, producing a 43-character URL-safe Base64 string of 32 random bytes (256 bits of entropy).
- The helper `get_or_create_csrf_token(request)` MUST:
  1. Read `request.session.get("csrf_token")`.
  2. If the value is missing, empty, or not a string, write a freshly generated token via `secrets.token_urlsafe(32)` into `request.session["csrf_token"]`.
  3. Return the (possibly newly written) token.
- The helper MUST NOT rotate an existing valid token. Once issued, the token stays for the lifetime of the session.

### FR-03: Token Issuance in GET Handlers

- `GET /login` MUST call `get_or_create_csrf_token(request)` and splice the returned token into the response HTML via `str.replace("{{csrf_token}}", html.escape(token, quote=True))`.
- `GET /signup` MUST do the same with the signup template.
- The handlers MUST take `request: Request` as a parameter (currently they take none) so `request.session` is accessible. This is the **only** signature change in `auth.py`.
- The splice MUST be done **after** reading the file and **before** returning the `HTMLResponse`. The escape is defensive: `secrets.token_urlsafe(32)` produces only `[A-Za-z0-9_-]`, none of which is HTML-significant, but `html.escape` keeps the splice safe under future token-format changes.

### FR-04: Token Validation in `CSRFMiddleware.__call__`

- On each POST HTTP request, the middleware MUST:
  1. Look up `session = scope.get("session")`. If `session` is not a dict (i.e., `SessionMiddleware` did not populate it), reject (FR-05).
  2. Look up `expected = session.get("csrf_token")`. If `expected` is missing, empty, or not a string, reject (FR-05).
  3. Drain the ASGI `receive` callable to assemble the full request body (concatenating all `http.request` message bodies until `more_body` is `False`).
  4. Inspect the `content-type` header in `scope["headers"]`. If it is not `application/x-www-form-urlencoded`, reject (FR-05) — JSON and multipart bodies are out of scope for this lab (spec §EC-09, §EC-10).
  5. Parse the body with `urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)` and read `submitted = parsed.get("csrf_token", [None])[0]`. If `submitted` is missing or empty, reject (FR-05).
  6. Compare with `secrets.compare_digest(str(expected), str(submitted))`. If the comparison returns `False`, reject (FR-05).
  7. Otherwise, build a wrapped `receive` callable that emits the buffered body as a single `http.request` message (with `more_body=False`) on the first call and an `http.disconnect` on subsequent calls, then forward to `await self.app(scope, wrapped_receive, send)`.
- The body MUST be read once from the original `receive` and replayed via the wrapped `receive`. FastAPI's `Form(...)` dependency reads the body again from the wrapped `receive` and parses it normally — no double-stream-consumption problem. This pattern is necessary because `BaseHTTPMiddleware` does NOT propagate `request.form()` caches to the downstream FastAPI handler.

### FR-05: Rejected Response Shape

- When a POST request is rejected, the middleware MUST return a `starlette.responses.JSONResponse` with:
  - `status_code = 403`
  - `content = {"error": "CSRF token missing or invalid"}`
  - No `Retry-After` header.
  - No `Set-Cookie` header changes (the session is not cleared on rejection — that would be a self-inflicted DoS vector where an attacker repeatedly forces the user to lose their session).
- The downstream handler (`auth_service.login()` / `auth_service.signup()`) MUST NOT be invoked for a rejected request — no bcrypt verify, no DB call, no session write.

### FR-06: Constant-Time Comparison

- The token comparison MUST use `secrets.compare_digest(str(expected), str(submitted))`, not `==`. This prevents timing-channel side leaks even though the threat model for a per-session unguessable token does not strongly require it; the cost of `compare_digest` is negligible and using `==` would be a documented anti-pattern in security code.
- Both operands MUST be coerced to `str` before the comparison to defend against the (impossible-under-normal-flow) case where `request.session["csrf_token"]` was overwritten by another middleware to a non-string.

### FR-07: Method Branch Comes First

- The combined scope-type + method check (FR-01) MUST be the very first statement in `__call__`. No session read, no body drain, no token comparison happens for non-POST or non-HTTP requests. This guarantees that GET routes (`/`, `/login`, `/signup` HTML page loads, `/welcome`, `/search`, `/logout`, every `/static/*` asset), HEAD / OPTIONS pre-flights, ASGI lifespan events, and any future websocket scope pay **at most two dict lookups + two equality comparisons** of overhead.

### FR-08: Middleware Does Not Modify Successful Responses

- For non-rejected requests, the middleware MUST forward `(scope, wrapped_receive, send)` to `self.app` and immediately return — it MUST NOT wrap, buffer, or transform the response. The downstream handler's response messages (`http.response.start`, `http.response.body`) flow directly through the unmodified `send`. In particular, the `Set-Cookie` headers written by `SessionMiddleware` MUST flow through verbatim, and the JSON body returned by `POST /login` MUST be byte-for-byte unchanged.

### FR-09: Middleware Ordering in `main.py`

- The middleware stack in `main.py` MUST be (in source-order of `add_middleware` calls):

  ```python
  app.add_middleware(CSRFMiddleware)
  app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
  app.add_middleware(RateLimitMiddleware, max_requests=RATE_LIMIT_MAX, window_seconds=RATE_LIMIT_WINDOW_SECONDS)
  ```

- Starlette's `add_middleware` **prepends** the middleware to its internal `user_middleware` list. The stack is then built by wrapping each entry around the next, so the **last** `add_middleware` call ends up as the **outermost** layer on the request path (and the first call as the innermost — closest to the handler). With the order above, `app.user_middleware` reads `[RateLimitMiddleware, SessionMiddleware, CSRFMiddleware]`, and the request-path layering is:

  ```
  client → RateLimit (outer) → Session → CSRF (inner) → handler
  ```

  Three consequences:
  1. **Rate-limit still gates first.** A flood of forged POSTs from one IP is throttled at 429 *before* CSRF reads any request body. The forged-token attack cannot CPU-burn the CSRF validator.
  2. **CSRF runs after Session on the request path.** `SessionMiddleware` populates `scope["session"]` *before* `CSRFMiddleware.__call__` runs, so `scope["session"].get("csrf_token")` returns the correct value. If CSRF were registered last (outer), it would see `scope["session"]` unset and reject every request — a verified failure mode during implementation.
  3. **Handler runs last.** All three gates pass before the handler's bcrypt / SQL work begins.

- **Verification snippet.** The ordering can be confirmed at runtime by printing `[m.cls.__name__ for m in app.user_middleware]`; the expected output is `['RateLimitMiddleware', 'SessionMiddleware', 'CSRFMiddleware']` (outer → inner).

### FR-10: Handler Code Minimal Diff

- `backend/app/api/routes/auth.py` is modified ONLY to:
  - Add a `request: Request` parameter to `signup_page` and `login_page`.
  - Add a call to `get_or_create_csrf_token(request)` in each.
  - Add a `str.replace("{{csrf_token}}", html.escape(token, quote=True))` in each.
  - Add a single `from app.core.csrf import get_or_create_csrf_token` import.
- Every other handler (`index`, `signup_post`, `login_post`, `search_user`, `welcome_page`, `logout`) MUST remain byte-for-byte unchanged.
- `backend/app/services/auth_service.py` MUST NOT be modified — the service layer knows nothing about CSRF.

### FR-11: Standard-Library Only

- The middleware MUST use only the Python standard library (`secrets`, `json`, `urllib.parse`) plus the existing transitive `starlette` API (`starlette.requests.Request`, used by the `get_or_create_csrf_token` helper for typing only — the middleware class itself is pure ASGI and imports no Starlette base class). No third-party dependency (`fastapi-csrf-protect`, `starlette-csrf`, etc.) is added.

### FR-12: No Database Schema Change

- The CSRF token lives **only** in the signed session cookie (via `request.session`). No new column is added to `users` or any other table. `vulnerable_app.db` schema is byte-for-byte unchanged.

---

## 5. Non-Functional Requirements

### NFR-01: Effectiveness Against Cross-Origin Forgery

- After the fix, an attacker hosting `evil.com` cannot craft a working `POST /login` or `POST /signup` from a victim's browser. The session cookie is sent (the browser owns it), but the `csrf_token` form field is not — the attacker cannot read it (it lives in a signed cookie the attacker cannot decode) and cannot guess it (256 bits of entropy from `secrets.token_urlsafe(32)`).
- The middleware rejects the forged POST with HTTP 403 before `auth_service.signup()` or `auth_service.login()` runs.

### NFR-02: Surgical Scope

- Exactly one vulnerability (CSRF) is closed. The diff MUST NOT touch session secrets, the SQL construction, any XSS escape, the bcrypt verification, the `/download/db` posture, or the rate-limit posture.

### NFR-03: API Stability for Legitimate Requests

- For any `POST /login` or `POST /signup` that includes the correct `csrf_token` (i.e., every request originating from one of the rendered forms in the same browser session), the public response is byte-for-byte unchanged: same status, same body, same `Set-Cookie` headers.
- GET routes are entirely unaffected.
- The login JS continues to use `new FormData(form)` and `fetch('/login', { method: 'POST', body: formData })`. Because the `<input type="hidden" name="csrf_token">` is inside the form, FormData picks it up automatically — no JS change.
- The signup form continues to be a native `<form action="/signup" method="POST">` submission.

### NFR-04: Per-Request Overhead

- For a non-POST (or non-HTTP) scope, the middleware adds two dict lookups + two equality comparisons (sub-microsecond Python).
- For a POST request: one `scope.get("session")` lookup, one dict membership check, one ASGI receive drain into `bytes`, one `body.decode("utf-8")`, one `urllib.parse.parse_qs` over the urlencoded body, one `secrets.compare_digest` on ~43-char strings, and the construction of one wrapped `receive` closure. All O(n) in body length, with n bounded by FastAPI's standard form-body limits.

### NFR-05: Memory Bound

- No new in-process state. The token lives in the session cookie (already paid for by VULN-4 closure). The middleware itself holds no maps, no caches, no per-IP state.

### NFR-06: No Information Leakage

- The rejected response body MUST NOT contain the IP address, the user agent, the request path, the expected token, the submitted token, or any per-user identifier. The `{"error": "CSRF token missing or invalid"}` body is identical across all rejected paths.
- HTTP status `403` and a generic JSON body are the only signals exposed.

### NFR-07: Fail-Closed on Validation Failure

- A missing session, an absent session-token field, a missing form-token field, an empty form-token field, a non-matching pair — every one of these cases MUST return 403. The middleware MUST NOT "fail open" by allowing a request through when validation cannot be performed. Rationale: an unguarded state-changing endpoint is the original vulnerability; failing open would re-open it.
- Internal exceptions inside the middleware's own bookkeeping (e.g., a malformed urlencoded body that raises during `parse_qs`, or a `UnicodeDecodeError` on non-UTF-8 bytes) MUST also fail closed with the same 403 response — not fail open as the rate-limit middleware does (NFR-07 of the rate-limit spec). Rationale: rate-limit fail-open trades a brief loss of throttling for liveness; CSRF fail-open trades a brief CSRF vulnerability for liveness, which directly re-opens the vulnerability we are fixing.

### NFR-08: Determinism Across Restarts

- Token state is bound to the session. If `SECRET_KEY` survives restart (env var set), sessions and therefore CSRF tokens survive too. If `SECRET_KEY` is regenerated each start (lab default), sessions are invalidated, the user re-logs in via the unauthenticated `/login` page, and a fresh token is issued — the same behavior as VULN-4's "Local lab use" note.

### NFR-09: Standard-Library Only / Zero Dependency Delta

- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. Every imported module is part of CPython's standard library or already transitively present via Starlette/FastAPI.

### NFR-10: Idempotency of Token Issuance

- A user who visits `GET /login`, then `GET /signup`, then `GET /login` again in the same session sees the **same** `csrf_token` value in all three rendered pages. `get_or_create_csrf_token` reads the existing value before generating a new one; the token is generated once per session.

---

## 6. Success Paths

### SP-01: Legitimate Signup

1. User issues `GET /signup` from a fresh browser. `SessionMiddleware` opens a session, `CSRFMiddleware` lets the GET through, `signup_page` calls `get_or_create_csrf_token(request)` which writes `t1 = "h7-…43chars…"` into `request.session["csrf_token"]` and returns it.
2. The HTML response carries `<input type="hidden" name="csrf_token" value="h7-…43chars…">`. The `Set-Cookie: session=…` is updated to reflect the new session content.
3. User fills out the form and submits. The browser issues `POST /signup` with form fields `username`, `email`, `password`, `csrf_token=h7-…`.
4. `RateLimitMiddleware` admits (counter at 1). `SessionMiddleware` decodes the cookie into `scope["session"]`. `CSRFMiddleware.__call__` reads `expected = scope["session"]["csrf_token"] = "h7-…"`, drains the body, parses the urlencoded form, reads `submitted = "h7-…"`, runs `compare_digest` → True, replays the buffered body via a wrapped `receive`, and forwards to the handler. `auth_service.signup()` runs unchanged; returns its 302 to `/login`.

### SP-02: Legitimate Login (JS Fetch)

1. User issues `GET /login`. `login_page` reads the existing `request.session["csrf_token"] = "h7-…"` (issued in SP-01) — no new token written (NFR-10). The HTML is rendered with the hidden field holding `h7-…`.
2. User submits the form. The page's JS reads `new FormData(form)` (which includes the hidden input), POSTs to `/login`. The middleware validates, forwards, `auth_service.login()` runs, returns JSON success.

### SP-03: Forged Signup From `evil.com` Rejected

1. Attacker hosts `<form action="http://localhost:3001/signup" method="POST">` on `evil.com`. The victim's browser auto-submits with `username=ghost`, `email=attacker@x`, `password=p`, no `csrf_token` field.
2. The browser sends the victim's `session=…` cookie (it's the victim's domain). `RateLimitMiddleware` admits the first attempt.
3. `CSRFMiddleware.__call__` reads `expected = scope["session"].get("csrf_token")`. If the victim has visited `/login` or `/signup` recently, `expected` is non-empty. The form body lacks the `csrf_token` field → `submitted` is `None` → reject with 403.
4. If the victim has *never* visited `/login` or `/signup` (no token issued yet), `expected` is `None` → reject with 403 regardless. **The fix is correct under both states.**

### SP-04: Forged Login From `evil.com` Rejected

1. Same shape as SP-03, but the attacker is trying to log the victim into the attacker's account (login-CSRF). The POST has the attacker's `username` and `password` plus no `csrf_token`.
2. The middleware rejects with 403 before `auth_service.login()` runs. No session is overwritten; the victim's existing session (if any) is preserved.

### SP-05: Token Replay From Different Session Rejected

1. Attacker captures token `t_A` from their own session via `GET /login`. They craft a `POST /login` (or `/signup`) including `csrf_token=t_A`, but the request is sent from the victim's browser via a cross-origin POST.
2. The victim's session cookie carries `csrf_token = t_V` (a different value, or `None`). `compare_digest(t_V, t_A)` returns `False` → 403. The attacker cannot bridge tokens across sessions because the comparison is against the **victim's** session, not a global table.

### SP-06: GET Routes Untouched

1. A user loads `GET /login`, `GET /signup`, `GET /welcome`, `GET /search?q=alice`, `GET /static/css/styles.css`, and `GET /logout` in rapid succession.
2. The middleware sees `scope["type"] == "http"` and `scope["method"] != "POST"` on every request and forwards to `self.app` immediately. No 403. No session lookup. No body drain.

### SP-07: User Visits Login, Then Signup, Then Login Again

1. `GET /login` → fresh session, token `t1` written.
2. `GET /signup` → `t1` already present, NOT regenerated (NFR-10). HTML rendered with `t1`.
3. `GET /login` → `t1` still present, NOT regenerated. HTML rendered with `t1`.
4. Same form value is acceptable for `POST /login` and `POST /signup` because both endpoints share the same session token. This is the documented synchronizer-token-pattern behavior.

### SP-08: User Logs In Successfully

1. After SP-02 succeeds, `auth_service.login()` writes `request.session["user_id"]` and `request.session["username"]`. The pre-existing `request.session["csrf_token"]` is **untouched**.
2. The user navigates to `/welcome` (a GET, bypasses CSRF middleware). The dashboard renders. The session still carries the same `csrf_token` value.
3. If the user logs out (`GET /logout` → `request.session.clear()`), the entire session is erased — including the CSRF token. A subsequent `GET /login` issues a fresh token via `get_or_create_csrf_token` (it sees the cleared session). This is correct: after logout, the threat model resets.

---

## 7. Edge Cases

### EC-01: No Session at All

- A direct `POST /signup` from `curl` with no cookie jar carries no session cookie.
- `SessionMiddleware` initializes `request.session = {}`. `CSRFMiddleware` reads `request.session.get("csrf_token")` → `None`. Reject with 403.
- **Educational consequence:** students cannot brute-force `POST /signup` via raw `curl` without first fetching `GET /signup` (or `/login`) to obtain a token. This is correct and the same defense `requests.Session()` would naturally satisfy.

### EC-02: Session Without CSRF Token

- A user with an existing session (e.g., one written by a future, non-form-rendering route) but no `csrf_token` field — `expected` is `None`. Reject with 403.
- This is the failure-closed posture (NFR-07). The user fixes it by visiting any GET that calls `get_or_create_csrf_token` — i.e., `/login` or `/signup`.

### EC-03: Form Without `csrf_token` Field

- The form-encoded POST body is parsed, but the `csrf_token` key is absent — `form.get("csrf_token")` returns `None`. Reject with 403.

### EC-04: Form With Empty `csrf_token` Field

- `form.get("csrf_token")` returns `""`. The middleware MUST treat empty-string the same as missing — reject. The check is `if not submitted: reject` (a falsy check covers both `None` and `""`).

### EC-05: Form With Wrong `csrf_token` Field

- `compare_digest(expected, submitted)` returns `False`. Reject with 403.

### EC-06: Two Tabs in the Same Browser Session

- Tab A loads `/login`, Tab B loads `/signup`. Both render the same token (NFR-10). Either tab can submit its form successfully. Token is per-session, not per-page.

### EC-07: User Logs Out, Then Re-Submits a Cached Form

- The browser caches a `/login` HTML page with `csrf_token=t_old`. User logs out → session cleared. User goes back via browser history, re-submits the cached form. POST carries `csrf_token=t_old`. The middleware sees `expected = request.session.get("csrf_token")` — but after logout, the session is empty, so `expected = None`. Reject with 403.
- **Educational consequence:** logout invalidates outstanding forms. This is correct behavior for a session-bound token.

### EC-08: `secrets.token_urlsafe(32)` Output Format

- The function returns a 43-character string drawn from `[A-Za-z0-9_-]`. None of these characters is HTML-significant, so the `html.escape(token, quote=True)` splice is a no-op for the current algorithm. The escape stays as a defensive measure in case the algorithm later changes — and to make the security posture explicit ("we escape every templated splice site").

### EC-09: Multipart vs Form-Urlencoded Bodies

- The lab uses `application/x-www-form-urlencoded` for both `/login` (JS `FormData` → urlencoded) and `/signup` (HTML form, default urlencoded). The middleware's `_extract_csrf_token` helper checks the `content-type` header in `scope["headers"]` and only attempts `parse_qs` when it starts with `application/x-www-form-urlencoded`. Both lab endpoints satisfy that.

### EC-10: JSON Body POST

- A future POST endpoint that consumes a JSON body (e.g., a REST API) would have `request.form()` return an empty form. `submitted` would be `None` → reject with 403. This is correct: a JSON API client should fetch `/login` or `/signup` HTML first to learn its token, or a future fix should switch to header-based token submission. **Out of scope for this fix** — the lab has no JSON-bodied POST endpoints today.

### EC-11: Token in URL Query String

- The middleware reads ONLY from the parsed urlencoded request body (via `parse_qs` over the buffered bytes), not from `scope["query_string"]`. A request that places `?csrf_token=…` in the URL but omits it from the body is rejected. Rationale: query-string tokens leak into server logs, Referer headers, and browser history; the spec mandates form-body submission only.

### EC-12: Body Re-Streaming for the Downstream Handler

- The pure-ASGI middleware drains the `receive` callable to assemble the request body in `bytes`, then provides a wrapped `receive` to the downstream app. The wrapped callable emits a single `http.request` message carrying the buffered body (with `more_body=False`) on its first invocation, then emits `http.disconnect` on every subsequent call. FastAPI's `Form(...)` dependency reads from this wrapped `receive` and parses the body normally.
- **Why not `BaseHTTPMiddleware`?** `BaseHTTPMiddleware` wraps the request in its own `Request` object. Calling `await request.form()` inside `dispatch` parses and caches the form on *that* wrapper, but FastAPI builds a *fresh* `Request` from the same `scope`/`receive` for the route handler — the cache does not carry over. The handler then tries to read the body via the now-exhausted `receive`, sees empty bytes, and reports "all fields are required" (HTTP 400 from the handler's own validation). The pure-ASGI approach with explicit body re-streaming is the standard, well-defined primitive for this case.

### EC-13: Handler Code That Never Reads `request.session["csrf_token"]`

- The login and signup *POST* handlers do not need to read `csrf_token` themselves — the middleware has already validated it. The form field is dropped on the floor by `auth_service.signup()` / `auth_service.login()` (they pull `username`, `email`, `password` by name via FastAPI's `Form(...)` and ignore the unknown extra field). This is the standard FastAPI behavior; no code change in the service or POST handler is needed.

---

## 8. Acceptance Criteria

### AC-01: New Middleware File Exists

- `backend/app/core/csrf.py` exists and contains a class `CSRFMiddleware` implementing the pure ASGI interface (`__init__(self, app)` plus `async def __call__(self, scope, receive, send)`), plus a top-level function `get_or_create_csrf_token(request)`. The class MUST NOT inherit from `BaseHTTPMiddleware`.

### AC-02: Middleware Stdlib-Only

- The only `import` statements in `backend/app/core/csrf.py` are from `secrets`, `json`, `urllib.parse`, and `starlette.requests` (the last used only for typing the helper's `Request` parameter). No third-party module is imported.

### AC-03: Method Check Comes First

- The first executable statement in `CSRFMiddleware.__call__` is a combined check that forwards `await self.app(scope, receive, send)` if `scope["type"] != "http"` or `scope.get("method") != "POST"`.

### AC-04: Forged POST Returns 403

- A `POST /login` (or `POST /signup`) submitted **without** a `csrf_token` field — or with a wrong value — from the same IP as a valid session returns HTTP `403`.

### AC-05: 403 Response Body Shape

- The rejected response body is JSON of the form `{"error": "CSRF token missing or invalid"}`. No IP address, user agent, path, or token leak.

### AC-06: Legitimate POST Untouched

- A `POST /signup` issued by a client that has first done `GET /signup` (so the cookie jar holds the session and the form holds the matching `csrf_token`) returns the existing 302 redirect to `/login` and the existing `Set-Cookie: session=...`.
- A `POST /login` issued by a client that has first done `GET /login` and includes the matching token returns the existing JSON `{"success": true, "redirect": "/welcome"}` (for valid credentials) or `{"success": false, "error": "..."}` (for invalid credentials).

### AC-07: GET Routes Unaffected

- 50 consecutive `GET /login` requests (or `GET /signup`, `GET /welcome`, `GET /search`, `GET /logout`, or any static-file fetch) all return HTTP `200` (or `302` / `200` for `/welcome` and `/logout`, depending on session state). No `403` appears.

### AC-08: Middleware Registered in `main.py`

- `backend/app/main.py` contains three `add_middleware` calls in this source order: `app.add_middleware(CSRFMiddleware)`, then `app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)`, then `app.add_middleware(RateLimitMiddleware, max_requests=..., window_seconds=...)`. The resulting `app.user_middleware` order (printable at runtime) is `[RateLimitMiddleware, SessionMiddleware, CSRFMiddleware]`, corresponding to the request-path layering `RateLimit (outer) → Session → CSRF (inner) → handler`.

### AC-09: Token Field Present in Rendered Forms

- `curl -s -c jar http://localhost:3001/login` and `curl -s -c jar http://localhost:3001/signup` HTML output both contain a line matching `<input type="hidden" name="csrf_token" value="[A-Za-z0-9_-]{43}">`.

### AC-10: Token Persists Across Same-Session GETs

- `curl -s -c jar -b jar http://localhost:3001/login` issued twice in a row produces the **same** `csrf_token` value in both rendered HTMLs (per NFR-10).

### AC-11: Constant-Time Comparison

- `backend/app/core/csrf.py` contains a call to `secrets.compare_digest(...)` and contains NO `==` comparison between session-held and form-held token values.

### AC-12: Token Issuance Idempotent Within a Session

- After `GET /login` writes `csrf_token=t1` to the session, `GET /signup` in the same session does NOT overwrite `csrf_token`. The token is generated once per session.

### AC-13: Handler Code Untouched Beyond the Two GET Routes

- `backend/app/services/auth_service.py`, `backend/app/core/security.py`, `backend/app/core/rate_limit.py`, `backend/app/db/session.py`, every POST handler in `auth.py` (`signup_post`, `login_post`), and `search_user` / `welcome_page` / `logout` / `index` are byte-for-byte unchanged.

### AC-14: Other Vulnerabilities Preserved

- VULN-1 (SQL Injection): `auth_service.py` and `/search` still use parameterized queries — closed.
- VULN-2 (Stored XSS): `welcome_page` still calls `html.escape(username, quote=True)` — closed.
- VULN-3 (Reflected XSS): `/search` still escapes `q`, both row columns, and exception text — closed.
- VULN-4 (Session Hijacking): `main.py` still sources `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback — closed.
- VULN-5 (Weak Password): `core/security.py` still uses bcrypt with rounds ≥ 12 — closed.
- VULN-6 (Exposed DB): `GET /download/db` still returns HTTP 404 — closed.
- VULN-7 (No Rate Limiting): `RateLimitMiddleware` still registered and still returns 429 on the 6th POST in 60 s — closed.

### AC-15: CLAUDE.md Updated

- The Vulnerability Map row for "CSRF" reads "Closed" with a one-line mechanism description.
- The opening paragraph reads "All 8 of them … have since been closed. No vulnerabilities remain intentionally exploitable."
- The "Important Rules" section replaces "Never add CSRF tokens to forms (preserves VULN-8)" with "Never remove the CSRF middleware in `backend/app/main.py` / `backend/app/core/csrf.py`, the hidden `csrf_token` field in the login/signup templates, or the `get_or_create_csrf_token` calls in the two GET handlers (VULN-8 stays closed)".
- A new "CSRF Protection After the Fix" subsection appears between "Rate Limiting After the Fix" and "Frontend-Backend Integration".
- The Specification Hierarchy list appends item 11: `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md`.

### AC-16: No New Dependency

- `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. `git status --porcelain` shows no entry for any of those files.

### AC-17: Application Boots

- The app starts via `uv run backend/app/main.py` with no `ImportError`, `NameError`, or traceback.

### AC-18: Hidden Field Not Visible in Rendered Page

- The `<input type="hidden">` does not visually render in the browser. (Trivially satisfied by `type="hidden"`.) Stated for completeness — no CSS or layout change is permitted.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Middleware file exists with the right class and helper | Repo checkout | `grep -n 'class CSRFMiddleware' backend/app/core/csrf.py` matches; `grep -n 'def get_or_create_csrf_token' backend/app/core/csrf.py` matches |
| TC-02 | Middleware uses stdlib only | Repo checkout | `grep -nE '^(import|from)' backend/app/core/csrf.py` shows only `secrets`, `json`, `urllib.parse`, and `starlette.requests` (for typing only) |
| TC-03 | Middleware registered in `main.py` with correct order | Repo checkout | `grep -n 'CSRFMiddleware\|SessionMiddleware\|RateLimitMiddleware' backend/app/main.py` shows three `add_middleware` calls in source order `CSRFMiddleware` → `SessionMiddleware` → `RateLimitMiddleware` |
| TC-04 | Method-first short-circuit | Repo checkout | First non-trivial line of `CSRFMiddleware.__call__` checks `scope["type"] != "http"` or `scope.get("method") != "POST"` |
| TC-05 | `secrets.compare_digest` used (constant-time) | Repo checkout | `grep -n 'secrets.compare_digest' backend/app/core/csrf.py` matches |
| TC-06 | Hidden field present in `/login` HTML | App running | `curl -s http://localhost:3001/login` contains `<input type="hidden" name="csrf_token" value="..."` matching `[A-Za-z0-9_-]{43}` |
| TC-07 | Hidden field present in `/signup` HTML | App running | Same as TC-06 against `/signup` |
| TC-08 | Token persists across same-session GETs | App running, single cookie jar | Two sequential `curl -c jar -b jar /login` calls return the same `csrf_token` value |
| TC-09 | POST without token rejected | App running | `POST /signup` (no `csrf_token` field) → HTTP `403` with body `{"error":"CSRF token missing or invalid"}` |
| TC-10 | POST with wrong token rejected | App running, valid session | `POST /signup` with `csrf_token=invalid` → HTTP `403` |
| TC-11 | POST with matching token succeeds | App running | After `GET /signup` to obtain a token, `POST /signup` with `csrf_token=<that token>` plus valid fields → HTTP `302` to `/login` |
| TC-12 | Login POST with matching token succeeds | App running, user registered | After `GET /login`, `POST /login` with `csrf_token=<that token>` + valid creds → HTTP `200`, JSON `{"success":true,"redirect":"/welcome"}` |
| TC-13 | Login POST with matching token but wrong creds returns 401 | App running | `POST /login` with valid `csrf_token` but `password=wrong` → HTTP `401`, normal failure JSON |
| TC-14 | GET routes unrejected | App running | 50 sequential `GET /login` requests all return `200`; no `403` |
| TC-15 | Logout clears token | App running | After `GET /logout`, the next `POST /signup` from the same cookie jar (without revisiting `/login` or `/signup` GET) → `403` |
| TC-16 | Cross-session token replay rejected | App running, two cookie jars | `POST /signup` from jar B with `csrf_token` copied from jar A → `403` |
| TC-17 | Handler code untouched | Repo checkout | `git diff --stat main..HEAD -- backend/app/services/auth_service.py backend/app/core/security.py backend/app/core/rate_limit.py backend/app/db/session.py frontend/templates/dashboard.html` reports zero changes |
| TC-18 | SQL injection stays closed (VULN-1) | Repo checkout | `grep -n 'WHERE username = ?' backend/app/services/auth_service.py` matches; `grep -n 'LIKE ?' backend/app/api/routes/auth.py` matches |
| TC-19 | Stored XSS stays closed (VULN-2) | Repo checkout | `grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py` matches |
| TC-20 | Reflected XSS stays closed (VULN-3) | Repo checkout | `grep -c 'html.escape(' backend/app/api/routes/auth.py` reports at least `5` (the original 5; may be `6` or `7` once the CSRF-token splices are added) |
| TC-21 | Session secret stays env-sourced (VULN-4) | Repo checkout | `grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py` matches; `grep 'super-secret-key-12345' backend/app/main.py` returns no matches |
| TC-22 | Bcrypt stays in use (VULN-5) | Repo checkout | `grep -n 'bcrypt' backend/app/core/security.py` matches |
| TC-23 | `/download/db` stays removed (VULN-6) | App running | `GET /download/db` → HTTP `404` |
| TC-24 | Rate limit stays in place (VULN-7) | App running | After 5 valid `POST /login` (each carrying a fresh token), the 6th valid POST in the same 60 s window still returns `429` (rate-limit gate fires before CSRF) |
| TC-25 | No new dependency | Repo checkout | `git status --porcelain` shows no entry for `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock` |
| TC-26 | Application boots cleanly | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-27 | Affected-files audit | After change | `git status --porcelain` shows only the six declared files plus the two new spec docs |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Confirm Middleware File and Helper (AC-01, TC-01)

```bash
grep -n 'class CSRFMiddleware' backend/app/core/csrf.py
grep -n 'def get_or_create_csrf_token' backend/app/core/csrf.py
```

Expected: each command returns one matching line.

### 10.2 Confirm Standard-Library-Only Imports (AC-02, TC-02)

```bash
grep -nE '^(import|from)' backend/app/core/csrf.py
```

Expected: only `secrets`, `json`, `urllib.parse`, and `starlette.requests` (the last used only for typing the `get_or_create_csrf_token` helper). No `fastapi_csrf_protect`, no `starlette_csrf`, no `BaseHTTPMiddleware`, no third-party module.

### 10.3 Confirm Middleware Registered in `main.py` (AC-08, TC-03)

```bash
grep -n 'CSRFMiddleware\|SessionMiddleware\|RateLimitMiddleware' backend/app/main.py
```

Expected: the import line and three `app.add_middleware(...)` lines in source order `CSRFMiddleware` → `SessionMiddleware` → `RateLimitMiddleware`. The runtime middleware ordering can be confirmed independently with:

```bash
cd backend && uv run python -c "from app.main import app; print([m.cls.__name__ for m in app.user_middleware])" && cd ..
```

Expected output: `['RateLimitMiddleware', 'SessionMiddleware', 'CSRFMiddleware']` — outer-to-inner on the request path, i.e. `RateLimit → Session → CSRF → handler`.

### 10.4 Confirm Constant-Time Comparison (AC-11, TC-05)

```bash
grep -n 'secrets.compare_digest' backend/app/core/csrf.py
```

Expected: a single matching line. Also: `grep -n '==' backend/app/core/csrf.py` returns no lines that compare `submitted` against `expected` with `==`.

### 10.5 Start the Application (AC-17, TC-26)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

The server listens on `http://localhost:3001` with no import/boot error.

### 10.6 Hidden Field Present in Both Forms (AC-09, TC-06, TC-07)

```bash
curl -s -c jar.txt http://localhost:3001/login  | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"'
curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"'
```

Expected: each command prints one matching line with a 43-char URL-safe Base64 value.

### 10.7 Token Persists Across Same-Session GETs (AC-10, AC-12, TC-08)

```bash
T1=$(curl -s -c jar.txt -b jar.txt http://localhost:3001/login  | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | head -1)
T2=$(curl -s -c jar.txt -b jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | head -1)
test "$T1" = "$T2" && echo 'tokens match (NFR-10 satisfied)' || echo 'TOKENS DIFFER — REGRESSION'
```

Expected: prints `tokens match (NFR-10 satisfied)`.

### 10.8 Forged POST Without Token Rejected (AC-04, AC-05, TC-09)

```bash
curl -s -o body -w 'HTTP=%{http_code}\n' -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost' \
     --data-urlencode 'email=ghost@x' \
     --data-urlencode 'password=p'
cat body
```

Expected: `HTTP=403` and `body` contains `{"error":"CSRF token missing or invalid"}`. **No new account is created** (verify with `sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username='ghost';"` → empty).

### 10.9 Forged POST With Wrong Token Rejected (TC-10)

```bash
# Start a session, get a real token, then try a POST with a wrong token
curl -s -c jar.txt http://localhost:3001/signup > /dev/null
curl -s -o body -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost' \
     --data-urlencode 'email=ghost@x' \
     --data-urlencode 'password=p' \
     --data-urlencode 'csrf_token=wrong-value-here'
```

Expected: `HTTP=403`.

### 10.10 Legitimate Signup With Matching Token Succeeds (AC-06, TC-11)

```bash
rm -f jar.txt
TOKEN=$(curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' \
     --data-urlencode 'email=alice@test.com' \
     --data-urlencode 'password=pass123' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=302` (the existing signup-success redirect).

### 10.11 Legitimate Login With Matching Token Succeeds (AC-06, TC-12)

```bash
TOKEN=$(curl -s -b jar.txt -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -i -b jar.txt -c jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=pass123' \
     --data-urlencode "csrf_token=$TOKEN" | head -20
```

Expected: HTTP `200`, JSON body `{"success":true,"redirect":"/welcome"}`, and a `Set-Cookie: session=...` header.

### 10.12 Login With Matching Token but Wrong Password Returns 401 (TC-13)

```bash
TOKEN=$(curl -s -b jar.txt -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=wrong' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=401`. The CSRF token gates pass; the bcrypt check fails — exactly the pre-existing 401 path.

### 10.13 GET Routes Unaffected (AC-07, TC-14)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/login
done | sort -u
```

Expected: only `200`.

### 10.14 Logout Invalidates Token (TC-15)

```bash
curl -s -b jar.txt http://localhost:3001/logout > /dev/null
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost2' \
     --data-urlencode 'email=g2@x' \
     --data-urlencode 'password=p' \
     --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=403` (the cleared session has no `csrf_token` — the cached `$TOKEN` no longer matches).

### 10.15 Cross-Session Replay Rejected (TC-16)

```bash
# Jar A has its token; Jar B starts fresh and steals A's token value
TOKEN_A=$(curl -s -c jarA.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -c jarB.txt http://localhost:3001/login > /dev/null
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jarB.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=ghost3' \
     --data-urlencode 'email=g3@x' \
     --data-urlencode 'password=p' \
     --data-urlencode "csrf_token=$TOKEN_A"
```

Expected: `HTTP=403`. Jar B's session token does not match Jar A's stolen value.

### 10.16 Rate Limit Still Gates First (TC-24)

```bash
# With a valid session/token, blast 6 POSTs in <60 s — the 6th must be 429 (rate limit), not 403 (CSRF).
# This proves Rate-Limit middleware is still the outermost layer.
rm -f jar.txt
TOKEN=$(curl -s -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
for i in {1..6}; do
  curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt -X POST http://localhost:3001/login \
       --data-urlencode 'username=alice' \
       --data-urlencode 'password=wrong' \
       --data-urlencode "csrf_token=$TOKEN"
done
```

Expected: five `401` lines and a final `429` (not `403`). The rate-limit middleware short-circuits before CSRF parses the body.

### 10.17 Vulnerability Preservation Walkthrough (AC-14, TC-18–TC-24)

```bash
# VULN-1 SQL injection stays closed (TC-18)
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py

# VULN-2 Stored XSS stays closed (TC-19)
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py

# VULN-3 Reflected XSS stays closed (TC-20) — count at least 5 (original) html.escape calls in auth.py
test "$(grep -c 'html.escape(' backend/app/api/routes/auth.py)" -ge 5 \
  && echo '(>=5 html.escape calls present — VULN-2 + VULN-3 closures intact)'

# VULN-4 Session secret env-sourced (TC-21)
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-5 Bcrypt stays in use (TC-22)
grep -n 'bcrypt' backend/app/core/security.py

# VULN-6 /download/db stays removed (TC-23)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
# Expected: 404.

# VULN-7 Rate limit stays in place — see 10.16 above.
```

### 10.18 No New Dependency (AC-16, TC-25)

```bash
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'
```

Expected: prints the fallback.

### 10.19 Affected-Files Audit (TC-27)

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

---

## 11. Operational Note

This fix requires **no database migration and no data changes**.

- Existing user accounts continue to work without modification — they can still log in, sign up, search, and visit the dashboard.
- The `vulnerable_app.db` file is not modified, moved, or deleted.
- The `users` table schema is unchanged.
- The session cookie format is unchanged (the cookie itself gains one additional key — `csrf_token` — but Starlette's `SessionMiddleware` serialises the entire session dict transparently; no migration is required).

After deploying this change:

- Every `POST /signup` and `POST /login` must carry a `csrf_token` form field whose value matches the per-session token written to `request.session["csrf_token"]` by the user's prior `GET /signup` or `GET /login`. Mismatched or missing tokens receive HTTP `403` with a generic JSON body and never reach the application handler — so the (intentionally slow) bcrypt verify and the SQLite write are never executed on a forged call.
- GET routes (page loads, search, static assets) are entirely unaffected.
- Operators do not need to configure anything — the token is generated, stored, and validated automatically. There is no env var.

**Trade-offs intentionally accepted for the lab:**

- **Session-bound, not per-request, token rotation.** One token per session, the same value for every form in that session. Per-request rotation is unnecessary because XSS (the only practical way to steal a session-bound token after issuance) is already closed (VULN-2, VULN-3).
- **No `Origin`/`Referer` header check.** The synchronizer token is sufficient on its own. Adding header checks would not catch attacks the token misses, but would add branches.
- **No `SameSite=Strict` cookie attribute change.** Starlette's `SessionMiddleware` already defaults to `SameSite=Lax` since 0.20, which together with the synchronizer token forms defense-in-depth. The fix does NOT change this attribute (touching the session middleware risks re-opening VULN-4).
- **Combined with the prior seven fixes**, the OWASP-Top-10 attack surface against this lab is now sharply reduced to **zero open vulnerabilities** from the original v0.1.0 baseline. The application is now a complete "before / after" reference for an instructor-led course.
