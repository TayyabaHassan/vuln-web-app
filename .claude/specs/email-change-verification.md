# Software Specification Document — Email Change with Verification

**Version:** 1.0.0
**Last Updated:** July 5, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Base Release:** v0.1.0 (intentionally vulnerable baseline — the eight lab vulnerabilities remain exploitable)

---

## 1. Overview

The Email Change with Verification feature lets an authenticated user of the Security Vulnerability Lab replace the email address on their account. From the `/profile` page the user enters their **current password**, a **new email**, and a **confirmation of the new email**; the server validates the password with bcrypt, checks the new address for syntactic validity and uniqueness, and emails a single-use, one-hour verification link to the new address. The user's existing email remains in effect until that link is opened. The feature is **additive** — it introduces a new pending-email workflow that rides the existing `SessionMiddleware`, `CSRFMiddleware`, and `RateLimitMiddleware`, and reuses the existing `secrets.token_urlsafe(32)` token model, the existing `EMAIL_VERIFICATION_TTL_SECONDS` (1 hour) lifetime, and the existing SendGrid transport in `core/mailer.py`. The eight lab vulnerabilities (VULN-1 through VULN-8) are not modified by this slice and remain intentionally exploitable in v0.1.0; a dedicated test case asserts that the unauthenticated `/download/db` route still serves the SQLite file (VULN-6 still open).

---

## 2. Scope & Non-Goals

### 2.1 In Scope (re. the 8 lab vulnerabilities)

| # | Vulnerability | File | In-scope for this slice? |
|---|---------------|------|--------------------------|
| 1 | SQL Injection | `backend/app/services/auth_service.py` | **No** — not modified. New SQL added by this slice is parameterized, but the existing `login()` / `signup()` concatenation is intentionally left intact. |
| 2 | Stored XSS | `backend/app/api/routes/auth.py` | **No** — not modified. Any new reflected value introduced by this slice (`{{pending_email}}`, `{{new_email}}` on the profile page, etc.) is `html.escape(..., quote=True)` before substitution. |
| 3 | Reflected XSS | `backend/app/api/routes/auth.py` | **No** — not modified. The raw email-change token is **never** reflected into any response, URL, template, or log. The `/verify-email-change` route renders a fixed, escape-encoded outcome message — not the token. |
| 4 | Session Hijacking | `backend/app/main.py` | **No** — not modified. The hardcoded `super-secret-key-12345` remains in v0.1.0; this slice does not touch `main.py`. |
| 5 | Weak Password Storage | `backend/app/core/security.py` | **No** — not modified. New password verification uses the existing `verify_password(...)` (MD5 in v0.1.0, bcrypt in later versions). |
| 6 | Exposed Database | `backend/app/api/routes/auth.py` | **No** — not modified. The unauthenticated `/download/db` route remains. A test case (TC-13) explicitly asserts it is still reachable and serves the SQLite file. |
| 7 | No Rate Limiting | `backend/app/main.py` + `core/rate_limit.py` | **No** — not modified. v0.1.0 has no rate limiter; the new `POST /profile/email/request` is therefore unthrottled at the app layer in this base release (a deliberate consequence of the additive posture). |
| 8 | CSRF | `backend/app/main.py` + `core/csrf.py` | **No** — not modified. v0.1.0 has no CSRF middleware. The new POST carries a hidden `csrf_token` field in the rendered profile HTML so the form is **forward-compatible** with the eventual CSRF middleware, but no middleware enforces it in v0.1.0. |

### 2.2 In Scope (feature behavior)

- A new "Change Email" card on the existing authenticated `/profile` page, with three fields (current password, new email, confirm new email) and a hidden `csrf_token` field.
- A new `POST /profile/email/request` endpoint (session-gated) that validates input, persists a `pending_email` + `pending_email_token` + `pending_email_token_expires` triple on the `users` row, and emails a verification link to the **new** address (not the current one).
- A new `GET /verify-email-change?token=…` endpoint (token-as-capability, like the existing `GET /verify`; not session-gated) that, on a valid unexpired match, **atomically promotes** `pending_email` to `email`, clears the three pending columns (single-use), updates `request.session["email"]` if a session is present, and renders a fixed outcome page.
- A new helper module `backend/app/services/email_change_service.py` that owns the business logic (mirrors `services/verification_service.py`).
- A new email-send helper `core/mailer.send_email_change_email(to_email, username, confirm_url)` that reuses the SendGrid HTTPS transport and is `html.escape(..., quote=True)`-safe on every reflected value.
- A new `frontend/templates/verify_email_change_result.html` (analog of the existing `verify_result.html`).
- A new `frontend/templates/email_not_configured_for_change.html` (analog of the existing `email_not_configured.html`) shown when the `is_email_configured()` gate is false.
- A new `frontend/static/css/styles.css` block `.email-change-card` (additive, theme-aware via existing custom properties).

### 2.3 Non-Goals

- **No fix to any of the 8 lab vulnerabilities** (per §2.1).
- **No new third-party dependency.** Token math is stdlib `secrets`; the email transport is the existing SendGrid transport in `core/mailer.py` (already a `urllib` HTTPS POST). The QR / TOTP dependency (`segno`) is **not** added.
- **No modification to `backend/app/main.py`.** The existing three middlewares (or none, in v0.1.0) cover the new routes; no new middleware is registered.
- **No modification to `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `services/auth_service.py`, `services/verification_service.py`, `services/lockout_service.py`, `services/otp_service.py`, `services/totp_service.py`, or `db/session.py`'s public surface.** The pending-email columns are added via an additive `ALTER TABLE` migration in `init_db()`; the existing CREATE statement is left intact and the migration is a no-op on fresh databases.
- **No schema redesign.** Three nullable columns are added: `pending_email`, `pending_email_token`, `pending_email_token_expires`. No existing column is dropped, renamed, or retyped. No data is backfilled or grandfathered.
- **No email-verification bypass.** A user who has not yet clicked the original signup verification link (existing `is_verified` flow) can still request an email change, but the change only commits after the **new** link is clicked. The `is_verified` flag and the pending-email flag are independent.
- **No multi-device session invalidation.** When the email change is confirmed, only `request.session["email"]` of the verifying browser is updated. Other live sessions keep their old `email` value until they next log in (acceptable per the additive posture — a session-fixation hardening pass is out of scope).
- **No "revert to old email" flow** if the new address turns out to be a typo. The user can request a second change; the second request overwrites the first.
- **No per-IP throttling of the new POST** (no rate limiter exists in v0.1.0; the feature must not add one). The per-account lockout mechanism (`services/lockout_service.py`) is **not** extended to count failed email-change attempts.

---

## 3. Affected Files (exact repository paths)

| Path | Change |
|------|--------|
| `backend/app/services/email_change_service.py` | **New.** Houses `start_email_change()`, `verify_email_change_token()`, and `resend_email_change_for_credentials()`. Mirrors the structure of `backend/app/services/verification_service.py`. |
| `backend/app/api/routes/auth.py` | **Modified.** Three new route handlers (`profile_page` extended to splice the pending-email status; `profile_email_request_post`; `verify_email_change_page`); one new helper `render_verify_email_change_result(...)`. No existing handler is removed or weakened. |
| `backend/app/db/session.py` | **Modified.** The existing `init_db()` is extended with an idempotent `ALTER TABLE` migration that adds `pending_email`, `pending_email_token`, `pending_email_token_expires` (all nullable / no default). The `CREATE TABLE IF NOT EXISTS` statement is unchanged. |
| `backend/app/core/mailer.py` | **Modified.** One new public function `send_email_change_email(to_email, username, confirm_url)`, mirroring `send_verification_email`. The SendGrid transport, the `_send_via_sendgrid` POST, and `send_verification_email` / `send_otp_email` are unchanged. |
| `backend/app/core/config.py` | **Modified.** One new setting `EMAIL_CHANGE_TTL_SECONDS` (default `3600`, env-tunable, non-secret). No new secret. `is_email_configured()` is unchanged and reused. |
| `frontend/templates/profile.html` | **Modified.** Additive "Change Email" card with three fields, the hidden `csrf_token` input, an inline status line for the pending state, and the `{{profile_message}}` / `{{pending_email}}` splice pattern already used by the change-password card. No existing markup is removed. |
| `frontend/templates/verify_email_change_result.html` | **New.** A fixed, escape-encoded outcome page. Carries a pre-render theme init script and a theme toggle in the shared header, matching the project's template convention. The raw token is **never** reflected. |
| `frontend/templates/email_not_configured_for_change.html` | **New.** A graceful-degrade page, shown by `GET /profile` and `POST /profile/email/request` when `is_email_configured()` is false (mirrors `email_not_configured.html` for the signup flow). |
| `frontend/static/css/styles.css` | **Modified.** One new additive block `.email-change-card` (and `.email-change-status`). Reuses existing `--color-bg-surface`, `--color-border-soft`, `--color-error-*`, `--color-success-*` custom properties so light/dark theming comes for free. |
| `docs/PRD.md` | **Modified.** A new bullet under §3 (Functional Requirements) noting email change as a v0.1.x feature. No other section changes. |
| `docs/TDD.md` | **Modified.** A new sub-section under §11.4 (Endpoint Inventory) listing the three new endpoints; a new sub-section under §11.3 (Schema) listing the three new columns. No other section changes. |

No file is deleted. No existing test is removed. No file outside this list is touched.

---

## 4. Runtime Behavior

### 4.1 Database Initialization

- On application startup, `init_db()` is called and executes the existing `CREATE TABLE IF NOT EXISTS` for the `users` table (unchanged).
- After the CREATE step, the same `init_db()` function issues three idempotent `ALTER TABLE users ADD COLUMN ...` statements for `pending_email` (TEXT NULL), `pending_email_token` (TEXT NULL), and `pending_email_token_expires` (REAL NULL). Each is wrapped in a `try/except sqlite3.OperationalError` so re-runs (column already exists) are silent no-ops.
- A fresh database is fully functional in one boot. A pre-existing v0.1.0 database gains the three nullable columns without touching existing rows; the new columns are NULL for every existing user, which the application treats as "no pending change."

### 4.2 Session Gating

- `GET /profile` and `POST /profile/email/request` require `request.session.get("user_id")` to be truthy. A missing key → `302 /login`. This matches the existing `welcome_page` gate exactly.
- `GET /verify-email-change?token=…` is **not** session-gated — the token itself is the capability (mirrors the existing `GET /verify` for signup verification, and the OAuth callback's GET-only design). The handler does, however, read the (optional) `request.session` to update `email` if a session is present.

### 4.3 Request Lifecycle — `POST /profile/email/request`

1. Session gate: if `user_id` is missing, return `302 /login` (no body).
2. CSRF gate: the request must include a `csrf_token` form field. In v0.1.0 (no CSRF middleware) the value is read but not validated — the field is rendered so a future middleware can be added without breaking the form. A missing field is treated as a client error (`400 {"error": "Missing CSRF token"}`) so the same handler code is forward-compatible.
3. Read fields via `Form(...)`: `current_password`, `new_email`, `confirm_new_email`.
4. Validate syntactically:
   - All three fields non-empty (else `400 {"error": "All fields are required"}`).
   - `new_email == confirm_new_email` (else `400 {"error": "Emails do not match"}`).
   - `new_email` matches the project's email regex (mirrors the signup regex; else `400 {"error": "Invalid email address"}`).
5. Look up the calling user: parameterized `SELECT id, username, email, password FROM users WHERE id = ?` bound to `request.session["user_id"]`.
6. Verify the current password with `verify_password(current_password, row["password"]` from `core/security.py`). On mismatch, return `401 {"error": "Incorrect password"}` — no enumeration leak (the response is identical regardless of whether the account exists in this session, since the session itself is the prerequisite).
7. Uniqueness check: parameterized `SELECT id FROM users WHERE email = ? AND id != ?` bound to `[new_email, current_user_id]`. If any row returns, return `409 {"error": "That email is already in use"}`.
8. Issue token: `token = secrets.token_urlsafe(32)`, `expires = time.time() + config.EMAIL_CHANGE_TTL_SECONDS`.
9. Persist: parameterized `UPDATE users SET pending_email = ?, pending_email_token = ?, pending_email_token_expires = ? WHERE id = ?` bound to `[new_email, token, expires, current_user_id]`. Commit.
10. Build the confirm URL: `f"{config.APP_BASE_URL}/verify-email-change?token={token}"`.
11. Hand the URL to `core/mailer.send_email_change_email(new_email, row["username"], confirm_url)` (a new function; see §4.5).
12. On mailer success: return `200 {"success": true, "message": "Verification email sent to {new_email}."}`. The new email value is `html.escape(..., quote=True)` before it enters the JSON string in the case it ever surfaces in an error log (VULN-3 posture).
13. On mailer failure: roll back the persistence by issuing a second parameterized `UPDATE users SET pending_email = NULL, pending_email_token = NULL, pending_email_token_expires = NULL WHERE id = ?`. Return `502 {"error": "Could not send the verification email. Please try again later."}`.
14. If `is_email_configured()` is false (no SendGrid key, no `MAIL_*` env), the route renders `email_not_configured_for_change.html` with `200` (graceful degrade — mirrors the signup flow). No state is written and no email is sent.

### 4.4 Request Lifecycle — `GET /verify-email-change?token=…`

1. Read `token` from the query string. A missing or empty token → render `verify_email_change_result.html` with `status="invalid"`, `status_message="This email-change link is invalid or has expired."` (the raw token is never reflected — VULN-3).
2. Look up the token: parameterized `SELECT id, username, email, pending_email, pending_email_token_expires FROM users WHERE pending_email_token = ?` bound to `[token]`. No row → render with `status="invalid"`, same fixed message.
3. Check expiry: `pending_email_token_expires` is `None` or `time.time() > expires` → render with `status="expired"`, same fixed message. (No state change; the row keeps its `pending_email` so the user can re-request.)
4. Atomic promotion: parameterized `UPDATE users SET email = pending_email, pending_email = NULL, pending_email_token = NULL, pending_email_token_expires = NULL WHERE id = ?` bound to `[row["id"]]`. Commit. The same `UPDATE` is a single SQL statement — there is no readable intermediate state.
5. If `request.session.get("user_id") == row["id"]`, also write `request.session["email"] = row["pending_email"]` so the profile page (and any `{{email}}` splice) immediately reflects the new address. (If the user is not signed in, the DB is updated; the new email takes effect on next login.)
6. Render `verify_email_change_result.html` with `status="ok"`, `status_message="Your email has been updated. You can now close this tab."` and a link back to `/profile`.

### 4.5 Mailer Helper — `core/mailer.send_email_change_email(to_email, username, confirm_url)`

- Mirrors the structure of `core/mailer.send_verification_email(...)`.
- Returns `True` on SendGrid HTTP 2xx, `False` on any other outcome (never raises — the caller treats `False` as "could not send" and rolls back).
- Subject: `"Confirm your new email - Security Vulnerability Lab"`.
- Text body: confirms the change-of-email intent, includes the `confirm_url`, and notes the 1-hour validity.
- HTML body: same content, with `html.escape(username, quote=True)` and `html.escape(confirm_url, quote=True)` before the values enter the markup (VULN-2). The raw token therefore never appears as unescaped text in either the text or HTML body — only the pre-built URL does, and the URL's `?token=` parameter is treated as one opaque value to be escaped wholesale.
- The API key is **never** logged (VULN-4 posture). Only `"Email change confirmation sent to <to_email>"` is logged on success, and `"SendGrid API send failed to <to_email>"` on failure.

### 4.6 Profile Page — `/profile` Augmentation

- The existing `GET /profile` handler is extended (not rewritten) to splice four new placeholders before the response is sent:
  - `{{email_change_card}}` — the rendered `email-change-card` block (with current/pending state) or, when `is_email_configured()` is false, an inline notice linking to `email_not_configured_for_change.html`.
  - `{{email_change_status}}` — a `<p class="email-change-status">…</p>` line that is empty when no change is pending, or reads `"A change to <pending_email> is pending verification."` with `pending_email` `html.escape(..., quote=True)`-d.
  - `{{profile_message}}` (existing placeholder) — reused for the JSON-driven success/error message after a `POST /profile/email/request` 4xx/2xx response.
  - `{{csrf_token}}` (existing placeholder) — already used by the change-password form; the email-change form reuses the same session-bound token.
- No existing placeholder is removed. The `change_password` card is untouched.

### 4.7 CSRF Token Forward-Compatibility

- The new `email-change-card` block in `profile.html` includes `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` as the first child of the form, identical to the change-password card.
- In v0.1.0, no middleware enforces the token, so the field is "best-effort." When the future `CSRFMiddleware` lands, the form will be automatically protected without further changes.
- The route handler reads the field via `Form("csrf_token", alias="csrf_token")` and rejects a missing field with `400` so a future middleware swap requires no handler change.

---

## 5. User Flows

### 5.1 Email Change — Happy Path

1. An authenticated user navigates to `GET /profile` (session-gated).
2. The server reads `profile.html` from disk, splices the `{{email_change_card}}` (with empty `{{email_change_status}}`), and returns the page.
3. The user enters their **current password**, **new email**, and **confirm new email**, then submits the form.
4. The browser POSTs to `/profile/email/request` (urlencoded via `URLSearchParams`).
5. The server validates the input, verifies the current password (MD5 in v0.1.0 via `verify_password` from `core/security.py`), checks uniqueness, persists the `pending_email` triple, and calls `mailer.send_email_change_email(...)`.
6. The server returns `200 {"success": true, "message": "Verification email sent to {new_email}."}`.
7. The profile page (re-rendered on the same response) shows a green `.is-success` banner with the message and a yellow `.email-change-status` line reading "A change to {new_email} is pending verification." with `new_email` escaped.
8. The user opens the email on any device and clicks the link `https://…/verify-email-change?token=…`.
9. `GET /verify-email-change` reads the token, finds the row, checks expiry, atomically promotes `pending_email` to `email`, clears the pending columns, and (if the verifying browser is signed in) updates `request.session["email"]`.
10. The server renders `verify_email_change_result.html` with a fixed `status="ok"` message. The raw token is **never** reflected in the HTML.

### 5.2 Email Change — Wrong Current Password

1. Steps 1–3 of §5.1.
2. The user enters a wrong current password.
3. The server returns `401 {"error": "Incorrect password"}`. The pending email is not persisted; no email is sent.
4. The profile page re-renders with a red `.is-error` banner; the form values are not preserved (the user must re-type the new email to avoid an XSS via value-reflection — VULN-3 posture).

### 5.3 Email Change — Token Expired

1. Steps 1–7 of §5.1; the user does not click the link within 1 hour.
2. The user opens the link later.
3. `GET /verify-email-change` reads the token, finds the row, and detects `time.time() > pending_email_token_expires`.
4. The server renders `verify_email_change_result.html` with `status="expired"` and a fixed message ("This email-change link has expired. You can request a new one from your profile."). The DB row is **not** modified; the `pending_email` stays set so the user sees the same pending state on `/profile` and can re-submit the form to re-issue.
5. The raw token is not reflected.

### 5.4 Email Change — Token Reused (Already Consumed)

1. The user clicks the link once; the row is promoted and the token columns are cleared (single-use).
2. The user clicks the link a second time (e.g., from a stale email client).
3. `GET /verify-email-change` looks up the now-NULL token and finds no row.
4. The server renders `verify_email_change_result.html` with `status="invalid"` and a fixed message. The DB row is not modified.

### 5.5 Email Change — New Email Already in Use

1. Steps 1–3 of §5.1; the user enters an email that another user has already registered.
2. The uniqueness `SELECT` returns a row, the server returns `409 {"error": "That email is already in use"}`. The pending email is not persisted; no email is sent.
3. The profile page re-renders with a red `.is-error` banner.

### 5.6 Email Change — Email Send Failure

1. Steps 1–7 of §5.1; SendGrid returns a non-2xx (or the request times out at `SENDGRID_HTTP_TIMEOUT`).
2. The mailer returns `False` (never raises). The handler issues the rollback `UPDATE` (clears the pending triple) and returns `502 {"error": "Could not send the verification email. Please try again later."}`.
3. The profile page re-renders with a red `.is-error` banner. The DB row is in a consistent state (no half-committed change).

---

## 6. Functional Requirements

### FR-01: Authenticated Access

- `GET /profile` and `POST /profile/email/request` MUST check `request.session.get("user_id")` before doing any work; missing → `302 /login`.
- `GET /verify-email-change` MUST NOT require a session. The token is the capability.

### FR-02: Input Validation

- `current_password`, `new_email`, `confirm_new_email` MUST all be non-empty.
- `new_email` MUST equal `confirm_new_email`.
- `new_email` MUST match the project's email regex (the same regex used by the signup form's `type="email"` validation, mirrored server-side).
- `new_email` MUST NOT equal the user's current `users.email` (a "change" that doesn't change is rejected with `400 {"error": "New email must be different from the current email"}`).

### FR-03: Password Verification

- The current password MUST be verified with `core.security.verify_password(current_password, row["password"])`. No comparison shortcut; the MD5 hex equality check inside `auth_service.login()` is the sole authenticator.
- A wrong password MUST return `401 {"error": "Incorrect password"}` and MUST NOT persist the pending-email triple or send any email.

### FR-04: Uniqueness Check

- A parameterized `SELECT id FROM users WHERE email = ? AND id != ?` MUST be run against `new_email` and the current `user_id` (excluded so a user re-submitting their own current address doesn't fail spuriously after a previous change).
- Any matching row → `409 {"error": "That email is already in use"}`.

### FR-05: Token Issuance and Persistence

- The token MUST be `secrets.token_urlsafe(32)` (256-bit, URL-safe Base64).
- The token MUST be stored **raw** in `pending_email_token` and MUST be the same value placed in the confirmation URL.
- `pending_email_token_expires` MUST be `time.time() + config.EMAIL_CHANGE_TTL_SECONDS` (default 3600 seconds; env-tunable).
- All three new columns MUST be written via a single parameterized `UPDATE`.

### FR-06: Email Send

- The confirmation email MUST be delivered through `core/mailer.send_email_change_email(new_email, username, confirm_url)`, which uses the existing SendGrid HTTPS transport.
- On mailer failure, the pending triple MUST be rolled back (parameterized `UPDATE` setting the three columns to NULL).
- The API key MUST NEVER be logged.
- The username in the email body MUST be `html.escape(username, quote=True)`-d; the URL MUST be `html.escape(confirm_url, quote=True)`-d before it enters the HTML body (VULN-2).

### FR-07: Token Verification

- `GET /verify-email-change?token=…` MUST look up the token with a parameterized `SELECT id, username, email, pending_email, pending_email_token_expires FROM users WHERE pending_email_token = ?`.
- A missing/empty token, a non-matching row, or an expired row MUST render `verify_email_change_result.html` with the appropriate `status` and a fixed `status_message`. The raw token MUST NOT appear anywhere in the response body, the URL bar (the server never echoes it), or the server log (VULN-3).

### FR-08: Atomic Promotion and Single-Use

- On a valid token, the handler MUST issue a single parameterized `UPDATE users SET email = pending_email, pending_email = NULL, pending_email_token = NULL, pending_email_token_expires = NULL WHERE id = ?` and commit. The promotion is one statement, so there is no observable intermediate state.
- After the UPDATE, the row's `pending_email_token` is NULL, so a second visit with the same token finds no matching row and renders `status="invalid"`.

### FR-09: Session Refresh

- If `request.session.get("user_id") == row["id"]` at the moment of promotion, the handler MUST write `request.session["email"] = row["pending_email"]` so the next render of the profile page (and any other `{{email}}` splice) shows the new address.
- If no session is present, the DB is updated silently; the new email takes effect on the next login.

### FR-10: Graceful Degrade When Email Is Unconfigured

- If `core.config.is_email_configured()` is false, `GET /profile` MUST render the `email-change-card` notice (linking to `email_not_configured_for_change.html`) and the new email-change form MUST NOT be rendered. `POST /profile/email/request` MUST return `200` with `email_not_configured_for_change.html` and MUST NOT persist any state. The mirror of the existing `email_not_configured.html` for the signup flow.

### FR-11: CSRF Field Forward-Compatibility

- The new email-change form MUST include `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` as the first child.
- The handler MUST read the field via `Form("csrf_token", alias="csrf_token")` and MUST return `400 {"error": "Missing CSRF token"}` on a missing/empty field.
- In v0.1.0 (no CSRF middleware), the value is not compared against the session. The contract is forward-compatible with the eventual `CSRFMiddleware`.

### FR-12: Pending-Status Visibility

- `GET /profile` MUST splice `{{email_change_status}}` so the user sees an inline line reading `"A change to {pending_email} is pending verification."` whenever `row["pending_email"]` is non-NULL.
- The spliced `pending_email` MUST be `html.escape(pending_email, quote=True)`-d (VULN-2).

### FR-13: No Modification of Existing Routes or Middleware

- `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/qr_login.py`, and the route handlers for `/login`, `/signup`, `/welcome`, `/logout`, `/search`, `/download/db`, `/verify`, `/verify/resend`, `/auth/google/*`, `/profile/password`, `/profile/2fa*`, `/login/otp*`, `/login/totp*`, `/qr/*` MUST NOT be modified.
- `services/auth_service.py`, `services/verification_service.py`, `services/lockout_service.py`, `services/otp_service.py`, `services/totp_service.py`, and `services/oauth_service.py` MUST NOT be modified.

### FR-14: Existing-Vulnerability Intact (Hard Constraint)

- The unauthenticated `GET /download/db` route MUST continue to serve the SQLite file with no session check. This is a deliberate, observable consequence of the additive posture in v0.1.0 and is asserted by TC-13.

---

## 7. Non-Functional Requirements

### NFR-01: No New Third-Party Dependency

- Token math: `secrets.token_urlsafe(32)` from the stdlib.
- Email transport: the existing SendGrid HTTPS transport in `core/mailer.py` (already a `urllib.request` POST). No `requests`, `httpx`, `sendgrid-python`, `boto3`, etc.
- No new Python package in `backend/pyproject.toml`.

### NFR-02: Parameterized SQL Everywhere

- Every `SELECT`, `UPDATE`, and `INSERT` introduced by this slice MUST use bound parameters (`?` placeholders, list/tuple second argument). No f-string or `+`-concatenation with user input into SQL — VULN-1 posture is preserved in the new code (even though the existing `auth_service.login()` / `signup()` concatenation in v0.1.0 is intentionally left in place).

### NFR-03: Output Encoding

- Every attacker-controllable value that enters an HTML response, an HTML email body, or a JSON string in an error message MUST be `html.escape(..., quote=True)`-d first.
- The raw email-change token MUST never appear in any response, URL path segment, or log line (VULN-3 posture). The `confirm_url` as a whole is treated as one opaque string and is escaped wholesale; it is not split on `?token=`.

### NFR-04: Fail-Safe Mailer

- `core/mailer.send_email_change_email` MUST return `False` (never raise) on every error path: unconfigured, network error, non-2xx response, JSON serialization error, timeout. The caller treats `False` as "could not send" and rolls back the pending triple.

### NFR-05: Idempotent Schema Migration

- The three `ALTER TABLE` statements added to `init_db()` MUST be wrapped in `try/except sqlite3.OperationalError` so re-running on a database that already has the columns is a silent no-op. The original `CREATE TABLE IF NOT EXISTS` MUST be unchanged.

### NFR-06: Minimal main.py Surface

- The new routes are registered through the existing `app.include_router(router)` line in `main.py`. No new `add_middleware` call, no new import, no new top-level statement.

### NFR-07: Theme-Aware CSS

- The new `.email-change-card` / `.email-change-status` block in `styles.css` MUST use the existing `--color-bg-surface`, `--color-border-soft`, `--color-error-*`, and `--color-success-*` custom properties. No new color literal is introduced; toggling `data-theme` must recolor the card without JS involvement.

### NFR-08: No Logged Secrets or Tokens

- The SendGrid API key MUST NOT be logged. The raw token MUST NOT be logged. The username and email MAY be logged (they are already user-controlled inputs logged elsewhere in the project). The new helper logs only `"Email change confirmation sent to <to_email>"` (success) or `"SendGrid API send failed to <to_email>"` (failure).

### NFR-09: Observability for the Pending State

- `GET /profile` MUST splice `{{email_change_status}}` so the user can see the pending state on every page load until the link is clicked or the link expires and is re-requested.

### NFR-10: Backward Compatibility With v0.1.0 Lab Posture

- A fresh v0.1.0 database (no `pending_email` columns) MUST work after the migration is applied at first boot. The new columns are nullable, so existing rows need no backfill.
- A user with no pending change (the common case) MUST see the email-change card with an empty status line; the route handler MUST treat `pending_email IS NULL` as "no pending change" everywhere it reads the row.

---

## 8. Success Paths

### SP-01: Email Change Issued and Confirmed

1. Authenticated user opens `GET /profile`, sees the email-change card.
2. User enters correct current password, valid new email, matching confirm-new-email.
3. Server validates input → verifies current password (MD5 in v0.1.0) → uniqueness check passes → persists the pending triple → emails the confirm URL.
4. Profile re-renders with `200` and a green success banner.
5. User opens the link within 1 hour; server promotes `pending_email` to `email` and clears the three pending columns (single-use).
6. If the verifying browser is signed in as the same user, the session's `email` is updated.
7. `verify_email_change_result.html` renders with `status="ok"`. The raw token is not in the HTML.

### SP-02: Re-Request After Expiry

1. User requests a change, the link expires unclicked.
2. User returns to `/profile`; the pending status line is still visible (the `pending_email` was not cleared on expiry — only on successful promotion or rollback).
3. User re-submits the form (possibly with a different new email).
4. The second `start_email_change(...)` call overwrites the prior `pending_email_token` and `pending_email_token_expires` (the old token is now invalid; the new one is the only valid one).
5. Email is re-sent to the new address.

### SP-03: Email Configuration Missing — Graceful Degrade

1. `core.config.is_email_configured()` is false.
2. `GET /profile` shows the email-change card with an inline notice and no form.
3. `POST /profile/email/request` returns `200` with `email_not_configured_for_change.html`; no DB write occurs.
4. The rest of the profile page (username, email, change-password card) still renders normally.

---

## 9. Alternate Paths

### AP-01: Wrong Current Password

1. `POST /profile/email/request` with a wrong `current_password`.
2. `verify_password` returns `False`.
3. Server returns `401 {"error": "Incorrect password"}`. No persistence, no email.
4. Profile re-renders with a red `.is-error` banner. The new-email fields are not pre-filled.

### AP-02: New Email In Use by Another User

1. `POST /profile/email/request` with a `new_email` that already exists on another row.
2. Uniqueness `SELECT` returns a row.
3. Server returns `409 {"error": "That email is already in use"}`. No persistence, no email.
4. Profile re-renders with a red `.is-error` banner.

### AP-03: New Email Same as Current

1. `POST /profile/email/request` with `new_email == users.email`.
2. Server returns `400 {"error": "New email must be different from the current email"}`. No persistence, no email.

### AP-04: Mismatched Confirmation

1. `POST /profile/email/request` with `new_email != confirm_new_email`.
2. Server returns `400 {"error": "Emails do not match"}`. No persistence, no email.

### AP-05: Syntactically Invalid Email

1. `POST /profile/email/request` with `new_email` failing the regex.
2. Server returns `400 {"error": "Invalid email address"}`. No persistence, no email.

### AP-06: Email Send Fails

1. `mailer.send_email_change_email` returns `False`.
2. Handler rolls back the pending triple.
3. Server returns `502 {"error": "Could not send the verification email. Please try again later."}`.
4. Profile re-renders with a red `.is-error` banner. DB is in a consistent state.

### AP-07: Token Expired on Click

1. User opens the confirm link after the 1-hour TTL.
2. Server renders `verify_email_change_result.html` with `status="expired"`. DB is unchanged (the `pending_email` stays set so the user can re-request). Raw token not reflected.

### AP-08: Token Already Consumed

1. User opens the confirm link a second time after a successful first visit.
2. Server renders `verify_email_change_result.html` with `status="invalid"`. DB unchanged.

### AP-09: Token Never Issued (Forged / Random)

1. A non-authenticated third party visits `/verify-email-change?token=<random>`.
2. Server renders `verify_email_change_result.html` with `status="invalid"`. DB unchanged. Raw token not reflected.

### AP-10: Missing CSRF Token

1. `POST /profile/email/request` without a `csrf_token` field.
2. Server returns `400 {"error": "Missing CSRF token"}`. No persistence.

### AP-11: Session Expired Mid-Form

1. User's session cookie is no longer valid (e.g., they cleared cookies while reading the email).
2. The user opens `/verify-email-change?token=…` from the email link.
3. Server runs the verification without a session, updates the DB, and renders the result page. The new email takes effect on the user's next login.

---

## 10. Edge Cases

### EC-01: Database File Recreated

- The `ALTER TABLE` migration is idempotent. After a `vulnerable_app.db` deletion, the next boot creates the table from `CREATE TABLE IF NOT EXISTS` and then runs the three `ALTER`s — all of which become no-ops against the freshly-created columns. The app is fully functional.

### EC-02: Very Long Email Address

- An attacker submits a 10-KB `new_email`. The regex rejects it (`Invalid email address`); no DB write occurs. The handler does not impose its own length cap, relying on the regex's anchored structure to keep the input bounded.

### EC-03: Unicode in Username Displayed in Email

- The email body splices `username` with `html.escape(..., quote=True)`. Unicode in the username renders correctly in the HTML body (escaping is for `<`, `>`, `&`, `"`, `'` only).

### EC-04: Token Collision

- `secrets.token_urlsafe(32)` provides 256 bits of entropy; the probability of a collision across all issued tokens is negligible. The DB enforces the column's `UNIQUE` constraint implicitly by treating a duplicate `pending_email_token` as a single matching row; the first-to-claim semantics are correct.

### EC-05: Email Mismatch with Token's `pending_email`

- An attacker who somehow learned a valid `pending_email_token` for user A and tried to register with their own `new_email` could not: the token is bound to the user row that owns it, and the promotion `UPDATE` reads `pending_email` from that same row, not from any request parameter. The attacker cannot substitute a different email.

### EC-06: Concurrent Email-Change Requests

- Two browser tabs submit `POST /profile/email/request` near-simultaneously. The second `start_email_change(...)` overwrites the first's token. Whichever confirm link the user clicks first wins; the other becomes a no-op (the row's `pending_email_token` no longer matches).

### EC-07: Token URL with Extra Query Parameters

- A user (or attacker) appends `&foo=bar` to the confirm URL. The server's `?token=…` read picks up the `token` value; the extra parameters are ignored. No special handling is needed.

### EC-08: User Deletes Their Account Mid-Change

- There is no account-deletion endpoint in v0.1.0. If a future version adds one, the pending-email row would be removed along with the user; the token would simply not match any row (rendering `status="invalid"`). This slice does not add an account-deletion endpoint.

### EC-09: `request.session` Contains Stale `email`

- After the promotion, the handler writes `request.session["email"] = row["pending_email"]` only when the verifying browser is signed in as the same user. Other live sessions of the same user keep the old `email` until they re-login. The `/profile` page reads `request.session["email"]`, not the DB, so other sessions display the old address until refresh/login. This is a deliberate, documented trade-off (NFR-10 + §2.3).

### EC-10: SendGrid Returns 202 but Email Lands in Spam

- Out of scope. The mailer treats a 2xx as success; deliverability is a SendGrid-side concern.

---

## 11. Business Rules

1. **The current email remains in effect until the new one is verified.** Promotion happens only on a successful, unexpired token match — never on form submission alone.
2. **The token is the only capability required to promote.** No re-prompt of the current password on the verify page; the link is the authorization (mirrors the existing `/verify` and OAuth callback posture).
3. **The token is single-use.** The promotion `UPDATE` clears `pending_email_token` to NULL; a second visit renders `status="invalid"`.
4. **The token is time-bounded.** Default 1 hour, env-tunable via `EMAIL_CHANGE_TTL_SECONDS`. An expired token does not clear `pending_email`, so the user can re-request.
5. **A failed email send rolls back the pending state.** The DB must never hold a `pending_email` whose confirmation email was never delivered; the user would otherwise see "pending verification" on `/profile` but have no working link.
6. **The eight lab vulnerabilities remain exploitable.** This slice is additive only. In particular, `GET /download/db` continues to serve the SQLite file without authentication; SQL concatenation in `services/auth_service.py` is untouched; the dashboard still reflects the unescaped `{{username}}`; the hardcoded `super-secret-key-12345` is still in `main.py`. TC-13 asserts VULN-6 is still open.
7. **No new middleware.** The new POSTs are covered by whatever middleware stack is present (in v0.1.0: none; in later versions: the existing CSRF + rate-limit pair). The handler reads the `csrf_token` field forward-compatibly.
8. **The new columns are nullable and have no default.** Existing rows need no backfill; the migration is purely additive. A `pending_email IS NULL` row is "no pending change."

---

## 12. Acceptance Criteria

### AC-01: Authenticated Profile Page

- An authenticated `GET /profile` MUST render the email-change card with the current email, the new-email form, and the hidden `csrf_token` field.
- An unauthenticated `GET /profile` MUST return `302 /login` (no email-change markup leaks).

### AC-02: Form Submission With Valid Input

- `POST /profile/email/request` with the correct current password, a syntactically valid new email, a matching confirm-new-email, and a non-empty `csrf_token` field MUST persist the pending triple, send a SendGrid email, and return `200 {"success": true, "message": "..."}`.
- The pending triple (`pending_email`, `pending_email_token`, `pending_email_token_expires`) MUST be present in the `users` row after the response.

### AC-03: Form Submission With Wrong Password

- `POST /profile/email/request` with the wrong current password MUST return `401 {"error": "Incorrect password"}`. The pending triple MUST NOT be present in the `users` row. No email MUST be sent.

### AC-04: Form Submission With Email In Use

- `POST /profile/email/request` with a `new_email` belonging to another user MUST return `409 {"error": "That email is already in use"}`. No persistence, no email.

### AC-05: Form Submission With Mismatched Confirmation

- `POST /profile/email/request` with `new_email != confirm_new_email` MUST return `400 {"error": "Emails do not match"}`. No persistence, no email.

### AC-06: Form Submission With Invalid Email Syntax

- `POST /profile/email/request` with a `new_email` failing the regex MUST return `400 {"error": "Invalid email address"}`. No persistence, no email.

### AC-07: Email Send Failure Rolls Back

- A `POST /profile/email/request` that triggers a SendGrid non-2xx MUST leave the `users` row with the three pending columns NULL (rolled back). The response MUST be `502 {"error": "Could not send the verification email. Please try again later."}`.

### AC-08: Clicking the Confirm Link Within 1 Hour

- `GET /verify-email-change?token=<valid>` within 1 hour of issuance MUST issue the atomic promotion `UPDATE` and render `verify_email_change_result.html` with `status="ok"`. The raw token MUST NOT appear in the response body or any log line.
- If the verifying browser is signed in as the same user, `request.session["email"]` MUST be the new value.
- A second visit with the same token MUST render `status="invalid"` (single-use).

### AC-09: Clicking the Confirm Link After 1 Hour

- `GET /verify-email-change?token=<valid>` after expiry MUST render `verify_email_change_result.html` with `status="expired"`. The DB row's `pending_email` MUST remain set so the user can re-request.

### AC-10: Clicking the Confirm Link Without a Session

- A `GET /verify-email-change?token=<valid>` from a browser with no session cookie MUST still promote the email in the DB. The result page renders normally. The new email takes effect on the user's next login.

### AC-11: Graceful Degrade When Email Is Unconfigured

- With `is_email_configured()` false, `GET /profile` MUST render the email-change card notice and no form. `POST /profile/email/request` MUST return `200` with `email_not_configured_for_change.html`. No DB write MUST occur.

### AC-12: Pending Status Visible

- A `GET /profile` for a user with a non-NULL `pending_email` MUST splice `{{email_change_status}}` so the user sees a yellow status line `"A change to {pending_email} is pending verification."` with `pending_email` escaped.

### AC-13: CSRF Field Forward-Compatibility

- A `POST /profile/email/request` without a `csrf_token` field MUST return `400 {"error": "Missing CSRF token"}`. With a non-empty `csrf_token` field, the request MUST proceed (regardless of the value, in v0.1.0).

### AC-14: No Existing-Vulnerability Regressions

- A `GET /download/db` request (no session) MUST still serve the SQLite file (VULN-6 is still open in v0.1.0). TC-13 asserts this.
- An SQLi payload in the `/login` username field (`' OR '1'='1`) MUST still bypass authentication (VULN-1 is still open in v0.1.0). TC-14 asserts this.

### AC-15: No New Dependency

- `backend/pyproject.toml` MUST NOT be modified by this slice. The new modules use only stdlib (`secrets`, `sqlite3`, `time`, `html`, `urllib`, `json`, `logging`, `threading`).

### AC-16: No main.py Modification

- `backend/app/main.py` MUST NOT be modified. The new routes are registered through the existing `app.include_router(router)` line.

### AC-17: Theme-Aware CSS

- Toggling the theme on the profile page (via the existing `#theme-toggle`) MUST recolor the new email-change card with no JS involvement.

---

## 13. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Authenticated profile page renders the email-change card | User `alice` (password `Passw0rd!`) is signed in | `GET /profile` returns `200`; the response HTML contains a `name="new_email"` input, a `name="confirm_new_email"` input, a `name="current_password"` input, and a `<input type="hidden" name="csrf_token" …>` field |
| TC-02 | Unauthenticated profile request redirects | No session cookie | `GET /profile` returns `302` to `/login`; the response body does not contain `name="new_email"` |
| TC-03 | Valid email-change request persists the pending triple | `alice` is signed in; no pending change; SendGrid is configured | `POST /profile/email/request` with `current_password=Passw0rd!`, `new_email=new@example.com`, `confirm_new_email=new@example.com`, `csrf_token=<any>` returns `200 {"success": true, ...}`; the `users` row for `alice` has `pending_email='new@example.com'`, `pending_email_token` non-NULL, `pending_email_token_expires > now`; an email is dispatched via SendGrid |
| TC-04 | Wrong current password is rejected | `alice` is signed in | `POST /profile/email/request` with `current_password=wrong` returns `401 {"error": "Incorrect password"}`; the `users` row for `alice` has `pending_email=NULL`; no email is sent |
| TC-05 | New email in use by another user is rejected | `alice` is signed in; user `bob` has `email='taken@example.com'` | `POST /profile/email/request` with `new_email=taken@example.com` returns `409 {"error": "That email is already in use"}`; no DB write; no email |
| TC-06 | Mismatched confirmation is rejected | `alice` is signed in | `POST /profile/email/request` with `new_email=a@b.com`, `confirm_new_email=c@d.com` returns `400 {"error": "Emails do not match"}`; no DB write; no email |
| TC-07 | Syntactically invalid email is rejected | `alice` is signed in | `POST /profile/email/request` with `new_email=not-an-email` returns `400 {"error": "Invalid email address"}`; no DB write; no email |
| TC-08 | New email same as current is rejected | `alice` is signed in; `alice.email='alice@example.com'` | `POST /profile/email/request` with `new_email=alice@example.com` returns `400 {"error": "New email must be different from the current email"}`; no DB write; no email |
| TC-09 | Missing CSRF token is rejected | `alice` is signed in | `POST /profile/email/request` without a `csrf_token` field returns `400 {"error": "Missing CSRF token"}`; no DB write; no email |
| TC-10 | Confirm link within 1 hour promotes the email | `alice` has a pending `pending_email='new@example.com'` with a non-NULL, unexpired `pending_email_token` | `GET /verify-email-change?token=<pending_email_token>` returns `200` with `verify_email_change_result.html`; `status="ok"`; `alice.email='new@example.com'`; `alice.pending_email=NULL`; `alice.pending_email_token=NULL`; the response body does NOT contain the literal token value |
| TC-11 | Confirm link is single-use | The link from TC-10 was already visited once | A second `GET /verify-email-change?token=<same>` returns `200` with `status="invalid"`; `alice.email` is still `new@example.com`; no further state change |
| TC-12 | Confirm link after expiry renders expired | `alice` has a pending `pending_email` with `pending_email_token_expires < now` | `GET /verify-email-change?token=<pending_email_token>` returns `200` with `status="expired"`; the row's `pending_email` is still set so the user can re-request |
| TC-13 | **VULN-6 still intact: `/download/db` serves the SQLite file without authentication** | The application is running on v0.1.0; `vulnerable_app.db` exists at the project root | `GET /download/db` (no cookies, no `csrf_token`) returns `200` with `Content-Type: application/octet-stream` and the response body is byte-equal to the on-disk `vulnerable_app.db`. This is the deliberate, observable consequence of the additive posture in v0.1.0. **This test MUST pass on v0.1.0 and MUST continue to pass after this slice lands.** |
| TC-14 | **VULN-1 still intact: SQLi on `/login`** | The application is running on v0.1.0; a user `victim` exists with password `Passw0rd!` | `POST /login` with `username=' OR '1'='1` (and any password) returns `200 {"success": true, "redirect": "/welcome"}`. The concatenated SQL still returns a row. **This test MUST pass on v0.1.0.** |
| TC-15 | Confirm link works without a session | `alice` has a pending email; `alice`'s session cookie is cleared | `GET /verify-email-change?token=<valid>` from a clean browser returns `200` with `status="ok"`; `alice.email` is updated in the DB; the new email takes effect on `alice`'s next login |
| TC-16 | Email send failure rolls back | `alice` is signed in; SendGrid returns non-2xx (simulated by an invalid `SENDGRID_API_KEY`) | `POST /profile/email/request` returns `502 {"error": "Could not send the verification email..."}`; the `users` row for `alice` has `pending_email=NULL`, `pending_email_token=NULL`, `pending_email_token_expires=NULL` |
| TC-17 | Pending status line is visible on profile | `alice` is signed in and has `pending_email='new@example.com'` | `GET /profile` returns `200`; the response HTML contains the substring `is pending verification` and the escaped `new@example.com`; the status line is wrapped in an element with class `email-change-status` |
| TC-18 | Graceful degrade when email is unconfigured | `SENDGRID_API_KEY` is unset; `MAIL_*` env is unset; `alice` is signed in | `GET /profile` returns `200`; the email-change card is replaced by a notice linking to `email_not_configured_for_change.html`; `POST /profile/email/request` returns `200` with `email_not_configured_for_change.html`; no DB write |
| TC-19 | Second request overwrites the first token | `alice` is signed in; a pending email change exists with token T1 | A second `POST /profile/email/request` issues token T2 and overwrites T1; `GET /verify-email-change?token=T1` renders `status="invalid"`; `GET /verify-email-change?token=T2` renders `status="ok"` |
| TC-20 | No new third-party dependency | The slice has been applied | `cat backend/pyproject.toml` shows the same dependencies as the v0.1.0 baseline; `git diff backend/pyproject.toml` is empty; `git diff backend/uv.lock` shows only transitive bumps that were already in the lockfile |
| TC-21 | No modification to `main.py` | The slice has been applied | `git diff backend/app/main.py` is empty; the new routes are registered through the existing `app.include_router(router)` line |
| TC-22 | Theme toggle recolors the email-change card | The slice has been applied; the user toggles the theme via `#theme-toggle` | The card's background, border, and text colors flip to the `[data-theme="dark"]` palette via the existing CSS custom properties; no JS-specific to the email-change card runs |
| TC-23 | Token is not logged | `alice` issues a change; the confirm link is clicked | `grep "<pending_email_token>" server.log` returns no row; the only logged lines reference the user-id / username, never the token |
| TC-24 | No modification to other lab-vulnerable routes | The slice has been applied | `git diff backend/app/api/routes/auth.py` shows only the addition of three new route handlers + one helper, and the extension of `profile_page`; the existing `login_post`, `signup_post`, `welcome_page`, `logout`, `search`, `download_db` are unchanged (the SQLi concatenation in `login_post` is intact per VULN-1) |

---

## 14. Verification Steps

### 14.1 Local Boot

```bash
# From the project root, with SENDGRID_API_KEY / MAIL_* unset to test the graceful-degrade path:
uv run backend/app/main.py
# Default URL: http://localhost:3001/
```

### 14.2 Manual Walkthrough (Happy Path)

1. Open `http://localhost:3001/signup`, register a user (e.g., `alice` / `alice@example.com` / `Passw0rd!`).
2. Open `http://localhost:3001/login`, sign in as `alice`. (The session cookie is set.)
3. Navigate to `http://localhost:3001/profile`. The new **Change Email** card is rendered with three fields (`Current Password`, `New Email`, `Confirm New Email`) and a hidden `csrf_token` field.
4. Enter `Passw0rd!` / `newalice@example.com` / `newalice@example.com`, submit.
5. The page re-renders with a green success banner. Check the SQLite row for `alice`:

   ```bash
   sqlite3 vulnerable_app.db "SELECT id, username, email, pending_email, pending_email_token_expires FROM users WHERE username='alice';"
   # pending_email='newalice@example.com'; pending_email_token_expires > now()
   ```

6. Copy the confirm URL from the SendGrid log (or the outbox if capturing locally). Visit it in a fresh browser tab.
7. The `verify_email_change_result.html` page renders with `status="ok"`. Re-check the row:

   ```bash
   sqlite3 vulnerable_app.db "SELECT id, username, email, pending_email, pending_email_token_expires FROM users WHERE username='alice';"
   # email='newalice@example.com'; pending_email=NULL; pending_email_token=NULL; pending_email_token_expires=NULL
   ```

8. Visit the same URL a second time. The page renders with `status="invalid"` (single-use).
9. Visit `http://localhost:3001/profile`. The displayed email is now `newalice@example.com` (the session was updated in step 6).

### 14.3 URL Inventory

| URL | Method | Auth | Purpose |
|-----|--------|------|---------|
| `/profile` | GET | Session | Existing profile page; now also renders the email-change card (§4.6) |
| `/profile/email/request` | POST | Session + `csrf_token` | Issue a pending email change (§4.3) |
| `/verify-email-change?token=…` | GET | None (token is the capability) | Promote the pending email on a valid, unexpired, unconsumed token (§4.4) |
| `/login`, `/signup`, `/welcome`, `/logout`, `/search`, `/download/db` | (unchanged) | (unchanged) | v0.1.0 lab endpoints; the lab vulnerabilities remain exploitable per AC-14 / TC-13 / TC-14 |

### 14.4 Quick Sanity Checks

- `git diff backend/app/main.py` → empty.
- `git diff backend/pyproject.toml backend/uv.lock` → no new dependency added.
- `grep -R "pending_email_token" backend/` shows only the new `services/email_change_service.py` and the route handler; no other module reads or writes the column.
- `sqlite3 vulnerable_app.db ".schema users"` shows the three new columns as nullable TEXT / REAL.
- Visiting `http://localhost:3001/download/db` without a session returns the SQLite file (VULN-6 still open — TC-13).
- Visiting `http://localhost:3001/login` and submitting `username=' OR '1'='1` with any password returns `200 {"success": true, ...}` (VULN-1 still open — TC-14).
