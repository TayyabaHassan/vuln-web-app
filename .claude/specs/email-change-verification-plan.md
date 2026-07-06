# Implementation Plan — Email Change with Verification

**Version:** 1.0.0
**Last Updated:** July 5, 2026
**Parent Spec:** [`.claude/specs/email-change-verification.md`](./email-change-verification.md)
**Base Release:** v0.1.0 (intentionally vulnerable baseline — the eight lab vulnerabilities remain exploitable)
**Posture:** ADDITIVE ONLY. No existing route, middleware, service, template, or schema statement is removed, refactored, or "fixed" by this slice.

---

## 0. Plan Overview & Guiding Principles

This plan turns the spec into an ordered sequence of edits, each one testable in isolation. The slice touches **10 files** (3 new, 7 modified) and adds **3 nullable DB columns** with no data backfill. It reuses the existing `secrets.token_urlsafe(32)` token model, the existing `EMAIL_VERIFICATION_TTL_SECONDS`-style TTL, the existing `core/mailer` SendGrid transport, the existing `core/csrf.get_or_create_csrf_token`, the existing `_load_template` helper, and the existing `html.escape(..., quote=True)` output-encoding discipline.

**Reuse map** (where every borrowed primitive lives):

| Reused primitive | Source | Used by |
|---|---|---|
| `secrets.token_urlsafe(32)` | stdlib | `email_change_service.start_email_change` |
| `verify_password` | `backend/app/core/security.py` | `email_change_service.start_email_change` (current-password gate) |
| `core.mailer.send_email_change_email` (new) | mirrors `send_verification_email` | `email_change_service.start_email_change` |
| `core.config.APP_BASE_URL` | `backend/app/core/config.py` | confirm-URL construction |
| `core.config.EMAIL_CHANGE_TTL_SECONDS` (new) | `backend/app/core/config.py` | token-expiry calculation |
| `core.config.is_email_configured()` | `backend/app/core/config.py` | graceful-degrade gate |
| `get_or_create_csrf_token` | `backend/app/core/csrf.py` | `profile_page` (already used) |
| `_load_template` | `backend/app/api/routes/auth.py` | new route handlers |
| `html.escape(..., quote=True)` | stdlib | every new template splice + every new mailer body |
| `get_db` / `init_db` | `backend/app/db/session.py` | new service + migration |
| `Router` registration | existing `app.include_router(router)` in `main.py` | automatic (no `main.py` change) |

**Non-negotiables** (cross-cutting rules every phase obeys):

1. **No `main.py` edit** — new routes are picked up by the existing `app.include_router(router)`. Phase 7 has a `git diff backend/app/main.py` check that MUST be empty.
2. **No new third-party dependency** — `git diff backend/pyproject.toml backend/uv.lock` MUST be empty.
3. **All new SQL is parameterized** — no f-strings, no `+` concat with user input.
4. **Every reflected value is `html.escape(..., quote=True)`-d** before it enters HTML or a JSON error string. The raw email-change token never appears in any response, URL fragment after `?token=`, or log line.
5. **No existing route is touched** — only `profile_page` is extended (additive) and three new handlers are added.
6. **The eight lab vulnerabilities are not modified by this slice.** TC-13 (VULN-6) and TC-14 (VULN-1) assert that. *Important reconciliation note for v0.1.0 vs. the current working tree: see §11 below — when the slice is built on the current `main`, those two specific tests must be re-anchored to whatever vuln is still open in the base being used.*

---

## 1. Phase Index

| Phase | Files | Output |
|---|---|---|
| **P1. Configuration & docstrings** | `backend/app/core/config.py` | New `EMAIL_CHANGE_TTL_SECONDS` setting (default 3600 s, env-tunable, non-secret) |
| **P2. Schema migration** | `backend/app/db/session.py` | Three idempotent `ALTER TABLE` statements + `PRAGMA table_info` guard |
| **P3. Mailer helper** | `backend/app/core/mailer.py` | `send_email_change_email(to_email, username, confirm_url)` — mirrors `send_verification_email` |
| **P4. Service layer** | `backend/app/services/email_change_service.py` (new) | `start_email_change`, `verify_email_change_token`, `resend_email_change_for_credentials` (spec §3) |
| **P5. Route handlers** | `backend/app/api/routes/auth.py` | `profile_page` extension + `profile_email_request_post` + `verify_email_change_page` + `_render_verify_email_change_result` helper |
| **P6. Templates** | `frontend/templates/profile.html` (modified), `frontend/templates/verify_email_change_result.html` (new), `frontend/templates/email_not_configured_for_change.html` (new) | Profile card + outcome page + degrade page |
| **P7. CSS** | `frontend/static/css/styles.css` | `.email-change-card` / `.email-change-status` block (theme-aware) |
| **P8. Docs** | `docs/PRD.md`, `docs/TDD.md` | Feature noted under §3 FR / §11.3 schema / §11.4 endpoint inventory |
| **P9. Manual verification** | (no file edits) | Run spec §14.2 walkthrough + §14.4 sanity checks |

Each phase lists: exact files to modify, the precise implementation tasks, the security/error-handling considerations, and a short "done means" check.

---

## 2. Phase P1 — Configuration (`backend/app/core/config.py`)

### 2.1 Files to modify
- `backend/app/core/config.py` — add one new module-level constant.

### 2.2 Implementation tasks
1. Locate the existing `EMAIL_VERIFICATION_TTL_SECONDS` block (around line 96–98) and add a parallel `EMAIL_CHANGE_TTL_SECONDS` immediately after it:

   ```python
   # --- Email-change token lifetime (env-tunable, non-secret) -------------
   # Mirrors EMAIL_VERIFICATION_TTL_SECONDS but is intentionally independent
   # so the email-change flow can be tightened or relaxed without affecting
   # the signup verification flow. Default 1 hour; lower for demos via
   #   EMAIL_CHANGE_TTL_SECONDS=60 uv run backend/app/main.py
   EMAIL_CHANGE_TTL_SECONDS = int(
       os.environ.get("EMAIL_CHANGE_TTL_SECONDS", "3600")
   )
   ```

2. Do NOT touch `is_email_configured()`, `is_sendgrid_configured()`, the SendGrid constants, the `TURNSTILE_*` keys, the `TOTP_*` constants, the `OTP_*` constants, the `QR_LOGIN_*` constants, the `ACCOUNT_LOCKOUT_*` constants, or the `_load_dotenv` helper. None of them are affected by this slice.

### 2.3 Security considerations
- The new setting is **non-secret** and has **no `is_*_configured()` gate**. It is always available, just like `EMAIL_VERIFICATION_TTL_SECONDS`.
- The env var is intentionally un-prefixed with `MAIL_` or similar to keep it adjacent to its sibling setting in `config.py`.

### 2.4 Error handling
- `int(os.environ.get(...))` raises `ValueError` on a non-integer value. That is the correct posture: misconfiguration should crash the app at startup, not be silently swallowed. The existing `EMAIL_VERIFICATION_TTL_SECONDS` follows the same posture and is not changed.

### 2.5 "Done means"
```bash
git diff backend/app/core/config.py
# shows the EMAIL_CHANGE_TTL_SECONDS block and nothing else
python -c "from app.core import config; assert config.EMAIL_CHANGE_TTL_SECONDS == 3600"
EMAIL_CHANGE_TTL_SECONDS=120 python -c "from app.core import config; assert config.EMAIL_CHANGE_TTL_SECONDS == 120"
```

---

## 3. Phase P2 — Schema Migration (`backend/app/db/session.py`)

### 3.1 Files to modify
- `backend/app/db/session.py` — extend the existing migration map.

### 3.2 Implementation tasks
1. Leave the `CREATE TABLE IF NOT EXISTS` statement (lines 102–126) **byte-for-byte unchanged**. The CREATE is the spec's "fresh-database" path; the three new columns are added via `ALTER TABLE` for the migration path. (Alternatively, for maximum simplicity, the new columns can be added to the CREATE itself *and* via ALTER for upgrades. The spec leaves both options open; this plan picks the **additive ALTER-only** path to mirror the existing pattern used for `is_verified`, `verification_token`, `failed_login_attempts`, `locked_until`, `two_factor_enabled`, `otp_*`, `totp_*`.)

2. Extend the `migrations` dict (currently lines 134–163) with three new entries, placed after the TOTP block to keep the file's chronological ordering (each comment block is tagged with the feature that introduced it):

   ```python
   # Email Change with Verification feature: three nullable / no-default columns.
   # The defaults (NULL for all three) already mean "no pending change", so -- like
   # the lockout / otp / totp columns -- NO grandfather UPDATE is needed; existing
   # rows are correct as-is. pending_email_token_expires stores Unix epoch seconds
   # (REAL), matching the same pattern as verification_token_expires and the
   # lockout / OTP / TOTP timestamp columns.
   "pending_email":            "ALTER TABLE users ADD COLUMN pending_email TEXT",
   "pending_email_token":      "ALTER TABLE users ADD COLUMN pending_email_token TEXT",
   "pending_email_token_expires": "ALTER TABLE users ADD COLUMN pending_email_token_expires REAL",
   ```

3. **Do NOT** add a grandfather `UPDATE` for `pending_email` (unlike `is_verified` which needed one). The new columns are nullable; existing rows with `pending_email = NULL` already mean "no pending change," which is the correct default for a v0.1.0 user.

4. The existing `for column, ddl in migrations.items():` loop will pick up the three new entries automatically — no other change to `init_db()` is required.

### 3.3 Database/model changes (summary)
- **No table redesign.** `users` gains three nullable columns: `pending_email` (TEXT), `pending_email_token` (TEXT), `pending_email_token_expires` (REAL). No column is dropped, renamed, retyped, or reindexed.
- **No data backfill.** Every existing row gets `NULL` for all three columns on the first boot that applies the migration, which is the desired "no pending change" state.
- **No new `UNIQUE` constraint.** `pending_email_token` is intentionally **not** `UNIQUE` at the schema level: (a) SQLite's `ALTER TABLE ADD COLUMN` cannot add a `UNIQUE` constraint anyway (cf. the comment on `google_id` at line 128), and (b) the 256-bit entropy of `secrets.token_urlsafe(32)` makes collisions astronomically unlikely, and a duplicate-token race resolves to "first claim wins, second becomes a no-op" — see EC-04.

### 3.4 Security considerations
- The migration is **idempotent** via the `PRAGMA table_info(users)` check at line 133. Re-running on a database that already has the columns is a silent no-op (NFR-05).
- No column carries a default that would touch existing data.

### 3.5 Error handling
- The existing `for` loop will raise on any unhandled `sqlite3.OperationalError`. The new ALTER statements follow the same pattern as the existing ones; if a future SQLite quirk raises, the operator sees a clear stack trace at startup, which is the right behavior.

### 3.6 "Done means"
```bash
sqlite3 vulnerable_app.db ".schema users" | grep -i pending
# shows three columns, all nullable
# delete the DB and re-run the app; the columns reappear via the ALTER loop:
rm vulnerable_app.db
uv run backend/app/main.py &  # exits because main.py blocks; or run --help
sqlite3 vulnerable_app.db ".schema users" | grep -i pending
# still three columns
```

---

## 4. Phase P3 — Mailer Helper (`backend/app/core/mailer.py`)

### 4.1 Files to modify
- `backend/app/core/mailer.py` — add one new public function, `send_email_change_email`.

### 4.2 Implementation tasks
1. Add a new public function immediately after `send_otp_email` (so the file's order is: `_send_via_sendgrid`, `_deliver`, `send_verification_email`, `send_otp_email`, `send_email_change_email`):

   ```python
   def send_email_change_email(to_email: str, username: str, confirm_url: str) -> bool:
       """Send the email-change confirmation email. Returns True on success, else False.

       Same posture as send_verification_email and send_otp_email:
       - Returns False (never raises) on every failure path (unconfigured, network,
         non-2xx, JSON error, timeout) so the caller can roll back the pending-email
         triple in services/email_change_service.start_email_change().
       - The API key is never logged.
       - The username and the confirm URL are html.escape(..., quote=True)'d before
         they enter the HTML body (VULN-2 posture). The raw token is NEVER in
         either the text or HTML body -- the URL is treated as one opaque string
         and escaped wholesale; we never split on `?token=`.
       - On success logs only "Email change confirmation sent to <to_email>".

       The user is changing the email address ON THEIR EXISTING ACCOUNT, so this
       email goes to the NEW address (proving the user controls it). The OLD
       address receives nothing -- mirroring /verify signup behavior.
       """
       if not config.is_email_configured():
           logger.warning("Email not configured; skipping email-change email to %s", to_email)
           return False

       safe_username = html.escape(username or "", quote=True)
       safe_url = html.escape(confirm_url, quote=True)

       subject = "Confirm your new email - Security Vulnerability Lab"
       text_body = (
           f"Hi {username},\n\n"
           "We received a request to change the email address on your Security "
           "Vulnerability Lab account to this address. If you made this request, "
           "open the link below within 1 hour to confirm the change. The link "
           "can be used only once.\n\n"
           f"{confirm_url}\n\n"
           "If you did not request this change, you can safely ignore this email "
           "-- your current address will stay in effect."
       )
       html_body = (
           f"<p>Hi {safe_username},</p>"
           "<p>We received a request to change the email address on your "
           "<strong>Security Vulnerability Lab</strong> account to this address. "
           "If you made this request, click the button below within 1 hour to "
           "confirm the change. The link can be used only once.</p>"
           f'<p><a href="{safe_url}">Confirm new email</a></p>'
           "<p>If you did not request this change, you can safely ignore this "
           "email -- your current address will stay in effect.</p>"
       )

       ok = _deliver(to_email, subject, text_body, html_body)
       if ok:
           logger.info("Email change confirmation sent to %s", to_email)
       return ok
   ```

2. Do NOT modify `_send_via_sendgrid`, `_deliver`, `send_verification_email`, `send_otp_email`, or the module docstring.

### 4.3 Email format — before vs. after

**Before (no email-change helper exists).** The file ends at `send_otp_email`. The signup flow is the only consumer of the SendGrid transport.

**After (this slice).** A fifth function, `send_email_change_email`, follows `send_otp_email`. It reuses `_deliver` and the SendGrid payload shape verbatim. The subject is distinct (`"Confirm your new email - ..."`) so the message is recognizable in the recipient's inbox even if both flows race for the same user.

### 4.4 Security considerations
- **VULN-2 (Stored XSS):** `safe_username` and `safe_url` are `html.escape(..., quote=True)`-d. The `confirm_url` is treated as one opaque string — we do NOT split it on `?token=` and try to escape the path and query parts separately. Splitting would risk splitting in the wrong place (a token that happens to contain an ampersand, say). One wholesale escape is correct.
- **VULN-3 (Reflected XSS):** The raw token does not appear in the email body. The user copies the URL by clicking the link, not by retyping the token, so the URL is a complete opaque payload.
- **VULN-4 (Session Hijacking):** No session secret is touched here. The `SENDGRID_API_KEY` is read by `_deliver` and is never logged (NFR-08).
- **Fail-safe:** the function returns `False` (never raises). The caller treats `False` as "could not send" and rolls back the pending triple (spec §4.3 step 13, FR-06).

### 4.5 Error handling
| Outcome | Return | Log |
|---|---|---|
| `is_email_configured()` is `False` | `False` | `"Email not configured; skipping email-change email to <to_email>"` |
| SendGrid returns 2xx | `True` | `"Email change confirmation sent to <to_email>"` |
| SendGrid returns non-2xx | `False` | `"SendGrid API send failed to <to_email>"` (from `_send_via_sendgrid`) |
| Network / timeout / any other exception | `False` | `"SendGrid API send failed to <to_email>"` (from `_send_via_sendgrid`) |
| URL parse error in `urllib` | `False` | same as above |

### 4.6 "Done means"
```bash
# with SENDGRID_API_KEY unset, the function must return False without raising
python -c "
from app.core.mailer import send_email_change_email
result = send_email_change_email('alice@example.com', 'alice', 'https://x/verify-email-change?token=abc')
assert result is False, f'expected False, got {result}'
print('OK')
"
# with a bogus key, also False
SENDGRID_API_KEY=definitely_not_real SENDGRID_FROM=test@example.com python -c "
from app.core.mailer import send_email_change_email
assert send_email_change_email('alice@example.com', 'alice', 'https://x/verify-email-change?token=abc') is False
print('OK')
"
# check that the API key is never in the log
SENDGRID_API_KEY=definitely_not_real SENDGRID_FROM=test@example.com python -c "
import logging; logging.basicConfig(level=logging.INFO)
from app.core.mailer import send_email_change_email
send_email_change_email('alice@example.com', 'alice', 'https://x/verify-email-change?token=abc')
" 2>&1 | grep -i 'definitely_not_real' && echo 'LEAK!' || echo 'no leak'
```

---

## 5. Phase P4 — Service Layer (`backend/app/services/email_change_service.py`, new file)

### 5.1 Files to create
- `backend/app/services/email_change_service.py`

### 5.2 Implementation tasks
Create the file with three functions, mirroring `backend/app/services/verification_service.py`'s structure. The docstrings reference spec sections so a future reader can find the spec.

```python
"""Email-change business logic (issue / verify / resend).

This is the only module that touches the ``pending_email`` / ``pending_email_token``
/ ``pending_email_token_expires`` columns on the ``users`` table. It is the
email-change analog of ``services/verification_service.py``: the route layer
in ``api/routes/auth.py`` calls these functions and renders/redirects on the
result.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized -- never
  concatenate.
- VULN-3 (Reflected XSS): the token is never reflected back to the client; the
  /verify-email-change route renders a fixed outcome message, not the token.
- VULN-7 / VULN-8: the issue endpoint is reached via ``POST /profile/email/request``,
  which the existing CSRF + rate-limit middleware already guard (in v0.1.0 with
  no middleware the form still carries a hidden csrf_token field, and the handler
  in auth.py reads it forward-compatibly). This module adds no new auth surface.

Token model (mirrors Option A in verification_service.py):
- ``secrets.token_urlsafe(32)`` (256-bit) stored raw in ``pending_email_token``.
- ``pending_email_token_expires`` is ``time.time() + config.EMAIL_CHANGE_TTL_SECONDS``
  (default 1 hour, env-tunable).
- A successful verify clears all three columns, making the link single-use.
- The atomic promotion is one UPDATE: ``email = pending_email, pending_email =
  NULL, pending_email_token = NULL, pending_email_token_expires = NULL``.
"""

import logging
import re
import secrets
import time

from fastapi.responses import HTMLResponse, JSONResponse

from app.core import config, mailer
from app.core.security import verify_password
from app.db.session import get_db

logger = logging.getLogger(__name__)

# Project-wide email regex. The signup form uses HTML5 type="email" client-side
# (no server-side check exists in auth_service.signup); the email-change flow
# enforces it server-side as a defense-in-depth gate. Kept narrow on purpose
# to match what the browser considers a valid email.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(value: str) -> bool:
    """Return True iff `value` is a syntactically well-formed email address.

    Server-side mirror of the browser's type="email" check. Narrow by design:
    rejects empty strings, whitespace, strings without `@`, and strings without
    a dot in the domain. Does not second-guess unusual but valid TLDs.
    """
    if not value:
        return False
    return _EMAIL_RE.match(value) is not None


def start_email_change(
    request_user_id: int, current_password: str, new_email: str, confirm_new_email: str
) -> JSONResponse:
    """Issue a pending email change for the calling user.

    Inputs are pre-validated by the route handler (non-empty, match, regex).
    This function does the password gate, the uniqueness check, the token
    issuance, the persistence, and the email send.

    Returns JSON for every outcome so the profile page's fetch() handler can
    render feedback inline without a reload (mirrors
    verification_service.resend_for_credentials):
    - 401 {"error": "Incorrect password"}
    - 400 {"error": "New email must be different from the current email"}
    - 409 {"error": "That email is already in use"}
    - 502 {"error": "Could not send the verification email. Please try again later."}
            (rolled back; pending triple is NULL)
    - 200 {"success": True, "message": "Verification email sent to {new_email}."}

    Every SELECT/UPDATE is parameterized; the confirm URL is the only string
    that crosses the wire, and the mailer escapes it before it enters HTML.
    """
    if not (current_password and new_email and confirm_new_email):
        # Defense in depth -- the route handler should have caught this. 400
        # is a generic catch-all.
        return JSONResponse(
            content={"error": "All fields are required"}, status_code=400
        )
    if new_email != confirm_new_email:
        return JSONResponse(content={"error": "Emails do not match"}, status_code=400)
    if not is_valid_email(new_email):
        return JSONResponse(content={"error": "Invalid email address"}, status_code=400)

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, password FROM users WHERE id = ?",
            [request_user_id],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        # Session references a row that no longer exists. The CSRF middleware
        # in v1.0.4+ blocks session-less POSTs at 403; this is defense in depth.
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    # FR-03: verify the current password with bcrypt in Python. The MD5 hex
    # equality check inside auth_service.login() is the sole authenticator on
    # the login path; here we use the existing primitive and never store the
    # plain text.
    if not verify_password(current_password, row["password"]):
        return JSONResponse(
            content={"error": "Incorrect password"}, status_code=401
        )

    # FR-02 final gate: refuse a "change" that doesn't change.
    if new_email == row["email"]:
        return JSONResponse(
            content={"error": "New email must be different from the current email"},
            status_code=400,
        )

    # FR-04: uniqueness check. Exclude the calling user's own row so a user
    # re-submitting their own current address doesn't fail spuriously after a
    # previous successful change. Parameterized.
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by email + id !=
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            [new_email, request_user_id],
        ).fetchone()
    finally:
        conn.close()
    if existing:
        return JSONResponse(
            content={"error": "That email is already in use"}, status_code=409
        )

    # FR-05: issue a fresh token and persist the pending triple. We re-issue
    # even if a previous pending triple is still set, so the second click wins
    # (matches SP-02 and TC-19 in the spec).
    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_CHANGE_TTL_SECONDS

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET pending_email = ?, pending_email_token = ?, "
            "pending_email_token_expires = ? WHERE id = ?",
            [new_email, token, expires, request_user_id],
        )
        conn.commit()
    except Exception:
        logger.exception("start_email_change: persist failed for user_id=%s", request_user_id)
        # Roll back (no-op because we just wrote -- but be explicit so a future
        # ordering change doesn't leak a half-state) and return 502.
        try:
            conn.execute(
                "UPDATE users SET pending_email = NULL, pending_email_token = NULL, "
                "pending_email_token_expires = NULL WHERE id = ?",
                [request_user_id],
            )
            conn.commit()
        except Exception:
            logger.exception("start_email_change: rollback persist failed for user_id=%s", request_user_id)
        return JSONResponse(
            content={"error": "Could not save the email change. Please try again."},
            status_code=500,
        )
    finally:
        conn.close()

    # Build the confirm URL. The token stays in the URL as one opaque value;
    # the mailer (P3) will escape it wholesale before it enters the HTML body.
    confirm_url = f"{config.APP_BASE_URL}/verify-email-change?token={token}"

    # FR-06: synchronous send. We choose background=False so the mailer's
    # return value tells us whether to roll back. The signup flow uses
    # background=True because the user can resend from /login; here, the
    # user has no resend affordance other than re-submitting the form, so
    # failing fast and rolling back is the right trade-off.
    if not mailer.send_email_change_email(new_email, row["username"], confirm_url):
        # Roll back the persistence. We re-open a connection because the previous
        # one was closed in the finally block above.
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET pending_email = NULL, pending_email_token = NULL, "
                "pending_email_token_expires = NULL WHERE id = ?",
                [request_user_id],
            )
            conn.commit()
        except Exception:
            logger.exception("start_email_change: rollback after send failed for user_id=%s", request_user_id)
        finally:
            conn.close()
        return JSONResponse(
            content={"error": "Could not send the verification email. Please try again later."},
            status_code=502,
        )

    # The new email is reflected in the success message so the user can confirm
    # they typed the right address. It is escaped (VULN-3) before the JSON
    # serialization (json.dumps does NOT escape HTML by default).
    return JSONResponse(
        content={
            "success": True,
            "message": f"Verification email sent to {html_escape(new_email)}.",
        }
    )


def verify_email_change_token(token: str) -> dict:
    """Validate the token and atomically promote pending_email -> email on success.

    Returns a dict with shape::

        {"status": "ok",      "user": {id, username, new_email}}
        {"status": "expired", "user": None}
        {"status": "invalid", "user": None}

    The token is looked up by exact match -- it is never reflected back to
    the caller (VULN-3 posture). A successful verify is a single UPDATE that
    promotes the email AND clears the three pending columns, so the same
    token cannot be used twice.

    Called by GET /verify-email-change, which is a token-as-capability GET
    (no session required). The route handler also writes request.session
    if a session is present, so the verifying browser sees the new email
    immediately on /profile; the route handler is the right place for that
    side-effect because it knows about the request.
    """
    if not token:
        return {"status": "invalid", "user": None}

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized lookup by token value.
        row = conn.execute(
            "SELECT id, username, email, pending_email, "
            "pending_email_token_expires FROM users "
            "WHERE pending_email_token = ?",
            [token],
        ).fetchone()
        if not row:
            # No outstanding token matches (never issued, or already consumed).
            return {"status": "invalid", "user": None}

        expires = row["pending_email_token_expires"]
        if expires is None or time.time() > float(expires):
            # Expired -- DO NOT clear the pending triple. The user can
            # re-submit the form to re-issue a fresh token. (SP-02, EC-09.)
            return {"status": "expired", "user": None}

        # FIXED: SQL Injection closed -- single-statement atomic promotion.
        # Reading pending_email from the same row that owns the token means an
        # attacker who learned a valid token cannot substitute a different
        # email (EC-05).
        conn.execute(
            "UPDATE users SET email = pending_email, pending_email = NULL, "
            "pending_email_token = NULL, pending_email_token_expires = NULL "
            "WHERE id = ?",
            [row["id"]],
        )
        conn.commit()
        return {
            "status": "ok",
            "user": {
                "id": row["id"],
                "username": row["username"],
                "new_email": row["pending_email"],
            },
        }
    except Exception:
        logger.exception("verify_email_change_token failed")
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def resend_email_change_for_credentials(
    request_user_id: int, current_password: str
) -> JSONResponse:
    """Re-issue a fresh token against the same pending_email, gated on the password.

    The route handler in auth.py does NOT currently call this function -- the
    spec (FR-XX) defines the re-request path as "user re-submits the form,"
    which goes through start_email_change with a fresh password re-prompt.
    This helper exists for spec completeness (the affected-files table in
    spec §3 lists it) and for a future UI affordance to resend without
    re-typing the new email.

    Behavior (mirrors verification_service.resend_for_credentials):
    - 401 {"error": "Not authenticated"} -- row gone
    - 401 {"error": "Incorrect password"}
    - 400 {"error": "No pending email change to resend."} -- row has NULL
            pending_email (user has not yet submitted a request)
    - 200 {"success": True, "message": "Verification email sent to {new_email}."}
    - 502 {"error": "Could not send the verification email..."} (no state change
            if a previous send already failed; the new send simply re-tries)
    """
    if not current_password:
        return JSONResponse(
            content={"error": "Current password is required"}, status_code=400
        )

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, password, pending_email "
            "FROM users WHERE id = ?",
            [request_user_id],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    if not verify_password(current_password, row["password"]):
        return JSONResponse(content={"error": "Incorrect password"}, status_code=401)

    if not row["pending_email"]:
        return JSONResponse(
            content={"error": "No pending email change to resend."},
            status_code=400,
        )

    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_CHANGE_TTL_SECONDS

    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET pending_email_token = ?, "
            "pending_email_token_expires = ? WHERE id = ?",
            [token, expires, request_user_id],
        )
        conn.commit()
    except Exception:
        logger.exception("resend_email_change_for_credentials: persist failed")
        return JSONResponse(
            content={"error": "Could not save the email change. Please try again."},
            status_code=500,
        )
    finally:
        conn.close()

    confirm_url = f"{config.APP_BASE_URL}/verify-email-change?token={token}"
    if not mailer.send_email_change_email(
        row["pending_email"], row["username"], confirm_url
    ):
        return JSONResponse(
            content={"error": "Could not send the verification email. Please try again later."},
            status_code=502,
        )

    return JSONResponse(
        content={
            "success": True,
            "message": f"Verification email sent to {html_escape(row['pending_email'])}.",
        }
    )


def html_escape(value: str) -> str:
    """Local helper: html.escape(..., quote=True) re-exported for readability."""
    import html as _html
    return _html.escape(value or "", quote=True)
```

### 5.3 Security considerations
- **VULN-1 (SQL Injection):** every `SELECT`/`UPDATE` uses `?` placeholders with a list/tuple second arg. No f-strings, no `+` concat. The same posture as `services/verification_service.py`.
- **VULN-3 (Reflected XSS):** the token is read from the route handler's query string and never reflected back. The `new_email` is escaped via `html_escape(...)` before it lands in a JSON success message.
- **VULN-4 (Session Hijacking):** no session secret is read or written here. The session mutation (writing `request.session["email"] = ...`) is the route handler's responsibility because it has the `Request` object.
- **Atomicity:** the promotion `UPDATE` is one statement. A second visit with the same token finds no matching row.

### 5.4 Error handling
| Outcome | Return shape |
|---|---|
| Empty / mismatched / invalid inputs | `JSONResponse(400, {"error": "All fields are required" \| "Emails do not match" \| "Invalid email address"})` |
| Wrong current password | `JSONResponse(401, {"error": "Incorrect password"})` |
| `new_email == current email` | `JSONResponse(400, {"error": "New email must be different from the current email"})` |
| Email in use by another user | `JSONResponse(409, {"error": "That email is already in use"})` |
| Persist failed (DB error) | `JSONResponse(500, {"error": "Could not save the email change. Please try again."})` (pending triple rolled back) |
| Mailer returned False | `JSONResponse(502, {"error": "Could not send the verification email..."})` (pending triple rolled back) |
| Success | `JSONResponse(200, {"success": True, "message": "..."})` |

For `verify_email_change_token`: returns `{"status": "ok" \| "expired" \| "invalid", "user": ...}` — the route maps the status to the outcome page.

### 5.5 "Done means"
```bash
python -c "
from app.services import email_change_service
assert email_change_service.is_valid_email('a@b.co') is True
assert email_change_service.is_valid_email('no-at') is False
assert email_change_service.is_valid_email('') is False
assert email_change_service.is_valid_email('a@b') is False  # no TLD
print('OK')
"
# verify the token function returns the right shape for an unknown token
python -c "
from app.services import email_change_service
assert email_change_service.verify_email_change_token('') == {'status': 'invalid', 'user': None}
assert email_change_service.verify_email_change_token('not-a-real-token') == {'status': 'invalid', 'user': None}
print('OK')
"
```

---

## 6. Phase P5 — Route Handlers (`backend/app/api/routes/auth.py`)

### 6.1 Files to modify
- `backend/app/api/routes/auth.py` — three additive changes:
  1. Extend `profile_page` to splice four new placeholders.
  2. Add new handler `profile_email_request_post` (POST `/profile/email/request`).
  3. Add new handler `verify_email_change_page` (GET `/verify-email-change`).
  4. Add small helper `_render_verify_email_change_result(status)` (used only by the new GET handler).

### 6.2 Implementation tasks

#### 6.2.1 Imports (additive, no replacements)

At the existing import block, add:
```python
from app.services import email_change_service
```

Do NOT remove or reorder any existing import.

#### 6.2.2 Extend `profile_page` (additive splice only)

Locate the existing `profile_page` (lines 362–410). It currently splices six placeholders: `{{csrf_token}}`, `{{username}}`, `{{email}}`, `{{twofa_enabled}}`, `{{email_configured}}`, `{{totp_enabled}}`. Add three more placeholders **after** the existing six, reading the pending state with one additional parameterized SELECT:

```python
# Email Change with Verification: read the pending-email triple so the
# profile page can show the "change to <pending_email> is pending verification"
# status line and either render the form or, when email is unconfigured,
# link to the degrade page. Parameterized SELECT -- VULN-1.
pending_email = ""
conn = get_db()
try:
    row = conn.execute(
        "SELECT pending_email FROM users WHERE id = ?", [user_id]
    ).fetchone()
finally:
    conn.close()
if row and row["pending_email"]:
    pending_email = row["pending_email"]
```

Then splice the three new placeholders before the final `return HTMLResponse`:

```python
# Email Change card: either the form (FR-06 in the spec) or the "email not
# configured" inline notice linking to email_not_configured_for_change.html
# (FR-10). The card markup is the same on every render -- the only difference
# is which body it carries.
if config.is_email_configured():
    email_change_card = (
        '<form id="email-change-form">'
        f'<input type="hidden" name="csrf_token" value="{html.escape(token, quote=True)}">'
        '<div class="form-group">'
        '<label class="form-label" for="current_password_email">Current Password</label>'
        '<input type="password" id="current_password_email" name="current_password" class="form-input" placeholder="Enter your current password" required>'
        '</div>'
        '<div class="form-group">'
        '<label class="form-label" for="new_email">New Email</label>'
        '<input type="email" id="new_email" name="new_email" class="form-input" placeholder="Enter your new email" required>'
        '</div>'
        '<div class="form-group">'
        '<label class="form-label" for="confirm_new_email">Confirm New Email</label>'
        '<input type="email" id="confirm_new_email" name="confirm_new_email" class="form-input" placeholder="Re-enter the new email" required>'
        '</div>'
        '<button type="submit" class="btn btn-primary">Send verification email</button>'
        '</form>'
    )
else:
    email_change_card = (
        '<p class="form-subtitle">'
        'Changing your email requires email delivery, which is not configured on this server. '
        f'See <a href="/email-not-configured-for-change">/email-not-configured-for-change</a> for details.'
        '</p>'
    )

# Pending-state status line -- empty when no change is pending, otherwise
# "A change to {pending_email} is pending verification." with the address
# escaped (VULN-2). Spec §4.6 / AC-12.
if pending_email:
    email_change_status = (
        f'<p class="email-change-status">A change to {html.escape(pending_email, quote=True)} '
        'is pending verification. Check the inbox of that address for the confirmation link.</p>'
    )
else:
    email_change_status = ""

# profile_message placeholder is unchanged -- it's the JSON-driven success/
# error banner the change-password JS already shows. The email-change JS
# reuses it for its own messages (no new DOM id needed).
page = page.replace("{{email_change_card}}", email_change_card)
page = page.replace("{{email_change_status}}", email_change_status)
```

**Before / after — `profile_page` placeholder count:**

| | Before | After |
|---|---|---|
| Placeholders spliced | 6 (`{{csrf_token}}`, `{{username}}`, `{{email}}`, `{{twofa_enabled}}`, `{{email_configured}}`, `{{totp_enabled}}`) | 9 (the 6 above + `{{email_change_card}}`, `{{email_change_status}}`, `{{profile_message}}` — the last is added here for the email-change JS, replacing any existing token; if `{{profile_message}}` is already replaced elsewhere, this is a no-op) |

> **Note on `{{profile_message}}`:** the spec's §3 affected-files table says the existing `{{profile_message}}` is "reused." In the current `profile.html` the change-password card already has `<div id="profile-message">` but no `{{profile_message}}` placeholder. The plan does **not** add a `{{profile_message}}` placeholder to the email-change form; the email-change JS uses a *new* `id="email-change-message"` div (added by P6) that lives next to the form. The existing change-password card is untouched.

**Security check (additive only):** the `if config.is_email_configured():` branch renders the form with a `csrf_token` hidden input; the `else` branch renders a paragraph (no form, no token needed because there is no POST). Both branches embed only the session-bound CSRF token (via `get_or_create_csrf_token`, already called above) — the pending_email address is escaped via `html.escape(pending_email, quote=True)` before the f-string.

#### 6.2.3 New handler `profile_email_request_post`

Place this immediately after the existing `profile_password_post` handler (so the new route is grouped with the other profile-POSTs):

```python
@router.post("/profile/email/request")
async def profile_email_request_post(
    request: Request,
    current_password: str = Form(""),
    new_email: str = Form(""),
    confirm_new_email: str = Form(""),
    csrf_token: str = Form("", alias="csrf_token"),
):
    """Handle an email-change request from the authenticated profile page.

    Session-gated: the request must carry a valid session cookie (the route
    returns 401 {"error": "Not authenticated"} otherwise -- defense in depth
    on top of the 302 /login redirect from the session check below).

    CSRF-forward-compatible: the form MUST include a `csrf_token` hidden field.
    In v0.1.0 (no CSRF middleware) the value is read but not validated against
    the session. A missing or empty field is a client error (400) so the
    handler is unchanged when a future CSRFMiddleware is added.

    Every other validation (non-empty, match, regex, current-password gate,
    uniqueness, persistence, email send, rollback on send failure) lives in
    services/email_change_service.start_email_change() -- this handler is a
    thin shim that:
      1. gates on the session,
      2. reads the four form fields,
      3. forwards to the service,
      4. returns the service's JSONResponse verbatim (the profile page's
         fetch() handler renders it in the #email-change-message div).

    No SQL is built here; the service owns every parameter and every
    placeholder. No HTML is built here; the service returns JSON, not markup.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    # FR-11: a missing csrf_token field is a client error. In v0.1.0 we do not
    # compare against request.session["csrf_token"] (no middleware enforces
    # it); the field is required so a future CSRFMiddleware is forward-
    # compatible without touching this handler.
    if not csrf_token:
        return JSONResponse(
            content={"error": "Missing CSRF token"}, status_code=400
        )

    return email_change_service.start_email_change(
        user_id, current_password, new_email, confirm_new_email
    )
```

#### 6.2.4 New handler `verify_email_change_page`

Place this immediately after the existing `verify_email` handler (lines 144–189), so the new GET sits next to the existing `/verify` GET:

```python
@router.get("/verify-email-change")
async def verify_email_change_page(request: Request, token: str = ""):
    """Consume an email-change confirmation link.

    The token IS the capability (mirrors /verify, /auth/google/callback, and
    the QR scan GET). A session is NOT required. The handler does, however,
    read the (optional) request.session so the verifying browser's session
    is updated to the new email address (FR-09). The DB is updated either
    way; an unauthenticated click still promotes the email and the new
    address takes effect on the user's next login.

    VULN-3 posture: the raw token is NEVER reflected in the response body,
    the URL bar (the server never echoes it), or any log line. The
    _render_verify_email_change_result helper escapes every user-influenced
    value before splicing.
    """
    result = email_change_service.verify_email_change_token(token)

    if result["status"] == "ok":
        user = result["user"]
        # FR-09: if the verifying browser is signed in as the same user,
        # promote the session's email so /profile (and any other {{email}}
        # splice) immediately reflects the new address. Other live sessions
        # of the same user keep their old email until they re-login (EC-09).
        if request.session.get("user_id") == user["id"]:
            request.session["email"] = user["new_email"]
        return _render_verify_email_change_result("ok")

    return _render_verify_email_change_result(result["status"])
```

#### 6.2.5 New helper `_render_verify_email_change_result`

Place this near `_load_template` (lines 60–68), since both are static rendering helpers:

```python
def _render_verify_email_change_result(status: str) -> HTMLResponse:
    """Render the fixed-outcome page for /verify-email-change.

    Three status values, three fixed title/message pairs. The raw token is
    never on the page; the {{new_email}} splice carries the new email only
    on the "ok" branch and is escaped before substitution (VULN-2).

    The status string is author-controlled (one of "ok", "expired",
    "invalid"); the strings in the dict are also author-controlled. Even
    so, we still html.escape() them before splicing -- same defensive
    output-encoding discipline used by the existing verify_email handler.
    """
    outcomes = {
        "ok": (
            "Email updated",
            "Your email has been updated. You can now close this tab and "
            "return to your profile.",
        ),
        "expired": (
            "Link expired",
            "This email-change link has expired. You can request a new one "
            "from your profile page.",
        ),
        "invalid": (
            "Invalid link",
            "This email-change link is invalid or has already been used.",
        ),
    }
    title, message = outcomes.get(status, outcomes["invalid"])
    page = _load_template("verify_email_change_result.html")
    page = page.replace("{{title}}", html.escape(title, quote=True))
    page = page.replace("{{message}}", html.escape(message, quote=True))
    return HTMLResponse(content=page)
```

### 6.3 Authentication and password verification logic

- The session gate (`request.session.get("user_id")`) is the **only** authentication check. It returns `401 {"error": "Not authenticated"}` on miss (defense in depth — the spec's §4.3 step 1 says `302 /login`, but for a `POST` that expects a JSON response the 401 JSON body is what the profile page's `fetch()` handler can render without a reload; the spec's "302 /login" applies to the GET /profile case which is the same handler the user came from, so a fresh GET /profile will redirect them).
- The current-password gate is `verify_password(current_password, row["password"])` from `app/core/security.py`. This is the same primitive the login path and the change-password path use. In v0.1.0 it is MD5-hex equality; in later versions it is bcrypt. Either way, it fails closed.

### 6.4 Email verification workflow (route-side summary)

| Step | Code | Lines |
|---|---|---|
| Token read | `token = request.query_params.get("token", "")` | inside `verify_email_change_page` |
| Token validated | `result = email_change_service.verify_email_change_token(token)` | same |
| Atomic promotion + token columns cleared | inside `verify_email_change_token` (P4) | one parameterized UPDATE |
| Session email refresh | `if request.session.get("user_id") == user["id"]: request.session["email"] = user["new_email"]` | inside `verify_email_change_page` |
| Fixed outcome page | `_render_verify_email_change_result(...)` → `verify_email_change_result.html` | new helper + new template |

### 6.5 Security considerations
- **VULN-1:** all new SQL is in the service module and is parameterized. The route handlers contain no SQL.
- **VULN-2:** the form HTML, the `email_change_status` line, and the outcome page's `{{title}}` / `{{message}}` placeholders are all escape-encoded before splicing. The pending_email address and the user-controlled `new_email` (if ever reflected) flow through `html.escape(..., quote=True)`.
- **VULN-3:** the token is never reflected. The new helper reads from a fixed dict; the route never puts `token` (or any user-influenced value) into the response.
- **VULN-8 (CSRF) — forward-compat:** every POST reads the `csrf_token` field via `Form("csrf_token", alias="csrf_token")` and rejects a missing field with 400. The form's hidden input is `html.escape(token, quote=True)`. In v0.1.0 the value is not compared; in future versions, the existing `CSRFMiddleware` will validate it (it already validates the change-password form's csrf_token field identically).
- **VULN-4 (Session Hijacking):** no change to `main.py` and no change to the `SECRET_KEY` handling.
- **No modification to existing routes:** the existing `login_post`, `signup_post`, `welcome_page`, `logout`, `search`, `download_db` (where present) are not touched. `profile_page` is extended (additive splices + one additive SELECT) but no existing line is removed or weakened.

### 6.6 Error handling
| Endpoint | Outcome | Response |
|---|---|---|
| POST /profile/email/request | No session | 401 `{"error": "Not authenticated"}` |
| POST /profile/email/request | Missing csrf_token | 400 `{"error": "Missing CSRF token"}` |
| POST /profile/email/request | Service returns 4xx/5xx JSON | passthrough (e.g. 401 wrong password, 409 in use, 400 mismatch, 502 send fail) |
| POST /profile/email/request | Email unconfigured (route gate) | 200 HTML with `email_not_configured_for_change.html` (see §6.2.6 below) |
| GET /verify-email-change | Missing token | 200 HTML with status="invalid" |
| GET /verify-email-change | Unknown token | 200 HTML with status="invalid" |
| GET /verify-email-change | Expired token | 200 HTML with status="expired" (no DB change) |
| GET /verify-email-change | Valid token | 200 HTML with status="ok" (DB updated; session updated if applicable) |

#### 6.2.6 Email-not-configured gate (additive to the new POST)

Per FR-10: when `is_email_configured()` is false, the POST MUST return 200 with `email_not_configured_for_change.html` and MUST NOT persist any state. Add a single check at the very top of `profile_email_request_post`, before the session check (so the unauthenticated case also gets the friendly page instead of a 401):

```python
@router.post("/profile/email/request")
async def profile_email_request_post(request: Request, ...):
    if not config.is_email_configured():
        return HTMLResponse(content=_load_template("email_not_configured_for_change.html"))
    # ... rest of the handler
```

This mirrors the existing `signup_post` (lines 127–129) which returns the same shape for the signup gate.

### 6.7 Success messages

| Outcome | Server response | UI text |
|---|---|---|
| Email sent | `{"success": true, "message": "Verification email sent to <new_email>."}` | "Verification email sent to <new_email>." (rendered by the email-change JS, P6) |
| Email change confirmed (verify page) | 200 HTML, status="ok" | "Your email has been updated. You can now close this tab and return to your profile." |
| Email change confirmation expired (verify page) | 200 HTML, status="expired" | "This email-change link has expired. You can request a new one from your profile page." |
| Email change confirmation invalid (verify page) | 200 HTML, status="invalid" | "This email-change link is invalid or has already been used." |

### 6.8 "Done means"
```bash
# No edit to any existing route's body
git diff backend/app/api/routes/auth.py | grep -E '^[+-]' | grep -vE 'profile_email_request_post|verify_email_change_page|_render_verify_email_change_result|email_change_service|email_change_card|email_change_status|email_not_configured_for_change|profile_email_request_post|is_email_configured|html.escape'
# shows only the new symbols + the three new splices; the existing handlers are untouched

# Routes are registered
python -c "
from app.api.routes.auth import router
paths = sorted({r.path for r in router.routes})
assert '/profile/email/request' in paths
assert '/verify-email-change' in paths
print('OK')
"
```

---

## 7. Phase P6 — Templates

### 7.1 Files
- `frontend/templates/profile.html` — modified (additive card).
- `frontend/templates/verify_email_change_result.html` — **new**.
- `frontend/templates/email_not_configured_for_change.html` — **new**.

### 7.2 `profile.html` — add the email-change card

Insert a new `<div class="profile-card">…</div>` block **after the existing "Change Password" card and before the "Two-Factor Authentication" card** (so the new card slots in between two existing ones without disturbing their order). The card uses the same DOM pattern (`<form id="…">` + hidden `csrf_token` + a status div with `id="email-change-message"`).

**Before (current `profile.html`, lines 70–91):**
```html
<!-- Change Password -->
<div class="profile-card">
    <h2 class="section-title">Change Password</h2>
    <form id="change-password-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        ... (current password / new password / confirm / submit)
    </form>
</div>

<!-- Two-Factor Authentication (Email OTP 2FA, v1.0.6) -->
<div class="profile-card">
    ...
</div>
```

**After (additive only — the existing two cards are unchanged):**
```html
<!-- Change Password -->
<div class="profile-card">
    <h2 class="section-title">Change Password</h2>
    <form id="change-password-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        ... (unchanged)
    </form>
</div>

<!-- Change Email (Email Change with Verification) -->
<div class="profile-card email-change-card">
    <h2 class="section-title">Change Email</h2>
    {{email_change_status}}
    {{email_change_card}}
    <div id="email-change-message" class="profile-message" role="status" aria-live="polite" style="display: none;"></div>
</div>

<!-- Two-Factor Authentication (Email OTP 2FA, v1.0.6) -->
<div class="profile-card">
    ...
</div>
```

The new card is wrapped in `<div class="profile-card email-change-card">` so the existing `.profile-card` styles carry over, and the additional `.email-change-card` class (added in P7) gives the new card its own theme-aware padding/heading rules if needed.

The new `<div id="email-change-message">` sits below the spliced `{{email_change_card}}` so the JS (P6 §7.4) can render success/error messages inline without disturbing the form.

### 7.3 `verify_email_change_result.html` — new file

Modeled exactly on the existing `verify_result.html`. The file is read fresh from disk on every request (the project's `_load_template` helper is called by `_render_verify_email_change_result`). The template contains **only** `{{title}}` and `{{message}}` placeholders; both are author-controlled strings and both are `html.escape(..., quote=True)`-d before splicing.

**File contents (write verbatim):**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        // Pre-paint theme init -- same IIFE used by every other template so
        // dark-mode preference is honored before the first paint. The shared
        // stylesheet already defines the [data-theme="dark"] overrides.
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') {
                    saved = null;
                }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) {
                    theme = 'light';
                }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
    <title>{{title}} - Security Vulnerability Lab</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body class="dashboard-body">
    <!-- Shared Header (matches every other template) -->
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
        <div class="header-logos">
            <img src="/static/images/PUCIT_Logo.png" alt="PUCIT" class="header-logo">
            <img src="/static/images/excaliat-logo.png" alt="Excaliat" class="header-logo">
            <img src="/static/images/blue-logo-scl2.png" alt="FCCU" class="header-logo">
        </div>
    </header>

    <main class="dashboard-content">
        <div class="profile-card">
            <h2 class="section-title">{{title}}</h2>
            <p class="mission-description">{{message}}</p>
            <p class="form-link"><a href="/profile">Back to your profile</a></p>
        </div>
    </main>

    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;
            function reflect(theme) {
                var nextAction = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
                var icon = theme === 'dark' ? '☀' : '🌙';
                toggle.setAttribute('aria-label', nextAction);
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = icon;
            }
            reflect(document.documentElement.getAttribute('data-theme') || 'light');
            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try { localStorage.setItem('theme', next); } catch (e) { /* in-page flip still works */ }
                reflect(next);
            });
        })();
    </script>
</body>
</html>
```

**Verification email format — what the user receives (rendered in a mail client):**

```
From:    <SENDGRID_FROM>          (e.g. no-reply@example.com)
To:      <new_email>
Subject: Confirm your new email - Security Vulnerability Lab

Plain-text body:
    Hi <username>,

    We received a request to change the email address on your Security
    Vulnerability Lab account to this address. If you made this request,
    open the link below within 1 hour to confirm the change. The link
    can be used only once.

    https://localhost:3001/verify-email-change?token=<256-bit-token>

    If you did not request this change, you can safely ignore this email
    -- your current address will stay in effect.

HTML body: a <p>Hi <username></p> + a confirmation paragraph + an <a href="<confirm_url>">Confirm new email</a> button. The username and the confirm URL are html.escape(..., quote=True)'d before they enter the markup (VULN-2 posture).
```

The token is **not** in either body as a separate, unescaped string. The URL is one opaque value to be escaped wholesale.

### 7.4 `email_not_configured_for_change.html` — new file

A standalone page that explains the situation and provides a link back to `/profile`. Modeled on the existing `email_not_configured.html`.

**File contents (write verbatim):**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        // Pre-paint theme init -- identical to the other templates.
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') { saved = null; }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) { theme = 'light'; }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) { document.documentElement.setAttribute('data-theme', 'light'); }
        })();
    </script>
    <title>Email not configured - Security Vulnerability Lab</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body class="dashboard-body">
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
        <div class="header-logos">
            <img src="/static/images/PUCIT_Logo.png" alt="PUCIT" class="header-logo">
            <img src="/static/images/excaliat-logo.png" alt="Excaliat" class="header-logo">
            <img src="/static/images/blue-logo-scl2.png" alt="FCCU" class="header-logo">
        </div>
    </header>

    <main class="dashboard-content">
        <div class="profile-card">
            <h2 class="section-title">Email delivery is not configured</h2>
            <p class="mission-description">
                Changing your email address requires the server to send a
                confirmation link to the new address. This server does not
                have email delivery set up, so the email-change feature is
                unavailable right now.
            </p>
            <p class="mission-description">
                To enable this feature, set the
                <code>SENDGRID_API_KEY</code> and <code>SENDGRID_FROM</code>
                environment variables (or the matching entries in a
                git-ignored <code>.env</code> file) and restart the
                application. See <code>core/config.py</code> for the full list
                of supported settings.
            </p>
            <p class="form-link"><a href="/profile">Back to your profile</a></p>
        </div>
    </main>

    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;
            function reflect(theme) {
                var nextAction = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
                var icon = theme === 'dark' ? '☀' : '🌙';
                toggle.setAttribute('aria-label', nextAction);
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = icon;
            }
            reflect(document.documentElement.getAttribute('data-theme') || 'light');
            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try { localStorage.setItem('theme', next); } catch (e) { /* in-page flip still works */ }
                reflect(next);
            });
        })();
    </script>
</body>
</html>
```

### 7.5 JS handler in `profile.html`

Add a third `<script>` block, immediately after the change-password JS and before the 2FA JS (or anywhere after the form is rendered), that handles the email-change form's submit:

```html
<script>
    // Email Change with Verification. The form posts urlencoded (so the
    // hidden csrf_token field reaches the handler; the existing CSRF
    // middleware in v1.0.4+ parses urlencoded bodies only). The success /
    // error JSON is rendered inline in #email-change-message. After a
    // success we re-fetch the profile so the new pending_email status line
    // appears without a manual refresh.
    (function () {
        var form = document.getElementById('email-change-form');
        var msg = document.getElementById('email-change-message');
        if (!form || !msg) return;

        function show(text, ok) {
            msg.textContent = text;
            msg.classList.remove('is-error', 'is-success');
            msg.classList.add(ok ? 'is-success' : 'is-error');
            msg.style.display = 'block';
        }

        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            msg.style.display = 'none';
            var body = new URLSearchParams(new FormData(form));
            try {
                var res = await fetch('/profile/email/request', { method: 'POST', body: body });
                var data = await res.json().catch(function () { return {}; });
                if (data.success) {
                    show(data.message || 'Verification email sent.', true);
                    // Re-fetch the profile so the {{email_change_status}}
                    // placeholder reflects the new pending state. A small
                    // timeout gives the server a moment to commit the row.
                    setTimeout(function () { window.location.reload(); }, 400);
                } else {
                    show(data.error || 'Could not request the email change.', false);
                }
            } catch (err) {
                show('Something went wrong. Please try again.', false);
            }
        });
    })();
</script>
```

### 7.6 Form validation (server-side recap, mirrors §4.3)

| Field | Client-side check | Server-side check (in `email_change_service.start_email_change`) | Error response |
|---|---|---|---|
| `current_password` | `<input type="password" required>` | non-empty + `verify_password()` against `users.password` | `401 {"error": "Incorrect password"}` |
| `new_email` | `<input type="email" required>` | non-empty + `is_valid_email(new_email)` regex + `new_email != users.email` | `400 {"error": "Invalid email address" \| "New email must be different from the current email"}` |
| `confirm_new_email` | `<input type="email" required>` | non-empty + `new_email == confirm_new_email` | `400 {"error": "Emails do not match"}` |
| `csrf_token` | `<input type="hidden" required>` (via form) | non-empty | `400 {"error": "Missing CSRF token"}` |

The server-side checks are the authoritative gate. The client-side `required` and `type="email"` attributes are advisory UX only; a hand-crafted POST skipping the form is still rejected with the same 4xx response.

### 7.7 "Done means"
```bash
ls frontend/templates/verify_email_change_result.html frontend/templates/email_not_configured_for_change.html
# both files exist

# The new card appears in profile.html and is inside the existing profile-content flex container
grep -A 2 'email-change-card' frontend/templates/profile.html

# The token placeholder is NOT in verify_email_change_result.html
grep -c '{{token}}' frontend/templates/verify_email_change_result.html
# outputs 0 -- the raw token is not in the template
```

---

## 8. Phase P7 — CSS (`frontend/static/css/styles.css`)

### 8.1 Files to modify
- `frontend/static/css/styles.css` — append one new block at the bottom of the file.

### 8.2 Implementation tasks
Append the following block, immediately after the existing `.cf-turnstile` block (line ~979) and before EOF. The block uses only existing custom properties so light/dark theming works without a new color literal.

```css
/* ============================================================
 * Email Change with Verification (profile card).
 * The card reuses the existing .profile-card surface/border/colors
 * so light/dark theming comes for free. The .email-change-status
 * line is a soft yellow callout (not a true warning) built from
 * the existing --color-error-* palette swapped to a more friendly
 * hue via opacity -- no new palette literal is introduced.
 * ============================================================ */

.email-change-card {
    /* No new colors. The base .profile-card already supplies
       --color-bg-surface / --color-border-soft / --color-text-primary. */
}

.email-change-status {
    margin: 0 0 16px 0;
    padding: 10px 12px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--color-error-bg) 60%, transparent);
    color: var(--color-text-primary);
    font-size: 0.85rem;
    line-height: 1.5;
    border: 1px solid color-mix(in srgb, var(--color-error-border) 70%, transparent);
}
```

If `color-mix(in srgb, ...)` is unsupported on the target browsers, fall back to the literal `--color-error-bg` for the background and `--color-error-border` for the border (the simpler rule below also works; the `color-mix` line is preferred for a softer look):

```css
.email-change-status {
    margin: 0 0 16px 0;
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--color-error-bg);
    color: var(--color-text-primary);
    font-size: 0.85rem;
    line-height: 1.5;
    border: 1px solid var(--color-error-border);
}
```

**Pick the `color-mix` variant for the slice; the fallback exists only as a contingency in case the project's test environment can't resolve the function.**

### 8.3 Security considerations
- The CSS does not introduce any new color literal. Theming via `data-theme` is automatic.
- The status line is rendered only when `pending_email` is non-NULL (P5 §6.2.2). The address is `html.escape(pending_email, quote=True)`-d before splicing, so even a malicious pending email address (impossible — it passed the regex — but defensive) cannot inject markup into the styled block.

### 8.4 "Done means"
```bash
# toggling data-theme on a profile page should recolor the .email-change-status
# block without any JS specific to this slice running. Manual check.

# The new selector appears exactly once
grep -c '\.email-change-card' frontend/static/css/styles.css
grep -c '\.email-change-status' frontend/static/css/styles.css
# both output 1
```

---

## 9. Phase P8 — Docs (`docs/PRD.md`, `docs/TDD.md`)

### 9.1 Files to modify
- `docs/PRD.md` — one new bullet under §3 (Functional Requirements).
- `docs/TDD.md` — one new sub-section under §11.3 (Schema) and one under §11.4 (Endpoint Inventory).

### 9.2 `docs/PRD.md` — add under §3 "Core Features" (after FR-5: User Search, before §3.2 Intentional Vulnerabilities)

```markdown
#### FR-6: User Email Change
- Authenticated users must be able to request a change of their email address from the profile page
- The change must require the current password and confirmation of the new email
- The new email must be verified via a single-use confirmation link before it becomes active
- The current email must remain in effect until the verification link is opened
```

### 9.3 `docs/TDD.md` — add under §11.3 (Database Schema)

```sql
-- Email Change with Verification: three nullable columns on the users table.
-- pending_email stores the not-yet-active address; pending_email_token stores
-- the raw secrets.token_urlsafe(32) link; pending_email_token_expires is a
-- Unix epoch REAL. All three are nullable / no default -- a row with all
-- NULLs has no pending change.
ALTER TABLE users ADD COLUMN pending_email TEXT;
ALTER TABLE users ADD COLUMN pending_email_token TEXT;
ALTER TABLE users ADD COLUMN pending_email_token_expires REAL;
```

### 9.4 `docs/TDD.md` — add to §11.4 (API Endpoints) as two new rows

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/profile/email/request` | Request an email change (sends verification link to the new address) | Yes (session + `csrf_token`) |
| GET | `/verify-email-change?token=…` | Promote `pending_email` to `email` on a valid, unexpired, unconsumed token | No (token is the capability) |

(The `/profile` GET row is already in §11.4; nothing to add there. The new `email_not_configured_for_change.html` page is a static template — not a new endpoint, just a return body for the new POST when email is unconfigured.)

### 9.5 Security considerations
- The docs change is documentation only; no code path is affected.
- The docs do **not** mention the rollback on send failure, the `secrets.compare_digest` semantics (N/A here — we don't compare the token to a session; we look it up by exact match), or the per-IP rate-limit non-coverage in v0.1.0. These are implementation details that belong in code comments and the spec, not in the PRD/TDD.

### 9.6 "Done means"
```bash
grep -c 'FR-6: User Email Change' docs/PRD.md
grep -c 'pending_email' docs/TDD.md
# both output >= 1
```

---

## 10. Phase P9 — Manual Verification

Mirrors the spec's §14.2 (manual walkthrough) and §14.4 (sanity checks). The phase is run by a human in a shell, not by writing more code.

### 10.1 Local boot

```bash
# From the project root. With SENDGRID_API_KEY unset, the new POST and the new
# GET /profile will both degrade to the "email not configured" pages.
uv run backend/app/main.py
# Default URL: http://localhost:3001/
```

To test the happy path, set a real SendGrid key in `.env` (or env vars) before booting.

### 10.2 Manual walkthrough (happy path)

| Step | Action | Expected |
|---|---|---|
| 1 | `curl -i http://localhost:3001/signup -c /tmp/c.txt` | 200, signup HTML |
| 2 | POST a new user (alice / alice@example.com / Passw0rd!) — fill in the `<form action="/signup" method="POST">` and POST, save cookies to `/tmp/c.txt` | 302 to `/check-email` |
| 3 | Find the verification email in the SendGrid outbox (or the Mailtrap/SMTP catcher if dev) | URL like `http://localhost:3001/verify?token=…` |
| 4 | `curl -i "<verify-url>" -b /tmp/c.txt -c /tmp/c.txt` | 302 to `/welcome`; session now has `user_id=alice` |
| 5 | `curl -i http://localhost:3001/profile -b /tmp/c.txt` | 200, HTML contains `name="new_email"`, `name="confirm_new_email"`, `name="current_password"`, `<input type="hidden" name="csrf_token" …>` |
| 6 | POST `/profile/email/request` with `current_password=Passw0rd!`, `new_email=newalice@example.com`, `confirm_new_email=newalice@example.com`, `csrf_token=<whatever>` — urlencoded, save cookies | 200 `{"success": true, "message": "Verification email sent to newalice@example.com."}` |
| 7 | `sqlite3 vulnerable_app.db "SELECT id, username, email, pending_email, pending_email_token_expires FROM users WHERE username='alice';"` | `pending_email='newalice@example.com'`, `pending_email_token` is non-NULL, `pending_email_token_expires > now()` |
| 8 | Find the email-change email in the outbox. It contains a URL like `http://localhost:3001/verify-email-change?token=…` | yes |
| 9 | `curl -i "<confirm-url>" -b /tmp/c.txt` | 200, HTML with title "Email updated" and the message; **the raw token is not in the response body** |
| 10 | Re-check the SQLite row: `pending_email` is NULL; `email='newalice@example.com'` | yes |
| 11 | `curl -i "<confirm-url>" -b /tmp/c.txt` (same URL, second visit) | 200, title "Invalid link" |
| 12 | `curl -i http://localhost:3001/profile -b /tmp/c.txt` | 200, `{{email}}` splice now shows `newalice@example.com` |

### 10.3 URL inventory (matches spec §14.3)

| URL | Method | Auth | Purpose |
|---|---|---|---|
| `/profile` | GET | Session | Profile page; now also renders the email-change card |
| `/profile/email/request` | POST | Session + `csrf_token` | Issue a pending email change |
| `/verify-email-change?token=…` | GET | None (token is the capability) | Promote `pending_email` to `email` |
| `/login`, `/signup`, `/welcome`, `/logout`, `/search`, `/download/db` | (unchanged) | (unchanged) | v0.1.0 lab endpoints |

### 10.4 Sanity checks (matches spec §14.4)

```bash
git diff backend/app/main.py                                # empty
git diff backend/pyproject.toml backend/uv.lock             # empty (no new dep)
grep -R "pending_email_token" backend/ | wc -l              # 2 (the service + the route handler)
sqlite3 vulnerable_app.db ".schema users" | grep pending    # three nullable columns
```

### 10.5 Negative-path walkthrough (no SMTP configured)

```bash
# unset all mail env
unset SENDGRID_API_KEY SENDGRID_FROM

uv run backend/app/main.py &
SERVER_PID=$!

# Sign in as alice (password is whatever it is in your DB; or sign up fresh)
curl -i -c /tmp/c.txt -X POST http://localhost:3001/login \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'username=alice&password=Passw0rd!&csrf_token=x' \
     # NOTE: signup is gated too -- you may need to register via a one-off
     # python -c "import sqlite3; conn=sqlite3.connect('vulnerable_app.db');
     #            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
     #                         ('alice', 'alice@example.com', '5f4dcc3b5aa765d61d8327deb882cf99'));  # MD5('password')
     #            conn.commit(); conn.close()"
# Then log in via /login.

curl -i -b /tmp/c.txt http://localhost:3001/profile
# the email-change card body is replaced with the "email is not configured" notice

curl -i -b /tmp/c.txt -X POST http://localhost:3001/profile/email/request \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'current_password=Passw0rd!&new_email=x@y.com&confirm_new_email=x@y.com&csrf_token=x'
# 200 with email_not_configured_for_change.html in the body; no DB write

sqlite3 vulnerable_app.db "SELECT pending_email FROM users WHERE username='alice';"
# NULL (no row was written)

kill $SERVER_PID
```

### 10.6 Edge-case walkthroughs

| EC | Action | Expected |
|---|---|---|
| EC-03 (Unicode username in email) | Create a user with username `ünïcödé`, request an email change, view the sent email's HTML part | The `Hi ünïcödé` line renders correctly; `<`/`>`/`&`/`"`/`'` in the username are escaped (defense in depth) |
| EC-04 (token collision) | Not testable by hand. Math: 2^256 keyspace; not feasible | n/a |
| EC-05 (forged token) | `curl -i "http://localhost:3001/verify-email-change?token=ANYTHING"` | 200 with "Invalid link"; no DB write |
| EC-06 (concurrent requests) | Two near-simultaneous POSTs to `/profile/email/request` from the same user | Whichever confirm link the user clicks first wins; the other renders "Invalid link" because `pending_email_token` was overwritten |
| EC-09 (stale session) | Sign in as alice, then clear the session cookie, then click the email-change confirm link | The DB is updated; the new email takes effect on alice's next login |
| EC-10 (SendGrid 202 + spam folder) | Out of scope | n/a |

---

## 11. Reconciliation with the v0.1.0 Framing vs. the Current Working Tree

The user framed this slice as "v0.1.0 base" and the spec was written against that framing. The current working tree at the time of writing has **all eight lab vulnerabilities closed** (per `CLAUDE.md`'s description of post-v2.0.0). Concretely:

| VULN | Current code | What "still intact" means for TC-13 / TC-14 |
|---|---|---|
| 1 — SQLi | `auth_service.login` and `auth_service.signup` use parameterized queries | The concatenated SQL is **gone**. TC-14 (`' OR '1'='1` on `/login`) will NOT return 200 on the current `main` — login will return 401. |
| 2 — Stored XSS | `welcome_page` does `html.escape(username, quote=True)` | The dashboard is escaped. TC-13 (the `/download/db` route) is the cleanest "still open" assertion — but `/download/db` was also removed in the v0.2.x fix. |
| 3 — Reflected XSS | `search_user` escapes `q`, the row columns, and the exception text | The reflection is escaped. |
| 4 — Session Hijacking | `main.py` sources `SECRET_KEY` from env with a strong `secrets.token_hex(32)` fallback | The hardcoded key is gone. |
| 5 — Weak Password | `security.py` uses bcrypt at cost 12 | MD5 is gone. |
| 6 — Exposed Database | The `/download/db` route is removed entirely | The route is gone. |
| 7 — No Rate Limiting | `RateLimitMiddleware` is registered | The middleware is in. |
| 8 — CSRF | `CSRFMiddleware` is registered | The middleware is in. |

**Implication for the two "vuln-still-intact" tests in the spec:**

- **TC-13** (`GET /download/db` returns 200 with the SQLite file) will fail on the current `main` because the route is no longer registered. It passes on `v0.1.0`.
- **TC-14** (`' OR '1'='1` on `/login`) will fail on the current `main` because `auth_service.login` uses parameterized queries. It passes on `v0.1.0`.

The spec is correct for the v0.1.0 framing the user provided. The plan keeps the tests as written. **What this means in practice:**

1. The slice ships with the two tests as defined. When the user checks out the v0.1.0 tag and runs the test suite, TC-13 and TC-14 pass — and that is the "vulnerability still intact" assertion the spec requires.
2. When the slice is built and tested on the current `main`, TC-13 and TC-14 fail (because the underlying vulns are closed). The plan does **not** "fix" this by repointing the tests at different code; that would weaken the spec's hard constraint that this slice not modify any existing vulnerability.
3. A short note can be added to `docs/PRD.md` and `docs/TDD.md` clarifying that TC-13 and TC-14 are v0.1.0-base tests; this is a documentation-only change and is out of scope for this plan (it would belong in a separate "test plan" document).

**No code change in this slice is made to "make TC-13 / TC-14 pass on the current `main`."** That would be removing or weakening an existing fix, which is the opposite of the additive posture the spec mandates.

---

## 12. Cross-Phase Checklist (run after every phase)

| Check | Command | Pass condition |
|---|---|---|
| `main.py` untouched | `git diff backend/app/main.py` | empty output |
| `pyproject.toml` / `uv.lock` untouched | `git diff backend/pyproject.toml backend/uv.lock` | empty output |
| No SQL string concatenation in new code | `grep -R '+ "' backend/app/services/email_change_service.py backend/app/api/routes/auth.py \| grep -i 'WHERE\|SELECT\|UPDATE\|INSERT' \| grep -v '?'` | no matches (all SQL uses `?` placeholders) |
| No raw token in any log line | `grep -R 'pending_email_token' backend/app/services/email_change_service.py` | the only log lines reference `user_id` / `username`, never the token |
| All new HTML splices go through `html.escape` | `grep -nE 'replace\("\{\{[^}]+\}\}"' backend/app/api/routes/auth.py \| grep -v 'html.escape'` | no matches (every splice's right-hand side is an escaped string) |
| All new mailer bodies escape attacker-influenced values | `grep -n 'username\|confirm_url' backend/app/core/mailer.py \| grep -v 'html.escape\|safe_'` | no matches outside the `safe_*` lines |
| Theme variables reused, no new color literal | `grep -E '#[0-9a-fA-F]{3,8}\|rgb\(\|hsl\(' frontend/static/css/styles.css \| grep -v 'comment' \| wc -l` | the new block adds zero new color literals |

---

## 13. Definition of Done

The slice is complete when **all** of the following are simultaneously true:

1. The 10 files listed in spec §3 are in the expected state (3 new, 7 modified).
2. `git diff backend/app/main.py` is empty.
3. `git diff backend/pyproject.toml backend/uv.lock` is empty.
4. `sqlite3 vulnerable_app.db ".schema users"` shows the three new columns as nullable.
5. `python -c "from app.services import email_change_service; assert email_change_service.is_valid_email('a@b.co') and not email_change_service.is_valid_email('no-at')"` passes.
6. The walkthrough in §10.2 succeeds end-to-end on a v0.1.0 base (TC-13, TC-14 pass; the 22 other TC-XX pass on either base).
7. The walkthrough in §10.5 succeeds end-to-end on a current `main` (graceful degrade renders; no DB writes; the existing 2FA and change-password cards still work — i.e., the additive splice to `profile_page` did not break the existing cards).
8. The CSS recolors correctly when the theme is toggled.
9. No new third-party package was installed.
10. The 8 lab vulnerabilities remain exploitable on v0.1.0 (per TC-13/TC-14) and the slice is **purely additive** on any later base.

---

## 14. End-to-End Before/After Summary

### 14.1 New "Change Email" card on the profile page

**Before (current `profile.html` lines 70–91):** the only "Change" card is "Change Password." There is no email-change UI anywhere.

**After (this slice):** a new card slots in between "Change Password" and "Two-Factor Authentication." Rendered HTML (when email is configured):

```html
<div class="profile-card email-change-card">
    <h2 class="section-title">Change Email</h2>
    <p class="email-change-status">A change to newalice@example.com is pending verification. Check the inbox of that address for the confirmation link.</p>
    <form id="email-change-form">
        <input type="hidden" name="csrf_token" value="<43-char token>">
        <div class="form-group">
            <label class="form-label" for="current_password_email">Current Password</label>
            <input type="password" id="current_password_email" name="current_password" class="form-input" placeholder="Enter your current password" required>
        </div>
        <div class="form-group">
            <label class="form-label" for="new_email">New Email</label>
            <input type="email" id="new_email" name="new_email" class="form-input" placeholder="Enter your new email" required>
        </div>
        <div class="form-group">
            <label class="form-label" for="confirm_new_email">Confirm New Email</label>
            <input type="email" id="confirm_new_email" name="confirm_new_email" class="form-input" placeholder="Re-enter the new email" required>
        </div>
        <button type="submit" class="btn btn-primary">Send verification email</button>
    </form>
    <div id="email-change-message" class="profile-message" role="status" aria-live="polite" style="display: none;"></div>
</div>
```

When `is_email_configured()` is false, the `<form>` is replaced by:

```html
<p class="form-subtitle">
    Changing your email requires email delivery, which is not configured on this server.
    See <a href="/email-not-configured-for-change">/email-not-configured-for-change</a> for details.
</p>
```

### 14.2 The verification route

**Before:** no `/verify-email-change` route. The closest analog is `/verify` (signup verification), which has a fixed, escape-encoded outcome page.

**After:**

| URL | Outcome | Response |
|---|---|---|
| `/verify-email-change?token=<valid>` | status="ok" | 200 HTML; title "Email updated"; message "Your email has been updated. You can now close this tab and return to your profile." |
| `/verify-email-change?token=<valid-but-expired>` | status="expired" | 200 HTML; title "Link expired"; message "This email-change link has expired. You can request a new one from your profile page." |
| `/verify-email-change?token=<unknown>` | status="invalid" | 200 HTML; title "Invalid link"; message "This email-change link is invalid or has already been used." |
| `/verify-email-change` (no token) | status="invalid" | same as above |

### 14.3 The pending-email and verification-token workflow (data lifecycle)

```
1. POST /profile/email/request (session + csrf_token)
   ├─ validate fields
   ├─ SELECT users WHERE id = ?   (parameterized)
   ├─ verify_password(...)
   ├─ SELECT users WHERE email = ? AND id != ?   (parameterized; uniqueness)
   ├─ token = secrets.token_urlsafe(32)
   ├─ UPDATE users SET pending_email, pending_email_token, pending_email_token_expires WHERE id = ?   (parameterized)
   └─ mailer.send_email_change_email(new_email, username, confirm_url)
      ├─ on True  -> 200 JSON {success: True, message: "..."}
      └─ on False -> UPDATE users SET pending_email = NULL, ... WHERE id = ?   (rollback; parameterized)
                      -> 502 JSON {error: "Could not send ..."}

2. (later, on the new address)
   GET /verify-email-change?token=<token>
   ├─ SELECT users WHERE pending_email_token = ?   (parameterized)
   ├─ if not found OR expired -> render verify_email_change_result.html with status="invalid" / "expired"
   └─ else:
      ├─ UPDATE users SET email = pending_email, pending_email = NULL, pending_email_token = NULL,
      │                  pending_email_token_expires = NULL WHERE id = ?   (atomic promotion; parameterized)
      ├─ if request.session["user_id"] == user_id:
      │     request.session["email"] = user["new_email"]   (session refresh)
      └─ render verify_email_change_result.html with status="ok"

3. Second visit with the same token
   └─ SELECT returns no row (pending_email_token is now NULL) -> status="invalid"
```

Every step is a single parameterized SQL statement. There is no readable intermediate state. The raw token never enters an HTML response or a log line.

---

## 15. Final Notes for the Implementer

- **The slice is small but cross-cuts many files.** Touch them in the order P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8 → P9. Each phase has an independent "done means" check; you can stop after any phase and the code is in a consistent state (the only exception is P4 without P5, which leaves the service module unreferenced but importable).
- **Re-read spec §4 (Runtime Behavior) before editing P5** — the spec is the source of truth for the route-lifecycle step ordering, and the handler comments in §6.2 above mirror it line-for-line.
- **Run the cross-phase checklist (§12) after every phase**, not just at the end. It catches the most common slip — a `main.py` edit or a `pyproject.toml` edit — within seconds of being introduced.
- **The "v0.1.0 base" reconciliation in §11 is real and important.** Do not be tempted to "fix" TC-13 / TC-14 by editing the test expectations; the spec is correct for the base it was written against. The slice must remain additive.
